// SPDX-License-Identifier: AGPL-3.0-only

// Package currentbundle is the canonical, minimum-disclosure boundary from a
// reviewed local API observation projection to Prufyx evaluation input.
//
// observation.Import remains the first-stage hardened reader. This package
// owns the second-stage schema: it does not expose the observation package's
// internal model and never turns a missing field into a guessed value.
package currentbundle

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/prufyx/prufyx/cli/internal/observation"
)

const (
	APIVersion                     = "prufyx.io/current-bundle/v1alpha1"
	Kind                           = "CurrentBundle"
	Schema                         = "current-bundle/v1alpha1"
	Assurance                      = "LOCAL_MANIFEST_INTEGRITY_ONLY"
	PredicateRegistryVersion       = "v1"
	PredicateRegistryVersionV2     = "v2"
	OmissionRegistryVersion        = "v1"
	configurationAdapterV3         = "component-configuration-adapter-v3"
	currentBundleAdapterV2         = "current-bundle-v2"
	currentBundleAdapterV3         = "current-bundle-v3"
	prometheusID                   = "pkg:oci/prometheus/prometheus"
	prometheusAgentModePredicate   = "component.prometheus.agent_mode"
	prometheusImageDigestPredicate = "component.prometheus.image_digest"
	maxBundleBytes                 = 8 << 20
	maxSourceBindings              = 4096
	maxReferences                  = 8192
	maxRoles                       = 32
	maxReasons                     = 32
	maxValues                      = 64
	maxPolicyIDBytes               = 128
	maxFreshnessAgeSeconds         = 30 * 24 * 60 * 60
	maxArrayItems                  = 10000
	maxComponents                  = 256
	maxPredicates                  = 128
	maxJSONDepth                   = 64
	maxJSONMembers                 = 4096
)

var errJSONDuplicateKey = errors.New("duplicate JSON object key")

type predicateDefinition struct{ valueKind string }

// These registries are deliberately closed and versioned. A predicate or
// omission not present here is rejected before it can cross this boundary.
var predicateRegistry = map[string]predicateDefinition{
	"component.metrics_server.kubernetes_min_minor":                        {"string"},
	"component.metrics_server.metrics_api_group":                           {"string"},
	"component.metrics_server.kubelet_tls_mode":                            {"string"},
	"component.metrics_server.ha_aggregator_routing":                       {"boolean"},
	"component.metrics_server.resource_metrics_window":                     {"string"},
	"component.external_dns.annotation_prefix":                             {"string"},
	"component.external_dns.policy_flag_presence":                          {"boolean"},
	"component.external_dns.source_api_surface":                            {"string"},
	"component.external_dns.registry_mode":                                 {"string"},
	"component.external_dns.provider_surface":                              {"string"},
	"component.prometheus.web_admin_api_enabled":                           {"boolean"},
	"component.prometheus.web_lifecycle_enabled":                           {"boolean"},
	"component.prometheus.log_level":                                       {"string"},
	"component.prometheus.agent_mode":                                      {"boolean"},
	"component.prometheus.image_digest":                                    {"string"},
	"component.argo_workflows.namespaced_mode":                             {"boolean"},
	"component.argo_workflows.managed_namespace_configured":                {"boolean"},
	"component.argo_cd.insecure_server_enabled":                            {"boolean"},
	"component.argo_cd.repo_server_configured":                             {"boolean"},
	"component.cert_manager.owner_ref_enabled":                             {"boolean"},
	"component.cert_manager.dns01_recursive_nameservers_configured":        {"boolean"},
	"component.cert_manager.controller_present":                            {"boolean"},
	"component.cert_manager.webhook_present":                               {"boolean"},
	"component.cert_manager.cainjector_present":                            {"boolean"},
	"component.cert_manager.startupapicheck_present":                       {"boolean"},
	"component.cert_manager.feature_gate_acme_use_ari":                     {"boolean"},
	"component.cert_manager.feature_gate_experimental_gateway_api_support": {"boolean"},
	"component.cert_manager.feature_gate_listener_sets":                    {"boolean"},
	"component.cert_manager.feature_gate_server_side_apply":                {"boolean"},
	"component.cert_manager.feature_gate_ca_injector_merging":              {"boolean"},
	"component.cert_manager.feature_gate_other_names":                      {"boolean"},
	"component.cert_manager.feature_gate_certificate_request_controllers":  {"boolean"},
	"component.cert_manager.install_mode":                                  {"string"},
	"component.cert_manager.crd_certificates_v1_served":                    {"boolean"},
	"component.cert_manager.crd_certificates_v1_storage":                   {"boolean"},
	"component.cert_manager.crd_certificaterequests_v1_served":             {"boolean"},
	"component.cert_manager.crd_certificaterequests_v1_storage":            {"boolean"},
	"component.cert_manager.crd_issuers_v1_served":                         {"boolean"},
	"component.cert_manager.crd_issuers_v1_storage":                        {"boolean"},
	"component.cert_manager.crd_clusterissuers_v1_served":                  {"boolean"},
	"component.cert_manager.crd_clusterissuers_v1_storage":                 {"boolean"},
	"component.cert_manager.crd_challenges_v1_served":                      {"boolean"},
	"component.cert_manager.crd_challenges_v1_storage":                     {"boolean"},
	"component.cert_manager.crd_orders_v1_served":                          {"boolean"},
	"component.cert_manager.crd_orders_v1_storage":                         {"boolean"},
	"component.cert_manager.admission_webhook_v1":                          {"boolean"},
	"component.cert_manager.admission_webhook_failure_policy_fail":         {"boolean"},
	"component.cert_manager.admission_webhook_identity_present":            {"boolean"},
	"component.cert_manager.rbac_serviceaccounts_token_create":             {"boolean"},
	"component.cert_manager.rbac_cert_manager_api_groups":                  {"boolean"},
	"component.cert_manager.rbac_acme_api_group":                           {"boolean"},
	"component.cert_manager.metrics_servicemonitor_present":                {"boolean"},
	"component.cert_manager.metrics_podmonitor_present":                    {"boolean"},
	"component.cert_manager.metrics_scrape_port_present":                   {"boolean"},
	"component.cert_manager.metrics_scrape_path_present":                   {"boolean"},
	"component.cert_manager.health_desired_count":                          {"integer"},
	"component.cert_manager.health_ready_count":                            {"integer"},
	"component.cert_manager.health_available_count":                        {"integer"},
	"component.cilium.ipv4_enabled":                                        {"boolean"},
	"component.cilium.ipv6_enabled":                                        {"boolean"},
	"component.cilium.k8s_network_policy_enabled":                          {"boolean"},
	"component.cilium.bpf_masquerade_enabled":                              {"boolean"},
	"component.gateway.enabled":                                            {"boolean"},
}

// IsRegisteredPredicate exposes the closed registry to the decision layer
// without exposing mutable registry state.
func IsRegisteredPredicate(id string) bool { _, ok := predicateRegistry[id]; return ok }

var omissionRegistry = map[string]struct{}{
	"COMPONENT_CONFIGURATION_VERSION_UNRESOLVED": {},
	"COMPONENT_CONFIGURATION_ARGS_MALFORMED":     {}, "COMPONENT_CONFIGURATION_ARGS_UNAVAILABLE": {},
	"COMPONENT_CONFIGURATION_COMMAND_SURFACE_UNAVAILABLE": {}, "COMPONENT_CONFIGURATION_IDENTITY_UNRESOLVED": {},
	"COMPONENT_CONFIGURATION_DECLARED_ROLE_UNAVAILABLE": {}, "COMPONENT_CONFIGURATION_DECLARED_ROLE_AMBIGUOUS": {},
	"COMPONENT_CONFIGURATION_NO_REGULAR_CONTAINERS": {}, "COMPONENT_CONFIGURATION_PREDICATE_CONFLICT": {},
	"COMPONENT_CONFIGURATION_PREDICATE_MALFORMED": {}, "COMPONENT_CONFIGURATION_WORKLOAD_ROLE_UNSUPPORTED": {},
	"API_READ_FAILED":     {},
	"PROVIDER_UNOBSERVED": {}, "DISTRIBUTION_UNOBSERVED": {},
	"NODE_PROFILE_UNOBSERVED": {}, "UNSUPPORTED_SURFACES_NOT_PROJECTED": {},
	"COMPONENT_CONFIGURATION_PREDICATE_UNOBSERVED": {}, "COMPONENT_CONFIGURATION_API_UNAVAILABLE": {},
	"COMPONENT_CONFIGURATION_RBAC_FORBIDDEN": {}, "COMPONENT_CONFIGURATION_CRD_SURFACE_UNAVAILABLE": {},
	"COMPONENT_CONFIGURATION_INSTALL_MODE_UNKNOWN": {}, "COMPONENT_CONFIGURATION_HEALTH_UNAVAILABLE": {},
	"COMPONENT_CONFIGURATION_OUTPUT_LIMIT_EXCEEDED":                                         {},
	"COMPONENT_CONFIGURATION_KUBERNETES_API_READ_FAILED":                                    {},
	"COMPONENT_CONFIGURATION_KUBERNETES_API_READ_FAILED_AUTHENTICATION_EXEC_PLUGIN_FAILURE": {},
	"COMPONENT_CONFIGURATION_KUBERNETES_API_READ_FAILED_AUTHORIZATION_RBAC_FORBIDDEN":       {},
	"COMPONENT_CONFIGURATION_KUBERNETES_API_READ_FAILED_DNS":                                {},
	"COMPONENT_CONFIGURATION_KUBERNETES_API_READ_FAILED_INVALID_KUBECONFIG_CONTEXT":         {},
	"COMPONENT_CONFIGURATION_KUBERNETES_API_READ_FAILED_TLS_CERTIFICATE":                    {},
	"COMPONENT_CONFIGURATION_KUBERNETES_API_READ_FAILED_TRANSPORT_TIMEOUT_UNREACHABLE":      {},
	"COMPONENT_CONFIGURATION_KUBERNETES_API_READ_FAILED_UNAUTHORIZED":                       {},
	"COMPONENT_CONFIGURATION_KUBERNETES_API_READ_FAILED_UNSUPPORTED_NOT_FOUND_API":          {},
	"COMPONENT_CONFIGURATION_PIPELINE_FAILED":                                               {}, "COMPONENT_CONFIGURATION_PROJECTION_FILTER_REJECTED": {},
	"COMPONENT_CONFIGURATION_STRICT_JSON_REJECTED":           {},
	"COMPONENT_CONFIGURATION_ENTRYPOINT_VERSION_UNSUPPORTED": {},
	"COMPONENT_CONFIGURATION_IMAGE_BINDING_UNVERIFIED":       {},
	"COMPONENT_CONFIGURATION_INIT_CONTAINERS_IGNORED":        {},
	"KUBERNETES_VERSION_UNOBSERVED":                          {},
}

var (
	digestRE      = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	componentIDRE = regexp.MustCompile(`^pkg:oci/[a-z0-9][a-z0-9._-]*/[a-z0-9][a-z0-9._-]*$`)
	roleRE        = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_.-]{0,63}$`)
	versionRE     = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$`)
)

var allowedRoles = map[string]struct{}{"DaemonSet": {}, "StatefulSet": {}, "ReplicaSet": {}, "CronJob": {}, "ReplicationController": {}, "Deployment": {}, "Job": {}, "server": {}, "controller": {}, "application-controller": {}, "repo-server": {}, "workflow-controller": {}, "webhook": {}, "cainjector": {}}

var (
	ErrInvalid   = observation.ErrInvalid
	ErrIntegrity = observation.ErrIntegrity
	ErrAmbiguous = observation.ErrAmbiguous
	ErrIO        = errors.New("current bundle local I/O failure")
)

// CurrentBundle is a closed canonical schema. BundleDigest is derived from
// the same value with BundleDigest cleared; callers must not hand-edit it.
type CurrentBundle struct {
	APIVersion               string           `json:"apiVersion"`
	Kind                     string           `json:"kind"`
	Schema                   string           `json:"schema"`
	PredicateRegistryVersion string           `json:"predicateRegistryVersion"`
	OmissionRegistryVersion  string           `json:"omissionRegistryVersion"`
	BundleDigest             string           `json:"bundleDigest,omitempty"`
	Revision                 string           `json:"revision"`
	CapturedAt               string           `json:"capturedAt,omitempty"`
	Target                   TargetIdentity   `json:"target"`
	Assurance                AssuranceState   `json:"assurance"`
	Environment              Environment      `json:"environment"`
	Planes                   EvidencePlanes   `json:"planes"`
	Sources                  []SourceBinding  `json:"sources"`
	Adapters                 []AdapterBinding `json:"adapters"`
	Collector                CollectorBinding `json:"collector"`
	Freshness                FreshnessBinding `json:"freshness"`
	Conflicts                []Conflict       `json:"conflicts"`
	Omissions                []Omission       `json:"omissions"`
	// Source metadata is internal provenance carried from observation.Import;
	// json remains the closed canonical current-bundle contract.
	SourceGeneratedAt         string   `json:"-"`
	SourceGeneratedAtValid    bool     `json:"-"`
	SourceGeneratedAtConflict bool     `json:"-"`
	SourceCollectionStatus    string   `json:"-"`
	SourceOmissionCodes       []string `json:"-"`
	// Synthetic is durable source provenance. Downstream authority/admission
	// sinks must reject it before interpreting any decision value.
	Synthetic *observation.SyntheticProvenance `json:"syntheticProvenance,omitempty"`
}

type TargetIdentity struct {
	Fingerprint string `json:"fingerprint"`
	State       string `json:"state"` // exact|unknown
}

type AssuranceState struct {
	Class              string `json:"class"`
	EvaluationEligible bool   `json:"evaluationEligible"`
}

type Environment struct {
	Provider         FieldValue `json:"provider"`
	Distribution     FieldValue `json:"distribution"`
	Kubernetes       FieldValue `json:"kubernetesVersion"`
	NodeOS           FieldValue `json:"nodeOS"`
	Kernel           FieldValue `json:"kernel"`
	Architecture     FieldValue `json:"architecture"`
	ContainerRuntime FieldValue `json:"containerRuntime"`
}

type FieldValue struct {
	State  string      `json:"state"` // observed|declared|derived|missing|unknown|conflict
	Value  string      `json:"value,omitempty"`
	Source []SourceRef `json:"source,omitempty"`
}

type EvidencePlanes struct {
	Observed EvidencePlane `json:"observed"`
	Declared EvidencePlane `json:"declared"`
	Derived  EvidencePlane `json:"derived"`
	Unknown  UnknownPlane  `json:"unknown"`
}

type EvidencePlane struct {
	Status     string               `json:"status"` // supplied|not_supplied|not_derived
	Components []CanonicalComponent `json:"components"`
}

type UnknownPlane struct {
	Status     string         `json:"status"`
	Components []UnknownValue `json:"components"`
}

type UnknownValue struct {
	ComponentID string   `json:"componentId"`
	Reasons     []string `json:"reasons"`
}

type CanonicalComponent struct {
	ComponentID string               `json:"componentId"`
	Version     VersionIdentity      `json:"version"`
	Artifact    ArtifactIdentity     `json:"artifact"`
	Roles       []string             `json:"roles"`
	Predicates  []CanonicalPredicate `json:"predicates"`
	Sources     []SourceRef          `json:"source"`
}

type VersionIdentity struct {
	State string `json:"state"` // exact|unknown|conflict
	Value string `json:"value,omitempty"`
}

type ArtifactIdentity struct {
	State string `json:"state"` // exact|unknown|conflict
	Value string `json:"value,omitempty"`
}

type CanonicalPredicate struct {
	ID            string          `json:"id"`
	State         string          `json:"state"`
	SourceRole    string          `json:"sourceRole,omitempty"`
	EvidenceClass string          `json:"evidenceClass,omitempty"`
	Value         json.RawMessage `json:"value,omitempty"`
	Sources       []SourceRef     `json:"source"`
}

type SourceRef struct {
	PathClass string `json:"pathClass"`
	Digest    string `json:"digest"`
}

type SourceBinding struct {
	PathClass string `json:"pathClass"`
	Digest    string `json:"digest"`
}

type AdapterBinding struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type CollectorBinding struct {
	Profile        string `json:"profile"`
	NetworkUsed    bool   `json:"networkUsed"`
	SubprocessUsed bool   `json:"subprocessUsed"`
	ClusterUsed    bool   `json:"clusterUsed"`
}

type FreshnessBinding struct {
	State         string `json:"state"` // fresh|stale|unknown
	CapturedAt    string `json:"capturedAt,omitempty"`
	PolicyID      string `json:"policyId,omitempty"`
	MaxAgeSeconds int64  `json:"maxAgeSeconds,omitempty"`
}

type Omission struct {
	Code                  string   `json:"code"`
	Scope                 string   `json:"scope"`
	PathClass             string   `json:"pathClass,omitempty"`
	Sources               []string `json:"sourceDigests,omitempty"`
	Reason                string   `json:"reason,omitempty"`
	RequiredForEvaluation bool     `json:"requiredForEvaluation,omitempty"`
	SourceFile            string   `json:"sourceFile,omitempty"`
	Count                 int      `json:"count,omitempty"`
}

type Conflict struct {
	ComponentID string   `json:"componentId"`
	Kind        string   `json:"kind"`
	Values      []string `json:"values"`
}

// Disclosure is a bounded receipt. SourcePaths are fixed relative classes,
// never customer-controlled or absolute paths.
type Disclosure struct {
	Profile         string   `json:"profile"`
	SourceCount     int      `json:"sourceCount"`
	SourcePaths     []string `json:"sourcePaths"`
	SourceDigests   []string `json:"sourceDigests"`
	OmissionCount   int      `json:"omissionCount"`
	ConflictCount   int      `json:"conflictCount"`
	UnknownCount    int      `json:"unknownCount"`
	FreshnessStatus string   `json:"freshnessStatus"`
	RawDataRetained bool     `json:"rawDataRetained"`
	NetworkUsed     bool     `json:"networkUsed"`
	SubprocessUsed  bool     `json:"subprocessUsed"`
	ClusterUsed     bool     `json:"clusterUsed"`
}

type DisclosureSummary = Disclosure

// Options supplies replay inputs for freshness. No wall clock is read by the
// package; a zero value intentionally produces an explicit UNKNOWN freshness.
type Options struct {
	CapturedAt      time.Time
	Now             time.Time
	FreshnessPolicy FreshnessPolicy
	// RequireSourceCapture requires a verified, matching index/metadata
	// timestamp. It is used by snapshot-to-current seams that must not permit
	// a caller to relabel source age.
	RequireSourceCapture bool
}

type FreshnessPolicy struct {
	ID     string
	MaxAge time.Duration
}

// Artifact is the deterministic canonical result. Digest and BundleDigest
// are the digest of canonical bundle bytes with bundleDigest excluded.
type Artifact struct {
	Bundle     CurrentBundle `json:"bundle"`
	Bytes      []byte        `json:"-"`
	Digest     string        `json:"digest"`
	Disclosure Disclosure    `json:"disclosure"`
}

// ImportObservation converts one descriptor-owned observation into the
// explicit canonical schema without retaining or closing the capability.
func ImportObservation(ctx context.Context, root *observation.Root, options Options) (CurrentBundle, error) {
	if err := validateOptions(options); err != nil {
		return CurrentBundle{}, err
	}
	projected, err := observation.Import(ctx, root, observation.ImportOptions{})
	if err != nil {
		if errors.Is(err, observation.ErrInvalid) || errors.Is(err, observation.ErrIntegrity) || errors.Is(err, observation.ErrAmbiguous) || errors.Is(err, observation.ErrCancelled) || errors.Is(err, observation.ErrUnsupportedPlatform) {
			return CurrentBundle{}, err
		}
		return CurrentBundle{}, fmt.Errorf("observation I/O: %w: %v", ErrIO, err)
	}
	return importProjected(projected, options)
}

// BuildObservationWithProjection imports the descriptor-owned observation
// exactly once and returns both the canonical artifact and the exact
// projection used to build it. This is intentionally a narrow owner bridge
// for synthetic factory receipt verification; callers receive no path or
// mutable authority token.
func BuildObservationWithProjection(ctx context.Context, root *observation.Root, options Options) (Artifact, observation.CurrentBundle, error) {
	if err := validateOptions(options); err != nil {
		return Artifact{}, observation.CurrentBundle{}, err
	}
	projected, err := observation.Import(ctx, root, observation.ImportOptions{})
	if err != nil {
		if errors.Is(err, observation.ErrInvalid) || errors.Is(err, observation.ErrIntegrity) || errors.Is(err, observation.ErrAmbiguous) || errors.Is(err, observation.ErrCancelled) || errors.Is(err, observation.ErrUnsupportedPlatform) {
			return Artifact{}, observation.CurrentBundle{}, err
		}
		return Artifact{}, observation.CurrentBundle{}, fmt.Errorf("observation I/O: %w: %v", ErrIO, err)
	}
	bundle, err := importProjected(projected, options)
	if err != nil {
		return Artifact{}, observation.CurrentBundle{}, err
	}
	data, err := Marshal(bundle)
	if err != nil {
		return Artifact{}, observation.CurrentBundle{}, err
	}
	digest, err := Digest(bundle)
	if err != nil || digest != bundle.BundleDigest {
		return Artifact{}, observation.CurrentBundle{}, fmt.Errorf("bundle digest binding: %w", ErrIntegrity)
	}
	return Artifact{Bundle: bundle, Bytes: append([]byte(nil), data...), Digest: digest, Disclosure: disclosure(bundle)}, projected, nil
}

func importProjected(projected observation.CurrentBundle, options Options) (CurrentBundle, error) {
	if options.RequireSourceCapture {
		if projected.SourceGeneratedAtConflict {
			return CurrentBundle{}, fmt.Errorf("source capture timestamps conflict: %w", ErrIntegrity)
		}
		if !projected.SourceGeneratedAtValid {
			return CurrentBundle{}, fmt.Errorf("source capture timestamp is missing or invalid: %w", ErrInvalid)
		}
		if options.CapturedAt.IsZero() || options.Now.IsZero() {
			return CurrentBundle{}, fmt.Errorf("source freshness binding requires explicit times: %w", ErrInvalid)
		}
		if options.CapturedAt.UTC().Format(time.RFC3339Nano) != projected.SourceGeneratedAt {
			return CurrentBundle{}, fmt.Errorf("caller capture time does not match source: %w", ErrIntegrity)
		}
		if sourceTime, err := time.Parse(time.RFC3339Nano, projected.SourceGeneratedAt); err != nil || sourceTime.After(options.Now) {
			return CurrentBundle{}, fmt.Errorf("source capture time is in the future: %w", ErrInvalid)
		}
	}
	if options.RequireSourceCapture {
		options.CapturedAt, _ = time.Parse(time.RFC3339Nano, projected.SourceGeneratedAt)
	}
	bundle, err := convert(projected, options)
	if err != nil {
		return CurrentBundle{}, err
	}
	if err := validateBundle(bundle); err != nil {
		return CurrentBundle{}, err
	}
	if err := canonicalize(&bundle); err != nil {
		return CurrentBundle{}, err
	}
	digest, err := Digest(bundle)
	if err != nil {
		return CurrentBundle{}, err
	}
	bundle.BundleDigest = digest
	return bundle, nil
}

// BuildObservation imports and emits canonical full bytes plus its digest and
// disclosure. Path resolution remains the caller's boundary responsibility.
func BuildObservation(ctx context.Context, root *observation.Root, options Options) (Artifact, error) {
	bundle, err := ImportObservation(ctx, root, options)
	if err != nil {
		return Artifact{}, err
	}
	data, err := Marshal(bundle)
	if err != nil {
		return Artifact{}, err
	}
	digest, err := Digest(bundle)
	if err != nil || digest != bundle.BundleDigest {
		return Artifact{}, fmt.Errorf("bundle digest binding: %w", ErrIntegrity)
	}
	return Artifact{Bundle: bundle, Bytes: append([]byte(nil), data...), Digest: digest, Disclosure: disclosure(bundle)}, nil
}

// ReadBoundedFile reads one already-materialized contract using the same
// descriptor-relative, no-follow path walk as persisted artifacts. It is
// intentionally byte-only: callers must decode and validate the returned
// bytes against their own closed schema.
func ReadBoundedFile(path string, limit int) (result []byte, err error) {
	result, _, err = ReadBoundedFileInfo(path, limit)
	return result, err
}

// ReadBoundedFileInfo is the descriptor-retaining variant used by trust
// loaders. The returned FileInfo is the post-read fstat of the same secure
// descriptor that supplied result; callers must not reopen pathnames to check
// identity, mode, ownership, or link count.
func ReadBoundedFileInfo(path string, limit int) (result []byte, info os.FileInfo, err error) {
	if !validArtifactPath(path) || limit <= 0 || limit > maxBundleBytes {
		return nil, nil, fmt.Errorf("invalid bounded input: %w", ErrInvalid)
	}
	file, err := openArtifactFile(path, os.O_RDONLY, 0)
	if err != nil {
		return nil, nil, fmt.Errorf("open bounded input: %w", ErrInvalid)
	}
	defer func() {
		if closeErr := file.Close(); closeErr != nil {
			if err == nil {
				result = nil
				info = nil
				err = fmt.Errorf("close bounded input: %w", ErrIntegrity)
			} else {
				err = fmt.Errorf("%w; close bounded input: %v", err, closeErr)
			}
		}
	}()
	before, err := file.Stat()
	if err != nil || !before.Mode().IsRegular() || before.Size() < 0 || before.Size() > int64(limit) || artifactLinkCount(before) != 1 {
		return nil, nil, fmt.Errorf("invalid bounded input file: %w", ErrInvalid)
	}
	b, err := io.ReadAll(io.LimitReader(file, int64(limit)+1))
	if err != nil || len(b) > limit {
		return nil, nil, fmt.Errorf("bounded input read: %w", ErrInvalid)
	}
	after, err := file.Stat()
	if err != nil || !os.SameFile(before, after) || !artifactChangeTimesMatch(before, after) || artifactLinkCount(after) != 1 || after.Size() != before.Size() || int64(len(b)) != after.Size() {
		return nil, nil, fmt.Errorf("bounded input changed during read: %w", ErrIntegrity)
	}
	return b, after, nil
}

// ReadArtifact reads one persisted canonical artifact with descriptor-relative
// identity, no-follow, hardlink, and bounded-size checks.
func ReadArtifact(path string) (result Artifact, err error) {
	if !validArtifactPath(path) {
		return Artifact{}, fmt.Errorf("invalid artifact path: %w", ErrInvalid)
	}
	file, err := openArtifactFile(path, os.O_RDONLY, 0)
	if err != nil {
		return Artifact{}, fmt.Errorf("open artifact: %w", ErrInvalid)
	}
	defer func() {
		if closeErr := file.Close(); closeErr != nil {
			if err == nil {
				result = Artifact{}
				err = fmt.Errorf("close artifact: %w", ErrIntegrity)
			} else {
				err = fmt.Errorf("%w; close artifact: %v", err, closeErr)
			}
		}
	}()
	before, err := file.Stat()
	if err != nil || !before.Mode().IsRegular() || before.Size() <= 0 || before.Size() > maxBundleBytes || artifactLinkCount(before) != 1 {
		return Artifact{}, fmt.Errorf("invalid artifact file: %w", ErrInvalid)
	}
	data, err := io.ReadAll(io.LimitReader(file, maxBundleBytes+1))
	if err != nil || len(data) == 0 || len(data) > maxBundleBytes {
		return Artifact{}, fmt.Errorf("read artifact: %w", ErrInvalid)
	}
	after, err := file.Stat()
	if err != nil || !os.SameFile(before, after) || artifactLinkCount(after) != 1 || after.Size() != before.Size() || int64(len(data)) != after.Size() {
		return Artifact{}, fmt.Errorf("artifact changed during read: %w", ErrIntegrity)
	}
	bundle, err := decodeBundle(data)
	if err != nil {
		return Artifact{}, err
	}
	digest, err := Digest(bundle)
	if err != nil {
		return Artifact{}, err
	}
	a := Artifact{Bundle: bundle, Bytes: append([]byte(nil), data...), Digest: digest, Disclosure: disclosure(bundle)}
	if err := ValidateArtifact(a); err != nil {
		return Artifact{}, err
	}
	return a, nil
}

// WriteArtifact persists exact canonical bytes after full validation.
func WriteArtifact(path string, artifact Artifact) (err error) {
	if !validArtifactPath(path) {
		return fmt.Errorf("invalid artifact path: %w", ErrInvalid)
	}
	if err := ValidateArtifact(artifact); err != nil {
		return err
	}
	file, err := openArtifactFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return fmt.Errorf("open artifact output: %w", ErrInvalid)
	}
	defer func() {
		if closeErr := file.Close(); closeErr != nil {
			if err == nil {
				err = fmt.Errorf("close artifact output: %w", ErrIntegrity)
			} else {
				err = fmt.Errorf("%w; close artifact output: %v", err, closeErr)
			}
		}
	}()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || artifactLinkCount(info) != 1 {
		return fmt.Errorf("invalid artifact output: %w", ErrInvalid)
	}
	if err := file.Chmod(0o600); err != nil {
		return fmt.Errorf("secure artifact output: %w", ErrInvalid)
	}
	if err := file.Truncate(0); err != nil {
		return fmt.Errorf("truncate artifact output: %w", ErrInvalid)
	}
	if _, err := file.Write(artifact.Bytes); err != nil {
		return fmt.Errorf("write artifact: %w", ErrInvalid)
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("sync artifact: %w", ErrInvalid)
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("verify artifact: %w", ErrIntegrity)
	}
	check, err := io.ReadAll(io.LimitReader(file, maxBundleBytes+1))
	if err != nil || !bytes.Equal(check, artifact.Bytes) {
		return fmt.Errorf("artifact write verification: %w", ErrIntegrity)
	}
	after, err := file.Stat()
	if err != nil || !os.SameFile(info, after) || artifactLinkCount(after) != 1 || after.Size() != int64(len(artifact.Bytes)) {
		return fmt.Errorf("artifact identity changed: %w", ErrIntegrity)
	}
	return nil
}

// Write is the short persisted-artifact alias; unlike Build it never imports
// an observation directory and only accepts an already validated artifact.
func Write(path string, artifact Artifact) error { return WriteArtifact(path, artifact) }

func validArtifactPath(path string) bool {
	return path != "" && strings.IndexByte(path, 0) < 0 && !strings.HasSuffix(path, string(filepath.Separator))
}

func decodeBundle(data []byte) (CurrentBundle, error) {
	if !utf8.Valid(data) {
		return CurrentBundle{}, fmt.Errorf("decode artifact UTF-8: %w", ErrInvalid)
	}
	if err := validateJSONTokens(data); err != nil {
		class := ErrInvalid
		if errors.Is(err, errJSONDuplicateKey) {
			class = ErrIntegrity
		}
		return CurrentBundle{}, fmt.Errorf("decode artifact: %w", class)
	}
	var bundle CurrentBundle
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&bundle); err != nil {
		return CurrentBundle{}, fmt.Errorf("decode artifact: %w", ErrInvalid)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return CurrentBundle{}, fmt.Errorf("trailing artifact data: %w", ErrInvalid)
	}
	return bundle, nil
}

// validateJSONTokens performs the structural checks that encoding/json does
// not provide. In particular, encoding/json accepts the last value for a
// duplicate object key; persisted canonical artifacts reject duplicates at
// every nesting level before typed decoding. The token walk is bounded so a
// malformed artifact cannot create an unbounded object/array traversal.
func validateJSONTokens(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := consumeJSONValue(decoder, 0); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		if err == nil {
			return errors.New("trailing JSON value")
		}
		return err
	}
	return nil
}

func consumeJSONValue(decoder *json.Decoder, depth int) error {
	if depth > maxJSONDepth {
		return errors.New("JSON depth exceeds bound")
	}
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delimiter {
	case '[':
		for count := 0; decoder.More(); count++ {
			if count >= maxArrayItems {
				return errors.New("JSON array exceeds bound")
			}
			if err := consumeJSONValue(decoder, depth+1); err != nil {
				return err
			}
		}
	case '{':
		seen := make(map[string]struct{})
		for count := 0; decoder.More(); count++ {
			if count >= maxJSONMembers {
				return errors.New("JSON object exceeds bound")
			}
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return errors.New("JSON object key is not a string")
			}
			if _, duplicate := seen[key]; duplicate {
				return errJSONDuplicateKey
			}
			seen[key] = struct{}{}
			if err := consumeJSONValue(decoder, depth+1); err != nil {
				return err
			}
		}
	default:
		return errors.New("unexpected JSON delimiter")
	}
	closeDelimiter, err := decoder.Token()
	if err != nil {
		return err
	}
	want := json.Delim(']')
	if delimiter == '{' {
		want = json.Delim('}')
	}
	if closeDelimiter != want {
		return errors.New("mismatched JSON delimiter")
	}
	return nil
}

// Marshal emits deterministic JSON after deep-copying and canonicalizing the
// input. It does not mutate caller-owned slices or RawMessage values.
func Marshal(bundle CurrentBundle) ([]byte, error) {
	clone := cloneBundle(bundle)
	if err := canonicalize(&clone); err != nil {
		return nil, err
	}
	return marshalCanonicalValue(clone)
}

func MarshalCanonical(bundle CurrentBundle) ([]byte, error) { return Marshal(bundle) }

// Digest computes the content digest with bundleDigest excluded.
func Digest(bundle CurrentBundle) (string, error) {
	clone := cloneBundle(bundle)
	clone.BundleDigest = ""
	if err := canonicalize(&clone); err != nil {
		return "", err
	}
	data, err := marshalCanonicalValue(clone)
	if err != nil {
		return "", err
	}
	return DigestBytes(data), nil
}

func DigestBytes(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func marshalCanonicalValue(value any) ([]byte, error) {
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buffer.Bytes(), []byte{'\n'}), nil
}

func convert(source observation.CurrentBundle, options Options) (CurrentBundle, error) {
	predicateRegistryVersion := PredicateRegistryVersion
	observationAdapterVersion := currentBundleAdapterV2
	if source.ConfigurationAdapterVersion != "" {
		if source.ConfigurationAdapterVersion != configurationAdapterV3 {
			return CurrentBundle{}, fmt.Errorf("unsupported configuration adapter version: %w", ErrInvalid)
		}
		predicateRegistryVersion = PredicateRegistryVersionV2
		observationAdapterVersion = currentBundleAdapterV3
	}
	digests := append([]string(nil), source.SourceDigests...)
	sort.Strings(digests)
	revisionBytes, _ := json.Marshal(digests)
	revision := DigestBytes(revisionBytes)
	components := make([]CanonicalComponent, 0, len(source.Components))
	unknown := make([]UnknownValue, 0)
	for _, item := range source.Components {
		version := VersionIdentity{State: "unknown"}
		if item.Status == "conflict" {
			version.State = "conflict"
		} else if item.Version != "" {
			version = VersionIdentity{State: "exact", Value: item.Version}
		}
		predicates := make([]CanonicalPredicate, 0, len(item.Predicates))
		for _, predicate := range item.Predicates {
			definition, ok := predicateRegistry[predicate.ID]
			if !ok || !predicateAllowedInRegistry(predicate.ID, predicateRegistryVersion) {
				// This is a privacy boundary: silently dropping an unknown would
				// make the evaluation projection appear complete.
				return CurrentBundle{}, fmt.Errorf("unregistered predicate: %w", ErrInvalid)
			}
			state := predicate.State
			if state == "" {
				state = "observed"
			}
			value := append([]byte(nil), predicate.Value...)
			evidenceClass := predicate.EvidenceClass
			if source.Synthetic != nil && evidenceClass == "" && predicate.Role != "" {
				evidenceClass = "synthetic_fixture_context_v1"
			}
			if item.Status == "conflict" && state == "observed" {
				state, value = "conflict", nil
			}
			if state != "observed" {
				value = nil
			}
			if state == "observed" && !validPredicateValue(predicate.ID, definition, value) {
				return CurrentBundle{}, fmt.Errorf("predicate value type: %w", ErrInvalid)
			}
			predicates = append(predicates, CanonicalPredicate{ID: predicate.ID, State: state, SourceRole: predicate.Role, EvidenceClass: evidenceClass, Value: value, Sources: sourceRefs(predicate.SourceDigests)})
		}
		componentRefs := sourceRefs(item.SourceDigests)
		component := CanonicalComponent{ComponentID: item.ComponentID, Version: version,
			Artifact: ArtifactIdentity{State: "exact", Value: item.ComponentID}, Roles: append([]string(nil), item.Roles...), Predicates: predicates, Sources: componentRefs}
		components = append(components, component)
		if version.State != "exact" {
			unknown = append(unknown, UnknownValue{ComponentID: item.ComponentID, Reasons: []string{"VERSION_NOT_EXACT"}})
		}
	}
	omissions := make([]Omission, 0, len(source.Omissions)+8)
	conflicts := make([]Conflict, 0, len(source.Conflicts))
	for _, item := range source.Conflicts {
		conflicts = append(conflicts, Conflict{ComponentID: item.ComponentID, Kind: item.Kind, Values: append([]string(nil), item.Values...)})
	}
	for _, item := range source.Omissions {
		if _, ok := omissionRegistry[item.Code]; !ok {
			return CurrentBundle{}, fmt.Errorf("unregistered omission: %w", ErrInvalid)
		}
		omissions = append(omissions, Omission{Code: item.Code, Scope: "observation", Sources: append([]string(nil), digests...), Reason: item.Reason, RequiredForEvaluation: item.RequiredForEvaluation, SourceFile: item.SourceFile, Count: item.Count})
	}
	// These source files/surfaces are not represented by observation.CurrentBundle
	// and therefore remain explicit unknowns instead of a false complete claim.
	for _, code := range []string{"PROVIDER_UNOBSERVED", "DISTRIBUTION_UNOBSERVED", "NODE_PROFILE_UNOBSERVED", "UNSUPPORTED_SURFACES_NOT_PROJECTED"} {
		omissions = append(omissions, Omission{Code: code, Scope: "environment", Sources: append([]string(nil), digests...)})
	}
	fresh := freshness(options)
	kubernetes := FieldValue{State: "observed", Value: source.KubernetesVersion, Source: sourceRefs(source.KubernetesSourceDigests)}
	if source.KubernetesVersion == "" {
		kubernetes = fieldUnknown("KUBERNETES_VERSION_UNOBSERVED")
	}
	return CurrentBundle{
		APIVersion: APIVersion, Kind: Kind, Schema: Schema, PredicateRegistryVersion: predicateRegistryVersion, OmissionRegistryVersion: OmissionRegistryVersion, Revision: revision, CapturedAt: fresh.CapturedAt,
		Target:    TargetIdentity{Fingerprint: revision, State: "exact"},
		Assurance: AssuranceState{Class: Assurance, EvaluationEligible: false},
		Environment: Environment{
			Provider: fieldUnknown("PROVIDER_UNOBSERVED"), Distribution: fieldUnknown("DISTRIBUTION_UNOBSERVED"),
			Kubernetes: kubernetes,
			NodeOS:     fieldUnknown("NODE_PROFILE_UNOBSERVED"), Kernel: fieldUnknown("NODE_PROFILE_UNOBSERVED"),
			Architecture: fieldUnknown("NODE_PROFILE_UNOBSERVED"), ContainerRuntime: fieldUnknown("NODE_PROFILE_UNOBSERVED"),
		},
		Planes: EvidencePlanes{
			Observed: EvidencePlane{Status: "supplied", Components: components},
			Declared: EvidencePlane{Status: "not_supplied", Components: []CanonicalComponent{}},
			Derived:  EvidencePlane{Status: "not_derived", Components: []CanonicalComponent{}},
			Unknown:  UnknownPlane{Status: "explicit", Components: unknown},
		},
		Sources: sourceBindings(digests), Adapters: adapterBindings(source, observationAdapterVersion),
		Collector: CollectorBinding{Profile: "local-observation"},
		Freshness: fresh, Conflicts: conflicts, Omissions: omissions,
		SourceGeneratedAt: source.SourceGeneratedAt, SourceGeneratedAtValid: source.SourceGeneratedAtValid,
		SourceGeneratedAtConflict: source.SourceGeneratedAtConflict, SourceCollectionStatus: source.SourceCollectionStatus,
		SourceOmissionCodes: append([]string(nil), source.SourceOmissionCodes...),
		Synthetic:           source.Synthetic,
	}, nil
}

// ImageSourcesDigestAdapter is the adapter name under which a bundle records
// the digest of the reviewed image registry that produced its image rows (the
// schema is recorded beside it in the collection metadata and is part of the
// digested bytes).
const ImageSourcesDigestAdapter = "image-source-registry"

func adapterBindings(source observation.CurrentBundle, observationAdapterVersion string) []AdapterBinding {
	adapters := []AdapterBinding{{Name: "observation-to-current-bundle", Version: observationAdapterVersion}}
	if source.CertManagerProjectionDigest != "" {
		adapters = append(adapters, AdapterBinding{Name: "cert-manager-projection", Version: source.CertManagerProjectionDigest})
	}
	if source.ImageSourcesDigest != "" {
		adapters = append(adapters, AdapterBinding{Name: ImageSourcesDigestAdapter, Version: source.ImageSourcesDigest})
	}
	return adapters
}

func fieldUnknown(code string) FieldValue {
	return FieldValue{State: "unknown", Source: []SourceRef{{PathClass: "omission:" + code}}}
}

func freshness(options Options) FreshnessBinding {
	result := FreshnessBinding{State: "unknown"}
	if options.CapturedAt.IsZero() || options.Now.IsZero() || options.FreshnessPolicy.ID == "" || options.FreshnessPolicy.MaxAge <= 0 {
		return result
	}
	if options.CapturedAt.After(options.Now) {
		result.CapturedAt, result.PolicyID, result.MaxAgeSeconds = options.CapturedAt.UTC().Format(time.RFC3339Nano), options.FreshnessPolicy.ID, int64(options.FreshnessPolicy.MaxAge/time.Second)
		return result
	}
	result.CapturedAt, result.PolicyID, result.MaxAgeSeconds = options.CapturedAt.UTC().Format(time.RFC3339Nano), options.FreshnessPolicy.ID, int64(options.FreshnessPolicy.MaxAge/time.Second)
	if options.Now.Sub(options.CapturedAt) <= options.FreshnessPolicy.MaxAge {
		result.State = "fresh"
	} else {
		result.State = "stale"
	}
	return result
}

func validateOptions(options Options) error {
	anyCapture := !options.CapturedAt.IsZero() || !options.Now.IsZero()
	anyPolicy := options.FreshnessPolicy.ID != "" || options.FreshnessPolicy.MaxAge != 0
	if !anyCapture && !anyPolicy {
		return nil
	}
	if options.CapturedAt.IsZero() || options.Now.IsZero() || !validPolicyID(options.FreshnessPolicy.ID) || options.FreshnessPolicy.MaxAge <= 0 || options.FreshnessPolicy.MaxAge%time.Second != 0 || options.FreshnessPolicy.MaxAge/time.Second > maxFreshnessAgeSeconds {
		return fmt.Errorf("invalid freshness options: %w", ErrInvalid)
	}
	return nil
}

func validPolicyID(id string) bool {
	if len(id) == 0 || len(id) > maxPolicyIDBytes || strings.IndexByte(id, 0) >= 0 {
		return false
	}
	for _, r := range id {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' || r == '.') {
			return false
		}
	}
	return true
}

func isJSONString(raw []byte) bool {
	var value string
	return json.Unmarshal(raw, &value) == nil && len(value) <= 4096 && strings.IndexByte(value, 0) < 0
}

func isJSONBool(raw []byte) bool {
	var value bool
	return json.Unmarshal(raw, &value) == nil
}

func validPredicateValue(id string, definition predicateDefinition, raw []byte) bool {
	if definition.valueKind == "boolean" {
		return isJSONBool(raw)
	}
	if definition.valueKind == "integer" {
		var value json.Number
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.UseNumber()
		if err := decoder.Decode(&value); err != nil {
			return false
		}
		parsed, err := value.Int64()
		return err == nil && parsed >= 0 && parsed <= 1000000
	}
	if definition.valueKind != "string" || !isJSONString(raw) {
		return false
	}
	if id == "component.prometheus.log_level" {
		var value string
		if json.Unmarshal(raw, &value) != nil {
			return false
		}
		switch value {
		case "debug", "info", "warn", "error":
			return true
		default:
			return false
		}
	}
	if id == "component.cert_manager.install_mode" {
		var value string
		if json.Unmarshal(raw, &value) != nil {
			return false
		}
		switch value {
		case "helm", "static", "operator", "unknown":
			return true
		default:
			return false
		}
	}
	return true
}

func predicateAllowedInRegistry(id, registryVersion string) bool {
	if registryVersion != PredicateRegistryVersion && registryVersion != PredicateRegistryVersionV2 {
		return false
	}
	if id == prometheusAgentModePredicate || id == prometheusImageDigestPredicate {
		return registryVersion == PredicateRegistryVersionV2
	}
	_, ok := predicateRegistry[id]
	return ok
}

func sourceRefs(digests []string) []SourceRef {
	refs := make([]SourceRef, 0, len(digests))
	for _, digest := range digests {
		refs = append(refs, SourceRef{PathClass: "context/projection", Digest: digest})
	}
	return refs
}

func sourceBindings(digests []string) []SourceBinding {
	result := make([]SourceBinding, 0, len(digests))
	for _, digest := range digests {
		result = append(result, SourceBinding{PathClass: "context/projection", Digest: digest})
	}
	return result
}

func disclosure(bundle CurrentBundle) Disclosure {
	digests := make([]string, 0, len(bundle.Sources))
	for _, source := range bundle.Sources {
		digests = append(digests, source.Digest)
	}
	return Disclosure{Profile: "current-bundle-minimum-v1", SourceCount: len(digests), SourcePaths: []string{"index.json", "MANIFEST.sha256", "context/MANIFEST.sha256", "context/*.json", "context/omissions.tsv"}, SourceDigests: digests, OmissionCount: len(bundle.Omissions), ConflictCount: len(bundle.Conflicts), UnknownCount: len(bundle.Planes.Unknown.Components), FreshnessStatus: bundle.Freshness.State}
}

func validateBundle(bundle CurrentBundle) error {
	if bundle.APIVersion != APIVersion || bundle.Kind != Kind || bundle.Schema != Schema || bundle.Assurance.Class != Assurance || bundle.Assurance.EvaluationEligible {
		return fmt.Errorf("invalid canonical bundle envelope: %w", ErrInvalid)
	}
	if bundle.PredicateRegistryVersion != PredicateRegistryVersion && bundle.PredicateRegistryVersion != PredicateRegistryVersionV2 || bundle.OmissionRegistryVersion != OmissionRegistryVersion {
		return fmt.Errorf("unsupported registry version: %w", ErrInvalid)
	}
	if bundle.Synthetic != nil {
		if bundle.Synthetic.Classification != "PUBLIC_SYNTHETIC" || bundle.Synthetic.Authority != "SYNTHETIC_NON_AUTHORITATIVE_TEST_INPUT" || bundle.Synthetic.Canary != "PRUFYX_SYNTHETIC_NEVER_COMPATIBILITY_EVIDENCE" || !bundle.Synthetic.NonAuthoritative {
			return fmt.Errorf("invalid synthetic provenance: %w", ErrInvalid)
		}
		if bundle.Assurance.EvaluationEligible {
			return fmt.Errorf("synthetic bundle cannot be evaluation eligible: %w", ErrInvalid)
		}
	}
	if !digestRE.MatchString(bundle.Revision) || bundle.Target.Fingerprint != bundle.Revision || bundle.Target.State != "exact" {
		return fmt.Errorf("invalid canonical revision binding: %w", ErrInvalid)
	}
	if bundle.Environment.Kubernetes.State == "observed" {
		if !versionRE.MatchString(bundle.Environment.Kubernetes.Value) {
			return fmt.Errorf("missing Kubernetes version: %w", ErrInvalid)
		}
	} else if bundle.Environment.Kubernetes.State != "unknown" || bundle.Environment.Kubernetes.Value != "" {
		return fmt.Errorf("invalid Kubernetes version state: %w", ErrInvalid)
	}
	if len(bundle.Sources) == 0 || len(bundle.Sources) > maxSourceBindings || len(bundle.Omissions) > maxArrayItems || len(bundle.Conflicts) > maxArrayItems {
		return fmt.Errorf("bundle cardinality exceeds bound: %w", ErrInvalid)
	}
	knownSources := make(map[string]struct{}, len(bundle.Sources))
	for _, source := range bundle.Sources {
		if source.PathClass != "context/projection" || !digestRE.MatchString(source.Digest) {
			return fmt.Errorf("invalid source binding: %w", ErrInvalid)
		}
		if _, exists := knownSources[source.Digest]; exists {
			return fmt.Errorf("duplicate source binding: %w", ErrInvalid)
		}
		knownSources[source.Digest] = struct{}{}
	}
	revisionDigests := make([]string, 0, len(bundle.Sources))
	for digest := range knownSources {
		revisionDigests = append(revisionDigests, digest)
	}
	sort.Strings(revisionDigests)
	revisionBytes, _ := json.Marshal(revisionDigests)
	if DigestBytes(revisionBytes) != bundle.Revision {
		return fmt.Errorf("revision source binding mismatch: %w", ErrIntegrity)
	}
	refs := 0
	if err := validateField(bundle.Environment.Provider, knownSources); err != nil {
		return err
	}
	refs += len(bundle.Environment.Provider.Source)
	if err := validateField(bundle.Environment.Distribution, knownSources); err != nil {
		return err
	}
	refs += len(bundle.Environment.Distribution.Source)
	if err := validateField(bundle.Environment.Kubernetes, knownSources); err != nil {
		return err
	}
	refs += len(bundle.Environment.Kubernetes.Source)
	if err := validateField(bundle.Environment.NodeOS, knownSources); err != nil {
		return err
	}
	refs += len(bundle.Environment.NodeOS.Source)
	if err := validateField(bundle.Environment.Kernel, knownSources); err != nil {
		return err
	}
	refs += len(bundle.Environment.Kernel.Source)
	if err := validateField(bundle.Environment.Architecture, knownSources); err != nil {
		return err
	}
	refs += len(bundle.Environment.Architecture.Source)
	if err := validateField(bundle.Environment.ContainerRuntime, knownSources); err != nil {
		return err
	}
	refs += len(bundle.Environment.ContainerRuntime.Source)
	if refs > maxReferences {
		return fmt.Errorf("source reference cardinality exceeds bound: %w", ErrInvalid)
	}
	if bundle.Planes.Observed.Status != "supplied" || bundle.Planes.Declared.Status != "not_supplied" || bundle.Planes.Derived.Status != "not_derived" || bundle.Planes.Unknown.Status != "explicit" {
		return fmt.Errorf("invalid evidence plane status: %w", ErrInvalid)
	}
	if len(bundle.Planes.Declared.Components) != 0 || len(bundle.Planes.Derived.Components) != 0 {
		return fmt.Errorf("unsupported evidence plane data: %w", ErrInvalid)
	}
	if len(bundle.Planes.Observed.Components)+len(bundle.Planes.Declared.Components)+len(bundle.Planes.Derived.Components) > maxComponents || len(bundle.Planes.Unknown.Components) > maxComponents {
		return fmt.Errorf("component cardinality exceeds bound: %w", ErrInvalid)
	}
	seenComponents := map[string]struct{}{}
	for _, plane := range []*EvidencePlane{&bundle.Planes.Observed, &bundle.Planes.Declared, &bundle.Planes.Derived} {
		for _, component := range plane.Components {
			if err := validateComponent(component, bundle.PredicateRegistryVersion, knownSources, seenComponents, &refs); err != nil {
				return err
			}
		}
	}
	for _, unknown := range bundle.Planes.Unknown.Components {
		if !componentIDRE.MatchString(unknown.ComponentID) || len(unknown.Reasons) == 0 || len(unknown.Reasons) > maxReasons {
			return fmt.Errorf("invalid unknown component: %w", ErrInvalid)
		}
		for _, reason := range unknown.Reasons {
			if reason != "VERSION_NOT_EXACT" {
				return fmt.Errorf("unknown reason is not registered: %w", ErrInvalid)
			}
		}
	}
	observedVersions := make(map[string]string, len(bundle.Planes.Observed.Components))
	for _, component := range bundle.Planes.Observed.Components {
		observedVersions[component.ComponentID] = component.Version.State
	}
	unknownIDs := make(map[string]struct{}, len(bundle.Planes.Unknown.Components))
	for _, unknown := range bundle.Planes.Unknown.Components {
		state, ok := observedVersions[unknown.ComponentID]
		if !ok || state == "exact" {
			return fmt.Errorf("unknown-plane linkage is invalid: %w", ErrIntegrity)
		}
		if _, duplicate := unknownIDs[unknown.ComponentID]; duplicate {
			return fmt.Errorf("duplicate unknown component: %w", ErrInvalid)
		}
		unknownIDs[unknown.ComponentID] = struct{}{}
	}
	for id, state := range observedVersions {
		if state != "exact" {
			if _, ok := unknownIDs[id]; !ok {
				return fmt.Errorf("non-exact component missing unknown-plane entry: %w", ErrIntegrity)
			}
		}
	}
	seenOmissions := map[string]struct{}{}
	for _, omission := range bundle.Omissions {
		if _, ok := omissionRegistry[omission.Code]; !ok || omission.Scope != "observation" && omission.Scope != "environment" || (omission.PathClass != "" && omission.PathClass != "context/projection") || len(omission.Sources) > maxSourceBindings {
			return fmt.Errorf("invalid omission: %w", ErrInvalid)
		}
		// Distinct projected source files are independent omission evidence. A
		// closed code may therefore occur once per source file, while duplicate
		// entries from the same file remain an integrity failure.
		if _, exists := seenOmissions[omission.Code+"\x00"+omission.Scope+"\x00"+omission.PathClass+"\x00"+omission.SourceFile]; exists {
			return fmt.Errorf("duplicate omission: %w", ErrInvalid)
		}
		seenOmissions[omission.Code+"\x00"+omission.Scope+"\x00"+omission.PathClass+"\x00"+omission.SourceFile] = struct{}{}
		if omission.Count < 0 || omission.Count > 1000000 || strings.ContainsAny(omission.Reason, "\x00\r\n") || len(omission.Reason) > 4096 || strings.ContainsAny(omission.SourceFile, "\x00\r\n/") || len(omission.SourceFile) > 256 {
			return fmt.Errorf("invalid omission provenance: %w", ErrInvalid)
		}
		for _, digest := range omission.Sources {
			refs++
			if refs > maxReferences {
				return fmt.Errorf("source reference cardinality exceeds bound: %w", ErrInvalid)
			}
			if !digestRE.MatchString(digest) {
				return fmt.Errorf("invalid omission source: %w", ErrInvalid)
			}
			if _, ok := knownSources[digest]; !ok {
				return fmt.Errorf("omission source is not bound: %w", ErrIntegrity)
			}
		}
	}
	for _, conflict := range bundle.Conflicts {
		if !componentIDRE.MatchString(conflict.ComponentID) || conflict.Kind != "version_or_predicate" || len(conflict.Values) > maxValues {
			return fmt.Errorf("invalid conflict: %w", ErrInvalid)
		}
		for _, value := range conflict.Values {
			if len(value) > 4096 || strings.IndexByte(value, 0) >= 0 || !versionRE.MatchString(value) {
				return fmt.Errorf("invalid conflict value: %w", ErrInvalid)
			}
		}
	}
	if bundle.Freshness.State != "fresh" && bundle.Freshness.State != "stale" && bundle.Freshness.State != "unknown" {
		return fmt.Errorf("invalid freshness state: %w", ErrInvalid)
	}
	if err := validateFreshness(bundle); err != nil {
		return err
	}
	if bundle.CapturedAt != bundle.Freshness.CapturedAt {
		return fmt.Errorf("capture timestamp binding mismatch: %w", ErrIntegrity)
	}
	if bundle.Collector.Profile != "local-observation" || bundle.Collector.NetworkUsed || bundle.Collector.SubprocessUsed || bundle.Collector.ClusterUsed {
		return fmt.Errorf("invalid collector assurance: %w", ErrInvalid)
	}
	if len(bundle.Adapters) < 1 || len(bundle.Adapters) > 3 {
		return fmt.Errorf("invalid adapter bindings: %w", ErrInvalid)
	}
	certProjectionAdapterSeen, imageSourcesAdapterSeen := false, false
	observationAdapterVersion := ""
	for _, adapter := range bundle.Adapters {
		switch adapter.Name {
		case "observation-to-current-bundle":
			if observationAdapterVersion != "" || (adapter.Version != "current-bundle-v1" && adapter.Version != currentBundleAdapterV2 && adapter.Version != currentBundleAdapterV3) {
				return fmt.Errorf("invalid adapter binding: %w", ErrInvalid)
			}
			observationAdapterVersion = adapter.Version
		case "cert-manager-projection":
			if certProjectionAdapterSeen || !digestRE.MatchString(adapter.Version) {
				return fmt.Errorf("invalid cert-manager projection adapter binding: %w", ErrInvalid)
			}
			certProjectionAdapterSeen = true
		case ImageSourcesDigestAdapter:
			if imageSourcesAdapterSeen || !digestRE.MatchString(adapter.Version) {
				return fmt.Errorf("invalid image sources adapter binding: %w", ErrInvalid)
			}
			imageSourcesAdapterSeen = true
		default:
			return fmt.Errorf("invalid adapter binding: %w", ErrInvalid)
		}
	}
	if observationAdapterVersion == "" {
		return fmt.Errorf("missing observation adapter binding: %w", ErrInvalid)
	}
	if bundle.PredicateRegistryVersion == PredicateRegistryVersionV2 && observationAdapterVersion != currentBundleAdapterV3 || bundle.PredicateRegistryVersion == PredicateRegistryVersion && observationAdapterVersion == currentBundleAdapterV3 {
		return fmt.Errorf("predicate registry and observation adapter versions are not bound: %w", ErrIntegrity)
	}
	for _, component := range bundle.Planes.Observed.Components {
		for _, predicate := range component.Predicates {
			if predicate.EvidenceClass == "declared_container_context_v1" && observationAdapterVersion != currentBundleAdapterV2 && observationAdapterVersion != currentBundleAdapterV3 {
				return fmt.Errorf("declared context is not bound to a declared observation adapter: %w", ErrIntegrity)
			}
			if predicate.EvidenceClass == "synthetic_fixture_context_v1" && bundle.Synthetic == nil {
				return fmt.Errorf("synthetic context lacks coherent synthetic provenance: %w", ErrIntegrity)
			}
		}
	}
	return nil
}

func containsAdapter(adapters []AdapterBinding, name, version string) bool {
	for _, adapter := range adapters {
		if adapter.Name == name && adapter.Version == version {
			return true
		}
	}
	return false
}

func knownCurrentEvidenceClass(class string) bool {
	switch class {
	case "", "declared_container_context_v1", "synthetic_fixture_context_v1":
		return true
	default:
		return false
	}
}

func validPublicString(value string, max int) bool {
	return value != "" && len(value) <= max && strings.IndexByte(value, 0) < 0 && !strings.ContainsAny(value, "\r\n")
}

func validateField(field FieldValue, sources map[string]struct{}) error {
	switch field.State {
	case "observed", "declared", "derived", "missing", "unknown", "conflict":
	default:
		return fmt.Errorf("invalid field state: %w", ErrInvalid)
	}
	if len(field.Source) > maxSourceBindings {
		return fmt.Errorf("field source bound: %w", ErrInvalid)
	}
	if field.State == "unknown" && field.Value != "" {
		return fmt.Errorf("unknown field has value: %w", ErrInvalid)
	}
	if field.State == "observed" && len(field.Source) == 0 {
		return fmt.Errorf("observed field missing source: %w", ErrIntegrity)
	}
	if field.State == "observed" && !allBoundSourceRefs(field.Source) {
		return fmt.Errorf("observed field has omission-only source: %w", ErrIntegrity)
	}
	if field.Value != "" && !validPublicString(field.Value, 4096) {
		return fmt.Errorf("invalid field value: %w", ErrInvalid)
	}
	for _, ref := range field.Source {
		if err := validateSourceRef(ref, sources); err != nil {
			return err
		}
	}
	if duplicateSourceRefs(field.Source) {
		return fmt.Errorf("duplicate field source: %w", ErrInvalid)
	}
	return nil
}

func duplicateSourceRefs(refs []SourceRef) bool {
	seen := make(map[string]struct{}, len(refs))
	for _, ref := range refs {
		key := ref.PathClass + "\x00" + ref.Digest
		if _, ok := seen[key]; ok {
			return true
		}
		seen[key] = struct{}{}
	}
	return false
}

func allBoundSourceRefs(refs []SourceRef) bool {
	if len(refs) == 0 {
		return false
	}
	for _, ref := range refs {
		if ref.PathClass != "context/projection" || ref.Digest == "" {
			return false
		}
	}
	return true
}

func validateSourceRef(ref SourceRef, sources map[string]struct{}) error {
	if ref.PathClass != "context/projection" && !strings.HasPrefix(ref.PathClass, "omission:") {
		return fmt.Errorf("invalid source path class: %w", ErrInvalid)
	}
	if strings.HasPrefix(ref.PathClass, "omission:") {
		if _, ok := omissionRegistry[strings.TrimPrefix(ref.PathClass, "omission:")]; !ok {
			return fmt.Errorf("unregistered omission source: %w", ErrInvalid)
		}
	}
	if ref.PathClass == "context/projection" && ref.Digest == "" {
		return fmt.Errorf("bound source is missing digest: %w", ErrIntegrity)
	}
	if ref.Digest != "" {
		if !digestRE.MatchString(ref.Digest) {
			return fmt.Errorf("invalid source digest: %w", ErrInvalid)
		}
		if _, ok := sources[ref.Digest]; !ok {
			return fmt.Errorf("source reference is not bound: %w", ErrIntegrity)
		}
	}
	return nil
}

func validateComponent(component CanonicalComponent, registryVersion string, sources map[string]struct{}, seen map[string]struct{}, refs *int) error {
	if !componentIDRE.MatchString(component.ComponentID) || len(component.ComponentID) > 4096 {
		return fmt.Errorf("invalid component identity: %w", ErrInvalid)
	}
	if _, exists := seen[component.ComponentID]; exists {
		return fmt.Errorf("duplicate component identity: %w", ErrInvalid)
	}
	seen[component.ComponentID] = struct{}{}
	if component.Version.State != "exact" && component.Version.State != "unknown" && component.Version.State != "conflict" {
		return fmt.Errorf("invalid version state: %w", ErrInvalid)
	}
	if component.Version.State == "exact" && (!validPublicString(component.Version.Value, 4096) || !versionRE.MatchString(component.Version.Value)) {
		return fmt.Errorf("invalid exact version: %w", ErrInvalid)
	}
	if component.Version.State != "exact" && component.Version.Value != "" {
		return fmt.Errorf("non-exact version has value: %w", ErrInvalid)
	}
	if component.Artifact.State != "exact" || component.Artifact.Value != component.ComponentID {
		return fmt.Errorf("artifact identity is not exact: %w", ErrInvalid)
	}
	if len(component.Sources) == 0 {
		return fmt.Errorf("component missing source binding: %w", ErrIntegrity)
	}
	if !allBoundSourceRefs(component.Sources) {
		return fmt.Errorf("component source is not bound: %w", ErrIntegrity)
	}
	if len(component.Roles) > maxRoles || len(component.Predicates) > maxPredicates || len(component.Sources) > maxSourceBindings {
		return fmt.Errorf("component cardinality exceeds bound: %w", ErrInvalid)
	}
	for _, role := range component.Roles {
		if !roleRE.MatchString(role) {
			return fmt.Errorf("invalid component role: %w", ErrInvalid)
		}
		if _, ok := allowedRoles[role]; !ok {
			return fmt.Errorf("unregistered component role: %w", ErrInvalid)
		}
	}
	for _, ref := range component.Sources {
		if err := validateSourceRef(ref, sources); err != nil {
			return err
		}
		*refs++
		if *refs > maxReferences {
			return fmt.Errorf("source reference cardinality exceeds bound: %w", ErrInvalid)
		}
	}
	if duplicateSourceRefs(component.Sources) {
		return fmt.Errorf("duplicate component source: %w", ErrInvalid)
	}
	seenPredicates := map[string]struct{}{}
	for _, predicate := range component.Predicates {
		definition, ok := predicateRegistry[predicate.ID]
		if !ok || !predicateAllowedInRegistry(predicate.ID, registryVersion) {
			return fmt.Errorf("unregistered predicate: %w", ErrInvalid)
		}
		if strings.HasPrefix(predicate.ID, "component.metrics_server.") && component.ComponentID != "pkg:oci/kubernetes/metrics-server" || strings.HasPrefix(predicate.ID, "component.external_dns.") && component.ComponentID != "pkg:oci/kubernetes/external-dns" || strings.HasPrefix(predicate.ID, "component.prometheus.") && component.ComponentID != prometheusID || strings.HasPrefix(predicate.ID, "component.cert_manager.") && component.ComponentID != "pkg:oci/cert-manager/cert-manager" {
			return fmt.Errorf("predicate is owned by another component: %w", ErrIntegrity)
		}
		if _, exists := seenPredicates[predicate.ID]; exists {
			return fmt.Errorf("duplicate predicate: %w", ErrInvalid)
		}
		seenPredicates[predicate.ID] = struct{}{}
		if predicate.State != "observed" && predicate.State != "conflict" && predicate.State != "unknown" {
			if predicate.State != "missing" && predicate.State != "ambiguous" && predicate.State != "stale" && predicate.State != "unsupported" {
				return fmt.Errorf("invalid predicate state: %w", ErrInvalid)
			}
		}
		if predicate.SourceRole != "" {
			if _, ok := allowedRoles[predicate.SourceRole]; !ok {
				return fmt.Errorf("invalid predicate source role: %w", ErrInvalid)
			}
			found := false
			for _, role := range component.Roles {
				found = found || role == predicate.SourceRole
			}
			if !found {
				return fmt.Errorf("predicate source role is not component-bound: %w", ErrIntegrity)
			}
		}
		if !knownCurrentEvidenceClass(predicate.EvidenceClass) || (predicate.EvidenceClass != "" && predicate.SourceRole == "") {
			return fmt.Errorf("invalid predicate evidence class: %w", ErrInvalid)
		}
		validDeclaredContext := component.ComponentID == "pkg:oci/argoproj/argo-workflows" && predicate.SourceRole == "workflow-controller" || registryVersion == PredicateRegistryVersionV2 && component.ComponentID == prometheusID && predicate.SourceRole == "server"
		if predicate.EvidenceClass == "declared_container_context_v1" && !validDeclaredContext {
			return fmt.Errorf("declared context class is outside its closed component role: %w", ErrIntegrity)
		}
		if predicate.State == "observed" && len(predicate.Value) == 0 {
			return fmt.Errorf("observed predicate missing value: %w", ErrInvalid)
		}
		if predicate.State == "observed" && len(predicate.Sources) == 0 {
			return fmt.Errorf("predicate missing source binding: %w", ErrIntegrity)
		}
		if predicate.State == "observed" && !allBoundSourceRefs(predicate.Sources) {
			return fmt.Errorf("observed predicate source is not bound: %w", ErrIntegrity)
		}
		if predicate.State != "observed" && len(predicate.Value) != 0 {
			return fmt.Errorf("non-observed predicate has value: %w", ErrInvalid)
		}
		if len(predicate.Value) != 0 {
			value, err := canonicalPredicateValue(predicate.Value)
			if err != nil {
				return err
			}
			if !bytes.Equal(value, predicate.Value) {
				return fmt.Errorf("predicate value is not canonical: %w", ErrIntegrity)
			}
			if !validPredicateValue(predicate.ID, definition, value) {
				return fmt.Errorf("predicate value type mismatch: %w", ErrInvalid)
			}
		}
		if len(predicate.Sources) > maxSourceBindings {
			return fmt.Errorf("predicate source bound: %w", ErrInvalid)
		}
		for _, ref := range predicate.Sources {
			if err := validateSourceRef(ref, sources); err != nil {
				return err
			}
			*refs++
			if *refs > maxReferences {
				return fmt.Errorf("source reference cardinality exceeds bound: %w", ErrInvalid)
			}
		}
		if duplicateSourceRefs(predicate.Sources) {
			return fmt.Errorf("duplicate predicate source: %w", ErrInvalid)
		}
	}
	if err := validatePrometheusIdentityPredicates(component, registryVersion); err != nil {
		return err
	}
	return nil
}

func validatePrometheusIdentityPredicates(component CanonicalComponent, registryVersion string) error {
	var agentMode, imageDigest *CanonicalPredicate
	for i := range component.Predicates {
		switch component.Predicates[i].ID {
		case prometheusAgentModePredicate:
			agentMode = &component.Predicates[i]
		case prometheusImageDigestPredicate:
			imageDigest = &component.Predicates[i]
		}
	}
	if agentMode == nil && imageDigest == nil {
		return nil
	}
	if registryVersion != PredicateRegistryVersionV2 || component.ComponentID != prometheusID || component.Version.State != "exact" {
		return fmt.Errorf("Prometheus identity predicates are outside their registry/component/version binding: %w", ErrIntegrity)
	}
	if agentMode == nil || imageDigest == nil || agentMode.State != "observed" || imageDigest.State != "observed" || agentMode.SourceRole != "server" || imageDigest.SourceRole != "server" || agentMode.EvidenceClass != "declared_container_context_v1" || imageDigest.EvidenceClass != "declared_container_context_v1" {
		return fmt.Errorf("Prometheus identity predicates lack paired declared server evidence: %w", ErrIntegrity)
	}
	if !reflect.DeepEqual(agentMode.Sources, imageDigest.Sources) {
		return fmt.Errorf("Prometheus identity predicates do not share the same source binding: %w", ErrIntegrity)
	}
	expectedDigest, ok := observation.ApprovedPrometheusImageDigest(component.Version.Value)
	if !ok {
		return fmt.Errorf("Prometheus identity predicates use an unsupported version: %w", ErrInvalid)
	}
	var actualDigest string
	if err := json.Unmarshal(imageDigest.Value, &actualDigest); err != nil || actualDigest != expectedDigest {
		return fmt.Errorf("Prometheus image digest does not match the approved version binding: %w", ErrIntegrity)
	}
	var mode bool
	if err := json.Unmarshal(agentMode.Value, &mode); err != nil {
		return fmt.Errorf("Prometheus agent mode is not boolean: %w", ErrInvalid)
	}
	return nil
}

func validateFreshness(bundle CurrentBundle) error {
	fresh := bundle.Freshness
	if fresh.State == "unknown" {
		if fresh.CapturedAt == "" && fresh.PolicyID == "" && fresh.MaxAgeSeconds == 0 {
			return nil
		}
		if !validRFC3339(fresh.CapturedAt) || !validPolicyID(fresh.PolicyID) || fresh.MaxAgeSeconds <= 0 || fresh.MaxAgeSeconds > maxFreshnessAgeSeconds {
			return fmt.Errorf("invalid freshness binding: %w", ErrInvalid)
		}
		return nil
	}
	if !validRFC3339(fresh.CapturedAt) || !validPolicyID(fresh.PolicyID) || fresh.MaxAgeSeconds <= 0 || fresh.MaxAgeSeconds > maxFreshnessAgeSeconds {
		return fmt.Errorf("invalid freshness binding: %w", ErrInvalid)
	}
	return nil
}

func validRFC3339(value string) bool {
	parsed, err := time.Parse(time.RFC3339Nano, value)
	return err == nil && parsed.UTC().Format(time.RFC3339Nano) == value
}

func cloneBundle(bundle CurrentBundle) CurrentBundle {
	clone := bundle
	if bundle.Synthetic != nil {
		synthetic := *bundle.Synthetic
		clone.Synthetic = &synthetic
	}
	clone.Environment.Provider.Source = cloneRefs(bundle.Environment.Provider.Source)
	clone.Environment.Distribution.Source = cloneRefs(bundle.Environment.Distribution.Source)
	clone.Environment.Kubernetes.Source = cloneRefs(bundle.Environment.Kubernetes.Source)
	clone.Environment.NodeOS.Source = cloneRefs(bundle.Environment.NodeOS.Source)
	clone.Environment.Kernel.Source = cloneRefs(bundle.Environment.Kernel.Source)
	clone.Environment.Architecture.Source = cloneRefs(bundle.Environment.Architecture.Source)
	clone.Environment.ContainerRuntime.Source = cloneRefs(bundle.Environment.ContainerRuntime.Source)
	clone.Planes.Observed.Components = cloneComponents(bundle.Planes.Observed.Components)
	clone.Planes.Declared.Components = cloneComponents(bundle.Planes.Declared.Components)
	clone.Planes.Derived.Components = cloneComponents(bundle.Planes.Derived.Components)
	clone.Planes.Unknown.Components = cloneUnknownValues(bundle.Planes.Unknown.Components)
	for i := range clone.Planes.Unknown.Components {
		clone.Planes.Unknown.Components[i].Reasons = cloneStrings(bundle.Planes.Unknown.Components[i].Reasons)
	}
	clone.Sources = cloneSourceBindings(bundle.Sources)
	clone.Adapters = cloneAdapterBindings(bundle.Adapters)
	clone.Conflicts = cloneConflicts(bundle.Conflicts)
	for i := range clone.Conflicts {
		clone.Conflicts[i].Values = cloneStrings(bundle.Conflicts[i].Values)
	}
	clone.Omissions = cloneOmissions(bundle.Omissions)
	for i := range clone.Omissions {
		clone.Omissions[i].Sources = cloneStrings(bundle.Omissions[i].Sources)
	}
	return clone
}

// ErrSyntheticEvidence is returned before a production authority path may
// inspect any decision, TestRecord result, or release status derived from a
// synthetic fixture. Synthetic bundles remain importable only by explicit
// test-only branch harnesses.
var ErrSyntheticEvidence = errors.New("synthetic evidence is ineligible for production authority")

// RejectSyntheticAuthority is the common admission primitive for production
// authority sinks. It deliberately validates only the closed provenance
// marker before returning the stable denial sentinel; callers must invoke it
// before parsing or reducing any decision value.
func RejectSyntheticAuthority(bundle CurrentBundle) error {
	if bundle.Synthetic == nil {
		return nil
	}
	if bundle.Synthetic.Classification != "PUBLIC_SYNTHETIC" || bundle.Synthetic.Authority != "SYNTHETIC_NON_AUTHORITATIVE_TEST_INPUT" || bundle.Synthetic.Canary != "PRUFYX_SYNTHETIC_NEVER_COMPATIBILITY_EVIDENCE" || !bundle.Synthetic.NonAuthoritative {
		return fmt.Errorf("invalid synthetic provenance: %w", ErrIntegrity)
	}
	return fmt.Errorf("SYNTHETIC_EVIDENCE_INELIGIBLE: %w", ErrSyntheticEvidence)
}

func RejectSyntheticArtifact(artifact Artifact) error {
	return RejectSyntheticAuthority(artifact.Bundle)
}

// RejectSyntheticBytes is a pre-parse admission canary for sinks that receive
// canonical bundle bytes rather than a typed Artifact. Detaching the marker
// changes the signed/content-addressed bytes; retaining any closed marker
// always fails before the sink parses a decision or TestRecord result.
func RejectSyntheticBytes(data []byte) error {
	for _, marker := range [][]byte{
		[]byte(`"syntheticProvenance"`),
		[]byte(`PRUFYX_SYNTHETIC_NEVER_COMPATIBILITY_EVIDENCE`),
		[]byte(`SYNTHETIC_NON_AUTHORITATIVE_TEST_INPUT`),
	} {
		if bytes.Contains(data, marker) {
			return fmt.Errorf("SYNTHETIC_EVIDENCE_INELIGIBLE: %w", ErrSyntheticEvidence)
		}
	}
	return nil
}

func cloneComponents(input []CanonicalComponent) []CanonicalComponent {
	if input == nil {
		return nil
	}
	result := make([]CanonicalComponent, len(input))
	copy(result, input)
	for i := range result {
		result[i].Roles = cloneStrings(input[i].Roles)
		result[i].Sources = cloneRefs(input[i].Sources)
		if input[i].Predicates == nil {
			result[i].Predicates = nil
		} else {
			result[i].Predicates = make([]CanonicalPredicate, len(input[i].Predicates))
			copy(result[i].Predicates, input[i].Predicates)
		}
		for j := range result[i].Predicates {
			result[i].Predicates[j].Value = append([]byte(nil), input[i].Predicates[j].Value...)
			result[i].Predicates[j].Sources = cloneRefs(input[i].Predicates[j].Sources)
		}
	}
	return result
}

func cloneRefs(input []SourceRef) []SourceRef {
	if input == nil {
		return nil
	}
	return append(make([]SourceRef, 0, len(input)), input...)
}

func cloneStrings(input []string) []string {
	if input == nil {
		return nil
	}
	return append(make([]string, 0, len(input)), input...)
}
func cloneUnknownValues(input []UnknownValue) []UnknownValue {
	if input == nil {
		return nil
	}
	return append(make([]UnknownValue, 0, len(input)), input...)
}
func cloneSourceBindings(input []SourceBinding) []SourceBinding {
	if input == nil {
		return nil
	}
	return append(make([]SourceBinding, 0, len(input)), input...)
}
func cloneAdapterBindings(input []AdapterBinding) []AdapterBinding {
	if input == nil {
		return nil
	}
	return append(make([]AdapterBinding, 0, len(input)), input...)
}
func cloneConflicts(input []Conflict) []Conflict {
	if input == nil {
		return nil
	}
	return append(make([]Conflict, 0, len(input)), input...)
}
func cloneOmissions(input []Omission) []Omission {
	if input == nil {
		return nil
	}
	return append(make([]Omission, 0, len(input)), input...)
}

func canonicalize(bundle *CurrentBundle) error {
	fields := []*FieldValue{
		&bundle.Environment.Provider, &bundle.Environment.Distribution,
		&bundle.Environment.Kubernetes, &bundle.Environment.NodeOS,
		&bundle.Environment.Kernel, &bundle.Environment.Architecture,
		&bundle.Environment.ContainerRuntime,
	}
	for _, field := range fields {
		sort.Slice(field.Source, func(i, j int) bool { return sourceRefKey(field.Source[i]) < sourceRefKey(field.Source[j]) })
	}
	for _, plane := range []*EvidencePlane{&bundle.Planes.Observed, &bundle.Planes.Declared, &bundle.Planes.Derived} {
		sort.Slice(plane.Components, func(i, j int) bool {
			left, right := plane.Components[i], plane.Components[j]
			if left.ComponentID != right.ComponentID {
				return left.ComponentID < right.ComponentID
			}
			if left.Version.State != right.Version.State {
				return left.Version.State < right.Version.State
			}
			return left.Version.Value < right.Version.Value
		})
		for i := range plane.Components {
			component := &plane.Components[i]
			sort.Strings(component.Roles)
			for j := range component.Predicates {
				if len(component.Predicates[j].Value) != 0 {
					value, err := canonicalPredicateValue(component.Predicates[j].Value)
					if err != nil {
						return err
					}
					component.Predicates[j].Value = value
				}
			}
			sort.Slice(component.Predicates, func(a, b int) bool {
				if component.Predicates[a].ID != component.Predicates[b].ID {
					return component.Predicates[a].ID < component.Predicates[b].ID
				}
				if string(component.Predicates[a].Value) != string(component.Predicates[b].Value) {
					return string(component.Predicates[a].Value) < string(component.Predicates[b].Value)
				}
				return sourceKey(component.Predicates[a].Sources) < sourceKey(component.Predicates[b].Sources)
			})
			sort.Slice(component.Sources, func(a, b int) bool {
				if component.Sources[a].Digest != component.Sources[b].Digest {
					return component.Sources[a].Digest < component.Sources[b].Digest
				}
				return component.Sources[a].PathClass < component.Sources[b].PathClass
			})
			for j := range component.Predicates {
				sort.Slice(component.Predicates[j].Sources, func(a, b int) bool {
					left, right := component.Predicates[j].Sources[a], component.Predicates[j].Sources[b]
					if left.Digest != right.Digest {
						return left.Digest < right.Digest
					}
					return left.PathClass < right.PathClass
				})
			}
		}
	}
	for i := range bundle.Conflicts {
		sort.Strings(bundle.Conflicts[i].Values)
	}
	sort.Slice(bundle.Planes.Unknown.Components, func(i, j int) bool {
		left, right := bundle.Planes.Unknown.Components[i], bundle.Planes.Unknown.Components[j]
		if left.ComponentID != right.ComponentID {
			return left.ComponentID < right.ComponentID
		}
		return stringsKey(left.Reasons) < stringsKey(right.Reasons)
	})
	for i := range bundle.Planes.Unknown.Components {
		sort.Strings(bundle.Planes.Unknown.Components[i].Reasons)
	}
	sort.Slice(bundle.Sources, func(i, j int) bool {
		if bundle.Sources[i].Digest != bundle.Sources[j].Digest {
			return bundle.Sources[i].Digest < bundle.Sources[j].Digest
		}
		return bundle.Sources[i].PathClass < bundle.Sources[j].PathClass
	})
	sort.Slice(bundle.Conflicts, func(i, j int) bool {
		if bundle.Conflicts[i].ComponentID != bundle.Conflicts[j].ComponentID {
			return bundle.Conflicts[i].ComponentID < bundle.Conflicts[j].ComponentID
		}
		if bundle.Conflicts[i].Kind != bundle.Conflicts[j].Kind {
			return bundle.Conflicts[i].Kind < bundle.Conflicts[j].Kind
		}
		return stringsKey(bundle.Conflicts[i].Values) < stringsKey(bundle.Conflicts[j].Values)
	})
	sort.Slice(bundle.Omissions, func(i, j int) bool {
		if bundle.Omissions[i].Code != bundle.Omissions[j].Code {
			return bundle.Omissions[i].Code < bundle.Omissions[j].Code
		}
		if bundle.Omissions[i].Scope != bundle.Omissions[j].Scope {
			return bundle.Omissions[i].Scope < bundle.Omissions[j].Scope
		}
		return bundle.Omissions[i].PathClass < bundle.Omissions[j].PathClass
	})
	for i := range bundle.Omissions {
		sort.Strings(bundle.Omissions[i].Sources)
	}
	return nil
}

// canonicalPredicateValue converts the admitted scalar into its semantic JSON
// representation. Raw bytes, whitespace, duplicate object keys, numbers, and
// composite values are never accepted as a canonical predicate value.
func canonicalPredicateValue(raw json.RawMessage) ([]byte, error) {
	var value any
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(&value); err != nil {
		return nil, fmt.Errorf("predicate value is not JSON: %w", ErrInvalid)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return nil, fmt.Errorf("predicate value is not one scalar: %w", ErrInvalid)
	}
	switch typed := value.(type) {
	case bool:
		return json.Marshal(typed)
	case string:
		if len(typed) > 4096 || strings.IndexByte(typed, 0) >= 0 {
			return nil, fmt.Errorf("predicate string exceeds bound: %w", ErrInvalid)
		}
		return json.Marshal(typed)
	case json.Number:
		value, err := typed.Int64()
		if err != nil || value < 0 || value > 1000000 {
			return nil, fmt.Errorf("predicate integer is out of bounds: %w", ErrInvalid)
		}
		return []byte(strconv.FormatInt(value, 10)), nil
	default:
		return nil, fmt.Errorf("predicate value type is not registered scalar: %w", ErrInvalid)
	}
}

func sourceKey(refs []SourceRef) string {
	parts := make([]string, 0, len(refs))
	for _, ref := range refs {
		parts = append(parts, ref.Digest+"\x00"+ref.PathClass)
	}
	sort.Strings(parts)
	return stringsKey(parts)
}

func sourceRefKey(ref SourceRef) string { return ref.Digest + "\x00" + ref.PathClass }

func stringsKey(values []string) string {
	result := ""
	for _, value := range values {
		result += value + "\x00"
	}
	return result
}

// ValidateArtifact verifies canonical bytes and the digest-without-field
// binding. It does not authenticate the local manifest origin.
func ValidateArtifact(artifact Artifact) error {
	if err := validateBundle(artifact.Bundle); err != nil {
		return err
	}
	canonical := cloneBundle(artifact.Bundle)
	if err := canonicalize(&canonical); err != nil || !reflect.DeepEqual(canonical, artifact.Bundle) {
		return fmt.Errorf("artifact bundle is not canonical: %w", ErrIntegrity)
	}
	if !sameDisclosure(artifact.Disclosure, disclosure(artifact.Bundle)) {
		return fmt.Errorf("artifact disclosure mismatch: %w", ErrIntegrity)
	}
	if artifact.Digest == "" || !digestRE.MatchString(artifact.Digest) || artifact.Digest != artifact.Bundle.BundleDigest || artifact.Digest != DigestBytesWithoutBundleDigest(artifact.Bundle) {
		return fmt.Errorf("artifact digest mismatch: %w", ErrIntegrity)
	}
	encoded, err := Marshal(artifact.Bundle)
	if err != nil || len(artifact.Bytes) == 0 || len(artifact.Bytes) > maxBundleBytes || len(encoded) > maxBundleBytes || !bytes.Equal(encoded, artifact.Bytes) {
		return fmt.Errorf("artifact bytes mismatch: %w", ErrIntegrity)
	}
	return nil
}

func sameDisclosure(left, right Disclosure) bool {
	if left.Profile != right.Profile || left.SourceCount != right.SourceCount || left.OmissionCount != right.OmissionCount || left.ConflictCount != right.ConflictCount || left.UnknownCount != right.UnknownCount || left.FreshnessStatus != right.FreshnessStatus || left.RawDataRetained != right.RawDataRetained || left.NetworkUsed != right.NetworkUsed || left.SubprocessUsed != right.SubprocessUsed || left.ClusterUsed != right.ClusterUsed || len(left.SourcePaths) != len(right.SourcePaths) || len(left.SourceDigests) != len(right.SourceDigests) {
		return false
	}
	for i := range left.SourcePaths {
		if left.SourcePaths[i] != right.SourcePaths[i] {
			return false
		}
	}
	for i := range left.SourceDigests {
		if left.SourceDigests[i] != right.SourceDigests[i] {
			return false
		}
	}
	return true
}

func DigestBytesWithoutBundleDigest(bundle CurrentBundle) string {
	digest, _ := Digest(bundle)
	return digest
}

// ToEvaluationProjection is intentionally lossy. It is the only explicit
// adapter from the richer canonical boundary to the legacy evaluator shape;
// declared/derived/unknown planes and non-observed predicate states cannot be
// mistaken for observed facts.
func (bundle CurrentBundle) ToEvaluationProjection() (observation.CurrentBundle, error) {
	if err := validateBundle(bundle); err != nil {
		return observation.CurrentBundle{}, err
	}
	if len(bundle.Planes.Unknown.Components) != 0 {
		return observation.CurrentBundle{}, fmt.Errorf("evaluation projection would drop unknown-plane data: %w", ErrInvalid)
	}
	projection := observation.CurrentBundle{
		APIVersion: observation.APIVersion, Kind: observation.Kind,
		KubernetesVersion: bundle.Environment.Kubernetes.Value,
		Components:        []observation.Component{}, Conflicts: []observation.Conflict{}, Omissions: []observation.Omission{},
	}
	projection.Synthetic = bundle.Synthetic
	for _, source := range bundle.Sources {
		projection.SourceDigests = append(projection.SourceDigests, source.Digest)
	}
	projection.KubernetesSourceDigests = sourceDigestStrings(bundle.Environment.Kubernetes.Source)
	for _, component := range bundle.Planes.Observed.Components {
		item := observation.Component{ComponentID: component.ComponentID, Status: "observed", Roles: append([]string(nil), component.Roles...), SourceDigests: sourceDigestStrings(component.Sources)}
		if component.Version.State == "exact" {
			item.Version = component.Version.Value
		} else {
			item.Status = component.Version.State
		}
		for _, predicate := range component.Predicates {
			if predicate.State != "observed" {
				return observation.CurrentBundle{}, fmt.Errorf("evaluation projection would drop predicate state: %w", ErrInvalid)
			}
			item.Predicates = append(item.Predicates, observation.Predicate{ID: predicate.ID, Value: append([]byte(nil), predicate.Value...), State: predicate.State, Role: predicate.SourceRole, SourceDigests: sourceDigestStrings(predicate.Sources)})
		}
		projection.Components = append(projection.Components, item)
	}
	for _, conflict := range bundle.Conflicts {
		projection.Conflicts = append(projection.Conflicts, observation.Conflict{ComponentID: conflict.ComponentID, Kind: conflict.Kind, Values: append([]string(nil), conflict.Values...)})
	}
	for _, omission := range bundle.Omissions {
		projection.Omissions = append(projection.Omissions, observation.Omission{Code: omission.Code})
	}
	return projection, nil
}

func ToEvaluationProjection(bundle CurrentBundle) (observation.CurrentBundle, error) {
	return bundle.ToEvaluationProjection()
}

func (artifact Artifact) ToEvaluationProjection() (observation.CurrentBundle, error) {
	if err := ValidateArtifact(artifact); err != nil {
		return observation.CurrentBundle{}, err
	}
	return artifact.Bundle.ToEvaluationProjection()
}

func sourceDigestStrings(refs []SourceRef) []string {
	result := make([]string, 0, len(refs))
	for _, ref := range refs {
		if ref.Digest != "" {
			result = append(result, ref.Digest)
		}
	}
	return result
}
