// SPDX-License-Identifier: AGPL-3.0-only

// Package observation imports the local, sanitized KubeconfigAPIObservation
// envelope.  It is deliberately a one-way projection: names, namespaces,
// image references, endpoints, context identifiers, and absolute paths never
// enter the returned CurrentBundle.
package observation

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	APIVersion                     = "prufyx.io/observation/v1alpha1"
	Kind                           = "CurrentBundle"
	ObservationSchema              = "prufyx.io/kubeconfig-api-observation/v1alpha1"
	IndexSchema                    = "prufyx.io/kubeconfig-api-observation-index/v1alpha1"
	maxInputBytes                  = 64 << 20
	maxFileBytes                   = 8 << 20
	maxManifestBytes               = 2 << 20
	maxFiles                       = 4096
	maxDirectories                 = 1024
	inventoryBatch                 = 64
	maxJSONDepth                   = 32
	maxArrayItems                  = 10000
	maxObjectMembers               = 256
	maxStringBytes                 = 4096
	maxComponents                  = 256
	maxPredicates                  = 128
	maxPathDepth                   = 32
	prometheusID                   = "pkg:oci/prometheus/prometheus"
	prometheusAgentModePredicate   = "component.prometheus.agent_mode"
	prometheusImageDigestPredicate = "component.prometheus.image_digest"
	configurationAdapterV2         = "component-configuration-adapter-v2"
	configurationAdapterV3         = "component-configuration-adapter-v3"
)

var (
	ErrInvalid    = errors.New("invalid observation")
	ErrIntegrity  = errors.New("observation integrity mismatch")
	ErrAmbiguous  = errors.New("observation context is ambiguous")
	versionRE     = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$`)
	idRE          = regexp.MustCompile(`^pkg:oci/[a-z0-9][a-z0-9._-]*/[a-z0-9][a-z0-9._-]*$`)
	codeRE        = regexp.MustCompile(`^[A-Z][A-Z0-9_.-]{2,127}$`)
	digestRE      = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	goVersionRE   = regexp.MustCompile(`^go(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:\.(0|[1-9][0-9]*))?(?: X:boringcrypto)?$`)
	gkeVersionRE  = regexp.MustCompile(`^((0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*))-gke\.(0|[1-9][0-9]*)$`)
	surfaceFileRE = regexp.MustCompile(`^[A-Za-z0-9._-]+\.json$`)
)

// CurrentBundle is a closed, public-only projection of one observation
// context. It is not a compatibility decision and carries no customer
// identity or raw Kubernetes object data.
type CurrentBundle struct {
	APIVersion              string      `json:"apiVersion"`
	Kind                    string      `json:"kind"`
	KubernetesVersion       string      `json:"kubernetesVersion"`
	Components              []Component `json:"components"`
	Conflicts               []Conflict  `json:"conflicts"`
	Omissions               []Omission  `json:"omissions"`
	SourceDigests           []string    `json:"sourceDigests"`
	KubernetesSourceDigests []string    `json:"-"`
	// CertManagerProjectionDigest binds the optional persisted helper version
	// into the next-stage currentbundle adapter and is not public JSON.
	CertManagerProjectionDigest string `json:"-"`
	// ImageSourcesDigest and ImageSourcesSchema record which reviewed image
	// registry produced the image rows. Empty for bundles collected before the
	// registry existed. They are not public JSON; the bridge binds them as
	// adapters.
	ImageSourcesDigest string `json:"-"`
	ImageSourcesSchema string `json:"-"`
	// ConfigurationAdapterVersion transports only the producer-v3 admission
	// identity to the next-stage currentbundle adapter. Older producers retain
	// their exact historical output path and leave this field empty.
	ConfigurationAdapterVersion string `json:"-"`
	// Source capture metadata is verified from both index.json and the context
	// snapshot metadata. It is intentionally not part of this adapter's public
	// JSON projection; currentbundle uses it to bind freshness.
	SourceGeneratedAt         string   `json:"-"`
	SourceGeneratedAtValid    bool     `json:"-"`
	SourceGeneratedAtConflict bool     `json:"-"`
	SourceCollectionStatus    string   `json:"-"`
	SourceOmissionCodes       []string `json:"-"`
	// Synthetic is a typed, durable provenance marker. A non-nil value is
	// never compatibility evidence and must be denied by downstream sinks.
	Synthetic *SyntheticProvenance `json:"syntheticProvenance,omitempty"`
}

type SyntheticProvenance struct {
	Classification   string `json:"classification"`
	Authority        string `json:"authority"`
	Canary           string `json:"canary"`
	NonAuthoritative bool   `json:"nonAuthoritative"`
}

type Component struct {
	ComponentID   string      `json:"componentId"`
	Version       string      `json:"version,omitempty"`
	Status        string      `json:"status"`
	Roles         []string    `json:"roles"`
	Predicates    []Predicate `json:"predicates"`
	SourceDigests []string    `json:"sourceDigests"`
}

type Predicate struct {
	ID            string          `json:"id"`
	Value         json.RawMessage `json:"value"`
	State         string          `json:"state,omitempty"`
	Role          string          `json:"sourceRole,omitempty"`
	EvidenceClass string          `json:"evidenceClass,omitempty"`
	// SourceDigests is provenance retained for the currentbundle bridge. It is
	// intentionally omitted from this projection's JSON compatibility surface.
	SourceDigests []string `json:"-"`
}

type Conflict struct {
	ComponentID string   `json:"componentId"`
	Kind        string   `json:"kind"`
	Values      []string `json:"values"`
}

type Omission struct {
	Code                  string `json:"code"`
	Reason                string `json:"reason,omitempty"`
	RequiredForEvaluation bool   `json:"requiredForEvaluation,omitempty"`
	SourceFile            string `json:"sourceFile,omitempty"`
	Count                 int    `json:"count,omitempty"`
}

type indexFile struct {
	Schema      string         `json:"schema"`
	GeneratedAt string         `json:"generatedAt"`
	Contexts    []indexContext `json:"contexts"`
}

type indexContext struct {
	Directory        string `json:"directory"`
	ContextHash      string `json:"contextHash"`
	CollectionStatus string `json:"collectionStatus"`
	OmissionCount    int    `json:"omissionCount"`
}

type metadataFile struct {
	Schema                                 string          `json:"schema"`
	Format                                 string          `json:"format"`
	GeneratedAt                            string          `json:"generatedAt"`
	ContextHash                            string          `json:"contextHash"`
	CollectionStatus                       string          `json:"collectionStatus"`
	IncludePodStatusImages                 bool            `json:"includePodStatusImages"`
	IncludeComponentConfiguration          bool            `json:"includeComponentConfiguration"`
	ComponentConfigurationAdapterVersion   *string         `json:"componentConfigurationAdapterVersion"`
	ComponentConfigurationRegistryVersion  *string         `json:"componentConfigurationRegistryVersion"`
	ComponentConfigurationRegistryDigest   *string         `json:"componentConfigurationRegistryDigest"`
	ComponentConfigurationFilterDigest     *string         `json:"componentConfigurationFilterDigest"`
	ComponentConfigurationAggregateDigest  *string         `json:"componentConfigurationAggregateDigest"`
	ComponentConfigurationStrictJSONDigest *string         `json:"componentConfigurationStrictJsonDigest"`
	KubectlStderrClassifierDigest          string          `json:"kubectlStderrClassifierDigest"`
	KubectlStderrClassifierTaxonomyVersion string          `json:"kubectlStderrClassifierTaxonomyVersion"`
	KubectlStderrClassifierAuthority       string          `json:"kubectlStderrClassifierAuthority"`
	KubectlBoundedRunnerDigest             string          `json:"kubectlBoundedRunnerDigest"`
	ImageSourcesDigest                     *string         `json:"imageSourcesDigest"`
	ImageSourcesSchema                     *string         `json:"imageSourcesSchema"`
	CRDPaginationPolicy                    json.RawMessage `json:"crdPaginationPolicy"`
	OmissionCount                          int             `json:"omissionCount"`
	DataClassification                     string          `json:"dataClassification"`
	Authority                              string          `json:"authority"`
	EvaluationEligible                     bool            `json:"evaluationEligible"`
	NotACompatibilitySnapshot              bool            `json:"notACompatibilitySnapshot"`
	Retained                               []string        `json:"retained"`
	OmittedByPolicy                        []string        `json:"omittedByPolicy"`
	Disclosure                             []string        `json:"disclosure"`
	SyntheticClassification                string          `json:"syntheticClassification"`
	SyntheticAuthority                     string          `json:"syntheticAuthority"`
	SyntheticCanary                        string          `json:"syntheticCanary"`
	SyntheticNonAuthoritative              bool            `json:"syntheticNonAuthoritative"`
}

type serverVersionFile struct {
	GitVersion   string  `json:"gitVersion"`
	GitCommit    *string `json:"gitCommit"`
	GitTreeState *string `json:"gitTreeState"`
	BuildDate    *string `json:"buildDate"`
	GoVersion    *string `json:"goVersion"`
	Compiler     *string `json:"compiler"`
	Platform     *string `json:"platform"`
}

// validateServerVersionFields is deliberately closed and bounded.  The
// collector's server-version projection is the only server identity surface
// accepted here; arbitrary metadata (including URLs or credentials) must not
// cross the observation boundary.
func validateServerVersionFields(server serverVersionFile) error {
	for name, value := range map[string]string{
		"gitCommit": optionalString(server.GitCommit), "gitTreeState": optionalString(server.GitTreeState),
		"buildDate": optionalString(server.BuildDate), "goVersion": optionalString(server.GoVersion),
		"compiler": optionalString(server.Compiler), "platform": optionalString(server.Platform),
	} {
		if value != "" && (len(value) > maxStringBytes || strings.ContainsAny(value, "\x00\r\n")) {
			return fmt.Errorf("invalid server version %s: %w", name, ErrInvalid)
		}
	}
	if value := optionalString(server.GitCommit); value != "" && !regexp.MustCompile(`^[A-Za-z0-9._+-]+$`).MatchString(value) {
		return fmt.Errorf("invalid server version gitCommit: %w", ErrInvalid)
	}
	if value := optionalString(server.GitTreeState); value != "" && value != "clean" && value != "dirty" && value != "unknown" {
		return fmt.Errorf("invalid server version gitTreeState: %w", ErrInvalid)
	}
	if value := optionalString(server.BuildDate); value != "" {
		if _, err := time.Parse(time.RFC3339, value); err != nil {
			return fmt.Errorf("invalid server version buildDate: %w", ErrInvalid)
		}
	}
	if value := optionalString(server.GoVersion); value != "" && !goVersionRE.MatchString(value) {
		return fmt.Errorf("invalid server version goVersion: %w", ErrInvalid)
	}
	if value := optionalString(server.Compiler); value != "" && !regexp.MustCompile(`^[A-Za-z0-9._+-]+$`).MatchString(value) {
		return fmt.Errorf("invalid server version compiler: %w", ErrInvalid)
	}
	if value := optionalString(server.Platform); value != "" && !regexp.MustCompile(`^[A-Za-z0-9._+-]+/[A-Za-z0-9._+-]+$`).MatchString(value) {
		return fmt.Errorf("invalid server version platform: %w", ErrInvalid)
	}
	return nil
}

func optionalString(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

type imageSummary struct {
	ComponentID      string  `json:"componentId"`
	ObservedVersion  *string `json:"observedVersion"`
	VersionScheme    string  `json:"versionScheme"`
	ObservationState string  `json:"observationState"`
	ObservationCount int     `json:"observationCount"`
	VersionConflict  bool    `json:"versionConflict"`
}

type surfaceFile struct {
	APIVersion                  string             `json:"apiVersion"`
	Kind                        string             `json:"kind"`
	Metadata                    surfaceMetadata    `json:"metadata"`
	Components                  []surfaceComponent `json:"components"`
	Omissions                   []surfaceOmission  `json:"omissions"`
	LicenseCopyrightDisposition string             `json:"licenseCopyrightDisposition"`
}

type surfaceMetadata struct {
	SchemaVersion                          string  `json:"schemaVersion"`
	AdapterVersion                         string  `json:"adapterVersion"`
	RegistryVersion                        string  `json:"registryVersion"`
	RegistryDigest                         string  `json:"registryDigest"`
	FilterDigest                           string  `json:"filterDigest"`
	AggregateDigest                        string  `json:"aggregateDigest"`
	StrictJSONDigest                       string  `json:"strictJsonDigest"`
	KubectlStderrClassifierDigest          string  `json:"kubectlStderrClassifierDigest"`
	KubectlBoundedRunnerDigest             string  `json:"kubectlBoundedRunnerDigest"`
	KubectlStderrClassifierTaxonomyVersion string  `json:"kubectlStderrClassifierTaxonomyVersion"`
	KubectlStderrClassifierAuthority       string  `json:"kubectlStderrClassifierAuthority"`
	CertManagerProjectionDigest            *string `json:"certManagerProjectionDigest"`
}

type surfaceComponent struct {
	ComponentID         string                     `json:"componentId"`
	ObservedVersion     *string                    `json:"observedVersion"`
	VersionScheme       string                     `json:"versionScheme"`
	VersionConflict     bool                       `json:"versionConflict"`
	ObservationState    string                     `json:"observationState"`
	ObservationCount    int                        `json:"observationCount"`
	Predicates          map[string]json.RawMessage `json:"predicates"`
	Roles               []string                   `json:"roles,omitempty"`
	PredicateEvidence   []surfacePredicateEvidence `json:"predicateEvidence,omitempty"`
	ConflictingVersions []string                   `json:"conflictingVersions,omitempty"`
}

type surfacePredicateEvidence struct {
	PredicateID   string `json:"predicateId"`
	State         string `json:"state"`
	SourceRole    string `json:"sourceRole"`
	EvidenceClass string `json:"evidenceClass,omitempty"`
}

type surfaceOmission struct {
	Code                  string `json:"code"`
	Reason                string `json:"reason"`
	RequiredForEvaluation bool   `json:"requiredForEvaluation"`
	SourceFile            string `json:"sourceFile"`
	Count                 int    `json:"count"`
}

type manifestEntry struct {
	Digest string
	Path   string
}

type componentState struct {
	id               string
	versions         map[string]struct{}
	roles            map[string]struct{}
	predicates       map[string]json.RawMessage
	predicateSources map[string]map[string]struct{}
	predicateStates  map[string]string
	predicateRoles   map[string]string
	predicateClasses map[string]string
	digests          map[string]struct{}
	conflict         bool
	// unresolved is set when a workload image row of this component carries no
	// usable version (digest-only, latest, off-scheme, pre-release). A component
	// with such a row never takes an exact version from a sibling row.
	unresolved bool
}

type byteCache struct {
	root         *os.File
	rootIdentity stableIdentity
	files        map[string]stableIdentity
	directories  map[string]stableIdentity
	data         map[string][]byte
	hook         *importReadHooks
	ctx          context.Context
	limits       normalizedLimits
	total        int64
}

type importReadHooks struct {
	afterStableStat     func(string) error
	afterInventoryDir   func(string) error
	afterFirstInventory func() error
}

func newByteCache(ctx context.Context, root *os.File, rootIdentity stableIdentity, files, directories map[string]stableIdentity, limits normalizedLimits, hook *importReadHooks) *byteCache {
	return &byteCache{root: root, rootIdentity: rootIdentity, files: files, directories: directories, data: map[string][]byte{}, hook: hook, ctx: ctx, limits: limits}
}

func (c *byteCache) read(path string, limit int64) ([]byte, error) {
	if err := checkContext(c.ctx); err != nil {
		return nil, err
	}
	if data, ok := c.data[path]; ok {
		return data, nil
	}
	if limit > c.limits.file {
		limit = c.limits.file
	}
	data, err := readRelativeFile(c.ctx, c.root, path, limit, c.rootIdentity, c.files, c.directories, c.hook)
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > c.limits.total-c.total {
		return nil, fmt.Errorf("observation exceeds retained-byte bound: %w", ErrInvalid)
	}
	c.total += int64(len(data))
	data = append([]byte(nil), data...)
	c.data[path] = data
	return data, nil
}

// Import reads and verifies one descriptor-owned observation root. Exactly one
// context is accepted in this MVP; multiple contexts produce ErrAmbiguous.
func Import(ctx context.Context, root *Root, options ImportOptions) (CurrentBundle, error) {
	return importWithReadHooks(ctx, root, options, nil)
}

// importWithReadHooks is a deterministic test seam with no pathname bypass.
func importWithReadHooks(ctx context.Context, root *Root, options ImportOptions, hooks *importReadHooks) (CurrentBundle, error) {
	if err := checkContext(ctx); err != nil {
		return CurrentBundle{}, err
	}
	limits, err := normalizeImportOptions(options)
	if err != nil {
		return CurrentBundle{}, err
	}
	rootFD, err := root.ownedSnapshot()
	if err != nil {
		return CurrentBundle{}, err
	}
	defer rootFD.Close()
	files, directories, firstRootIdentity, total, err := inventoryFiles(ctx, rootFD, "", limits, hooks)
	if err != nil {
		return CurrentBundle{}, err
	}
	cache := newByteCache(ctx, rootFD, firstRootIdentity, files, directories, limits, hooks)
	if hooks != nil && hooks.afterFirstInventory != nil {
		if err := hooks.afterFirstInventory(); err != nil {
			return CurrentBundle{}, fmt.Errorf("observation first-inventory synchronization: %w", err)
		}
	}
	if total > limits.total {
		return CurrentBundle{}, fmt.Errorf("observation exceeds byte bound: %w", ErrInvalid)
	}
	rootEntries, rootManifestBytes, err := readManifest(cache, "", "MANIFEST.sha256", files, limits.manifest)
	if err != nil {
		return CurrentBundle{}, err
	}
	indexBytes, err := cache.read("index.json", limits.file)
	if err != nil {
		return CurrentBundle{}, err
	}
	var index indexFile
	if err := decodeJSON(indexBytes, &index); err != nil {
		return CurrentBundle{}, fmt.Errorf("decode index: %w", err)
	}
	if index.Schema != IndexSchema {
		return CurrentBundle{}, fmt.Errorf("invalid index schema: %w", ErrInvalid)
	}
	if len(index.Contexts) != 1 {
		return CurrentBundle{}, fmt.Errorf("%w: exactly one context required", ErrAmbiguous)
	}
	indexCtx := index.Contexts[0]
	if indexCtx.OmissionCount < 0 {
		return CurrentBundle{}, fmt.Errorf("negative context omission count: %w", ErrInvalid)
	}
	if !safeRelativePath(indexCtx.Directory) || strings.Contains(indexCtx.Directory, "/") || indexCtx.Directory == "." || indexCtx.Directory == ".." {
		return CurrentBundle{}, fmt.Errorf("invalid context directory: %w", ErrInvalid)
	}
	// The collector deliberately excludes each context's own manifest from
	// the root manifest. Permit exactly the one manifest named by the verified
	// single-context index; every other root file remains covered below.
	if err := exactFileSet(files, rootEntries, "MANIFEST.sha256", filepath.ToSlash(filepath.Join(indexCtx.Directory, "MANIFEST.sha256"))); err != nil {
		return CurrentBundle{}, err
	}
	ctxFiles := make(map[string]stableIdentity)
	contextPrefix := indexCtx.Directory + "/"
	for path, identity := range files {
		if strings.HasPrefix(path, contextPrefix) {
			ctxFiles[strings.TrimPrefix(path, contextPrefix)] = identity
		}
	}
	ctxEntries, ctxManifestBytes, err := readManifest(cache, indexCtx.Directory, "MANIFEST.sha256", ctxFiles, limits.manifest)
	if err != nil {
		return CurrentBundle{}, err
	}
	if err := exactFileSet(ctxFiles, ctxEntries, "MANIFEST.sha256"); err != nil {
		return CurrentBundle{}, err
	}

	bundle, err := projectContext(cache, indexCtx.Directory, ctxEntries, indexBytes, rootManifestBytes, ctxManifestBytes, indexCtx.CollectionStatus, indexCtx.OmissionCount)
	if err != nil {
		return CurrentBundle{}, err
	}
	secondRoot, err := root.ownedSnapshot()
	if err != nil {
		return CurrentBundle{}, err
	}
	defer secondRoot.Close()
	second, secondDirectories, secondRootIdentity, secondTotal, err := inventoryFiles(ctx, secondRoot, "", limits, hooks)
	if err != nil {
		return CurrentBundle{}, err
	}
	if secondTotal != total || !firstRootIdentity.equal(secondRootIdentity) || !sameInventory(files, second) || !sameInventory(directories, secondDirectories) {
		return CurrentBundle{}, fmt.Errorf("observation tree changed during import: %w", ErrIntegrity)
	}
	return bundle, nil
}

// Marshal returns deterministic JSON bytes for a projected bundle.
func Marshal(bundle CurrentBundle) ([]byte, error) { return json.Marshal(bundle) }

func projectContext(cache *byteCache, ctx string, entries []manifestEntry, indexBytes, rootManifestBytes, ctxManifestBytes []byte, collectionStatus string, declaredOmissions int) (CurrentBundle, error) {
	bundle := CurrentBundle{APIVersion: APIVersion, Kind: Kind, Components: []Component{}, Conflicts: []Conflict{}, Omissions: []Omission{}, SourceDigests: []string{digest(indexBytes), digest(rootManifestBytes), digest(ctxManifestBytes)}}
	rootDigest := digest(rootManifestBytes)[len("sha256:"):]
	addDigest := func(d string) {
		if !contains(bundle.SourceDigests, d) {
			bundle.SourceDigests = append(bundle.SourceDigests, d)
		}
	}
	states := map[string]*componentState{}
	getState := func(id string) *componentState {
		if states[id] == nil {
			states[id] = &componentState{id: id, versions: map[string]struct{}{}, roles: map[string]struct{}{}, predicates: map[string]json.RawMessage{}, predicateSources: map[string]map[string]struct{}{}, predicateStates: map[string]string{}, predicateRoles: map[string]string{}, predicateClasses: map[string]string{}, digests: map[string]struct{}{rootDigest: {}}}
		}
		return states[id]
	}
	addOmission := func(code string) error {
		if code == "" || !codeRE.MatchString(code) {
			return fmt.Errorf("invalid omission code: %w", ErrInvalid)
		}
		for _, o := range bundle.Omissions {
			if o.Code == code {
				return nil
			}
		}
		bundle.Omissions = append(bundle.Omissions, Omission{Code: code})
		return nil
	}
	serverSeen := false
	metadataSeen := false
	metadataStatus := ""
	metadataOmissions := -1
	certManagerProjectionDigest := ""
	configurationAdapterVersion := ""
	var observationMetadata *metadataFile
	var persistedSurfaceMetadata *surfaceMetadata
	configurationSurfaceSeen := false
	omissionsSeen := false
	for _, entry := range entries {
		base := filepath.Base(entry.Path)
		data, err := cache.read(filepath.ToSlash(filepath.Join(ctx, entry.Path)), maxFileBytes)
		if err != nil {
			return CurrentBundle{}, err
		}
		addDigest("sha256:" + entry.Digest)
		switch base {
		case "server-version.json":
			var server serverVersionFile
			if err := decodeJSON(data, &server); err != nil {
				return CurrentBundle{}, fmt.Errorf("decode server version: %w", err)
			}
			if err := validateServerVersionFields(server); err != nil {
				return CurrentBundle{}, err
			}
			version, ok := normalizeKubernetesVersion(server.GitVersion)
			if !ok {
				return CurrentBundle{}, fmt.Errorf("invalid server version: %w", ErrInvalid)
			}
			if serverSeen && bundle.KubernetesVersion != version {
				return CurrentBundle{}, fmt.Errorf("conflicting Kubernetes versions: %w", ErrIntegrity)
			}
			bundle.KubernetesVersion, serverSeen = version, true
			bundle.KubernetesSourceDigests = append(bundle.KubernetesSourceDigests, "sha256:"+entry.Digest)
		case "snapshot-metadata.json":
			var metadata metadataFile
			if err := decodeJSON(data, &metadata); err != nil {
				return CurrentBundle{}, fmt.Errorf("decode snapshot metadata: %w", err)
			}
			if err := validateSnapshotMetadata(metadata); err != nil {
				return CurrentBundle{}, err
			}
			if err := validateSyntheticMetadata(metadata); err != nil {
				return CurrentBundle{}, err
			}
			if metadata.Schema != ObservationSchema || metadata.Format != "KubeconfigAPIObservation" {
				return CurrentBundle{}, fmt.Errorf("invalid snapshot metadata: %w", ErrInvalid)
			}
			if metadata.OmissionCount < 0 {
				return CurrentBundle{}, fmt.Errorf("negative metadata omission count: %w", ErrInvalid)
			}
			if metadata.CollectionStatus != "complete_for_declared_surface" && metadata.CollectionStatus != "partial_for_declared_surface" {
				return CurrentBundle{}, fmt.Errorf("invalid collection status: %w", ErrInvalid)
			}
			if metadata.KubectlStderrClassifierDigest != "" && !digestRE.MatchString(metadata.KubectlStderrClassifierDigest) {
				return CurrentBundle{}, fmt.Errorf("invalid kubectl classifier digest: %w", ErrInvalid)
			}
			if metadata.KubectlBoundedRunnerDigest != "" && !digestRE.MatchString(metadata.KubectlBoundedRunnerDigest) {
				return CurrentBundle{}, fmt.Errorf("invalid bounded runner digest: %w", ErrInvalid)
			}
			if (metadata.ImageSourcesDigest == nil) != (metadata.ImageSourcesSchema == nil) {
				return CurrentBundle{}, fmt.Errorf("image sources digest and schema must be recorded together: %w", ErrInvalid)
			}
			if metadata.ImageSourcesDigest != nil && (!digestRE.MatchString(*metadata.ImageSourcesDigest) || len(*metadata.ImageSourcesSchema) == 0 || len(*metadata.ImageSourcesSchema) > 128 || strings.ContainsAny(*metadata.ImageSourcesSchema, "\x00\r\n")) {
				return CurrentBundle{}, fmt.Errorf("invalid image sources digest or schema: %w", ErrInvalid)
			}
			if metadata.IncludeComponentConfiguration {
				if metadata.ComponentConfigurationAdapterVersion == nil || metadata.ComponentConfigurationRegistryVersion == nil || metadata.ComponentConfigurationRegistryDigest == nil || metadata.ComponentConfigurationFilterDigest == nil || metadata.ComponentConfigurationAggregateDigest == nil || metadata.ComponentConfigurationStrictJSONDigest == nil {
					return CurrentBundle{}, fmt.Errorf("component configuration metadata is incomplete: %w", ErrInvalid)
				}
				for _, digest := range []*string{metadata.ComponentConfigurationRegistryDigest, metadata.ComponentConfigurationFilterDigest, metadata.ComponentConfigurationAggregateDigest, metadata.ComponentConfigurationStrictJSONDigest} {
					if !digestRE.MatchString(*digest) {
						return CurrentBundle{}, fmt.Errorf("component configuration metadata digest is invalid: %w", ErrInvalid)
					}
				}
			}
			metadataSeen = true
			metadataCopy := metadata
			observationMetadata = &metadataCopy
			metadataStatus, metadataOmissions = metadata.CollectionStatus, metadata.OmissionCount
		case "component-configuration-surface.json":
			if configurationSurfaceSeen {
				return CurrentBundle{}, fmt.Errorf("duplicate component configuration surface: %w", ErrIntegrity)
			}
			configurationSurfaceSeen = true
			var surface surfaceFile
			if err := decodeJSON(data, &surface); err != nil {
				return CurrentBundle{}, fmt.Errorf("decode configuration surface: %w", err)
			}
			if surface.APIVersion != "prufyx.io/configuration-surface/v1alpha1" || surface.Kind != "ComponentConfigurationSurface" {
				return CurrentBundle{}, fmt.Errorf("invalid configuration surface: %w", ErrInvalid)
			}
			if surface.LicenseCopyrightDisposition != "" && surface.LicenseCopyrightDisposition != "metadata_only_derived_predicates" {
				return CurrentBundle{}, fmt.Errorf("invalid configuration surface licensing disposition: %w", ErrInvalid)
			}
			if err := validateSurfaceMetadata(surface.Metadata); err != nil {
				return CurrentBundle{}, err
			}
			if surface.Metadata.AdapterVersion == configurationAdapterV3 {
				if configurationAdapterVersion != "" && configurationAdapterVersion != surface.Metadata.AdapterVersion {
					return CurrentBundle{}, fmt.Errorf("conflicting component configuration adapter versions: %w", ErrIntegrity)
				}
				configurationAdapterVersion = surface.Metadata.AdapterVersion
			}
			surfaceMetadataCopy := surface.Metadata
			persistedSurfaceMetadata = &surfaceMetadataCopy
			if observationMetadata != nil && observationMetadata.IncludeComponentConfiguration {
				if observationMetadata.ComponentConfigurationAdapterVersion == nil || observationMetadata.ComponentConfigurationRegistryVersion == nil || observationMetadata.ComponentConfigurationRegistryDigest == nil || observationMetadata.ComponentConfigurationFilterDigest == nil || observationMetadata.ComponentConfigurationAggregateDigest == nil || observationMetadata.ComponentConfigurationStrictJSONDigest == nil || surface.Metadata.AdapterVersion != *observationMetadata.ComponentConfigurationAdapterVersion || surface.Metadata.RegistryVersion != *observationMetadata.ComponentConfigurationRegistryVersion || surface.Metadata.RegistryDigest != *observationMetadata.ComponentConfigurationRegistryDigest || surface.Metadata.FilterDigest != *observationMetadata.ComponentConfigurationFilterDigest || surface.Metadata.AggregateDigest != *observationMetadata.ComponentConfigurationAggregateDigest || surface.Metadata.StrictJSONDigest != *observationMetadata.ComponentConfigurationStrictJSONDigest {
					return CurrentBundle{}, fmt.Errorf("component configuration metadata does not match persisted surface: %w", ErrIntegrity)
				}
			}
			if surface.Metadata.CertManagerProjectionDigest != nil {
				digest := *surface.Metadata.CertManagerProjectionDigest
				if !digestRE.MatchString(digest) {
					return CurrentBundle{}, fmt.Errorf("invalid cert-manager projection digest: %w", ErrInvalid)
				}
				if certManagerProjectionDigest != "" && certManagerProjectionDigest != digest {
					return CurrentBundle{}, fmt.Errorf("conflicting cert-manager projection digests: %w", ErrIntegrity)
				}
				certManagerProjectionDigest = digest
			}
			if len(surface.Components) > maxComponents || len(surface.Omissions) > maxArrayItems {
				return CurrentBundle{}, fmt.Errorf("configuration surface exceeds bound: %w", ErrInvalid)
			}
			for _, omission := range surface.Omissions {
				if omission.Reason == "" && omission.SourceFile == "" && omission.Count == 0 && !omission.RequiredForEvaluation {
					if err := addOmission(omission.Code); err != nil {
						return CurrentBundle{}, err
					}
					continue
				}
				if omission.Code == "" || omission.Reason == "" || omission.SourceFile == "" || !validConfigurationOmissionSource(omission.Code, omission.SourceFile) || omission.Count < 1 || omission.Count > 1000000 || strings.ContainsAny(omission.Reason, "\x00\r\n") || strings.ContainsAny(omission.SourceFile, "\x00\r\n/") {
					return CurrentBundle{}, fmt.Errorf("invalid configuration omission provenance: %w", ErrInvalid)
				}
				bundle.Omissions = append(bundle.Omissions, Omission{Code: omission.Code, Reason: omission.Reason, RequiredForEvaluation: omission.RequiredForEvaluation, SourceFile: omission.SourceFile, Count: omission.Count})
			}
			for _, row := range surface.Components {
				if err := validateComponentID(row.ComponentID); err != nil {
					return CurrentBundle{}, err
				}
				if !validConfigurationObservation(row) {
					return CurrentBundle{}, fmt.Errorf("invalid configuration observation state or version scheme: %w", ErrInvalid)
				}
				if row.ObservedVersion != nil {
					version, ok := normalizeVersion(*row.ObservedVersion)
					if !ok {
						return CurrentBundle{}, fmt.Errorf("invalid component version: %w", ErrInvalid)
					}
					*row.ObservedVersion = version
				}
				if row.ObservationCount < 1 || row.ObservationCount > maxArrayItems {
					return CurrentBundle{}, fmt.Errorf("invalid observation count: %w", ErrInvalid)
				}
				if err := validateProducerBoundPredicates(surface.Metadata, row); err != nil {
					return CurrentBundle{}, err
				}
				st := getState(row.ComponentID)
				st.digests[entry.Digest] = struct{}{}
				rowRoles := make(map[string]struct{}, len(row.Roles))
				for _, role := range row.Roles {
					if !syntheticLogicalRole(role) {
						return CurrentBundle{}, fmt.Errorf("invalid component role: %w", ErrInvalid)
					}
					if _, duplicate := rowRoles[role]; duplicate {
						return CurrentBundle{}, fmt.Errorf("duplicate component role: %w", ErrInvalid)
					}
					rowRoles[role] = struct{}{}
					st.roles[role] = struct{}{}
				}
				if row.ObservedVersion != nil && row.VersionScheme != "digest" {
					st.versions[*row.ObservedVersion] = struct{}{}
				}
				if len(row.ConflictingVersions) != 0 {
					if !row.VersionConflict || row.ObservationState != "conflict" || len(row.ConflictingVersions) < 2 || len(row.ConflictingVersions) > 8 {
						return CurrentBundle{}, fmt.Errorf("invalid conflicting version set: %w", ErrInvalid)
					}
					for _, version := range row.ConflictingVersions {
						normalized, ok := normalizeVersion(version)
						if !ok {
							return CurrentBundle{}, fmt.Errorf("invalid conflicting version: %w", ErrInvalid)
						}
						st.versions[normalized] = struct{}{}
					}
				}
				if row.VersionConflict || row.ObservationState == "conflict" {
					st.conflict = true
				}
				if len(row.Predicates) > maxPredicates {
					return CurrentBundle{}, fmt.Errorf("too many predicates: %w", ErrInvalid)
				}
				keys := make([]string, 0, len(row.Predicates))
				for key, value := range row.Predicates {
					if len(key) > maxStringBytes || !strings.HasPrefix(key, "component.") || !scalarPredicate(value) {
						return CurrentBundle{}, fmt.Errorf("invalid predicate: %w", ErrInvalid)
					}
					keys = append(keys, key)
				}
				sort.Strings(keys)
				for _, key := range keys {
					if st.predicateSources[key] == nil {
						st.predicateSources[key] = map[string]struct{}{}
					}
					st.predicateSources[key][entry.Digest] = struct{}{}
					if prior, ok := st.predicates[key]; ok && !bytes.Equal(prior, row.Predicates[key]) {
						st.conflict = true
					} else {
						st.predicates[key] = append([]byte(nil), row.Predicates[key]...)
					}
				}
				seenEvidence := map[string]struct{}{}
				for _, evidence := range row.PredicateEvidence {
					if _, duplicate := seenEvidence[evidence.PredicateID]; duplicate || !strings.HasPrefix(evidence.PredicateID, "component.") || !syntheticPredicateState(evidence.State) || !syntheticLogicalRole(evidence.SourceRole) || !knownEvidenceClass(evidence.EvidenceClass) {
						return CurrentBundle{}, fmt.Errorf("invalid predicate evidence: %w", ErrInvalid)
					}
					declaredProducer := surface.Metadata.AdapterVersion == configurationAdapterV2 || surface.Metadata.AdapterVersion == configurationAdapterV3
					if declaredProducer && evidence.EvidenceClass != "declared_container_context_v1" {
						return CurrentBundle{}, fmt.Errorf("declared predicate evidence is missing its context class: %w", ErrInvalid)
					}
					if evidence.EvidenceClass == "declared_container_context_v1" && !declaredProducer {
						return CurrentBundle{}, fmt.Errorf("declared context class is not producer-bound: %w", ErrIntegrity)
					}
					if _, ok := rowRoles[evidence.SourceRole]; !ok {
						return CurrentBundle{}, fmt.Errorf("predicate evidence source role is not bound in its component row: %w", ErrIntegrity)
					}
					seenEvidence[evidence.PredicateID] = struct{}{}
					if evidence.State == "observed" {
						if _, ok := row.Predicates[evidence.PredicateID]; !ok {
							return CurrentBundle{}, fmt.Errorf("observed predicate evidence missing value: %w", ErrIntegrity)
						}
					} else if _, ok := row.Predicates[evidence.PredicateID]; ok {
						return CurrentBundle{}, fmt.Errorf("non-observed predicate evidence carries value: %w", ErrIntegrity)
					}
					if prior, exists := st.predicateRoles[evidence.PredicateID]; exists && (prior != evidence.SourceRole || st.predicateStates[evidence.PredicateID] != evidence.State || st.predicateClasses[evidence.PredicateID] != evidence.EvidenceClass) {
						return CurrentBundle{}, fmt.Errorf("conflicting predicate evidence binding: %w", ErrIntegrity)
					}
					st.predicateStates[evidence.PredicateID] = evidence.State
					st.predicateRoles[evidence.PredicateID] = evidence.SourceRole
					st.predicateClasses[evidence.PredicateID] = evidence.EvidenceClass
					if st.predicateSources[evidence.PredicateID] == nil {
						st.predicateSources[evidence.PredicateID] = map[string]struct{}{}
					}
					st.predicateSources[evidence.PredicateID][entry.Digest] = struct{}{}
				}
			}
		case "omissions.tsv":
			if omissionsSeen {
				return CurrentBundle{}, fmt.Errorf("duplicate omissions file: %w", ErrIntegrity)
			}
			omissionsSeen = true
			omissions, omissionErr := parseOmissions(data)
			if omissionErr != nil {
				return CurrentBundle{}, fmt.Errorf("parse omissions: %w", omissionErr)
			}
			if err := validateCollection(collectionStatus, declaredOmissions, len(omissions)); err != nil {
				return CurrentBundle{}, err
			}
			for _, code := range omissions {
				if err := addOmission(code); err != nil {
					return CurrentBundle{}, err
				}
			}
		default:
			if isWorkloadImageFile(base) {
				role := workloadRole(base)
				var rows []imageSummary
				if err := decodeJSON(data, &rows); err != nil || len(rows) > maxArrayItems {
					return CurrentBundle{}, fmt.Errorf("invalid workload image summary: %w", ErrInvalid)
				}
				for _, row := range rows {
					if err := validateComponentID(row.ComponentID); err != nil {
						return CurrentBundle{}, err
					}
					if !validWorkloadObservation(row) {
						return CurrentBundle{}, fmt.Errorf("invalid workload observation state or version scheme: %w", ErrInvalid)
					}
					st := getState(row.ComponentID)
					st.digests[entry.Digest] = struct{}{}
					st.roles[role] = struct{}{}
					version := ""
					if row.ObservedVersion != nil {
						var ok bool
						version, ok = normalizeVersion(*row.ObservedVersion)
						if !ok {
							return CurrentBundle{}, fmt.Errorf("invalid workload version: %w", ErrInvalid)
						}
						*row.ObservedVersion = version
					}
					if row.ObservedVersion == nil || row.VersionScheme == "digest" || row.VersionScheme == "unknown" || row.ObservationState != "active" {
						// A tag pinned by digest (version present, scheme digest) is
						// the adapter path's own pinned form: it adds no version but
						// does not contradict one. Every other row without a usable
						// version leaves the whole component unresolved.
						if row.ObservedVersion == nil || row.VersionScheme == "unknown" || row.ObservationState != "active" {
							st.unresolved = true
						}
						if err := addOmission("COMPONENT_CONFIGURATION_VERSION_UNRESOLVED"); err != nil {
							return CurrentBundle{}, err
						}
					} else {
						st.versions[version] = struct{}{}
					}
					if row.ObservationCount < 1 || row.ObservationCount > maxArrayItems || row.ObservationState != "active" || row.VersionConflict {
						st.conflict = true
					}
				}
			}
		}
	}
	if !serverSeen {
		// Authorization failures can prevent the discovery endpoint from being
		// read.  Preserve that as an explicit UNKNOWN only for a collector
		// partial result; a complete result missing the required file is invalid.
		if collectionStatus != "partial_for_declared_surface" {
			return CurrentBundle{}, fmt.Errorf("server-version.json missing: %w", ErrInvalid)
		}
		if err := addOmission("KUBERNETES_VERSION_UNOBSERVED"); err != nil {
			return CurrentBundle{}, err
		}
	}
	if observationMetadata != nil && observationMetadata.IncludeComponentConfiguration && persistedSurfaceMetadata == nil {
		return CurrentBundle{}, fmt.Errorf("component configuration surface missing: %w", ErrIntegrity)
	}
	if observationMetadata != nil && !observationMetadata.IncludeComponentConfiguration && persistedSurfaceMetadata != nil && persistedSurfaceMetadata.AdapterVersion != "" {
		return CurrentBundle{}, fmt.Errorf("component configuration surface was not enabled by snapshot metadata: %w", ErrIntegrity)
	}
	if observationMetadata != nil && observationMetadata.IncludeComponentConfiguration && persistedSurfaceMetadata != nil {
		if observationMetadata.ComponentConfigurationAdapterVersion == nil || observationMetadata.ComponentConfigurationRegistryVersion == nil || observationMetadata.ComponentConfigurationRegistryDigest == nil || observationMetadata.ComponentConfigurationFilterDigest == nil || observationMetadata.ComponentConfigurationAggregateDigest == nil || observationMetadata.ComponentConfigurationStrictJSONDigest == nil || persistedSurfaceMetadata.AdapterVersion != *observationMetadata.ComponentConfigurationAdapterVersion || persistedSurfaceMetadata.RegistryVersion != *observationMetadata.ComponentConfigurationRegistryVersion || persistedSurfaceMetadata.RegistryDigest != *observationMetadata.ComponentConfigurationRegistryDigest || persistedSurfaceMetadata.FilterDigest != *observationMetadata.ComponentConfigurationFilterDigest || persistedSurfaceMetadata.AggregateDigest != *observationMetadata.ComponentConfigurationAggregateDigest || persistedSurfaceMetadata.StrictJSONDigest != *observationMetadata.ComponentConfigurationStrictJSONDigest {
			return CurrentBundle{}, fmt.Errorf("component configuration metadata does not match persisted surface: %w", ErrIntegrity)
		}
	}
	if !metadataSeen || !omissionsSeen || metadataStatus != collectionStatus || metadataOmissions != declaredOmissions {
		return CurrentBundle{}, fmt.Errorf("collection metadata mismatch: %w", ErrIntegrity)
	}
	// generatedAt is a source binding, not a caller-provided label. Preserve
	// whether both verified metadata surfaces agree so a downstream seam can
	// reject missing, malformed, or conflicting capture times explicitly.
	bundle.SourceCollectionStatus = collectionStatus
	if observationMetadata != nil {
		bundle.SourceOmissionCodes = make([]string, 0, len(bundle.Omissions))
		for _, omission := range bundle.Omissions {
			bundle.SourceOmissionCodes = append(bundle.SourceOmissionCodes, omission.Code)
		}
		sort.Strings(bundle.SourceOmissionCodes)
	}
	indexGeneratedAt := ""
	var indexDoc indexFile
	if err := decodeJSON(indexBytes, &indexDoc); err == nil {
		indexGeneratedAt = indexDoc.GeneratedAt
	}
	metadataGeneratedAt := ""
	if observationMetadata != nil {
		metadataGeneratedAt = observationMetadata.GeneratedAt
	}
	indexTime, indexOK := parseSourceTime(indexGeneratedAt)
	metadataTime, metadataOK := parseSourceTime(metadataGeneratedAt)
	if indexOK && metadataOK {
		if indexTime.Equal(metadataTime) {
			bundle.SourceGeneratedAt = indexTime.UTC().Format(time.RFC3339Nano)
			bundle.SourceGeneratedAtValid = true
		} else {
			bundle.SourceGeneratedAtConflict = true
		}
	} else if indexGeneratedAt != "" || metadataGeneratedAt != "" {
		// A partial or malformed pair is deliberately represented as invalid
		// source time. The project-current boundary turns this into a rejection.
		bundle.SourceGeneratedAtConflict = indexGeneratedAt != "" && metadataGeneratedAt != ""
	}
	bundle.CertManagerProjectionDigest = certManagerProjectionDigest
	bundle.ConfigurationAdapterVersion = configurationAdapterVersion
	if observationMetadata != nil && observationMetadata.ImageSourcesDigest != nil {
		bundle.ImageSourcesDigest, bundle.ImageSourcesSchema = *observationMetadata.ImageSourcesDigest, *observationMetadata.ImageSourcesSchema
	}
	if observationMetadata != nil && observationMetadata.SyntheticClassification != "" {
		bundle.Synthetic = &SyntheticProvenance{Classification: observationMetadata.SyntheticClassification, Authority: observationMetadata.SyntheticAuthority, Canary: observationMetadata.SyntheticCanary, NonAuthoritative: observationMetadata.SyntheticNonAuthoritative}
	}
	for _, st := range states {
		for predicateID, evidenceClass := range st.predicateClasses {
			if evidenceClass == "synthetic_fixture_context_v1" && bundle.Synthetic == nil {
				return CurrentBundle{}, fmt.Errorf("synthetic evidence class lacks coherent synthetic provenance for %s: %w", predicateID, ErrIntegrity)
			}
		}
	}
	if len(states) > maxComponents {
		return CurrentBundle{}, fmt.Errorf("too many components: %w", ErrInvalid)
	}
	ids := make([]string, 0, len(states))
	for id := range states {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		st := states[id]
		versions := sortedKeys(st.versions)
		status := "observed"
		version := ""
		if len(versions) == 1 && !st.conflict && !st.unresolved {
			version = versions[0]
		} else if len(versions) > 1 || st.conflict || (st.unresolved && len(versions) >= 1) {
			status = "conflict"
			bundle.Conflicts = append(bundle.Conflicts, Conflict{ComponentID: id, Kind: "version_or_predicate", Values: versions})
		} else {
			status = "unknown"
		}
		roles := sortedKeys(st.roles)
		predicates := make([]Predicate, 0, len(st.predicateSources))
		pkeys := make([]string, 0, len(st.predicateSources))
		for key := range st.predicates {
			pkeys = append(pkeys, key)
		}
		for key := range st.predicateStates {
			if _, exists := st.predicates[key]; !exists {
				pkeys = append(pkeys, key)
			}
		}
		sort.Strings(pkeys)
		for _, key := range pkeys {
			state := st.predicateStates[key]
			if state == "" {
				state = "observed"
			}
			predicates = append(predicates, Predicate{ID: key, Value: st.predicates[key], State: state, Role: st.predicateRoles[key], EvidenceClass: st.predicateClasses[key], SourceDigests: prefixDigests(sortedKeys(st.predicateSources[key]))})
		}
		digests := sortedKeys(st.digests)
		bundle.Components = append(bundle.Components, Component{ComponentID: id, Version: version, Status: status, Roles: roles, Predicates: predicates, SourceDigests: prefixDigests(digests)})
	}
	sort.Strings(bundle.SourceDigests)
	sort.Slice(bundle.Conflicts, func(i, j int) bool { return bundle.Conflicts[i].ComponentID < bundle.Conflicts[j].ComponentID })
	sort.Slice(bundle.Omissions, func(i, j int) bool { return bundle.Omissions[i].Code < bundle.Omissions[j].Code })
	return bundle, nil
}

func syntheticLogicalRole(role string) bool {
	switch role {
	case "server", "controller", "application-controller", "repo-server", "workflow-controller", "webhook", "cainjector":
		return true
	default:
		return false
	}
}

func syntheticPredicateState(state string) bool {
	switch state {
	case "observed", "missing", "ambiguous", "stale", "conflicting", "unsupported":
		return true
	default:
		return false
	}
}

func knownEvidenceClass(class string) bool {
	switch class {
	case "", "declared_container_context_v1", "synthetic_fixture_context_v1":
		return true
	default:
		return false
	}
}

func validateProducerBoundPredicates(metadata surfaceMetadata, row surfaceComponent) error {
	_, hasAgentMode := row.Predicates[prometheusAgentModePredicate]
	_, hasImageDigest := row.Predicates[prometheusImageDigestPredicate]
	for _, evidence := range row.PredicateEvidence {
		hasAgentMode = hasAgentMode || evidence.PredicateID == prometheusAgentModePredicate
		hasImageDigest = hasImageDigest || evidence.PredicateID == prometheusImageDigestPredicate
	}
	if !hasAgentMode && !hasImageDigest {
		return nil
	}
	if metadata.SchemaVersion != "1.1.0" || metadata.AdapterVersion != configurationAdapterV3 || metadata.RegistryVersion != "v3" {
		return fmt.Errorf("Prometheus identity predicates are not producer-v3-bound: %w", ErrIntegrity)
	}
	if row.ComponentID != prometheusID || row.ObservedVersion == nil || row.VersionScheme != "tag" {
		return fmt.Errorf("Prometheus identity predicates are outside their component/version binding: %w", ErrIntegrity)
	}
	expectedDigest, ok := ApprovedPrometheusImageDigest(*row.ObservedVersion)
	if !ok {
		return fmt.Errorf("Prometheus identity predicates use an unsupported version: %w", ErrInvalid)
	}
	agentRaw, agentOK := row.Predicates[prometheusAgentModePredicate]
	imageRaw, imageOK := row.Predicates[prometheusImageDigestPredicate]
	if !agentOK || !imageOK || !scalarPredicate(agentRaw) || !scalarPredicate(imageRaw) {
		return fmt.Errorf("Prometheus identity predicates are incomplete: %w", ErrIntegrity)
	}
	var agentMode bool
	if err := json.Unmarshal(agentRaw, &agentMode); err != nil {
		return fmt.Errorf("Prometheus agent-mode predicate is not boolean: %w", ErrInvalid)
	}
	var imageDigest string
	if err := json.Unmarshal(imageRaw, &imageDigest); err != nil || imageDigest != expectedDigest {
		return fmt.Errorf("Prometheus image digest does not match the approved version binding: %w", ErrIntegrity)
	}
	roleBound := false
	for _, role := range row.Roles {
		roleBound = roleBound || role == "server"
	}
	if !roleBound {
		return fmt.Errorf("Prometheus identity predicates are not server-role-bound: %w", ErrIntegrity)
	}
	evidenceByID := map[string]surfacePredicateEvidence{}
	for _, evidence := range row.PredicateEvidence {
		if evidence.PredicateID != prometheusAgentModePredicate && evidence.PredicateID != prometheusImageDigestPredicate {
			continue
		}
		if _, duplicate := evidenceByID[evidence.PredicateID]; duplicate {
			return fmt.Errorf("duplicate Prometheus identity predicate evidence: %w", ErrInvalid)
		}
		evidenceByID[evidence.PredicateID] = evidence
	}
	for _, predicateID := range []string{prometheusAgentModePredicate, prometheusImageDigestPredicate} {
		evidence, ok := evidenceByID[predicateID]
		if !ok || evidence.State != "observed" || evidence.SourceRole != "server" || evidence.EvidenceClass != "declared_container_context_v1" {
			return fmt.Errorf("Prometheus identity predicate lacks same-row declared server evidence: %w", ErrIntegrity)
		}
	}
	return nil
}

func validConfigurationOmissionSource(code, source string) bool {
	if surfaceFileRE.MatchString(source) {
		return true
	}
	switch source {
	case "component-configuration-aggregate":
		return code == "COMPONENT_CONFIGURATION_DECLARED_ROLE_AMBIGUOUS"
	case "cert-manager-derived-predicates":
		return code == "COMPONENT_CONFIGURATION_CRD_SURFACE_UNAVAILABLE" ||
			code == "COMPONENT_CONFIGURATION_API_UNAVAILABLE" ||
			code == "COMPONENT_CONFIGURATION_RBAC_FORBIDDEN" ||
			code == "COMPONENT_CONFIGURATION_HEALTH_UNAVAILABLE"
	default:
		return false
	}
}

// approvedPrometheusImageDigestTable is the single source of truth for the
// Prometheus image digests this verifier will honor. Both the observation
// projection and the currentbundle projection read it through
// ApprovedPrometheusImageDigest; neither keeps its own copy.
//
// The same digests are mirrored as entrypointContract.imageBindings[].
// platformDigests for pkg:oci/prometheus/prometheus in
// internal/localcollector/assets/component-configuration-adapters-v3.json,
// because the collector matches observed images against the asset before this
// table is ever consulted. That mirror is not a second source of truth: the
// localcollector test TestAdapterAssetPrometheusDigestsMatchApprovedTable
// fails if the two ever diverge in either direction. A digest is added,
// removed, or changed in both places in the same commit, or in neither.
//
// Known gap, tracked separately and deliberately not addressed here: every
// platformDigests array currently holds exactly one digest and it is the
// linux/arm64/v8 platform digest, so an amd64 cluster running the same tag is
// reported as unverified_image. Capture is being changed to record every
// platform. The sync test compares both sides as sets and assumes nothing
// about how many digests a version has, so it needs no rewrite for that work;
// it will however fail the moment the asset carries a platform digest this
// table does not honor, which is the point. Widen both sides together.
var approvedPrometheusImageDigestTable = map[string]string{
	"2.55.1": "sha256:f4def6b3b61109a6eeea59945d578bb7e926c36cb0e036a23e3ceb8b6de024ad",
	"3.1.0":  "sha256:0ea5254abf85f87901e8cfbd18fd243c59162c338ce0acd86aa2b0153d83dce2",
}

// ApprovedPrometheusImageDigest reports the approved image digest bound to an
// observed Prometheus version, and whether that version is approved at all.
// An unapproved version yields ("", false) and must be rejected by the caller.
func ApprovedPrometheusImageDigest(version string) (string, bool) {
	digest, ok := approvedPrometheusImageDigestTable[version]
	return digest, ok
}

// ApprovedPrometheusImageDigests returns a copy of the approved version-to-
// digest table, for tests and reporting that need to enumerate it. The copy
// keeps callers from mutating a trust anchor through the returned map.
func ApprovedPrometheusImageDigests() map[string]string {
	out := make(map[string]string, len(approvedPrometheusImageDigestTable))
	for version, digest := range approvedPrometheusImageDigestTable {
		out[version] = digest
	}
	return out
}

func parseSourceTime(value string) (time.Time, bool) {
	if value == "" {
		return time.Time{}, false
	}
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil || parsed.IsZero() || parsed.Location() != time.UTC || parsed.UTC().Format(time.RFC3339Nano) != value {
		return time.Time{}, false
	}
	return parsed, true
}

func validWorkloadVersionScheme(scheme string, hasVersion bool) bool {
	if hasVersion {
		return scheme == "semver" || scheme == "calver" || scheme == "tag" || scheme == "digest"
	}
	return scheme == "digest" || scheme == "unknown"
}

func validConfigurationVersionScheme(scheme string, hasVersion bool) bool {
	if hasVersion {
		return scheme == "tag" || scheme == "digest"
	}
	return scheme == "unknown"
}

func validConfigurationObservation(row surfaceComponent) bool {
	if row.ObservationState == "conflict" {
		return row.ObservedVersion == nil && row.VersionScheme == "unknown" && row.VersionConflict
	}
	return row.ObservationState == "observed" && !row.VersionConflict && validConfigurationVersionScheme(row.VersionScheme, row.ObservedVersion != nil)
}

func validWorkloadObservation(row imageSummary) bool {
	if row.ObservationState == "conflict" {
		return row.ObservedVersion == nil && row.VersionScheme == "unknown" && row.VersionConflict
	}
	return (row.ObservationState == "active" || row.ObservationState == "declared") && !row.VersionConflict && validWorkloadVersionScheme(row.VersionScheme, row.ObservedVersion != nil)
}

func validateComponentID(id string) error {
	if !idRE.MatchString(id) || len(id) > maxStringBytes {
		return fmt.Errorf("invalid public component id: %w", ErrInvalid)
	}
	return nil
}
func isWorkloadImageFile(name string) bool {
	for _, prefix := range []string{"deployment", "daemonset", "statefulset", "replicaset", "job", "cronjob", "replicationcontroller"} {
		if name == prefix+"-images.json" {
			return true
		}
	}
	return false
}

func workloadRole(name string) string {
	name = strings.TrimSuffix(name, "-images.json")
	switch name {
	case "daemonset":
		return "DaemonSet"
	case "statefulset":
		return "StatefulSet"
	case "replicaset":
		return "ReplicaSet"
	case "cronjob":
		return "CronJob"
	case "replicationcontroller":
		return "ReplicationController"
	case "deployment":
		return "Deployment"
	case "job":
		return "Job"
	default:
		return "Unknown"
	}
}
func scalarPredicate(raw json.RawMessage) bool {
	var value any
	if json.Unmarshal(raw, &value) != nil {
		return false
	}
	switch value.(type) {
	case bool, string:
		return len(raw) <= maxStringBytes && validateStrings(value, 0) == nil
	case float64:
		// Numeric predicates are restricted to bounded integral counts. This
		// keeps the observation scalar and avoids precision-sensitive values.
		n := value.(float64)
		return n >= 0 && n <= 1000000 && n == math.Trunc(n)
	default:
		return false
	}
}

type OmissionParseError struct{ Reason string }

func (e *OmissionParseError) Error() string { return "invalid omissions.tsv: " + e.Reason }

func parseOmissions(data []byte) ([]string, error) {
	if len(data) > maxFileBytes {
		return nil, &OmissionParseError{Reason: "file exceeds byte bound"}
	}
	var result []string
	seen := map[string]struct{}{}
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 1024), maxStringBytes*2)
	for scanner.Scan() {
		line := scanner.Text()
		if len(line) > maxStringBytes*2 {
			return nil, &OmissionParseError{Reason: "line exceeds bound"}
		}
		fields := strings.Split(line, "\t")
		if len(fields) != 2 && len(fields) != 3 {
			return nil, &OmissionParseError{Reason: "malformed row"}
		}
		canonical, collectorCode := canonicalCollectorOmission(fields[1])
		if fields[0] == "" || len(fields[0]) > maxStringBytes || (!codeRE.MatchString(fields[1]) && !collectorCode) {
			return nil, &OmissionParseError{Reason: "malformed row"}
		}
		if len(fields) == 3 && (len(fields[2]) > maxStringBytes || strings.IndexByte(fields[2], 0) >= 0) {
			return nil, &OmissionParseError{Reason: "reason exceeds bound"}
		}
		if _, exists := seen[canonical]; exists && !collectorCode {
			return nil, &OmissionParseError{Reason: "duplicate omission code"}
		}
		seen[canonical] = struct{}{}
		result = append(result, canonical)
		if len(result) > maxArrayItems {
			return nil, &OmissionParseError{Reason: "row count exceeds bound"}
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, &OmissionParseError{Reason: "scanner limit"}
	}
	return result, nil
}

// The shell collector historically records its bounded stage classification
// tokens in omissions.tsv. They are an internal, lower-case vocabulary, not
// public omission codes. Accept exactly that closed vocabulary and normalize
// it to the current versioned registry; arbitrary lower-case data remains
// rejected.
func canonicalCollectorOmission(value string) (string, bool) {
	const prefix = "COMPONENT_CONFIGURATION_"
	known := map[string]string{
		"kubernetes_api_read_failed":                                    prefix + "KUBERNETES_API_READ_FAILED",
		"kubernetes_api_read_failed_authentication_exec_plugin_failure": prefix + "KUBERNETES_API_READ_FAILED_AUTHENTICATION_EXEC_PLUGIN_FAILURE",
		"kubernetes_api_read_failed_unauthorized":                       prefix + "KUBERNETES_API_READ_FAILED_UNAUTHORIZED",
		"kubernetes_api_read_failed_authorization_rbac_forbidden":       prefix + "KUBERNETES_API_READ_FAILED_AUTHORIZATION_RBAC_FORBIDDEN",
		"kubernetes_api_read_failed_invalid_kubeconfig_context":         prefix + "KUBERNETES_API_READ_FAILED_INVALID_KUBECONFIG_CONTEXT",
		"kubernetes_api_read_failed_tls_certificate":                    prefix + "KUBERNETES_API_READ_FAILED_TLS_CERTIFICATE",
		"kubernetes_api_read_failed_dns":                                prefix + "KUBERNETES_API_READ_FAILED_DNS",
		"kubernetes_api_read_failed_transport_timeout_unreachable":      prefix + "KUBERNETES_API_READ_FAILED_TRANSPORT_TIMEOUT_UNREACHABLE",
		"kubernetes_api_read_failed_unsupported_not_found_api":          prefix + "KUBERNETES_API_READ_FAILED_UNSUPPORTED_NOT_FOUND_API",
		"strict_json_rejected":                                          prefix + "STRICT_JSON_REJECTED",
		"projection_filter_rejected":                                    prefix + "PROJECTION_FILTER_REJECTED",
		"pipeline_failed":                                               prefix + "PIPELINE_FAILED",
	}
	if mapped, ok := known[value]; ok {
		return mapped, true
	}
	return value, false
}

func validateCollection(status string, declared, parsed int) error {
	if declared < 0 || parsed < 0 || declared != parsed {
		return fmt.Errorf("collection omission count mismatch: %w", ErrIntegrity)
	}
	if status == "complete_for_declared_surface" && declared != 0 {
		return fmt.Errorf("complete collection has omissions: %w", ErrIntegrity)
	}
	if status != "complete_for_declared_surface" && status != "partial_for_declared_surface" && status != "partial" && status != "unknown" {
		return fmt.Errorf("invalid collection status: %w", ErrInvalid)
	}
	return nil
}

func normalizeVersion(raw string) (string, bool) {
	if strings.HasPrefix(raw, "v") {
		raw = strings.TrimPrefix(raw, "v")
	}
	if !versionRE.MatchString(raw) {
		return "", false
	}
	parts := strings.SplitN(raw, "+", 2)
	core := parts[0]
	coreParts := strings.SplitN(core, "-", 2)
	if len(coreParts) == 2 {
		for _, identifier := range strings.Split(coreParts[1], ".") {
			if identifier == "" || (allDigits(identifier) && len(identifier) > 1 && identifier[0] == '0') {
				return "", false
			}
		}
	}
	return raw, true
}

// normalizeKubernetesVersion removes only the reviewed GKE build suffix from
// the Kubernetes server identity. Unreviewed provider suffixes and prerelease
// or build metadata remain intact so they cannot silently become a stable
// numeric compatibility version. Component versions continue to use
// normalizeVersion so their prerelease/build identity is preserved.
func normalizeKubernetesVersion(raw string) (string, bool) {
	version, ok := normalizeVersion(raw)
	if !ok {
		return "", false
	}
	if matches := gkeVersionRE.FindStringSubmatch(version); matches != nil {
		return matches[1], true
	}
	return version, true
}

func allDigits(value string) bool {
	if value == "" {
		return false
	}
	for _, char := range value {
		if char < '0' || char > '9' {
			return false
		}
	}
	return true
}

func validateStrings(value any, depth int) error {
	if depth > maxJSONDepth {
		return fmt.Errorf("JSON depth exceeds bound: %w", ErrInvalid)
	}
	switch typed := value.(type) {
	case string:
		if len(typed) > maxStringBytes || strings.IndexByte(typed, 0) >= 0 {
			return fmt.Errorf("JSON string exceeds bound: %w", ErrInvalid)
		}
	case []any:
		if len(typed) > maxArrayItems {
			return fmt.Errorf("JSON array exceeds bound: %w", ErrInvalid)
		}
		for _, child := range typed {
			if err := validateStrings(child, depth+1); err != nil {
				return err
			}
		}
	case map[string]any:
		if len(typed) > maxObjectMembers {
			return fmt.Errorf("JSON object exceeds bound: %w", ErrInvalid)
		}
		for key, child := range typed {
			if len(key) > maxStringBytes {
				return fmt.Errorf("JSON key exceeds bound: %w", ErrInvalid)
			}
			if err := validateStrings(child, depth+1); err != nil {
				return err
			}
		}
	}
	return nil
}
func contains(values []string, value string) bool {
	for _, item := range values {
		if item == value {
			return true
		}
	}
	return false
}
func sortedKeys(set map[string]struct{}) []string {
	result := make([]string, 0, len(set))
	for key := range set {
		result = append(result, key)
	}
	sort.Strings(result)
	return result
}
func prefixDigests(values []string) []string {
	result := make([]string, len(values))
	for i, value := range values {
		result[i] = "sha256:" + value
	}
	return result
}
func digest(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func inventoryFiles(ctx context.Context, root *os.File, prefix string, limits normalizedLimits, hooks *importReadHooks) (map[string]stableIdentity, map[string]stableIdentity, stableIdentity, int64, error) {
	files := map[string]stableIdentity{}
	directories := map[string]stableIdentity{}
	var total int64
	count := 0
	entriesSeen := 0
	directoriesSeen := 0
	var walk func(*os.File, string, int) error
	walk = func(directory *os.File, currentPrefix string, depth int) error {
		for {
			if err := checkContext(ctx); err != nil {
				return err
			}
			entries, readErr := directory.Readdir(inventoryBatch)
			if readErr != nil && readErr != io.EOF {
				return readErr
			}
			for _, entry := range entries {
				entriesSeen++
				if entriesSeen > limits.files {
					return fmt.Errorf("observation tree exceeds entry bound: %w", ErrInvalid)
				}
				if entry.Name() == "." || entry.Name() == ".." || strings.ContainsAny(entry.Name(), `/\\`) || strings.IndexByte(entry.Name(), 0) >= 0 {
					return fmt.Errorf("invalid observation entry: %w", ErrInvalid)
				}
				rel := filepath.ToSlash(filepath.Join(currentPrefix, entry.Name()))
				if depth >= limits.depth {
					return fmt.Errorf("observation path exceeds depth bound: %w", ErrInvalid)
				}
				entryIdentity, identityErr := observationStatAt(directory, entry.Name())
				if identityErr != nil {
					return fmt.Errorf("classify observation entry: %w", ErrIntegrity)
				}
				if entryIdentity.isDirectory() {
					directoriesSeen++
					if directoriesSeen > limits.directories {
						return fmt.Errorf("observation directory tree exceeds bound: %w", ErrInvalid)
					}
					subdir, openedIdentity, openErr := observationOpenBoundDirectory(directory, entry.Name())
					if openErr != nil {
						return fmt.Errorf("open observation directory: %w", openErr)
					}
					if !entryIdentity.equal(openedIdentity) {
						_ = subdir.Close()
						return fmt.Errorf("observation directory changed while opening: %w", ErrIntegrity)
					}
					directories[rel] = openedIdentity
					walkErr := walk(subdir, rel, depth+1)
					afterIdentity, statErr := observationStableIdentity(subdir)
					_ = subdir.Close()
					if walkErr != nil {
						return walkErr
					}
					if hooks != nil && hooks.afterInventoryDir != nil {
						if hookErr := hooks.afterInventoryDir(rel); hookErr != nil {
							return fmt.Errorf("observation inventory synchronization: %w", hookErr)
						}
					}
					if statErr != nil || !openedIdentity.equal(afterIdentity) {
						return fmt.Errorf("observation directory changed during inventory: %w", ErrIntegrity)
					}
					boundAfter, bindErr := observationStatAt(directory, entry.Name())
					if bindErr != nil || !openedIdentity.equal(boundAfter) {
						return fmt.Errorf("observation directory entry changed during inventory: %w", ErrIntegrity)
					}
					continue
				}
				if !entryIdentity.isRegular() || entryIdentity.links != 1 {
					return fmt.Errorf("non-regular observation file: %w", ErrInvalid)
				}
				file, openedIdentity, openErr := observationOpenBoundFile(directory, entry.Name())
				if openErr != nil {
					return fmt.Errorf("open observation file: %w", openErr)
				}
				_ = file.Close()
				if !entryIdentity.equal(openedIdentity) {
					return fmt.Errorf("observation file changed while opening: %w", ErrIntegrity)
				}
				boundAfter, bindErr := observationStatAt(directory, entry.Name())
				if bindErr != nil || !openedIdentity.equal(boundAfter) {
					return fmt.Errorf("observation file entry changed during inventory: %w", ErrIntegrity)
				}
				count++
				if count > limits.files {
					return fmt.Errorf("too many observation files: %w", ErrInvalid)
				}
				if openedIdentity.size < 0 || openedIdentity.size > limits.file || openedIdentity.size > limits.total-total {
					return fmt.Errorf("observation file exceeds byte bound: %w", ErrInvalid)
				}
				total += openedIdentity.size
				files[rel] = openedIdentity
			}
			if readErr == io.EOF {
				return nil
			}
		}
	}
	rootBefore, rootErr := observationStableIdentity(root)
	if rootErr != nil || !rootBefore.isDirectory() {
		return nil, nil, stableIdentity{}, 0, fmt.Errorf("inventory observation root: %w", ErrIntegrity)
	}
	err := walk(root, prefix, 0)
	if err != nil {
		return nil, nil, stableIdentity{}, 0, fmt.Errorf("inventory observation: %w", err)
	}
	rootAfter, rootErr := observationStableIdentity(root)
	if rootErr != nil || !rootBefore.equal(rootAfter) {
		return nil, nil, stableIdentity{}, 0, fmt.Errorf("observation root changed during inventory: %w", ErrIntegrity)
	}
	return files, directories, rootAfter, total, nil
}
func readRelativeFile(ctx context.Context, root *os.File, path string, limit int64, expectedRoot stableIdentity, expectedFiles, expectedDirectories map[string]stableIdentity, hooks *importReadHooks) ([]byte, error) {
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	if path == "" || !safeRelativePath(path) || strings.HasPrefix(filepath.ToSlash(path), "../") {
		return nil, fmt.Errorf("invalid observation path: %w", ErrInvalid)
	}
	parts := strings.Split(filepath.ToSlash(filepath.Clean(path)), "/")
	rootNow, err := observationStableIdentity(root)
	if err != nil || !expectedRoot.equal(rootNow) {
		return nil, fmt.Errorf("observation root differs from first inventory: %w", ErrIntegrity)
	}
	directory := root
	type openedDirectory struct {
		parent   *os.File
		leaf     string
		file     *os.File
		expected stableIdentity
	}
	var opened []openedDirectory
	defer func() {
		for _, directory := range opened {
			_ = directory.file.Close()
		}
	}()
	for index, part := range parts[:len(parts)-1] {
		if err := checkContext(ctx); err != nil {
			return nil, err
		}
		next, identity, err := observationOpenBoundDirectory(directory, part)
		if err != nil {
			return nil, fmt.Errorf("required observation directory missing: %w", ErrIntegrity)
		}
		rel := strings.Join(parts[:index+1], "/")
		expected, ok := expectedDirectories[rel]
		if !ok || !expected.equal(identity) {
			_ = next.Close()
			return nil, fmt.Errorf("observation directory differs from first inventory: %w", ErrIntegrity)
		}
		opened = append(opened, openedDirectory{parent: directory, leaf: part, file: next, expected: expected})
		directory = next
	}
	file, before, err := observationOpenBoundFile(directory, parts[len(parts)-1])
	if err != nil {
		return nil, fmt.Errorf("required regular file missing: %w", ErrInvalid)
	}
	defer file.Close()
	expected, ok := expectedFiles[filepath.ToSlash(filepath.Clean(path))]
	if !ok || !expected.equal(before) {
		return nil, fmt.Errorf("observation file differs from first inventory: %w", ErrIntegrity)
	}
	if !before.isRegular() || before.size < 0 || before.size > limit || before.links != 1 {
		return nil, fmt.Errorf("file exceeds byte bound: %w", ErrInvalid)
	}
	if hooks != nil && hooks.afterStableStat != nil {
		if err := hooks.afterStableStat(path); err != nil {
			return nil, fmt.Errorf("observation read synchronization: %w", err)
		}
	}
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil || int64(len(data)) > limit {
		return nil, fmt.Errorf("read observation file: %w", ErrInvalid)
	}
	after, err := observationStableIdentity(file)
	if err != nil {
		return nil, fmt.Errorf("observation file changed during read: %w", ErrIntegrity)
	}
	if !before.equal(after) || after.links != 1 || int64(len(data)) != after.size {
		return nil, fmt.Errorf("observation file changed during read: %w", ErrIntegrity)
	}
	boundFileAfter, err := observationStatAt(directory, parts[len(parts)-1])
	if err != nil || !expected.equal(boundFileAfter) {
		return nil, fmt.Errorf("observation file entry changed during read: %w", ErrIntegrity)
	}
	for _, link := range opened {
		openedAfter, statErr := observationStableIdentity(link.file)
		boundAfter, bindErr := observationStatAt(link.parent, link.leaf)
		if statErr != nil || bindErr != nil || !link.expected.equal(openedAfter) || !link.expected.equal(boundAfter) {
			return nil, fmt.Errorf("observation directory changed during read: %w", ErrIntegrity)
		}
	}
	rootAfter, err := observationStableIdentity(root)
	if err != nil || !expectedRoot.equal(rootAfter) {
		return nil, fmt.Errorf("observation root changed during read: %w", ErrIntegrity)
	}
	return data, nil
}

func sameInventory(first, second map[string]stableIdentity) bool {
	if len(first) != len(second) {
		return false
	}
	for name, before := range first {
		after, ok := second[name]
		if !ok || !before.equal(after) {
			return false
		}
	}
	return true
}

func readManifest(cache *byteCache, base, name string, files map[string]stableIdentity, limit int64) ([]manifestEntry, []byte, error) {
	path := filepath.ToSlash(filepath.Join(base, name))
	data, err := cache.read(path, limit)
	if err != nil {
		return nil, nil, err
	}
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 1024), int(limit))
	var entries []manifestEntry
	seen := map[string]struct{}{}
	previous := ""
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}
		fields := strings.SplitN(line, "  ", 2)
		if len(fields) != 2 || len(fields[0]) != 64 || !isLowerHex(fields[0]) {
			return nil, nil, fmt.Errorf("invalid manifest entry: %w", ErrIntegrity)
		}
		rel, ok := normalizeManifestPath(fields[1])
		if !ok || rel == "MANIFEST.sha256" || (previous != "" && rel <= previous) {
			return nil, nil, fmt.Errorf("manifest ordering/path invalid: %w", ErrIntegrity)
		}
		previous = rel
		if _, ok := seen[rel]; ok {
			return nil, nil, fmt.Errorf("duplicate manifest entry: %w", ErrIntegrity)
		}
		seen[rel] = struct{}{}
		candidate := filepath.ToSlash(filepath.Join(base, rel))
		fileBytes, err := cache.read(candidate, maxFileBytes)
		if err != nil {
			return nil, nil, err
		}
		sum := sha256.Sum256(fileBytes)
		if hex.EncodeToString(sum[:]) != fields[0] {
			return nil, nil, fmt.Errorf("manifest digest mismatch: %w", ErrIntegrity)
		}
		entries = append(entries, manifestEntry{Digest: fields[0], Path: rel})
	}
	if err := scanner.Err(); err != nil || len(entries) == 0 {
		return nil, nil, fmt.Errorf("invalid empty manifest: %w", ErrIntegrity)
	}
	return entries, data, nil
}
func exactFileSet(files map[string]stableIdentity, entries []manifestEntry, manifestName string, allowedUnlisted ...string) error {
	listed := map[string]struct{}{}
	allowed := map[string]struct{}{manifestName: {}}
	for _, name := range allowedUnlisted {
		allowed[filepath.ToSlash(name)] = struct{}{}
	}
	for _, entry := range entries {
		rel := filepath.ToSlash(entry.Path)
		listed[rel] = struct{}{}
	}
	for rel := range files {
		if _, ok := allowed[rel]; ok {
			continue
		}
		if _, ok := listed[rel]; !ok {
			// Do not echo caller-controlled filenames across the public error
			// boundary; the manifest/file-set relation is sufficient diagnosis.
			return fmt.Errorf("unlisted observation file: %w", ErrIntegrity)
		}
	}
	covered := make(map[string]struct{}, len(listed)+len(allowed))
	for name := range listed {
		covered[name] = struct{}{}
	}
	for name := range allowed {
		covered[name] = struct{}{}
	}
	if len(covered) != len(files) {
		return fmt.Errorf("manifest file set mismatch: %w", ErrIntegrity)
	}
	return nil
}
func normalizeManifestPath(path string) (string, bool) {
	if path == "" || strings.ContainsRune(path, '\\') || strings.ContainsRune(path, 0) || filepath.IsAbs(path) {
		return "", false
	}
	if strings.HasPrefix(path, "./") {
		path = strings.TrimPrefix(path, "./")
		if path == "" || strings.HasPrefix(path, "./") {
			return "", false
		}
	}
	rawParts := strings.Split(path, "/")
	for _, part := range rawParts {
		if part == "." || part == ".." || part == "" {
			return "", false
		}
	}
	clean := filepath.ToSlash(filepath.Clean(filepath.FromSlash(path)))
	if clean == "." || clean == ".." || strings.HasPrefix(clean, "../") {
		return "", false
	}
	return clean, true
}
func safeRelativePath(path string) bool { _, ok := normalizeManifestPath(path); return ok }
func isLowerHex(value string) bool {
	for _, c := range value {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

func decodeJSON(data []byte, destination any) error {
	if !utf8.Valid(data) {
		return fmt.Errorf("JSON is not valid UTF-8: %w", ErrInvalid)
	}
	if err := walkJSON(bytes.NewReader(data), 0); err != nil {
		return fmt.Errorf("unsafe JSON: %w: %v", ErrInvalid, err)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return fmt.Errorf("schema: %w: %v", ErrInvalid, err)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return fmt.Errorf("trailing JSON: %w", ErrInvalid)
	}
	return nil
}

func validateSnapshotMetadata(metadata metadataFile) error {
	if metadata.GeneratedAt != "" {
		if _, err := time.Parse(time.RFC3339, metadata.GeneratedAt); err != nil {
			return fmt.Errorf("invalid metadata generatedAt: %w", ErrInvalid)
		}
	}
	if metadata.ContextHash != "" && !digestRE.MatchString(metadata.ContextHash) {
		return fmt.Errorf("invalid metadata context hash: %w", ErrInvalid)
	}
	if metadata.CollectionStatus != "" && metadata.CollectionStatus != "complete_for_declared_surface" && metadata.CollectionStatus != "partial_for_declared_surface" {
		return fmt.Errorf("invalid metadata collection status: %w", ErrInvalid)
	}
	if metadata.KubectlStderrClassifierAuthority != "" && metadata.KubectlStderrClassifierAuthority != "heuristic_local_diagnostic_not_proof" {
		return fmt.Errorf("invalid metadata classifier authority: %w", ErrInvalid)
	}
	if metadata.KubectlStderrClassifierTaxonomyVersion != "" && metadata.KubectlStderrClassifierTaxonomyVersion != "kubectl-stderr-taxonomy-v1" {
		return fmt.Errorf("invalid metadata classifier taxonomy: %w", ErrInvalid)
	}
	if metadata.DataClassification != "" && metadata.DataClassification != "confidential local inventory" {
		return fmt.Errorf("invalid metadata data classification: %w", ErrInvalid)
	}
	if metadata.Authority != "" && metadata.Authority != "local unsigned API observation" {
		return fmt.Errorf("invalid metadata authority: %w", ErrInvalid)
	}
	if metadata.EvaluationEligible || (metadata.NotACompatibilitySnapshot == false && metadata.Authority != "") {
		return fmt.Errorf("metadata claims compatibility authority: %w", ErrInvalid)
	}
	for _, values := range [][]string{metadata.Retained, metadata.OmittedByPolicy, metadata.Disclosure} {
		if len(values) > 64 {
			return fmt.Errorf("metadata disclosure exceeds bound: %w", ErrInvalid)
		}
		for _, value := range values {
			if value == "" || len(value) > maxStringBytes || strings.ContainsAny(value, "\x00\r\n") {
				return fmt.Errorf("metadata disclosure value is invalid: %w", ErrInvalid)
			}
		}
	}
	if len(metadata.CRDPaginationPolicy) > 0 {
		var policy map[string]json.RawMessage
		if err := json.Unmarshal(metadata.CRDPaginationPolicy, &policy); err != nil {
			return fmt.Errorf("metadata CRD pagination policy is invalid: %w", ErrInvalid)
		}
		for _, key := range []string{"version", "endpoint", "profile", "pageLimit", "maxPages", "maxItems", "maxVersions", "maxProjectedBytes", "overallTimeoutSeconds", "localJsonStageDigest", "pageProjectionDigest", "finalMergeDigest"} {
			if _, ok := policy[key]; !ok {
				return fmt.Errorf("metadata CRD pagination policy is incomplete: %w", ErrInvalid)
			}
		}
		if len(policy) != 12 {
			return fmt.Errorf("metadata CRD pagination policy is not closed: %w", ErrInvalid)
		}
		var version, endpoint, profile string
		if json.Unmarshal(policy["version"], &version) != nil || (version != "crd-pagination-policy-v1" && version != "crd-pagination-policy-v2-go") || json.Unmarshal(policy["endpoint"], &endpoint) != nil || endpoint != "/apis/apiextensions.k8s.io/v1/customresourcedefinitions" || json.Unmarshal(policy["profile"], &profile) != nil || profile != "raw-v1-continue" {
			return fmt.Errorf("metadata CRD pagination policy identity is invalid: %w", ErrInvalid)
		}
		for _, key := range []string{"localJsonStageDigest", "pageProjectionDigest", "finalMergeDigest"} {
			var digest string
			if json.Unmarshal(policy[key], &digest) != nil || !digestRE.MatchString(digest) {
				return fmt.Errorf("metadata CRD pagination policy digest is invalid: %w", ErrInvalid)
			}
		}
		for key, maximum := range map[string]int64{
			"pageLimit": 10000, "maxPages": 10000, "maxItems": 1000000,
			"maxVersions": 1000000, "maxProjectedBytes": 64 << 20,
			"overallTimeoutSeconds": 3600,
		} {
			decoder := json.NewDecoder(bytes.NewReader(policy[key]))
			decoder.UseNumber()
			var value any
			if err := decoder.Decode(&value); err != nil {
				return fmt.Errorf("metadata CRD pagination policy %s is not an integer: %w", key, ErrInvalid)
			}
			number, ok := value.(json.Number)
			if !ok {
				return fmt.Errorf("metadata CRD pagination policy %s is not an integer: %w", key, ErrInvalid)
			}
			parsed, err := strconv.ParseInt(string(number), 10, 64)
			if err != nil || parsed < 1 || parsed > maximum {
				return fmt.Errorf("metadata CRD pagination policy %s is out of bounds: %w", key, ErrInvalid)
			}
			if decoder.Decode(&value) != io.EOF {
				return fmt.Errorf("metadata CRD pagination policy %s has trailing data: %w", key, ErrInvalid)
			}
		}
	}
	return nil
}

func validateSyntheticMetadata(metadata metadataFile) error {
	anyMarker := metadata.SyntheticClassification != "" || metadata.SyntheticAuthority != "" || metadata.SyntheticCanary != "" || metadata.SyntheticNonAuthoritative
	if !anyMarker {
		return nil
	}
	if metadata.SyntheticClassification != "PUBLIC_SYNTHETIC" || metadata.SyntheticAuthority != "SYNTHETIC_NON_AUTHORITATIVE_TEST_INPUT" || metadata.SyntheticCanary != "PRUFYX_SYNTHETIC_NEVER_COMPATIBILITY_EVIDENCE" || !metadata.SyntheticNonAuthoritative {
		return fmt.Errorf("invalid synthetic provenance marker: %w", ErrInvalid)
	}
	return nil
}

func validateSurfaceMetadata(metadata surfaceMetadata) error {
	if metadata.SchemaVersion == "" && metadata.AdapterVersion == "" && metadata.RegistryVersion == "" && metadata.RegistryDigest == "" && metadata.FilterDigest == "" && metadata.AggregateDigest == "" && metadata.StrictJSONDigest == "" {
		return nil // pre-v1 optional surface metadata remains import-compatible
	}
	legacyV1 := metadata.SchemaVersion == "1.0.0" && metadata.AdapterVersion == "component-configuration-adapter-v1" && metadata.RegistryVersion == "v1"
	declaredV2 := metadata.SchemaVersion == "1.0.0" && metadata.AdapterVersion == configurationAdapterV2 && metadata.RegistryVersion == "v2"
	declaredV3 := metadata.SchemaVersion == "1.1.0" && metadata.AdapterVersion == configurationAdapterV3 && metadata.RegistryVersion == "v3"
	if (!legacyV1 && !declaredV2 && !declaredV3) || metadata.KubectlStderrClassifierTaxonomyVersion != "kubectl-stderr-taxonomy-v1" || metadata.KubectlStderrClassifierAuthority != "heuristic_local_diagnostic_not_proof" {
		return fmt.Errorf("configuration surface metadata identity is invalid: %w", ErrInvalid)
	}
	for _, digest := range []string{metadata.RegistryDigest, metadata.FilterDigest, metadata.AggregateDigest, metadata.StrictJSONDigest, metadata.KubectlStderrClassifierDigest, metadata.KubectlBoundedRunnerDigest} {
		if !digestRE.MatchString(digest) {
			return fmt.Errorf("configuration surface metadata digest is invalid: %w", ErrInvalid)
		}
	}
	if metadata.CertManagerProjectionDigest != nil && !digestRE.MatchString(*metadata.CertManagerProjectionDigest) {
		return fmt.Errorf("cert-manager projection digest is invalid: %w", ErrInvalid)
	}
	return nil
}

func walkJSON(reader io.Reader, depth int) error {
	decoder := json.NewDecoder(reader)
	decoder.UseNumber()
	return walkValue(decoder, depth)
}
func walkValue(decoder *json.Decoder, depth int) error {
	if depth > maxJSONDepth {
		return fmt.Errorf("JSON depth exceeds bound: %w", ErrInvalid)
	}
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	switch token := token.(type) {
	case json.Delim:
		switch token {
		case '{':
			count := 0
			seen := map[string]struct{}{}
			for decoder.More() {
				key, err := decoder.Token()
				if err != nil {
					return err
				}
				name, ok := key.(string)
				if !ok {
					return fmt.Errorf("invalid object key")
				}
				if len(name) > maxStringBytes || strings.IndexByte(name, 0) >= 0 {
					return fmt.Errorf("JSON key exceeds bound: %w", ErrInvalid)
				}
				if _, ok := seen[name]; ok {
					return fmt.Errorf("duplicate JSON key %q", name)
				}
				seen[name] = struct{}{}
				count++
				if count > maxObjectMembers {
					return fmt.Errorf("object exceeds bound: %w", ErrInvalid)
				}
				if err := walkValue(decoder, depth+1); err != nil {
					return err
				}
			}
			_, err = decoder.Token()
			return err
		case '[':
			count := 0
			for decoder.More() {
				count++
				if count > maxArrayItems {
					return fmt.Errorf("array exceeds bound: %w", ErrInvalid)
				}
				if err := walkValue(decoder, depth+1); err != nil {
					return err
				}
			}
			_, err = decoder.Token()
			return err
		}
	case json.Number:
		value := string(token)
		if strings.ContainsAny(value, ".eE") {
			parsed, parseErr := strconv.ParseFloat(value, 64)
			if parseErr != nil || math.IsNaN(parsed) || math.IsInf(parsed, 0) || math.Abs(parsed) > 9007199254740991 {
				return fmt.Errorf("unsafe JSON number: %w", ErrInvalid)
			}
		} else if parsed, parseErr := strconv.ParseInt(value, 10, 64); parseErr != nil || parsed > 9007199254740991 || parsed < -9007199254740991 {
			return fmt.Errorf("unsafe JSON integer: %w", ErrInvalid)
		}
	case string:
		if len(token) > maxStringBytes || strings.IndexByte(token, 0) >= 0 {
			return fmt.Errorf("JSON string exceeds bound: %w", ErrInvalid)
		}
	}
	return nil
}
func mustFloat(value string) float64 { parsed, _ := strconv.ParseFloat(value, 64); return parsed }
