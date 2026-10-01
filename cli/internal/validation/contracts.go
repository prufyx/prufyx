// SPDX-License-Identifier: AGPL-3.0-only

// Package validation owns the bounded, offline validation command contracts.
//
// Candidate validation integrates only the sanitized observation projection
// and candidate knowledge packs. It never grants compatibility authority.
package validation

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

const (
	APIVersion            = "prufyx.io/validation/v1alpha1"
	ProposedBundleKind    = "ProposedBundle"
	PolicyReferenceKind   = "PolicyReference"
	ReportAPIVersion      = "prufyx.io/validation/v1alpha1"
	ReportKind            = "ChangeValidationReport"
	SchemaVersion         = "1.0.0"
	MaxInputBytes         = 8 << 20
	MaxComponents         = 10_000
	MaxStringBytes        = 4_096
	MaxJSONDepth          = 32
	MaxArrayItems         = 10_000
	MaxObjectMembers      = 256
	MaxOutputReportBytes  = 1 << 20
	MaxSourceEvidenceLine = 1_000_000
	CandidateReportStatus = "CANDIDATE_ONLY"
	maxReportListItems    = 1024
	EvaluatorVersion      = "candidate-evaluator-v1"
)

var (
	ErrInvalid   = errors.New("invalid validation input")
	ErrIntegrity = errors.New("validation input integrity mismatch")
	ErrIO        = errors.New("validation local I/O failure")

	digestPattern        = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	componentRegex       = regexp.MustCompile(`^pkg:[a-z0-9][a-z0-9+._/-]{2,255}$`)
	versionRegex         = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$`)
	observedVersionRegex = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$`)
	profileRegex         = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{0,127}$`)
	// Configuration keys may be generic profile keys or registered predicate
	// shaped names. The latter deliberately stays in the component namespace;
	// evaluator support still requires an exact catalog predicate binding.
	configurationKeyRegex  = regexp.MustCompile(`^(?:[a-z0-9][a-z0-9.-]{0,127}|component\.[a-z0-9][a-z0-9_-]{0,63}\.[a-z0-9][a-z0-9_-]{0,127})$`)
	idRegex                = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,127}$`)
	reasonRegex            = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]{0,127}$`)
	commitRegex            = regexp.MustCompile(`^[0-9a-f]{40}$`)
	checkpointRegex        = regexp.MustCompile(`^github-release-checkpoint:[0-9]{4}-[0-9]{2}-[0-9]{2}$`)
	evidenceGapRegex       = regexp.MustCompile(`^[A-Z][A-Z0-9_.-]{2,127}$`)
	credentialPattern      = regexp.MustCompile(`(?i)(?:password|passwd|secret|token|bearer|authorization|credential|api[_-]?key)\s*[:=]`)
	privateEndpointPattern = regexp.MustCompile(`(?i)(?:localhost|127\.0\.0\.1|::1|\.internal\b|\.local\b|\.invalid\b)`)
	privateIPv4Pattern     = regexp.MustCompile(`(?i)\b(?:10|192\.168|172\.(?:1[6-9]|2[0-9]|3[0-1]))(?:\.[0-9]{1,3}){2}\b`)
	absolutePathPattern    = regexp.MustCompile(`(?:^|[\s(])/(?:[^\s/]+(?:/[^\s]*)?)`)
	windowsPathPattern     = regexp.MustCompile(`(?i)\b[A-Za-z]:[\\/]`)
)

// Planner UNKNOWN codes are the only requirement codes that can authorize a
// report component to describe the observed current version without target
// source evidence. Keep this allowlist closed so a forged arbitrary missing
// code cannot opt an exact-target report into the empty-evidence form.
var plannerUnknownRequirementCodes = map[string]struct{}{
	"IDENTITY_UNRESOLVED": {}, "IDENTITY_AMBIGUOUS": {}, "CURRENT_SCOPE_UNKNOWN": {},
	"TARGET_UNSUPPORTED": {}, "TARGET_AMBIGUOUS": {}, "RECEIPT_MISSING": {},
	"NO_ACTIVE_RECEIPT": {}, "RECEIPT_STALE_OR_REVOKED": {}, "RECEIPT_NOT_ACTIVE": {},
	"CONFIGURATION_INCOMPLETE": {}, "CURRENT_VERSION_UNVERSIONED": {}, "ROLLBACK_NOT_SUPPORTED": {},
}

type PolicyReference struct {
	APIVersion    string `json:"apiVersion"`
	Kind          string `json:"kind"`
	SchemaVersion string `json:"schemaVersion"`
	PolicyID      string `json:"policyId"`
	Revision      string `json:"revision"`
	Digest        string `json:"digest"`
}

type ProposedTarget struct {
	Component       string                     `json:"component"`
	Version         string                     `json:"version,omitempty"`
	Profile         string                     `json:"profile"`
	RetainedCurrent bool                       `json:"retainedCurrent,omitempty"`
	Configuration   map[string]json.RawMessage `json:"configuration,omitempty"`
}

type ProposedBundle struct {
	APIVersion    string           `json:"apiVersion"`
	Kind          string           `json:"kind"`
	SchemaVersion string           `json:"schemaVersion"`
	BundleID      string           `json:"bundleId"`
	PolicyRef     PolicyReference  `json:"policyRef"`
	Components    []ProposedTarget `json:"components"`
}

type TestRecord struct {
	Outcome  string
	Verified bool
	Scoped   bool
}

type VerifiedBlocker struct {
	Verified   bool
	Applicable bool
}

type DecisionInput struct {
	RequiredEvidence   int
	VerifiedEvidence   int
	ApplicableEvidence int
	UnknownEvidence    bool
	Blockers           []VerifiedBlocker
	TestsRequired      bool
	TestRecords        []TestRecord
}

type Decision string

const (
	DecisionSafe    Decision = "SAFE"
	DecisionBlocked Decision = "BLOCKED"
	DecisionUnknown Decision = "UNKNOWN"
)

type TruthLabels struct {
	CandidateOnly bool `json:"candidateOnly"`
	ModelUsed     bool `json:"modelUsed"`
	NetworkUsed   bool `json:"networkUsed"`
	// ClusterOperationUsed is the explicit v0.1 name. ClusterUsed remains
	// for compatibility with earlier local reports and is required false.
	ClusterOperationUsed bool `json:"clusterOperationUsed"`
	ClusterUsed          bool `json:"clusterUsed"`
}

type InputDigests struct {
	ObservationProjection string        `json:"observationProjection"`
	ProposedBundle        string        `json:"proposedBundle"`
	PolicyReference       string        `json:"policyReference"`
	PolicyPin             string        `json:"policyPin"`
	KnowledgeIndex        string        `json:"knowledgeIndex"`
	KnowledgeSources      string        `json:"knowledgeSources"`
	KnowledgePacks        []NamedDigest `json:"knowledgePacks"`
}

type NamedDigest struct {
	Name   string `json:"name"`
	Digest string `json:"digest"`
}

type CurrentSummary struct {
	KubernetesVersion string `json:"kubernetesVersion"`
	ComponentCount    int    `json:"componentCount"`
}

// RequirementDetail is a bounded, candidate-only explanation. It carries
// remediation text but never source bodies, selectors, or private paths.
type RequirementDetail struct {
	Code       string `json:"code"`
	Reason     string `json:"reason"`
	NextAction string `json:"nextAction"`
}

// SourceEvidence is the minimal receipt projection. URL and digest are
// retained for review; selector text and artifact paths are deliberately not
// part of this public report contract.
type SourceEvidence struct {
	SourceID      string `json:"sourceId"`
	URL           string `json:"url"`
	ContentDigest string `json:"contentDigest"`
	StartLine     int    `json:"startLine"`
	EndLine       int    `json:"endLine"`
}

type CandidateComponentReport struct {
	ComponentID    string `json:"componentId"`
	CurrentVersion string `json:"currentVersion,omitempty"`
	TargetVersion  string `json:"targetVersion"`
	AlreadyCurrent bool   `json:"alreadyCurrent"`
	// RetainedCurrent marks the bounded projection used when the planner could
	// not select an exact target. Version is then the observed current version
	// (or empty when that version is unversioned), never a proposed target.
	RetainedCurrent      bool                `json:"retainedCurrent,omitempty"`
	ObservedPredicateIDs []string            `json:"observedPredicateIds"`
	MissingRequirements  []string            `json:"missingRequirementCodes"`
	ReleaseCheckpoint    string              `json:"releaseCheckpoint"`
	SourceURLs           []string            `json:"sourceUrls"`
	SourceDigests        []string            `json:"sourceDigests"`
	RequirementDetails   []RequirementDetail `json:"requirementDetails"`
	SourceEvidence       []SourceEvidence    `json:"sourceEvidence"`
	EvidenceGaps         []string            `json:"evidenceGaps"`
	EvidenceState        string              `json:"evidenceState"`
	Decision             Decision            `json:"decision"`
}

type CandidateReport struct {
	APIVersion            string                     `json:"apiVersion"`
	Kind                  string                     `json:"kind"`
	SchemaVersion         string                     `json:"schemaVersion"`
	Status                string                     `json:"status"`
	Decision              Decision                   `json:"decision"`
	ReasonCode            string                     `json:"reasonCode"`
	Now                   string                     `json:"now"`
	Current               CurrentSummary             `json:"current"`
	Components            []CandidateComponentReport `json:"components"`
	MissingRequirements   []string                   `json:"missingRequirementCodes"`
	GlobalEvidenceGaps    []string                   `json:"globalEvidenceGaps"`
	ComponentEvidenceGaps map[string][]string        `json:"componentEvidenceGaps"`
	KnowledgeRevision     string                     `json:"knowledgeRevision"`
	ReleaseCheckpoint     string                     `json:"releaseCheckpoint"`
	Inputs                InputDigests               `json:"inputs"`
	Truth                 TruthLabels                `json:"truth"`
}

type ValidationReplay struct {
	APIVersion              string       `json:"apiVersion"`
	Kind                    string       `json:"kind"`
	SchemaVersion           string       `json:"schemaVersion"`
	Now                     string       `json:"now"`
	KnowledgeRevision       string       `json:"knowledgeRevision"`
	ReportDigest            string       `json:"reportDigest"`
	Inputs                  InputDigests `json:"inputs"`
	Truth                   TruthLabels  `json:"truth"`
	EvaluatorVersion        string       `json:"evaluatorVersion"`
	EvaluatorContractDigest string       `json:"evaluatorContractDigest"`
}

// ReduceDecision applies the normative precedence. Test PASS is evidence only:
// it cannot independently create SAFE without complete verified relations.
func ReduceDecision(input DecisionInput) (Decision, error) {
	if input.RequiredEvidence < 0 || input.VerifiedEvidence < 0 || input.ApplicableEvidence < 0 || input.VerifiedEvidence > input.RequiredEvidence || input.ApplicableEvidence > input.VerifiedEvidence {
		return "", fmt.Errorf("validate decision evidence counts: %w", ErrInvalid)
	}
	for _, blocker := range input.Blockers {
		if blocker.Verified && blocker.Applicable {
			return DecisionBlocked, nil
		}
	}
	if input.UnknownEvidence || input.VerifiedEvidence < input.RequiredEvidence {
		return DecisionUnknown, nil
	}
	if input.RequiredEvidence == 0 || input.VerifiedEvidence == 0 || input.ApplicableEvidence < input.RequiredEvidence {
		return DecisionUnknown, nil
	}
	if len(input.TestRecords) > 0 && !input.TestsRequired {
		return DecisionUnknown, nil
	}
	if input.TestsRequired {
		if len(input.TestRecords) == 0 {
			return DecisionUnknown, nil
		}
		for _, record := range input.TestRecords {
			if record.Outcome != "PASS" || !record.Verified || !record.Scoped {
				return DecisionUnknown, nil
			}
		}
	}
	return DecisionSafe, nil
}

func ReadProposedBundle(path string) (ProposedBundle, error) {
	var bundle ProposedBundle
	_, err := readStrictJSON(path, "proposed bundle", &bundle)
	if err != nil {
		return ProposedBundle{}, err
	}
	if err := bundle.validate(); err != nil {
		return ProposedBundle{}, err
	}
	bundle.PolicyRef = normalizedPolicy(bundle.PolicyRef)
	return bundle, nil
}

func ReadPolicyReference(path string) (PolicyReference, error) {
	var policy PolicyReference
	if _, err := readStrictJSON(path, "trust policy reference", &policy); err != nil {
		return PolicyReference{}, err
	}
	if err := policy.validate(); err != nil {
		return PolicyReference{}, err
	}
	return normalizedPolicy(policy), nil
}

// ParsePolicyReference validates already-retained bytes. Callers that opened
// a private input through a descriptor can use this without reopening a
// pathname and reintroducing a TOCTOU window.
func ParsePolicyReference(raw []byte) (PolicyReference, error) {
	var policy PolicyReference
	if len(raw) == 0 || len(raw) > MaxInputBytes || !utf8.Valid(raw) || rejectDuplicateKeys(raw) != nil {
		return PolicyReference{}, fmt.Errorf("policy bytes: %w", ErrInvalid)
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&policy); err != nil {
		return PolicyReference{}, fmt.Errorf("policy bytes: %w", ErrInvalid)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return PolicyReference{}, fmt.Errorf("policy bytes trailing data: %w", ErrInvalid)
	}
	if err := validateJSONValue(raw, 0); err != nil {
		return PolicyReference{}, err
	}
	if err := policy.validate(); err != nil {
		return PolicyReference{}, err
	}
	return normalizedPolicy(policy), nil
}

func (bundle ProposedBundle) validate() error {
	if bundle.APIVersion != APIVersion || bundle.Kind != ProposedBundleKind || bundle.SchemaVersion != SchemaVersion {
		return fmt.Errorf("validate proposed bundle kind/schema: %w", ErrInvalid)
	}
	if err := boundedID(bundle.BundleID, "bundleId"); err != nil {
		return err
	}
	if len(bundle.Components) == 0 || len(bundle.Components) > MaxComponents {
		return fmt.Errorf("validate proposed bundle components: %w", ErrInvalid)
	}
	if err := bundle.PolicyRef.validate(); err != nil {
		return fmt.Errorf("validate proposed bundle policyRef: %w", err)
	}
	seen := make(map[string]struct{}, len(bundle.Components))
	for index, target := range bundle.Components {
		if err := target.validate(); err != nil {
			return fmt.Errorf("validate proposed target %d: %w", index, err)
		}
		if _, exists := seen[target.Component]; exists {
			return fmt.Errorf("duplicate proposed component %q: %w", target.Component, ErrInvalid)
		}
		seen[target.Component] = struct{}{}
	}
	return nil
}

func (policy PolicyReference) validate() error {
	if policy.APIVersion != APIVersion || policy.Kind != PolicyReferenceKind || policy.SchemaVersion != SchemaVersion {
		return fmt.Errorf("validate policy reference kind/schema: %w", ErrInvalid)
	}
	if err := boundedID(policy.PolicyID, "policyId"); err != nil {
		return err
	}
	if err := boundedID(policy.Revision, "revision"); err != nil {
		return err
	}
	if !digestPattern.MatchString(policy.Digest) {
		return fmt.Errorf("policy digest is invalid: %w", ErrInvalid)
	}
	return nil
}

func normalizedPolicy(policy PolicyReference) PolicyReference {
	return PolicyReference{APIVersion: policy.APIVersion, Kind: policy.Kind, SchemaVersion: policy.SchemaVersion, PolicyID: policy.PolicyID, Revision: policy.Revision, Digest: strings.ToLower(policy.Digest)}
}

func DigestProposedBundle(bundle ProposedBundle) string {
	// This is a bounded local report/replay digest only. The community
	// authority path must replace it with the architecture's JCS digest before
	// any signed or compatibility-bearing report is emitted.
	encoded, err := json.Marshal(bundle)
	if err != nil {
		return ""
	}
	digestBytes := sha256.Sum256(encoded)
	return "sha256:" + hex.EncodeToString(digestBytes[:])
}

func DigestBytes(raw []byte) string {
	digestBytes := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(digestBytes[:])
}

func DigestPolicyReference(policy PolicyReference) string {
	encoded, err := json.Marshal(policy)
	if err != nil {
		return ""
	}
	return DigestBytes(encoded)
}

func (target ProposedTarget) validate() error {
	if !componentRegex.MatchString(target.Component) || !profileRegex.MatchString(target.Profile) || (!target.RetainedCurrent && !versionRegex.MatchString(target.Version)) || (target.RetainedCurrent && target.Version != "" && !versionRegex.MatchString(target.Version)) {
		return fmt.Errorf("target requires exact component/version/profile: %w", ErrInvalid)
	}
	if len(target.Configuration) > MaxObjectMembers {
		return fmt.Errorf("target configuration exceeds bound: %w", ErrInvalid)
	}
	keys := make([]string, 0, len(target.Configuration))
	for key, raw := range target.Configuration {
		if !configurationKeyRegex.MatchString(key) || len(raw) > MaxStringBytes {
			return fmt.Errorf("target configuration key/value is invalid: %w", ErrInvalid)
		}
		if err := validateJSONValue(raw, 0); err != nil {
			return fmt.Errorf("target configuration %q: %w", key, err)
		}
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return nil
}

func boundedID(value, label string) error {
	if !idRegex.MatchString(value) || len(value) > MaxStringBytes {
		return fmt.Errorf("%s is invalid: %w", label, ErrInvalid)
	}
	return nil
}

func readStrictJSON(path, label string, destination any) ([]byte, error) {
	if path == "" {
		return nil, fmt.Errorf("%s path is required: %w", label, ErrInvalid)
	}
	opened, err := openInputFile(path)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w: %v", label, ErrIO, err)
	}
	defer opened.Close()
	info, err := opened.Stat()
	if err != nil || !info.Mode().IsRegular() || !singleLink(info) {
		return nil, fmt.Errorf("stat %s: %w", label, ErrInvalid)
	}
	if info.Size() > MaxInputBytes {
		return nil, fmt.Errorf("%s exceeds byte bound: %w", label, ErrInvalid)
	}
	raw, err := io.ReadAll(io.LimitReader(opened, MaxInputBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read %s: %w: %v", label, ErrIO, err)
	}
	if len(raw) > MaxInputBytes {
		return nil, fmt.Errorf("%s exceeds byte bound: %w", label, ErrInvalid)
	}
	if !utf8.Valid(raw) {
		return nil, fmt.Errorf("%s is not valid UTF-8: %w", label, ErrInvalid)
	}
	if err := rejectDuplicateKeys(raw); err != nil {
		return nil, fmt.Errorf("decode %s: %w: %v", label, ErrInvalid, err)
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return nil, fmt.Errorf("decode %s: %w", label, ErrInvalid)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("decode %s trailing data: %w", label, ErrInvalid)
	}
	if err := validateJSONValue(raw, 0); err != nil {
		return nil, fmt.Errorf("validate %s bounds: %w", label, err)
	}
	return raw, nil
}

func validateJSONValue(raw json.RawMessage, depth int) error {
	if depth > MaxJSONDepth {
		return fmt.Errorf("JSON depth exceeds bound: %w", ErrInvalid)
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return fmt.Errorf("JSON value is invalid: %w", ErrInvalid)
	}
	if err := validateDecoded(value, depth); err != nil {
		return err
	}
	return nil
}

func validateDecoded(value any, depth int) error {
	if depth > MaxJSONDepth {
		return fmt.Errorf("JSON depth exceeds bound: %w", ErrInvalid)
	}
	switch item := value.(type) {
	case string:
		if len(item) > MaxStringBytes {
			return fmt.Errorf("JSON string exceeds bound: %w", ErrInvalid)
		}
	case json.Number:
		text := item.String()
		if strings.ContainsAny(text, ".eE") {
			value, err := strconv.ParseFloat(text, 64)
			if err != nil || math.IsInf(value, 0) || math.IsNaN(value) {
				return fmt.Errorf("JSON number exceeds safe finite bound: %w", ErrInvalid)
			}
		} else {
			value, err := strconv.ParseInt(text, 10, 64)
			if err != nil || value > 9_007_199_254_740_991 || value < -9_007_199_254_740_991 {
				return fmt.Errorf("JSON integer exceeds safe bound: %w", ErrInvalid)
			}
		}
	case []any:
		if len(item) > MaxArrayItems {
			return fmt.Errorf("JSON array exceeds bound: %w", ErrInvalid)
		}
		for _, child := range item {
			if err := validateDecoded(child, depth+1); err != nil {
				return err
			}
		}
	case map[string]any:
		if len(item) > MaxObjectMembers {
			return fmt.Errorf("JSON object exceeds bound: %w", ErrInvalid)
		}
		for key, child := range item {
			if len(key) > MaxStringBytes {
				return fmt.Errorf("JSON key exceeds bound: %w", ErrInvalid)
			}
			if err := validateDecoded(child, depth+1); err != nil {
				return err
			}
		}
	}
	return nil
}

func rejectDuplicateKeys(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	if delimiter, ok := token.(json.Delim); !ok || delimiter != '{' {
		return errors.New("root must be an object")
	} else if err := walkObject(decoder); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return errors.New("multiple JSON values")
	}
	return nil
}

func walkObject(decoder *json.Decoder) error {
	seen := map[string]struct{}{}
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		key, ok := token.(string)
		if !ok {
			return errors.New("object key is not a string")
		}
		if _, exists := seen[key]; exists {
			return fmt.Errorf("duplicate key %q", key)
		}
		seen[key] = struct{}{}
		if err := walkValue(decoder); err != nil {
			return err
		}
	}
	_, err := decoder.Token()
	return err
}

func walkValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	if delimiter, ok := token.(json.Delim); ok {
		switch delimiter {
		case '{':
			return walkObject(decoder)
		case '[':
			for decoder.More() {
				if err := walkValue(decoder); err != nil {
					return err
				}
			}
			_, err := decoder.Token()
			return err
		}
	}
	return nil
}

type OutputRoot struct {
	path           string
	parent         *os.File
	stageName      string
	stageInfo      os.FileInfo
	directory      *os.File
	stageFiles     []string
	publishedFiles []string
	committed      bool
	// stageBindingLost means the stage pathname no longer names our directory.
	// Cleanup may still unlink files through the retained descriptor, but must
	// never remove the now-unowned namespace entry by name.
	stageBindingLost bool
	// batchStarted distinguishes the explicit multi-artifact API from the
	// legacy Write method.  The latter remains a one-call publication API;
	// explicit batches must be committed through Commit after all files have
	// been staged.
	batchStarted bool
	batchFiles   map[string]RunArtifact
	batchBytes   int64
}

var outputParentSyncHook func(*os.File) error

// outputCommitHook is intentionally package-private and test-only. It runs
// before the final descriptor validation, allowing pre-commit fault coverage
// without an ambient environment control.
var outputCommitHook func(string) error

// outputStageRenameHook is intentionally package-private and test-only. It
// runs after the final pre-rename stage identity check and immediately before
// the platform no-replace rename, allowing deterministic stage-name swap
// coverage without an ambient race.
var outputStageRenameHook func(string) error

// outputFileCommitHook is intentionally package-private and test-only. It
// runs after the public directory is reserved and before each staged file is
// exclusively created, allowing per-file creator races to be tested.
var outputFileCommitHook func(*os.File, string) error

// outputFilePostCopyHook and outputFinalDirectoryHook are package-private,
// deterministic fault seams. They model a same-UID writer replacing a copied
// leaf or the final directory at the corresponding ownership witness.
var outputFilePostCopyHook func(*os.File, string) error
var outputFinalDirectoryHook func(*os.File) error

// exclusiveFilePublicationHook is test-only and models an ancestor/parent
// replacement immediately before the final identity check.
var exclusiveFilePublicationHook func(string) error

// outputWriteFaultHook is intentionally package-private and test-only; it
// allows fault-injection coverage without an ambient environment control.
var outputWriteFaultHook func(string) error

func syncOutputParent(parent *os.File) error {
	if outputParentSyncHook != nil {
		return outputParentSyncHook(parent)
	}
	return syncDirectory(parent)
}

func PrepareOutputRoot(path string) (OutputRoot, error) {
	if path == "" {
		return OutputRoot{}, fmt.Errorf("output root is required: %w", ErrInvalid)
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return OutputRoot{}, fmt.Errorf("resolve output root: %w: %v", ErrIO, err)
	}
	parent, err := openDirectoryPath(filepath.Dir(abs))
	if err != nil {
		return OutputRoot{}, fmt.Errorf("open output parent: %w: %v", ErrIO, err)
	}
	if _, err := os.Lstat(abs); err == nil || !os.IsNotExist(err) {
		_ = parent.Close()
		return OutputRoot{}, fmt.Errorf("output root already exists: %w", ErrIO)
	}
	stageName, err := newOutputStageName()
	if err != nil {
		_ = parent.Close()
		return OutputRoot{}, fmt.Errorf("create output staging identity: %w: %v", ErrIO, err)
	}
	if err := mkdirRelative(parent, stageName, 0o700); err != nil {
		_ = parent.Close()
		return OutputRoot{}, fmt.Errorf("create output staging root: %w: %v", ErrIO, err)
	}
	rootFD, err := openRelativeDirectory(parent, stageName)
	if err != nil {
		_ = removeDirectoryRelative(parent, stageName)
		_ = parent.Close()
		return OutputRoot{}, fmt.Errorf("retain output staging root: %w: %v", ErrIO, err)
	}
	info, err := rootFD.Stat()
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0o700 {
		_ = rootFD.Close()
		_ = removeDirectoryRelative(parent, stageName)
		_ = parent.Close()
		return OutputRoot{}, fmt.Errorf("validate output root: %w", ErrIO)
	}
	err = syncOutputParent(parent)
	if err != nil {
		_ = rootFD.Close()
		_ = removeDirectoryRelative(parent, stageName)
		_ = parent.Close()
		return OutputRoot{}, fmt.Errorf("sync output parent: %w: %v", ErrIO, err)
	}
	return OutputRoot{path: abs, parent: parent, stageName: stageName, stageInfo: info, directory: rootFD}, nil
}

// PublishExclusiveCanonicalFile publishes one already-canonical receipt from
// a private temporary file. The parent and every ancestor are opened
// descriptor-relative with no-follow checks, and the final move is an atomic
// no-replace operation. The containing directory is fsynced after publication
// so a successful call is durable across a crash (an fsync failure leaves the
// complete receipt visible and returns ErrIO; callers must not retry blindly).
// This is intentionally a narrow helper for receipt-like single files, not a
// general path or archive writer.
func PublishExclusiveCanonicalFile(path string, data []byte) (err error) {
	if path == "" || !filepath.IsAbs(path) || filepath.Base(path) != pathLeaf(path) || strings.ContainsAny(filepath.Base(path), `/\\`) || len(data) > MaxOutputReportBytes {
		return fmt.Errorf("receipt output path or bytes are invalid: %w", ErrInvalid)
	}
	abs := filepath.Clean(path)
	parent, err := openDirectoryPath(filepath.Dir(abs))
	if err != nil {
		return fmt.Errorf("open receipt parent: %w: %v", ErrIO, err)
	}
	defer func() {
		if closeErr := parent.Close(); err == nil && closeErr != nil {
			err = fmt.Errorf("close receipt parent: %w: %v", ErrIO, closeErr)
		}
	}()
	if err := verifyDirectoryIdentity(filepath.Dir(abs), parent); err != nil {
		return err
	}
	tmpName, err := newOutputStageName()
	if err != nil {
		return fmt.Errorf("create receipt staging identity: %w: %v", ErrIO, err)
	}
	tmp, err := openRelativeExclusive(parent, tmpName, 0o600)
	if err != nil {
		return fmt.Errorf("create receipt staging file: %w: %v", ErrIO, err)
	}
	removeTemp := true
	defer func() {
		if removeTemp {
			_ = removeRelative(parent, tmpName)
		}
	}()
	if err := writeAll(tmp, append(append([]byte(nil), data...), '\n')); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write receipt: %w: %v", ErrIO, err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("sync receipt: %w: %v", ErrIO, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close receipt: %w: %v", ErrIO, err)
	}
	if exclusiveFilePublicationHook != nil {
		if err := exclusiveFilePublicationHook(filepath.Dir(abs)); err != nil {
			return fmt.Errorf("receipt publication precommit: %w: %v", ErrIO, err)
		}
	}
	if err := verifyDirectoryIdentity(filepath.Dir(abs), parent); err != nil {
		return err
	}
	if err := renameNoReplaceRelative(parent, tmpName, filepath.Base(abs)); err != nil {
		return fmt.Errorf("publish receipt without overwrite: %w: %v", ErrIO, err)
	}
	removeTemp = false
	if err := syncOutputParent(parent); err != nil {
		return fmt.Errorf("sync published receipt parent: %w: %v", ErrIO, err)
	}
	return nil
}

// pathLeaf exists to keep the helper's path check explicit and portable.
func pathLeaf(path string) string { return filepath.Base(path) }

func verifyDirectoryIdentity(path string, descriptor *os.File) error {
	// Re-walk the complete path through no-follow descriptors. Checking only
	// Lstat(path) would still follow a replacement symlink in an ancestor.
	current, err := openDirectoryPath(path)
	if err != nil {
		return fmt.Errorf("receipt parent path changed: %w", ErrIntegrity)
	}
	defer current.Close()
	want, err := descriptor.Stat()
	if err != nil {
		return fmt.Errorf("receipt parent identity unavailable: %w", ErrIntegrity)
	}
	got, err := current.Stat()
	if err != nil || !os.SameFile(want, got) {
		return fmt.Errorf("receipt parent identity changed: %w", ErrIntegrity)
	}
	return nil
}

func newOutputStageName() (string, error) {
	var nonce [24]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		return "", err
	}
	return ".prufyx-output-stage-" + hex.EncodeToString(nonce[:]), nil
}

func (root OutputRoot) Path() string { return root.path }

func (root *OutputRoot) cleanupStage() error {
	if root == nil || root.parent == nil || root.committed {
		return nil
	}
	var firstErr error
	if root.stageName != "" && !root.stageBindingLost && !stageNameMatchesInfo(root.parent, root.stageName, root.stageInfo) {
		root.stageBindingLost = true
	}
	if root.directory != nil {
		// Enumerate through the retained descriptor itself. The stage pathname
		// may have been swapped, so opening it for cleanup would risk traversing
		// an unowned directory. The descriptor remains the unlink authority.
		if names, err := root.directory.Readdirnames(-1); err == nil {
			for _, name := range names {
				if err := removeStageEntry(root.directory, name); err != nil && !errors.Is(err, os.ErrNotExist) && firstErr == nil {
					firstErr = err
				}
			}
		} else if firstErr == nil {
			firstErr = err
		}
		// If enumeration was unavailable, do not fall back to unlinking the
		// ownership list by name: a same-UID writer may have replaced a leaf
		// between enumeration and unlink. Retain the bounded tree and report the
		// cleanup error instead.
		if err := syncDirectory(root.directory); err != nil && firstErr == nil {
			firstErr = err
		}
		if err := root.directory.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
		root.directory = nil
	}
	root.stageFiles = nil
	if root.stageName != "" && !root.stageBindingLost && !stageNameMatchesInfo(root.parent, root.stageName, root.stageInfo) {
		root.stageBindingLost = true
	}
	if root.stageName != "" && !root.stageBindingLost {
		// A previous cleanup may have reported a non-empty rogue directory and
		// closed the retained stage FD. Retry through a fresh descriptor so an
		// operator can remove the bounded rogue contents and call Close again.
		if root.directory == nil {
			if scan, err := openRelativeDirectory(root.parent, root.stageName); err == nil {
				names, readErr := scan.Readdirnames(-1)
				if readErr != nil && firstErr == nil {
					firstErr = readErr
				}
				for _, name := range names {
					if err := removeStageEntry(scan, name); err != nil && !errors.Is(err, os.ErrNotExist) && firstErr == nil {
						firstErr = err
					}
				}
				if err := scan.Close(); err != nil && firstErr == nil {
					firstErr = err
				}
			} else if firstErr == nil && !errors.Is(err, os.ErrNotExist) {
				firstErr = err
			}
		}
		err := removeDirectoryRelative(root.parent, root.stageName)
		if err == nil || errors.Is(err, os.ErrNotExist) {
			root.stageName = ""
		} else if firstErr == nil {
			firstErr = err
		}
	}
	if err := syncDirectory(root.parent); err != nil && firstErr == nil {
		firstErr = err
	}
	return firstErr
}

// removeStageEntry unlinks regular files and symlinks, and removes an empty
// rogue directory without traversing it by pathname. Non-empty directories
// are deliberately retained and reported: recursively deleting an unbounded
// attacker-owned tree would exceed the cleanup boundary.
func removeStageEntry(directory *os.File, name string) error {
	if err := removeRelative(directory, name); err == nil || errors.Is(err, os.ErrNotExist) {
		return err
	}
	child, err := openRelativeDirectory(directory, name)
	if err != nil {
		return err
	}
	names, readErr := child.Readdirnames(1)
	closeErr := child.Close()
	if readErr == nil {
		return fmt.Errorf("non-empty staged output entry: %w", ErrIO)
	}
	if !errors.Is(readErr, io.EOF) {
		return readErr
	}
	if closeErr != nil {
		return closeErr
	}
	_ = names
	return removeDirectoryRelative(directory, name)
}

func (root *OutputRoot) Close() error {
	if root == nil || root.parent == nil {
		return nil
	}
	var firstErr error
	if !root.committed {
		firstErr = root.cleanupStage()
	}
	if err := root.parent.Close(); err != nil && firstErr == nil {
		firstErr = err
	}
	root.parent = nil
	return firstErr
}

func (root *OutputRoot) Write(name string, data []byte) error {
	if root != nil && root.batchStarted {
		return fmt.Errorf("legacy write cannot be mixed with an explicit batch: %w", ErrIO)
	}
	if root.path == "" || name == "" || name == "." || name == ".." || filepath.Base(name) != name || strings.ContainsAny(name, `/\\`) {
		return fmt.Errorf("output file name is invalid: %w", ErrInvalid)
	}
	if len(data) > MaxOutputReportBytes {
		return fmt.Errorf("output file exceeds bound: %w", ErrInvalid)
	}
	return root.writeBundle(map[string][]byte{name: data})
}

func (root *OutputRoot) commit() error {
	if root == nil || root.parent == nil || root.directory == nil || root.committed {
		return fmt.Errorf("output root is closed: %w", ErrIO)
	}
	if err := syncDirectory(root.directory); err != nil {
		return root.abortWithError(fmt.Errorf("sync staged output directory: %w: %v", ErrIO, err))
	}
	// Legacy Write retains its pre-commit hook semantics. Explicit batches run
	// the hook before their final descriptor validation in Commit. The
	// stage-rename hook is exercised immediately before final-directory
	// reservation; the source itself is always opened through root.directory.
	if outputCommitHook != nil && !root.batchStarted {
		if err := outputCommitHook(root.stageName); err != nil {
			return root.abortWithError(fmt.Errorf("pre-commit output fault: %w: %v", ErrIO, err))
		}
	}
	if err := verifyStageBinding(root); err != nil {
		return root.abortWithError(err)
	}
	publish := publishNoReplaceDirectory
	if !root.batchStarted {
		publish = publishLegacyNoReplaceDirectory
	}
	if err := publish(root.parent, root.directory, filepath.Dir(root.path), root.stageName, filepath.Base(root.path), root.batchFiles, root.stageFiles); err != nil {
		if errors.Is(err, errStageBindingLost) || !stageBindingMatches(root) {
			// A generic platform error can still follow a source-name swap.
			// Never clean that pathname by name after this point; it may belong
			// to another owner.
			root.stageBindingLost = true
		}
		return root.abortWithError(fmt.Errorf("commit output directory: %w: %w", ErrIO, err))
	}
	root.publishedFiles = append([]string(nil), root.stageFiles...)
	// Publication is source-descriptor bound, but staging cleanup still needs
	// to avoid a swapped stage pathname. Treat a lost name as an integrity
	// boundary and retain that namespace entry while cleaning via root.directory.
	if err := verifyStageBinding(root); err != nil {
		root.stageBindingLost = true
	}
	stageCleanupErr := root.cleanupStage()
	root.directory = nil
	root.stageName = ""
	root.stageFiles = nil
	// After rename the output is complete and visible. It must never be
	// removed by reopening the public name: that name may have been replaced
	// by another owner. Mark committed before the durability check and leave a
	// complete run in place if the parent fsync reports an error.
	root.committed = true
	if err := syncOutputParent(root.parent); err != nil {
		return fmt.Errorf("sync committed output parent: %w: %v", ErrIO, err)
	}
	if stageCleanupErr != nil {
		return fmt.Errorf("cleanup staged output after publication: %w: %v", ErrIO, stageCleanupErr)
	}
	return nil
}

func (root *OutputRoot) writeBundle(files map[string][]byte) error {
	if root == nil || root.parent == nil || root.directory == nil || root.committed {
		return fmt.Errorf("output root is closed: %w", ErrIO)
	}
	if len(files) == 0 || len(files) > 8 {
		return fmt.Errorf("invalid output bundle: %w", ErrInvalid)
	}
	// Keep the legacy one-call API descriptor-bound too: publication validates
	// the exact bytes originally staged, rather than trusting a later source
	// pathname read.
	root.batchFiles = make(map[string]RunArtifact, len(files))
	publicNames := make([]string, 0, len(files))
	for name, data := range files {
		if name == "" || name[0] == '.' || filepath.Base(name) != name || strings.ContainsAny(name, `/\\`) || len(data) > MaxOutputReportBytes {
			return fmt.Errorf("invalid output bundle member: %w", ErrInvalid)
		}
		publicNames = append(publicNames, name)
	}
	sort.Strings(publicNames)
	for _, publicName := range publicNames {
		root.stageFiles = append(root.stageFiles, publicName)
		file, err := openRelativeExclusive(root.directory, publicName, 0o600)
		if err != nil {
			return root.abortWithError(fmt.Errorf("create staged output: %w: %v", ErrIO, err))
		}
		if _, err := file.Write(files[publicName]); err != nil {
			primary := fmt.Errorf("write staged output: %w: %v", ErrIO, err)
			if closeErr := file.Close(); closeErr != nil {
				primary = fmt.Errorf("%w; close failed: %v", primary, closeErr)
			}
			return root.abortWithError(primary)
		}
		if err := file.Sync(); err != nil {
			primary := fmt.Errorf("sync staged output: %w: %v", ErrIO, err)
			if closeErr := file.Close(); closeErr != nil {
				primary = fmt.Errorf("%w; close failed: %v", primary, closeErr)
			}
			return root.abortWithError(primary)
		}
		if err := file.Close(); err != nil {
			return root.abortWithError(fmt.Errorf("close staged output: %w: %v", ErrIO, err))
		}
		root.batchFiles[publicName] = RunArtifact{Name: publicName, Bytes: int64(len(files[publicName])), Digest: DigestBytes(files[publicName])}
		root.batchBytes += int64(len(files[publicName]))
		if outputWriteFaultHook != nil {
			if err := outputWriteFaultHook(publicName); err != nil {
				return root.abortWithError(fmt.Errorf("staged output fault: %w: %v", ErrIO, err))
			}
		}
	}
	return root.commit()
}

type IncompleteReport struct {
	APIVersion           string   `json:"apiVersion"`
	Kind                 string   `json:"kind"`
	SchemaVersion        string   `json:"schemaVersion"`
	Status               string   `json:"status"`
	Decision             Decision `json:"decision"`
	ReasonCode           string   `json:"reasonCode"`
	Now                  string   `json:"now"`
	ProposedBundleDigest string   `json:"proposedBundleDigest"`
	PolicyDigest         string   `json:"policyDigest"`
	ComponentCount       int      `json:"componentCount"`
}

func (root *OutputRoot) WriteIncompleteReport(report IncompleteReport) (string, error) {
	if report.APIVersion == "" {
		report.APIVersion = ReportAPIVersion
	}
	if report.Kind == "" {
		report.Kind = ReportKind
	}
	if report.SchemaVersion == "" {
		report.SchemaVersion = SchemaVersion
	}
	if report.APIVersion != ReportAPIVersion || report.Kind != ReportKind || report.SchemaVersion != SchemaVersion {
		return "", fmt.Errorf("validate incomplete report kind/schema: %w", ErrInvalid)
	}
	if !digestPattern.MatchString(report.ProposedBundleDigest) || !digestPattern.MatchString(report.PolicyDigest) || !reasonRegex.MatchString(report.ReasonCode) && report.ReasonCode != "" {
		return "", fmt.Errorf("validate incomplete report digests: %w", ErrInvalid)
	}
	if report.ComponentCount < 0 || report.ComponentCount > MaxComponents {
		return "", fmt.Errorf("validate incomplete report component count: %w", ErrInvalid)
	}
	report.Status = "IMPLEMENTATION_INCOMPLETE"
	report.Decision = DecisionUnknown
	if _, err := time.Parse(time.RFC3339, report.Now); err != nil {
		return "", fmt.Errorf("validate report now: %w", ErrInvalid)
	}
	encoded, err := json.Marshal(report)
	if err != nil {
		return "", fmt.Errorf("encode incomplete report: %w: %v", ErrIO, err)
	}
	encoded = append(encoded, '\n')
	digest := DigestBytes(encoded)
	replay := struct {
		APIVersion              string `json:"apiVersion"`
		Kind                    string `json:"kind"`
		SchemaVersion           string `json:"schemaVersion"`
		Now                     string `json:"now"`
		ReportDigest            string `json:"reportDigest"`
		ProposedBundleDigest    string `json:"proposedBundleDigest"`
		PolicyDigest            string `json:"policyDigest"`
		EvaluatorVersion        string `json:"evaluatorVersion"`
		EvaluatorContractDigest string `json:"evaluatorContractDigest"`
	}{APIVersion: APIVersion, Kind: "ValidationReplay", SchemaVersion: SchemaVersion, Now: report.Now, ReportDigest: digest, ProposedBundleDigest: report.ProposedBundleDigest, PolicyDigest: report.PolicyDigest, EvaluatorVersion: EvaluatorVersion, EvaluatorContractDigest: DigestBytes([]byte(EvaluatorVersion))}
	replayBytes, err := json.Marshal(replay)
	if err != nil {
		return "", fmt.Errorf("encode replay: %w: %v", ErrIO, err)
	}
	if err := root.writeBundle(map[string][]byte{"report.json": encoded, "report.sha256": []byte(digest + "\n"), "replay.json": append(replayBytes, '\n')}); err != nil {
		return "", err
	}
	return digest, nil
}

func validateCandidateReport(report *CandidateReport) error {
	if len(report.Components) == 0 || len(report.Components) > MaxComponents {
		return fmt.Errorf("candidate report component count: %w", ErrInvalid)
	}
	if report.Current.ComponentCount < 0 || report.Current.ComponentCount > MaxComponents {
		return fmt.Errorf("candidate report current component count: %w", ErrInvalid)
	}
	// An offline observation may have no Kubernetes server-version surface.
	// Preserve that as an empty/unknown summary rather than requiring the
	// bridge to invent a version; validate the syntax only when supplied.
	if report.Current.KubernetesVersion != "" {
		if err := boundedString(report.Current.KubernetesVersion, "current Kubernetes version"); err != nil {
			return err
		}
	}
	if report.Current.KubernetesVersion != "" && !validObservedVersion(report.Current.KubernetesVersion) {
		return fmt.Errorf("current Kubernetes version is invalid: %w", ErrInvalid)
	}
	if err := boundedString(report.KnowledgeRevision, "knowledge revision"); err != nil {
		return err
	}
	if err := boundedCheckpoint(report.ReleaseCheckpoint); err != nil {
		return err
	}
	if err := canonicalCodes(&report.MissingRequirements, "missing requirements"); err != nil {
		return err
	}
	if err := canonicalEvidenceGaps(&report.GlobalEvidenceGaps, "global evidence gaps"); err != nil {
		return err
	}
	if len(report.ComponentEvidenceGaps) > MaxComponents {
		return fmt.Errorf("component evidence gap map exceeds bound: %w", ErrInvalid)
	}
	seenComponents := make(map[string]struct{}, len(report.Components))
	for index := range report.Components {
		component := &report.Components[index]
		if !componentRegex.MatchString(component.ComponentID) || len(component.ComponentID) > MaxStringBytes || component.Decision != DecisionUnknown || component.EvidenceState != CandidateReportStatus {
			return fmt.Errorf("candidate component is not bounded UNKNOWN: %w", ErrIntegrity)
		}
		if _, exists := seenComponents[component.ComponentID]; exists {
			return fmt.Errorf("duplicate candidate component: %w", ErrInvalid)
		}
		seenComponents[component.ComponentID] = struct{}{}
		if index > 0 && report.Components[index-1].ComponentID >= component.ComponentID {
			return fmt.Errorf("candidate components are not sorted: %w", ErrInvalid)
		}
		if component.CurrentVersion != "" && !validObservedVersion(component.CurrentVersion) {
			return fmt.Errorf("candidate current version is invalid: %w", ErrInvalid)
		}
		if component.RetainedCurrent {
			if component.TargetVersion != component.CurrentVersion || !component.AlreadyCurrent {
				return fmt.Errorf("retained current projection is invalid: %w", ErrIntegrity)
			}
		} else if !versionRegex.MatchString(component.TargetVersion) {
			return fmt.Errorf("candidate target version is invalid: %w", ErrInvalid)
		}
		plannerUnknown := plannerUnknownProjection(*component)
		if component.ReleaseCheckpoint == "" {
			if !plannerUnknown {
				return fmt.Errorf("release checkpoint is invalid: %w", ErrInvalid)
			}
		} else if err := boundedCheckpoint(component.ReleaseCheckpoint); err != nil {
			return err
		}
		if err := canonicalIDs(&component.ObservedPredicateIDs, "observed predicate IDs"); err != nil {
			return err
		}
		if err := canonicalCodes(&component.MissingRequirements, "component missing requirements"); err != nil {
			return err
		}
		if err := canonicalEvidenceGaps(&component.EvidenceGaps, "component evidence gaps"); err != nil {
			return err
		}
		if err := canonicalURLs(&component.SourceURLs); err != nil {
			return err
		}
		if err := canonicalDigests(&component.SourceDigests, "component source digests"); err != nil {
			return err
		}
		if err := canonicalRequirementDetails(&component.RequirementDetails, component.MissingRequirements); err != nil {
			return err
		}
		if err := canonicalSourceEvidence(&component.SourceEvidence, plannerUnknown); err != nil {
			return err
		}
	}
	for componentID, gaps := range report.ComponentEvidenceGaps {
		if _, exists := seenComponents[componentID]; !exists || !componentRegex.MatchString(componentID) {
			return fmt.Errorf("component evidence gap key is invalid: %w", ErrInvalid)
		}
		if err := canonicalEvidenceGaps(&gaps, "component evidence gaps"); err != nil {
			return err
		}
		report.ComponentEvidenceGaps[componentID] = gaps
	}
	if len(report.ComponentEvidenceGaps) != len(report.Components) {
		return fmt.Errorf("component evidence gap map is incomplete: %w", ErrIntegrity)
	}
	if len(report.Inputs.KnowledgePacks) > maxReportListItems {
		return fmt.Errorf("knowledge pack list exceeds bound: %w", ErrInvalid)
	}
	seenPacks := map[string]struct{}{}
	for index := range report.Inputs.KnowledgePacks {
		pack := &report.Inputs.KnowledgePacks[index]
		if (boundedID(pack.Name, "knowledge pack name") != nil && !componentRegex.MatchString(pack.Name)) || !digestPattern.MatchString(pack.Digest) {
			return fmt.Errorf("knowledge pack digest is invalid: %w", ErrInvalid)
		}
		if _, exists := seenPacks[pack.Name]; exists || (index > 0 && report.Inputs.KnowledgePacks[index-1].Name >= pack.Name) {
			return fmt.Errorf("knowledge pack list is not unique and sorted: %w", ErrInvalid)
		}
		seenPacks[pack.Name] = struct{}{}
	}
	return nil
}

func boundedString(value, label string) error {
	if len(value) == 0 || len(value) > MaxStringBytes || strings.IndexByte(value, 0) >= 0 {
		return fmt.Errorf("%s is invalid: %w", label, ErrInvalid)
	}
	return nil
}

func validObservedVersion(value string) bool {
	if len(value) > MaxStringBytes || !observedVersionRegex.MatchString(value) {
		return false
	}
	core := strings.SplitN(value, "+", 2)[0]
	parts := strings.SplitN(core, "-", 2)
	if len(parts) != 2 {
		return true
	}
	for _, identifier := range strings.Split(parts[1], ".") {
		if identifier == "" || (allDigits(identifier) && len(identifier) > 1 && identifier[0] == '0') {
			return false
		}
	}
	return true
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

func boundedCheckpoint(value string) error {
	if value == "" || len(value) > MaxStringBytes || !checkpointRegex.MatchString(value) {
		return fmt.Errorf("release checkpoint is invalid: %w", ErrInvalid)
	}
	return nil
}

func canonicalCodes(values *[]string, label string) error {
	if len(*values) > maxReportListItems {
		return fmt.Errorf("%s exceeds bound: %w", label, ErrInvalid)
	}
	seen := map[string]struct{}{}
	canonical := make([]string, 0, len(*values))
	for _, value := range *values {
		if len(value) > MaxStringBytes || !evidenceGapRegex.MatchString(value) {
			return fmt.Errorf("%s contains invalid code: %w", label, ErrInvalid)
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		canonical = append(canonical, value)
	}
	sort.Strings(canonical)
	*values = canonical
	return nil
}

func canonicalEvidenceGaps(values *[]string, label string) error {
	return canonicalCodes(values, label)
}

func canonicalIDs(values *[]string, label string) error {
	if len(*values) > maxReportListItems {
		return fmt.Errorf("%s exceeds bound: %w", label, ErrInvalid)
	}
	seen := map[string]struct{}{}
	for _, value := range *values {
		if err := boundedString(value, label); err != nil || !idRegex.MatchString(value) {
			return fmt.Errorf("%s contains invalid ID: %w", label, ErrInvalid)
		}
		if _, exists := seen[value]; exists {
			return fmt.Errorf("%s contains duplicate ID: %w", label, ErrInvalid)
		}
		seen[value] = struct{}{}
	}
	sort.Strings(*values)
	return nil
}

func canonicalURLs(values *[]string) error {
	if len(*values) > maxReportListItems {
		return fmt.Errorf("source URL list exceeds bound: %w", ErrInvalid)
	}
	seen := map[string]struct{}{}
	for _, value := range *values {
		if len(value) > MaxStringBytes {
			return fmt.Errorf("source URL exceeds bound: %w", ErrInvalid)
		}
		parsed, err := url.ParseRequestURI(value)
		if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.Hostname() == "" {
			return fmt.Errorf("source URL is invalid: %w", ErrInvalid)
		}
		if _, exists := seen[value]; exists {
			return fmt.Errorf("source URL list contains duplicate: %w", ErrInvalid)
		}
		seen[value] = struct{}{}
	}
	sort.Strings(*values)
	return nil
}

func canonicalDigests(values *[]string, label string) error {
	if len(*values) > maxReportListItems {
		return fmt.Errorf("%s exceeds bound: %w", label, ErrInvalid)
	}
	seen := map[string]struct{}{}
	for _, value := range *values {
		if !digestPattern.MatchString(value) {
			return fmt.Errorf("%s contains invalid digest: %w", label, ErrInvalid)
		}
		if _, exists := seen[value]; exists {
			return fmt.Errorf("%s contains duplicate digest: %w", label, ErrInvalid)
		}
		seen[value] = struct{}{}
	}
	sort.Strings(*values)
	return nil
}

func canonicalRequirementDetails(values *[]RequirementDetail, missing []string) error {
	if len(*values) > maxReportListItems || len(*values) != len(missing) {
		return fmt.Errorf("requirement detail cardinality or binding is invalid: %w", ErrInvalid)
	}
	missingSet := make(map[string]struct{}, len(missing))
	for _, code := range missing {
		missingSet[code] = struct{}{}
	}
	seen := make(map[string]struct{}, len(*values))
	for _, detail := range *values {
		if !evidenceGapRegex.MatchString(detail.Code) || len(detail.Code) > MaxStringBytes || !safeExplanationText(detail.Reason) || !safeExplanationText(detail.NextAction) {
			return fmt.Errorf("requirement detail is invalid: %w", ErrInvalid)
		}
		if _, ok := missingSet[detail.Code]; !ok {
			return fmt.Errorf("requirement detail is not bound to a missing code: %w", ErrIntegrity)
		}
		if _, ok := seen[detail.Code]; ok {
			return fmt.Errorf("requirement detail code is duplicated: %w", ErrInvalid)
		}
		seen[detail.Code] = struct{}{}
	}
	sort.Slice(*values, func(i, j int) bool {
		if (*values)[i].Code != (*values)[j].Code {
			return (*values)[i].Code < (*values)[j].Code
		}
		if (*values)[i].Reason != (*values)[j].Reason {
			return (*values)[i].Reason < (*values)[j].Reason
		}
		return (*values)[i].NextAction < (*values)[j].NextAction
	})
	return nil
}

func canonicalSourceEvidence(values *[]SourceEvidence, allowEmpty bool) error {
	if len(*values) == 0 && !allowEmpty || len(*values) > maxReportListItems {
		return fmt.Errorf("source evidence cardinality is invalid: %w", ErrInvalid)
	}
	seen := make(map[string]struct{}, len(*values))
	for _, evidence := range *values {
		if len(evidence.SourceID) == 0 || len(evidence.SourceID) > MaxStringBytes || !idRegex.MatchString(evidence.SourceID) || len(evidence.URL) == 0 || len(evidence.URL) > MaxStringBytes || len(evidence.ContentDigest) > MaxStringBytes || !digestPattern.MatchString(evidence.ContentDigest) || evidence.StartLine < 1 || evidence.StartLine > evidence.EndLine || evidence.EndLine > MaxSourceEvidenceLine {
			return fmt.Errorf("source evidence fields are invalid: %w", ErrInvalid)
		}
		parsed, err := url.Parse(evidence.URL)
		if err != nil || parsed.Scheme != "https" || parsed.Host != "github.com" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.RawPath != "" || !validGitHubBlobEvidencePath(parsed.Path) {
			return fmt.Errorf("source evidence URL is invalid: %w", ErrInvalid)
		}
		if _, ok := seen[evidence.SourceID]; ok {
			return fmt.Errorf("source evidence is duplicated: %w", ErrInvalid)
		}
		seen[evidence.SourceID] = struct{}{}
	}
	sort.Slice(*values, func(i, j int) bool { return (*values)[i].SourceID < (*values)[j].SourceID })
	return nil
}

func plannerUnknownProjection(component CandidateComponentReport) bool {
	if component.TargetVersion != component.CurrentVersion || !component.AlreadyCurrent ||
		component.ReleaseCheckpoint != "" || len(component.SourceURLs) != 0 || len(component.SourceDigests) != 0 || len(component.SourceEvidence) != 0 {
		return false
	}
	if !component.RetainedCurrent && component.CurrentVersion == "" {
		return false
	}
	missing := make(map[string]struct{}, len(component.MissingRequirements))
	for _, code := range component.MissingRequirements {
		missing[code] = struct{}{}
	}
	for _, detail := range component.RequirementDetails {
		if _, stable := plannerUnknownRequirementCodes[detail.Code]; stable {
			if _, bound := missing[detail.Code]; bound && detail.NextAction != "" {
				return true
			}
		}
	}
	return false
}

func safeExplanationText(value string) bool {
	if value == "" || len(value) > MaxStringBytes || !utf8.ValidString(value) {
		return false
	}
	// Explanations are public report data. Reject path-, endpoint-, and
	// credential-shaped text even when it is otherwise valid UTF-8; source
	// receipts carry the only permitted URLs and digests.
	if strings.Contains(value, "://") || absolutePathPattern.MatchString(value) || windowsPathPattern.MatchString(value) ||
		credentialPattern.MatchString(value) || privateEndpointPattern.MatchString(value) || privateIPv4Pattern.MatchString(value) {
		return false
	}
	for _, r := range value {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

func validGitHubBlobEvidencePath(path string) bool {
	if path == "" || !strings.HasPrefix(path, "/") || strings.HasSuffix(path, "/") || strings.Contains(path, "\\") {
		return false
	}
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	if len(parts) < 5 || parts[0] == "" || parts[1] == "" || parts[0] == "." || parts[0] == ".." || parts[1] == "." || parts[1] == ".." || parts[2] != "blob" || !commitRegex.MatchString(parts[3]) {
		return false
	}
	for _, part := range parts[4:] {
		if part == "" || part == "." || part == ".." || strings.Contains(part, "\\") {
			return false
		}
	}
	return true
}

// CanonicalCandidateReport validates and canonicalizes a candidate-only
// report without performing any filesystem operation. The returned bytes are
// the exact report.json representation, including its single terminating
// newline, and are the sole serialization authority shared by writers and
// integrated workflows.
func CanonicalCandidateReport(report CandidateReport) ([]byte, error) {
	if report.APIVersion == "" {
		report.APIVersion = ReportAPIVersion
	}
	if report.Kind == "" {
		report.Kind = ReportKind
	}
	if report.SchemaVersion == "" {
		report.SchemaVersion = SchemaVersion
	}
	if report.APIVersion != ReportAPIVersion || report.Kind != ReportKind || report.SchemaVersion != SchemaVersion {
		return nil, fmt.Errorf("validate candidate report kind/schema: %w", ErrInvalid)
	}
	if report.Status != CandidateReportStatus || report.Decision != DecisionUnknown || !reasonRegex.MatchString(report.ReasonCode) {
		return nil, fmt.Errorf("candidate report must remain UNKNOWN: %w", ErrIntegrity)
	}
	if !report.Truth.CandidateOnly || report.Truth.ModelUsed || report.Truth.NetworkUsed || report.Truth.ClusterOperationUsed || report.Truth.ClusterUsed {
		return nil, fmt.Errorf("candidate truth labels are invalid: %w", ErrIntegrity)
	}
	if _, err := time.Parse(time.RFC3339, report.Now); err != nil {
		return nil, fmt.Errorf("validate candidate report now: %w", ErrInvalid)
	}
	if err := validateCandidateReport(&report); err != nil {
		return nil, err
	}
	if !digestPattern.MatchString(report.Inputs.ObservationProjection) || !digestPattern.MatchString(report.Inputs.ProposedBundle) || !digestPattern.MatchString(report.Inputs.PolicyReference) || !digestPattern.MatchString(report.Inputs.PolicyPin) || !digestPattern.MatchString(report.Inputs.KnowledgeIndex) || !digestPattern.MatchString(report.Inputs.KnowledgeSources) {
		return nil, fmt.Errorf("validate candidate report input digests: %w", ErrIntegrity)
	}
	for _, named := range report.Inputs.KnowledgePacks {
		if named.Name == "" || !digestPattern.MatchString(named.Digest) {
			return nil, fmt.Errorf("validate candidate report pack digest: %w", ErrIntegrity)
		}
	}
	encoded, err := json.Marshal(report)
	if err != nil {
		return nil, fmt.Errorf("encode candidate report: %w: %v", ErrIO, err)
	}
	return append(encoded, '\n'), nil
}

func (root *OutputRoot) WriteCandidateReport(report CandidateReport) (string, error) {
	encoded, err := CanonicalCandidateReport(report)
	if err != nil {
		return "", err
	}
	// CanonicalCandidateReport is authoritative. Decode its already-validated
	// bytes only to obtain normalized fields for the replay envelope.
	if err := json.Unmarshal(bytes.TrimSuffix(encoded, []byte{'\n'}), &report); err != nil {
		return "", fmt.Errorf("decode canonical candidate report: %w: %v", ErrIO, err)
	}
	// The digest is over the exact bytes written to report.json, including the
	// terminating newline. This keeps report.sha256 directly verifiable with
	// ordinary file hashing tools and binds replay to the emitted artifact.
	reportDigest := DigestBytes(encoded)
	replay := ValidationReplay{APIVersion: APIVersion, Kind: "ValidationReplay", SchemaVersion: SchemaVersion, Now: report.Now, KnowledgeRevision: report.KnowledgeRevision, ReportDigest: reportDigest, Inputs: report.Inputs, Truth: report.Truth, EvaluatorVersion: EvaluatorVersion, EvaluatorContractDigest: DigestBytes([]byte(EvaluatorVersion))}
	replayBytes, err := json.Marshal(replay)
	if err != nil {
		return "", fmt.Errorf("encode candidate replay: %w: %v", ErrIO, err)
	}
	if err := root.writeBundle(map[string][]byte{"report.json": encoded, "report.sha256": []byte(reportDigest + "\n"), "replay.json": append(replayBytes, '\n')}); err != nil {
		return "", err
	}
	return reportDigest, nil
}
