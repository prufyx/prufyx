// SPDX-License-Identifier: AGPL-3.0-only

package main

import "encoding/json"

// Schemas of the files the tool reads and writes.
const (
	ClaimsSchema    = "prufyx.io/kind-val-claims/v1"
	ClaimsSchemaV2  = "prufyx.io/kind-val-claims/v2"
	SnapshotSchema  = "prufyx.io/kind-val-snapshot/v1"
	VerdictsSchema  = "prufyx.io/kind-val-verdicts/v1"
	CRDRunSchema    = "prufyx.io/kind-val-crd-run/v1"
	ResultsSchema   = "prufyx.io/kind-val-results/v1"
	ResultsSchemaV2 = "prufyx.io/kind-val-results/v2"
	ControlsSchema  = "prufyx.io/kind-val-controls/v1"
)

// Claim kinds.
const (
	KindServedAPI  = "k8s-served-api"
	KindK8sRemoval = "k8s-removal"
	KindCRDVersion = "crd-version"
	KindCRDRemoval = "crd-removal"
	KindCRDPair    = "crd-pair"
	KindAddonRule  = "addon-rule"
	KindCRDField   = "crd-field"
)

// Field changes a crd-field claim names: what the To release's schema does
// to an object the From release's schema accepts.
const (
	ChangeFieldRemoved        = "field-removed"
	ChangeRequiredAdded       = "field-required-added"
	ChangeTypeChanged         = "field-type-changed"
	ChangeEnumValueRemoved    = "enum-value-removed"
	ChangeValidationTightened = "validation-tightened"
)

// fieldChanges is the closed list of field changes.
var fieldChanges = map[string]bool{ChangeFieldRemoved: true, ChangeRequiredAdded: true, ChangeTypeChanged: true, ChangeEnumValueRemoved: true, ChangeValidationTightened: true}

// Expectations and observations of a served API.
const (
	ExpectServed    = "served"
	ExpectNotServed = "not_served"
)

// Claim outcomes.
const (
	OutcomeConfirmed    = "confirmed"
	OutcomeRefuted      = "refuted"
	OutcomeUndetermined = "undetermined"
	OutcomeError        = "error"
)

// Verdicts (results v2): the outcome as a consumer may rely on it. Nothing
// stronger than what the API server showed: only a confirmed outcome is
// confirmed-by-execution.
const (
	VerdictConfirmed    = "confirmed-by-execution"
	VerdictRefuted      = "refuted"
	VerdictUndetermined = "undetermined"
	VerdictError        = "error"
)

// Reason codes (results v2): why a result is not confirmed-by-execution. The
// list is closed; docs/kind-val.md has the table.
const (
	ReasonNotEvaluated        = "not-evaluated"
	ReasonNoSnapshot          = "no-snapshot"
	ReasonNoRun               = "no-run"
	ReasonNoCorpusCase        = "no-corpus-case"
	ReasonNotProbed           = "not-probed"
	ReasonReleaseUnavailable  = "release-unavailable"
	ReasonReleaseNotInstalled = "release-not-installed"
	ReasonServerNoAnswer      = "server-no-answer"
	ReasonScanNoReport        = "scan-no-report"
	ReasonInstallFailed       = "install-failed"
	ReasonInstallRejected     = "install-rejected"
	ReasonCRDMissing          = "crd-missing"
	ReasonVersionNotDeclared  = "version-not-declared"
	ReasonImageDigestMismatch = "image-digest-mismatch"
	ReasonDisagreement        = "disagreement"
	ReasonCanaryFailed        = "canary-failed"
	ReasonControlsAbsent      = "controls-absent"
	// crd-field
	ReasonSchemaPermissive   = "schema-permissive"
	ReasonPathNotInFrom      = "path-not-in-from"
	ReasonValueMissing       = "value-missing"
	ReasonObjectNotBuildable = "object-not-buildable"
	ReasonFromRejected       = "from-rejected"
	ReasonOtherRejection     = "other-rejection"
)

// Reasons is the closed list of reason codes.
var Reasons = []string{
	ReasonNotEvaluated, ReasonNoSnapshot, ReasonNoRun, ReasonNoCorpusCase, ReasonNotProbed,
	ReasonReleaseUnavailable, ReasonReleaseNotInstalled, ReasonServerNoAnswer, ReasonScanNoReport,
	ReasonInstallFailed, ReasonInstallRejected, ReasonCRDMissing, ReasonVersionNotDeclared, ReasonImageDigestMismatch,
	ReasonDisagreement, ReasonCanaryFailed, ReasonControlsAbsent,
	ReasonSchemaPermissive, ReasonPathNotInFrom, ReasonValueMissing, ReasonObjectNotBuildable,
	ReasonFromRejected, ReasonOtherRejection,
}

// Control expectations: a control claim is known true (expected confirmed)
// or known false (expected refuted).
const (
	ControlTrue  = "true"
	ControlFalse = "false"
)

// Control group states (results v2, totals.controls).
const (
	ControlStateOK     = "ok"
	ControlStateFailed = "failed"
	ControlStateAbsent = "absent"
	// ControlStateIncomplete: every control of the group came out as
	// expected, but all have the same expectation.
	ControlStateIncomplete = "incomplete"
)

// Finding severities.
const (
	SeverityHigh   = "HIGH"
	SeverityMedium = "MEDIUM"
	SeverityInfo   = "INFO"
)

// Claims is the input: a list of statements the knowledge makes, each to
// be confirmed or refuted by a real API server. See docs/kind-val.md.
type Claims struct {
	Schema string `json:"schema"`
	// Lines is the cluster matrix of the run (v2 only): the controls of the
	// file are exactly the reviewed controls expanded for these lines.
	Lines  []string `json:"lines,omitempty"`
	Claims []Claim  `json:"claims"`
}

// Claim is one statement. Subject holds the members of the claim's kind;
// Expect is read for k8s-served-api only; Evidence is passed through.
type Claim struct {
	ID       string          `json:"id"`
	Kind     string          `json:"kind"`
	Subject  Subject         `json:"subject"`
	Expect   string          `json:"expect,omitempty"`
	Evidence json.RawMessage `json:"evidence,omitempty"`
	// Control marks a reviewed control claim (v2 only): "true" when the
	// claim is known to hold, "false" when it is known not to.
	Control string `json:"control,omitempty"`
}

// Subject is the union of the subject members of every claim kind; a kind
// reads only its own.
type Subject struct {
	// k8s-served-api
	Line string `json:"line,omitempty"`
	// k8s-removal: release lines; crd-removal, crd-pair: releases.
	From json.RawMessage `json:"from,omitempty"`
	To   json.RawMessage `json:"to,omitempty"`
	// API identity (k8s-* and crd-*).
	Group   string `json:"group,omitempty"`
	Version string `json:"version,omitempty"`
	Kind    string `json:"kind,omitempty"`
	RuleID  string `json:"ruleId,omitempty"`
	// crd-*
	Project string      `json:"project,omitempty"`
	Repo    string      `json:"repo,omitempty"`
	Release *CRDRelease `json:"release,omitempty"`
	CRD     string      `json:"crd,omitempty"`
	Served  *bool       `json:"served,omitempty"`
	Storage *bool       `json:"storage,omitempty"`
	// crd-field: the field (dot-separated property names; an array is
	// crossed through its items), the change, and the From-valid value To
	// should refuse (enum-value-removed, field-type-changed,
	// validation-tightened).
	Path   string          `json:"path,omitempty"`
	Change string          `json:"change,omitempty"`
	Value  json.RawMessage `json:"value,omitempty"`
}

// CRDRelease is one release of a project: its tag, the commit the tag
// names and the manifest files (repository paths) that define its CRDs.
type CRDRelease struct {
	Tag    string   `json:"tag"`
	Commit string   `json:"commit"`
	Files  []string `json:"files"`
}

// CRDDef is one definition as the cluster holds it: the versions with
// their served and storage flags.
type CRDDef struct {
	Name     string       `json:"name"`
	Group    string       `json:"group"`
	Kind     string       `json:"kind"`
	Scope    string       `json:"scope,omitempty"`
	Versions []CRDVersion `json:"versions"`
}

// CRDVersion is one declared version of a definition.
type CRDVersion struct {
	Name    string `json:"name"`
	Served  bool   `json:"served"`
	Storage bool   `json:"storage"`
}

// Snapshot is the served-API set of one cluster, read from discovery.
type Snapshot struct {
	Schema        string `json:"schema"`
	Line          string `json:"line"`
	ServerVersion string `json:"serverVersion"`
	Image         string `json:"image"`
	// ObservedImageDigests are the repository digests of the image the node
	// container actually runs (docker inspect), recorded next to the
	// configured Image; the evaluation requires the configured digest among them.
	ObservedImageDigests []string `json:"observedImageDigests,omitempty"`
	TakenAt              string   `json:"takenAt"`
	Served               []string `json:"served"`
}

// VerdictRun is the behavioural check on one cluster: every corpus case
// applied with a server dry run, and, for the cases whose target line is
// this cluster's line, the scan verdict for the hop into it.
type VerdictRun struct {
	Schema      string        `json:"schema"`
	Line        string        `json:"line"`
	FromVersion string        `json:"fromVersion"`
	ToVersion   string        `json:"toVersion"`
	Prufyx      string        `json:"prufyx"`
	Cases       []VerdictCase `json:"cases"`
}

// VerdictCase is one corpus manifest on one cluster.
type VerdictCase struct {
	ID       string    `json:"id"`
	API      string    `json:"api"`
	Server   ServerTry `json:"server"`
	Scan     *ScanTry  `json:"scan,omitempty"`
	Manifest string    `json:"manifest"`
}

// ServerTry is the outcome of `kubectl create --dry-run=server`:
// "accepted", "not_served" (the server has no such API) or "rejected"
// (served, but the object was refused for another reason).
type ServerTry struct {
	Outcome string `json:"outcome"`
	Message string `json:"message,omitempty"`
}

// ScanTry is the outcome of `prufyx scan` for the hop into this line.
type ScanTry struct {
	From    string   `json:"from"`
	To      string   `json:"to"`
	Exit    int      `json:"exit"`
	Verdict string   `json:"verdict"`
	Gaps    []string `json:"gaps"`
	Rules   []string `json:"rules"`
	Error   string   `json:"error,omitempty"`
}

// Server outcomes.
const (
	ServerAccepted  = "accepted"
	ServerNotServed = "not_served"
	ServerRejected  = "rejected"
	// ServerError: the call did not reach an answer from the API server
	// (kubectl missing, connection refused, timeout, TLS or kubeconfig
	// failure). It is evidence of nothing: a claim that depends on it is
	// an error, never confirmed and never refuted.
	ServerError = "error"
)

// CRDRun is the custom-resource check of the pairs run on one cluster.
type CRDRun struct {
	Schema string `json:"schema"`
	Line   string `json:"line"`
	Image  string `json:"image"`
	// ObservedImageDigests: see Snapshot.
	ObservedImageDigests []string        `json:"observedImageDigests,omitempty"`
	Pairs                []CRDPairResult `json:"pairs"`
	// Releases: releases named by crd-version claims that no pair covers,
	// each installed on its own.
	Releases []CRDReleaseResult `json:"releases,omitempty"`
	// Fields: one entry per crd-field claim, decided within the run of its
	// pair.
	Fields []CRDFieldResult `json:"fields,omitempty"`
}

// CRDFieldResult is what the cluster said about one crd-field claim: the
// object built from the From schema, the server's answer to it after From
// was installed, after To was applied in place and after To was installed
// fresh, the state of To's schema at the path, and the message pattern the
// fresh answer matched. The claim is decided on the fresh install (no cached
// From schema can answer there); the in-place answer is a cross-check. Skip is
// the reason code when the claim was decided before an answer could tell (the
// schema is permissive, the path is not in From, no value, no buildable
// object). Error is a failed install or schema read: the claim is an error,
// never confirmed.
type CRDFieldResult struct {
	ID     string `json:"id"`
	Pair   string `json:"pair"`
	Change string `json:"change"`
	// ServerPath is the path as the API server names it (an array element
	// is [0]).
	ServerPath string `json:"serverPath,omitempty"`
	Skip       string `json:"skip,omitempty"`
	Detail     string `json:"detail,omitempty"`
	// ObjectDigest is the sha256 digest of the object sent (JSON).
	ObjectDigest string     `json:"objectDigest,omitempty"`
	FromAnswer   *ServerTry `json:"from,omitempty"`
	// InPlace is "applied" or "refused": the in-place apply of To over From.
	InPlace   string     `json:"inPlace,omitempty"`
	ToInPlace *ServerTry `json:"toInPlace,omitempty"`
	ToAnswer  *ServerTry `json:"to,omitempty"`
	// ToSchema is the state of the path in To's installed schema: present,
	// absent or permissive (it or an ancestor preserves unknown fields).
	ToSchema string `json:"toSchema,omitempty"`
	Pattern  string `json:"pattern,omitempty"`
	Error    string `json:"error,omitempty"`
	// InstallError is set, next to Error, when the install was rejected.
	InstallError *InstallError `json:"install_error,omitempty"`
}

// CRDReleaseResult is what the cluster said about one release installed on
// its own. Unavailable says why the release could not be installed from the
// claims' own evidence (its files cannot be fetched or hold no definitions):
// the claims about it stay undetermined. Error is a failed install or
// cleanup on the cluster: the claims are errors, never confirmed.
type CRDReleaseResult struct {
	ID          string          `json:"id"`
	Project     string          `json:"project"`
	Tag         string          `json:"tag"`
	State       CRDReleaseState `json:"state"`
	Unavailable string          `json:"unavailable,omitempty"`
	Error       string          `json:"error,omitempty"`
}

// CRDPairResult is what the cluster said about one pair of releases.
type CRDPairResult struct {
	ID      string          `json:"id"`
	Project string          `json:"project"`
	FromTag string          `json:"fromTag"`
	ToTag   string          `json:"toTag"`
	From    CRDReleaseState `json:"from"`
	To      CRDReleaseState `json:"to"`
	InPlace InPlaceUpgrade  `json:"inPlaceUpgrade"`
	Error   string          `json:"error,omitempty"`
}

// CRDReleaseState is the cluster's view after one release's CRDs were
// installed: the definitions it holds, and the server's answer to an object
// of every version either release declared.
type CRDReleaseState struct {
	Files   []FetchedFile `json:"files"`
	CRDs    []CRDDef      `json:"crds"`
	Objects []ObjectTry   `json:"objects"`
	Error   string        `json:"error,omitempty"`
	// InstallError is set, next to Error, when the API server refused the
	// apply (see InstallError).
	InstallError *InstallError `json:"install_error,omitempty"`
}

// InstallError is the structured form of an apply the API server refused
// with a deterministic answer (reason install-rejected), as opposed to an
// apply that failed to reach it (install-failed). Phase is "apply"; Exit is
// the kubectl exit code; Lines are the first lines kubectl printed on stderr
// (at most InstallErrorMaxLines); CRDs are the definitions the lines name.
type InstallError struct {
	Phase string   `json:"phase"`
	Exit  int      `json:"exit"`
	Lines []string `json:"lines"`
	CRDs  []string `json:"crds"`
}

// FetchedFile is one manifest file as fetched, with its digest.
type FetchedFile struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	CRDs   int    `json:"crds"`
}

// ObjectTry is the server's answer to a dry-run create of a minimal object
// of one group/version/Kind.
type ObjectTry struct {
	Member  string `json:"member"`
	Outcome string `json:"outcome"`
	Message string `json:"message,omitempty"`
}

// InPlaceUpgrade records whether applying the To release's CRDs over the
// From release's succeeded. The API server refuses a definition that drops a
// version still listed in status.storedVersions. Leftover lists the
// definitions From had and To no longer defines: a plain apply leaves them
// in the cluster, so their objects stay accepted until someone deletes them.
type InPlaceUpgrade struct {
	Attempted bool     `json:"attempted"`
	Succeeded bool     `json:"succeeded"`
	Message   string   `json:"message,omitempty"`
	Leftover  []string `json:"leftover,omitempty"`
}

// Results is the evaluation of every claim against every run.
type Results struct {
	Schema      string        `json:"schema"`
	GeneratedAt string        `json:"generatedAt"`
	Prufyx      Binary        `json:"prufyx"`
	LogDigest   string        `json:"logDigest,omitempty"`
	Lines       []LineSummary `json:"lines"`
	Claims      []ClaimResult `json:"claims"`
	// Controls (v2 only) are the control claims of the run with their
	// outcomes; they are never in Claims or the claim totals.
	Controls []ControlResult `json:"controls,omitempty"`
	Diffs    []LineDiff      `json:"diffs"`
	Findings []Finding       `json:"findings"`
	Totals   Totals          `json:"totals"`
}

// ControlResult is one control claim with its outcome; OK when the outcome
// is the expected one (confirmed for a true control, refuted for a false).
type ControlResult struct {
	ID       string `json:"id"`
	Kind     string `json:"kind"`
	Line     string `json:"line,omitempty"`
	Expected string `json:"expected"`
	Outcome  string `json:"outcome"`
	OK       bool   `json:"ok"`
	Reason   string `json:"reason,omitempty"`
	Detail   string `json:"detail,omitempty"`
}

// ControlSummary is the state of the controls of one kind on one line
// (Line is empty for the custom-resource kinds, decided on one line, and
// for a kind the controls file has no entry for).
type ControlSummary struct {
	Kind   string   `json:"kind"`
	Line   string   `json:"line,omitempty"`
	State  string   `json:"state"`
	True   int      `json:"true"`
	False  int      `json:"false"`
	Failed []string `json:"failed,omitempty"`
}

// VerdictTotals counts the claim results by verdict (v2 only).
type VerdictTotals struct {
	ConfirmedByExecution int `json:"confirmed-by-execution"`
	Refuted              int `json:"refuted"`
	Undetermined         int `json:"undetermined"`
	Error                int `json:"error"`
}

// Binary identifies the scanned prufyx binary.
type Binary struct {
	Commit string `json:"commit,omitempty"`
	SHA256 string `json:"sha256,omitempty"`
}

// LineSummary is one cluster line of the run.
type LineSummary struct {
	Line          string `json:"line"`
	ServerVersion string `json:"serverVersion"`
	Image         string `json:"image"`
	Served        int    `json:"served"`
}

// ClaimResult is one claim with its outcome.
type ClaimResult struct {
	ID              string          `json:"id"`
	Kind            string          `json:"kind"`
	Outcome         string          `json:"outcome"`
	Verdict         string          `json:"verdict,omitempty"`
	Reason          string          `json:"reason,omitempty"`
	Detail          string          `json:"detail,omitempty"`
	InstallError    *InstallError   `json:"install_error,omitempty"`
	PrufyxCommit    string          `json:"prufyxCommit,omitempty"`
	NodeImageDigest string          `json:"nodeImageDigest,omitempty"`
	LogDigest       string          `json:"logDigest,omitempty"`
	Evidence        json.RawMessage `json:"evidence,omitempty"`
}

// LineDiff is the served-API difference between two consecutive lines, and
// the removed APIs no claim names.
type LineDiff struct {
	From            string   `json:"from"`
	To              string   `json:"to"`
	Removed         []string `json:"removed"`
	Added           []string `json:"added"`
	UnknownRemovals []string `json:"unknownRemovals"`
}

// Finding is one disagreement worth a look.
type Finding struct {
	Severity string `json:"severity"`
	ID       string `json:"id"`
	Message  string `json:"message"`
}

// Totals counts the results.
type Totals struct {
	Claims       int `json:"claims"`
	Confirmed    int `json:"confirmed"`
	Refuted      int `json:"refuted"`
	Undetermined int `json:"undetermined"`
	Error        int `json:"error"`
	High         int `json:"high"`
	Medium       int `json:"medium"`
	Info         int `json:"info"`
	// Verdicts and Controls are v2 only.
	Verdicts *VerdictTotals   `json:"verdicts,omitempty"`
	Controls []ControlSummary `json:"controls,omitempty"`
}
