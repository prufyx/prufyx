// SPDX-License-Identifier: AGPL-3.0-only

package main

import "encoding/json"

// Schemas of the files the tool reads and writes.
const (
	ClaimsSchema   = "prufyx.io/kind-val-claims/v1"
	SnapshotSchema = "prufyx.io/kind-val-snapshot/v1"
	VerdictsSchema = "prufyx.io/kind-val-verdicts/v1"
	CRDRunSchema   = "prufyx.io/kind-val-crd-run/v1"
	ResultsSchema  = "prufyx.io/kind-val-results/v1"
)

// Claim kinds.
const (
	KindServedAPI  = "k8s-served-api"
	KindK8sRemoval = "k8s-removal"
	KindCRDVersion = "crd-version"
	KindCRDRemoval = "crd-removal"
	KindCRDPair    = "crd-pair"
	KindAddonRule  = "addon-rule"
)

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

// Finding severities.
const (
	SeverityHigh   = "HIGH"
	SeverityMedium = "MEDIUM"
	SeverityInfo   = "INFO"
)

// Claims is the input: a list of statements the knowledge makes, each to
// be confirmed or refuted by a real API server. See docs/kind-val.md.
type Claims struct {
	Schema string  `json:"schema"`
	Claims []Claim `json:"claims"`
}

// Claim is one statement. Subject holds the members of the claim's kind;
// Expect is read for k8s-served-api only; Evidence is passed through.
type Claim struct {
	ID       string          `json:"id"`
	Kind     string          `json:"kind"`
	Subject  Subject         `json:"subject"`
	Expect   string          `json:"expect,omitempty"`
	Evidence json.RawMessage `json:"evidence,omitempty"`
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
	Diffs       []LineDiff    `json:"diffs"`
	Findings    []Finding     `json:"findings"`
	Totals      Totals        `json:"totals"`
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
	Detail          string          `json:"detail,omitempty"`
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
}
