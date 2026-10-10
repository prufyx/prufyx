// SPDX-License-Identifier: AGPL-3.0-only

package main

// Schemas of the files the tool reads and writes.
const (
	ClaimsSchema   = "prufyx.io/kind-val-claims/v1"
	SnapshotSchema = "prufyx.io/kind-val-snapshot/v1"
	VerdictsSchema = "prufyx.io/kind-val-verdicts/v1"
	CRDRunSchema   = "prufyx.io/kind-val-crd-run/v1"
	ResultsSchema  = "prufyx.io/kind-val-results/v1"
)

// Expectations and observations of a served API.
const (
	ExpectServed    = "served"
	ExpectNotServed = "not_served"
)

// Claim statuses.
const (
	StatusConfirmed   = "confirmed"
	StatusRefuted     = "refuted"
	StatusUnevaluated = "unevaluated"
)

// Finding severities.
const (
	SeverityHigh   = "HIGH"
	SeverityMedium = "MEDIUM"
	SeverityInfo   = "INFO"
)

// Claims is the input of a run: what the knowledge says, as checkable
// statements. The Kubernetes claims are derived from the removal table built
// into the binary; the custom-resource pairs are supplied by the caller (for
// example from the crd.version-removal extractor's proof).
type Claims struct {
	Schema          string     `json:"schema"`
	Kubernetes      []APIClaim `json:"kubernetes"`
	CustomResources []CRDPair  `json:"customResources"`
}

// APIClaim says that one release line serves, or does not serve, one API:
// "group/version Kind" ("version Kind" for the core group), the pair form of
// a served-API list.
type APIClaim struct {
	ID     string `json:"id"`
	Line   string `json:"line"`
	API    string `json:"api"`
	Expect string `json:"expect"`
	Source string `json:"source"`
}

// CRDPair is one consecutive-release pair of a project's
// CustomResourceDefinitions: what each release's manifests define, and the
// files (pinned by commit) that define them. A version served at From and
// not at To is a removal the pair claims; a pair with no such version claims
// that nothing was removed.
type CRDPair struct {
	ID      string     `json:"id"`
	Project string     `json:"project"`
	Repo    string     `json:"repo"`
	From    CRDRelease `json:"from"`
	To      CRDRelease `json:"to"`
}

// CRDRelease is one release of a project: its tag, the commit the tag names,
// the manifest files that define the CRDs (repository paths) and the
// definitions the knowledge expects in them.
type CRDRelease struct {
	Tag    string   `json:"tag"`
	Commit string   `json:"commit"`
	Files  []string `json:"files"`
	CRDs   []CRDDef `json:"crds"`
}

// CRDDef is one definition: the versions a release declares with their
// served and storage flags.
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
	Schema        string   `json:"schema"`
	Line          string   `json:"line"`
	ServerVersion string   `json:"serverVersion"`
	Image         string   `json:"image"`
	TakenAt       string   `json:"takenAt"`
	Served        []string `json:"served"`
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
	OutcomeAccepted  = "accepted"
	OutcomeNotServed = "not_served"
	OutcomeRejected  = "rejected"
)

// CRDRun is the custom-resource check of the pairs run on one cluster.
type CRDRun struct {
	Schema string          `json:"schema"`
	Line   string          `json:"line"`
	Pairs  []CRDPairResult `json:"pairs"`
}

// CRDPairResult is what the cluster said about one pair.
type CRDPairResult struct {
	ID      string          `json:"id"`
	Project string          `json:"project"`
	From    CRDReleaseState `json:"from"`
	To      CRDReleaseState `json:"to"`
	InPlace InPlaceUpgrade  `json:"inPlaceUpgrade"`
	Error   string          `json:"error,omitempty"`
}

// CRDReleaseState is the cluster's view after one release's CRDs were
// installed: the definitions it holds, and the server's answer to an object
// of every declared version.
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
// version still listed in status.storedVersions.
type InPlaceUpgrade struct {
	Attempted bool   `json:"attempted"`
	Succeeded bool   `json:"succeeded"`
	Message   string `json:"message,omitempty"`
}

// Results is the evaluation of every claim against every run.
type Results struct {
	Schema      string          `json:"schema"`
	GeneratedAt string          `json:"generatedAt"`
	Lines       []LineSummary   `json:"lines"`
	Claims      []ClaimResult   `json:"claims"`
	Verdicts    []VerdictResult `json:"verdicts"`
	Diffs       []LineDiff      `json:"diffs"`
	Findings    []Finding       `json:"findings"`
	Totals      Totals          `json:"totals"`
}

// LineSummary is one cluster line of the run.
type LineSummary struct {
	Line          string `json:"line"`
	ServerVersion string `json:"serverVersion"`
	Image         string `json:"image"`
	Served        int    `json:"served"`
}

// ClaimResult is one claim with its status.
type ClaimResult struct {
	ID       string `json:"id"`
	Kind     string `json:"kind"`
	Line     string `json:"line,omitempty"`
	Subject  string `json:"subject"`
	Expect   string `json:"expect"`
	Observed string `json:"observed,omitempty"`
	Status   string `json:"status"`
	Detail   string `json:"detail,omitempty"`
}

// VerdictResult is one corpus case over one hop: what both API servers
// said and what the scan said, and whether they agree.
type VerdictResult struct {
	ID         string   `json:"id"`
	API        string   `json:"api"`
	From       string   `json:"from"`
	To         string   `json:"to"`
	ServerFrom string   `json:"serverFrom"`
	ServerTo   string   `json:"serverTo"`
	ScanExit   int      `json:"scanExit"`
	ScanGaps   []string `json:"scanGaps"`
	Expected   string   `json:"expected"`
	Status     string   `json:"status"`
	Detail     string   `json:"detail,omitempty"`
}

// LineDiff is the served-API difference between two consecutive lines, and
// the removed APIs the removal table does not name.
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
	Claims      int `json:"claims"`
	Confirmed   int `json:"confirmed"`
	Refuted     int `json:"refuted"`
	Unevaluated int `json:"unevaluated"`
	Verdicts    int `json:"verdicts"`
	VerdictsOK  int `json:"verdictsOk"`
	VerdictsBad int `json:"verdictsBad"`
	High        int `json:"high"`
	Medium      int `json:"medium"`
	Info        int `json:"info"`
}
