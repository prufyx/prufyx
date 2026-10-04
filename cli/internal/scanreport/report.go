// SPDX-License-Identifier: AGPL-3.0-only

// Package scanreport holds the scan report: its types, its deterministic
// order, the verdict and headline, the message catalog that is the only
// source of English text in a report (rule titles and fixes come from rule
// data), and the human and JSON renderers.
//
// The package decides nothing about upgrades. It derives the verdict from
// what the caller assembled, and it can only make the verdict stricter: a
// report reaches SCOPE_COMPLETE_PASS only when it carries no finding and no
// gap, and every planned hop of every path is COVERED.
package scanreport

import (
	"math"
	"sort"

	"github.com/prufyx/prufyx/cli/internal/buildidentity"
	"github.com/prufyx/prufyx/cli/internal/constraintengine"
)

// Schema is the report schema.
const Schema = "prufyx.io/scan-report/v1alpha1"

// Verdicts.
const (
	VerdictBlocked = "BLOCKED"
	VerdictUnknown = "UNKNOWN"
	VerdictPass    = "SCOPE_COMPLETE_PASS"
)

// Hop statuses.
const (
	HopBlocked = "BLOCKED"
	HopCovered = "COVERED"
	HopPartial = "PARTIAL"
	HopNoData  = "NO_DATA"
)

// Exit codes of a finished scan.
const (
	ExitPass    = 0
	ExitBlocked = 10
	ExitUnknown = 11
)

// Report is one scan.
type Report struct {
	Schema    string      `json:"schema"`
	Verdict   string      `json:"verdict"`
	Headline  string      `json:"headline"`
	Summary   Summary     `json:"summary"`
	Inventory []Component `json:"inventory"`
	Paths     []Path      `json:"paths"`
	Findings  []Finding   `json:"findings"`
	Gaps      []Gap       `json:"gaps"`
	Passes    []Pass      `json:"passes"`
	// Notices are one-way changes: informational, never part of the
	// verdict, the headline, the exit code or any count but their own.
	Notices []Notice `json:"notices"`
	// Leads are unverified readings: informational, never part of the
	// verdict, like notices.
	Leads []Lead `json:"leads"`
	// Unsupported are combinations outside a documented support range:
	// never a blocker, never a pass; each keeps its hop undecided.
	Unsupported []Unsupported `json:"unsupported"`
	// TrustPolicy is present only when the trust policy left out a rule
	// that applies to the upgrade.
	TrustPolicy *TrustPolicy `json:"trustPolicy,omitempty"`
	// Omitted lists every document or file that was seen but not
	// evaluated, with the reason.
	Omitted []Omitted `json:"omitted"`
	// Omissions are standing statements of what a scan never checks.
	Omissions []string `json:"omissions"`
	// Notes are informational lines about the input (permission notice).
	Notes      []string   `json:"notes"`
	Provenance Provenance `json:"provenance"`
}

// Summary counts the report's content.
type Summary struct {
	Blockers           int `json:"blockers"`
	Gaps               int `json:"gaps"`
	Passes             int `json:"passes"`
	ComponentsDetected int `json:"componentsDetected"`
	ComponentsCovered  int `json:"componentsCovered"`
	Hops               int `json:"hops"`
	DocumentsRead      int `json:"documentsRead"`
	DocumentsOmitted   int `json:"documentsOmitted"`
	Notices            int `json:"notices"`
	Leads              int `json:"leads"`
	Unsupported        int `json:"unsupported"`
}

// Component is one component named by a version declaration.
type Component struct {
	Name          string `json:"name"`
	Component     string `json:"component,omitempty"`
	Current       string `json:"current,omitempty"`
	CurrentSource string `json:"currentSource,omitempty"`
	Target        string `json:"target,omitempty"`
	TargetSource  string `json:"targetSource,omitempty"`
	// Covered is true when scan evaluates this component.
	Covered bool `json:"covered"`
}

// Path is the planned upgrade of one component.
type Path struct {
	Component string `json:"component"`
	From      string `json:"from"`
	To        string `json:"to"`
	// Policy is the reviewed path policy the plan follows, empty when none.
	Policy string `json:"policy"`
	Hops   []Hop  `json:"hops"`
	// Gap names why no plan exists; Hops is then empty.
	Gap string `json:"gap,omitempty"`
}

// Endpoint is an exact version or a whole release line.
type Endpoint struct {
	Version string `json:"version,omitempty"`
	Line    string `json:"line,omitempty"`
}

// String is the version or the line.
func (e Endpoint) String() string {
	if e.Version != "" {
		return e.Version
	}
	return e.Line
}

// Hop is one evaluated hop of a path.
type Hop struct {
	Index  int      `json:"index"`
	From   Endpoint `json:"from"`
	To     Endpoint `json:"to"`
	Status string   `json:"status"`
	// InputDigest is the digest of the engine input evaluated for the hop.
	InputDigest string `json:"inputDigest,omitempty"`
	// EngineContractDigest is the engine contract the hop's rules were
	// evaluated under. It depends on the features of the selected rules
	// (for example a one-way notice or a lead), so it can differ between
	// hops and between knowledge revisions without any change of verdict.
	EngineContractDigest string       `json:"engineContractDigest,omitempty"`
	Attestation          *Attestation `json:"attestation,omitempty"`
	// Reasons are the gap reasons that keep the hop from COVERED.
	Reasons []string `json:"reasons,omitempty"`
}

// Attestation is the line review a hop relied on, or found not current.
type Attestation struct {
	Line       string `json:"line"`
	Family     string `json:"family"`
	Basis      string `json:"basis"`
	Freshness  string `json:"freshness"`
	ValidUntil string `json:"validUntil"`
}

// HopRef names a hop of a component's path. WholeUpgrade marks the
// end-to-end transition from the current version to the target, evaluated
// besides the hops for rules that span several lines.
type HopRef struct {
	Index        int    `json:"index"`
	From         string `json:"from"`
	To           string `json:"to"`
	WholeUpgrade bool   `json:"wholeUpgrade,omitempty"`
}

// order sorts hops by index; the whole upgrade sorts after every hop.
func (h HopRef) order() int {
	if h.WholeUpgrade {
		return math.MaxInt
	}
	return h.Index
}

// Finding is one decided blocker, reported once at the first hop where it
// blocks.
type Finding struct {
	RuleID    string   `json:"ruleId"`
	Component string   `json:"component"`
	Hop       HopRef   `json:"hop"`
	AlsoAt    []HopRef `json:"alsoAt,omitempty"`
	Title     string   `json:"title"`
	Fix       string   `json:"fix"`
	// Match is how the rule matched: "anchor" (its reviewed pair) or
	// "range" (inside its reviewed range).
	Match      string                            `json:"match"`
	Locations  []Location                        `json:"locations"`
	Basis      string                            `json:"basis"`
	Extractor  string                            `json:"extractor,omitempty"`
	Citations  []constraintengine.SourceEvidence `json:"citations"`
	RuleDigest string                            `json:"ruleDigest"`
}

// Location is one object that made a finding true. It never holds values.
type Location struct {
	File      string `json:"file"`
	Document  int    `json:"document"`
	Item      int    `json:"item"`
	Line      int    `json:"line,omitempty"`
	Kind      string `json:"kind"`
	Namespace string `json:"namespace,omitempty"`
	Name      string `json:"name"`
}

// Gap is one reason the answer is not complete.
type Gap struct {
	Component string  `json:"component"`
	Hop       *HopRef `json:"hop,omitempty"`
	Reason    string  `json:"reason"`
	Detail    string  `json:"detail"`
	Action    string  `json:"action"`
}

// Pass is one decided PASS claim.
type Pass struct {
	RuleID    string `json:"ruleId"`
	Component string `json:"component"`
	Hop       HopRef `json:"hop"`
}

// Notice is a one-way notice rule that applies to a hop: the reviewed
// transition cannot be rolled back. Established is false when the notice
// rule applies but could not be evaluated (Reason says why); the absence of a
// notice never says that a rollback is possible.
type Notice struct {
	RuleID      string                            `json:"ruleId"`
	Component   string                            `json:"component"`
	Hop         HopRef                            `json:"hop"`
	AlsoAt      []HopRef                          `json:"alsoAt,omitempty"`
	Established bool                              `json:"established"`
	Reason      string                            `json:"reason,omitempty"`
	Text        string                            `json:"text"`
	Basis       string                            `json:"basis"`
	Citations   []constraintengine.SourceEvidence `json:"citations"`
}

// Lead is an unverified lead rule that would block on a hop. It never
// blocks, never passes and never changes the answer.
type Lead struct {
	RuleID    string                            `json:"ruleId"`
	Component string                            `json:"component"`
	Hop       HopRef                            `json:"hop"`
	AlsoAt    []HopRef                          `json:"alsoAt,omitempty"`
	Text      string                            `json:"text"`
	Citations []constraintengine.SourceEvidence `json:"citations"`
}

// Unsupported is a support-range rule that finds the planned combination
// outside its documented support range on a hop.
type Unsupported struct {
	RuleID    string                            `json:"ruleId"`
	Component string                            `json:"component"`
	Hop       HopRef                            `json:"hop"`
	AlsoAt    []HopRef                          `json:"alsoAt,omitempty"`
	Reason    string                            `json:"reason"`
	Fix       string                            `json:"fix"`
	Basis     string                            `json:"basis"`
	Citations []constraintengine.SourceEvidence `json:"citations"`
}

// TrustPolicy discloses the evidence bases a scan evaluated and how many
// rules that apply to the upgrade it left out: verdict rules (so the answer
// cannot pass) and lead rules (which never take part).
type TrustPolicy struct {
	RequiredBasis     []string `json:"requiredBasis"`
	ExcludedRules     int      `json:"excludedRules"`
	ExcludedLeadRules int      `json:"excludedLeadRules,omitempty"`
}

// Omitted is one document or file that was seen and not evaluated.
type Omitted struct {
	File     string `json:"file"`
	Document int    `json:"document"`
	Item     int    `json:"item"`
	Line     int    `json:"line,omitempty"`
	Reason   string `json:"reason"`
}

// Provenance identifies everything the answer depends on.
type Provenance struct {
	EvaluatedAt          string                 `json:"evaluatedAt"`
	InputDigest          string                 `json:"inputDigest"`
	ConfigDigest         string                 `json:"configDigest,omitempty"`
	KnowledgeOrigin      string                 `json:"knowledgeOrigin"`
	KnowledgeRevision    string                 `json:"knowledgeRevision"`
	KnowledgeDigest      string                 `json:"knowledgeDigest"`
	EngineContractDigest string                 `json:"engineContractDigest"`
	NetworkUsed          bool                   `json:"networkUsed"`
	Build                buildidentity.Identity `json:"build"`
	// KnowledgeStore is set when the knowledge was selected from a verified
	// local knowledge database (--knowledge-db). KnowledgeRevision and
	// KnowledgeDigest then identify the selected target.
	KnowledgeStore *KnowledgeStore `json:"knowledgeStore,omitempty"`
}

// KnowledgeStore identifies the knowledge database a scan read: where it is,
// its layout, the selected target and trust receipt, and each project
// target the scan opened from it.
type KnowledgeStore struct {
	Path               string                  `json:"path"`
	Layout             string                  `json:"layout"`
	TargetPath         string                  `json:"targetPath"`
	TrustReceiptDigest string                  `json:"trustReceiptDigest"`
	Purpose            string                  `json:"purpose"`
	ImportedVerifiedAt string                  `json:"importedVerifiedAt"`
	Projects           []KnowledgeStoreProject `json:"projects,omitempty"`
}

// KnowledgeStoreProject is one project target opened from a per-project
// knowledge database. Status is "present", or "absent_from_index" when the
// selected index has no target for the project.
type KnowledgeStoreProject struct {
	Project    string `json:"project"`
	Status     string `json:"status"`
	TargetPath string `json:"targetPath,omitempty"`
	Revision   string `json:"revision,omitempty"`
	Digest     string `json:"digest,omitempty"`
}

// Finalize puts the report in its canonical order, fills the summary and
// derives the verdict and headline. Call it once, after every part is set.
func Finalize(report *Report) {
	report.Schema = Schema
	sortReport(report)
	report.Summary.Blockers = len(report.Findings)
	report.Summary.Gaps = len(report.Gaps)
	report.Summary.Passes = len(report.Passes)
	report.Summary.ComponentsDetected = len(report.Inventory)
	report.Summary.ComponentsCovered = 0
	for _, component := range report.Inventory {
		if component.Covered {
			report.Summary.ComponentsCovered++
		}
	}
	report.Summary.Hops = 0
	for _, path := range report.Paths {
		report.Summary.Hops += len(path.Hops)
	}
	report.Summary.DocumentsOmitted = len(report.Omitted)
	report.Summary.Notices = len(report.Notices)
	report.Summary.Leads = len(report.Leads)
	report.Summary.Unsupported = len(report.Unsupported)
	report.Verdict = verdict(*report)
	report.Headline = headline(*report)
}

// verdict is BLOCKED with any finding; SCOPE_COMPLETE_PASS only with no gap,
// at least one path, and every path planned with every hop COVERED;
// UNKNOWN otherwise.
func verdict(report Report) string {
	if len(report.Findings) > 0 {
		return VerdictBlocked
	}
	if len(report.Gaps) > 0 || len(report.Paths) == 0 {
		return VerdictUnknown
	}
	for _, path := range report.Paths {
		if path.Gap != "" || len(path.Hops) == 0 {
			return VerdictUnknown
		}
		for _, hop := range path.Hops {
			if hop.Status != HopCovered {
				return VerdictUnknown
			}
		}
	}
	for _, component := range report.Inventory {
		if component.Target != "" && !component.Covered {
			return VerdictUnknown
		}
	}
	return VerdictPass
}

// Exit is the process exit code for the report's verdict.
func Exit(report Report) int {
	switch report.Verdict {
	case VerdictBlocked:
		return ExitBlocked
	case VerdictPass:
		return ExitPass
	}
	return ExitUnknown
}

func sortReport(report *Report) {
	sort.SliceStable(report.Inventory, func(i, j int) bool { return report.Inventory[i].Name < report.Inventory[j].Name })
	sort.SliceStable(report.Paths, func(i, j int) bool { return report.Paths[i].Component < report.Paths[j].Component })
	for p := range report.Paths {
		hops := report.Paths[p].Hops
		sort.SliceStable(hops, func(i, j int) bool { return hops[i].Index < hops[j].Index })
		for h := range hops {
			hops[h].Reasons = uniqueSorted(hops[h].Reasons)
		}
	}
	for f := range report.Findings {
		finding := &report.Findings[f]
		sortLocations(finding.Locations)
		sort.SliceStable(finding.AlsoAt, func(i, j int) bool { return finding.AlsoAt[i].order() < finding.AlsoAt[j].order() })
	}
	sort.SliceStable(report.Findings, func(i, j int) bool {
		a, b := report.Findings[i], report.Findings[j]
		if a.Component != b.Component {
			return a.Component < b.Component
		}
		if a.Hop.order() != b.Hop.order() {
			return a.Hop.order() < b.Hop.order()
		}
		return a.RuleID < b.RuleID
	})
	sort.SliceStable(report.Gaps, func(i, j int) bool { return gapLess(report.Gaps[i], report.Gaps[j]) })
	report.Gaps = uniqueGaps(report.Gaps)
	sort.SliceStable(report.Passes, func(i, j int) bool {
		a, b := report.Passes[i], report.Passes[j]
		if a.Component != b.Component {
			return a.Component < b.Component
		}
		if a.Hop.order() != b.Hop.order() {
			return a.Hop.order() < b.Hop.order()
		}
		return a.RuleID < b.RuleID
	})
	sortOmitted(report.Omitted)
	if report.Inventory == nil {
		report.Inventory = []Component{}
	}
	if report.Paths == nil {
		report.Paths = []Path{}
	}
	for p := range report.Paths {
		if report.Paths[p].Hops == nil {
			report.Paths[p].Hops = []Hop{}
		}
	}
	if report.Findings == nil {
		report.Findings = []Finding{}
	}
	if report.Gaps == nil {
		report.Gaps = []Gap{}
	}
	if report.Passes == nil {
		report.Passes = []Pass{}
	}
	for n := range report.Notices {
		notice := &report.Notices[n]
		sort.SliceStable(notice.AlsoAt, func(i, j int) bool { return notice.AlsoAt[i].order() < notice.AlsoAt[j].order() })
	}
	sort.SliceStable(report.Notices, func(i, j int) bool {
		a, b := report.Notices[i], report.Notices[j]
		if a.Component != b.Component {
			return a.Component < b.Component
		}
		if a.Hop.order() != b.Hop.order() {
			return a.Hop.order() < b.Hop.order()
		}
		return a.RuleID < b.RuleID
	})
	if report.Notices == nil {
		report.Notices = []Notice{}
	}
	for l := range report.Leads {
		lead := &report.Leads[l]
		sort.SliceStable(lead.AlsoAt, func(i, j int) bool { return lead.AlsoAt[i].order() < lead.AlsoAt[j].order() })
	}
	sort.SliceStable(report.Leads, func(i, j int) bool {
		a, b := report.Leads[i], report.Leads[j]
		if a.Component != b.Component {
			return a.Component < b.Component
		}
		if a.Hop.order() != b.Hop.order() {
			return a.Hop.order() < b.Hop.order()
		}
		return a.RuleID < b.RuleID
	})
	if report.Leads == nil {
		report.Leads = []Lead{}
	}
	for u := range report.Unsupported {
		entry := &report.Unsupported[u]
		sort.SliceStable(entry.AlsoAt, func(i, j int) bool { return entry.AlsoAt[i].order() < entry.AlsoAt[j].order() })
	}
	sort.SliceStable(report.Unsupported, func(i, j int) bool {
		a, b := report.Unsupported[i], report.Unsupported[j]
		if a.Component != b.Component {
			return a.Component < b.Component
		}
		if a.Hop.order() != b.Hop.order() {
			return a.Hop.order() < b.Hop.order()
		}
		return a.RuleID < b.RuleID
	})
	if report.Unsupported == nil {
		report.Unsupported = []Unsupported{}
	}
	if report.Omitted == nil {
		report.Omitted = []Omitted{}
	}
	if report.Omissions == nil {
		report.Omissions = []string{}
	}
	if report.Notes == nil {
		report.Notes = []string{}
	}
}

// sortLocations orders a finding's locations by file, document and item.
// Redact calls it again after replacing the file with its digest.
func sortLocations(locations []Location) {
	sort.SliceStable(locations, func(i, j int) bool { return locationLess(locations[i], locations[j]) })
}

// sortOmitted orders omitted documents by file, document, item and reason.
// Redact calls it again after replacing the file with its digest.
func sortOmitted(omitted []Omitted) {
	sort.SliceStable(omitted, func(i, j int) bool {
		a, b := omitted[i], omitted[j]
		if a.File != b.File {
			return a.File < b.File
		}
		if a.Document != b.Document {
			return a.Document < b.Document
		}
		if a.Item != b.Item {
			return a.Item < b.Item
		}
		return a.Reason < b.Reason
	})
}

func locationLess(a, b Location) bool {
	if a.File != b.File {
		return a.File < b.File
	}
	if a.Document != b.Document {
		return a.Document < b.Document
	}
	return a.Item < b.Item
}

func gapOrder(h *HopRef) int {
	if h == nil {
		return -1
	}
	return h.order()
}

func gapLess(a, b Gap) bool {
	if a.Component != b.Component {
		return a.Component < b.Component
	}
	if gapOrder(a.Hop) != gapOrder(b.Hop) {
		return gapOrder(a.Hop) < gapOrder(b.Hop)
	}
	if a.Reason != b.Reason {
		return a.Reason < b.Reason
	}
	if a.Detail != b.Detail {
		return a.Detail < b.Detail
	}
	if a.Action != b.Action {
		return a.Action < b.Action
	}
	return hopRefLess(a.Hop, b.Hop)
}

// hopRefLess breaks the last tie between gaps: two hop references with the
// same order but different fields. Callers do not produce such hops today;
// the tie-break keeps the order total, so it never depends on input order,
// and keeps exact duplicates adjacent for uniqueGaps.
func hopRefLess(a, b *HopRef) bool {
	if a == nil || b == nil {
		return a == nil && b != nil
	}
	if a.Index != b.Index {
		return a.Index < b.Index
	}
	if a.From != b.From {
		return a.From < b.From
	}
	if a.To != b.To {
		return a.To < b.To
	}
	return !a.WholeUpgrade && b.WholeUpgrade
}

// uniqueGaps drops exact repeats of a sorted gap list.
func uniqueGaps(gaps []Gap) []Gap {
	out := make([]Gap, 0, len(gaps))
	for index, gap := range gaps {
		if index > 0 && sameGap(gaps[index-1], gap) {
			continue
		}
		out = append(out, gap)
	}
	return out
}

func sameGap(a, b Gap) bool {
	if a.Component != b.Component || a.Reason != b.Reason || a.Detail != b.Detail || a.Action != b.Action || (a.Hop == nil) != (b.Hop == nil) {
		return false
	}
	return a.Hop == nil || *a.Hop == *b.Hop
}

func uniqueSorted(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	sorted := append([]string(nil), values...)
	sort.Strings(sorted)
	out := sorted[:1]
	for _, value := range sorted[1:] {
		if value != out[len(out)-1] {
			out = append(out, value)
		}
	}
	return out
}
