// SPDX-License-Identifier: AGPL-3.0-only

// Package upgradeplan turns one scan report, produced with the full
// (current, target) pair of every component, into an ordered upgrade plan:
// one stage per planned hop, an order label per stage, and a verdict per
// stage that never says PASS for anything the plan cannot prove.
//
// It evaluates no rule. Every finding, gap and unsupported combination in a
// stage comes from the scan report; the plan only places them. The honesty
// rules are the design's: a stage is PASS only when its hop is COVERED, its
// order is required, its hop actions are checked and its node rolls are
// planned. This version checks no hop actions and plans no node rolls, so no
// stage is PASS yet; the gates are explicit so a later version can lift them
// one at a time.
package upgradeplan

import (
	"fmt"
	"sort"

	"github.com/prufyx/prufyx/cli/internal/scanconfig"
	"github.com/prufyx/prufyx/cli/internal/scanreport"
)

// Schema is the JSON schema of a rendered plan.
const Schema = "prufyx.io/upgrade-plan/v1alpha1"

// Stage and plan verdicts, worst first.
const (
	VerdictBlocked     = "BLOCKED"
	VerdictUnsupported = "UNSUPPORTED"
	VerdictUnknown     = "UNKNOWN"
	VerdictPass        = "PASS"
)

// Exit codes, as scan.
const (
	ExitPass    = 0
	ExitBlocked = 10
	ExitUnknown = 11
)

// Order kinds.
const (
	// OrderRequired: a reviewed path policy forces the order of the hops.
	OrderRequired = "required"
	// OrderInferred: Prufyx chose the place; no cited constraint says so.
	OrderInferred = "inferred"
	// OrderFree: nothing constrains the place.
	OrderFree = "free"
)

// Reason codes that keep a stage from PASS besides the scan's own findings.
const (
	ReasonOrderInferred       = "ORDER_INFERRED"
	ReasonActionsNotChecked   = "HOP_ACTIONS_NOT_CHECKED"
	ReasonNodeRollsNotPlanned = "NODE_ROLLS_NOT_PLANNED"
	ReasonHopNotCovered       = "HOP_NOT_COVERED"
	// ReasonBlockedEarlier: the hop is BLOCKED by a rule the scan reported at
	// an earlier hop of the same component.
	ReasonBlockedEarlier = "BLOCKED_BY_EARLIER_FINDING"
	ReasonComponentGap   = "COMPONENT_GAP"
	// ReasonLatestNotResolved: the target was "latest" and no signed
	// release-line snapshot ships, so the component is not planned.
	ReasonLatestNotResolved = "LATEST_NOT_RESOLVED"
	// ReasonPlanGap is the plan-level gap code for a path the scan could
	// not plan; the scan's own gap name is kept in the detail.
	ReasonPlanGap = "PATH_NOT_PLANNED"
)

const kubernetes = "kubernetes"

// Capabilities are what this version of the planner can establish. A stage
// is PASS only when every one it needs is true.
type Capabilities struct {
	ActionsChecked   bool
	NodeRollsPlanned bool
}

// Plan is the ordered upgrade plan.
type Plan struct {
	Schema   string  `json:"schema"`
	Verdict  string  `json:"verdict"`
	Headline string  `json:"headline"`
	Routes   []Route `json:"routes"`
	Stages   []Stage `json:"stages"`
	// Gaps are the plan-level reasons a component is not planned.
	Gaps []Gap `json:"gaps"`
	// Undecided counts the stages that are not PASS.
	Undecided int `json:"undecided"`
	// Notes say how a target was chosen when Prufyx chose it.
	Notes []string `json:"notes"`
	// Provenance repeats the scan's, so the plan names what it rests on.
	Provenance scanreport.Provenance `json:"provenance"`
	ExitCode   int                   `json:"exitCode"`
}

// Route is the planned path of one component.
type Route struct {
	Component string   `json:"component"`
	From      string   `json:"from"`
	To        string   `json:"to"`
	Policy    string   `json:"policy"`
	Stops     []string `json:"stops"`
	Hops      int      `json:"hops"`
	Gap       string   `json:"gap,omitempty"`
}

// Order says why a stage sits where it does.
type Order struct {
	Kind   string `json:"kind"`
	Reason string `json:"reason"`
}

// Stage is one hop of one component, in plan order.
type Stage struct {
	Index     int    `json:"index"`
	Component string `json:"component"`
	From      string `json:"from"`
	To        string `json:"to"`
	Order     Order  `json:"order"`
	// HopStatus is the scan's status of the hop.
	HopStatus   string    `json:"hopStatus"`
	Verdict     string    `json:"verdict"`
	Findings    []Finding `json:"findings"`
	Unsupported []Finding `json:"unsupported"`
	Notices     []string  `json:"notices"`
	// Reasons are the codes that keep the stage from PASS other than a
	// finding: scan gaps of the hop, the order, unchecked actions.
	Reasons []string `json:"reasons"`
	Gaps    []Gap    `json:"gaps"`
	// WholeUpgrade marks a stage that carries a finding of the end-to-end
	// transition (a rule spanning several lines).
	WholeUpgrade bool `json:"wholeUpgrade,omitempty"`
}

// Finding is a rule result placed in a stage.
type Finding struct {
	RuleID string `json:"ruleId"`
	Title  string `json:"title"`
	Fix    string `json:"fix"`
	// Whole is true when the rule decided the end-to-end upgrade; it is
	// shown in exactly one stage.
	Whole bool `json:"whole,omitempty"`
}

// Gap is a reason part of the answer is missing.
type Gap struct {
	Component string `json:"component"`
	Reason    string `json:"reason"`
	Detail    string `json:"detail"`
	Action    string `json:"action"`
}

// Build places the scan report's paths in a plan. latest lists the
// components whose target was "latest": they are not in the scan, and each
// becomes a LATEST_NOT_RESOLVED gap.
func Build(report scanreport.Report, latest []string, caps Capabilities) Plan {
	plan := Plan{Schema: Schema, Routes: []Route{}, Stages: []Stage{}, Gaps: []Gap{}, Notes: []string{}, Provenance: report.Provenance}
	for _, component := range latest {
		plan.Gaps = append(plan.Gaps, Gap{Component: component, Reason: ReasonLatestNotResolved,
			Detail: "the target is latest and no signed release-line snapshot ships, so the newest release is not known",
			Action: "give an explicit target version: --to " + component + "=X.Y.Z"})
	}

	for _, c := range report.Inventory {
		if c.TargetSource == string(scanconfig.FromNewestCovered) {
			plan.Notes = append(plan.Notes, fmt.Sprintf("%s target %s was chosen by Prufyx: the newest release line with a current reviewed list in the knowledge, at its .0 release. It is not the newest release.", c.Name, c.Target))
		}
	}

	paths := append([]scanreport.Path(nil), report.Paths...)
	sort.SliceStable(paths, func(i, j int) bool {
		ki, kj := paths[i].Component == kubernetes, paths[j].Component == kubernetes
		if ki != kj {
			return ki
		}
		return paths[i].Component < paths[j].Component
	})
	hasK8s := len(paths) > 0 && paths[0].Component == kubernetes && len(paths[0].Hops) > 0

	used := map[string]bool{}
	components := len(latest)
	for _, path := range paths {
		route := Route{Component: path.Component, From: path.From, To: path.To, Policy: path.Policy, Stops: []string{}, Hops: len(path.Hops), Gap: path.Gap}
		for i, hop := range path.Hops {
			if i < len(path.Hops)-1 {
				route.Stops = append(route.Stops, hop.To.String())
			}
		}
		plan.Routes = append(plan.Routes, route)
		components++
		if path.Gap != "" || len(path.Hops) == 0 {
			plan.Gaps = append(plan.Gaps, Gap{Component: path.Component, Reason: ReasonPlanGap, Detail: "the scan planned no hops: " + path.Gap,
				Action: "see prufyx scan --help for the gap " + path.Gap})
			continue
		}
		for _, hop := range path.Hops {
			plan.Stages = append(plan.Stages, newStage(path, hop, hasK8s, report, caps, used))
		}
	}
	for i := range plan.Stages {
		plan.Stages[i].Index = i + 1
	}

	placeWhole(&plan, report, used)
	placeLeftovers(&plan, report, used)
	for i := range plan.Stages {
		finishStage(&plan.Stages[i], caps)
	}
	finish(&plan, report, components)
	return plan
}

func newStage(path scanreport.Path, hop scanreport.Hop, hasK8s bool, report scanreport.Report, caps Capabilities, used map[string]bool) Stage {
	stage := Stage{Component: path.Component, From: hop.From.String(), To: hop.To.String(), HopStatus: hop.Status,
		Findings: []Finding{}, Unsupported: []Finding{}, Notices: []string{}, Reasons: []string{}, Gaps: []Gap{}}
	switch {
	case path.Component == kubernetes && path.Policy != "":
		stage.Order = Order{OrderRequired, "reviewed path policy " + path.Policy + " forces one hop per minor line"}
	case path.Component == kubernetes:
		stage.Order = Order{OrderInferred, "no reviewed path policy"}
	case hasK8s:
		stage.Order = Order{OrderInferred, "placed after the last Kubernetes hop; no support-range data orders it earlier"}
	default:
		stage.Order = Order{OrderFree, "no other component is planned"}
	}
	for _, f := range report.Findings {
		if f.Component == path.Component && !f.Hop.WholeUpgrade && f.Hop.Index == hop.Index {
			stage.Findings = append(stage.Findings, Finding{RuleID: f.RuleID, Title: f.Title, Fix: f.Fix})
			used["f:"+key(f.Component, f.RuleID)] = true
		}
	}
	for _, u := range report.Unsupported {
		if u.Component == path.Component && !u.Hop.WholeUpgrade && u.Hop.Index == hop.Index {
			stage.Unsupported = append(stage.Unsupported, Finding{RuleID: u.RuleID, Title: u.Reason, Fix: u.Fix})
			used["u:"+key(u.Component, u.RuleID)] = true
		}
	}
	for _, n := range report.Notices {
		if n.Component == path.Component && !n.Hop.WholeUpgrade && n.Hop.Index == hop.Index {
			stage.Notices = append(stage.Notices, n.RuleID+": "+n.Text)
		}
	}
	for i, g := range report.Gaps {
		if g.Component != path.Component {
			continue
		}
		if g.Hop == nil || g.Hop.Index == hop.Index && !g.Hop.WholeUpgrade {
			stage.Gaps = append(stage.Gaps, Gap{Component: g.Component, Reason: g.Reason, Detail: g.Detail, Action: g.Action})
			used[fmt.Sprintf("g:%d", i)] = true
		}
	}
	return stage
}

// placeWhole puts every end-to-end finding in the last stage of its
// component: exactly one stage shows it.
func placeWhole(plan *Plan, report scanreport.Report, used map[string]bool) {
	last := map[string]int{}
	for i, s := range plan.Stages {
		last[s.Component] = i
	}
	for _, f := range report.Findings {
		if !f.Hop.WholeUpgrade {
			continue
		}
		if i, ok := last[f.Component]; ok {
			plan.Stages[i].Findings = append(plan.Stages[i].Findings, Finding{RuleID: f.RuleID, Title: f.Title, Fix: f.Fix, Whole: true})
			plan.Stages[i].WholeUpgrade = true
			used["f:"+key(f.Component, f.RuleID)] = true
		}
	}
	for i, g := range report.Gaps {
		if g.Hop == nil || !g.Hop.WholeUpgrade {
			continue
		}
		if j, ok := last[g.Component]; ok {
			plan.Stages[j].Gaps = append(plan.Stages[j].Gaps, Gap{Component: g.Component, Reason: g.Reason, Detail: g.Detail, Action: g.Action})
			used[fmt.Sprintf("g:%d", i)] = true
		}
	}
	for _, u := range report.Unsupported {
		if !u.Hop.WholeUpgrade {
			continue
		}
		if i, ok := last[u.Component]; ok {
			plan.Stages[i].Unsupported = append(plan.Stages[i].Unsupported, Finding{RuleID: u.RuleID, Title: u.Reason, Fix: u.Fix, Whole: true})
			plan.Stages[i].WholeUpgrade = true
			used["u:"+key(u.Component, u.RuleID)] = true
		}
	}
}

// placeLeftovers keeps a result that fits no stage (its component has no
// hops, or the hop index is unknown): it is a plan gap, so a blocker is
// never dropped. Findings keep the plan BLOCKED through the report verdict.
func placeLeftovers(plan *Plan, report scanreport.Report, used map[string]bool) {
	for _, f := range report.Findings {
		if !used["f:"+key(f.Component, f.RuleID)] {
			plan.Gaps = append(plan.Gaps, Gap{Component: f.Component, Reason: "FINDING_NOT_PLACED", Detail: f.RuleID + ": " + f.Title, Action: f.Fix})
		}
	}
	for _, u := range report.Unsupported {
		if !used["u:"+key(u.Component, u.RuleID)] {
			plan.Gaps = append(plan.Gaps, Gap{Component: u.Component, Reason: "UNSUPPORTED_NOT_PLACED", Detail: u.RuleID + ": " + u.Reason, Action: u.Fix})
		}
	}
	for i, g := range report.Gaps {
		if !used[fmt.Sprintf("g:%d", i)] {
			plan.Gaps = append(plan.Gaps, Gap{Component: g.Component, Reason: g.Reason, Detail: g.Detail, Action: g.Action})
		}
	}
}

func key(component, rule string) string { return component + "\x00" + rule }

// finishStage derives the reasons and the verdict of a stage.
func finishStage(stage *Stage, caps Capabilities) {
	if stage.HopStatus != scanreport.HopCovered && stage.HopStatus != scanreport.HopBlocked && len(stage.Findings) == 0 {
		stage.Reasons = append(stage.Reasons, ReasonHopNotCovered)
	}
	if len(stage.Gaps) > 0 {
		stage.Reasons = append(stage.Reasons, ReasonComponentGap)
	}
	if stage.Order.Kind == OrderInferred {
		stage.Reasons = append(stage.Reasons, ReasonOrderInferred)
	}
	if !caps.ActionsChecked {
		stage.Reasons = append(stage.Reasons, ReasonActionsNotChecked)
	}
	if stage.Component == kubernetes && !caps.NodeRollsPlanned {
		stage.Reasons = append(stage.Reasons, ReasonNodeRollsNotPlanned)
	}
	if stage.HopStatus == scanreport.HopBlocked && len(stage.Findings) == 0 {
		// The scan reports a blocker once, at its first hop; later hops it
		// blocks keep the BLOCKED status and name no finding.
		stage.Reasons = append(stage.Reasons, ReasonBlockedEarlier)
	}
	switch {
	case stage.HopStatus == scanreport.HopBlocked, len(stage.Findings) > 0:
		stage.Verdict = VerdictBlocked
	case len(stage.Unsupported) > 0:
		stage.Verdict = VerdictUnsupported
	case len(stage.Reasons) > 0:
		stage.Verdict = VerdictUnknown
	default:
		stage.Verdict = VerdictPass
	}
}

// finish sets the plan verdict (the worst stage; any plan gap is at least
// UNKNOWN), the counts, the exit code and the headline.
func finish(plan *Plan, report scanreport.Report, components int) {
	rank := map[string]int{VerdictPass: 0, VerdictUnknown: 1, VerdictUnsupported: 2, VerdictBlocked: 3}
	worst := VerdictPass
	blocked := report.Verdict == scanreport.VerdictBlocked || len(report.Findings) > 0
	counts := map[string]int{}
	for _, s := range plan.Stages {
		counts[s.Verdict]++
		if rank[s.Verdict] > rank[worst] {
			worst = s.Verdict
		}
	}
	if blocked && rank[worst] < rank[VerdictBlocked] {
		worst = VerdictBlocked
	}
	if (len(plan.Gaps) > 0 || len(plan.Stages) == 0) && rank[worst] < rank[VerdictUnknown] {
		worst = VerdictUnknown
	}
	plan.Verdict = worst
	plan.Undecided = len(plan.Stages) - counts[VerdictPass]
	switch worst {
	case VerdictPass:
		plan.ExitCode = ExitPass
	case VerdictBlocked:
		plan.ExitCode = ExitBlocked
	default:
		plan.ExitCode = ExitUnknown
	}
	plan.Headline = fmt.Sprintf("Upgrade plan: %d components, %d hops in %d stages. Verdict: %s (BLOCKED %d, UNSUPPORTED %d, UNKNOWN %d, PASS %d).",
		components, hopCount(plan.Routes), len(plan.Stages), worst, counts[VerdictBlocked], counts[VerdictUnsupported], counts[VerdictUnknown], counts[VerdictPass])
}

func hopCount(routes []Route) int {
	n := 0
	for _, r := range routes {
		n += r.Hops
	}
	return n
}
