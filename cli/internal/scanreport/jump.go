// SPDX-License-Identifier: AGPL-3.0-only

package scanreport

import (
	"fmt"
	"sort"
	"strings"
)

// Jump statuses. The answer for an upgrade over several hops is composed from
// the statuses of its hops. STEPWISE_PASS is the only pass wording: it holds
// for the stepwise upgrade through the listed hops and for nothing else.
const (
	JumpBlocked      = "BLOCKED"
	JumpAttention    = "ATTENTION"
	JumpStepwisePass = "STEPWISE_PASS"
	JumpUnknown      = "UNKNOWN"
)

// Jump hop statuses. A hop is UNDECIDED unless it is positively one of the
// other three; an absent or unknown status is UNDECIDED.
const (
	JumpHopBlocked   = "BLOCKED"
	JumpHopPass      = "PASS"
	JumpHopAttention = "ATTENTION"
	JumpHopUndecided = "UNDECIDED"
)

// JumpScope is the sentence every jump carries: what a jump answer covers
// and what it does not.
const JumpScope = "composed from the hops of the stepwise path through the named releases, for the custom-resource versions of the manifests as they are today; " +
	"a direct skip of a release line, stored versions and conversion, hooks and data migrations, other patch releases of an intermediate line, " +
	"and a retagged or withdrawn release (not detectable offline) are not evaluated"

// Jump is the answer for an upgrade of several minor lines, composed from the
// decided hops of the stepwise path. It is informational: Verdict and Exit
// never read it.
type Jump struct {
	Status string `json:"status"`
	Scope  string `json:"scope"`
	// ObjectSetDigest is the one digest of the object set every hop was
	// evaluated on. A hop on another set is not composable.
	ObjectSetDigest string `json:"objectSetDigest"`
	// Releases are the intermediate releases the path goes through, with the
	// commit the line reviews pin them to.
	Releases []JumpRelease `json:"releases"`
	// Hops lists every hop of the path with its own status, always.
	Hops []JumpHop `json:"hops"`
	// DecidedBy are the hops that set the status.
	DecidedBy []int `json:"decidedBy"`
	// Missing names, for every hop that is not decided, the missing evidence
	// and the next bounded action.
	Missing []JumpMissing `json:"missing"`
}

// JumpRelease is an intermediate release of the path.
type JumpRelease struct {
	Line    string `json:"line"`
	Version string `json:"version"`
	Commit  string `json:"commit"`
}

// JumpHop is one hop of the path and its status.
type JumpHop struct {
	Index           int    `json:"index"`
	From            string `json:"from"`
	To              string `json:"to"`
	Status          string `json:"status"`
	ObjectSetDigest string `json:"objectSetDigest,omitempty"`
	// RuleIDs are the rules that blocked the hop.
	RuleIDs []string `json:"ruleIds,omitempty"`
	// Entries are the cited change-list entries of an ATTENTION hop.
	Entries     []string     `json:"entries,omitempty"`
	Attestation *Attestation `json:"attestation,omitempty"`
	// Reasons are the gap reasons of an undecided hop.
	Reasons []string `json:"reasons,omitempty"`
}

// JumpMissing is what keeps a hop from being decided.
type JumpMissing struct {
	Hop      int    `json:"hop"`
	Evidence string `json:"evidence"`
	Action   string `json:"action"`
}

// normal returns the status a hop counts as: anything that is not a
// positive, supported status is UNDECIDED.
func (h JumpHop) normal(digest string) string {
	if digest == "" || h.ObjectSetDigest != digest {
		return JumpHopUndecided
	}
	switch h.Status {
	case JumpHopBlocked:
		if len(h.RuleIDs) > 0 {
			return JumpHopBlocked
		}
	case JumpHopAttention:
		if len(h.Entries) > 0 {
			return JumpHopAttention
		}
	case JumpHopPass:
		return JumpHopPass
	}
	return JumpHopUndecided
}

// ComposeJump derives the status of a jump from its hops alone, with no clock
// and no other input, so a recorded jump can be recomputed. A BLOCKED hop wins
// only when it names the rule that blocked it and sits on the jump's one
// object set; STEPWISE_PASS needs every hop PASS on that set, in an unbroken
// chain. The hop list is never empty in the result of a jump with hops.
func ComposeJump(hops []JumpHop, digest string) (status string, decidedBy []int) {
	decidedBy = []int{}
	chained := len(hops) > 0
	for i, hop := range hops {
		if hop.Index != i+1 || (i > 0 && !sameEnd(hops[i-1].To, hop.From)) {
			chained = false
		}
	}
	var blocked, attention, passed []int
	for _, hop := range hops {
		switch hop.normal(digest) {
		case JumpHopBlocked:
			blocked = append(blocked, hop.Index)
		case JumpHopAttention:
			attention = append(attention, hop.Index)
		case JumpHopPass:
			passed = append(passed, hop.Index)
		}
	}
	switch {
	case len(blocked) > 0:
		return JumpBlocked, blocked
	case chained && len(attention) > 0:
		return JumpAttention, attention
	case chained && len(passed) == len(hops):
		return JumpStepwisePass, passed
	}
	return JumpUnknown, decidedBy
}

// NewJump composes a jump from its hops. Every hop that is not PASS, and
// every hop that cannot be composed, is listed in Missing with the evidence
// it lacks, so no jump answer is a bare UNKNOWN.
func NewJump(hops []JumpHop, digest string, releases []JumpRelease, actions map[int]string) Jump {
	j := Jump{Scope: JumpScope, ObjectSetDigest: digest, Releases: append([]JumpRelease{}, releases...), Hops: append([]JumpHop{}, hops...), Missing: []JumpMissing{}}
	j.Status, j.DecidedBy = ComposeJump(j.Hops, digest)
	for _, hop := range j.Hops {
		norm := hop.normal(digest)
		if norm == JumpHopPass || norm == JumpHopBlocked || norm == JumpHopAttention {
			continue
		}
		evidence := strings.Join(hop.Reasons, ", ")
		switch {
		case digest == "" || hop.ObjectSetDigest != digest:
			evidence = "the hop was not evaluated on the jump's object set"
		case evidence == "":
			evidence = "no decided result for the hop"
		}
		action := actions[hop.Index]
		if action == "" {
			action = "check this hop's upgrade notes and custom-resource versions by hand"
		}
		j.Missing = append(j.Missing, JumpMissing{Hop: hop.Index, Evidence: evidence, Action: action})
	}
	sort.Slice(j.Missing, func(a, b int) bool { return j.Missing[a].Hop < j.Missing[b].Hop })
	return j
}

// JumpLines renders a jump: the status, every hop with its own status, which
// hops decide the result and what is missing. It always prints the per-hop
// table.
func JumpLines(component, from, to string, j Jump) []string {
	var out []string
	switch j.Status {
	case JumpBlocked:
		out = append(out, fmt.Sprintf(labelJumpBlocked, component, from, to, joinInts(j.DecidedBy)))
	case JumpAttention:
		out = append(out, fmt.Sprintf(labelJumpAttention, component, from, to, joinInts(j.DecidedBy)))
	case JumpStepwisePass:
		out = append(out, fmt.Sprintf(labelJumpPass, component, from, to))
	default:
		out = append(out, fmt.Sprintf(labelJumpUnknown, component, from, to))
	}
	for _, hop := range j.Hops {
		text := fmt.Sprintf(labelJumpHop, hop.Index, hop.From, hop.To, hop.Status)
		switch {
		case len(hop.RuleIDs) > 0:
			text += " " + strings.Join(hop.RuleIDs, ", ")
		case len(hop.Entries) > 0:
			text += " " + strings.Join(hop.Entries, "; ")
		case len(hop.Reasons) > 0:
			text += " (" + strings.Join(hop.Reasons, ", ") + ")"
		}
		out = append(out, text)
	}
	if len(j.Releases) > 0 {
		var via []string
		for _, r := range j.Releases {
			via = append(via, r.Version+" (commit "+r.Commit+")")
		}
		out = append(out, fmt.Sprintf(labelJumpVia, strings.Join(via, ", ")))
	}
	if len(j.DecidedBy) > 0 {
		out = append(out, fmt.Sprintf(labelJumpDecidedBy, joinInts(j.DecidedBy)))
	}
	for _, m := range j.Missing {
		out = append(out, fmt.Sprintf(labelJumpMissing, m.Hop, m.Evidence, m.Action))
	}
	out = append(out, fmt.Sprintf(labelJumpScope, j.Scope))
	for i := range out {
		out[i] = Sanitize(out[i])
	}
	return out
}

// sameEnd reports whether two hop ends name the same release or line; the end
// of one hop is the start of the next.
func sameEnd(end, start string) bool { return end == start }

func joinInts(values []int) string {
	parts := make([]string, len(values))
	for i, v := range values {
		parts[i] = fmt.Sprint(v)
	}
	return strings.Join(parts, ", ")
}

// JumpLabels are the texts of a jump.
const (
	labelJumpBlocked   = "%s %s -> %s: BLOCKED on the stepwise path (hop %s decides); a direct skip was not evaluated"
	labelJumpAttention = "%s %s -> %s: ATTENTION on the stepwise path (hop %s lists changes to check); never a pass"
	labelJumpPass      = "%s %s -> %s: STEPWISE_PASS, every hop of the stepwise path is decided; not a statement about a direct jump"
	labelJumpUnknown   = "%s %s -> %s: UNKNOWN, at least one hop of the stepwise path is not decided; every hop is listed"
	labelJumpHop       = "  hop %d %s -> %s: %s"
	labelJumpVia       = "  path goes through %s"
	labelJumpDecidedBy = "  decided by hop %s"
	labelJumpMissing   = "  missing for hop %d: %s; next: %s"
	labelJumpScope     = "  scope: %s"
)
