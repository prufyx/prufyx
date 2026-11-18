// SPDX-License-Identifier: AGPL-3.0-only

package knowledgegate

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/prufyx/prufyx/cli/internal/buildidentity"
	"github.com/prufyx/prufyx/cli/internal/cncfcheck"
	"github.com/prufyx/prufyx/cli/internal/constraintengine"
	"github.com/prufyx/prufyx/cli/internal/maintainer/evidencereattest"
)

// Pinned leases. A rule on the pinned lease (evidence.lease "pinned") is
// never stale on time, so the gate holds the lease to a narrow contract.
//
//   - Time -> pinned is a loosening change (KindPin) admitted only by a
//     verified human reattestation statement whose row for the rule says
//     lease "pinned" (evidencereattest checks the row, the sample, the cycle
//     cap and the byte-exact recomputation). An owner approval, a batch
//     approval or any other proof never admits it, and a rule is never
//     created pinned. The head rule must also meet the fixed-version
//     predicate (constraintengine.PinnedRuleReasons) with validUntil exactly
//     reviewedAt plus constraintengine.PinnedLeaseYears, and the oldest
//     supported client must be able to read the field.
//   - Pinned -> time and pinned -> withdrawn are tightening (KindUnpin,
//     KindWithdraw), admitted without proof like any tightening.
//   - Every other edit of a pinned rule is refused, all fields counted and
//     its dates included.
//   - Pinned rules are exempt from the ISO-week stagger cap only (see
//     staggerExempt): the stagger spreads end dates and a pinned rule has
//     none. They count against the daily and per-change loosening limits
//     like any loosening change.
//
// Refusals carry the reason code LeasePinnedNotEligible and the precise
// reasons after it.

// LeasePinnedNotEligible is the reason code of a refused pinned lease.
const LeasePinnedNotEligible = "LEASE_PINNED_NOT_ELIGIBLE"

// staggerExempt names the one rule that exempts a pinned rule from the
// stagger cap (the 15 percent per ISO week limit on end dates): the rule
// holds a pinned lease, which has no end date to spread. Nothing else about
// a pinned rule is exempt.
func staggerExempt(e *entry) bool {
	return e != nil && e.Evidence.Lease == constraintengine.LeasePinned
}

// entryRuleJSON is the rule object of an admitted pack entry.
func entryRuleJSON(e *entry) ([]byte, error) {
	var shape struct {
		Rule json.RawMessage `json:"rule"`
	}
	if err := json.Unmarshal(e.Raw, &shape); err != nil || len(shape.Rule) == 0 {
		return nil, fmt.Errorf("the entry has no rule object")
	}
	return shape.Rule, nil
}

// pinnedHeadReasons recomputes the fixed-version predicate and the fixed
// window of a head entry that holds a pinned lease; empty means it holds.
func pinnedHeadReasons(e *entry) []string {
	raw, err := entryRuleJSON(e)
	if err != nil {
		return []string{err.Error()}
	}
	found, err := constraintengine.PinnedRuleReasons(raw)
	if err != nil {
		return []string{"the rule cannot be read"}
	}
	// A pinned rule may be withdrawn: that is the tightening way out, so the
	// active-state clause is not asked of a withdrawn one.
	var reasons []string
	for _, reason := range found {
		if reason != constraintengine.PinnedReasonState || e.Evidence.State != "withdrawn" {
			reasons = append(reasons, reason)
		}
	}
	want, err := constraintengine.PinnedValidUntil(e.Evidence.ReviewedAt)
	if err != nil || e.Evidence.ValidUntil != want {
		reasons = append(reasons, "validUntil-is-not-reviewedAt-plus-10-years")
	}
	return reasons
}

func pinnedRefusal(reasons ...string) string {
	sorted := append([]string(nil), reasons...)
	sort.Strings(sorted)
	return LeasePinnedNotEligible + ": " + strings.Join(sorted, "; ")
}

// pinnedPre decides every change of a rule that touches a pinned lease. It
// reports whether it decided the change (admitted or refused it); a change
// that does not involve a pinned head goes on to the ordinary admission.
func pinnedPre(c *Change, stmt statementResult, opts Options) bool {
	if c.head == nil || c.head.Evidence.Lease != constraintengine.LeasePinned {
		return false
	}
	if c.base != nil && c.base.Evidence.Lease == constraintengine.LeasePinned {
		c.fail(pinnedRefusal("a pinned rule may change only by dropping its lease or being withdrawn; every other edit of it, its dates included, is refused"))
		return true
	}
	if c.base == nil {
		c.fail(pinnedRefusal("a rule is never created pinned; its lease is pinned by a signed human reattestation row"))
		return true
	}
	if reasons := pinnedHeadReasons(c.head); len(reasons) > 0 {
		c.fail(pinnedRefusal(reasons...))
		return true
	}
	if !stmt.OK {
		reason := "no verified reattestation statement"
		if stmt.Detail != "" {
			reason = "reattestation: " + stmt.Detail
		}
		c.fail(pinnedRefusal("a lease is pinned only by a signed human reattestation row", reason))
		return true
	}
	if stmt.Role != evidencereattest.RoleHuman {
		c.fail(pinnedRefusal("the statement is not a human statement"))
		return true
	}
	pinnedRow := false
	for _, row := range stmt.Statement.Rules {
		if row.RuleID == c.RuleID && row.Lease == constraintengine.LeasePinned {
			pinnedRow = true
		}
	}
	if !pinnedRow {
		c.fail(pinnedRefusal("the reattestation statement has no row that pins this rule"))
		return true
	}
	if err := pinnedClientFloor(opts); err != nil {
		c.fail(pinnedRefusal(err.Error()))
		return true
	}
	c.OK, c.Proof = true, ProofReattestation
	return true
}

// pinnedClientFloor refuses unless the oldest-supported-client pin of both the
// base and the head is at or above the version that reads evidence.lease: an
// older client rejects a pack that carries the field as an integrity failure,
// so no pinned lease is admitted while such a client is still supported.
func pinnedClientFloor(opts Options) error {
	for _, t := range []struct {
		name string
		tree Tree
	}{{"base", opts.Base}, {"head", opts.Head}} {
		raw, err := t.tree.Read(OldestClientPinPath, 1024)
		if err != nil {
			return fmt.Errorf("the %s's oldest supported client pin: %v", t.name, err)
		}
		version, err := pinVersion(raw)
		if err != nil {
			return fmt.Errorf("the %s's oldest supported client pin: %v", t.name, err)
		}
		if !buildidentity.AtLeast(version, cncfcheck.PinnedLeaseMinClientVersion) {
			return fmt.Errorf("the %s still supports client %s, which cannot read a pinned lease: none is admitted before the oldest supported client is %s or later", t.name, version, cncfcheck.PinnedLeaseMinClientVersion)
		}
	}
	return nil
}

// pinnedCheck is the per-pack check that every pinned rule of the head still
// meets the fixed-version predicate and its fixed window, changed or not.
// A pack without a pinned rule adds no check.
func (r *Report) pinnedCheck(spec PackSpec, h *loadedPack) {
	pinned := 0
	var bad []string
	for _, id := range h.Order {
		e := h.Entries[id]
		if e.Evidence.Lease != constraintengine.LeasePinned {
			continue
		}
		pinned++
		if reasons := pinnedHeadReasons(e); len(reasons) > 0 {
			bad = append(bad, fmt.Sprintf("%s: %s", id, strings.Join(reasons, ", ")))
		}
	}
	if pinned == 0 {
		return
	}
	if len(bad) == 0 {
		r.add("pinned/"+spec.Name, true, "%d pinned rules, all meet the fixed-version predicate", pinned)
		return
	}
	r.add("pinned/"+spec.Name, false, "%s%s", LeasePinnedNotEligible, listDetail(bad))
}
