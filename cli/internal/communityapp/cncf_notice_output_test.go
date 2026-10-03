// SPDX-License-Identifier: AGPL-3.0-only

package communityapp

import (
	"bytes"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/constraintengine"
)

const noticeBeforeText = "take an etcd snapshot and verify that it restores before upgrading"

func noticeClaim(id, status, reason, nextAction string) constraintengine.Claim {
	return constraintengine.Claim{RuleID: id, Operator: constraintengine.OperatorNoticeOneWay, Status: status, ReasonCode: reason, NextAction: nextAction, EvidenceFreshness: "current"}
}

// TestNoticeHumanOutput: each NOTICE prints on its own lines with its
// reviewed text; notices are never collapsed with passes or counted as
// unreviewed; a notice that does not apply prints nothing; and no notice
// line says anything is safe.
func TestNoticeHumanOutput(t *testing.T) {
	pass := constraintengine.Claim{RuleID: "rule-pass", Operator: "forbid_predicate_value", Status: "PASS", ReasonCode: "FEATURE_REMOVED"}
	unreviewed := constraintengine.Claim{RuleID: "rule-other", Operator: "forbid_target_version", Status: "UNKNOWN", ReasonCode: reasonTransitionNotReviewed}
	claims := []constraintengine.Claim{
		noticeClaim("notice-applies", constraintengine.StatusNotice, constraintengine.ReasonOneWayTransition, noticeBeforeText),
		noticeClaim("notice-other-pair", "UNKNOWN", reasonTransitionNotReviewed, "no rule for declared pair"),
		noticeClaim("notice-stale", "UNKNOWN", "RULE_EVIDENCE_STALE", "select later declared rule source references with current evidence"),
		pass, unreviewed,
	}
	summary := summarizeClaims(claims, false)
	if summary.passes != 1 || summary.unreviewed != 1 || len(summary.shown) != 0 || len(summary.notices) != 3 || summary.allUnreviewed {
		t.Fatalf("summary=%+v", summary)
	}
	var out bytes.Buffer
	if err := writeNotices(&out, summary.notices); err != nil {
		t.Fatal(err)
	}
	if err := writeCollapsedNotes(&out, summary); err != nil {
		t.Fatal(err)
	}
	text := out.String()
	want := "cannot be rolled back: notice-applies\nbefore you upgrade: " + noticeBeforeText + "\nevidence basis: reviewed by maintainer\n" +
		"one-way notice not established: notice-stale (RULE_EVIDENCE_STALE)\nnext action: select later declared rule source references with current evidence\nevidence basis: reviewed by maintainer\n" +
		"1 rules for other transitions not applicable to this pair\n1 rules PASS (not listed; use --show-passes)\n"
	if text != want {
		t.Fatalf("output:\n%s\nwant:\n%s", text, want)
	}
	if strings.Contains(strings.ToLower(text), "safe") || strings.Contains(text, "notice-other-pair") {
		t.Fatalf("output:\n%s", text)
	}
	for _, line := range strings.Split(text, "\n") {
		if len(line) > 256 {
			t.Fatalf("line over 256 bytes: %q", line)
		}
	}
	// With only notices and unreviewed verdict claims, the transition is
	// still reported as unreviewed: notices do not count either way.
	onlyUnreviewed := summarizeClaims([]constraintengine.Claim{unreviewed, claims[0]}, false)
	if !onlyUnreviewed.allUnreviewed {
		t.Fatalf("summary=%+v", onlyUnreviewed)
	}
	// Only notices: nothing is unreviewed and nothing passes.
	onlyNotices := summarizeClaims(claims[:3], true)
	if onlyNotices.allUnreviewed || onlyNotices.passes != 0 || len(onlyNotices.shown) != 0 {
		t.Fatalf("summary=%+v", onlyNotices)
	}
}
