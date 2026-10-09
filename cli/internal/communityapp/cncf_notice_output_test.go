// SPDX-License-Identifier: AGPL-3.0-only

package communityapp

import (
	"bytes"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/constraintengine"
	"github.com/prufyx/prufyx/cli/internal/extract/supersedeids"
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
	t.Parallel()
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
	if err := writeNotices(&out, summary.notices, false); err != nil {
		t.Fatal(err)
	}
	if err := writeCollapsedNotes(&out, summary); err != nil {
		t.Fatal(err)
	}
	text := out.String()
	want := "cannot be rolled back: notice-applies\nbefore you upgrade: " + noticeBeforeText + "\nevidence basis: reviewed by maintainer\n" +
		"one-way notice not established: notice-stale (RULE_EVIDENCE_STALE)\nnext action: select later declared rule source references with current evidence\nevidence basis: reviewed by maintainer\n" + noticeScopeLine + "\n" +
		"1 rule for another transition not applicable to this pair\n1 rule PASS (not listed; use --show-passes)\n"
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

// TestNoticeWritersOnEveryRoute: the native-resource writer, the external
// knowledge writer, the per-project claim writer and the component
// configuration writer all print a notice with the one-way wording, never
// as a plain status line, and a report holding only notices says that no
// rule decided the transition.
func TestNoticeWritersOnEveryRoute(t *testing.T) {
	t.Parallel()
	notice := noticeClaim("notice-applies", constraintengine.StatusNotice, constraintengine.ReasonOneWayTransition, noticeBeforeText)
	other := noticeClaim("notice-other-pair", "UNKNOWN", reasonTransitionNotReviewed, "no rule for declared pair")
	blocked := constraintengine.Claim{RuleID: "rule-blocked", Operator: "forbid_target_version", Status: "BLOCKED", ReasonCode: "FEATURE_REMOVED", NextAction: "plan a reviewed route"}
	wording := "cannot be rolled back: notice-applies\nbefore you upgrade: " + noticeBeforeText + "\n"
	check := func(name, text string, onlyNotices bool) {
		t.Helper()
		if !strings.Contains(text, wording) || strings.Contains(text, "NOTICE (") || strings.Contains(text, "notice-other-pair") || strings.Contains(strings.ToLower(text), "safe") {
			t.Fatalf("%s:\n%s", name, text)
		}
		if onlyNotices != strings.Contains(text, noVerdictLine) {
			t.Fatalf("%s: no-verdict line wrong:\n%s", name, text)
		}
	}
	for _, claims := range [][]constraintengine.Claim{{notice, other}, {blocked, notice, other}} {
		only := len(claims) == 2
		var native, external, headline, component bytes.Buffer
		if err := writeNativeClaims(&native, summarizeClaims(claims, false), claims); err != nil {
			t.Fatal(err)
		}
		check("native", native.String(), only)
		if err := writeExternalClaims(&external, claims); err != nil {
			t.Fatal(err)
		}
		check("external", external.String(), only)
		for _, claim := range claims {
			if _, err := writeClaimHeadline(&headline, claim); err != nil {
				t.Fatal(err)
			}
		}
		check("per-project", headline.String(), false)
		if err := writeKubernetesComponentResult(&component, claims, "inspect the declared sources"); err != nil {
			t.Fatal(err)
		}
		text := component.String()
		if only != strings.Contains(text, "scoped result: UNKNOWN (no reviewed rule for this input and transition)") || !strings.Contains(text, wording) || strings.Contains(text, "NOTICE (") {
			t.Fatalf("component config:\n%s", text)
		}
	}
	// A notice that does not apply prints nothing, so no evidence line either.
	var out bytes.Buffer
	if printed, err := writeClaimHeadline(&out, other); err != nil || printed || out.Len() != 0 {
		t.Fatalf("printed=%v err=%v out=%q", printed, err, out.String())
	}
}

// BOUNDARY-1 F3: in a mixed output, claims of rules whose release boundary the
// hop crosses are counted apart from "other transitions" and never described
// as not applicable.
func TestCollapsedNotesCountBoundaryClaimsApart(t *testing.T) {
	boundary := constraintengine.Claim{RuleID: supersedeids.ID("kubernetes.cronjob-v1beta1-removed.1-24-0-to-1-25-0"), Operator: "forbid_predicate_value", Status: "UNKNOWN", ReasonCode: constraintengine.ReasonReleaseBoundaryNotReviewed}
	other := constraintengine.Claim{RuleID: "rule-other", Operator: "forbid_target_version", Status: "UNKNOWN", ReasonCode: reasonTransitionNotReviewed}
	pass := constraintengine.Claim{RuleID: "rule-pass", Operator: "forbid_predicate_value", Status: "PASS", ReasonCode: "FEATURE_REMOVED"}
	summary := summarizeClaims([]constraintengine.Claim{boundary, other, pass}, false)
	if summary.boundary != 1 || summary.unreviewed != 1 || summary.passes != 1 || summary.allUnreviewed {
		t.Fatalf("summary=%+v", summary)
	}
	var out bytes.Buffer
	if err := writeCollapsedNotes(&out, summary); err != nil {
		t.Fatal(err)
	}
	want := "1 rule for another transition not applicable to this pair\n1 rule about a release boundary (1.25.0) this hop crosses is not reviewed for this hop\n1 rule PASS (not listed; use --show-passes)\n"
	if out.String() != want {
		t.Fatalf("output:\n%s\nwant:\n%s", out.String(), want)
	}
	onlyBoundary := summarizeClaims([]constraintengine.Claim{boundary}, false)
	if !onlyBoundary.allUnreviewed || onlyBoundary.unreviewed != 0 {
		t.Fatalf("summary=%+v", onlyBoundary)
	}
}
