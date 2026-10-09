// SPDX-License-Identifier: AGPL-3.0-only

package communityapp

import (
	"bytes"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/constraintengine"
	"github.com/prufyx/prufyx/cli/internal/projectcheck"
)

// TestProjectClaimsOutputNeverOverclaims: the human lines of a
// community-project report word an UNSUPPORTED claim as not verified and not
// shown to be broken, print a one-way notice with its scope, and never word
// anything as safe.
func TestProjectClaimsOutputNeverOverclaims(t *testing.T) {
	unsupported := constraintengine.Claim{RuleID: "addon.support", Operator: "require_component_version", Status: constraintengine.StatusUnsupported, ReasonCode: "ADDON_KUBERNETES_SUPPORT_RANGE", Severity: constraintengine.SeverityUnsupported, NextAction: "move to a release line whose documented support range includes the target", EvidenceFreshness: "current"}
	notice := constraintengine.Claim{RuleID: "addon.one-way", Operator: constraintengine.OperatorNoticeOneWay, Status: constraintengine.StatusNotice, ReasonCode: constraintengine.ReasonOneWayTransition, NextAction: "take a backup and verify that it restores before upgrading", EvidenceFreshness: "current"}
	unmatchedNotice := constraintengine.Claim{RuleID: "addon.other", Operator: constraintengine.OperatorNoticeOneWay, Status: "UNKNOWN", ReasonCode: "RULE_TRANSITION_NOT_REVIEWED", NextAction: "x", EvidenceFreshness: "current"}
	pass := constraintengine.Claim{RuleID: "addon.pass", Operator: "forbid_predicate_value", Status: "PASS", ReasonCode: "REVIEWED_SOURCE_CONSTRAINT", NextAction: "keep", EvidenceFreshness: "current"}
	for name, tc := range map[string]struct {
		claims  []constraintengine.Claim
		want    []string
		notWant []string
	}{
		"unsupported": {
			claims:  []constraintengine.Claim{pass, unsupported},
			want:    []string{"1 component combination is outside its documented support range (not verified, not shown to be broken)", "addon.support: UNSUPPORTED (ADDON_KUBERNETES_SUPPORT_RANGE)", "addon.pass: PASS"},
			notWant: []string{"BLOCKED", "no reviewed rule decided"},
		},
		"notice with a verdict": {
			claims:  []constraintengine.Claim{pass, notice},
			want:    []string{"cannot be rolled back: addon.one-way", "before you upgrade: take a backup", "evidence basis: reviewed by maintainer", noticeScopeLine},
			notWant: []string{"no reviewed rule decided", "addon.one-way: NOTICE"},
		},
		"stale notice prints no scope line": {
			claims:  []constraintengine.Claim{pass, constraintengine.Claim{RuleID: "addon.stale", Operator: constraintengine.OperatorNoticeOneWay, Status: "UNKNOWN", ReasonCode: "RULE_EVIDENCE_STALE", NextAction: "select later sources", EvidenceFreshness: "current"}},
			want:    []string{"one-way notice not established: addon.stale (RULE_EVIDENCE_STALE)", "evidence basis: reviewed by maintainer"},
			notWant: []string{noticeScopeLine},
		},
		"notice only": {
			claims:  []constraintengine.Claim{notice},
			want:    []string{"cannot be rolled back: addon.one-way", noticeScopeLine, noVerdictLine},
			notWant: []string{"PASS"},
		},
		"notice that does not apply prints nothing": {
			claims:  []constraintengine.Claim{pass, unmatchedNotice},
			want:    []string{"addon.pass: PASS"},
			notWant: []string{"addon.other", noticeScopeLine, "cannot be rolled back"},
		},
	} {
		t.Run(name, func(t *testing.T) {
			var out bytes.Buffer
			if err := writeProjectClaims(&out, tc.claims); err != nil {
				t.Fatal(err)
			}
			text := out.String()
			for _, want := range tc.want {
				if !strings.Contains(text, want) {
					t.Fatalf("missing %q in:\n%s", want, text)
				}
			}
			for _, notWant := range tc.notWant {
				if strings.Contains(text, notWant) {
					t.Fatalf("unexpected %q in:\n%s", notWant, text)
				}
			}
			if strings.Contains(strings.ToLower(text), "safe") {
				t.Fatalf("output words something as safe:\n%s", text)
			}
		})
	}
}

// TestNotEvaluatedSupportRangeIsListedWithItsAction: a support-range rule the
// native route left out stays visible and names the route that can decide it,
// never a flag that does not exist.
func TestNotEvaluatedSupportRangeIsListedWithItsAction(t *testing.T) {
	var out bytes.Buffer
	writeNotEvaluated(&out, []projectcheck.NotEvaluatedRule{{RuleID: "addon.support", ReasonCode: projectcheck.ReasonDependencyNotDeclarableOnRoute, NextAction: "not evaluated on this route; use `prufyx check batch` with the dependency declared, or check the cited source by hand"}})
	want := "addon.support: not evaluated on this route; use `prufyx check batch` with the dependency declared, or check the cited source by hand\n"
	if out.String() != want {
		t.Fatalf("output %q want %q", out.String(), want)
	}
	if strings.Contains(out.String(), "--") {
		t.Fatalf("names a flag: %q", out.String())
	}
}
