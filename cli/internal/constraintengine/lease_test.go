// SPDX-License-Identifier: AGPL-3.0-only

package constraintengine

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

const pinnedCondition = `"condition":{"side":"proposed","component":"` + testComponent + `","factId":"` + testFact + `","boolValue":true}`

// leaseDocument is a fixed-version rule document: a forbid_predicate_value
// rule reviewed on 2026-01-01, with the evidence edited by mutate.
func leaseDocument(operator string, mutate func(evidence map[string]any)) []byte {
	extra := pinnedCondition
	if operator != "forbid_predicate_value" {
		extra = ""
	}
	document := testRuleDocument(operator, extra)
	evidence := document["rules"].([]any)[0].(map[string]any)["evidence"].(map[string]any)
	mutate(evidence)
	raw, _ := json.Marshal(document)
	return raw
}

func pinned(evidence map[string]any) {
	evidence["lease"] = "pinned"
	evidence["validUntil"] = "2036-01-01T00:00:00Z"
}

func TestPinnedLeaseStrictParse(t *testing.T) {
	registry := testRegistry(t)
	for _, test := range []struct {
		name     string
		operator string
		mutate   func(map[string]any)
		valid    bool
	}{
		{"absent lease", "forbid_predicate_value", func(map[string]any) {}, true},
		{"explicit time lease", "forbid_predicate_value", func(e map[string]any) { e["lease"] = "time" }, true},
		{"pinned", "forbid_predicate_value", pinned, true},
		{"pinned reviewed basis", "forbid_predicate_value", func(e map[string]any) { pinned(e); e["basis"] = "reviewed" }, true},
		{"pinned withdrawn", "forbid_predicate_value", func(e map[string]any) { pinned(e); e["state"] = "withdrawn" }, true},
		{"unknown lease", "forbid_predicate_value", func(e map[string]any) { e["lease"] = "forever" }, false},
		{"uppercase lease", "forbid_predicate_value", func(e map[string]any) { e["lease"] = "Pinned" }, false},
		{"empty lease", "forbid_predicate_value", func(e map[string]any) { e["lease"] = "" }, false},
		{"null lease", "forbid_predicate_value", func(e map[string]any) { e["lease"] = nil }, false},
		{"numeric lease", "forbid_predicate_value", func(e map[string]any) { e["lease"] = 1 }, false},
		{"pinned with the time lease window", "forbid_predicate_value", func(e map[string]any) { e["lease"] = "pinned" }, false},
		{"pinned one second short", "forbid_predicate_value", func(e map[string]any) { pinned(e); e["validUntil"] = "2035-12-31T23:59:59Z" }, false},
		{"pinned one second long", "forbid_predicate_value", func(e map[string]any) { pinned(e); e["validUntil"] = "2036-01-01T00:00:01Z" }, false},
		{"pinned mechanical", "forbid_predicate_value", func(e map[string]any) { pinned(e); mechanical(e) }, false},
		{"pinned operator not admitted", "forbid_target_version", pinned, false},
		{"pinned source without a commit URL", "forbid_predicate_value", func(e map[string]any) {
			pinned(e)
			e["sources"].([]any)[0].(map[string]any)["url"] = "https://github.com/example/controller/blob/main/docs/upgrade.md"
		}, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := ParseRuleSet(leaseDocument(test.operator, test.mutate), registry)
			if test.valid && err != nil {
				t.Fatalf("rejected a valid rule: %v", err)
			}
			if !test.valid && !errors.Is(err, ErrInvalid) {
				t.Fatalf("accepted an invalid rule: %v", err)
			}
		})
	}
}

func TestPinnedRuleReasonsEachClauseNegated(t *testing.T) {
	build := func(mutate func(rule map[string]any)) []byte {
		document := testRuleDocument("forbid_predicate_value", pinnedCondition)
		rule := document["rules"].([]any)[0].(map[string]any)
		pinned(rule["evidence"].(map[string]any))
		mutate(rule)
		raw, _ := json.Marshal(rule)
		return raw
	}
	source := func(rule map[string]any) map[string]any {
		return rule["evidence"].(map[string]any)["sources"].([]any)[0].(map[string]any)
	}
	reasons, err := PinnedRuleReasons(build(func(map[string]any) {}))
	if err != nil || len(reasons) != 0 {
		t.Fatalf("the base rule must be eligible: %v %v", reasons, err)
	}
	for _, test := range []struct {
		name   string
		mutate func(map[string]any)
		want   string
	}{
		{"withdrawn", func(r map[string]any) { r["evidence"].(map[string]any)["state"] = "withdrawn" }, PinnedReasonState},
		{"mechanical", func(r map[string]any) { mechanical(r["evidence"].(map[string]any)) }, PinnedReasonBasis},
		{"consensus", func(r map[string]any) { r["evidence"].(map[string]any)["basis"] = "consensus" }, PinnedReasonBasis},
		{"alias from", func(r map[string]any) { r["subject"].(map[string]any)["from"] = "latest" }, PinnedReasonSubject},
		{"empty to", func(r map[string]any) { r["subject"].(map[string]any)["to"] = "" }, PinnedReasonSubject},
		{"same versions", func(r map[string]any) { r["subject"].(map[string]any)["to"] = "1.0.0" }, PinnedReasonSubject},
		{"range", func(r map[string]any) { r["range"] = map[string]any{} }, PinnedReasonRange},
		{"require_component_version", func(r map[string]any) { r["operator"] = "require_component_version" }, PinnedReasonOperator},
		{"forbid_target_version", func(r map[string]any) { r["operator"] = "forbid_target_version" }, PinnedReasonOperator},
		{"severity", func(r map[string]any) { r["severity"] = "unsupported" }, PinnedReasonSeverity},
		{"no sources", func(r map[string]any) { r["evidence"].(map[string]any)["sources"] = []any{} }, PinnedReasonSources},
		{"short revision", func(r map[string]any) { source(r)["revision"] = "0123456" }, PinnedReasonSources},
		{"tag revision", func(r map[string]any) { source(r)["revision"] = "v1.2.3" }, PinnedReasonSources},
		{"short digest", func(r map[string]any) { source(r)["contentDigest"] = "sha256:abc" }, PinnedReasonSources},
		{"inverted span", func(r map[string]any) { source(r)["startLine"] = 20 }, PinnedReasonSources},
		{"foreign host", func(r map[string]any) { source(r)["url"] = "https://example.com/x/y/blob/" + testRevision + "/a.md" }, PinnedReasonHost},
		{"branch URL", func(r map[string]any) { source(r)["url"] = "https://github.com/example/controller/blob/main/a.md" }, PinnedReasonHost},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := PinnedRuleReasons(build(test.mutate))
			if err != nil {
				t.Fatal(err)
			}
			found := false
			for _, reason := range got {
				found = found || reason == test.want
			}
			if !found {
				t.Fatalf("reasons %v do not name %s", got, test.want)
			}
		})
	}
	if _, err := PinnedRuleReasons([]byte(`{"evidence":`)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("an unreadable rule must be an error, not eligible: %v", err)
	}
}

func evaluateLease(t *testing.T, mutate func(map[string]any), at string) Claim {
	t.Helper()
	registry := testRegistry(t)
	rules, err := ParseRuleSet(leaseDocument("forbid_predicate_value", mutate), registry)
	if err != nil {
		t.Fatal(err)
	}
	input := testInput(t, registry, `{"id":"`+testFact+`","state":"declared","boolValue":true}`, "2.0.0")
	now, err := time.Parse(time.RFC3339, at)
	if err != nil {
		t.Fatal(err)
	}
	report, err := Evaluate(input, rules, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := MarshalReport(report); err != nil {
		t.Fatalf("the report does not seal: %v", err)
	}
	return report.Claims[0]
}

// A pinned rule is not stale three years after its review; the same rule on
// the time lease is, at the same instant.
func TestPinnedRuleIsNeverStaleOnTime(t *testing.T) {
	at := "2029-01-01T00:00:00Z"
	timeLease := evaluateLease(t, func(map[string]any) {}, at)
	if timeLease.ReasonCode != "RULE_EVIDENCE_STALE" || timeLease.EvidenceFreshness != "stale" {
		t.Fatalf("the time lease must be stale: %+v", timeLease)
	}
	claim := evaluateLease(t, pinned, at)
	if claim.ReasonCode == "RULE_EVIDENCE_STALE" || claim.EvidenceFreshness != FreshnessPinned || claim.Status != "BLOCKED" {
		t.Fatalf("a pinned rule must keep deciding and report the pinned freshness: %+v", claim)
	}
	for _, later := range []string{"2035-12-31T23:59:59Z", "2040-01-01T00:00:00Z"} {
		if got := evaluateLease(t, pinned, later); got.ReasonCode == "RULE_EVIDENCE_STALE" || got.EvidenceFreshness != FreshnessPinned {
			t.Fatalf("a pinned rule went stale at %s: %+v", later, got)
		}
	}
}

// The clock check and the withdrawal still bind a pinned rule.
func TestPinnedRuleStillHonoursClockAndWithdrawal(t *testing.T) {
	if got := evaluateLease(t, pinned, "2025-12-31T00:00:00Z"); got.ReasonCode != "RULE_EVIDENCE_CLOCK_BEFORE_REVIEW" {
		t.Fatalf("a pinned rule evaluated before its review: %+v", got)
	}
	withdrawn := func(e map[string]any) { pinned(e); e["state"] = "withdrawn" }
	if got := evaluateLease(t, withdrawn, "2029-01-01T00:00:00Z"); got.ReasonCode != "RULE_EVIDENCE_WITHDRAWN" || got.EvidenceFreshness != "withdrawn" {
		t.Fatalf("a withdrawn pinned rule must answer withdrawn: %+v", got)
	}
}

// A rule without a lease marshals and evaluates exactly as before the field
// existed, and an explicit time lease behaves the same.
func TestAbsentLeaseIsByteIdentical(t *testing.T) {
	registry := testRegistry(t)
	rules, err := ParseRuleSet(leaseDocument("forbid_predicate_value", func(map[string]any) {}), registry)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(mustMarshal(t, rules.document)), `"lease"`) {
		t.Fatal("a rule without a lease re-marshals with a lease")
	}
	at := "2026-06-01T00:00:00Z"
	base := evaluateLease(t, func(map[string]any) {}, at)
	explicit := evaluateLease(t, func(e map[string]any) { e["lease"] = "time" }, at)
	if base.Status != explicit.Status || base.ReasonCode != explicit.ReasonCode || base.EvidenceFreshness != "current" || explicit.EvidenceFreshness != "current" {
		t.Fatalf("the explicit time lease changed the verdict: %+v vs %+v", explicit, base)
	}
}

// A signed report may carry the pinned freshness only with the pinned window.
func TestValidClaimsPinnedFreshness(t *testing.T) {
	claim := evaluateLease(t, pinned, "2029-01-01T00:00:00Z")
	if !validClaims([]Claim{claim}) {
		t.Fatalf("a pinned claim is refused: %+v", claim)
	}
	forged := claim
	forged.EvidenceValidUntil = "2036-01-02T00:00:00Z"
	if validClaims([]Claim{forged}) {
		t.Fatal("a pinned claim with another window was accepted")
	}
	renamed := claim
	renamed.EvidenceFreshness = "perpetual"
	if validClaims([]Claim{renamed}) {
		t.Fatal("an unknown freshness was accepted")
	}
}
