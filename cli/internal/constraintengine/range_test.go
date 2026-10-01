// SPDX-License-Identifier: AGPL-3.0-only

package constraintengine

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

// The pinned values are the contract identities issued before ranges existed.
// Exact-only rule documents must keep them, or every historical report stops
// replaying.
const (
	pinnedEngineContractDigest = "sha256:170350db4774ea8531d1d2ea03bbd4873930fa81418c3148dc300e40d5542293"
	pinnedScopeContractDigest  = "sha256:5cdd6f8a290e145ccb5f0a2bd5072ee05dd56ae0ce796000e42d31cee9c8b9a9"
)

// rangeRuleSpec describes one test rule anchored like a Kubernetes removal:
// anchor 1.24.0 -> 1.25.0, range from [1.24.0,1.25.0) to [1.25.0,1.26.0).
type rangeRuleSpec struct {
	id, from, to                          string
	fromGte, fromLt, toGte, toLt          string
	bases                                 [4]string
	sources                               [4]string
	fact                                  string
	operator, extra, validUntil, rawRange string
	noRange                               bool
	evidenceSourceID                      string
}

func defaultRangeSpec() rangeRuleSpec {
	return rangeRuleSpec{
		id: "range-rule", from: "1.24.0", to: "1.25.0",
		fromGte: "1.24.0", fromLt: "1.25.0", toGte: "1.25.0", toLt: "1.26.0",
		bases:   [4]string{BasisPreviousMinorLine, BasisRemovedInRelease, BasisRemovedInRelease, BasisReviewedThroughMinorLine},
		sources: [4]string{"upstream-doc", "upstream-doc", "upstream-doc", "upstream-doc"},
		fact:    scopeFactA, operator: "forbid_predicate_value", validUntil: activeUntil, evidenceSourceID: "upstream-doc",
	}
}

func (s rangeRuleSpec) rangeJSON() string {
	if s.rawRange != "" {
		return s.rawRange
	}
	names := []string{"from.gte", "from.lt", "to.gte", "to.lt"}
	bounds := make([]string, 0, 4)
	for i, name := range names {
		bounds = append(bounds, `{"bound":"`+name+`","basis":"`+s.bases[i]+`","sourceId":"`+s.sources[i]+`"}`)
	}
	return `{"from":{"gte":"` + s.fromGte + `","lt":"` + s.fromLt + `"},"to":{"gte":"` + s.toGte + `","lt":"` + s.toLt + `"},"bounds":[` + strings.Join(bounds, ",") + `]}`
}

func (s rangeRuleSpec) ruleJSON() string {
	extra := s.extra
	if s.operator == "forbid_predicate_value" && extra == "" {
		extra = forbidFact(scopeComponentA, s.fact)
	}
	if !s.noRange {
		extra = `,"range":` + s.rangeJSON() + extra
	}
	evidence := `"evidence":{"state":"active","reviewedAt":"2026-01-01T00:00:00Z","validUntil":"` + s.validUntil + `","sources":[{"id":"` + s.evidenceSourceID + `","url":"https://github.com/example/controller/blob/` + testRevision + `/docs/upgrade.md","revision":"` + testRevision + `","contentDigest":"` + testDigest + `","startLine":10,"endLine":12}]}`
	return `{"id":"` + s.id + `","operator":"` + s.operator + `","subject":{"component":"` + scopeComponentA + `","from":"` + s.from + `","to":"` + s.to + `"}` + extra + `,` + evidence + `,"reasonCode":"FEATURE_REMOVED","nextAction":"remove the reviewed feature before upgrade"}`
}

func rangeDocument(schema string, corpus bool, rules ...string) []byte {
	attestation := ""
	if corpus {
		attestation = `,"corpus":{"completeness":"` + CorpusAttestation + `","components":["` + scopeComponentA + `"]}`
	}
	return []byte(`{"schema":"` + schema + `","revision":"1","policyId":"community-local","policyDigest":"` + testDigest + `","rules":[` + strings.Join(rules, ",") + `]` + attestation + `}`)
}

func parseRanged(t *testing.T, corpus bool, rules ...string) RuleSet {
	t.Helper()
	parsed, err := ParseRuleSet(rangeDocument(RulesSchemaRanged, corpus, rules...), scopeRegistry(t))
	if err != nil {
		t.Fatalf("parse ranged rules: %v", err)
	}
	return parsed
}

func rangeInput(t *testing.T, from, to, fact string, withScope bool) Input {
	t.Helper()
	return scopeInput(t, scopeRegistry(t), withScope, componentInput{Component: scopeComponentA, From: from, To: to, Fact: fact})
}

func TestContractDigestsForExactDocumentsArePinned(t *testing.T) {
	if EngineContractDigest() != pinnedEngineContractDigest || ScopeContractDigest() != pinnedScopeContractDigest {
		t.Fatalf("exact-only contract identity changed: engine=%s scope=%s", EngineContractDigest(), ScopeContractDigest())
	}
	if EngineContractDigestRanged() == pinnedEngineContractDigest || ScopeContractDigestRanged() == pinnedScopeContractDigest || scopeDigestFor(EngineContractDigestRanged()) != ScopeContractDigestRanged() || scopeDigestFor(pinnedEngineContractDigest) != pinnedScopeContractDigest || scopeDigestFor("sha256:"+strings.Repeat("0", 64)) != "" {
		t.Fatal("ranged contract identity must be distinct and paired")
	}
	rules := testRules(t, testRegistry(t), "forbid_target_version", "")
	report, err := Evaluate(testInput(t, testRegistry(t), "", "2.0.0"), rules, testNow(t))
	if err != nil || report.EngineContractDigest != pinnedEngineContractDigest {
		t.Fatalf("exact document report digest=%s err=%v", report.EngineContractDigest, err)
	}
}

// TestRangeMatcherTruthTable covers every bound just inside and just outside,
// the crossing rule, and versions the engine never admits.
func TestRangeMatcherTruthTable(t *testing.T) {
	ranged := RuleTransition{Component: scopeComponentA, From: "1.24.0", To: "1.25.0", Range: &VersionRange{From: VersionBound{Gte: "1.24.0", Lt: "1.25.0"}, To: VersionBound{Gte: "1.25.0", Lt: "1.26.0"}}}
	exact := RuleTransition{Component: scopeComponentA, From: "1.24.0", To: "1.25.0"}
	cases := []struct {
		name, from, to string
		ranged, exact  MatchMode
	}{
		{"anchor", "1.24.0", "1.25.0", MatchAnchor, MatchAnchor},
		{"motivating patch pair", "1.24.17", "1.25.3", MatchRange, MatchNone},
		{"from.gte just inside", "1.24.0", "1.25.3", MatchRange, MatchNone},
		{"from.gte just outside", "1.23.99", "1.25.3", MatchNone, MatchNone},
		{"from.lt just inside", "1.24.99", "1.25.3", MatchRange, MatchNone},
		{"from.lt just outside", "1.25.0", "1.25.3", MatchNone, MatchNone},
		{"to.gte just inside", "1.24.17", "1.25.0", MatchRange, MatchNone},
		{"to.gte just outside", "1.24.17", "1.24.99", MatchNone, MatchNone},
		{"to.lt just inside", "1.24.17", "1.25.99", MatchRange, MatchNone},
		{"to.lt just outside", "1.24.17", "1.26.0", MatchNone, MatchNone},
		{"crossing semantics: same-line patch upgrade", "1.25.1", "1.25.4", MatchNone, MatchNone},
		{"equal versions", "1.24.5", "1.24.5", MatchNone, MatchNone},
		{"downgrade", "1.25.3", "1.24.17", MatchNone, MatchNone},
		{"multi-minor jump", "1.23.4", "1.26.2", MatchNone, MatchNone},
		{"major crossing", "0.24.0", "1.25.0", MatchNone, MatchNone},
		{"pre-release target", "1.24.17", "1.25.0-rc.1", MatchNone, MatchNone},
		{"pre-release origin", "1.24.0-alpha.1", "1.25.3", MatchNone, MatchNone},
		{"v prefix", "1.24.17", "v1.25.3", MatchNone, MatchNone},
		{"distribution suffix", "1.24.17", "1.25.3+k3s1", MatchNone, MatchNone},
		{"leading zero", "1.24.17", "1.25.03", MatchNone, MatchNone},
		{"uint32 overflow", "1.24.4294967296", "1.25.3", MatchNone, MatchNone},
		{"uint32 max patch", "1.24.4294967295", "1.25.3", MatchRange, MatchNone},
		{"empty", "", "", MatchNone, MatchNone},
	}
	for _, tc := range cases {
		if got := ranged.Match(tc.from, tc.to); got != tc.ranged {
			t.Errorf("%s: ranged %s -> %s = %q, want %q", tc.name, tc.from, tc.to, got, tc.ranged)
		}
		if got := exact.Match(tc.from, tc.to); got != tc.exact {
			t.Errorf("%s: exact %s -> %s = %q, want %q", tc.name, tc.from, tc.to, got, tc.exact)
		}
	}
	if !ranged.MatchesFrom("1.24.9") || ranged.MatchesFrom("1.25.0") || !ranged.MatchesTo("1.25.9") || ranged.MatchesTo("1.26.0") || exact.MatchesFrom("1.24.9") || !exact.MatchesFrom("1.24.0") {
		t.Fatal("single-side matching disagrees with the bounds")
	}
	if !ranged.IsAnchor("1.24.0", "1.25.0") || ranged.IsAnchor("1.24.17", "1.25.3") {
		t.Fatal("anchor identity must stay exact")
	}
}

// TestRangeClaimDisclosesAndDecides is the motivating case at claim level.
func TestRangeClaimDisclosesAndDecides(t *testing.T) {
	rules := parseRanged(t, false, defaultRangeSpec().ruleJSON())
	now := testNow(t)
	cases := []struct {
		name, from, to, fact, status, reason string
		disclosed                            bool
	}{
		{"range blocked", "1.24.17", "1.25.3", declaredFact(scopeFactA, true), "BLOCKED", "FEATURE_REMOVED", true},
		{"range pass", "1.24.17", "1.25.3", declaredFact(scopeFactA, false), "PASS", "FEATURE_REMOVED", true},
		{"range fact missing", "1.24.17", "1.25.3", `{"id":"` + scopeFactA + `","state":"missing"}`, "UNKNOWN", "RULE_FACT_UNAVAILABLE", true},
		{"anchor blocked", "1.24.0", "1.25.0", declaredFact(scopeFactA, true), "BLOCKED", "FEATURE_REMOVED", false},
		{"outside", "1.24.17", "1.26.0", declaredFact(scopeFactA, true), "UNKNOWN", "RULE_TRANSITION_NOT_REVIEWED", false},
		{"crossing", "1.25.1", "1.25.4", declaredFact(scopeFactA, true), "UNKNOWN", "RULE_TRANSITION_NOT_REVIEWED", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			input := rangeInput(t, tc.from, tc.to, tc.fact, false)
			report, err := Evaluate(input, rules, now)
			if err != nil {
				t.Fatal(err)
			}
			claim := report.Claims[0]
			if claim.Status != tc.status || claim.ReasonCode != tc.reason || (claim.SubjectMatch != nil) != tc.disclosed {
				t.Fatalf("claim=%+v", claim)
			}
			if report.Assessment != AssessmentUnknown || report.EngineContractDigest != EngineContractDigestRanged() {
				t.Fatalf("assessment=%s digest=%s", report.Assessment, report.EngineContractDigest)
			}
			if tc.disclosed && (claim.SubjectMatch.Mode != "range" || claim.SubjectMatch.AnchorFrom != "1.24.0" || claim.SubjectMatch.AnchorTo != "1.25.0" || !strings.Contains(claim.NextAction, "matched by reviewed range; anchor pair 1.24.0 -> 1.25.0")) {
				t.Fatalf("disclosure=%+v action=%q", claim.SubjectMatch, claim.NextAction)
			}
			if tc.reason == "RULE_TRANSITION_NOT_REVIEWED" && !strings.Contains(claim.NextAction, "reviewed range") {
				t.Fatalf("out-of-range action=%q", claim.NextAction)
			}
			if len(claim.NextAction) > maxStringBytes {
				t.Fatal("next action exceeds public bound")
			}
			raw, err := MarshalReport(report)
			if err != nil {
				t.Fatal(err)
			}
			if tc.disclosed != strings.Contains(string(raw), `"subjectMatch"`) {
				t.Fatalf("serialized disclosure mismatch: %s", raw)
			}
			if _, err := Replay(input, rules, now, raw); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestRangeNextActionStaysBounded(t *testing.T) {
	spec := defaultRangeSpec()
	long := strings.Repeat("x", maxStringBytes-10)
	raw := strings.Replace(spec.ruleJSON(), "remove the reviewed feature before upgrade", long, 1)
	rules := parseRanged(t, false, raw)
	report, err := Evaluate(rangeInput(t, "1.24.17", "1.25.3", declaredFact(scopeFactA, false), false), rules, testNow(t))
	if err != nil {
		t.Fatal(err)
	}
	if claim := report.Claims[0]; claim.NextAction != long || claim.SubjectMatch == nil {
		t.Fatalf("overlong disclosure must fall back to the rule text and keep subjectMatch: %+v", claim)
	}
	if _, err := MarshalReport(report); err != nil {
		t.Fatal(err)
	}
}

// equalPairRange admits the equal pair 1.25.0 -> 1.25.0 (from [1.25.0,1.25.1),
// to [1.25.0,1.26.0)). Every other guard accepts it; only the strict-upgrade
// guard refuses it.
func equalPairRange() string {
	spec := defaultRangeSpec()
	spec.from, spec.to = "1.25.0", "1.25.3"
	spec.fromGte, spec.fromLt, spec.toGte, spec.toLt = "1.25.0", "1.25.1", "1.25.0", "1.26.0"
	spec.bases = [4]string{BasisAnchorOnly, BasisAnchorOnly, BasisTargetSeries, BasisTargetSeries}
	return spec.ruleJSON()
}

// downgradeRange admits only the downgrade 1.26.0 -> 1.25.0. Only the
// strict-upgrade guard refuses it.
func downgradeRange() string {
	spec := defaultRangeSpec()
	spec.from, spec.to = "1.26.0", "1.25.0"
	spec.fromGte, spec.fromLt, spec.toGte, spec.toLt = "1.26.0", "1.26.1", "1.25.0", "1.25.1"
	spec.bases = [4]string{BasisAnchorOnly, BasisAnchorOnly, BasisAnchorOnly, BasisAnchorOnly}
	return spec.ruleJSON()
}

func rangeRejected(t *testing.T, raw []byte) {
	t.Helper()
	if _, err := ParseRuleSet(raw, scopeRegistry(t)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("accepted invalid range document (err=%v): %s", err, raw)
	}
}

// TestRangeParserAdversarial is the fail-closed corpus: every document here
// must be refused with ErrInvalid.
func TestRangeParserAdversarial(t *testing.T) {
	mutate := func(change func(*rangeRuleSpec)) string {
		spec := defaultRangeSpec()
		change(&spec)
		return spec.ruleJSON()
	}
	good := defaultRangeSpec().ruleJSON()
	cases := map[string][]byte{
		"range in exact-only schema":    rangeDocument(RulesSchema, false, good),
		"ranged schema without a range": rangeDocument(RulesSchemaRanged, false, mutate(func(s *rangeRuleSpec) { s.noRange = true })),
		"missing to.lt (open bound)": rangeDocument(RulesSchemaRanged, false, mutate(func(s *rangeRuleSpec) {
			s.rawRange = `{"from":{"gte":"1.24.0","lt":"1.25.0"},"to":{"gte":"1.25.0"},"bounds":[]}`
		})),
		"empty to.lt (open bound)": rangeDocument(RulesSchemaRanged, false, mutate(func(s *rangeRuleSpec) { s.toLt = "" })),
		"null bound": rangeDocument(RulesSchemaRanged, false, mutate(func(s *rangeRuleSpec) {
			s.rawRange = `{"from":{"gte":"1.24.0","lt":"1.25.0"},"to":{"gte":"1.25.0","lt":null},"bounds":[]}`
		})),
		"missing to side":                     rangeDocument(RulesSchemaRanged, false, mutate(func(s *rangeRuleSpec) { s.rawRange = `{"from":{"gte":"1.24.0","lt":"1.25.0"},"bounds":[]}` })),
		"extra range key":                     rangeDocument(RulesSchemaRanged, false, strings.Replace(good, `"bounds":`, `"open":true,"bounds":`, 1)),
		"extra bound key":                     rangeDocument(RulesSchemaRanged, false, strings.Replace(good, `"to":{"gte":"1.25.0","lt":"1.26.0"}`, `"to":{"gte":"1.25.0","lt":"1.26.0","lte":"1.27.0"}`, 1)),
		"case-variant range key":              rangeDocument(RulesSchemaRanged, false, strings.Replace(good, `"range":`, `"Range":`, 1)),
		"case-variant side key":               rangeDocument(RulesSchemaRanged, false, strings.Replace(good, `"from":{"gte"`, `"FROM":{"gte"`, 1)),
		"numeric bound":                       rangeDocument(RulesSchemaRanged, false, strings.Replace(good, `"lt":"1.26.0"`, `"lt":1.26`, 1)),
		"pre-release bound":                   rangeDocument(RulesSchemaRanged, false, mutate(func(s *rangeRuleSpec) { s.toLt = "1.26.0-rc.1" })),
		"v-prefixed bound":                    rangeDocument(RulesSchemaRanged, false, mutate(func(s *rangeRuleSpec) { s.fromGte = "v1.24.0" })),
		"leading-zero bound":                  rangeDocument(RulesSchemaRanged, false, mutate(func(s *rangeRuleSpec) { s.toGte, s.fromLt = "1.25.00", "1.25.00" })),
		"anchor outside from range":           rangeDocument(RulesSchemaRanged, false, mutate(func(s *rangeRuleSpec) { s.from = "1.23.9" })),
		"anchor outside to range":             rangeDocument(RulesSchemaRanged, false, mutate(func(s *rangeRuleSpec) { s.to = "1.26.0" })),
		"inverted from interval":              rangeDocument(RulesSchemaRanged, false, mutate(func(s *rangeRuleSpec) { s.fromGte = "1.25.0" })),
		"empty to interval":                   rangeDocument(RulesSchemaRanged, false, mutate(func(s *rangeRuleSpec) { s.toLt = "1.25.0" })),
		"over-wide to range":                  rangeDocument(RulesSchemaRanged, false, mutate(func(s *rangeRuleSpec) { s.toLt = "1.27.0" })),
		"over-wide from range":                rangeDocument(RulesSchemaRanged, false, mutate(func(s *rangeRuleSpec) { s.from, s.fromGte, s.bases[0] = "1.23.0", "1.23.0", BasisAnchorOnly })),
		"to range crosses a major":            rangeDocument(RulesSchemaRanged, false, mutate(func(s *rangeRuleSpec) { s.toLt = "2.0.0" })),
		"three bound citations":               rangeDocument(RulesSchemaRanged, false, strings.Replace(good, `,{"bound":"to.lt","basis":"REVIEWED_THROUGH_MINOR_LINE","sourceId":"upstream-doc"}`, ``, 1)),
		"bound citations out of order":        rangeDocument(RulesSchemaRanged, false, strings.Replace(strings.Replace(good, `"bound":"from.gte"`, `"bound":"TMP"`, 1), `"bound":"from.lt"`, `"bound":"from.gte"`, 1)),
		"unknown basis":                       rangeDocument(RulesSchemaRanged, false, mutate(func(s *rangeRuleSpec) { s.bases[3] = "LATEST_RELEASE" })),
		"basis on the wrong bound":            rangeDocument(RulesSchemaRanged, false, mutate(func(s *rangeRuleSpec) { s.bases[0] = BasisReviewedThroughMinorLine })),
		"basis cites a missing source":        rangeDocument(RulesSchemaRanged, false, mutate(func(s *rangeRuleSpec) { s.sources[2] = "other-doc" })),
		"removal basis on one side only":      rangeDocument(RulesSchemaRanged, false, mutate(func(s *rangeRuleSpec) { s.bases[0], s.bases[1], s.fromLt = BasisAnchorOnly, BasisAnchorOnly, "1.24.1" })),
		"removal release not a minor start":   rangeDocument(RulesSchemaRanged, false, mutate(func(s *rangeRuleSpec) { s.fromLt, s.toGte, s.to = "1.25.1", "1.25.1", "1.25.1" })),
		"previous minor line misplaced":       rangeDocument(RulesSchemaRanged, false, mutate(func(s *rangeRuleSpec) { s.fromGte, s.from = "1.24.5", "1.24.5" })),
		"review horizon not a minor start":    rangeDocument(RulesSchemaRanged, false, mutate(func(s *rangeRuleSpec) { s.toLt = "1.25.9" })),
		"anchor-only bound wider than anchor": rangeDocument(RulesSchemaRanged, false, mutate(func(s *rangeRuleSpec) { s.bases[0] = BasisAnchorOnly; s.from = "1.24.3" })),
		"equal versions":                      rangeDocument(RulesSchemaRanged, false, equalPairRange()),
		"downgrade range":                     rangeDocument(RulesSchemaRanged, false, downgradeRange()),
		"intermediate inside from range": rangeDocument(RulesSchemaRanged, false, mutate(func(s *rangeRuleSpec) {
			s.operator, s.extra = "require_intermediate_version", `,"intermediate":"1.24.5"`
			s.from, s.to, s.fromGte, s.fromLt, s.toGte, s.toLt = "1.24.0", "1.26.0", "1.24.0", "1.25.0", "1.26.0", "1.27.0"
			s.bases = [4]string{BasisUpgradeFromSeries, BasisUpgradeFromSeries, BasisTargetSeries, BasisTargetSeries}
		})),
		"overlapping duplicate range rules": rangeDocument(RulesSchemaRanged, false, good, mutate(func(s *rangeRuleSpec) { s.id = "range-rule-twin" })),
		"exact duplicate inside a range": rangeDocument(RulesSchemaRanged, false, good, mutate(func(s *rangeRuleSpec) {
			s.id, s.noRange, s.from, s.to = "range-rule-exact", true, "1.24.3", "1.25.7"
		})),
		"contradictory overlapping predicates": rangeDocument(RulesSchemaRanged, false, good, strings.Replace(mutate(func(s *rangeRuleSpec) {
			s.id, s.from, s.to = "range-rule-inverse", "1.24.2", "1.25.2"
			s.bases[0] = BasisAnchorOnly
			s.fromGte = "1.24.2"
		}), `"boolValue":true}`, `"boolValue":false}`, 1)),
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) { rangeRejected(t, raw) })
	}
}

// TestRangeParserAcceptsDistinctNeighbours shows the lint is not a blanket
// ban: adjacent half-open ranges and different facts coexist.
func TestRangeParserAcceptsDistinctNeighbours(t *testing.T) {
	next := defaultRangeSpec()
	next.id, next.from, next.to, next.fromGte, next.fromLt, next.toGte, next.toLt = "range-rule-next", "1.25.0", "1.26.0", "1.25.0", "1.26.0", "1.26.0", "1.27.0"
	other := defaultRangeSpec()
	other.id, other.fact = "range-rule-other-fact", scopeFactB
	other.extra = forbidFact(scopeComponentB, scopeFactB)
	exactElsewhere := defaultRangeSpec()
	exactElsewhere.id, exactElsewhere.noRange, exactElsewhere.from, exactElsewhere.to = "range-rule-exact-elsewhere", true, "1.23.0", "1.24.0"
	for name, rules := range map[string][]string{
		"adjacent ranges":                {defaultRangeSpec().ruleJSON(), next.ruleJSON()},
		"different facts":                {defaultRangeSpec().ruleJSON(), other.ruleJSON()},
		"exact rule outside the range":   {defaultRangeSpec().ruleJSON(), exactElsewhere.ruleJSON()},
		"exact rule at the anchor alone": {defaultRangeSpec().ruleJSON()},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseRuleSet(rangeDocument(RulesSchemaRanged, false, rules...), scopeRegistry(t)); err != nil {
				t.Fatalf("rejected: %v", err)
			}
		})
	}
	// A reviewed intermediate strictly between the ranges is admitted.
	gap := defaultRangeSpec()
	gap.operator, gap.extra = "require_intermediate_version", `,"intermediate":"1.25.3"`
	gap.from, gap.to, gap.fromGte, gap.fromLt, gap.toGte, gap.toLt = "1.24.0", "1.26.0", "1.24.0", "1.25.0", "1.26.0", "1.27.0"
	gap.bases = [4]string{BasisUpgradeFromSeries, BasisUpgradeFromSeries, BasisTargetSeries, BasisTargetSeries}
	if _, err := ParseRuleSet(rangeDocument(RulesSchemaRanged, false, gap.ruleJSON()), scopeRegistry(t)); err != nil {
		t.Fatalf("intermediate between ranges rejected: %v", err)
	}
}

// TestRangeScopeCompletenessStaysAnchorOnly: a range-matched transition that
// would otherwise be scope-complete stays UNKNOWN; a range blocker still
// blocks; the anchor pair still reaches SCOPE_COMPLETE_PASS.
func TestRangeScopeCompletenessStaysAnchorOnly(t *testing.T) {
	rules := parseRanged(t, true, defaultRangeSpec().ruleJSON())
	now := testNow(t)
	cases := []struct {
		name, from, to string
		value          bool
		assessment     string
		unresolved     string
	}{
		{"range pass stays unknown", "1.24.17", "1.25.3", false, AssessmentUnknown, unresolvedTransitionNotAnchor},
		{"range blocker blocks", "1.24.17", "1.25.3", true, AssessmentBlocked, unresolvedTransitionNotAnchor},
		{"anchor pass is scope complete", "1.24.0", "1.25.0", false, AssessmentScopeCompletePass, ""},
		{"outside stays unknown", "1.24.17", "1.26.0", false, AssessmentUnknown, unresolvedNoApplicableRule},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			input := rangeInput(t, tc.from, tc.to, declaredFact(scopeFactA, tc.value), true)
			report, err := Evaluate(input, rules, now)
			if err != nil {
				t.Fatal(err)
			}
			if report.Assessment != tc.assessment || report.ScopeCompleteness == nil || report.ScopeCompleteness.UnresolvedReason != tc.unresolved || report.ScopeCompleteness.ContractDigest != ScopeContractDigestRanged() {
				t.Fatalf("assessment=%s scope=%+v", report.Assessment, report.ScopeCompleteness)
			}
			raw, err := MarshalReport(report)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := Replay(input, rules, now, raw); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// TestForgedRangeReportsAreRefused: a report that drops its range disclosure
// to claim completeness, or carries a disclosure under the exact contract,
// or pairs the wrong scope contract, never publishes.
func TestForgedRangeReportsAreRefused(t *testing.T) {
	rules := parseRanged(t, true, defaultRangeSpec().ruleJSON())
	report, err := Evaluate(rangeInput(t, "1.24.17", "1.25.3", declaredFact(scopeFactA, false), true), rules, testNow(t))
	if err != nil {
		t.Fatal(err)
	}
	forged := report
	forged.Claims = append([]Claim(nil), report.Claims...)
	forged.Claims[0].SubjectMatch = nil
	forged.Assessment = AssessmentScopeCompletePass
	scope := *report.ScopeCompleteness
	scope.Resolved, scope.UnresolvedReason = true, ""
	forged.ScopeCompleteness = &scope
	forged.Omissions = requiredOmissions(AssessmentScopeCompletePass)
	if _, err := MarshalReport(forged); !errors.Is(err, ErrIntegrity) {
		t.Fatal("sealed report accepted a dropped range disclosure")
	}
	// Re-sealed under the exact-only contract, a range disclosure is refused.
	exactContract := report
	exactContract.EngineContractDigest = EngineContractDigest()
	exactContract.ScopeCompleteness = &ScopeCompleteness{}
	*exactContract.ScopeCompleteness = *report.ScopeCompleteness
	exactContract.ScopeCompleteness.ContractDigest = ScopeContractDigest()
	if _, err := MarshalReport(issueReport(exactContract)); !errors.Is(err, ErrIntegrity) {
		t.Fatal("exact contract carried a range disclosure")
	}
	// Re-sealed with a scope contract that does not pair with the engine one.
	mismatched := report
	mismatched.ScopeCompleteness = &ScopeCompleteness{}
	*mismatched.ScopeCompleteness = *report.ScopeCompleteness
	mismatched.ScopeCompleteness.ContractDigest = ScopeContractDigest()
	if _, err := MarshalReport(issueReport(mismatched)); !errors.Is(err, ErrIntegrity) {
		t.Fatal("scope contract did not pair with the engine contract")
	}
	// Re-sealed with an unknown engine contract.
	unknown := report
	unknown.EngineContractDigest = "sha256:" + strings.Repeat("1", 64)
	if _, err := MarshalReport(issueReport(unknown)); !errors.Is(err, ErrIntegrity) {
		t.Fatal("unknown engine contract accepted")
	}
	// The untouched report still publishes.
	if _, err := MarshalReport(report); err != nil {
		t.Fatal(err)
	}
}

// TestRangeApplicabilityIgnoresTheClock: the matcher never reads time. A
// stale range rule is UNDETERMINED in range and NOT_APPLICABLE outside it,
// and applicability does not move as the clock sweeps across validUntil.
func TestRangeApplicabilityIgnoresTheClock(t *testing.T) {
	spec := defaultRangeSpec()
	spec.validUntil = expiredUntil
	rules := parseRanged(t, true, spec.ruleJSON())
	inRange := rangeInput(t, "1.24.17", "1.25.3", declaredFact(scopeFactA, false), true)
	outside := rangeInput(t, "1.24.17", "1.26.0", declaredFact(scopeFactA, false), true)
	for _, now := range []time.Time{time.Date(2026, 4, 30, 0, 0, 0, 0, time.UTC), time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC), testNow(t), time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)} {
		outsideReport, err := Evaluate(outside, rules, now)
		if err != nil {
			t.Fatal(err)
		}
		skipped := outsideReport.ScopeCompleteness.Components[0].NotEvaluated
		if len(skipped) != 1 || skipped[0].Applicability != ApplicabilityNotApplicable || skipped[0].ReasonCode != "RULE_TRANSITION_NOT_REVIEWED" {
			t.Fatalf("outside at %s: %+v", now, skipped)
		}
		inRangeReport, err := Evaluate(inRange, rules, now)
		if err != nil {
			t.Fatal(err)
		}
		component := inRangeReport.ScopeCompleteness.Components[0]
		if len(component.EvaluatedRuleIDs)+len(component.NotEvaluated) != 1 || len(component.NotEvaluated) == 1 && component.NotEvaluated[0].Applicability != ApplicabilityUndetermined {
			t.Fatalf("in range at %s: %+v", now, component)
		}
		if inRangeReport.Assessment == AssessmentScopeCompletePass {
			t.Fatalf("range transition reached completeness at %s", now)
		}
	}
	report, err := Evaluate(inRange, rules, testNow(t))
	if err != nil {
		t.Fatal(err)
	}
	if report.Claims[0].ReasonCode != "RULE_EVIDENCE_STALE" || report.Assessment != AssessmentUnknown || report.ScopeCompleteness.Components[0].NotEvaluated[0].Applicability != ApplicabilityUndetermined {
		t.Fatalf("stale in-range report=%+v", report)
	}
	report, err = Evaluate(outside, rules, testNow(t))
	if err != nil {
		t.Fatal(err)
	}
	skipped := report.ScopeCompleteness.Components[0].NotEvaluated[0]
	if skipped.Applicability != ApplicabilityNotApplicable || skipped.ReasonCode != "RULE_TRANSITION_NOT_REVIEWED" {
		t.Fatalf("stale out-of-range skipped=%+v", skipped)
	}
}

// TestWideningIsMonotone: for every transition, the widened rule yields the
// identical claim wherever the anchor-only rule matched, newly matches only
// transitions inside its range, and yields RULE_TRANSITION_NOT_REVIEWED for
// everything else. It never turns a BLOCKED into a PASS.
func TestWideningIsMonotone(t *testing.T) {
	exactSpec := defaultRangeSpec()
	exactSpec.noRange = true
	exactRules, err := ParseRuleSet(rangeDocument(RulesSchema, false, exactSpec.ruleJSON()), scopeRegistry(t))
	if err != nil {
		t.Fatal(err)
	}
	wideRules := parseRanged(t, false, defaultRangeSpec().ruleJSON())
	rng := VersionRange{From: VersionBound{Gte: "1.24.0", Lt: "1.25.0"}, To: VersionBound{Gte: "1.25.0", Lt: "1.26.0"}}
	versions := []string{"1.22.9", "1.23.0", "1.23.99", "1.24.0", "1.24.1", "1.24.17", "1.24.99", "1.25.0", "1.25.1", "1.25.3", "1.25.99", "1.26.0", "1.26.1", "2.25.0"}
	for _, from := range versions {
		for _, to := range versions {
			if from == to {
				continue
			}
			for _, value := range []bool{false, true} {
				input := rangeInput(t, from, to, declaredFact(scopeFactA, value), false)
				exact, err := Evaluate(input, exactRules, testNow(t))
				if err != nil {
					t.Fatal(err)
				}
				wide, err := Evaluate(input, wideRules, testNow(t))
				if err != nil {
					t.Fatal(err)
				}
				e, w := exact.Claims[0], wide.Claims[0]
				inRange := rng.From.Contains(from) && rng.To.Contains(to)
				switch {
				case e.ReasonCode != "RULE_TRANSITION_NOT_REVIEWED":
					// Anchor: identical verdict, no disclosure.
					if w.Status != e.Status || w.ReasonCode != e.ReasonCode || w.NextAction != e.NextAction || w.SubjectMatch != nil {
						t.Fatalf("%s -> %s: anchor claim changed: %+v vs %+v", from, to, e, w)
					}
				case inRange:
					if w.SubjectMatch == nil || w.Status == "UNKNOWN" || (value && w.Status != "BLOCKED") || (!value && w.Status != "PASS") {
						t.Fatalf("%s -> %s: in-range claim=%+v", from, to, w)
					}
				default:
					if w.Status != "UNKNOWN" || w.ReasonCode != "RULE_TRANSITION_NOT_REVIEWED" || w.SubjectMatch != nil {
						t.Fatalf("%s -> %s: out-of-range claim=%+v", from, to, w)
					}
				}
			}
		}
	}
}

// TestRangeRuleDigestCoversTheRange: a rule's digest changes with its range,
// and an exact rule's digest does not depend on the new field.
func TestRangeRuleDigestCoversTheRange(t *testing.T) {
	exactSpec := defaultRangeSpec()
	exactSpec.noRange = true
	exactRules, err := ParseRuleSet(rangeDocument(RulesSchema, false, exactSpec.ruleJSON()), scopeRegistry(t))
	if err != nil {
		t.Fatal(err)
	}
	var decoded rule
	if err := json.Unmarshal([]byte(exactSpec.ruleJSON()), &decoded); err != nil {
		t.Fatal(err)
	}
	marshalled, _ := json.Marshal(decoded)
	if strings.Contains(string(marshalled), `"range"`) {
		t.Fatal("absent range must not serialize")
	}
	wide := parseRanged(t, false, defaultRangeSpec().ruleJSON())
	if digestJSON(exactRules.document.Rules[0]) == digestJSON(wide.document.Rules[0]) {
		t.Fatal("range not bound into the rule digest")
	}
	narrower := defaultRangeSpec()
	narrower.toLt, narrower.bases[3] = "1.25.1", BasisAnchorOnly
	narrowRules := parseRanged(t, false, narrower.ruleJSON())
	if digestJSON(narrowRules.document.Rules[0]) == digestJSON(wide.document.Rules[0]) {
		t.Fatal("different ranges share a rule digest")
	}
}

func TestRangeSchemaSelection(t *testing.T) {
	exactSpec := defaultRangeSpec()
	exactSpec.noRange = true
	for name, tc := range map[string]struct {
		rules []string
		want  string
	}{
		"exact only": {[]string{exactSpec.ruleJSON()}, RulesSchema},
		"one range":  {[]string{exactSpec.ruleJSON(), strings.Replace(defaultRangeSpec().ruleJSON(), `"id":"range-rule"`, `"id":"range-rule-b"`, 1)}, RulesSchemaRanged},
		"empty":      {nil, RulesSchema},
	} {
		raws := make([]json.RawMessage, 0, len(tc.rules))
		for _, raw := range tc.rules {
			raws = append(raws, json.RawMessage(raw))
		}
		got, err := RulesSchemaFor(raws)
		if err != nil || got != tc.want {
			t.Fatalf("%s: schema=%s err=%v", name, got, err)
		}
	}
	if _, err := RulesSchemaFor([]json.RawMessage{json.RawMessage(`[`)}); err == nil {
		t.Fatal("malformed rule accepted")
	}
	subject, err := RuleTransitionOf([]byte(defaultRangeSpec().ruleJSON()))
	if err != nil || subject.Range == nil || subject.Match("1.24.17", "1.25.3") != MatchRange {
		t.Fatalf("subject=%+v err=%v", subject, err)
	}
}
