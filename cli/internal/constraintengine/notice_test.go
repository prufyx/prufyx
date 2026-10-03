// SPDX-License-Identifier: AGPL-3.0-only

package constraintengine

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"reflect"
	"sort"
	"strings"
	"testing"
)

const (
	noticeBefore                  = "take an etcd snapshot and verify that it restores before upgrading"
	pinnedEngineContractDigestSet = "sha256:0031ceb6f769f52c67e45345eef2791607f32146ec70617030126f62b2eb5311"
)

// noticeRule renders a notice_one_way rule over component.
func noticeRule(id, component, from, to, state, validUntil, extra string) string {
	evidence := `"evidence":{"state":"` + state + `","reviewedAt":"2026-01-01T00:00:00Z","validUntil":"` + validUntil + `","sources":[{"id":"upstream-doc","url":"https://github.com/example/controller/blob/` + testRevision + `/docs/upgrade.md","revision":"` + testRevision + `","contentDigest":"` + testDigest + `","startLine":10,"endLine":12}]}`
	return `{"id":"` + id + `","operator":"` + OperatorNoticeOneWay + `","subject":{"component":"` + component + `","from":"` + from + `","to":"` + to + `"}` + extra + `,` + evidence + `,"reasonCode":"` + ReasonOneWayTransition + `","nextAction":"` + noticeBefore + `"}`
}

func ruleDocumentJSON(schema string, corpus []string, rules ...string) []byte {
	attestation := ""
	if len(corpus) > 0 {
		quoted := make([]string, 0, len(corpus))
		for _, component := range corpus {
			quoted = append(quoted, `"`+component+`"`)
		}
		attestation = `,"corpus":{"completeness":"` + CorpusAttestation + `","components":[` + strings.Join(quoted, ",") + `]}`
	}
	return []byte(`{"schema":"` + schema + `","revision":"1","policyId":"community-local","policyDigest":"` + testDigest + `","rules":[` + strings.Join(rules, ",") + `]` + attestation + `}`)
}

func parseNotice(t *testing.T, corpus []string, rules ...string) RuleSet {
	t.Helper()
	parsed, err := ParseRuleSet(ruleDocumentJSON(RulesSchemaNotice, corpus, rules...), scopeRegistry(t))
	if err != nil {
		t.Fatalf("parse notice rules: %v", err)
	}
	return parsed
}

func appliesWhenA(value bool) string {
	return `,"appliesWhen":[{"side":"proposed","component":"` + scopeComponentA + `","factId":"` + scopeFactA + `","boolValue":` + boolToken(value) + `}]`
}

func rangedNoticeRule() string {
	spec := defaultRangeSpec()
	spec.operator, spec.id = OperatorNoticeOneWay, "notice-ranged"
	raw := strings.Replace(spec.ruleJSON(), `"reasonCode":"FEATURE_REMOVED"`, `"reasonCode":"`+ReasonOneWayTransition+`"`, 1)
	return strings.Replace(raw, `"nextAction":"remove the reviewed feature before upgrade"`, `"nextAction":"`+noticeBefore+`"`, 1)
}

func TestNoticeRuleStructure(t *testing.T) {
	registry := scopeRegistry(t)
	good := noticeRule("notice-a", scopeComponentA, "1.0.0", "2.0.0", "active", activeUntil, "")
	accepted := map[string][]byte{
		"plain notice":                 ruleDocumentJSON(RulesSchemaNotice, nil, good),
		"notice with appliesWhen":      ruleDocumentJSON(RulesSchemaNotice, nil, noticeRule("notice-a", scopeComponentA, "1.0.0", "2.0.0", "active", activeUntil, appliesWhenA(true))),
		"notice with range":            ruleDocumentJSON(RulesSchemaNotice, nil, rangedNoticeRule()),
		"notice beside a verdict rule": ruleDocumentJSON(RulesSchemaNotice, nil, good, scopeRule("rule-b", "forbid_target_version", scopeComponentA, "1.0.0", "3.0.0", "active", activeUntil, "")),
	}
	for name, raw := range accepted {
		parsed, err := ParseRuleSet(raw, registry)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if parsed.engineDigest() != EngineContractDigestNotice() {
			t.Fatalf("%s: contract %s", name, parsed.engineDigest())
		}
	}
	replace := func(old, new string) string { return strings.Replace(good, old, new, 1) }
	withField := func(field string) string { return replace(`,"evidence":`, field+`,"evidence":`) }
	rejected := map[string][]byte{
		"exact schema":                   ruleDocumentJSON(RulesSchema, nil, good),
		"ranged schema":                  ruleDocumentJSON(RulesSchemaRanged, nil, rangedNoticeRule()),
		"set schema":                     ruleDocumentJSON(RulesSchemaSet, nil, good),
		"notice schema, no notice":       ruleDocumentJSON(RulesSchemaNotice, nil, scopeRule("rule-b", "forbid_target_version", scopeComponentA, "1.0.0", "3.0.0", "active", activeUntil, "")),
		"other reason code":              ruleDocumentJSON(RulesSchemaNotice, nil, replace(ReasonOneWayTransition, "FEATURE_REMOVED")),
		"condition":                      ruleDocumentJSON(RulesSchemaNotice, nil, withField(forbidFact(scopeComponentA, scopeFactA))),
		"dependency":                     ruleDocumentJSON(RulesSchemaNotice, nil, withField(`,"dependency":{"side":"proposed","component":"`+scopeComponentA+`","comparison":"gte","version":"1.0.0"}`)),
		"intermediate":                   ruleDocumentJSON(RulesSchemaNotice, nil, withField(`,"intermediate":"1.5.0"`)),
		"set condition":                  ruleDocumentJSON(RulesSchemaNotice, nil, withField(`,"setCondition":{"side":"proposed","component":"`+scopeComponentA+`","factId":"`+scopeFactA+`","members":["a"]}`)),
		"safe wording":                   ruleDocumentJSON(RulesSchemaNotice, nil, replace(noticeBefore, "rolling back is SAFE after a snapshot")),
		"oversized before text":          ruleDocumentJSON(RulesSchemaNotice, nil, replace(noticeBefore, strings.Repeat("b", 257))),
		"control character in text":      ruleDocumentJSON(RulesSchemaNotice, nil, replace(noticeBefore, `take\u0007a snapshot`)),
		"corpus backed only by a notice": ruleDocumentJSON(RulesSchemaNotice, []string{scopeComponentA}, good),
		"unknown schema level":           ruleDocumentJSON("prufyx.io/deterministic-constraint-rules/v1alpha5", nil, good),
	}
	for name, raw := range rejected {
		if !json.Valid(raw) {
			t.Fatalf("%s: fixture is not JSON: %s", name, raw)
		}
		if _, err := ParseRuleSet(raw, registry); err == nil {
			t.Fatalf("%s: accepted", name)
		}
	}
	// The raw-rule schema selector agrees with the parser.
	for name, want := range map[string]string{good: RulesSchemaNotice, scopeRule("rule-b", "forbid_target_version", scopeComponentA, "1.0.0", "3.0.0", "active", activeUntil, ""): RulesSchema} {
		got, err := RulesSchemaFor([]json.RawMessage{json.RawMessage(name)})
		if err != nil || got != want {
			t.Fatalf("RulesSchemaFor=%s err=%v want %s", got, err, want)
		}
	}
}

func TestNoticeEvaluation(t *testing.T) {
	registry := scopeRegistry(t)
	cases := []struct {
		name, rule, to, fact string
		status, reason       string
		freshness            string
		ranged               bool
	}{
		{"matched and current", noticeRule("notice-a", scopeComponentA, "1.0.0", "2.0.0", "active", activeUntil, ""), "2.0.0", "", StatusNotice, ReasonOneWayTransition, "current", false},
		{"applicability holds", noticeRule("notice-a", scopeComponentA, "1.0.0", "2.0.0", "active", activeUntil, appliesWhenA(true)), "2.0.0", declaredFact(scopeFactA, true), StatusNotice, ReasonOneWayTransition, "current", false},
		{"stale", noticeRule("notice-a", scopeComponentA, "1.0.0", "2.0.0", "active", expiredUntil, ""), "2.0.0", "", "UNKNOWN", "RULE_EVIDENCE_STALE", "stale", false},
		{"withdrawn", noticeRule("notice-a", scopeComponentA, "1.0.0", "2.0.0", "withdrawn", activeUntil, ""), "2.0.0", "", "UNKNOWN", "RULE_EVIDENCE_WITHDRAWN", "withdrawn", false},
		{"transition not reviewed", noticeRule("notice-a", scopeComponentA, "1.0.0", "2.0.0", "active", activeUntil, ""), "3.0.0", "", "UNKNOWN", "RULE_TRANSITION_NOT_REVIEWED", "current", false},
		{"applicability not matched", noticeRule("notice-a", scopeComponentA, "1.0.0", "2.0.0", "active", activeUntil, appliesWhenA(true)), "2.0.0", declaredFact(scopeFactA, false), "UNKNOWN", "RULE_APPLICABILITY_NOT_MATCHED", "current", false},
		{"applicability fact missing", noticeRule("notice-a", scopeComponentA, "1.0.0", "2.0.0", "active", activeUntil, appliesWhenA(true)), "2.0.0", "", "UNKNOWN", "RULE_APPLICABILITY_FACT_UNAVAILABLE", "current", false},
		{"range match", rangedNoticeRule(), "1.25.3", "", StatusNotice, ReasonOneWayTransition, "current", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rules := parseNotice(t, nil, tc.rule)
			from := "1.0.0"
			if tc.ranged {
				from = "1.24.2"
			}
			input := scopeInput(t, registry, false, componentInput{Component: scopeComponentA, From: from, To: tc.to, Fact: tc.fact})
			report, err := Evaluate(input, rules, testNow(t))
			if err != nil {
				t.Fatal(err)
			}
			claim := report.Claims[0]
			if claim.Status != tc.status || claim.ReasonCode != tc.reason || claim.EvidenceFreshness != tc.freshness || !claim.IsNotice() || report.Assessment != AssessmentUnknown {
				t.Fatalf("claim=%+v", claim)
			}
			if tc.status == StatusNotice && !strings.HasPrefix(claim.NextAction, noticeBefore) {
				t.Fatalf("notice lost its reviewed text: %q", claim.NextAction)
			}
			if tc.ranged != (claim.SubjectMatch != nil) {
				t.Fatalf("range disclosure=%+v", claim.SubjectMatch)
			}
			raw, err := MarshalReport(report)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := Replay(input, rules, testNow(t), raw); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestNoticeNeutralInScope(t *testing.T) {
	registry := scopeRegistry(t)
	passA := scopeRule("rule-a-pass", "forbid_predicate_value", scopeComponentA, "1.0.0", "2.0.0", "active", activeUntil, forbidFact(scopeComponentA, scopeFactA))
	otherB := scopeRule("rule-b-other-pair", "forbid_target_version", scopeComponentB, "1.0.0", "3.0.0", "active", activeUntil, "")
	noticeA := noticeRule("notice-a", scopeComponentA, "1.0.0", "2.0.0", "active", activeUntil, "")
	noticeB := noticeRule("notice-b", scopeComponentB, "1.0.0", "2.0.0", "active", activeUntil, "")
	staleNoticeA := noticeRule("notice-a-stale", scopeComponentA, "1.0.0", "2.0.0", "active", expiredUntil, "")
	evaluate := func(schema string, corpus []string, fact bool, components []componentInput, rules ...string) Report {
		t.Helper()
		parsed, err := ParseRuleSet(ruleDocumentJSON(schema, corpus, rules...), registry)
		if err != nil {
			t.Fatal(err)
		}
		report, err := Evaluate(scopeInput(t, registry, true, components...), parsed, testNow(t))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := MarshalReport(report); err != nil {
			t.Fatalf("report refused: %+v", report.ScopeCompleteness)
		}
		return report
	}
	onlyA := func(fact bool) []componentInput {
		return []componentInput{{Component: scopeComponentA, From: "1.0.0", To: "2.0.0", Fact: declaredFact(scopeFactA, fact)}}
	}

	// All-PASS scope: the notice does not change the aggregate or the block.
	base := evaluate(RulesSchema, []string{scopeComponentA}, false, onlyA(false), passA)
	for _, rules := range [][]string{{noticeA, passA}, {noticeA, staleNoticeA, passA}} {
		with := evaluate(RulesSchemaNotice, []string{scopeComponentA}, false, onlyA(false), rules...)
		if base.Assessment != AssessmentScopeCompletePass || with.Assessment != AssessmentScopeCompletePass || with.ScopeCompleteness.NoticeRules != len(rules)-1 {
			t.Fatalf("base=%s with=%s scope=%+v", base.Assessment, with.Assessment, with.ScopeCompleteness)
		}
		if !reflect.DeepEqual(base.ScopeCompleteness.Components, with.ScopeCompleteness.Components) || with.ScopeCompleteness.ContractDigest != ScopeContractDigestNotice() {
			t.Fatalf("components changed: %+v vs %+v", base.ScopeCompleteness.Components, with.ScopeCompleteness.Components)
		}
	}
	// BLOCKED scope stays BLOCKED.
	blocked := evaluate(RulesSchemaNotice, []string{scopeComponentA}, true, onlyA(true), noticeA, passA)
	if blocked.Assessment != AssessmentBlocked {
		t.Fatalf("assessment=%s", blocked.Assessment)
	}
	// A component whose only applicable rule is a notice has no evaluated
	// rule and stays UNKNOWN.
	both := []componentInput{{Component: scopeComponentA, From: "1.0.0", To: "2.0.0", Fact: declaredFact(scopeFactA, false)}, {Component: scopeComponentB, From: "1.0.0", To: "2.0.0"}}
	gap := evaluate(RulesSchemaNotice, []string{scopeComponentA, scopeComponentB}, false, both, noticeA, noticeB, passA, otherB)
	if gap.Assessment != AssessmentUnknown || gap.ScopeCompleteness.UnresolvedReason != unresolvedNoApplicableRule || gap.ScopeCompleteness.NoticeRules != 2 {
		t.Fatalf("assessment=%s scope=%+v", gap.Assessment, gap.ScopeCompleteness)
	}
	if claim := gap.Claims[1]; claim.RuleID != "notice-b" || claim.Status != StatusNotice {
		t.Fatalf("notice claim=%+v", claim)
	}
	// Notice rules are never enumerated in a component.
	for _, component := range gap.ScopeCompleteness.Components {
		for _, id := range component.EvaluatedRuleIDs {
			if strings.HasPrefix(id, "notice") {
				t.Fatalf("notice evaluated: %+v", component)
			}
		}
		for _, skipped := range component.NotEvaluated {
			if strings.HasPrefix(skipped.RuleID, "notice") {
				t.Fatalf("notice enumerated: %+v", component)
			}
		}
	}
	// Without a notice, the scope block carries no notice field at all.
	raw, err := MarshalReport(base)
	if err != nil || strings.Contains(string(raw), "noticeRules") {
		t.Fatalf("raw=%s err=%v", raw, err)
	}
}

// reseal recomputes a forged report's digest so that only the integrity
// rules, not the seal, can refuse it.
func reseal(report Report) Report { return issueReport(report) }

func TestNoticeIntegrity(t *testing.T) {
	registry := scopeRegistry(t)
	passA := scopeRule("rule-a-pass", "forbid_predicate_value", scopeComponentA, "1.0.0", "2.0.0", "active", activeUntil, forbidFact(scopeComponentA, scopeFactA))
	rules := parseNotice(t, []string{scopeComponentA}, noticeRule("notice-a", scopeComponentA, "1.0.0", "2.0.0", "active", activeUntil, ""), passA)
	input := scopeInput(t, registry, true, componentInput{Component: scopeComponentA, From: "1.0.0", To: "2.0.0", Fact: declaredFact(scopeFactA, false)})
	report, err := Evaluate(input, rules, testNow(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := MarshalReport(report); err != nil || report.Claims[0].Status != StatusNotice || report.Assessment != AssessmentScopeCompletePass {
		t.Fatalf("baseline refused: %v %+v", err, report)
	}
	clone := func() Report {
		raw, _ := json.Marshal(report)
		var copied Report
		_ = json.Unmarshal(raw, &copied)
		return copied
	}
	forgeries := map[string]func(*Report){
		"NOTICE from another operator": func(r *Report) { r.Claims[0].Operator = "forbid_target_version" },
		"NOTICE on a verdict rule":     func(r *Report) { r.Claims[1].Status = StatusNotice },
		"notice claim as PASS":         func(r *Report) { r.Claims[0].Status = "PASS" },
		"notice claim as BLOCKED":      func(r *Report) { r.Claims[0].Status = "BLOCKED" },
		"NOTICE with another reason":   func(r *Report) { r.Claims[0].ReasonCode = "FEATURE_REMOVED" },
		"NOTICE on stale evidence":     func(r *Report) { r.Claims[0].EvidenceFreshness = "stale" },
		"notice under the set contract": func(r *Report) {
			r.EngineContractDigest = EngineContractDigestSet()
			r.ScopeCompleteness.ContractDigest = ScopeContractDigestRanged()
		},
		"notice under the exact contract": func(r *Report) {
			r.EngineContractDigest = EngineContractDigest()
			r.ScopeCompleteness.ContractDigest = ScopeContractDigest()
		},
		"notice count dropped": func(r *Report) {
			r.ScopeCompleteness.NoticeRules = 0
			r.ScopeCompleteness.OutOfScopeRules = 1
		},
		"notice count inflated": func(r *Report) { r.ScopeCompleteness.NoticeRules = 2 },
		"notice counted as evaluated": func(r *Report) {
			r.ScopeCompleteness.NoticeRules = 0
			r.ScopeCompleteness.Components[0].EvaluatedRuleIDs = []string{"notice-a", "rule-a-pass"}
		},
		"notice counted as undetermined": func(r *Report) {
			r.ScopeCompleteness.NoticeRules = 0
			r.ScopeCompleteness.Components[0].NotEvaluated = []NotEvaluatedRule{{RuleID: "notice-a", Applicability: ApplicabilityUndetermined, ReasonCode: "RULE_EVIDENCE_STALE"}}
			r.ScopeCompleteness.Resolved, r.ScopeCompleteness.UnresolvedReason = false, unresolvedApplicability
			r.Assessment = AssessmentUnknown
			r.Omissions = requiredOmissions(AssessmentUnknown)
		},
	}
	for name, forge := range forgeries {
		forged := clone()
		forge(&forged)
		if _, err := MarshalReport(reseal(forged)); err == nil {
			t.Fatalf("%s: forged report accepted", name)
		}
	}
	// The unforged clone passes, so each refusal above is the forgery's.
	if _, err := MarshalReport(reseal(clone())); err != nil {
		t.Fatalf("clone refused: %v", err)
	}
}

func TestContractDigestsStable(t *testing.T) {
	if EngineContractDigest() != pinnedEngineContractDigest || EngineContractDigestRanged() != pinnedEngineContractDigestRanged || EngineContractDigestSet() != pinnedEngineContractDigestSet {
		t.Fatalf("engine contracts changed: %s %s %s", EngineContractDigest(), EngineContractDigestRanged(), EngineContractDigestSet())
	}
	if ScopeContractDigest() != pinnedScopeContractDigest || ScopeContractDigestRanged() != pinnedScopeContractDigestRanged {
		t.Fatalf("scope contracts changed: %s %s", ScopeContractDigest(), ScopeContractDigestRanged())
	}
	if scopeDigestFor(pinnedEngineContractDigest) != pinnedScopeContractDigest || scopeDigestFor(pinnedEngineContractDigestRanged) != pinnedScopeContractDigestRanged || scopeDigestFor(pinnedEngineContractDigestSet) != pinnedScopeContractDigestRanged {
		t.Fatal("existing contract pairing changed")
	}
	notice, noticeScope := EngineContractDigestNotice(), ScopeContractDigestNotice()
	for _, existing := range []string{pinnedEngineContractDigest, pinnedEngineContractDigestRanged, pinnedEngineContractDigestSet} {
		if notice == existing {
			t.Fatal("notice contract is not distinct")
		}
	}
	if !digestRE.MatchString(notice) || noticeScope == pinnedScopeContractDigest || noticeScope == pinnedScopeContractDigestRanged || scopeDigestFor(notice) != noticeScope {
		t.Fatal("notice scope contract is not distinct and paired")
	}
}

// TestNoticeNeverChangesAggregateProperty: for random rule documents, adding
// notice rules (matching or not, current, stale or withdrawn, with or without
// applicability) leaves the aggregate, the per-component enumeration and every
// other claim exactly as they were.
func TestNoticeNeverChangesAggregateProperty(t *testing.T) {
	registry := scopeRegistry(t)
	random := rand.New(rand.NewSource(20261004))
	components := []string{scopeComponentA, scopeComponentB}
	facts := map[string]string{scopeComponentA: scopeFactA, scopeComponentB: scopeFactB}
	pick := func(values ...string) string { return values[random.Intn(len(values))] }
	validity := func() (string, string) {
		return pick("active", "active", "active", "withdrawn"), pick(activeUntil, activeUntil, activeUntil, expiredUntil)
	}
	applicability := func(component string) string {
		if random.Intn(3) != 0 {
			return ""
		}
		return `,"appliesWhen":[{"side":"proposed","component":"` + component + `","factId":"` + facts[component] + `","boolValue":` + boolToken(random.Intn(2) == 0) + `}]`
	}
	cases, tally := 0, map[string]int{}
	for iteration := 0; cases < 2000; iteration++ {
		if iteration > 20000 {
			t.Fatalf("only %d usable cases", cases)
		}
		var rules []string
		ruleCount := 1 + random.Intn(5)
		for index := 0; index < ruleCount; index++ {
			component := pick(components...)
			state, until := validity()
			id := fmt.Sprintf("rule-%02d", index)
			to := pick("2.0.0", "2.0.0", "3.0.0")
			extra := applicability(component)
			switch operator := random.Intn(10); {
			case operator < 5:
				rules = append(rules, scopeRule(id, "forbid_predicate_value", component, "1.0.0", to, state, until, forbidFact(component, facts[component])+extra))
			case operator < 7:
				rules = append(rules, scopeRule(id, "forbid_target_version", component, "1.0.0", to, state, until, extra))
			default:
				rules = append(rules, scopeRule(id, "require_component_version", component, "1.0.0", to, state, until, `,"dependency":{"side":"proposed","component":"`+pick(components...)+`","comparison":"`+pick("gte", "lt")+`","version":"2.0.0"}`+extra))
			}
		}
		withNotices := append([]string(nil), rules...)
		for index := 0; index < 1+random.Intn(3); index++ {
			component := pick(components...)
			state, until := validity()
			withNotices = append(withNotices, noticeRule(fmt.Sprintf("rule-%02d-notice", index), component, "1.0.0", pick("2.0.0", "3.0.0"), state, until, applicability(component)))
		}
		sort.Slice(withNotices, func(i, j int) bool { return ruleIDOf(withNotices[i]) < ruleIDOf(withNotices[j]) })
		subjects := map[string]bool{}
		for _, raw := range rules {
			subjects[subjectOf(raw)] = true
		}
		var corpus []string
		for _, component := range components {
			if subjects[component] && random.Intn(4) != 0 {
				corpus = append(corpus, component)
			}
		}
		var inputs []componentInput
		present := components
		if random.Intn(2) == 0 {
			present = []string{pick(components...)}
		}
		for _, component := range present {
			fact := ""
			switch random.Intn(4) {
			case 0:
				fact = declaredFact(facts[component], true)
			case 1, 2:
				fact = declaredFact(facts[component], false)
			}
			inputs = append(inputs, componentInput{Component: component, From: "1.0.0", To: pick("2.0.0", "2.0.0", "3.0.0"), Fact: fact})
		}
		baseRules, err := ParseRuleSet(ruleDocumentJSON(RulesSchema, corpus, rules...), registry)
		if err != nil {
			continue // a random document the parser refuses (for example a dependency on its own subject) proves nothing
		}
		noticeRules, err := ParseRuleSet(ruleDocumentJSON(RulesSchemaNotice, corpus, withNotices...), registry)
		if err != nil {
			t.Fatalf("notice document refused although its base parsed: %v", err)
		}
		input := scopeInput(t, registry, random.Intn(4) != 0, inputs...)
		base, err := Evaluate(input, baseRules, testNow(t))
		if err != nil {
			t.Fatal(err)
		}
		with, err := Evaluate(input, noticeRules, testNow(t))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := MarshalReport(base); err != nil {
			t.Fatalf("base refused: %v", err)
		}
		if _, err := MarshalReport(with); err != nil {
			t.Fatalf("notice report refused: %v", err)
		}
		if base.Assessment != with.Assessment || !reflect.DeepEqual(base.Omissions, with.Omissions) {
			t.Fatalf("case %d: aggregate %s became %s", cases, base.Assessment, with.Assessment)
		}
		if (base.ScopeCompleteness == nil) != (with.ScopeCompleteness == nil) {
			t.Fatalf("case %d: scope presence changed", cases)
		}
		if base.ScopeCompleteness != nil {
			b, w := *base.ScopeCompleteness, *with.ScopeCompleteness
			if w.NoticeRules != len(withNotices)-len(rules) || b.NoticeRules != 0 {
				t.Fatalf("case %d: notice count %d", cases, w.NoticeRules)
			}
			b.ContractDigest, w.ContractDigest, w.NoticeRules = "", "", 0
			if !reflect.DeepEqual(b, w) {
				t.Fatalf("case %d: scope changed:\n%+v\n%+v", cases, b, w)
			}
		}
		var verdicts []Claim
		for _, claim := range with.Claims {
			if !claim.IsNotice() {
				verdicts = append(verdicts, claim)
			} else if claim.Status != StatusNotice && claim.Status != "UNKNOWN" {
				t.Fatalf("case %d: notice claim %+v", cases, claim)
			}
		}
		if !reflect.DeepEqual(base.Claims, verdicts) {
			t.Fatalf("case %d: verdict claims changed", cases)
		}
		tally[with.Assessment]++
		cases++
	}
	t.Logf("aggregates over %d cases: %v", cases, tally)
	for _, assessment := range []string{AssessmentUnknown, AssessmentBlocked, AssessmentScopeCompletePass} {
		if tally[assessment] == 0 {
			t.Fatalf("no case reached %s: %v", assessment, tally)
		}
	}
}

func ruleIDOf(raw string) string {
	var shape struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal([]byte(raw), &shape)
	return shape.ID
}

func subjectOf(raw string) string {
	var shape struct {
		Subject struct {
			Component string `json:"component"`
		} `json:"subject"`
	}
	_ = json.Unmarshal([]byte(raw), &shape)
	return shape.Subject.Component
}

func TestNoticeLines(t *testing.T) {
	notice := Claim{RuleID: "notice-a", Operator: OperatorNoticeOneWay, Status: StatusNotice, ReasonCode: ReasonOneWayTransition, NextAction: noticeBefore}
	lines, ok := notice.NoticeLines()
	if !ok || !reflect.DeepEqual(lines, []string{"cannot be rolled back: notice-a", "before you upgrade: " + noticeBefore}) {
		t.Fatalf("lines=%q", lines)
	}
	long := notice
	long.NextAction = strings.Repeat("x", 250)
	if lines, _ := long.NoticeLines(); len(lines) != 3 || lines[1] != "before you upgrade:" {
		t.Fatalf("long lines=%q", lines)
	}
	for _, line := range append(lines, func() []string { l, _ := long.NoticeLines(); return l }()...) {
		if len(line) > 256 {
			t.Fatalf("line over 256 bytes: %q", line)
		}
	}
	notApplicable := notice
	notApplicable.Status, notApplicable.ReasonCode = "UNKNOWN", "RULE_TRANSITION_NOT_REVIEWED"
	if lines, ok := notApplicable.NoticeLines(); !ok || len(lines) != 0 {
		t.Fatalf("a notice that does not apply printed %q", lines)
	}
	stale := notice
	stale.Status, stale.ReasonCode, stale.NextAction = "UNKNOWN", "RULE_EVIDENCE_STALE", "select later declared rule source references with current evidence"
	if lines, ok := stale.NoticeLines(); !ok || len(lines) != 2 || !strings.HasPrefix(lines[0], "one-way notice not established: notice-a") {
		t.Fatalf("stale lines=%q", lines)
	}
	if _, ok := (Claim{Operator: "forbid_target_version", Status: "BLOCKED"}).NoticeLines(); ok {
		t.Fatal("a verdict claim produced notice lines")
	}
	for _, claim := range []Claim{notice, long, notApplicable, stale} {
		lines, _ := claim.NoticeLines()
		if strings.Contains(strings.ToLower(strings.Join(lines, "\n")), "safe") {
			t.Fatalf("notice wording mentions safety: %q", lines)
		}
	}
}
