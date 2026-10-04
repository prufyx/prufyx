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

const basisDerivedAt = "2026-01-01T00:00:00Z"

// withBasis declares an evidence basis (and derivedAt) on a rendered rule.
func withBasis(raw, basis string) string {
	return strings.Replace(raw, `"evidence":{"state":`, `"evidence":{"basis":"`+basis+`","derivedAt":"`+basisDerivedAt+`","state":`, 1)
}

func parseBasis(t *testing.T, corpus []string, rules ...string) RuleSet {
	t.Helper()
	parsed, err := ParseRuleSet(ruleDocumentJSON(RulesSchemaBasis, corpus, rules...), scopeRegistry(t))
	if err != nil {
		t.Fatalf("parse basis rules: %v", err)
	}
	return parsed
}

func TestValidateBasisAllTokens(t *testing.T) {
	extractor := &Extractor{ID: "k8s-feature-gates", Version: "1.0.0", CodeDigest: testDigest}
	type presence struct {
		extractor, derivedAt bool
	}
	all := []presence{{false, false}, {true, false}, {false, true}, {true, true}}
	accepted := map[string]presence{
		"":              {false, false},
		BasisReviewed:   {false, false},
		BasisMechanical: {true, true},
		BasisEmpirical:  {false, true},
		BasisConsensus:  {false, true},
		BasisLead:       {false, true},
	}
	for _, basis := range []string{"", BasisReviewed, BasisMechanical, BasisEmpirical, BasisConsensus, BasisLead, "Consensus", "model", "unknown"} {
		for _, p := range all {
			var e *Extractor
			derivedAt := ""
			if p.extractor {
				e = extractor
			}
			if p.derivedAt {
				derivedAt = basisDerivedAt
			}
			want, known := accepted[basis]
			err := ValidateBasis(basis, e, derivedAt)
			if ok := known && want == p; ok != (err == nil) {
				t.Fatalf("basis %q extractor=%v derivedAt=%v: err=%v", basis, p.extractor, p.derivedAt, err)
			}
			strict := ValidateReviewedOrMechanicalBasis(basis, e, derivedAt)
			strictOK := known && want == p && (basis == "" || basis == BasisReviewed || basis == BasisMechanical)
			if strictOK != (strict == nil) {
				t.Fatalf("strict basis %q extractor=%v derivedAt=%v: err=%v", basis, p.extractor, p.derivedAt, strict)
			}
		}
	}
	for _, basis := range []string{BasisEmpirical, BasisConsensus, BasisLead} {
		for _, bad := range []string{"2026-01-01T00:00:00+01:00", "2026-01-01", "2026-01-01T00:00:00.5Z"} {
			if ValidateBasis(basis, nil, bad) == nil {
				t.Fatalf("%s accepted derivedAt %q", basis, bad)
			}
		}
	}
}

func TestBasisPermissions(t *testing.T) {
	for _, tc := range []struct {
		basis                       string
		block, pass, blockOnly, neu bool
	}{
		{"", true, true, false, false},
		{BasisReviewed, true, true, false, false},
		{BasisMechanical, true, true, false, false},
		{BasisEmpirical, true, true, false, false},
		{BasisConsensus, true, false, true, false},
		{BasisLead, false, false, false, true},
		{"unknown", false, false, false, false},
	} {
		if BasisMayBlock(tc.basis) != tc.block || BasisMayPass(tc.basis) != tc.pass || BasisBlockOnly(tc.basis) != tc.blockOnly || BasisVerdictNeutral(tc.basis) != tc.neu {
			t.Fatalf("basis %q: block=%v pass=%v blockOnly=%v neutral=%v", tc.basis, BasisMayBlock(tc.basis), BasisMayPass(tc.basis), BasisBlockOnly(tc.basis), BasisVerdictNeutral(tc.basis))
		}
	}
	if !reflect.DeepEqual(Bases(), []string{"reviewed", "mechanical", "empirical", "consensus", "lead"}) {
		t.Fatalf("vocabulary %v", Bases())
	}
}

func TestBasisRuleStructure(t *testing.T) {
	registry := scopeRegistry(t)
	forbidA := scopeRule("rule-a", "forbid_predicate_value", scopeComponentA, "1.0.0", "2.0.0", "active", activeUntil, forbidFact(scopeComponentA, scopeFactA))
	consensusA := withBasis(forbidA, BasisConsensus)
	leadA := withBasis(forbidA, BasisLead)
	empiricalA := withBasis(forbidA, BasisEmpirical)
	notice := noticeRule("notice-a", scopeComponentA, "1.0.0", "2.0.0", "active", activeUntil, "")
	accepted := map[string]struct {
		schema   string
		contract string
		rules    []string
	}{
		"consensus":                {RulesSchemaBasis, EngineContractDigestBasis(), []string{consensusA}},
		"lead":                     {RulesSchemaBasis, EngineContractDigestBasis(), []string{leadA}},
		"consensus beside notice":  {RulesSchemaBasis, EngineContractDigestBasis(), []string{notice, withBasis(scopeRule("rule-b", "forbid_target_version", scopeComponentA, "1.0.0", "3.0.0", "active", activeUntil, ""), BasisConsensus)}},
		"ranged consensus":         {RulesSchemaBasis, EngineContractDigestBasis(), []string{withBasis(defaultRangeSpec().ruleJSON(), BasisConsensus)}},
		"empirical exact":          {RulesSchema, EngineContractDigest(), []string{empiricalA}},
		"empirical beside a range": {RulesSchemaRanged, EngineContractDigestRanged(), []string{withBasis(defaultRangeSpec().ruleJSON(), BasisEmpirical)}},
	}
	for name, tc := range accepted {
		parsed, err := ParseRuleSet(ruleDocumentJSON(tc.schema, nil, tc.rules...), registry)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if parsed.engineDigest() != tc.contract {
			t.Fatalf("%s: contract %s", name, parsed.engineDigest())
		}
		raws := make([]json.RawMessage, 0, len(tc.rules))
		for _, rule := range tc.rules {
			raws = append(raws, json.RawMessage(rule))
		}
		if schema, err := RulesSchemaFor(raws); err != nil || schema != tc.schema {
			t.Fatalf("%s: RulesSchemaFor=%s err=%v", name, schema, err)
		}
	}
	rejected := map[string][]byte{
		"consensus under exact schema":    ruleDocumentJSON(RulesSchema, nil, consensusA),
		"consensus under notice schema":   ruleDocumentJSON(RulesSchemaNotice, nil, notice, consensusA),
		"lead under set schema":           ruleDocumentJSON(RulesSchemaSet, nil, leadA),
		"basis schema without basis rule": ruleDocumentJSON(RulesSchemaBasis, nil, forbidA),
		"basis schema with empirical":     ruleDocumentJSON(RulesSchemaBasis, nil, empiricalA),
		"consensus one-way notice":        ruleDocumentJSON(RulesSchemaBasis, nil, withBasis(notice, BasisConsensus)),
		"lead one-way notice":             ruleDocumentJSON(RulesSchemaBasis, nil, withBasis(notice, BasisLead)),
		"corpus backed only by a lead":    ruleDocumentJSON(RulesSchemaBasis, []string{scopeComponentA}, leadA),
		"consensus without derivedAt":     ruleDocumentJSON(RulesSchemaBasis, nil, strings.Replace(consensusA, `"derivedAt":"`+basisDerivedAt+`",`, "", 1)),
		"consensus with extractor":        ruleDocumentJSON(RulesSchemaBasis, nil, strings.Replace(consensusA, `"derivedAt":`, `"extractor":{"id":"x","version":"1.0.0","codeDigest":"`+testDigest+`"},"derivedAt":`, 1)),
		"unknown basis":                   ruleDocumentJSON(RulesSchemaBasis, nil, consensusA, withBasis(scopeRule("rule-b", "forbid_target_version", scopeComponentA, "1.0.0", "3.0.0", "active", activeUntil, ""), "model")),
		"unknown schema level":            ruleDocumentJSON("prufyx.io/deterministic-constraint-rules/v1alpha9", nil, consensusA),
	}
	for name, raw := range rejected {
		if !json.Valid(raw) {
			t.Fatalf("%s: fixture is not JSON: %s", name, raw)
		}
		if _, err := ParseRuleSet(raw, registry); err == nil {
			t.Fatalf("%s: accepted", name)
		}
	}
	// A consensus rule may back a corpus attestation: it can block.
	if _, err := ParseRuleSet(ruleDocumentJSON(RulesSchemaBasis, []string{scopeComponentA}, consensusA), registry); err != nil {
		t.Fatalf("consensus corpus: %v", err)
	}
}

func TestConsensusSemantics(t *testing.T) {
	registry := scopeRegistry(t)
	consensusA := withBasis(scopeRule("rule-a-consensus", "forbid_predicate_value", scopeComponentA, "1.0.0", "2.0.0", "active", activeUntil, forbidFact(scopeComponentA, scopeFactA)), BasisConsensus)
	passB := scopeRule("rule-b-pass", "forbid_predicate_value", scopeComponentB, "1.0.0", "2.0.0", "active", activeUntil, forbidFact(scopeComponentB, scopeFactB))
	passA := scopeRule("rule-a-pass", "forbid_predicate_value", scopeComponentA, "1.0.0", "2.0.0", "active", activeUntil, forbidFact(scopeComponentA, scopeFactA))
	evaluate := func(withScope bool, factA bool, rules ...string) Report {
		t.Helper()
		parsed := parseBasis(t, []string{scopeComponentA, scopeComponentB}, rules...)
		report, err := Evaluate(scopeInput(t, registry, withScope,
			componentInput{Component: scopeComponentA, From: "1.0.0", To: "2.0.0", Fact: declaredFact(scopeFactA, factA)},
			componentInput{Component: scopeComponentB, From: "1.0.0", To: "2.0.0", Fact: declaredFact(scopeFactB, false)}), parsed, testNow(t))
		if err != nil {
			t.Fatal(err)
		}
		raw, err := MarshalReport(report)
		if err != nil {
			t.Fatalf("report refused: %+v", report)
		}
		input := scopeInput(t, registry, withScope,
			componentInput{Component: scopeComponentA, From: "1.0.0", To: "2.0.0", Fact: declaredFact(scopeFactA, factA)},
			componentInput{Component: scopeComponentB, From: "1.0.0", To: "2.0.0", Fact: declaredFact(scopeFactB, false)})
		if _, err := Replay(input, parsed, testNow(t), raw); err != nil {
			t.Fatalf("replay: %v", err)
		}
		return report
	}
	// Predicate true: BLOCKED, and the scope is BLOCKED.
	blocked := evaluate(true, true, consensusA, passA, passB)
	if claim := blocked.Claims[0]; claim.Status != "BLOCKED" || claim.ReasonCode != "FEATURE_REMOVED" || claim.EvidenceBasis != BasisConsensus || !claim.ReliesOnConsensus() {
		t.Fatalf("claim=%+v", claim)
	}
	if blocked.Assessment != AssessmentBlocked {
		t.Fatalf("assessment=%s", blocked.Assessment)
	}
	// Predicate false: NO_KNOWN_ISSUE, never PASS; with every other rule
	// passing in an attested scope, the aggregate stays UNKNOWN.
	noIssue := evaluate(true, false, consensusA, passA, passB)
	claim := noIssue.Claims[0]
	if claim.Status != StatusNoKnownIssue || claim.ReasonCode != ReasonConsensusNoKnownIssue || !claim.ReliesOnConsensus() {
		t.Fatalf("claim=%+v", claim)
	}
	if noIssue.Claims[1].Status != "PASS" || noIssue.Claims[2].Status != "PASS" {
		t.Fatalf("other claims=%+v", noIssue.Claims[1:])
	}
	scope := noIssue.ScopeCompleteness
	if noIssue.Assessment != AssessmentUnknown || scope == nil || scope.UnresolvedReason != unresolvedConsensusOnlyScope || scope.ContractDigest != ScopeContractDigestBasis() {
		t.Fatalf("assessment=%s scope=%+v", noIssue.Assessment, scope)
	}
	want := []NotEvaluatedRule{{RuleID: "rule-a-consensus", Applicability: ApplicabilityApplicable, ReasonCode: ReasonConsensusNoKnownIssue}}
	if !reflect.DeepEqual(scope.Components[0].NotEvaluated, want) || !reflect.DeepEqual(scope.Components[0].EvaluatedRuleIDs, []string{"rule-a-pass"}) {
		t.Fatalf("component=%+v", scope.Components[0])
	}
	// The same document without the consensus rule is a scope-complete pass,
	// so the consensus rule alone withholds it.
	withoutRaw := ruleDocumentJSON(RulesSchema, []string{scopeComponentA, scopeComponentB}, passA, passB)
	without, err := ParseRuleSet(withoutRaw, registry)
	if err != nil {
		t.Fatal(err)
	}
	baseline, err := Evaluate(scopeInput(t, registry, true,
		componentInput{Component: scopeComponentA, From: "1.0.0", To: "2.0.0", Fact: declaredFact(scopeFactA, false)},
		componentInput{Component: scopeComponentB, From: "1.0.0", To: "2.0.0", Fact: declaredFact(scopeFactB, false)}), without, testNow(t))
	if err != nil || baseline.Assessment != AssessmentScopeCompletePass {
		t.Fatalf("baseline=%s err=%v", baseline.Assessment, err)
	}
	// A component whose only applicable rule is consensus is still
	// CONSENSUS_ONLY_SCOPE, not an empty component.
	only := evaluate(true, false, consensusA, passB)
	if only.Assessment != AssessmentUnknown || only.ScopeCompleteness.UnresolvedReason != unresolvedConsensusOnlyScope {
		t.Fatalf("assessment=%s scope=%+v", only.Assessment, only.ScopeCompleteness)
	}
	// Unscoped: the claim is still NO_KNOWN_ISSUE.
	unscoped := evaluate(false, false, consensusA, passB)
	if unscoped.ScopeCompleteness != nil || unscoped.Claims[0].Status != StatusNoKnownIssue || unscoped.Assessment != AssessmentUnknown {
		t.Fatalf("unscoped=%+v", unscoped)
	}
	// Every operator: a consensus rule that would pass never passes.
	for name, rule := range map[string]string{
		"dependency satisfied": withBasis(scopeRule("rule-a-dep", "require_component_version", scopeComponentA, "1.0.0", "2.0.0", "active", activeUntil, `,"dependency":{"side":"proposed","component":"`+scopeComponentB+`","comparison":"gte","version":"2.0.0"}`), BasisConsensus),
	} {
		report := evaluate(false, false, rule, passB)
		if report.Claims[0].Status != StatusNoKnownIssue {
			t.Fatalf("%s: claim=%+v", name, report.Claims[0])
		}
	}
	// Stale consensus evidence is UNKNOWN, as for any other basis.
	stale := evaluate(true, false, withBasis(scopeRule("rule-a-consensus", "forbid_predicate_value", scopeComponentA, "1.0.0", "2.0.0", "active", expiredUntil, forbidFact(scopeComponentA, scopeFactA)), BasisConsensus), passA, passB)
	if stale.Claims[0].Status != "UNKNOWN" || stale.ScopeCompleteness.UnresolvedReason != unresolvedApplicability {
		t.Fatalf("stale=%+v", stale.ScopeCompleteness)
	}
}

func TestLeadIsNoticeOnly(t *testing.T) {
	registry := scopeRegistry(t)
	lead := func(state, until string) string {
		return withBasis(scopeRule("rule-a-lead", "forbid_predicate_value", scopeComponentA, "1.0.0", "2.0.0", state, until, forbidFact(scopeComponentA, scopeFactA)), BasisLead)
	}
	leadTarget := withBasis(scopeRule("rule-a-lead-target", "forbid_target_version", scopeComponentA, "1.0.0", "2.0.0", "active", activeUntil, ""), BasisLead)
	passA := scopeRule("rule-a-pass", "forbid_predicate_value", scopeComponentA, "1.0.0", "2.0.0", "active", activeUntil, forbidFact(scopeComponentA, scopeFactA))
	blockB := scopeRule("rule-b-block", "forbid_target_version", scopeComponentB, "1.0.0", "2.0.0", "active", activeUntil, "")
	inputFor := func(withScope, factA bool, onlyA ...bool) Input {
		components := []componentInput{{Component: scopeComponentA, From: "1.0.0", To: "2.0.0", Fact: declaredFact(scopeFactA, factA)}}
		if len(onlyA) == 0 {
			components = append(components, componentInput{Component: scopeComponentB, From: "1.0.0", To: "2.0.0"})
		}
		return scopeInput(t, registry, withScope, components...)
	}
	evaluate := func(schema string, corpus []string, input Input, rules ...string) Report {
		t.Helper()
		parsed, err := ParseRuleSet(ruleDocumentJSON(schema, corpus, rules...), registry)
		if err != nil {
			t.Fatal(err)
		}
		report, err := Evaluate(input, parsed, testNow(t))
		if err != nil {
			t.Fatal(err)
		}
		raw, err := MarshalReport(report)
		if err != nil {
			t.Fatalf("report refused: %+v", report)
		}
		if _, err := Replay(input, parsed, testNow(t), raw); err != nil {
			t.Fatal(err)
		}
		return report
	}
	// Predicate true: NOTICE LEAD_NOT_VERIFIED, never BLOCKED.
	for _, rule := range []string{lead("active", activeUntil), leadTarget} {
		report := evaluate(RulesSchemaBasis, nil, inputFor(false, true), rule)
		claim := report.Claims[0]
		if claim.Status != StatusNotice || claim.ReasonCode != ReasonLeadNotVerified || !claim.IsVerdictNeutral() || claim.IsNotice() {
			t.Fatalf("claim=%+v", claim)
		}
		lines, ok := claim.NoticeLines()
		if !ok || len(lines) != 2 || lines[0] != "unverified lead (does not block): "+claim.RuleID || lines[1] != "worth checking: remove the reviewed feature before upgrade" {
			t.Fatalf("lines=%q", lines)
		}
	}
	// Predicate false: NO_KNOWN_ISSUE, never PASS, and it prints nothing.
	report := evaluate(RulesSchemaBasis, nil, inputFor(false, false), lead("active", activeUntil))
	if claim := report.Claims[0]; claim.Status != StatusNoKnownIssue || claim.ReasonCode != ReasonLeadNoKnownIssue || claim.ReliesOnConsensus() {
		t.Fatalf("claim=%+v", claim)
	}
	if lines, ok := report.Claims[0].NoticeLines(); !ok || len(lines) != 0 {
		t.Fatalf("lines=%q", lines)
	}
	// Excluded from scope: the aggregate, omissions and every enumerated
	// component are identical with and without the lead, whatever it says.
	for _, scenario := range []struct {
		name  string
		factA bool
		want  string
		rules []string
	}{
		{"pass scope", false, AssessmentScopeCompletePass, []string{passA}},
		{"blocked scope", true, AssessmentBlocked, []string{passA}},
		{"blocked by other component", false, AssessmentBlocked, []string{passA, blockB}},
	} {
		for _, extra := range []string{lead("active", activeUntil), lead("active", expiredUntil), lead("withdrawn", activeUntil), leadTarget} {
			corpus, input := []string{scopeComponentA}, inputFor(true, scenario.factA, true)
			if len(scenario.rules) > 1 {
				corpus, input = []string{scopeComponentA, scopeComponentB}, inputFor(true, scenario.factA)
			}
			base := evaluate(RulesSchema, corpus, input, scenario.rules...)
			rules := append([]string{extra}, scenario.rules...)
			sort.Slice(rules, func(i, j int) bool { return ruleIDOf(rules[i]) < ruleIDOf(rules[j]) })
			with := evaluate(RulesSchemaBasis, corpus, input, rules...)
			if base.Assessment != scenario.want || with.Assessment != base.Assessment || !reflect.DeepEqual(base.Omissions, with.Omissions) {
				t.Fatalf("%s: base=%s with=%s", scenario.name, base.Assessment, with.Assessment)
			}
			b, w := *base.ScopeCompleteness, *with.ScopeCompleteness
			if w.LeadRules != 1 || b.LeadRules != 0 || w.ContractDigest != ScopeContractDigestBasis() {
				t.Fatalf("%s: scope=%+v", scenario.name, w)
			}
			b.ContractDigest, w.ContractDigest, w.LeadRules = "", "", 0
			if !reflect.DeepEqual(b, w) {
				t.Fatalf("%s: scope changed:\n%+v\n%+v", scenario.name, b, w)
			}
			for _, claim := range with.Claims {
				if claim.IsLead() && (claim.Status == "BLOCKED" || claim.Status == "PASS") {
					t.Fatalf("%s: lead claim %+v", scenario.name, claim)
				}
			}
		}
	}
	// A component whose only rule is a lead has nothing evaluated.
	gap := evaluate(RulesSchemaBasis, []string{scopeComponentB}, inputFor(true, true), lead("active", activeUntil), blockB)
	if gap.ScopeCompleteness.Components[0].Component != scopeComponentA || len(gap.ScopeCompleteness.Components[0].EvaluatedRuleIDs) != 0 || gap.ScopeCompleteness.LeadRules != 1 {
		t.Fatalf("gap=%+v", gap.ScopeCompleteness)
	}
	// Without a lead, the scope block carries no lead field.
	raw, err := MarshalReport(evaluate(RulesSchema, []string{scopeComponentA}, inputFor(true, false, true), passA))
	if err != nil || strings.Contains(string(raw), "leadRules") {
		t.Fatalf("raw=%s err=%v", raw, err)
	}
}

// TestConsensusNeverPassesProperty: for random rule documents, relabelling
// any rules' basis to consensus never turns a non-PASS aggregate into PASS
// and never turns a BLOCKED claim into anything but BLOCKED; adding lead
// rules leaves aggregate, scope and every verdict claim unchanged.
func TestConsensusNeverPassesProperty(t *testing.T) {
	registry := scopeRegistry(t)
	random := rand.New(rand.NewSource(20261005))
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
	render := func(id, component string) string {
		state, until := validity()
		to := pick("2.0.0", "2.0.0", "3.0.0")
		extra := applicability(component)
		switch operator := random.Intn(10); {
		case operator < 5:
			// The condition forbids the proposed fact being true. A
			// proposed guard requiring it false would make the rule
			// vacuous, which the parser refuses, so a false guard moves
			// to the current side: an independent fact, so the rule can
			// still PASS (proposed false, current false) or BLOCK.
			extra = strings.Replace(extra, `"side":"proposed","component":"`+component+`","factId":"`+facts[component]+`","boolValue":false`, `"side":"current","component":"`+component+`","factId":"`+facts[component]+`","boolValue":false`, 1)
			return scopeRule(id, "forbid_predicate_value", component, "1.0.0", to, state, until, forbidFact(component, facts[component])+extra)
		case operator < 7:
			return scopeRule(id, "forbid_target_version", component, "1.0.0", to, state, until, extra)
		default:
			return scopeRule(id, "require_component_version", component, "1.0.0", to, state, until, `,"dependency":{"side":"proposed","component":"`+pick(components...)+`","comparison":"`+pick("gte", "lt")+`","version":"2.0.0"}`+extra)
		}
	}
	cases, relabelled, tally := 0, 0, map[string]int{}
	// guardedPass counts PASS claims of guarded predicate rules (the
	// guard on the current side), and guardedRelabelled those relabelled
	// to consensus.
	guardedPass, guardedRelabelled := 0, 0
	for iteration := 0; cases < 2000; iteration++ {
		if iteration > 20000 {
			t.Fatalf("only %d usable cases", cases)
		}
		var rules []string
		for index := 0; index < 1+random.Intn(5); index++ {
			rules = append(rules, render(fmt.Sprintf("rule-%02d", index), pick(components...)))
		}
		consensus := append([]string(nil), rules...)
		changed := 0
		for index := range consensus {
			if random.Intn(2) == 0 {
				consensus[index] = withBasis(consensus[index], BasisConsensus)
				changed++
			}
		}
		if changed == 0 {
			consensus[0] = withBasis(consensus[0], BasisConsensus)
		}
		leads := append([]string(nil), rules...)
		for index := 0; index < 1+random.Intn(3); index++ {
			leads = append(leads, withBasis(render(fmt.Sprintf("rule-%02d-lead", index), pick(components...)), BasisLead))
		}
		sort.Slice(leads, func(i, j int) bool { return ruleIDOf(leads[i]) < ruleIDOf(leads[j]) })
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
			// The current fact follows the same draw, so the random
			// stream is unchanged: a current-side guard (false) holds in
			// cases 0 and 1, is contradicted in case 2 and absent in 3.
			fact, current := "", ""
			switch draw := random.Intn(4); draw {
			case 0:
				fact, current = declaredFact(facts[component], true), declaredFact(facts[component], false)
			case 1, 2:
				fact, current = declaredFact(facts[component], false), declaredFact(facts[component], draw == 2)
			}
			inputs = append(inputs, componentInput{Component: component, From: "1.0.0", To: pick("2.0.0", "2.0.0", "3.0.0"), Fact: fact, CurrentFact: current})
		}
		baseRules, err := ParseRuleSet(ruleDocumentJSON(RulesSchema, corpus, rules...), registry)
		if err != nil {
			continue // a random document the parser refuses proves nothing
		}
		consensusRules, err := ParseRuleSet(ruleDocumentJSON(RulesSchemaBasis, corpus, consensus...), registry)
		if err != nil {
			t.Fatalf("consensus document refused although its base parsed: %v", err)
		}
		leadRules, err := ParseRuleSet(ruleDocumentJSON(RulesSchemaBasis, corpus, leads...), registry)
		if err != nil {
			t.Fatalf("lead document refused although its base parsed: %v", err)
		}
		input := scopeInput(t, registry, random.Intn(4) != 0, inputs...)
		evaluate := func(rules RuleSet) Report {
			report, err := Evaluate(input, rules, testNow(t))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := MarshalReport(report); err != nil {
				t.Fatalf("case %d: report refused: %v", cases, err)
			}
			return report
		}
		base, withConsensus, withLeads := evaluate(baseRules), evaluate(consensusRules), evaluate(leadRules)
		if withConsensus.Assessment == AssessmentScopeCompletePass && base.Assessment != AssessmentScopeCompletePass {
			t.Fatalf("case %d: consensus turned %s into a pass", cases, base.Assessment)
		}
		if base.Assessment == AssessmentBlocked && withConsensus.Assessment != AssessmentBlocked {
			t.Fatalf("case %d: consensus turned BLOCKED into %s", cases, withConsensus.Assessment)
		}
		hasNoKnownIssue := false
		for index, claim := range withConsensus.Claims {
			was := base.Claims[index]
			if was.Status == "BLOCKED" && claim.Status != "BLOCKED" {
				t.Fatalf("case %d: BLOCKED claim became %s", cases, claim.Status)
			}
			if claim.EvidenceBasis == BasisConsensus && (claim.Status == "PASS" || claim.Status == StatusNotice) {
				t.Fatalf("case %d: consensus claim %+v", cases, claim)
			}
			if claim.Status == StatusNoKnownIssue {
				hasNoKnownIssue = true
				if was.Status != "PASS" {
					t.Fatalf("case %d: NO_KNOWN_ISSUE from %s", cases, was.Status)
				}
			} else if claim.Status != was.Status || claim.ReasonCode != was.ReasonCode {
				t.Fatalf("case %d: claim %+v was %+v", cases, claim, was)
			}
		}
		if hasNoKnownIssue && withConsensus.ScopeCompleteness != nil && withConsensus.Assessment == AssessmentScopeCompletePass {
			t.Fatalf("case %d: scope-complete pass beside NO_KNOWN_ISSUE", cases)
		}
		if changed > 0 {
			relabelled++
		}
		// Leads are neutral.
		if base.Assessment != withLeads.Assessment || !reflect.DeepEqual(base.Omissions, withLeads.Omissions) {
			t.Fatalf("case %d: leads changed %s into %s", cases, base.Assessment, withLeads.Assessment)
		}
		if base.ScopeCompleteness != nil {
			b, w := *base.ScopeCompleteness, *withLeads.ScopeCompleteness
			b.ContractDigest, w.ContractDigest, w.LeadRules = "", "", 0
			if !reflect.DeepEqual(b, w) {
				t.Fatalf("case %d: leads changed the scope", cases)
			}
		}
		var verdicts []Claim
		for _, claim := range withLeads.Claims {
			if claim.IsLead() {
				if claim.Status == "PASS" || claim.Status == "BLOCKED" {
					t.Fatalf("case %d: lead claim %+v", cases, claim)
				}
				continue
			}
			verdicts = append(verdicts, claim)
		}
		if !reflect.DeepEqual(base.Claims, verdicts) {
			t.Fatalf("case %d: leads changed verdict claims", cases)
		}
		for index, claim := range base.Claims {
			raw := rules[index]
			if ruleIDOf(raw) != claim.RuleID {
				t.Fatalf("case %d: claim %s is not aligned with rule %s", cases, claim.RuleID, ruleIDOf(raw))
			}
			if claim.Status == "PASS" && strings.Contains(raw, `"operator":"forbid_predicate_value"`) && strings.Contains(raw, `"appliesWhen":[{"side":"current"`) {
				guardedPass++
				if withConsensus.Claims[index].EvidenceBasis == BasisConsensus {
					guardedRelabelled++
				}
			}
		}
		tally[base.Assessment+"->"+withConsensus.Assessment]++
		cases++
	}
	t.Logf("aggregates over %d cases (%d relabelled): %v; guarded predicate PASS %d (%d relabelled)", cases, relabelled, tally, guardedPass, guardedRelabelled)
	if guardedPass == 0 || guardedRelabelled == 0 {
		t.Fatalf("no guarded predicate PASS was generated and relabelled: pass=%d relabelled=%d", guardedPass, guardedRelabelled)
	}
	for _, transition := range []string{AssessmentScopeCompletePass + "->" + AssessmentUnknown, AssessmentBlocked + "->" + AssessmentBlocked, AssessmentUnknown + "->" + AssessmentUnknown} {
		if tally[transition] == 0 {
			t.Fatalf("no case reached %s: %v", transition, tally)
		}
	}
}

func TestBasisClaimIntegrity(t *testing.T) {
	registry := scopeRegistry(t)
	consensusA := withBasis(scopeRule("rule-a-consensus", "forbid_predicate_value", scopeComponentA, "1.0.0", "2.0.0", "active", activeUntil, forbidFact(scopeComponentA, scopeFactA)), BasisConsensus)
	leadA := withBasis(scopeRule("rule-a-lead", "forbid_target_version", scopeComponentA, "1.0.0", "2.0.0", "active", activeUntil, ""), BasisLead)
	passA := scopeRule("rule-a-pass", "forbid_predicate_value", scopeComponentA, "1.0.0", "2.0.0", "active", activeUntil, forbidFact(scopeComponentA, scopeFactA))
	rules := parseBasis(t, []string{scopeComponentA}, consensusA, leadA, passA)
	input := scopeInput(t, registry, true, componentInput{Component: scopeComponentA, From: "1.0.0", To: "2.0.0", Fact: declaredFact(scopeFactA, false)})
	report, err := Evaluate(input, rules, testNow(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := MarshalReport(report); err != nil || report.Claims[0].Status != StatusNoKnownIssue || report.Claims[1].Status != StatusNotice || report.Claims[2].Status != "PASS" || report.Assessment != AssessmentUnknown {
		t.Fatalf("baseline refused: %v %+v", err, report)
	}
	clone := func(source Report) Report {
		raw, _ := json.Marshal(source)
		var copied Report
		_ = json.Unmarshal(raw, &copied)
		return copied
	}
	toPass := func(r *Report) {
		r.ScopeCompleteness.Components[0].NotEvaluated = []NotEvaluatedRule{}
		r.ScopeCompleteness.Components[0].EvaluatedRuleIDs = []string{"rule-a-consensus", "rule-a-pass"}
		r.ScopeCompleteness.Resolved, r.ScopeCompleteness.UnresolvedReason = true, ""
		r.Assessment, r.Omissions = AssessmentScopeCompletePass, requiredOmissions(AssessmentScopeCompletePass)
	}
	forgeries := map[string]func(*Report){
		"NO_KNOWN_ISSUE from a reviewed rule": func(r *Report) {
			r.Claims[2].Status, r.Claims[2].ReasonCode = StatusNoKnownIssue, ReasonConsensusNoKnownIssue
		},
		"NO_KNOWN_ISSUE from a mechanical-looking rule": func(r *Report) {
			r.Claims[0].EvidenceBasis = BasisEmpirical
		},
		"NO_KNOWN_ISSUE with another reason": func(r *Report) { r.Claims[0].ReasonCode = "FEATURE_REMOVED" },
		"NO_KNOWN_ISSUE with the lead reason": func(r *Report) {
			r.Claims[0].ReasonCode = ReasonLeadNoKnownIssue
		},
		"NO_KNOWN_ISSUE on stale evidence":    func(r *Report) { r.Claims[0].EvidenceFreshness = "stale" },
		"consensus claim as PASS":             func(r *Report) { r.Claims[0].Status, r.Claims[0].ReasonCode = "PASS", "FEATURE_REMOVED" },
		"consensus PASS counted in scope":     func(r *Report) { r.Claims[0].Status, r.Claims[0].ReasonCode = "PASS", "FEATURE_REMOVED"; toPass(r) },
		"NO_KNOWN_ISSUE counted as evaluated": toPass,
		"NO_KNOWN_ISSUE as not applicable": func(r *Report) {
			r.ScopeCompleteness.Components[0].NotEvaluated = []NotEvaluatedRule{{RuleID: "rule-a-consensus", Applicability: ApplicabilityNotApplicable, ReasonCode: "RULE_TRANSITION_NOT_REVIEWED"}}
			r.ScopeCompleteness.Resolved, r.ScopeCompleteness.UnresolvedReason = true, ""
			r.Assessment, r.Omissions = AssessmentScopeCompletePass, requiredOmissions(AssessmentScopeCompletePass)
		},
		"NO_KNOWN_ISSUE dropped from scope": func(r *Report) {
			r.ScopeCompleteness.Components[0].NotEvaluated = []NotEvaluatedRule{}
			r.ScopeCompleteness.OutOfScopeRules = 1
			r.ScopeCompleteness.Resolved, r.ScopeCompleteness.UnresolvedReason = true, ""
			r.Assessment, r.Omissions = AssessmentScopeCompletePass, requiredOmissions(AssessmentScopeCompletePass)
		},
		"unresolved reason erased": func(r *Report) {
			r.ScopeCompleteness.Resolved, r.ScopeCompleteness.UnresolvedReason = true, ""
		},
		"applicable entry on a PASS claim": func(r *Report) {
			r.ScopeCompleteness.Components[0].EvaluatedRuleIDs = []string{}
			r.ScopeCompleteness.Components[0].NotEvaluated = append(r.ScopeCompleteness.Components[0].NotEvaluated, NotEvaluatedRule{RuleID: "rule-a-pass", Applicability: ApplicabilityApplicable, ReasonCode: ReasonConsensusNoKnownIssue})
		},
		"lead claim as BLOCKED":     func(r *Report) { r.Claims[1].Status, r.Claims[1].ReasonCode = "BLOCKED", "FEATURE_REMOVED" },
		"lead claim as PASS":        func(r *Report) { r.Claims[1].Status, r.Claims[1].ReasonCode = "PASS", "FEATURE_REMOVED" },
		"lead NOTICE reason":        func(r *Report) { r.Claims[1].ReasonCode = ReasonOneWayTransition },
		"lead relabelled":           func(r *Report) { r.Claims[1].EvidenceBasis = BasisReviewed },
		"lead count dropped":        func(r *Report) { r.ScopeCompleteness.LeadRules, r.ScopeCompleteness.OutOfScopeRules = 0, 1 },
		"lead count inflated":       func(r *Report) { r.ScopeCompleteness.LeadRules = 2 },
		"NOTICE on a verdict claim": func(r *Report) { r.Claims[2].Status, r.Claims[2].ReasonCode = StatusNotice, ReasonLeadNotVerified },
		"under the notice contract": func(r *Report) {
			r.EngineContractDigest = EngineContractDigestNotice()
			r.ScopeCompleteness.ContractDigest = ScopeContractDigestNotice()
		},
		"under the exact contract": func(r *Report) {
			r.EngineContractDigest = EngineContractDigest()
			r.ScopeCompleteness.ContractDigest = ScopeContractDigest()
		},
		"basis scope under the notice contract": func(r *Report) { r.ScopeCompleteness.ContractDigest = ScopeContractDigestNotice() },
	}
	for name, forge := range forgeries {
		forged := clone(report)
		forge(&forged)
		if _, err := MarshalReport(reseal(forged)); err == nil {
			t.Fatalf("%s: forged report accepted", name)
		}
	}
	if _, err := MarshalReport(reseal(clone(report))); err != nil {
		t.Fatalf("clone refused: %v", err)
	}
	// Under an old contract, without a scope block, a NO_KNOWN_ISSUE claim
	// is refused by the claim bindings alone.
	old, err := ParseRuleSet(ruleDocumentJSON(RulesSchema, nil, passA), registry)
	if err != nil {
		t.Fatal(err)
	}
	oldReport, err := Evaluate(scopeInput(t, registry, false, componentInput{Component: scopeComponentA, From: "1.0.0", To: "2.0.0", Fact: declaredFact(scopeFactA, false)}), old, testNow(t))
	if err != nil {
		t.Fatal(err)
	}
	for name, forge := range map[string]func(*Report){
		"old contract NO_KNOWN_ISSUE": func(r *Report) {
			r.Claims[0].Status, r.Claims[0].ReasonCode = StatusNoKnownIssue, ReasonConsensusNoKnownIssue
		},
		"old contract consensus NO_KNOWN_ISSUE": func(r *Report) {
			r.Claims[0].Status, r.Claims[0].ReasonCode = StatusNoKnownIssue, ReasonConsensusNoKnownIssue
			r.Claims[0].EvidenceBasis, r.Claims[0].EvidenceDerivedAt = BasisConsensus, basisDerivedAt
		},
		"old contract consensus BLOCKED": func(r *Report) {
			r.Claims[0].Status = "BLOCKED"
			r.Claims[0].EvidenceBasis, r.Claims[0].EvidenceDerivedAt = BasisConsensus, basisDerivedAt
		},
		"old contract lead NOTICE": func(r *Report) {
			r.Claims[0].Status, r.Claims[0].ReasonCode = StatusNotice, ReasonLeadNotVerified
			r.Claims[0].EvidenceBasis, r.Claims[0].EvidenceDerivedAt = BasisLead, basisDerivedAt
		},
	} {
		forged := clone(oldReport)
		forge(&forged)
		if _, err := MarshalReport(reseal(forged)); err == nil {
			t.Fatalf("%s: forged report accepted", name)
		}
	}
	if _, err := MarshalReport(reseal(clone(oldReport))); err != nil {
		t.Fatalf("old clone refused: %v", err)
	}
}

func TestBasisLines(t *testing.T) {
	for basis, want := range map[string]string{
		"":              "evidence basis: reviewed by maintainer",
		BasisReviewed:   "evidence basis: reviewed by maintainer",
		BasisEmpirical:  "evidence basis: reproduced with upstream artifacts; may block or pass",
		BasisConsensus:  "evidence basis: two independent model readings, citations verified; may block, never passes",
		BasisLead:       "evidence basis: one unverified model reading; never blocks or passes",
		BasisMechanical: "evidence basis: derived from source by k8s-feature-gates v1.0.0",
	} {
		claim := Claim{EvidenceBasis: basis}
		if basis == BasisMechanical {
			claim.EvidenceExtractor = &Extractor{ID: "k8s-feature-gates", Version: "1.0.0", CodeDigest: testDigest}
		}
		if got := claim.EvidenceBasisLine(); got != want || len(got) > 256 {
			t.Fatalf("basis %q: %q", basis, got)
		}
	}
	consensus := func(status string) Claim { return Claim{EvidenceBasis: BasisConsensus, Status: status} }
	if _, ok := ConsensusNote([]Claim{consensus("UNKNOWN"), {Status: "BLOCKED"}, {EvidenceBasis: BasisLead, Status: StatusNotice}}); ok {
		t.Fatal("note without a consensus finding")
	}
	if note, ok := ConsensusNote([]Claim{consensus("BLOCKED")}); !ok || note != "1 finding relies on model consensus" {
		t.Fatalf("note=%q", note)
	}
	if note, ok := ConsensusNote([]Claim{consensus("BLOCKED"), consensus(StatusNoKnownIssue), consensus("UNKNOWN")}); !ok || note != "2 findings rely on model consensus" {
		t.Fatalf("note=%q", note)
	}
	long := Claim{RuleID: strings.Repeat("r", 128), EvidenceBasis: BasisLead, Status: StatusNotice, NextAction: strings.Repeat("x", 256)}
	lines, ok := long.NoticeLines()
	if !ok || len(lines) != 3 {
		t.Fatalf("lines=%q", lines)
	}
	for _, line := range lines {
		if len(line) > 256 {
			t.Fatalf("line over 256 bytes: %d", len(line))
		}
	}
}
