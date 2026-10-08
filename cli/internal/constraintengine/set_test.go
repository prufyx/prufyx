// SPDX-License-Identifier: AGPL-3.0-only

package constraintengine

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// The ranged contract identities as issued before set facts existed. Ranged
// documents must keep them so their reports keep replaying.
const (
	pinnedEngineContractDigestRanged = "sha256:162e8010c045fa731c68a5f5a187d78dc0fb4476820556c0afbc1d1b9941f2fe"
	pinnedScopeContractDigestRanged  = "sha256:6c2dd1d733a5745fa51bbd363b15d47173cb268a7cd744d7cce124f53b6d5c41"
)

const setTestFact = "component.example.feature_gates_set"

func setRegistry(t *testing.T) Registry {
	t.Helper()
	registry, err := NewRegistry([]FactDefinition{
		{ID: testFact, Component: testComponent, Type: FactBool},
		{ID: setTestFact, Component: testComponent, Type: FactSet},
	})
	if err != nil {
		t.Fatal(err)
	}
	return registry
}

func setFactJSON(members []string, complete bool) string {
	raw, _ := json.Marshal(members)
	if members == nil {
		raw = []byte("[]")
	}
	return `{"id":"` + setTestFact + `","state":"declared","setValue":{"members":` + string(raw) + `,"complete":` + boolToken(complete) + `}}`
}

func setConditionJSON(members ...string) string {
	raw, _ := json.Marshal(members)
	return `"setCondition":{"side":"proposed","component":"` + testComponent + `","factId":"` + setTestFact + `","members":` + string(raw) + `}`
}

func setRuleDocument(extra string) map[string]any {
	document := testRuleDocument(OperatorForbidSetMember, extra)
	document["schema"] = RulesSchemaSet
	return document
}

func parseSetRules(t *testing.T, registry Registry, members ...string) RuleSet {
	t.Helper()
	raw, _ := json.Marshal(setRuleDocument(setConditionJSON(members...)))
	rules, err := ParseRuleSet(raw, registry)
	if err != nil {
		t.Fatal(err)
	}
	return rules
}

func TestForbidSetMemberTruthTable(t *testing.T) {
	registry := setRegistry(t)
	rules := parseSetRules(t, registry, "RemovedGateA", "RemovedGateB")
	cases := []struct {
		name, fact, status, reason string
		matched                    []string
	}{
		{"complete without hit passes", setFactJSON([]string{"KeptGate", "OtherGate"}, true), "PASS", "FEATURE_REMOVED", nil},
		{"complete empty set passes", setFactJSON(nil, true), "PASS", "FEATURE_REMOVED", nil},
		{"complete with hit blocks", setFactJSON([]string{"KeptGate", "RemovedGateB"}, true), "BLOCKED", "FEATURE_REMOVED", []string{"RemovedGateB"}},
		{"incomplete with hit blocks", setFactJSON([]string{"RemovedGateA"}, false), "BLOCKED", "FEATURE_REMOVED", []string{"RemovedGateA"}},
		{"every hit is disclosed in order", setFactJSON([]string{"RemovedGateA", "RemovedGateB", "Zeta"}, false), "BLOCKED", "FEATURE_REMOVED", []string{"RemovedGateA", "RemovedGateB"}},
		{"incomplete without hit is unknown", setFactJSON([]string{"KeptGate"}, false), "UNKNOWN", "RULE_SET_FACT_INCOMPLETE", nil},
		{"incomplete empty set is unknown", setFactJSON(nil, false), "UNKNOWN", "RULE_SET_FACT_INCOMPLETE", nil},
		{"missing fact is unknown", `{"id":"` + setTestFact + `","state":"missing"}`, "UNKNOWN", "RULE_FACT_UNAVAILABLE", nil},
		{"unsupported fact is unknown", `{"id":"` + setTestFact + `","state":"unsupported"}`, "UNKNOWN", "RULE_FACT_UNAVAILABLE", nil},
		{"conflicting fact is unknown", `{"id":"` + setTestFact + `","state":"conflict"}`, "UNKNOWN", "RULE_FACT_UNAVAILABLE", nil},
		{"undeclared fact is unknown", "", "UNKNOWN", "RULE_FACT_UNAVAILABLE", nil},
		{"member match is case sensitive", setFactJSON([]string{"removedgatea"}, true), "PASS", "FEATURE_REMOVED", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			input := testInput(t, registry, tc.fact, "2.0.0")
			report, err := Evaluate(input, rules, testNow(t))
			if err != nil {
				t.Fatal(err)
			}
			claim := report.Claims[0]
			if claim.Status != tc.status || claim.ReasonCode != tc.reason || strings.Join(claim.MatchedMembers, ",") != strings.Join(tc.matched, ",") || (tc.matched == nil) != (claim.MatchedMembers == nil) {
				t.Fatalf("claim=%+v", claim)
			}
			if report.Assessment != AssessmentUnknown || report.EngineContractDigest != EngineContractDigestSet() || claim.Operator != OperatorForbidSetMember {
				t.Fatalf("report=%+v", report)
			}
			if len(claim.RequiredFacts) != 1 || claim.RequiredFacts[0].FactID != setTestFact || claim.RequiredFacts[0].Side != "proposed" {
				t.Fatalf("required facts=%+v", claim.RequiredFacts)
			}
			raw, err := MarshalReport(report)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(raw), "KeptGate") || strings.Contains(string(raw), "OtherGate") || strings.Contains(string(raw), "Zeta") {
				t.Fatalf("report disclosed a declared member the rule does not forbid: %s", raw)
			}
			if tc.matched == nil && strings.Contains(string(raw), "matchedMembers") {
				t.Fatalf("non-blocking claim carried matched members: %s", raw)
			}
			if !publicText(claim.NextAction) {
				t.Fatalf("next action is not bounded public text: %q", claim.NextAction)
			}
			if _, err := Replay(input, rules, testNow(t), raw); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// TestSetFactsNeverDecideOtherOperators: a set fact is legal only for
// forbid_set_member; it can neither guard applicability nor serve as a
// predicate condition.
func TestSetFactsNeverDecideOtherOperators(t *testing.T) {
	registry := setRegistry(t)
	for name, document := range map[string]map[string]any{
		"predicate on set fact":     testRuleDocument("forbid_predicate_value", `"condition":{"side":"proposed","component":"`+testComponent+`","factId":"`+setTestFact+`","boolValue":true}`),
		"applicability on set fact": testRuleDocument("forbid_target_version", `"appliesWhen":[{"side":"proposed","component":"`+testComponent+`","factId":"`+setTestFact+`","boolValue":true}]`),
	} {
		for _, schema := range []string{RulesSchema, RulesSchemaSet} {
			document["schema"] = schema
			raw, _ := json.Marshal(document)
			if _, err := ParseRuleSet(raw, registry); !errors.Is(err, ErrInvalid) {
				t.Fatalf("%s under %s accepted: %v", name, schema, err)
			}
		}
	}
}

func TestSetInputStrictParse(t *testing.T) {
	registry := setRegistry(t)
	long := strings.Repeat("a", MaxSetMemberBytes+1)
	tooMany := make([]string, 0, MaxSetMembers+1)
	for index := 0; index <= MaxSetMembers; index++ {
		tooMany = append(tooMany, "gate"+strings.Repeat("0", 4-len(itoa(index)))+itoa(index))
	}
	maximum := tooMany[:MaxSetMembers]
	accepted := []string{
		setFactJSON(nil, true),
		setFactJSON([]string{"A", "B", "a"}, false),
		setFactJSON([]string{strings.Repeat("a", MaxSetMemberBytes), "spec.template/x_y-z"}, true),
		setFactJSON(maximum, true),
	}
	for _, fact := range accepted {
		raw := `{"schema":"` + InputSchema + `","authority":"` + InputAuthority + `","current":{"components":[]},"proposed":{"components":[{"component":"` + testComponent + `","version":"2.0.0","facts":[` + fact + `]}]}}`
		if _, err := ParseInput([]byte(raw), registry); err != nil {
			t.Fatalf("valid set rejected: %.120s: %v", fact, err)
		}
	}
	rejected := map[string]string{
		"unsorted":                 setFactJSON([]string{"b", "a"}, true),
		"duplicate":                setFactJSON([]string{"a", "a"}, true),
		"empty member":             setFactJSON([]string{""}, true),
		"member with space":        setFactJSON([]string{"a b"}, true),
		"member with equals":       setFactJSON([]string{"Gate=true"}, true),
		"member with comma":        setFactJSON([]string{"A,B"}, true),
		"leading dash":             setFactJSON([]string{"-flag"}, true),
		"leading dot":              setFactJSON([]string{".x"}, true),
		"non-ascii member":         setFactJSON([]string{"gaté"}, true),
		"member too long":          setFactJSON([]string{long}, true),
		"too many members":         setFactJSON(tooMany, true),
		"members null":             `{"id":"` + setTestFact + `","state":"declared","setValue":{"members":null,"complete":true}}`,
		"members missing":          `{"id":"` + setTestFact + `","state":"declared","setValue":{"complete":true}}`,
		"complete missing":         `{"id":"` + setTestFact + `","state":"declared","setValue":{"members":[]}}`,
		"complete not bool":        `{"id":"` + setTestFact + `","state":"declared","setValue":{"members":[],"complete":"true"}}`,
		"member not string":        `{"id":"` + setTestFact + `","state":"declared","setValue":{"members":[1],"complete":true}}`,
		"unknown set field":        `{"id":"` + setTestFact + `","state":"declared","setValue":{"members":[],"complete":true,"partial":false}}`,
		"aliased set field":        `{"id":"` + setTestFact + `","state":"declared","setValue":{"Members":[],"complete":true}}`,
		"aliased value field":      `{"id":"` + setTestFact + `","state":"declared","SetValue":{"members":[],"complete":true}}`,
		"set value null":           `{"id":"` + setTestFact + `","state":"declared","setValue":null}`,
		"set value not object":     `{"id":"` + setTestFact + `","state":"declared","setValue":[]}`,
		"declared without value":   `{"id":"` + setTestFact + `","state":"declared"}`,
		"bool value on set fact":   `{"id":"` + setTestFact + `","state":"declared","boolValue":true}`,
		"enum value on set fact":   `{"id":"` + setTestFact + `","state":"declared","enumValue":"x"}`,
		"set and bool values":      `{"id":"` + setTestFact + `","state":"declared","boolValue":true,"setValue":{"members":[],"complete":true}}`,
		"set value on bool fact":   `{"id":"` + testFact + `","state":"declared","setValue":{"members":[],"complete":true}}`,
		"set value with missing":   `{"id":"` + setTestFact + `","state":"missing","setValue":{"members":[],"complete":true}}`,
		"set value with conflict":  `{"id":"` + setTestFact + `","state":"conflict","setValue":{"members":[],"complete":false}}`,
		"unregistered set fact id": `{"id":"component.example.flags_set","state":"declared","setValue":{"members":[],"complete":true}}`,
	}
	for name, fact := range rejected {
		raw := `{"schema":"` + InputSchema + `","authority":"` + InputAuthority + `","current":{"components":[]},"proposed":{"components":[{"component":"` + testComponent + `","version":"2.0.0","facts":[` + fact + `]}]}}`
		if _, err := ParseInput([]byte(raw), registry); !errors.Is(err, ErrInvalid) {
			t.Fatalf("%s accepted: %v", name, err)
		}
	}
}

func TestSetRuleStrictParse(t *testing.T) {
	registry := setRegistry(t)
	tooMany := make([]string, 0, MaxForbiddenMembers+1)
	for index := 0; index <= MaxForbiddenMembers; index++ {
		tooMany = append(tooMany, "gate"+strings.Repeat("0", 4-len(itoa(index)))+itoa(index))
	}
	if raw, _ := json.Marshal(setRuleDocument(setConditionJSON(tooMany[:MaxForbiddenMembers]...))); true {
		if _, err := ParseRuleSet(raw, registry); err != nil {
			t.Fatalf("maximum forbidden members rejected: %v", err)
		}
	}
	condition := func(body string) string { return `"setCondition":{` + body + `}` }
	base := `"side":"proposed","component":"` + testComponent + `","factId":"` + setTestFact + `"`
	rejected := map[string]map[string]any{
		"empty member list":          setRuleDocument(condition(base + `,"members":[]`)),
		"members null":               setRuleDocument(condition(base + `,"members":null`)),
		"members missing":            setRuleDocument(condition(base)),
		"unsorted members":           setRuleDocument(setConditionJSON("b", "a")),
		"duplicate members":          setRuleDocument(setConditionJSON("a", "a")),
		"invalid member":             setRuleDocument(setConditionJSON("Gate=false")),
		"empty member":               setRuleDocument(setConditionJSON("")),
		"member too long":            setRuleDocument(setConditionJSON(strings.Repeat("g", MaxSetMemberBytes+1))),
		"too many members":           setRuleDocument(setConditionJSON(tooMany...)),
		"member not string":          setRuleDocument(condition(base + `,"members":[true]`)),
		"unknown condition field":    setRuleDocument(condition(base + `,"members":["a"],"complete":true`)),
		"aliased condition field":    setRuleDocument(condition(`"side":"proposed","component":"` + testComponent + `","FactId":"` + setTestFact + `","members":["a"]`)),
		"bool value in condition":    setRuleDocument(condition(base + `,"members":["a"],"boolValue":true`)),
		"bad side":                   setRuleDocument(condition(`"side":"both","component":"` + testComponent + `","factId":"` + setTestFact + `","members":["a"]`)),
		"wrong component":            setRuleDocument(condition(`"side":"proposed","component":"pkg:oci/example/other","factId":"` + setTestFact + `","members":["a"]`)),
		"bool fact":                  setRuleDocument(condition(`"side":"proposed","component":"` + testComponent + `","factId":"` + testFact + `","members":["a"]`)),
		"unregistered fact":          setRuleDocument(condition(`"side":"proposed","component":"` + testComponent + `","factId":"component.example.flags_set","members":["a"]`)),
		"set condition null":         setRuleDocument(`"setCondition":null`),
		"operator without condition": setRuleDocument(""),
		"operator with predicate":    setRuleDocument(setConditionJSON("a") + `,"condition":{"side":"proposed","component":"` + testComponent + `","factId":"` + testFact + `","boolValue":true}`),
		"operator with dependency":   setRuleDocument(setConditionJSON("a") + `,"dependency":{"side":"proposed","component":"` + testComponent + `","comparison":"eq","version":"2.0.0"}`),
		"operator with intermediate": setRuleDocument(setConditionJSON("a") + `,"intermediate":"1.5.0"`),
		"set condition on predicate": func() map[string]any {
			document := testRuleDocument("forbid_predicate_value", setConditionJSON("a")+`,"condition":{"side":"proposed","component":"`+testComponent+`","factId":"`+testFact+`","boolValue":true}`)
			document["schema"] = RulesSchemaSet
			return document
		}(),
		"set condition on target": func() map[string]any {
			document := testRuleDocument("forbid_target_version", setConditionJSON("a"))
			document["schema"] = RulesSchemaSet
			return document
		}(),
		// Under the schema the operator itself selects, a set condition is
		// still refused on any other operator.
		"set condition on predicate, exact schema": testRuleDocument("forbid_predicate_value", setConditionJSON("a")+`,"condition":{"side":"proposed","component":"`+testComponent+`","factId":"`+testFact+`","boolValue":true}`),
		"set condition on target, exact schema":    testRuleDocument("forbid_target_version", setConditionJSON("a")),
		"exact schema with set rule": func() map[string]any {
			document := setRuleDocument(setConditionJSON("a"))
			document["schema"] = RulesSchema
			return document
		}(),
		"ranged schema with set rule": func() map[string]any {
			document := setRuleDocument(setConditionJSON("a"))
			document["schema"] = RulesSchemaRanged
			return document
		}(),
		"set schema without set rule": func() map[string]any {
			document := testRuleDocument("forbid_target_version", "")
			document["schema"] = RulesSchemaSet
			return document
		}(),
		"unknown schema": func() map[string]any {
			document := setRuleDocument(setConditionJSON("a"))
			document["schema"] = "prufyx.io/deterministic-constraint-rules/v1alpha4"
			return document
		}(),
		"oversized next action": func() map[string]any {
			document := setRuleDocument(setConditionJSON("a"))
			document["rules"].([]any)[0].(map[string]any)["nextAction"] = strings.Repeat("x", maxStringBytes+1)
			return document
		}(),
	}
	for name, document := range rejected {
		raw, _ := json.Marshal(document)
		if _, err := ParseRuleSet(raw, registry); !errors.Is(err, ErrInvalid) {
			t.Fatalf("%s accepted: %v", name, err)
		}
	}
	if _, err := NewRegistry([]FactDefinition{{ID: setTestFact, Component: testComponent, Type: FactSet, EnumTokens: []string{"a"}}}); !errors.Is(err, ErrInvalid) {
		t.Fatal("set fact with enum tokens accepted")
	}
}

func TestSetContractIsSeparateAndExistingContractsArePinned(t *testing.T) {
	if EngineContractDigest() != pinnedEngineContractDigest || ScopeContractDigest() != pinnedScopeContractDigest || EngineContractDigestRanged() != pinnedEngineContractDigestRanged || ScopeContractDigestRanged() != pinnedScopeContractDigestRanged {
		t.Fatalf("existing contract identity changed: %s %s %s %s", EngineContractDigest(), ScopeContractDigest(), EngineContractDigestRanged(), ScopeContractDigestRanged())
	}
	set := EngineContractDigestSet()
	if !digestRE.MatchString(set) || set == EngineContractDigest() || set == EngineContractDigestRanged() || scopeDigestFor(set) != ScopeContractDigestRanged() {
		t.Fatalf("set contract identity %s is not distinct and paired", set)
	}
	// The contract text binds the bounds the parser enforces.
	if setMemberPolicy != "set-members:max="+itoa(MaxSetMembers)+";member-bytes="+itoa(MaxSetMemberBytes)+";forbidden-per-rule="+itoa(MaxForbiddenMembers)+";pattern="+setMemberRE.String() {
		t.Fatalf("set member policy %q does not state the enforced bounds", setMemberPolicy)
	}
	// Exact and ranged documents keep their own contracts.
	exact := testRules(t, setRegistry(t), "forbid_target_version", "")
	report, err := Evaluate(testInput(t, setRegistry(t), "", "2.0.0"), exact, testNow(t))
	if err != nil || report.EngineContractDigest != pinnedEngineContractDigest {
		t.Fatalf("exact report contract=%s err=%v", report.EngineContractDigest, err)
	}
}

// TestSetRulesAcceptRangesAndCheckOverlapsByMember: a set document may carry
// ranges; overlapping set rules on one fact are legal when they forbid
// disjoint members and refused when they share one.
func TestSetRulesAcceptRangesAndCheckOverlapsByMember(t *testing.T) {
	registry, err := NewRegistry([]FactDefinition{{ID: "component.alpha.feature_gates_set", Component: scopeComponentA, Type: FactSet}})
	if err != nil {
		t.Fatal(err)
	}
	setRule := func(id, members string) string {
		spec := defaultRangeSpec()
		spec.id, spec.operator = id, OperatorForbidSetMember
		spec.extra = `,"setCondition":{"side":"proposed","component":"` + scopeComponentA + `","factId":"component.alpha.feature_gates_set","members":[` + members + `]}`
		return spec.ruleJSON()
	}
	disjoint := rangeDocument(RulesSchemaSet, false, setRule("gate-a", `"GateA"`), setRule("gate-b", `"GateB"`))
	rules, err := ParseRuleSet(disjoint, registry)
	if err != nil {
		t.Fatalf("disjoint set rules refused: %v", err)
	}
	input := scopeInput(t, registry, false, componentInput{Component: scopeComponentA, From: "1.24.17", To: "1.25.3", Fact: `{"id":"component.alpha.feature_gates_set","state":"declared","setValue":{"members":["GateB"],"complete":true}}`})
	report, err := Evaluate(input, rules, testNow(t))
	if err != nil || report.Claims[0].Status != "PASS" || report.Claims[1].Status != "BLOCKED" || report.Claims[1].SubjectMatch == nil || report.EngineContractDigest != EngineContractDigestSet() {
		t.Fatalf("report=%+v err=%v", report, err)
	}
	if _, err := MarshalReport(report); err != nil {
		t.Fatal(err)
	}
	shared := rangeDocument(RulesSchemaSet, false, setRule("gate-a", `"GateA","GateC"`), setRule("gate-b", `"GateB","GateC"`))
	if _, err := ParseRuleSet(shared, registry); !errors.Is(err, ErrInvalid) {
		t.Fatalf("overlapping set rules sharing a member accepted: %v", err)
	}
	ranged := rangeDocument(RulesSchemaRanged, false, setRule("gate-a", `"GateA"`))
	if _, err := ParseRuleSet(ranged, registry); !errors.Is(err, ErrInvalid) {
		t.Fatal("ranged schema admitted a set rule")
	}
}

// TestSetScopeCompleteness: a complete set without a hit counts as an
// evaluated rule; an incomplete one is UNDETERMINED and holds the aggregate
// at UNKNOWN; a hit is a blocker even on an incomplete set.
func TestSetScopeCompleteness(t *testing.T) {
	registry, err := NewRegistry([]FactDefinition{{ID: "component.alpha.feature_gates_set", Component: scopeComponentA, Type: FactSet}})
	if err != nil {
		t.Fatal(err)
	}
	spec := defaultRangeSpec()
	spec.operator, spec.noRange = OperatorForbidSetMember, true
	spec.extra = `,"setCondition":{"side":"proposed","component":"` + scopeComponentA + `","factId":"component.alpha.feature_gates_set","members":["GateA"]}`
	rules, err := ParseRuleSet(rangeDocument(RulesSchemaSet, true, spec.ruleJSON()), registry)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		members    string
		complete   bool
		assessment string
	}{
		{`"GateB"`, true, AssessmentScopeCompletePass},
		{`"GateB"`, false, AssessmentUnknown},
		{`"GateA"`, false, AssessmentBlocked},
		{`"GateA"`, true, AssessmentBlocked},
	} {
		fact := `{"id":"component.alpha.feature_gates_set","state":"declared","setValue":{"members":[` + tc.members + `],"complete":` + boolToken(tc.complete) + `}}`
		report, err := Evaluate(scopeInput(t, registry, true, componentInput{Component: scopeComponentA, From: "1.24.0", To: "1.25.0", Fact: fact}), rules, testNow(t))
		if err != nil || report.Assessment != tc.assessment {
			t.Fatalf("members=%s complete=%v report=%+v err=%v", tc.members, tc.complete, report, err)
		}
		if _, err := MarshalReport(report); err != nil {
			t.Fatal(err)
		}
		if tc.assessment == AssessmentUnknown {
			skipped := report.ScopeCompleteness.Components[0].NotEvaluated
			if len(skipped) != 1 || skipped[0].Applicability != ApplicabilityUndetermined || skipped[0].ReasonCode != reasonSetFactIncomplete {
				t.Fatalf("not evaluated=%+v", skipped)
			}
		}
	}
}

// TestForgedSetReportsAreRefused: matched members appear only on a BLOCKED
// forbid_set_member claim, and that operator only under the set contract.
func TestForgedSetReportsAreRefused(t *testing.T) {
	registry := setRegistry(t)
	rules := parseSetRules(t, registry, "RemovedGateA")
	blocked, err := Evaluate(testInput(t, registry, setFactJSON([]string{"RemovedGateA"}, true), "2.0.0"), rules, testNow(t))
	if err != nil {
		t.Fatal(err)
	}
	passed, err := Evaluate(testInput(t, registry, setFactJSON(nil, true), "2.0.0"), rules, testNow(t))
	if err != nil {
		t.Fatal(err)
	}
	forge := func(report Report, mutate func(*Report)) Report {
		copy := report
		copy.Claims = append([]Claim(nil), report.Claims...)
		mutate(&copy)
		return issueReport(copy)
	}
	for name, forged := range map[string]Report{
		"blocked without members":    forge(blocked, func(r *Report) { r.Claims[0].MatchedMembers = nil }),
		"blocked with empty members": forge(blocked, func(r *Report) { r.Claims[0].MatchedMembers = []string{} }),
		"invalid matched member":     forge(blocked, func(r *Report) { r.Claims[0].MatchedMembers = []string{"Gate=true"} }),
		"unsorted matched members":   forge(blocked, func(r *Report) { r.Claims[0].MatchedMembers = []string{"b", "a"} }),
		"pass with members":          forge(passed, func(r *Report) { r.Claims[0].MatchedMembers = []string{"RemovedGateA"} }),
		"members on other operator":  forge(blocked, func(r *Report) { r.Claims[0].Operator = "forbid_predicate_value" }),
		"set claim under ranged":     forge(blocked, func(r *Report) { r.EngineContractDigest = EngineContractDigestRanged() }),
		"set claim under exact":      forge(passed, func(r *Report) { r.EngineContractDigest = EngineContractDigest() }),
	} {
		if _, err := MarshalReport(forged); !errors.Is(err, ErrIntegrity) {
			t.Fatalf("%s published", name)
		}
	}
	for _, report := range []Report{blocked, passed} {
		if _, err := MarshalReport(report); err != nil {
			t.Fatal(err)
		}
	}
}

func TestRulesSchemaForSelectsSetSchema(t *testing.T) {
	setRule, _ := json.Marshal(setRuleDocument(setConditionJSON("a"))["rules"].([]any)[0])
	exactRule, _ := json.Marshal(testRuleDocument("forbid_target_version", "")["rules"].([]any)[0])
	for name, tc := range map[string]struct {
		rules []json.RawMessage
		want  string
	}{
		"exact only":      {[]json.RawMessage{exactRule}, RulesSchema},
		"set rule":        {[]json.RawMessage{exactRule, setRule}, RulesSchemaSet},
		"set with range":  {[]json.RawMessage{json.RawMessage(defaultRangeSpec().ruleJSON()), setRule}, RulesSchemaSet},
		"operator alone":  {[]json.RawMessage{json.RawMessage(`{"operator":"forbid_set_member"}`)}, RulesSchemaSet},
		"condition alone": {[]json.RawMessage{json.RawMessage(`{"setCondition":{}}`)}, RulesSchemaSet},
	} {
		got, err := RulesSchemaFor(tc.rules)
		if err != nil || got != tc.want {
			t.Fatalf("%s: schema=%s err=%v", name, got, err)
		}
	}
}

// TestInputsAndClaimsWithoutSetsAreByteIdentical: the new optional fields are
// omitted when unused, so existing inputs, rules and claims marshal as
// before.
func TestInputsAndClaimsWithoutSetsAreByteIdentical(t *testing.T) {
	fact, _ := json.Marshal(inputFact{ID: testFact, State: "missing"})
	claim, _ := json.Marshal(Claim{})
	ruleRaw, _ := json.Marshal(rule{})
	for _, raw := range [][]byte{fact, claim, ruleRaw} {
		if strings.Contains(string(raw), "setValue") || strings.Contains(string(raw), "matchedMembers") || strings.Contains(string(raw), "setCondition") {
			t.Fatalf("unused set field serialized: %s", raw)
		}
	}
	empty, _ := json.Marshal(inputFact{ID: setTestFact, State: "declared", SetValue: &SetValue{Members: []string{}, Complete: true}})
	if string(empty) != `{"id":"`+setTestFact+`","state":"declared","setValue":{"members":[],"complete":true}}` {
		t.Fatalf("empty set serialized as %s", empty)
	}
}

func itoa(value int) string {
	raw, _ := json.Marshal(value)
	return string(raw)
}

// TestValidateFactRefusesMixedValuesBehindTheShapeGate checks the typed
// validator on its own: the shape gate already refuses these documents, and
// the validator must refuse them as well.
func TestValidateFactRefusesMixedValuesBehindTheShapeGate(t *testing.T) {
	registry, err := NewRegistry([]FactDefinition{
		{ID: testFact, Component: testComponent, Type: FactBool},
		{ID: "component.example.mode", Component: testComponent, Type: FactEnum, EnumTokens: []string{"a"}},
		{ID: setTestFact, Component: testComponent, Type: FactSet},
	})
	if err != nil {
		t.Fatal(err)
	}
	yes, set := true, &SetValue{Members: []string{}, Complete: true}
	for name, fact := range map[string]inputFact{
		"bool with set":         {ID: testFact, State: "declared", BoolValue: &yes, SetValue: set},
		"enum with set":         {ID: "component.example.mode", State: "declared", EnumValue: "a", SetValue: set},
		"set with bool":         {ID: setTestFact, State: "declared", BoolValue: &yes, SetValue: set},
		"set with enum":         {ID: setTestFact, State: "declared", EnumValue: "a", SetValue: set},
		"set without value":     {ID: setTestFact, State: "declared"},
		"missing with set":      {ID: setTestFact, State: "missing", SetValue: set},
		"unsupported with set":  {ID: setTestFact, State: "unsupported", SetValue: set},
		"set with null members": {ID: setTestFact, State: "declared", SetValue: &SetValue{Complete: true}},
	} {
		err := validateFact(fact, testComponent, registry)
		if name == "set with null members" {
			// A nil member list is the empty set; the shape gate is what
			// refuses a JSON null.
			if err != nil {
				t.Fatalf("%s refused: %v", name, err)
			}
			continue
		}
		if err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
}

// TestSetOverlapsAreKeyedByFact: set rules on different facts (or sides) may
// forbid the same member in overlapping ranges.
func TestSetOverlapsAreKeyedByFact(t *testing.T) {
	registry, err := NewRegistry([]FactDefinition{
		{ID: "component.alpha.kubelet_feature_gates_set", Component: scopeComponentA, Type: FactSet},
		{ID: "component.alpha.apiserver_feature_gates_set", Component: scopeComponentA, Type: FactSet},
	})
	if err != nil {
		t.Fatal(err)
	}
	setRule := func(id, side, fact string) string {
		spec := defaultRangeSpec()
		spec.id, spec.operator = id, OperatorForbidSetMember
		spec.extra = `,"setCondition":{"side":"` + side + `","component":"` + scopeComponentA + `","factId":"` + fact + `","members":["GateA"]}`
		return spec.ruleJSON()
	}
	for name, document := range map[string][]byte{
		"different facts": rangeDocument(RulesSchemaSet, false, setRule("gate-a", "proposed", "component.alpha.apiserver_feature_gates_set"), setRule("gate-b", "proposed", "component.alpha.kubelet_feature_gates_set")),
		"different sides": rangeDocument(RulesSchemaSet, false, setRule("gate-a", "current", "component.alpha.kubelet_feature_gates_set"), setRule("gate-b", "proposed", "component.alpha.kubelet_feature_gates_set")),
	} {
		if _, err := ParseRuleSet(document, registry); err != nil {
			t.Fatalf("%s refused: %v", name, err)
		}
	}
}

// TestSetEvaluationReadsOnlyDeclaredFacts checks the evaluator on its own: a
// set value carried by a fact in any state but declared is never read. The
// parser already refuses such input.
func TestSetEvaluationReadsOnlyDeclaredFacts(t *testing.T) {
	condition := setCondition{Side: "proposed", Component: testComponent, FactID: setTestFact, Members: []string{"RemovedGate"}}
	r := rule{ID: "example-rule", Operator: OperatorForbidSetMember, SetCondition: &condition, ReasonCode: "FEATURE_REMOVED", NextAction: "act"}
	for _, state := range []string{"missing", "unsupported", "conflict"} {
		input := inputDocument{Proposed: inputSide{Components: []inputComponent{{Component: testComponent, Version: "2.0.0", Facts: []inputFact{{ID: setTestFact, State: state, SetValue: &SetValue{Members: []string{}, Complete: true}}}}}}}
		claim := evaluateSetRule(input, r, Claim{})
		if claim.Status != "UNKNOWN" || claim.ReasonCode != "RULE_FACT_UNAVAILABLE" {
			t.Fatalf("%s: claim=%+v", state, claim)
		}
	}
}

// TestFactValuePresenceIsExactlyOne checks the shape gate on its own: a
// declared fact carries exactly one value field, any other state none.
func TestFactValuePresenceIsExactlyOne(t *testing.T) {
	for raw, want := range map[string]bool{
		`{"state":"declared","setValue":{}}`:                    true,
		`{"state":"declared","boolValue":true}`:                 true,
		`{"state":"declared"}`:                                  false,
		`{"state":"declared","boolValue":true,"setValue":{}}`:   false,
		`{"state":"declared","enumValue":"a","setValue":{}}`:    false,
		`{"state":"declared","boolValue":true,"enumValue":"a"}`: false,
		`{"state":"missing","setValue":{}}`:                     false,
		`{"state":"missing"}`:                                   true,
	} {
		var fact map[string]json.RawMessage
		if err := json.Unmarshal([]byte(raw), &fact); err != nil {
			t.Fatal(err)
		}
		if validFactValuePresence(fact) != want {
			t.Fatalf("%s: presence=%v", raw, !want)
		}
	}
}
