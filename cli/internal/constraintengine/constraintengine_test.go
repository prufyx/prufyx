// SPDX-License-Identifier: AGPL-3.0-only

package constraintengine

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

const (
	testComponent = "pkg:oci/example/controller"
	testFact      = "component.example.feature_enabled"
	testRevision  = "0123456789abcdef0123456789abcdef01234567"
	testDigest    = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
)

func TestForbidPredicateTriStateAndAlwaysUnknownAggregate(t *testing.T) {
	registry := testRegistry(t)
	rules := testRules(t, registry, "forbid_predicate_value", "\"condition\":{\"side\":\"proposed\",\"component\":\"pkg:oci/example/controller\",\"factId\":\"component.example.feature_enabled\",\"boolValue\":true}")
	now := testNow(t)
	for name, fact := range map[string]string{
		"pass":    `{"id":"component.example.feature_enabled","state":"declared","boolValue":false}`,
		"blocked": `{"id":"component.example.feature_enabled","state":"declared","boolValue":true}`,
		"unknown": `{"id":"component.example.feature_enabled","state":"missing"}`,
	} {
		t.Run(name, func(t *testing.T) {
			input := testInput(t, registry, fact, "2.0.0")
			report, err := Evaluate(input, rules, now)
			if err != nil {
				t.Fatal(err)
			}
			if report.Assessment != "UNKNOWN" || report.Claims[0].Status != map[string]string{"pass": "PASS", "blocked": "BLOCKED", "unknown": "UNKNOWN"}[name] {
				t.Fatalf("report=%+v", report)
			}
			raw, err := MarshalReport(report)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(raw), "boolValue") || strings.Contains(string(raw), "operator-declared-private") {
				t.Fatalf("report leaked minimized input: %s", raw)
			}
			if _, err := Replay(input, rules, now, raw); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestClosedOperatorsAndUnknownTransition(t *testing.T) {
	registry := testRegistry(t)
	now := testNow(t)
	cases := []struct{ name, operator, extra, want string }{
		{"dependency-pass", "require_component_version", `"dependency":{"side":"proposed","component":"pkg:oci/example/controller","comparison":"eq","version":"2.0.0"}`, "PASS"},
		{"dependency-minimum", "require_component_version", `"dependency":{"side":"proposed","component":"pkg:oci/example/controller","comparison":"gte","version":"1.5.0"}`, "PASS"},
		{"dependency-maximum", "require_component_version", `"dependency":{"side":"proposed","component":"pkg:oci/example/controller","comparison":"lt","version":"1.30.0"}`, "BLOCKED"},
		{"intermediate", "require_intermediate_version", `"intermediate":"1.5.0"`, "BLOCKED"},
		{"target", "forbid_target_version", ``, "BLOCKED"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rules := testRules(t, registry, tc.operator, tc.extra)
			report, err := Evaluate(testInput(t, registry, `{"id":"component.example.feature_enabled","state":"declared","boolValue":false}`, "2.0.0"), rules, now)
			if err != nil || report.Claims[0].Status != tc.want {
				t.Fatalf("report=%+v err=%v", report, err)
			}
		})
	}
	rules := testRules(t, registry, "forbid_target_version", ``)
	report, err := Evaluate(testInput(t, registry, `{"id":"component.example.feature_enabled","state":"declared","boolValue":false}`, "2.1.0"), rules, now)
	if err != nil || report.Claims[0].Status != "UNKNOWN" || report.Claims[0].ReasonCode != "RULE_TRANSITION_NOT_REVIEWED" {
		t.Fatalf("report=%+v err=%v", report, err)
	}
	maximumRule := func(target string) RuleSet {
		document := testRuleDocument("require_component_version", `"dependency":{"side":"proposed","component":"pkg:oci/example/controller","comparison":"lt","version":"1.30.0"}`)
		document["rules"].([]any)[0].(map[string]any)["subject"].(map[string]any)["to"] = target
		raw, _ := json.Marshal(document)
		result, err := ParseRuleSet(raw, registry)
		if err != nil {
			t.Fatal(err)
		}
		return result
	}
	maximum := maximumRule("1.29.1")
	report, err = Evaluate(testInput(t, registry, `{"id":"component.example.feature_enabled","state":"declared","boolValue":false}`, "1.29.1"), maximum, now)
	if err != nil || report.Claims[0].Status != "PASS" {
		t.Fatalf("maximum patch boundary report=%+v err=%v", report, err)
	}
	maximum = maximumRule("1.30.0")
	report, err = Evaluate(testInput(t, registry, `{"id":"component.example.feature_enabled","state":"declared","boolValue":false}`, "1.30.0"), maximum, now)
	if err != nil || report.Claims[0].Status != "BLOCKED" {
		t.Fatalf("maximum boundary report=%+v err=%v", report, err)
	}
}

func TestEvidenceExpiryWithdrawalAndStrictInputs(t *testing.T) {
	registry := testRegistry(t)
	input := testInput(t, registry, `{"id":"component.example.feature_enabled","state":"declared","boolValue":false}`, "2.0.0")
	for _, test := range []struct {
		name, freshness string
		mutate          func(map[string]any)
	}{
		{"stale", "stale", func(r map[string]any) {
			r["rules"].([]any)[0].(map[string]any)["evidence"].(map[string]any)["validUntil"] = "2026-05-01T00:00:00Z"
		}},
		{"withdrawn", "withdrawn", func(r map[string]any) {
			r["rules"].([]any)[0].(map[string]any)["evidence"].(map[string]any)["state"] = "withdrawn"
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			document := testRuleDocument("forbid_target_version", "")
			test.mutate(document)
			raw, _ := json.Marshal(document)
			rules, err := ParseRuleSet(raw, registry)
			if err != nil {
				t.Fatal(err)
			}
			report, err := Evaluate(input, rules, testNow(t))
			if err != nil {
				t.Fatal(err)
			}
			if report.Claims[0].Status != "UNKNOWN" || report.Claims[0].EvidenceFreshness != test.freshness {
				t.Fatalf("claim=%+v", report.Claims[0])
			}
		})
	}
	for name, raw := range map[string]string{
		"unknown-field": `{"schema":"` + InputSchema + `","authority":"` + InputAuthority + `","current":{"components":[],"extra":true},"proposed":{"components":[]}}`,
		"duplicate":     `{"schema":"` + InputSchema + `","schema":"` + InputSchema + `","authority":"` + InputAuthority + `","current":{"components":[]},"proposed":{"components":[]}}`,
		"raw-string":    `{"schema":"` + InputSchema + `","authority":"` + InputAuthority + `","current":{"components":[]},"proposed":{"components":[{"component":"pkg:oci/example/controller","version":"2.0.0","facts":[{"id":"component.example.feature_enabled","state":"declared","enumValue":"secret"}]}]}}`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseInput([]byte(raw), registry); !errors.Is(err, ErrInvalid) {
				t.Fatalf("err=%v", err)
			}
		})
	}
	valid := `{"schema":"` + InputSchema + `","authority":"` + InputAuthority + `","current":{"components":[]},"proposed":{"components":[{"component":"pkg:oci/example/controller","version":"2.0.0","facts":[{"id":"component.example.feature_enabled","state":"declared","boolValue":true}]}]}}`
	if _, err := ParseInput([]byte(valid), EmptyRegistry()); !errors.Is(err, ErrInvalid) {
		t.Fatalf("empty compiled registry accepted an unreviewed fact: %v", err)
	}
	badRule := testRuleDocument("forbid_target_version", "")
	badRule["rules"].([]any)[0].(map[string]any)["evidence"].(map[string]any)["sources"].([]any)[0].(map[string]any)["url"] = "https://github.com/example/controller/blob/main/docs/upgrade.md"
	badRaw, _ := json.Marshal(badRule)
	if _, err := ParseRuleSet(badRaw, registry); !errors.Is(err, ErrInvalid) {
		t.Fatalf("mutable source URL accepted: %v", err)
	}
}

func TestImmutableGitURLAllowsOnlyPublicDotGitHubSegment(t *testing.T) {
	workflow := "https://github.com/example/controller/blob/" + testRevision + "/.github/workflows/review.yml"
	if !immutableGitURL(workflow, testRevision) {
		t.Fatal("immutable public workflow URL rejected")
	}
	private := "https://github.com/example/controller/blob/" + testRevision + "/.private/workflows/review.yml"
	if immutableGitURL(private, testRevision) {
		t.Fatal("non-public dot-prefixed path accepted")
	}
}

func TestFactAndConditionValuePresenceIsExact(t *testing.T) {
	registry := testRegistry(t)
	for _, state := range []string{"missing", "unsupported", "conflict"} {
		raw := `{"schema":"` + InputSchema + `","authority":"` + InputAuthority + `","current":{"components":[]},"proposed":{"components":[{"component":"` + testComponent + `","version":"2.0.0","facts":[{"id":"` + testFact + `","state":"` + state + `","enumValue":""}]}]}}`
		if _, err := ParseInput([]byte(raw), registry); !errors.Is(err, ErrInvalid) {
			t.Errorf("state %s accepted empty enum field: %v", state, err)
		}
	}
	for name, fact := range map[string]string{
		"declared-both":     `{"id":"` + testFact + `","state":"declared","boolValue":false,"enumValue":""}`,
		"declared-enum":     `{"id":"` + testFact + `","state":"declared","enumValue":""}`,
		"declared-no-value": `{"id":"` + testFact + `","state":"declared"}`,
	} {
		raw := `{"schema":"` + InputSchema + `","authority":"` + InputAuthority + `","current":{"components":[]},"proposed":{"components":[{"component":"` + testComponent + `","version":"2.0.0","facts":[` + fact + `]}]}}`
		if _, err := ParseInput([]byte(raw), registry); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s accepted ambiguous fact value: %v", name, err)
		}
	}
	valid := testInput(t, registry, `{"id":"`+testFact+`","state":"declared","boolValue":false}`, "2.0.0")
	rules := testRules(t, registry, "forbid_predicate_value", `"condition":{"side":"proposed","component":"`+testComponent+`","factId":"`+testFact+`","boolValue":true}`)
	report, err := Evaluate(valid, rules, testNow(t))
	if err != nil || report.Claims[0].Status != "PASS" {
		t.Fatalf("valid declared false changed behavior: report=%+v err=%v", report, err)
	}
	for name, condition := range map[string]string{
		"both":    `"boolValue":false,"enumValue":""`,
		"neither": ``,
	} {
		if condition != "" {
			condition = "," + condition
		}
		conditionJSON := `{"side":"proposed","component":"` + testComponent + `","factId":"` + testFact + `"` + condition + `}`
		if !json.Valid([]byte(conditionJSON)) {
			t.Fatal("regression fixture must be valid JSON")
		}
		document := testRuleDocument("forbid_predicate_value", `"condition":`+conditionJSON)
		raw, err := json.Marshal(document)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ParseRuleSet(raw, registry); !errors.Is(err, ErrInvalid) {
			t.Errorf("condition %s accepted ambiguous value presence: %v", name, err)
		}
		document = testRuleDocument("forbid_target_version", `"appliesWhen":[`+conditionJSON+`]`)
		raw, err = json.Marshal(document)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ParseRuleSet(raw, registry); !errors.Is(err, ErrInvalid) {
			t.Errorf("guard %s accepted ambiguous value presence: %v", name, err)
		}
	}
}

func TestRegistryOwnerExactKeysAndClockContracts(t *testing.T) {
	registry := testRegistry(t)
	for name, raw := range map[string]string{
		"case-alias":       `{"schema":"` + InputSchema + `","Authority":"` + InputAuthority + `","current":{"components":[]},"proposed":{"components":[]}}`,
		"null-current":     `{"schema":"` + InputSchema + `","authority":"` + InputAuthority + `","current":null,"proposed":{"components":[]}}`,
		"wrong-owner":      `{"schema":"` + InputSchema + `","authority":"` + InputAuthority + `","current":{"components":[]},"proposed":{"components":[{"component":"pkg:oci/example/other","version":"2.0.0","facts":[{"id":"component.example.feature_enabled","state":"declared","boolValue":true}]}]}}`,
		"version-overflow": `{"schema":"` + InputSchema + `","authority":"` + InputAuthority + `","current":{"components":[]},"proposed":{"components":[{"component":"pkg:oci/example/controller","version":"4294967296.0.0","facts":[]}]}}`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseInput([]byte(raw), registry); !errors.Is(err, ErrInvalid) {
				t.Fatalf("err=%v", err)
			}
		})
	}
	secret := `{"schema":"` + InputSchema + `","authority":"` + InputAuthority + `","current":{"components":[]},"proposed":{"components":[{"component":"pkg:oci/example/controller","version":"2.0.0","facts":[{"id":"component.example.private_token","state":"declared","boolValue":true}]}]}}`
	if _, err := ParseInput([]byte(secret), registry); !errors.Is(err, ErrInvalid) || strings.Contains(err.Error(), "private_token") {
		t.Fatalf("unsafe parser error=%v", err)
	}

	input := testInput(t, registry, `{"id":"component.example.feature_enabled","state":"declared","boolValue":false}`, "2.0.0")
	rules := testRules(t, registry, "forbid_target_version", "")
	if _, err := Evaluate(input, rules, testNow(t).Add(time.Nanosecond)); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("sub-second evaluation accepted: %v", err)
	}

	other, err := NewRegistry([]FactDefinition{{ID: testFact, Component: testComponent, Type: FactEnum, EnumTokens: []string{"enabled"}}})
	if err != nil {
		t.Fatal(err)
	}
	otherRules := testRules(t, other, "forbid_target_version", "")
	if _, err := Evaluate(input, otherRules, testNow(t)); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("different registry semantics accepted: %v", err)
	}
}

func TestApplicabilityGuardProducesUnknownBeforeMainConstraint(t *testing.T) {
	registry := testRegistry(t)
	guard := `"condition":{"side":"proposed","component":"pkg:oci/example/controller","factId":"component.example.feature_enabled","boolValue":true},"appliesWhen":[{"side":"proposed","component":"pkg:oci/example/controller","factId":"component.example.feature_enabled","boolValue":true}]`
	rules := testRules(t, registry, "forbid_predicate_value", guard)
	input := testInput(t, registry, `{"id":"component.example.feature_enabled","state":"declared","boolValue":false}`, "2.0.0")
	report, err := Evaluate(input, rules, testNow(t))
	if err != nil || report.Claims[0].Status != "UNKNOWN" || report.Claims[0].ReasonCode != "RULE_APPLICABILITY_NOT_MATCHED" {
		t.Fatalf("claim=%+v err=%v", report.Claims[0], err)
	}
}

func TestDeclaredAuthorityCanonicalEvidenceAndPublicText(t *testing.T) {
	registry := testRegistry(t)
	document := testRuleDocument("forbid_target_version", "")
	source := document["rules"].([]any)[0].(map[string]any)["evidence"].(map[string]any)["sources"].([]any)[0].(map[string]any)
	for name, value := range map[string]string{
		"attacker-host": "https://attacker.example/blob/" + testRevision + "/docs/upgrade.md",
		"query":         "https://github.com/example/controller/blob/" + testRevision + "/docs/upgrade.md?x=1",
		"fragment":      "https://github.com/example/controller/blob/" + testRevision + "/docs/upgrade.md#L1",
		"userinfo":      "https://user:pass@github.com/example/controller/blob/" + testRevision + "/docs/upgrade.md",
		"port":          "https://github.com:443/example/controller/blob/" + testRevision + "/docs/upgrade.md",
		"dot-segment":   "https://github.com/example/controller/blob/" + testRevision + "/docs/../upgrade.md",
		"escaped-dot":   "https://github.com/example/controller/blob/" + testRevision + "/docs/%2e%2e/upgrade.md",
	} {
		t.Run(name, func(t *testing.T) {
			source["url"] = value
			raw, _ := json.Marshal(document)
			if _, err := ParseRuleSet(raw, registry); !errors.Is(err, ErrInvalid) {
				t.Fatalf("evidence URL accepted: %v", err)
			}
		})
	}
	var raw []byte
	source["url"] = "https://github.com/karmada-io/karmada/blob/6d7b233a54d59c8473803901768153f6e4353d02/charts/karmada/_crds/bases/policy/policy.karmada.io_propagationpolicies.yaml"
	source["revision"] = "6d7b233a54d59c8473803901768153f6e4353d02"
	raw, _ = json.Marshal(document)
	if _, err := ParseRuleSet(raw, registry); err != nil {
		t.Fatalf("underscore-leading GitHub file segment rejected: %v", err)
	}
	source["url"] = "https://raw.githubusercontent.com/karmada-io/karmada/6d7b233a54d59c8473803901768153f6e4353d02/charts/karmada/_crds/bases/policy/policy.karmada.io_propagationpolicies.yaml"
	raw, _ = json.Marshal(document)
	if _, err := ParseRuleSet(raw, registry); err != nil {
		t.Fatalf("underscore-leading raw file segment rejected: %v", err)
	}
	source["revision"] = testRevision
	source["url"] = "https://raw.githubusercontent.com/example/controller/" + testRevision + "/docs/upgrade.md"
	raw, _ = json.Marshal(document)
	rules, err := ParseRuleSet(raw, registry)
	if err != nil {
		t.Fatal(err)
	}
	report, err := Evaluate(testInput(t, registry, `{"id":"component.example.feature_enabled","state":"declared","boolValue":false}`, "2.0.0"), rules, testNow(t))
	if err != nil || report.RulesAuthority != "DECLARED_RULE_SOURCE_REFERENCES" {
		t.Fatalf("report=%+v err=%v", report, err)
	}
	document["rules"].([]any)[0].(map[string]any)["nextAction"] = "bad\x1btext"
	raw, _ = json.Marshal(document)
	if _, err := ParseRuleSet(raw, registry); !errors.Is(err, ErrInvalid) {
		t.Fatalf("control character accepted: %v", err)
	}
}

func TestRequiredFactsIncludeApplicabilityGuards(t *testing.T) {
	registry, err := NewRegistry([]FactDefinition{
		{ID: "component.example.feature_enabled", Component: testComponent, Type: FactBool},
		{ID: "component.example.guard_enabled", Component: testComponent, Type: FactBool},
	})
	if err != nil {
		t.Fatal(err)
	}
	rules := testRules(t, registry, "forbid_predicate_value", `"condition":{"side":"proposed","component":"pkg:oci/example/controller","factId":"component.example.feature_enabled","boolValue":true},"appliesWhen":[{"side":"proposed","component":"pkg:oci/example/controller","factId":"component.example.guard_enabled","boolValue":true}]`)
	raw := `{"schema":"` + InputSchema + `","authority":"` + InputAuthority + `","current":{"components":[{"component":"` + testComponent + `","version":"1.0.0","facts":[]}]},"proposed":{"components":[{"component":"` + testComponent + `","version":"2.0.0","facts":[{"id":"component.example.feature_enabled","state":"declared","boolValue":true},{"id":"component.example.guard_enabled","state":"declared","boolValue":true}]}]}}`
	input, err := ParseInput([]byte(raw), registry)
	if err != nil {
		t.Fatal(err)
	}
	report, err := Evaluate(input, rules, testNow(t))
	if err != nil {
		t.Fatal(err)
	}
	want := []RequiredFact{{Side: "proposed", Component: testComponent, FactID: "component.example.feature_enabled"}, {Side: "proposed", Component: testComponent, FactID: "component.example.guard_enabled"}}
	if len(report.Claims[0].RequiredFacts) != len(want) || report.Claims[0].RequiredFacts[0] != want[0] || report.Claims[0].RequiredFacts[1] != want[1] {
		t.Fatalf("required facts=%v", report.Claims[0].RequiredFacts)
	}
	missingRaw := strings.Replace(raw, `{"id":"component.example.guard_enabled","state":"declared","boolValue":true}`, `{"id":"component.example.guard_enabled","state":"missing"}`, 1)
	missing, err := ParseInput([]byte(missingRaw), registry)
	if err != nil {
		t.Fatal(err)
	}
	missingReport, err := Evaluate(missing, rules, testNow(t))
	if err != nil || missingReport.Claims[0].Status != "UNKNOWN" || !strings.Contains(missingReport.Claims[0].NextAction, "component.example.guard_enabled") || !strings.Contains(missingReport.Claims[0].NextAction, "missing from the input") {
		t.Fatalf("missing guard report=%+v err=%v", missingReport, err)
	}
}

func TestNextActionsRequestTruthfulLocalInspection(t *testing.T) {
	registry := testRegistry(t)
	rules := testRules(t, registry, "forbid_predicate_value", `"condition":{"side":"proposed","component":"pkg:oci/example/controller","factId":"component.example.feature_enabled","boolValue":true}`)
	input := testInput(t, registry, `{"id":"component.example.feature_enabled","state":"missing"}`, "2.0.0")
	report, err := Evaluate(input, rules, testNow(t))
	if err != nil {
		t.Fatal(err)
	}
	action := report.Claims[0].NextAction
	if !strings.Contains(action, "`component.example.feature_enabled` is missing from the input") || !strings.Contains(action, "declare it in the input file") || strings.Contains(action, "inspect local") || strings.Contains(action, "pkg:") || strings.Contains(action, "mark missing") || strings.Contains(action, "expected true") {
		t.Fatalf("fact action is jargon or misleading: %q", action)
	}
	if dotted := factAction("example.rule", factCondition{FactID: testFact}); !strings.Contains(dotted, "prufyx catalog checks --project example") {
		t.Fatalf("fact action of a project rule does not point to the catalog: %q", dotted)
	}
	mismatched, err := Evaluate(testInput(t, registry, `{"id":"component.example.feature_enabled","state":"declared","boolValue":false}`, "2.1.0"), rules, testNow(t))
	if err != nil {
		t.Fatal(err)
	}
	action = mismatched.Claims[0].NextAction
	if !strings.Contains(action, "no rule for declared pair") || !strings.Contains(action, "retain actual versions") || !strings.Contains(action, "request coverage") {
		t.Fatalf("misleading transition action=%q", action)
	}
	longComponent := "pkg:" + strings.Repeat("a", 255)
	if len(subjectAction(transition{Component: longComponent, From: "1.0.0", To: "2.0.0"})) > maxStringBytes || len(factAction("example.rule", factCondition{Side: "proposed", Component: longComponent, FactID: testFact})) > maxStringBytes || len(dependencyAction(componentCheck{Side: "proposed", Component: longComponent, Comparison: "gte", Version: "1.0.0"})) > maxStringBytes {
		t.Fatal("long rule identifiers exceeded public action bound")
	}
}

func testRegistry(t *testing.T) Registry {
	t.Helper()
	registry, err := NewRegistry([]FactDefinition{{ID: testFact, Component: testComponent, Type: FactBool}})
	if err != nil {
		t.Fatal(err)
	}
	return registry
}

func testInput(t *testing.T, registry Registry, proposedFact, proposedVersion string) Input {
	t.Helper()
	raw := `{"schema":"` + InputSchema + `","authority":"` + InputAuthority + `","current":{"components":[{"component":"` + testComponent + `","version":"1.0.0","facts":[]}]},"proposed":{"components":[{"component":"` + testComponent + `","version":"` + proposedVersion + `","facts":[` + proposedFact + `]}]}}`
	input, err := ParseInput([]byte(raw), registry)
	if err != nil {
		t.Fatal(err)
	}
	return input
}

func testRules(t *testing.T, registry Registry, operator, extra string) RuleSet {
	t.Helper()
	raw, _ := json.Marshal(testRuleDocument(operator, extra))
	rules, err := ParseRuleSet(raw, registry)
	if err != nil {
		t.Fatal(err)
	}
	return rules
}

func testRuleDocument(operator, extra string) map[string]any {
	rule := map[string]any{
		"id": "example-rule", "operator": operator,
		"subject":    map[string]any{"component": testComponent, "from": "1.0.0", "to": "2.0.0"},
		"evidence":   map[string]any{"state": "active", "reviewedAt": "2026-01-01T00:00:00Z", "validUntil": "2027-01-01T00:00:00Z", "sources": []any{map[string]any{"id": "upstream-doc", "url": "https://github.com/example/controller/blob/" + testRevision + "/docs/upgrade.md", "revision": testRevision, "contentDigest": testDigest, "startLine": 10, "endLine": 12}}},
		"reasonCode": "FEATURE_REMOVED", "nextAction": "remove the reviewed feature before upgrade",
	}
	if extra != "" {
		var field map[string]any
		_ = json.Unmarshal([]byte("{"+extra+"}"), &field)
		for key, value := range field {
			rule[key] = value
		}
	}
	return map[string]any{"schema": RulesSchema, "revision": "1", "policyId": "community-local", "policyDigest": testDigest, "rules": []any{rule}}
}

func testNow(t *testing.T) time.Time {
	t.Helper()
	value, err := time.Parse(time.RFC3339, "2026-06-01T00:00:00Z")
	if err != nil {
		t.Fatal(err)
	}
	return value
}
