// SPDX-License-Identifier: AGPL-3.0-only

package constraintengine

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

const (
	pinnedEngineContractDigestChartNotice = "sha256:7282294ca4185aa7f27dd763cd1ef38740bf7378677581389bdbb01e2a5aeddb"
	pinnedScopeContractDigestChartNotice  = "sha256:a815c399ce8dac97a53ea6bb4944996f6f2064bafffcf973abd3dd032816e81c"

	noticeReason = "HELM_VALUES_KEY_NOT_REFERENCED"
	noticeText   = "review the listed keys before you upgrade"
)

// setNoticeRule is one set notice rule on the chart subject over the values
// set fact.
func setNoticeRule(t *testing.T, id, operator string, members ...string) map[string]any {
	t.Helper()
	rule := chartRuleDocument(t, operator, chartJSON(chartSource, chartName), requireConditionJSON(members...), false)["rules"].([]any)[0].(map[string]any)
	rule["id"], rule["reasonCode"], rule["nextAction"] = id, noticeReason, noticeText
	return rule
}

// noticeDocument holds the given rules (in id order) under the chart notice
// schema, with an attested corpus when corpus is set.
func noticeDocument(t *testing.T, corpus bool, rules ...map[string]any) map[string]any {
	t.Helper()
	document := chartRuleDocument(t, OperatorRequireSetMember, chartJSON(chartSource, chartName), requireConditionJSON("a"), corpus)
	document["schema"] = RulesSchemaChartNotice
	list := make([]any, 0, len(rules))
	for _, rule := range rules {
		list = append(list, rule)
	}
	document["rules"] = list
	return document
}

func TestChartNoticeContractDigestsArePinnedAndDistinct(t *testing.T) {
	if EngineContractDigestChartNotice() != pinnedEngineContractDigestChartNotice || ScopeContractDigestChartNotice() != pinnedScopeContractDigestChartNotice {
		t.Fatalf("chart notice contract digests moved: %s %s", EngineContractDigestChartNotice(), ScopeContractDigestChartNotice())
	}
	// Every earlier contract keeps the identity its reports were issued
	// under.
	for got, want := range map[string]string{
		EngineContractDigest(): pinnedEngineContractDigest, ScopeContractDigest(): pinnedScopeContractDigest,
		EngineContractDigestRanged(): pinnedEngineContractDigestRanged, ScopeContractDigestRanged(): pinnedScopeContractDigestRanged,
		EngineContractDigestSet(): pinnedEngineContractDigestSet, EngineContractDigestNotice(): pinnedEngineContractDigestNotice,
		ScopeContractDigestNotice(): pinnedScopeContractDigestNotice, EngineContractDigestBasis(): pinnedEngineContractDigestBasis,
		ScopeContractDigestBasis(): pinnedScopeContractDigestBasis, EngineContractDigestSeverity(): pinnedEngineContractDigestSeverity,
		ScopeContractDigestSeverity(): pinnedScopeContractDigestSeverity, EngineContractDigestCrossing(): pinnedEngineContractDigestCrossing,
		ScopeContractDigestCrossing(): pinnedScopeContractDigestCrossing, EngineContractDigestChart(): pinnedEngineContractDigestChart,
		ScopeContractDigestChart(): pinnedScopeContractDigestChart,
	} {
		if got != want {
			t.Fatalf("an earlier contract digest moved: %s != %s", got, want)
		}
	}
	if scopeDigestFor(EngineContractDigestChartNotice()) != ScopeContractDigestChartNotice() || EngineContractDigestChartNotice() == EngineContractDigestChart() || ScopeContractDigestChartNotice() == ScopeContractDigestChart() {
		t.Fatal("chart notice contract pairing")
	}
}

func TestSetNoticeTruthTable(t *testing.T) {
	registry := chartRegistry(t)
	missing := `{"id":"` + chartValuesFact + `","state":"missing"}`
	cases := []struct {
		name, operator, fact, status, reason string
		matched, absent                      []string
	}{
		{"present: incomplete, no hit", OperatorNoticeSetMemberPresent, valuesSetFact([]string{"z"}, false), "UNKNOWN", reasonSetFactIncomplete, nil, nil},
		{"present: complete, no hit", OperatorNoticeSetMemberPresent, valuesSetFact([]string{"z"}, true), "UNKNOWN", ReasonNoticeNotApplicable, nil, nil},
		{"present: complete empty set", OperatorNoticeSetMemberPresent, valuesSetFact(nil, true), "UNKNOWN", ReasonNoticeNotApplicable, nil, nil},
		{"present: incomplete, hit", OperatorNoticeSetMemberPresent, valuesSetFact([]string{"a.b", "z"}, false), StatusNotice, noticeReason, []string{"a.b"}, nil},
		{"present: complete, hit", OperatorNoticeSetMemberPresent, valuesSetFact([]string{"a.b", "c", "z"}, true), StatusNotice, noticeReason, []string{"a.b", "c"}, nil},
		{"present: missing fact", OperatorNoticeSetMemberPresent, missing, "UNKNOWN", "RULE_FACT_UNAVAILABLE", nil, nil},
		{"present: undeclared fact", OperatorNoticeSetMemberPresent, "", "UNKNOWN", "RULE_FACT_UNAVAILABLE", nil, nil},
		{"absent: incomplete, member absent", OperatorNoticeSetMemberAbsent, valuesSetFact([]string{"z"}, false), "UNKNOWN", reasonSetFactIncomplete, nil, nil},
		{"absent: incomplete, every member present", OperatorNoticeSetMemberAbsent, valuesSetFact([]string{"a.b", "c"}, false), "UNKNOWN", reasonSetFactIncomplete, nil, nil},
		{"absent: complete, member absent", OperatorNoticeSetMemberAbsent, valuesSetFact([]string{"c", "z"}, true), StatusNotice, noticeReason, nil, []string{"a.b"}},
		{"absent: complete empty set", OperatorNoticeSetMemberAbsent, valuesSetFact(nil, true), StatusNotice, noticeReason, nil, []string{"a.b", "c"}},
		{"absent: complete, every member present", OperatorNoticeSetMemberAbsent, valuesSetFact([]string{"a.b", "c"}, true), "UNKNOWN", ReasonNoticeNotApplicable, nil, nil},
		{"absent: missing fact", OperatorNoticeSetMemberAbsent, missing, "UNKNOWN", "RULE_FACT_UNAVAILABLE", nil, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rules := parseChartRules(t, registry, noticeDocument(t, false, setNoticeRule(t, "notice-rule", tc.operator, "a.b", "c")))
			report, raw := evaluateAndSeal(t, chartInput(t, registry, chartJSON(chartSource, chartName), tc.fact, false), rules)
			claim := report.Claims[0]
			if claim.Status != tc.status || claim.ReasonCode != tc.reason || strings.Join(claim.MatchedMembers, ",") != strings.Join(tc.matched, ",") || (tc.matched == nil) != (claim.MatchedMembers == nil) || strings.Join(claim.MissingMembers, ",") != strings.Join(tc.absent, ",") || (tc.absent == nil) != (claim.MissingMembers == nil) {
				t.Fatalf("claim=%+v", claim)
			}
			if !claim.IsNotice() || !claim.IsVerdictNeutral() || report.EngineContractDigest != EngineContractDigestChartNotice() || report.Assessment != AssessmentUnknown {
				t.Fatalf("report=%+v", report)
			}
			if strings.Contains(string(raw), `"z"`) {
				t.Fatalf("report disclosed a declared member the rule does not name: %s", raw)
			}
			// The members of a notice are never worded as forbidden or
			// required.
			if _, ok := claim.MatchedMembersLine(); ok {
				t.Fatal("matched members line printed for a notice")
			}
			if _, ok := claim.MissingMembersLine(); ok {
				t.Fatal("missing members line printed for a notice")
			}
			lines, ok := claim.NoticeLines()
			if !ok {
				t.Fatal("no notice lines")
			}
			text := strings.Join(lines, "\n")
			switch {
			case tc.status == StatusNotice:
				want := "notice: notice-rule\nbefore you upgrade: " + noticeText + "\n"
				if tc.matched != nil {
					want += "listed members present: " + strings.Join(tc.matched, ", ")
				} else {
					want += "listed members not present: " + strings.Join(tc.absent, ", ")
				}
				if text != want {
					t.Fatalf("lines %q", text)
				}
			case tc.reason == ReasonNoticeNotApplicable:
				if len(lines) != 0 {
					t.Fatalf("a notice that does not apply printed %q", text)
				}
			default:
				if !strings.HasPrefix(text, "notice not established: notice-rule ("+tc.reason+")") {
					t.Fatalf("lines %q", text)
				}
			}
			// Each operator says what an incomplete set leaves open.
			if tc.reason == reasonSetFactIncomplete {
				absent := strings.Contains(claim.NextAction, "whether a listed member is absent is decided only over a complete set")
				present := strings.Contains(claim.NextAction, "decided only over a complete set or a listed member present")
				if absent != (tc.operator == OperatorNoticeSetMemberAbsent) || present != (tc.operator == OperatorNoticeSetMemberPresent) {
					t.Fatalf("incomplete-set action %q", claim.NextAction)
				}
			}
			for _, line := range lines {
				if len(line) > maxStringBytes || strings.Contains(line, "forbidden") || strings.Contains(line, "required") || strings.Contains(strings.ToLower(line), "rolled back") {
					t.Fatalf("line %q", line)
				}
			}
		})
	}
}

// TestSetNoticeNeverChangesTheAggregate evaluates a scope-complete document
// with and without each notice, over sets that hit and miss it: the
// aggregate, the unresolved reason and every component's partition are the
// same, and noticeRules counts the notices.
func TestSetNoticeNeverChangesTheAggregate(t *testing.T) {
	registry := chartRegistry(t)
	verdict := func(member string) map[string]any {
		rule := chartRuleDocument(t, OperatorRequireSetMember, chartJSON(chartSource, chartName), requireConditionJSON(member), true)["rules"].([]any)[0].(map[string]any)
		rule["id"] = "a-require-rule"
		return rule
	}
	for _, required := range []string{"a", "q"} {
		for _, facts := range [][]string{{"a"}, {"a", "b", "c"}, {}} {
			for _, complete := range []bool{true, false} {
				input := chartInput(t, registry, chartJSON(chartSource, chartName), valuesSetFact(facts, complete), true)
				base, _ := evaluateAndSeal(t, input, parseChartRules(t, registry, func() map[string]any {
					document := chartRuleDocument(t, OperatorRequireSetMember, chartJSON(chartSource, chartName), requireConditionJSON(required), true)
					document["rules"].([]any)[0].(map[string]any)["id"] = "a-require-rule"
					return document
				}()))
				with, _ := evaluateAndSeal(t, input, parseChartRules(t, registry, noticeDocument(t, true, verdict(required),
					setNoticeRule(t, "b-notice-absent", OperatorNoticeSetMemberAbsent, "b", "d"),
					setNoticeRule(t, "c-notice-present", OperatorNoticeSetMemberPresent, "a", "c"))))
				if base.Assessment != with.Assessment || base.ScopeCompleteness == nil || with.ScopeCompleteness == nil {
					t.Fatalf("%s %v %v: aggregate %s -> %s", required, facts, complete, base.Assessment, with.Assessment)
				}
				b, w := *base.ScopeCompleteness, *with.ScopeCompleteness
				if b.UnresolvedReason != w.UnresolvedReason || w.NoticeRules != 2 || b.NoticeRules != 0 || w.LeadRules != 0 || w.OutOfScopeRules != b.OutOfScopeRules {
					t.Fatalf("scope %+v -> %+v", b, w)
				}
				bc, _ := json.Marshal(b.Components)
				wc, _ := json.Marshal(w.Components)
				if string(bc) != string(wc) {
					t.Fatalf("partition %s -> %s", bc, wc)
				}
				if w.ContractDigest != ScopeContractDigestChartNotice() || b.ContractDigest != ScopeContractDigestChart() {
					t.Fatalf("scope contracts %s %s", b.ContractDigest, w.ContractDigest)
				}
			}
		}
	}
	// The cases above include both decisive aggregates.
	input := chartInput(t, registry, chartJSON(chartSource, chartName), valuesSetFact([]string{"a", "c"}, true), true)
	for required, want := range map[string]string{"a": AssessmentScopeCompletePass, "q": AssessmentBlocked} {
		report, _ := evaluateAndSeal(t, input, parseChartRules(t, registry, noticeDocument(t, true, verdict(required),
			setNoticeRule(t, "b-notice-absent", OperatorNoticeSetMemberAbsent, "b"),
			setNoticeRule(t, "c-notice-present", OperatorNoticeSetMemberPresent, "a"))))
		if report.Assessment != want || report.Claims[1].Status != StatusNotice || report.Claims[2].Status != StatusNotice {
			t.Fatalf("required %s: %s %+v", required, report.Assessment, report.Claims)
		}
	}
	// A component whose only rules are notices has no evaluated rule: a
	// notice never supports a completeness attestation.
	document := noticeDocument(t, true, setNoticeRule(t, "c-notice-present", OperatorNoticeSetMemberPresent, "a"))
	raw, _ := json.Marshal(document)
	if _, err := ParseRuleSet(raw, registry); !errors.Is(err, ErrInvalid) {
		t.Fatalf("a corpus attested by a notice alone: %v", err)
	}
}

func TestSetNoticeStructure(t *testing.T) {
	registry := chartRegistry(t)
	good := func(operator string) map[string]any { return setNoticeRule(t, "notice-rule", operator, "a") }
	for _, operator := range []string{OperatorNoticeSetMemberPresent, OperatorNoticeSetMemberAbsent} {
		parseChartRules(t, registry, noticeDocument(t, false, good(operator)))
		refused := map[string]func(map[string]any){
			"no chart subject":  func(r map[string]any) { delete(r["subject"].(map[string]any), "chart") },
			"no set condition":  func(r map[string]any) { delete(r, "setCondition") },
			"bool fact":         func(r map[string]any) { r["setCondition"].(map[string]any)["factId"] = testFact },
			"unordered members": func(r map[string]any) { r["setCondition"].(map[string]any)["members"] = []any{"b", "a"} },
			"a condition": func(r map[string]any) {
				r["condition"] = map[string]any{"side": "proposed", "component": testComponent, "factId": testFact, "boolValue": true}
			},
			"a dependency": func(r map[string]any) {
				r["dependency"] = map[string]any{"side": "proposed", "component": "pkg:github/kubernetes/kubernetes", "comparison": "gte", "version": "1.0.0"}
			},
			"an intermediate": func(r map[string]any) { r["intermediate"] = "1.5.0" },
			"an applicability condition": func(r map[string]any) {
				r["appliesWhen"] = []any{map[string]any{"side": "proposed", "component": testComponent, "factId": testFact, "boolValue": true}}
			},
			"a severity": func(r map[string]any) { r["severity"] = SeverityUnsupported },
			"a range": func(r map[string]any) {
				r["range"] = map[string]any{"from": map[string]any{"gte": "1.0.0", "lt": "1.1.0"}, "to": map[string]any{"gte": "2.0.0", "lt": "2.1.0"}, "bounds": []any{}}
			},
			"a lead basis": func(r map[string]any) {
				ev := r["evidence"].(map[string]any)
				ev["basis"], ev["derivedAt"] = BasisLead, "2026-01-01T00:00:00Z"
			},
			"a consensus basis": func(r map[string]any) {
				ev := r["evidence"].(map[string]any)
				ev["basis"], ev["derivedAt"] = BasisConsensus, "2026-01-01T00:00:00Z"
			},
			"an engine reason":    func(r map[string]any) { r["reasonCode"] = ReasonNoticeNotApplicable },
			"the one-way reason":  func(r map[string]any) { r["reasonCode"] = ReasonOneWayTransition },
			"the set reason":      func(r map[string]any) { r["reasonCode"] = reasonSetFactIncomplete },
			"safe in the text":    func(r map[string]any) { r["nextAction"] = "the upgrade is Safe" },
			"block in the text":   func(r map[string]any) { r["nextAction"] = "this would BLOCK the upgrade" },
			"refuse in the text":  func(r map[string]any) { r["nextAction"] = "Helm refuses it" },
			"must in the text":    func(r map[string]any) { r["nextAction"] = "you must set it" },
			"block in the id":     func(r map[string]any) { r["id"] = "notice-blocker" },
			"non-ascii text":      func(r map[string]any) { r["nextAction"] = "review the keys é" },
			"a control character": func(r map[string]any) { r["nextAction"] = "review\tthe keys" },
		}
		for name, edit := range refused {
			t.Run(operator+"/"+name, func(t *testing.T) {
				rule := good(operator)
				edit(rule)
				raw, _ := json.Marshal(noticeDocument(t, false, rule))
				if _, err := ParseRuleSet(raw, registry); !errors.Is(err, ErrInvalid) {
					t.Fatalf("accepted: %v", err)
				}
			})
		}
	}
	// Schema and feature must match in both directions.
	for _, schema := range []string{RulesSchemaChart, RulesSchemaCrossing, RulesSchemaNotice, RulesSchemaSet} {
		document := noticeDocument(t, false, good(OperatorNoticeSetMemberPresent))
		document["schema"] = schema
		raw, _ := json.Marshal(document)
		if _, err := ParseRuleSet(raw, registry); !errors.Is(err, ErrInvalid) {
			t.Fatalf("set notice under %s accepted: %v", schema, err)
		}
	}
	for _, document := range []map[string]any{
		chartRuleDocument(t, OperatorRequireSetMember, chartJSON(chartSource, chartName), requireConditionJSON("a"), false),
		chartRuleDocument(t, "forbid_target_version", chartJSON(chartSource, chartName), "", false),
		testRuleDocument("forbid_target_version", ""),
	} {
		document["schema"] = RulesSchemaChartNotice
		raw, _ := json.Marshal(document)
		if _, err := ParseRuleSet(raw, registry); !errors.Is(err, ErrInvalid) {
			t.Fatalf("set notice schema without a set notice accepted: %v", err)
		}
	}
	for _, operator := range []string{OperatorNoticeSetMemberPresent, OperatorNoticeSetMemberAbsent} {
		raw, _ := json.Marshal(good(operator))
		if schema, err := RulesSchemaFor([]json.RawMessage{raw}); err != nil || schema != RulesSchemaChartNotice {
			t.Fatalf("RulesSchemaFor %s %v", schema, err)
		}
		for name, check := range map[string]func([]json.RawMessage) (bool, error){"AnyChartNoticeRule": AnyChartNoticeRule, "AnyChartRule": AnyChartRule} {
			if any, err := check([]json.RawMessage{raw}); err != nil || !any {
				t.Fatalf("%s missed %s", name, operator)
			}
		}
		if neutral, err := RawRuleVerdictNeutral(raw); err != nil || !neutral {
			t.Fatalf("RawRuleVerdictNeutral %v %v", neutral, err)
		}
		if kind, err := RawRuleKind(raw); err != nil || kind != RuleKindSetNotice {
			t.Fatalf("RawRuleKind %q %v", kind, err)
		}
	}
	plain, _ := json.Marshal(chartRuleDocument(t, OperatorRequireSetMember, chartJSON(chartSource, chartName), requireConditionJSON("a"), false)["rules"].([]any)[0])
	if any, err := AnyChartNoticeRule([]json.RawMessage{plain}); err != nil || any {
		t.Fatal("AnyChartNoticeRule flagged a require rule")
	}
	if schema, err := RulesSchemaFor([]json.RawMessage{plain}); err != nil || schema != RulesSchemaChart {
		t.Fatalf("a chart document moved schema: %s %v", schema, err)
	}
}

// A notice never contradicts a verdict rule: a forbid rule and a present
// notice, or a require rule and an absent notice, on the same member are
// admitted together.
func TestSetNoticeIsNoContradiction(t *testing.T) {
	registry := chartRegistry(t)
	forbid := chartRuleDocument(t, OperatorForbidSetMember, chartJSON(chartSource, chartName), requireConditionJSON("a"), false)["rules"].([]any)[0].(map[string]any)
	forbid["id"] = "a-forbid"
	require := chartRuleDocument(t, OperatorRequireSetMember, chartJSON(chartSource, chartName), requireConditionJSON("b"), false)["rules"].([]any)[0].(map[string]any)
	require["id"] = "b-require"
	parseChartRules(t, registry, noticeDocument(t, false, forbid, require,
		setNoticeRule(t, "c-absent", OperatorNoticeSetMemberAbsent, "a", "b"),
		setNoticeRule(t, "d-present", OperatorNoticeSetMemberPresent, "a", "b")))
	// The forbid and require pair itself is still refused.
	clash := chartRuleDocument(t, OperatorRequireSetMember, chartJSON(chartSource, chartName), requireConditionJSON("a"), false)["rules"].([]any)[0].(map[string]any)
	clash["id"] = "b-require"
	raw, _ := json.Marshal(noticeDocument(t, false, forbid, clash, setNoticeRule(t, "c-absent", OperatorNoticeSetMemberAbsent, "a")))
	if _, err := ParseRuleSet(raw, registry); !errors.Is(err, ErrInvalid) {
		t.Fatalf("forbid and require contradiction admitted next to a notice: %v", err)
	}
}

// TestSetNoticeClaimsBoundToTheirContract forges sealed reports: a set
// notice claim, its members and RULE_NOTICE_NOT_APPLICABLE are refused
// under the chart (v1alpha8) contract and every lower one, and a NOTICE
// claim must disclose exactly its own members.
func TestSetNoticeClaimsBoundToTheirContract(t *testing.T) {
	registry := chartRegistry(t)
	evaluate := func(operator, fact string) Report {
		t.Helper()
		rules := parseChartRules(t, registry, noticeDocument(t, false, setNoticeRule(t, "notice-rule", operator, "a", "b")))
		report, err := Evaluate(chartInput(t, registry, chartJSON(chartSource, chartName), fact, false), rules, testNow(t))
		if err != nil {
			t.Fatal(err)
		}
		return report
	}
	present := evaluate(OperatorNoticeSetMemberPresent, valuesSetFact([]string{"a"}, false))
	absent := evaluate(OperatorNoticeSetMemberAbsent, valuesSetFact([]string{"a"}, true))
	quiet := evaluate(OperatorNoticeSetMemberPresent, valuesSetFact([]string{"z"}, true))
	if present.Claims[0].Status != StatusNotice || absent.Claims[0].Status != StatusNotice || quiet.Claims[0].ReasonCode != ReasonNoticeNotApplicable {
		t.Fatalf("setup %+v %+v %+v", present.Claims[0], absent.Claims[0], quiet.Claims[0])
	}
	forge := func(report Report, edit func(*Report)) error {
		forged := report
		forged.Claims = append([]Claim(nil), report.Claims...)
		edit(&forged)
		_, err := MarshalReport(issueReport(forged))
		return err
	}
	for name, tc := range map[string]struct {
		report Report
		edit   func(*Report)
	}{
		"notice under the chart contract":               {present, func(r *Report) { r.EngineContractDigest = EngineContractDigestChart() }},
		"absent notice under the chart contract":        {absent, func(r *Report) { r.EngineContractDigest = EngineContractDigestChart() }},
		"not applicable under the chart contract":       {quiet, func(r *Report) { r.EngineContractDigest = EngineContractDigestChart() }},
		"notice under the one-way notice contract":      {present, func(r *Report) { r.EngineContractDigest = EngineContractDigestNotice() }},
		"notice under the crossing contract":            {present, func(r *Report) { r.EngineContractDigest = EngineContractDigestCrossing() }},
		"notice passing":                                {quiet, func(r *Report) { r.Claims[0].Status = "PASS" }},
		"notice blocking":                               {present, func(r *Report) { r.Claims[0].Status = "BLOCKED" }},
		"present notice without members":                {present, func(r *Report) { r.Claims[0].MatchedMembers = nil }},
		"present notice with unordered members":         {present, func(r *Report) { r.Claims[0].MatchedMembers = []string{"b", "a"} }},
		"present notice disclosing missing members":     {present, func(r *Report) { r.Claims[0].MissingMembers = []string{"b"} }},
		"absent notice without members":                 {absent, func(r *Report) { r.Claims[0].MissingMembers = nil }},
		"absent notice disclosing matched members":      {absent, func(r *Report) { r.Claims[0].MatchedMembers = []string{"a"} }},
		"members on a not-applicable claim":             {quiet, func(r *Report) { r.Claims[0].MatchedMembers = []string{"a"} }},
		"not applicable as a notice":                    {quiet, func(r *Report) { r.Claims[0].Status = StatusNotice }},
		"notice with an engine reason":                  {present, func(r *Report) { r.Claims[0].ReasonCode = reasonSetFactIncomplete }},
		"notice with the one-way reason":                {present, func(r *Report) { r.Claims[0].ReasonCode = ReasonOneWayTransition }},
		"notice with stale evidence":                    {present, func(r *Report) { r.Claims[0].EvidenceFreshness = "stale" }},
		"not applicable on another operator":            {quiet, func(r *Report) { r.Claims[0].Operator = OperatorForbidSetMember }},
		"notice members relabelled as a forbid":         {present, func(r *Report) { r.Claims[0].Operator = OperatorForbidSetMember }},
		"notice members relabelled as a one-way notice": {present, func(r *Report) { r.Claims[0].Operator = OperatorNoticeOneWay }},
		"absent members relabelled as a require":        {absent, func(r *Report) { r.Claims[0].Operator = OperatorRequireSetMember }},
	} {
		if err := forge(tc.report, tc.edit); !errors.Is(err, ErrIntegrity) {
			t.Errorf("%s: sealed: %v", name, err)
		}
	}
	for _, report := range []Report{present, absent, quiet} {
		if err := forge(report, func(*Report) {}); err != nil {
			t.Fatalf("unforged report refused: %v", err)
		}
	}
}

func TestSetNoticeMemberLinesFit(t *testing.T) {
	members := make([]string, 0, MaxForbiddenMembers)
	for i := 0; i < MaxForbiddenMembers; i++ {
		members = append(members, strings.Repeat(string(rune('a'+i%26)), 100)+string(rune('a'+i/26)))
	}
	lines := memberLines(noticeSetPresentPrefix, members)
	joined := ""
	for _, line := range lines {
		if len(line) > maxStringBytes || !strings.HasPrefix(line, noticeSetPresentPrefix) {
			t.Fatalf("line %d bytes: %q", len(line), line)
		}
		joined += strings.TrimPrefix(line, noticeSetPresentPrefix) + ", "
	}
	if joined != strings.Join(members, ", ")+", " {
		t.Fatal("members lost or reordered")
	}
}
