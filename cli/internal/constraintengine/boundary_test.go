// SPDX-License-Identifier: AGPL-3.0-only

package constraintengine

import (
	"errors"
	"sort"
	"strings"
	"testing"
)

// BOUNDARY-1: a ranged rule whose range pins a REMOVED_IN_RELEASE or
// CHANGED_IN_RELEASE boundary C must never exclude (NOT_APPLICABLE) a hop that
// crosses C outside the range. The hop is UNDETERMINED in scope, so a wide
// anchor rule next to it can never give SCOPE_COMPLETE_PASS.

// boundaryRangeRule is a release-boundary ranged rule: anchor 1.24.0 -> 1.25.0,
// range [1.24,1.25) -> [1.25,1.26), C = 1.25.0, with the fact blocking.
func boundaryRangeRule() string { return boundaryRangeRuleBasis(BasisRemovedInRelease) }

// boundaryBases are the two release bases a range may pin its boundary with.
var boundaryBases = []string{BasisRemovedInRelease, BasisChangedInRelease}

// boundaryRangeRuleBasis is boundaryRangeRule with the release basis of the
// from.lt and to.gte bounds set to basis.
func boundaryRangeRuleBasis(basis string) string {
	spec := defaultRangeSpec()
	spec.id, spec.operator, spec.fact = "range-removal", "forbid_target_version", ""
	spec.bases = [4]string{BasisPreviousMinorLine, basis, basis, BasisReviewedThroughMinorLine}
	return spec.ruleJSON()
}

// boundaryDocuments builds, for every range-capable contract, a document that
// holds the ranged rule, a wide anchor rule equal to the hop (which would
// give the scope pass on its own) and, for the later schemas, one companion
// rule that selects the schema without matching the hop.
func boundaryDocuments(t *testing.T, from, to string, ranged string) map[string]RuleSet {
	t.Helper()
	wide := scopeRule("anchor-wide", "require_component_version", scopeComponentA, from, to, "active", activeUntil, dependencyOn(scopeComponentA, "gte", "1.0.0"))
	parse := func(schema string, extra ...string) RuleSet {
		t.Helper()
		all := append([]string{wide, ranged}, extra...)
		sort.Slice(all, func(i, j int) bool { return ruleIDOf(all[i]) < ruleIDOf(all[j]) })
		rules, err := ParseRuleSet(rangeDocument(schema, true, all...), scopeRegistry(t))
		if err != nil {
			t.Fatalf("%s: %v", schema, err)
		}
		return rules
	}
	other := newXRule()
	other.id = "crossing-other"
	other.from, other.to, other.change, other.horizon = "1.40.0", "1.41.0", "1.41.0", "1.45.0"
	return map[string]RuleSet{
		"ranged":   parse(RulesSchemaRanged),
		"notice":   parse(RulesSchemaNotice, noticeRule("notice-other", scopeComponentA, "1.40.0", "1.41.0", "active", activeUntil, "")),
		"basis":    parse(RulesSchemaBasis, withBasis(scopeRule("consensus-other", "forbid_target_version", scopeComponentA, "1.40.0", "1.41.0", "active", activeUntil, ""), BasisConsensus)),
		"severity": parse(RulesSchemaSeverity, withSeverity(scopeRule("support-other", "require_component_version", scopeComponentA, "1.40.0", "1.41.0", "active", activeUntil, dependencyOn(scopeComponentB, "gte", "2.0.0")), SeverityUnsupported)),
		"crossing": parse(RulesSchemaCrossing, other.json()),
	}
}

func TestRangeReleaseBoundaryNeverExcludesACrossingHop(t *testing.T) {
	now := testNow(t)
	cases := []struct {
		name, from, to string
		blocked        bool
		undetermined   bool // the ranged rule is UNDETERMINED / RULE_RELEASE_BOUNDARY_NOT_REVIEWED
		// downgradeChanged marks a downgrade across C: UNDETERMINED for a
		// CHANGED_IN_RELEASE range (reverting a change is not proven harmless),
		// still excluded for REMOVED_IN_RELEASE (the removed API exists again).
		downgradeChanged bool
	}{
		// The opus probe: 1.21.0 -> 1.30.0 crosses C = 1.25.0 outside the range.
		{"wide hop across C", "1.21.0", "1.30.0", true, true, false},
		{"origin one line below the range", "1.23.5", "1.25.3", true, true, false},
		{"target one line above the range", "1.24.5", "1.26.0", true, true, false},
		{"fact false does not make it applicable", "1.21.0", "1.30.0", false, true, false},
		// Hops that provably do not cross C stay excluded.
		{"target below C", "1.21.0", "1.24.9", true, false, false},
		{"origin at C", "1.25.0", "1.30.0", true, false, false},
		{"origin above C", "1.26.0", "1.30.0", true, false, false},
		{"downgrade across C", "1.30.0", "1.21.0", true, false, true},
		{"downgrade just across C", "1.25.0", "1.24.9", true, false, true},
		{"downgrade not reaching C", "1.30.0", "1.25.0", true, false, false},
	}
	for _, basis := range boundaryBases {
		for _, tc := range cases {
			tc.undetermined = tc.undetermined || tc.downgradeChanged && basis == BasisChangedInRelease
			for schema, rules := range boundaryDocuments(t, tc.from, tc.to, boundaryRangeRuleBasis(basis)) {
				t.Run(basis+"/"+tc.name+"/"+schema, func(t *testing.T) {
					report, err := Evaluate(xInput(t, tc.from, tc.to, "", "", tc.blocked), rules, now)
					if err != nil {
						t.Fatal(err)
					}
					var entry *NotEvaluatedRule
					for i, skipped := range report.ScopeCompleteness.Components[0].NotEvaluated {
						if skipped.RuleID == "range-removal" {
							entry = &report.ScopeCompleteness.Components[0].NotEvaluated[i]
						}
					}
					if entry == nil {
						t.Fatalf("ranged rule not enumerated: %+v", report.ScopeCompleteness)
					}
					if tc.undetermined {
						if report.Assessment == AssessmentScopeCompletePass {
							t.Fatalf("a hop that crosses the pinned boundary reached SCOPE_COMPLETE_PASS")
						}
						if entry.Applicability != ApplicabilityUndetermined || entry.ReasonCode != ReasonReleaseBoundaryNotReviewed {
							t.Fatalf("ranged rule is %s/%s, want UNDETERMINED/%s", entry.Applicability, entry.ReasonCode, ReasonReleaseBoundaryNotReviewed)
						}
						for _, claim := range report.Claims {
							if claim.RuleID == "range-removal" && (claim.Status != "UNKNOWN" || claim.ReasonCode != ReasonReleaseBoundaryNotReviewed) {
								t.Fatalf("claim %+v", claim)
							}
						}
					} else {
						if entry.Applicability != ApplicabilityNotApplicable || entry.ReasonCode != "RULE_TRANSITION_NOT_REVIEWED" {
							t.Fatalf("ranged rule is %s/%s, want NOT_APPLICABLE/RULE_TRANSITION_NOT_REVIEWED", entry.Applicability, entry.ReasonCode)
						}
						if report.Assessment != AssessmentScopeCompletePass && !tc.blocked {
							t.Fatalf("a hop that does not cross C lost its scope pass: %s", report.Assessment)
						}
					}
					raw, err := MarshalReport(report)
					if err != nil {
						t.Fatalf("report refused: %v", err)
					}
					if _, err := Replay(xInput(t, tc.from, tc.to, "", "", tc.blocked), rules, now, raw); err != nil {
						t.Fatalf("report does not replay: %v", err)
					}
				})
			}
		}
	}
}

// A range whose boundary bounds do not both cite a release has no boundary the
// engine knows, so such a rule keeps excluding a hop outside the range.
func TestRangeWithoutReleaseBasisKeepsExcluding(t *testing.T) {
	spec := defaultRangeSpec()
	spec.id, spec.operator, spec.fact = "range-series", "forbid_target_version", ""
	spec.bases = [4]string{BasisUpgradeFromSeries, BasisUpgradeFromSeries, BasisTargetSeries, BasisTargetSeries}
	for schema, rules := range boundaryDocuments(t, "1.21.0", "1.30.0", spec.ruleJSON()) {
		report, err := Evaluate(xInput(t, "1.21.0", "1.30.0", "", "", false), rules, testNow(t))
		if err != nil {
			t.Fatal(err)
		}
		for _, skipped := range report.ScopeCompleteness.Components[0].NotEvaluated {
			if skipped.RuleID == "range-series" && (skipped.Applicability != ApplicabilityNotApplicable || skipped.ReasonCode != "RULE_TRANSITION_NOT_REVIEWED") {
				t.Errorf("%s: %+v", schema, skipped)
			}
		}
	}
}

// An exact-only document has no boundary: nothing changes, and its contract
// digest stays the original.
func TestExactDocumentsHaveNoReleaseBoundary(t *testing.T) {
	if EngineContractDigest() != pinnedEngineContractDigest {
		t.Fatal("exact-only engine contract changed")
	}
	var transition RuleTransition
	if _, ok := transition.ChangeVersion(); ok || transition.CrossesUnreviewed("1.21.0", "1.30.0") {
		t.Fatal("a subject without range or crossing has a release boundary")
	}
}

// A crossing rule keeps its own reason; a ranged rule gets the neutral one,
// even inside a crossing-schema document.
func TestReleaseBoundaryReasonIsNeutralForRangedRules(t *testing.T) {
	other := newXRule()
	other.id, other.from, other.to, other.change, other.horizon = "crossing-rule", "1.24.0", "1.25.0", "1.25.0", "1.30.0"
	rules, err := ParseRuleSet(xDocument(RulesSchemaCrossing, other.json(), boundaryRangeRuleOn("range-removal", "1.40.0", "1.41.0", "1.40.0", "1.41.0", "1.41.0", "1.42.0")), scopeRegistry(t))
	if err != nil {
		t.Fatal(err)
	}
	report, err := Evaluate(xInput(t, "1.38.0", "1.45.0", "", "", false), rules, testNow(t))
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]string{}
	for _, skipped := range report.ScopeCompleteness.Components[0].NotEvaluated {
		seen[skipped.RuleID] = skipped.ReasonCode
	}
	// The crossing rule's hop 1.38 -> 1.45 is above its change: excluded. The
	// ranged rule's boundary 1.41.0 is crossed outside its range.
	if seen["range-removal"] != ReasonReleaseBoundaryNotReviewed {
		t.Fatalf("ranged rule reason %q", seen["range-removal"])
	}
	if seen["crossing-rule"] != "RULE_TRANSITION_NOT_REVIEWED" {
		t.Fatalf("crossing rule reason %q", seen["crossing-rule"])
	}
}

func boundaryRangeRuleOn(id, from, to, fromGte, fromLt, toGte, toLt string) string {
	spec := defaultRangeSpec()
	spec.id, spec.operator, spec.fact = id, "forbid_target_version", ""
	spec.from, spec.to, spec.fromGte, spec.fromLt, spec.toGte, spec.toLt = from, to, fromGte, fromLt, toGte, toLt
	return spec.ruleJSON()
}

// The neutral reason belongs to the engine: a rule may not carry it, and the
// seal gate refuses it outside UNKNOWN claims of a range-capable contract.
func TestReleaseBoundaryReasonIsReservedAndBoundToItsContracts(t *testing.T) {
	reserved := strings.Replace(boundaryRangeRule(), `"reasonCode":"FEATURE_REMOVED"`, `"reasonCode":"`+ReasonReleaseBoundaryNotReviewed+`"`, 1)
	if _, err := ParseRuleSet(rangeDocument(RulesSchemaRanged, true, reserved), scopeRegistry(t)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("a rule carrying the engine reason was accepted: %v", err)
	}
	rules := boundaryDocuments(t, "1.21.0", "1.30.0", boundaryRangeRule())["ranged"]
	input := xInput(t, "1.21.0", "1.30.0", "", "", true)
	report, err := Evaluate(input, rules, testNow(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := MarshalReport(report); err != nil {
		t.Fatal(err)
	}
	var index = -1
	for i, claim := range report.Claims {
		if claim.RuleID == "range-removal" {
			index = i
		}
	}
	if index < 0 || report.Claims[index].ReasonCode != ReasonReleaseBoundaryNotReviewed {
		t.Fatalf("claims %+v", report.Claims)
	}
	forge := func(mutate func(*Report)) error {
		forged := report
		forged.Claims = append([]Claim(nil), report.Claims...)
		scope := *report.ScopeCompleteness
		forged.ScopeCompleteness = &scope
		mutate(&forged)
		_, err := MarshalReport(issueReport(forged))
		return err
	}
	forgeries := map[string]func(*Report){
		"relabelled BLOCKED": func(r *Report) { r.Claims[index].Status = "BLOCKED" },
		"relabelled PASS":    func(r *Report) { r.Claims[index].Status = "PASS" },
		"under exact contract": func(r *Report) {
			r.EngineContractDigest = EngineContractDigest()
			r.ScopeCompleteness.ContractDigest = ScopeContractDigest()
		},
		"with a range disclosure": func(r *Report) { r.Claims[index].SubjectMatch = &SubjectMatch{Mode: subjectMatchModeRange} },
		// Well-formed: valid anchors inside valid bounds, so only the
		// release-boundary clause of the seal gate can refuse it.
		"with a well-formed range disclosure": func(r *Report) {
			r.Claims[index].SubjectMatch = &SubjectMatch{Mode: subjectMatchModeRange, AnchorFrom: "1.24.0", AnchorTo: "1.25.0", From: VersionBound{Gte: "1.24.0", Lt: "1.25.0"}, To: VersionBound{Gte: "1.25.0", Lt: "1.26.0"}}
		},
	}
	for name, mutate := range forgeries {
		if err := forge(mutate); !errors.Is(err, ErrIntegrity) {
			t.Errorf("%s: sealed report accepted (err=%v)", name, err)
		}
	}
}

func TestReleaseBoundaryContractIdentity(t *testing.T) {
	// Every range-capable contract carries the boundary policy; the exact-only
	// contract does not.
	if !strings.Contains(rangeBoundaryPolicy, ReasonReleaseBoundaryNotReviewed) || !strings.Contains(crossingSemantics, ReasonReleaseBoundaryNotReviewed) {
		t.Fatal("the boundary policy does not name the neutral reason")
	}
	if EngineContractDigestRanged() == pinnedOldRangedDigest {
		t.Fatal("the ranged contract still has its pre-BOUNDARY-1 identity")
	}
}

const pinnedOldRangedDigest = "sha256:2cc7bb0052068bd2668d1c4419782bacd6fcbf34e73f9bf9cf08206cd1363fa6"

// The set schema is range-capable too: a ranged forbid_set_member rule gets the
// same boundary treatment as the other contracts, under both release bases.
func TestSetSchemaRangeReleaseBoundary(t *testing.T) {
	registry, err := NewRegistry([]FactDefinition{{ID: "component.alpha.feature_gates_set", Component: scopeComponentA, Type: FactSet}})
	if err != nil {
		t.Fatal(err)
	}
	now := testNow(t)
	for _, basis := range boundaryBases {
		spec := defaultRangeSpec()
		spec.id, spec.operator = "range-set", OperatorForbidSetMember
		spec.bases = [4]string{BasisPreviousMinorLine, basis, basis, BasisReviewedThroughMinorLine}
		spec.extra = `,"setCondition":{"side":"proposed","component":"` + scopeComponentA + `","factId":"component.alpha.feature_gates_set","members":["GateA"]}`
		for _, tc := range []struct {
			name, from, to string
			undetermined   bool
		}{
			{"wide hop across C", "1.21.0", "1.30.0", true},
			{"target one line above the range", "1.24.5", "1.26.0", true},
			{"target below C", "1.21.0", "1.24.9", false},
			{"origin above C", "1.26.0", "1.30.0", false},
		} {
			t.Run(basis+"/"+tc.name, func(t *testing.T) {
				wide := scopeRule("anchor-wide", "require_component_version", scopeComponentA, tc.from, tc.to, "active", activeUntil, dependencyOn(scopeComponentA, "gte", "1.0.0"))
				all := []string{wide, spec.ruleJSON()}
				sort.Slice(all, func(i, j int) bool { return ruleIDOf(all[i]) < ruleIDOf(all[j]) })
				rules, err := ParseRuleSet(rangeDocument(RulesSchemaSet, true, all...), registry)
				if err != nil {
					t.Fatal(err)
				}
				fact := `{"id":"component.alpha.feature_gates_set","state":"declared","setValue":{"members":["GateB"],"complete":true}}`
				report, err := Evaluate(scopeInput(t, registry, true, componentInput{Component: scopeComponentA, From: tc.from, To: tc.to, Fact: fact}), rules, now)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := MarshalReport(report); err != nil {
					t.Fatalf("report refused: %v", err)
				}
				var entry *NotEvaluatedRule
				for i, skipped := range report.ScopeCompleteness.Components[0].NotEvaluated {
					if skipped.RuleID == "range-set" {
						entry = &report.ScopeCompleteness.Components[0].NotEvaluated[i]
					}
				}
				if entry == nil {
					t.Fatalf("set rule not enumerated: %+v", report.ScopeCompleteness)
				}
				if tc.undetermined {
					if report.Assessment == AssessmentScopeCompletePass || entry.Applicability != ApplicabilityUndetermined || entry.ReasonCode != ReasonReleaseBoundaryNotReviewed {
						t.Fatalf("%s: %s/%s", report.Assessment, entry.Applicability, entry.ReasonCode)
					}
				} else if entry.Applicability != ApplicabilityNotApplicable || entry.ReasonCode != "RULE_TRANSITION_NOT_REVIEWED" {
					t.Fatalf("%s/%s", entry.Applicability, entry.ReasonCode)
				}
			})
		}
	}
}
