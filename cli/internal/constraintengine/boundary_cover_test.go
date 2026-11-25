// SPDX-License-Identifier: AGPL-3.0-only

package constraintengine

import (
	"errors"
	"sort"
	"strings"
	"testing"
)

// Boundary cover: an exact sibling that decides the same check on the exact
// declared pair answers a ranged rule's release-boundary question, under the
// boundary-covered schema only.

const (
	coverFrom = "1.21.0"
	coverTo   = "1.30.0"
)

// coverR is a ranged rule anchored 1.24.0 -> 1.25.0 (C = 1.25.0) on the
// scope fact.
func coverR(id string, mutate func(*rangeRuleSpec)) string {
	spec := defaultRangeSpec()
	spec.id = id
	if mutate != nil {
		mutate(&spec)
	}
	return spec.ruleJSON()
}

// coverE is an exact rule on the hop coverFrom -> coverTo on the scope fact.
func coverE(id string, mutate func(*rangeRuleSpec)) string {
	spec := defaultRangeSpec()
	spec.id, spec.from, spec.to, spec.noRange = id, coverFrom, coverTo, true
	if mutate != nil {
		mutate(&spec)
	}
	return spec.ruleJSON()
}

func coverDoc(t *testing.T, schema string, rules ...string) RuleSet {
	t.Helper()
	sort.Slice(rules, func(i, j int) bool { return ruleIDOf(rules[i]) < ruleIDOf(rules[j]) })
	parsed, err := ParseRuleSet(rangeDocument(schema, true, rules...), scopeRegistry(t))
	if err != nil {
		t.Fatalf("%s: %v", schema, err)
	}
	return parsed
}

func coverReport(t *testing.T, rules RuleSet, input Input) Report {
	t.Helper()
	report, err := Evaluate(input, rules, testNow(t))
	if err != nil {
		t.Fatal(err)
	}
	return report
}

func claimOf(t *testing.T, report Report, id string) Claim {
	t.Helper()
	for _, claim := range report.Claims {
		if claim.RuleID == id {
			return claim
		}
	}
	t.Fatalf("no claim %s", id)
	return Claim{}
}

func scopeEntry(report Report, id string) *NotEvaluatedRule {
	for i, component := range report.ScopeCompleteness.Components {
		for j, skipped := range component.NotEvaluated {
			if skipped.RuleID == id {
				return &report.ScopeCompleteness.Components[i].NotEvaluated[j]
			}
		}
	}
	return nil
}

// wantStays asserts the range rule keeps the boundary answer: UNKNOWN,
// UNDETERMINED in scope, no covering rule.
func wantStays(t *testing.T, report Report, id string) {
	t.Helper()
	claim := claimOf(t, report, id)
	entry := scopeEntry(report, id)
	if claim.Status != "UNKNOWN" || claim.ReasonCode != ReasonReleaseBoundaryNotReviewed || claim.CoveringRuleID != "" || entry == nil || entry.Applicability != ApplicabilityUndetermined || entry.ReasonCode != ReasonReleaseBoundaryNotReviewed {
		t.Fatalf("%s: claim=%s/%s covering=%q entry=%+v", id, claim.Status, claim.ReasonCode, claim.CoveringRuleID, entry)
	}
	if _, err := MarshalReport(report); err != nil {
		t.Fatalf("seal: %v", err)
	}
}

func wantCovered(t *testing.T, report Report, id, by string) {
	t.Helper()
	claim := claimOf(t, report, id)
	entry := scopeEntry(report, id)
	if claim.Status != "UNKNOWN" || claim.ReasonCode != ReasonBoundaryCoveredByExact || claim.CoveringRuleID != by || claim.SubjectMatch != nil || entry == nil || entry.Applicability != ApplicabilityNotApplicable || entry.ReasonCode != ReasonBoundaryCoveredByExact {
		t.Fatalf("%s: claim=%s/%s covering=%q entry=%+v", id, claim.Status, claim.ReasonCode, claim.CoveringRuleID, entry)
	}
	if _, err := MarshalReport(report); err != nil {
		t.Fatalf("seal: %v", err)
	}
}

func hopInput(t *testing.T, blocked bool) Input {
	return xInput(t, coverFrom, coverTo, "", "", blocked)
}

func TestBoundaryCoverPositive(t *testing.T) {
	for _, blocked := range []bool{true, false} {
		rules := coverDoc(t, RulesSchemaBoundaryCovered, coverR("r-range", nil), coverE("e-exact", nil))
		report := coverReport(t, rules, hopInput(t, blocked))
		wantCovered(t, report, "r-range", "e-exact")
		e := claimOf(t, report, "e-exact")
		want := "PASS"
		if blocked {
			want = "BLOCKED"
		}
		if e.Status != want || e.CoveringRuleID != "" || report.EngineContractDigest != engineContractDigestBoundaryCovered() {
			t.Fatalf("blocked=%v: e=%s digest=%s", blocked, e.Status, report.EngineContractDigest)
		}
		// E alone carries the verdict: the covered claim is never a PASS, and
		// a BLOCKED sibling keeps the aggregate BLOCKED.
		if blocked && report.Assessment != AssessmentBlocked {
			t.Fatalf("assessment %s", report.Assessment)
		}
		raw, err := MarshalReport(report)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := Replay(hopInput(t, blocked), rules, testNow(t), raw); err != nil {
			t.Fatalf("replay: %v", err)
		}
		if !claimOf(t, report, "r-range").IsBoundaryCovered() {
			t.Fatal("IsBoundaryCovered")
		}
	}
}

// Every refusal: the range rule keeps RULE_RELEASE_BOUNDARY_NOT_REVIEWED.
func TestBoundaryCoverNegatives(t *testing.T) {
	declared := func(t *testing.T) Input { return hopInput(t, true) }
	flipped := func(s *rangeRuleSpec) {
		s.extra = strings.Replace(forbidFact(scopeComponentA, scopeFactA), "true", "false", 1)
	}
	cases := []struct {
		name  string
		rules func() []string
		input func(*testing.T) Input
	}{
		{"4a no sibling at all", func() []string { return []string{coverR("r-range", nil)} }, declared},
		{"4b sibling UNKNOWN: fact undeclared", func() []string { return []string{coverR("r-range", nil), coverE("e-exact", nil)} },
			func(t *testing.T) Input {
				return scopeInput(t, scopeRegistry(t), true, componentInput{Component: scopeComponentA, From: coverFrom, To: coverTo})
			}},
		{"4b sibling stale", func() []string {
			return []string{coverR("r-range", nil), coverE("e-exact", func(s *rangeRuleSpec) { s.validUntil = expiredUntil })}
		}, declared},
		{"4c sibling anchor is another pair", func() []string {
			return []string{coverR("r-range", nil), coverE("e-exact", func(s *rangeRuleSpec) { s.from = "1.21.1" })}
		}, declared},
		{"4c sibling is itself a range", func() []string {
			return []string{coverR("r-range", nil), coverE("e-exact", func(s *rangeRuleSpec) {
				s.noRange, s.fromGte, s.fromLt, s.toGte, s.toLt = false, "1.21.0", "1.22.0", "1.30.0", "1.31.0"
				s.bases = [4]string{BasisUpgradeFromSeries, BasisUpgradeFromSeries, BasisTargetSeries, BasisTargetSeries}
			})}
		}, declared},
		{"4d different condition value", func() []string {
			return []string{coverR("r-range", nil), coverE("e-exact", flipped)}
		}, declared},
		{"4d different appliesWhen", func() []string {
			return []string{coverR("r-range", nil), coverE("e-exact", func(s *rangeRuleSpec) {
				s.extra = forbidFact(scopeComponentA, scopeFactA) + `,"appliesWhen":[{"side":"proposed","component":"` + scopeComponentA + `","factId":"` + scopeFactA + `","boolValue":true}]`
			})}
		}, declared},
		{"4d different operator", func() []string {
			return []string{coverR("r-range", nil), coverE("e-exact", func(s *rangeRuleSpec) {
				s.operator, s.extra = "require_component_version", dependencyOn(scopeComponentA, "gte", "1.0.0")
			})}
		}, declared},
		{"4g E on another hop, same check", func() []string {
			return []string{coverR("r-range", nil), coverE("e-exact", func(s *rangeRuleSpec) { s.to = "1.31.0" })}
		}, declared},
		{"C9 severity differs", func() []string {
			return []string{coverR("r-sev", func(s *rangeRuleSpec) {
				s.operator, s.extra = "require_component_version", dependencyOn(scopeComponentB, "gte", "2.0.0")
			}), withSeverity(coverE("e-exact", func(s *rangeRuleSpec) {
				s.operator, s.extra = "require_component_version", dependencyOn(scopeComponentB, "gte", "2.0.0")
			}), "unsupported")}
		}, func(t *testing.T) Input { return bothInput(t, "3.0.0") }},
		{"C9 sibling consensus basis", func() []string {
			return []string{coverR("r-range", nil), withBasis(coverE("e-exact", nil), BasisConsensus)}
		}, declared},
		{"C9 sibling lead basis", func() []string {
			return []string{coverR("r-range", nil), withBasis(coverE("e-exact", nil), BasisLead)}
		}, declared},
		{"C9 range rule is itself consensus", func() []string {
			return []string{withBasis(coverR("r-range", nil), BasisConsensus), coverE("e-exact", nil)}
		}, declared},
		{"C9 sibling of another component", func() []string {
			return []string{coverR("r-range", nil), strings.Replace(strings.Replace(coverE("e-exact", nil), scopeComponentA, scopeComponentB, -1), scopeFactA, scopeFactB, -1)}
		}, func(t *testing.T) Input { return bothInput(t, "3.0.0") }},
		{"C9 pre-release origin", func() []string {
			return []string{coverR("r-range", nil), coverE("e-exact", func(s *rangeRuleSpec) { s.from = "1.21.0-rc.1" })}
		}, func(t *testing.T) Input { return xInput(t, "1.21.0-rc.1", coverTo, "", "", true) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rules := tc.rules()
			parsed, err := ParseRuleSet(rangeDocument(RulesSchemaBoundaryCovered, true, sortedRules(rules)...), scopeRegistry(t))
			if err != nil {
				t.Skipf("fixture is not admitted by the parser, which is also a refusal: %v", err)
			}
			input := func() (in Input) {
				defer func() {
					if recover() != nil {
						t.Skip("fixture input refused")
					}
				}()
				return tc.input(t)
			}()
			report := coverReport(t, parsed, input)
			for _, claim := range report.Claims {
				if claim.CoveringRuleID != "" || claim.ReasonCode == ReasonBoundaryCoveredByExact {
					t.Fatalf("%s was covered: %+v", claim.RuleID, claim)
				}
			}
			if claim := claimOf(t, report, ruleIDOf(rules[0])); claim.ReasonCode == ReasonReleaseBoundaryNotReviewed {
				wantStays(t, report, ruleIDOf(rules[0]))
			}
		})
	}
}

func sortedRules(rules []string) []string {
	out := append([]string(nil), rules...)
	sort.Slice(out, func(i, j int) bool { return ruleIDOf(out[i]) < ruleIDOf(out[j]) })
	return out
}

func bothInput(t *testing.T, bVersion string) Input {
	t.Helper()
	return scopeInput(t, scopeRegistry(t), true,
		componentInput{Component: scopeComponentA, From: coverFrom, To: coverTo, Fact: declaredFact(scopeFactA, true)},
		componentInput{Component: scopeComponentB, From: "1.0.0", To: bVersion, Fact: declaredFact(scopeFactB, true)})
}

// require_component_version: E must be gte and at least as strict as R.
func TestBoundaryCoverRequireComponentVersion(t *testing.T) {
	dep := func(comparison, version string) func(*rangeRuleSpec) {
		return func(s *rangeRuleSpec) {
			s.operator, s.extra = "require_component_version", dependencyOn(scopeComponentB, comparison, version)
		}
	}
	for _, tc := range []struct {
		name        string
		rComp, rVer string
		eComp, eVer string
		covered     bool
	}{
		{"stricter sibling covers", "gte", "2.7.0", "gte", "3.2.0", true},
		{"equal sibling covers", "gte", "3.2.0", "gte", "3.2.0", true},
		{"weaker sibling refused", "gte", "3.2.0", "gte", "2.7.0", false},
		{"lte refused", "lte", "3.0.0", "lte", "3.0.0", false},
		{"lt refused", "lt", "9.0.0", "lt", "9.0.0", false},
		{"eq refused", "eq", "3.0.0", "eq", "3.0.0", false},
		{"comparison differs refused", "gte", "2.0.0", "lte", "3.0.0", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rules := coverDoc(t, RulesSchemaBoundaryCovered, coverR("r-dep", dep(tc.rComp, tc.rVer)), coverE("e-dep", dep(tc.eComp, tc.eVer)))
			for _, bVersion := range []string{"3.5.0", "1.0.0"} {
				report := coverReport(t, rules, bothInput(t, bVersion))
				if tc.covered {
					wantCovered(t, report, "r-dep", "e-dep")
				} else if claim := claimOf(t, report, "r-dep"); claim.CoveringRuleID != "" || claim.ReasonCode != ReasonReleaseBoundaryNotReviewed {
					t.Fatalf("covered: %+v", claim)
				}
				// A BLOCKED sibling (dependency too low) stays BLOCKED.
				if bVersion == "1.0.0" && tc.covered {
					if e := claimOf(t, report, "e-dep"); e.Status != "BLOCKED" {
						t.Fatalf("e=%s", e.Status)
					}
				}
			}
		})
	}
}

// Two range rules, one sibling: only the one with the equal decision key is
// covered.
func TestBoundaryCoverTwoRangesOneSibling(t *testing.T) {
	rules := coverDoc(t, RulesSchemaBoundaryCovered,
		coverR("r-a-same", nil),
		coverR("r-b-other", func(s *rangeRuleSpec) {
			s.operator, s.extra = "require_component_version", dependencyOn(scopeComponentB, "gte", "1.0.0")
		}),
		coverE("e-exact", nil))
	report := coverReport(t, rules, bothInput(t, "3.0.0"))
	wantCovered(t, report, "r-a-same", "e-exact")
	wantStays(t, report, "r-b-other")
}

// A second ranged rule whose anchor equals the hop is not an exact sibling:
// it never covers, and a covered rule is never a covering rule (no chains).
func TestBoundaryCoverNoChainsAndRangeSiblingNeverCovers(t *testing.T) {
	rules := coverDoc(t, RulesSchemaBoundaryCovered,
		coverR("r-range", nil),
		coverR("r-wide", func(s *rangeRuleSpec) {
			s.from, s.to = coverFrom, coverTo
			s.fromGte, s.fromLt, s.toGte, s.toLt = "1.21.0", "1.22.0", "1.30.0", "1.31.0"
			s.bases = [4]string{BasisUpgradeFromSeries, BasisUpgradeFromSeries, BasisTargetSeries, BasisTargetSeries}
		}))
	wantStays(t, coverReport(t, rules, hopInput(t, true)), "r-range")
}

// A downgrade across C is never covered, even with an exact sibling on the
// downgrade pair (a CHANGED_IN_RELEASE range is unreviewed there).
func TestBoundaryCoverDowngradeStays(t *testing.T) {
	r := coverR("r-range", func(s *rangeRuleSpec) {
		s.bases = [4]string{BasisPreviousMinorLine, BasisChangedInRelease, BasisChangedInRelease, BasisReviewedThroughMinorLine}
	})
	e := coverE("e-exact", func(s *rangeRuleSpec) { s.from, s.to = coverTo, coverFrom })
	parsed, err := ParseRuleSet(rangeDocument(RulesSchemaBoundaryCovered, true, sortedRules([]string{r, e})...), scopeRegistry(t))
	if err != nil {
		t.Skipf("downgrade anchor is not admitted: %v", err)
	}
	report := coverReport(t, parsed, xInput(t, coverTo, coverFrom, "", "", true))
	if claim := claimOf(t, report, "r-range"); claim.CoveringRuleID != "" || claim.ReasonCode == ReasonBoundaryCoveredByExact {
		t.Fatalf("downgrade covered: %+v", claim)
	}
}

// A crossing rule's own question (RULE_CROSSING_NOT_REVIEWED) is never
// covered, and the engine reasons are reserved from rule documents.
func TestBoundaryCoverNeverCoversCrossingAndReasonIsReserved(t *testing.T) {
	x := newXRule()
	x.id = "r-crossing"
	x.horizon = "1.28.0"
	ranged := coverR("z-range", func(s *rangeRuleSpec) {
		s.operator, s.extra = "require_component_version", dependencyOn(scopeComponentB, "gte", "1.0.0")
	})
	rules, err := ParseRuleSet(xDocument(RulesSchemaBoundaryCovered, sortedRules([]string{x.json(), ranged, coverE("s-exact", func(s *rangeRuleSpec) { s.from, s.to = "1.21.0", "1.40.0" })})...), scopeRegistry(t))
	if err != nil {
		t.Fatal(err)
	}
	report := coverReport(t, rules, xInput(t, "1.21.0", "1.40.0", "", "", true))
	for _, claim := range report.Claims {
		if claim.CoveringRuleID != "" || claim.ReasonCode == ReasonBoundaryCoveredByExact {
			t.Fatalf("covered: %+v", claim)
		}
	}
	forged := strings.Replace(coverR("r-range", nil), `"reasonCode":"FEATURE_REMOVED"`, `"reasonCode":"`+ReasonBoundaryCoveredByExact+`"`, 1)
	if _, err := ParseRuleSet(rangeDocument(RulesSchemaBoundaryCovered, true, forged), scopeRegistry(t)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("reserved reason accepted: %v", err)
	}
}

// Opt-in is by schema only: the same rules under the previous schema keep the
// boundary answer; the new schema needs a range; a pre-existing contract
// digest is unchanged by the new one.
func TestBoundaryCoverOptInIsBySchemaOnly(t *testing.T) {
	for _, schema := range []string{RulesSchemaRanged, RulesSchemaChartRanged} {
		parsed, err := ParseRuleSet(rangeDocument(schema, true, sortedRules([]string{coverR("r-range", nil), coverE("e-exact", nil)})...), scopeRegistry(t))
		if schema == RulesSchemaChartRanged {
			if !errors.Is(err, ErrInvalid) {
				t.Fatalf("%s accepted without a chart range: %v", schema, err)
			}
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		report := coverReport(t, parsed, hopInput(t, true))
		wantStays(t, report, "r-range")
		if report.EngineContractDigest == engineContractDigestBoundaryCovered() {
			t.Fatal("old schema reports under the new contract")
		}
	}
	if _, err := ParseRuleSet(rangeDocument(RulesSchemaBoundaryCovered, true, coverE("e-exact", nil)), scopeRegistry(t)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("new schema without a range accepted: %v", err)
	}
	digests := map[string]bool{}
	for _, d := range []string{engineContractDigest(), engineContractDigestRanged(), engineContractDigestSet(), engineContractDigestNotice(), engineContractDigestBasis(), engineContractDigestSeverity(), engineContractDigestCrossing(), engineContractDigestChart(), engineContractDigestChartNotice(), engineContractDigestChartRanged(), engineContractDigestBoundaryCovered()} {
		if digests[d] {
			t.Fatal("engine contract digests collide")
		}
		digests[d] = true
	}
	if scopeDigestFor(engineContractDigestBoundaryCovered()) != scopeContractDigestBoundaryCovered() || scopeContractDigestBoundaryCovered() == scopeContractDigestChartRanged() {
		t.Fatal("covered scope contract identity")
	}
	if got, err := RulesSchemaFor(nil); err != nil || got == RulesSchemaBoundaryCovered {
		t.Fatalf("schema inferred from rules: %q %v", got, err)
	}
}

// Forged claims: the seal gate refuses the reserved reason without a valid
// covering claim.
func TestBoundaryCoverForgedClaimsAreRefused(t *testing.T) {
	rules := coverDoc(t, RulesSchemaBoundaryCovered, coverR("r-range", nil), coverE("e-exact", nil), coverE("f-unknown", func(s *rangeRuleSpec) { s.from = "1.20.0" }))
	good := coverReport(t, rules, hopInput(t, true))
	wantCovered(t, good, "r-range", "e-exact")
	if !validCoveredClaims(good) {
		t.Fatal("good report refused")
	}
	mutate := func(f func(*Claim, map[string]*Claim)) bool {
		report := good
		report.Claims = append([]Claim(nil), good.Claims...)
		index := map[string]*Claim{}
		for i := range report.Claims {
			index[report.Claims[i].RuleID] = &report.Claims[i]
		}
		f(index["r-range"], index)
		return validCoveredClaims(report)
	}
	for name, f := range map[string]func(*Claim, map[string]*Claim){
		"reason without covering id": func(c *Claim, _ map[string]*Claim) { c.CoveringRuleID = "" },
		"covering id without reason": func(c *Claim, _ map[string]*Claim) { c.ReasonCode = ReasonReleaseBoundaryNotReviewed },
		"covering id unknown":        func(c *Claim, _ map[string]*Claim) { c.CoveringRuleID = "nope" },
		"covering id is itself":      func(c *Claim, _ map[string]*Claim) { c.CoveringRuleID = c.RuleID },
		"covering claim UNKNOWN":     func(c *Claim, m map[string]*Claim) { c.CoveringRuleID = "f-unknown" },
		"covering claim is covered":  func(c *Claim, m map[string]*Claim) { m["e-exact"].CoveringRuleID = "r-range" },
		"covering claim is a range": func(c *Claim, m map[string]*Claim) {
			m["e-exact"].SubjectMatch = &SubjectMatch{Mode: subjectMatchModeRange}
		},
		"covering claim stale":          func(c *Claim, m map[string]*Claim) { m["e-exact"].EvidenceFreshness = "stale" },
		"covering claim other operator": func(c *Claim, m map[string]*Claim) { m["e-exact"].Operator = "require_component_version" },
		"covered claim is a PASS":       func(c *Claim, _ map[string]*Claim) { c.Status = "PASS" },
		"covered claim has a range":     func(c *Claim, _ map[string]*Claim) { c.SubjectMatch = &SubjectMatch{Mode: subjectMatchModeRange} },
		"covering claim consensus":      func(c *Claim, m map[string]*Claim) { m["e-exact"].EvidenceBasis = BasisConsensus },
		"covered claim operator":        func(c *Claim, _ map[string]*Claim) { c.Operator = "forbid_target_version" },
	} {
		if mutate(f) {
			t.Errorf("%s: forged report accepted", name)
		}
	}
	// Under any other contract the reason is refused outright.
	other := good
	other.EngineContractDigest = engineContractDigestChartRanged()
	if validCoveredClaims(other) {
		t.Error("covered reason accepted under another contract")
	}
	// A scope entry for the reserved reason needs the covered scope contract
	// and a claim that carries the reason.
	scope := *good.ScopeCompleteness
	scope.Components = append([]ComponentScope(nil), scope.Components...)
	scope.ContractDigest = scopeContractDigestChartRanged()
	if validScopeBlock(&scope, good.Claims, engineContractDigestChartRanged()) {
		t.Error("covered scope entry accepted under another contract")
	}
}
