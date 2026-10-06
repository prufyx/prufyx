// SPDX-License-Identifier: AGPL-3.0-only

package constraintengine

import "testing"

// crossingRule is a removal rule with change version C = 1.22.0: from.lt and
// to.gte are both C, so a range match means from < C <= to.
func crossingRule(c string) RuleTransition {
	return RuleTransition{Component: scopeComponentA, From: "1.21.0", To: "1.22.0", Range: &VersionRange{
		From: VersionBound{Gte: "1.21.0", Lt: c},
		To:   VersionBound{Gte: c, Lt: "1.23.0"},
	}}
}

var crossingProbes = []struct {
	name, from, to string
	want           MatchMode
}{
	{"anchor", "1.21.0", "1.22.0", MatchAnchor},
	{"below C -> at C", "1.21.5", "1.22.0", MatchRange},
	{"below C -> above C", "1.21.9", "1.22.4", MatchRange},
	{"below C -> still below C", "1.21.2", "1.21.9", MatchNone},
	{"at C -> above C (already past C)", "1.22.0", "1.22.4", MatchNone},
	{"above C -> above C", "1.22.3", "1.22.9", MatchNone},
	{"origin below the reviewed range", "1.20.9", "1.22.1", MatchNone},
	{"multi-minor hop starting below range", "1.20.5", "1.22.0", MatchNone},
	{"multi-minor hop ending past the reviewed range", "1.21.5", "1.24.0", MatchNone},
	{"multi-minor hop far past the range", "1.21.5", "1.35.6", MatchNone},
	{"origin far above (real cluster)", "1.35.6", "1.36.0", MatchNone},
	{"downgrade across C", "1.22.4", "1.21.5", MatchNone},
	{"unparseable origin", "v1.21.5", "1.22.1", MatchNone},
	{"unknown (empty) origin", "", "1.22.1", MatchNone},
}

func TestRangeCrossingSemantics(t *testing.T) {
	rule := crossingRule("1.22.0")
	for _, tc := range crossingProbes {
		if got := rule.Match(tc.from, tc.to); got != tc.want {
			t.Errorf("%s: %s -> %s = %q, want %q", tc.name, tc.from, tc.to, got, tc.want)
		}
		// Invariant behind the semantics: a range match always crosses C.
		if rule.Match(tc.from, tc.to) == MatchRange && !(VersionLess(tc.from, "1.22.0") && !VersionLess(tc.to, "1.22.0")) {
			t.Errorf("%s: range matched a hop that does not satisfy from < C <= to", tc.name)
		}
	}
}

// TestRangeCrossingOutOfRangeIsUnknownNeverPass proves fail-closed at claim
// level: the fact is declared safe (which would PASS inside the range), yet
// every hop that is not covered by the reviewed range stays UNKNOWN.
func TestRangeCrossingOutOfRangeIsUnknownNeverPass(t *testing.T) {
	spec := defaultRangeSpec()
	spec.from, spec.to = "1.21.0", "1.22.0"
	spec.fromGte, spec.fromLt, spec.toGte, spec.toLt = "1.21.0", "1.22.0", "1.22.0", "1.23.0"
	rules := parseRanged(t, false, spec.ruleJSON())
	for _, tc := range crossingProbes {
		if tc.from == "" || tc.from[0] == 'v' {
			continue // an unparseable declared version is refused at input parse, before any verdict
		}
		input := rangeInput(t, tc.from, tc.to, declaredFact(scopeFactA, false), false)
		report, err := Evaluate(input, rules, testNow(t))
		if err != nil {
			t.Fatal(err)
		}
		claim := report.Claims[0]
		if tc.want == MatchNone && claim.Status == "PASS" {
			t.Errorf("%s: PASS outside the reviewed range", tc.name)
		}
		if tc.want == MatchNone && claim.Status != "UNKNOWN" {
			t.Errorf("%s: status=%s, want UNKNOWN", tc.name, claim.Status)
		}
		if tc.want != MatchNone && claim.Status != "PASS" {
			t.Errorf("%s: covered hop with a safe fact status=%s, want PASS", tc.name, claim.Status)
		}
	}
	// Covered hop whose fact is not observed must not PASS.
	input := rangeInput(t, "1.21.5", "1.22.1", `{"id":"`+scopeFactA+`","state":"missing"}`, false)
	report, err := Evaluate(input, rules, testNow(t))
	if err != nil || report.Claims[0].Status != "UNKNOWN" {
		t.Fatalf("missing fact inside range: %+v err=%v", report.Claims, err)
	}
}

// TestRangeCrossingMutationCheck mutates the rule's bounds and requires the
// probe table to notice every mutant, so the table is not vacuous.
func TestRangeCrossingMutationCheck(t *testing.T) {
	render := func(r RuleTransition) string {
		out := ""
		for _, tc := range crossingProbes {
			out += string(r.Match(tc.from, tc.to)) + "|"
		}
		return out
	}
	baseline := render(crossingRule("1.22.0"))
	mutants := map[string]RuleTransition{}
	m := crossingRule("1.22.0")
	m.Range.From.Lt = "1.21.3" // C moved below the origins
	mutants["from.lt lowered"] = m
	m = crossingRule("1.22.0")
	m.Range.To.Gte = "1.22.1" // target must be past C
	mutants["to.gte raised"] = m
	m = crossingRule("1.22.0")
	m.Range.From.Lt = "1.23.0" // open the origin side past C
	mutants["from.lt widened past C"] = m
	m = crossingRule("1.22.0")
	m.Range.To.Lt = "1.35.7" // open the target side far up
	mutants["to.lt widened"] = m
	m = crossingRule("1.22.0")
	m.Range.From.Gte = "1.20.0"
	mutants["from.gte lowered"] = m
	m = crossingRule("1.22.0")
	m.Range = nil
	mutants["range dropped"] = m
	for name, mutant := range mutants {
		if render(mutant) == baseline {
			t.Errorf("mutant %q survived: probe table did not detect it", name)
		}
	}
}
