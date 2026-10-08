// SPDX-License-Identifier: AGPL-3.0-only

package constraintengine

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

const (
	pinnedEngineContractDigestCrossing = "sha256:1add26d02bbb97eef3b4eabb78f8d944c33667c1ce9be92ee67bd416a7f42da7"
	pinnedScopeContractDigestCrossing  = "sha256:2e55c52dd71335510c0db4eb924c0f426f8529013b54e4ea75156bd824f6b91c"
)

// xRule builds a synthetic crossing rule for tests only: a removal at
// C = 1.25.0 reviewed through H = 1.36.0, anchored 1.24.0 -> 1.25.0.
type xRule struct {
	id, from, to, change, horizon string
	restored                      string
	distributions                 string // raw JSON array, or ""
	operator, basis               string
	horizonBasis, changeBasis     string
	changeSource, horizonSource   string
	extraCrossing                 string
	rng                           string // raw range JSON, or ""
}

func newXRule() xRule {
	return xRule{id: "crossing-rule", from: "1.24.0", to: "1.25.0", change: "1.25.0", horizon: "1.36.0", operator: "forbid_predicate_value",
		horizonBasis: BasisReviewedThroughMinorLine, changeBasis: BasisRemovedInRelease, changeSource: "upstream-doc", horizonSource: "upstream-doc"}
}

func (x xRule) crossingJSON() string {
	out := `{"change":{"version":"` + x.change + `","basis":"` + x.changeBasis + `","sourceId":"` + x.changeSource + `"},"horizon":{"lt":"` + x.horizon + `","basis":"` + x.horizonBasis + `","sourceId":"` + x.horizonSource + `"}`
	if x.restored != "" {
		out += `,"restored":{"version":"` + x.restored + `","basis":"` + BasisRestoredInRelease + `","sourceId":"upstream-doc"}`
	}
	if x.distributions != "" {
		out += `,"distributions":` + x.distributions
	}
	return out + x.extraCrossing + `}`
}

func (x xRule) json() string {
	extra := forbidFact(scopeComponentA, scopeFactA)
	if x.rng != "" {
		extra = `,"range":` + x.rng + extra
	}
	extra = `,"crossing":` + x.crossingJSON() + extra
	evidence := `"evidence":{"state":"active"` + x.basis + `,"reviewedAt":"2026-01-01T00:00:00Z","validUntil":"` + activeUntil + `","sources":[{"id":"upstream-doc","url":"https://github.com/example/controller/blob/` + testRevision + `/docs/upgrade.md","revision":"` + testRevision + `","contentDigest":"` + testDigest + `","startLine":10,"endLine":12}]}`
	return `{"id":"` + x.id + `","operator":"` + x.operator + `","subject":{"component":"` + scopeComponentA + `","from":"` + x.from + `","to":"` + x.to + `"}` + extra + `,` + evidence + `,"reasonCode":"FEATURE_REMOVED","nextAction":"remove the reviewed feature before upgrade"}`
}

func xDocument(schema string, rules ...string) []byte {
	return rangeDocument(schema, true, rules...)
}

func parseCrossing(t *testing.T, rules ...string) RuleSet {
	t.Helper()
	parsed, err := ParseRuleSet(xDocument(RulesSchemaCrossing, rules...), scopeRegistry(t))
	if err != nil {
		t.Fatalf("parse crossing rules: %v", err)
	}
	return parsed
}

func xInput(t *testing.T, from, to, fromDist, toDist string, blocked bool) Input {
	t.Helper()
	dist := func(d string) string {
		if d == "" {
			return ""
		}
		return `"distribution":"` + d + `",`
	}
	raw := `{"schema":"` + InputSchema + `","authority":"` + InputAuthority + `","current":{"components":[{"component":"` + scopeComponentA + `","version":"` + from + `",` + dist(fromDist) + `"facts":[]}]},"proposed":{"components":[{"component":"` + scopeComponentA + `","version":"` + to + `",` + dist(toDist) + `"facts":[` + declaredFact(scopeFactA, blocked) + `]}]},"scope":{"declaration":"` + ScopeDeclaration + `","components":["` + scopeComponentA + `"]}}`
	input, err := ParseInput([]byte(raw), scopeRegistry(t))
	if err != nil {
		t.Fatalf("parse input %s: %v", raw, err)
	}
	return input
}

func xSpec(restored string) *CrossingSpec {
	c := &CrossingSpec{Change: CrossingChange{Version: "1.25.0", Basis: BasisRemovedInRelease, SourceID: "s"}, Horizon: CrossingHorizon{Lt: "1.36.0", Basis: BasisReviewedThroughMinorLine, SourceID: "s"}}
	if restored != "" {
		c.Restored = &CrossingRestored{Version: restored, Basis: BasisRestoredInRelease, SourceID: "s"}
	}
	return c
}

func xTransition(c *CrossingSpec) RuleTransition {
	return RuleTransition{Component: scopeComponentA, From: "1.24.0", To: "1.25.0", Crossing: c}
}

type xProbe struct {
	name, from, to string
	restored       string
	want           MatchMode
}

var xProbes = []xProbe{
	{"anchor stays anchor", "1.24.0", "1.25.0", "", MatchAnchor},
	{"below C -> at C", "1.24.5", "1.25.0", "", MatchCrossing},
	{"below C -> above C", "1.24.5", "1.25.3", "", MatchCrossing},
	{"below C -> below C", "1.24.0", "1.24.9", "", MatchNone},
	{"at C -> above C", "1.25.0", "1.25.4", "", MatchNone},
	{"above C -> above C", "1.26.1", "1.30.0", "", MatchNone},
	{"wide hop 1.21 -> 1.35", "1.21.0", "1.35.0", "", MatchCrossing},
	{"wide hop 1.21.7 -> 1.35.9 (last patch below H)", "1.21.7", "1.35.9", "", MatchCrossing},
	{"hop to H is beyond the horizon", "1.21.0", "1.36.0", "", MatchNone},
	{"hop far beyond the horizon", "1.21.0", "1.40.2", "", MatchNone},
	{"restored caps: below R", "1.21.0", "1.29.9", "1.30.0", MatchCrossing},
	{"restored caps: at R", "1.21.0", "1.30.0", "1.30.0", MatchNone},
	{"restored caps: above R", "1.21.0", "1.35.0", "1.30.0", MatchNone},
	{"downgrade across C", "1.26.0", "1.24.0", "", MatchNone},
	{"downgrade inside the wide region", "1.35.0", "1.21.0", "", MatchNone},
	{"equal pair", "1.30.0", "1.30.0", "", MatchNone},
	{"unparseable origin", "v1.21.0", "1.35.0", "", MatchNone},
	{"unparseable target", "1.21.0", "1.35", "", MatchNone},
	{"pre-release target", "1.21.0", "1.35.0-rc.1", "", MatchNone},
	{"empty origin", "", "1.35.0", "", MatchNone},
}

func xRender(probes []xProbe, build func(restored string) RuleTransition) string {
	out := ""
	for _, p := range probes {
		out += string(build(p.restored).Match(p.from, p.to)) + "|"
	}
	return out
}

func TestCrossingMatcherTable(t *testing.T) {
	for _, p := range xProbes {
		got := xTransition(xSpec(p.restored)).Match(p.from, p.to)
		if got != p.want {
			t.Errorf("%s: %s -> %s = %q, want %q", p.name, p.from, p.to, got, p.want)
		}
		// Invariant: a crossing match is a strict upgrade across C below the cap.
		if got == MatchCrossing {
			spec := xSpec(p.restored)
			if !(VersionLess(p.from, "1.25.0") && !VersionLess(p.to, "1.25.0") && VersionLess(p.from, p.to) && VersionLess(p.to, spec.Cap())) {
				t.Errorf("%s: crossing matched outside from < C <= to < cap", p.name)
			}
		}
	}
	// Without a crossing object nothing crosses.
	if got := xTransition(nil).Match("1.21.0", "1.35.0"); got != MatchNone {
		t.Fatalf("no crossing object: %q", got)
	}
	// Partial filters stay consistent with the matcher.
	tr := xTransition(xSpec(""))
	if !tr.MatchesFrom("1.21.0") || tr.MatchesFrom("1.25.0") || !tr.MatchesTo("1.35.9") || tr.MatchesTo("1.36.0") || tr.MatchesTo("1.24.9") {
		t.Fatal("MatchesFrom/MatchesTo disagree with the crossing region")
	}
}

// TestCrossingMutationCheck mutates the crossing spec (its change version,
// horizon, restoration and presence) and requires the probe table to notice
// each mutant. The comparison operators of the matcher are covered by the
// probe table itself (TestCrossingMatcherTable), not mutated here.
func TestCrossingMutationCheck(t *testing.T) {
	baseline := xRender(xProbes, func(r string) RuleTransition { return xTransition(xSpec(r)) })
	mutants := map[string]func(restored string) RuleTransition{
		"C moved up": func(r string) RuleTransition {
			s := xSpec(r)
			s.Change.Version = "1.26.0"
			return xTransition(s)
		},
		"C moved down": func(r string) RuleTransition {
			s := xSpec(r)
			s.Change.Version = "1.24.1"
			return xTransition(s)
		},
		"horizon widened": func(r string) RuleTransition {
			s := xSpec(r)
			s.Horizon.Lt = "1.41.0"
			return xTransition(s)
		},
		"horizon narrowed": func(r string) RuleTransition {
			s := xSpec(r)
			s.Horizon.Lt = "1.30.0"
			return xTransition(s)
		},
		"restored ignored": func(r string) RuleTransition { return xTransition(xSpec("")) },
		"crossing dropped": func(r string) RuleTransition { return xTransition(nil) },
	}
	for name, build := range mutants {
		if xRender(xProbes, build) == baseline {
			t.Errorf("mutant %q survived: probe table did not detect it", name)
		}
	}
}

// TestCrossingNeverProducesPass is the claim-level table: every hop that
// matches only by crossing is BLOCKED when the fact blocks and UNKNOWN with
// RULE_CROSSING_PASS_NOT_REVIEWED when it does not, never PASS; hops outside
// the crossing region keep their old UNKNOWN; the anchor keeps its PASS.
func TestCrossingNeverProducesPass(t *testing.T) {
	now := testNow(t)
	for _, restored := range []string{"", "1.30.0"} {
		spec := newXRule()
		spec.restored = restored
		rules := parseCrossing(t, spec.json())
		for _, p := range xProbes {
			if p.restored != restored || p.from == "" || p.from[0] == 'v' || p.to == "1.35" || strings.Contains(p.to, "rc") {
				continue
			}
			for _, blocked := range []bool{true, false} {
				report, err := Evaluate(xInput(t, p.from, p.to, "", "", blocked), rules, now)
				if err != nil {
					t.Fatal(err)
				}
				claim := report.Claims[0]
				switch p.want {
				case MatchCrossing:
					if claim.CrossingMatch == nil || claim.CrossingMatch.Change != "1.25.0" || !strings.Contains(claim.NextAction, "crossing") && !blocked {
						t.Errorf("%s blocked=%v: no crossing disclosure: %+v", p.name, blocked, claim)
					}
					if blocked && (claim.Status != "BLOCKED" || !strings.Contains(claim.NextAction, "matched by removal crossing 1.25.0")) {
						t.Errorf("%s: crossing with a blocking fact = %s %q", p.name, claim.Status, claim.NextAction)
					}
					if !blocked && (claim.Status != "UNKNOWN" || claim.ReasonCode != ReasonCrossingPassNotReviewed) {
						t.Errorf("%s: crossing with a safe fact = %s/%s, want UNKNOWN/%s", p.name, claim.Status, claim.ReasonCode, ReasonCrossingPassNotReviewed)
					}
				case MatchAnchor:
					if !blocked && claim.Status != "PASS" || claim.CrossingMatch != nil {
						t.Errorf("%s: anchor must keep PASS and carry no crossing disclosure: %+v", p.name, claim)
					}
				default:
					// A pair outside the region keeps UNKNOWN. When it still
					// crosses C (beyond the horizon, at or above a restoration)
					// the reason is the crossing contract's undetermined one,
					// otherwise it stays the exclusion reason.
					wantReason := "RULE_TRANSITION_NOT_REVIEWED"
					if VersionLess(p.from, "1.25.0") && !VersionLess(p.to, "1.25.0") && VersionLess(p.from, p.to) {
						wantReason = ReasonCrossingNotReviewed
					}
					if claim.Status != "UNKNOWN" || claim.ReasonCode != wantReason || claim.CrossingMatch != nil {
						t.Errorf("%s blocked=%v: outside region = %s/%s, want UNKNOWN/%s", p.name, blocked, claim.Status, claim.ReasonCode, wantReason)
					}
				}
				if p.want != MatchAnchor && claim.Status == "PASS" {
					t.Errorf("%s: PASS through a non-anchor hop", p.name)
				}
				if report.Assessment == AssessmentScopeCompletePass && p.want != MatchAnchor {
					t.Errorf("%s: scope-complete pass through a non-anchor hop", p.name)
				}
				if p.want == MatchCrossing && !blocked && report.Assessment != AssessmentUnknown {
					t.Errorf("%s: unreviewed crossing assessment=%s", p.name, report.Assessment)
				}
				if p.want == MatchCrossing && blocked && report.Assessment != AssessmentBlocked {
					t.Errorf("%s: crossing blocker assessment=%s", p.name, report.Assessment)
				}
				raw, err := MarshalReport(report)
				if err != nil {
					t.Fatalf("%s: report refused: %v", p.name, err)
				}
				if _, err := Replay(xInput(t, p.from, p.to, "", "", blocked), rules, now, raw); err != nil {
					t.Fatalf("%s: replay: %v", p.name, err)
				}
				if report.EngineContractDigest != EngineContractDigestCrossing() || report.ScopeCompleteness.ContractDigest != ScopeContractDigestCrossing() {
					t.Fatalf("%s: wrong contract %s", p.name, report.EngineContractDigest)
				}
			}
		}
	}
}

func TestCrossingDistributionScope(t *testing.T) {
	now := testNow(t)
	cases := []struct {
		name, distributions, fromDist, toDist string
		crossing                              bool
	}{
		{"default is upstream only: upstream", "", "", "", true},
		{"default is upstream only: explicit upstream", "", "upstream", "upstream", true},
		{"default is upstream only: gke refused", "", "gke", "gke", false},
		{"gke listed with upstream", `["gke","upstream"]`, "gke", "gke", true},
		{"gke listed, upstream observed", `["gke","upstream"]`, "", "", true},
		{"gke only refuses upstream", `["gke"]`, "upstream", "upstream", false},
		{"one side outside scope", `["upstream"]`, "upstream", "gke", false},
		{"from side outside scope", `["upstream"]`, "gke", "upstream", false},
		{"mixed distributions both listed", `["gke","upstream"]`, "gke", "upstream", true},
	}
	for _, tc := range cases {
		spec := newXRule()
		spec.distributions = tc.distributions
		rules := parseCrossing(t, spec.json())
		report, err := Evaluate(xInput(t, "1.21.3", "1.35.1", tc.fromDist, tc.toDist, true), rules, now)
		if err != nil {
			t.Fatal(err)
		}
		claim := report.Claims[0]
		if tc.crossing && (claim.Status != "BLOCKED" || claim.CrossingMatch == nil) {
			t.Errorf("%s: want BLOCKED crossing, got %s", tc.name, claim.Status)
		}
		if !tc.crossing && (claim.Status != "UNKNOWN" || claim.CrossingMatch != nil || report.Assessment != AssessmentUnknown) {
			t.Errorf("%s: want UNKNOWN outside distribution scope, got %s %s", tc.name, claim.Status, report.Assessment)
		}
	}
}

func TestCrossingParserRejections(t *testing.T) {
	mutate := func(f func(*xRule)) string {
		spec := newXRule()
		f(&spec)
		return spec.json()
	}
	reject := map[string]string{
		"operator not forbid":      mutate(func(x *xRule) { x.operator = "forbid_target_version" }),
		"change basis not removed": mutate(func(x *xRule) { x.changeBasis = BasisChangedInRelease }),
		"horizon basis wrong":      mutate(func(x *xRule) { x.horizonBasis = BasisTargetSeries }),
		"horizon empty":            mutate(func(x *xRule) { x.horizon = "" }),
		"horizon wildcard":         mutate(func(x *xRule) { x.horizon = "*" }),
		"horizon not a minor line": mutate(func(x *xRule) { x.horizon = "1.36.1" }),
		"horizon below change":     mutate(func(x *xRule) { x.horizon = "1.24.0" }),
		"horizon equals change":    mutate(func(x *xRule) { x.horizon = "1.25.0" }),
		"horizon uncited":          mutate(func(x *xRule) { x.horizonSource = "not-a-source" }),
		"horizon empty source":     mutate(func(x *xRule) { x.horizonSource = "" }),
		"change uncited":           mutate(func(x *xRule) { x.changeSource = "not-a-source" }),
		"change not minor start":   mutate(func(x *xRule) { x.change = "1.25.3" }),
		"anchor below the region":  mutate(func(x *xRule) { x.to = "1.24.9" }),
		"anchor above the region":  mutate(func(x *xRule) { x.from = "1.25.1"; x.to = "1.26.0" }),
		"anchor beyond horizon":    mutate(func(x *xRule) { x.horizon = "1.26.0"; x.from = "1.24.0"; x.to = "1.26.0" }),
		"restored at change":       mutate(func(x *xRule) { x.restored = "1.25.0" }),
		"restored above horizon":   mutate(func(x *xRule) { x.restored = "1.40.0" }),
		"restored is a patch":      mutate(func(x *xRule) { x.restored = "1.27.4" }),
		"restored inside change":   mutate(func(x *xRule) { x.restored = "1.25.3" }),
		"restored below change":    mutate(func(x *xRule) { x.restored = "1.20.0" }),
		"horizon 999.0.0":          mutate(func(x *xRule) { x.horizon = "999.0.0" }),
		"horizon next major":       mutate(func(x *xRule) { x.horizon = "2.0.0" }),
		"horizon past the limit":   mutate(func(x *xRule) { x.horizon = "1.38.0" }),
		"distributions empty":      mutate(func(x *xRule) { x.distributions = "[]" }),
		"distributions unknown":    mutate(func(x *xRule) { x.distributions = `["eks"]` }),
		"distributions unsorted":   mutate(func(x *xRule) { x.distributions = `["upstream","gke"]` }),
		"distributions duplicate":  mutate(func(x *xRule) { x.distributions = `["gke","gke"]` }),
		"distributions not text":   mutate(func(x *xRule) { x.distributions = `[1]` }),
		"distributions null":       mutate(func(x *xRule) { x.distributions = `null` }),
		"unknown crossing key":     mutate(func(x *xRule) { x.extraCrossing = `,"open":true` }),
		"consensus basis":          mutate(func(x *xRule) { x.basis = `,"basis":"consensus"` }),
		"lead basis":               mutate(func(x *xRule) { x.basis = `,"basis":"lead"` }),
		"engine reason code":       strings.Replace(newXRule().json(), `"FEATURE_REMOVED"`, `"`+ReasonCrossingPassNotReviewed+`"`, 1),
		"range with other C": mutate(func(x *xRule) {
			x.rng = `{"from":{"gte":"1.24.0","lt":"1.26.0"},"to":{"gte":"1.26.0","lt":"1.27.0"},"bounds":[{"bound":"from.gte","basis":"PREVIOUS_MINOR_LINE","sourceId":"upstream-doc"},{"bound":"from.lt","basis":"REMOVED_IN_RELEASE","sourceId":"upstream-doc"},{"bound":"to.gte","basis":"REMOVED_IN_RELEASE","sourceId":"upstream-doc"},{"bound":"to.lt","basis":"REVIEWED_THROUGH_MINOR_LINE","sourceId":"upstream-doc"}]}`
			x.to = "1.26.0"
		}),
	}
	for name, rule := range reject {
		if !json.Valid([]byte(rule)) {
			t.Fatalf("%s: fixture is not valid JSON", name)
		}
		if _, err := ParseRuleSet(xDocument(RulesSchemaCrossing, rule), scopeRegistry(t)); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: accepted (err=%v)", name, err)
		}
	}
	good := map[string]string{
		"plain":            newXRule().json(),
		"restored":         mutate(func(x *xRule) { x.restored = "1.30.0" }),
		"restored at cap":  mutate(func(x *xRule) { x.restored = "1.36.0" }),
		"horizon at limit": mutate(func(x *xRule) { x.horizon = "1.37.0" }),
		"gke distribution": mutate(func(x *xRule) { x.distributions = `["gke","upstream"]` }),
	}
	for name, rule := range good {
		if _, err := ParseRuleSet(xDocument(RulesSchemaCrossing, rule), scopeRegistry(t)); err != nil {
			t.Errorf("%s: rejected: %v", name, err)
		}
	}
	// Schema discipline in every direction.
	plain := newXRule().json()
	for _, schema := range []string{RulesSchema, RulesSchemaRanged, RulesSchemaSet, RulesSchemaNotice, RulesSchemaBasis, RulesSchemaSeverity} {
		if _, err := ParseRuleSet(xDocument(schema, plain), scopeRegistry(t)); !errors.Is(err, ErrInvalid) {
			t.Errorf("crossing rule under %s accepted", schema)
		}
	}
	noCrossing := scopeRule("plain", "forbid_predicate_value", scopeComponentA, "1.0.0", "2.0.0", "active", activeUntil, forbidFact(scopeComponentA, scopeFactA))
	if _, err := ParseRuleSet(xDocument(RulesSchemaCrossing, noCrossing), scopeRegistry(t)); !errors.Is(err, ErrInvalid) {
		t.Error("crossing schema without a crossing rule accepted")
	}
	// A rule's crossing key must be a real object.
	for _, bad := range []string{`"crossing":null`, `"crossing":{}`, `"crossing":[]`, `"crossing":"x"`} {
		raw := strings.Replace(plain, `"crossing":`+newXRule().crossingJSON(), bad, 1)
		if _, err := ParseRuleSet(xDocument(RulesSchemaCrossing, raw), scopeRegistry(t)); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s accepted", bad)
		}
	}
}

// TestCrossingRestoredAndRangeGuards pins the guards the full parser also
// covers elsewhere, by calling the rule check directly: a restoration must be
// a minor-line start above the change version and at or above the end of the
// rule's range target side, and a range must pin the crossing's own release.
func TestCrossingRestoredAndRangeGuards(t *testing.T) {
	build := func(restored string, rng *VersionRange) rule {
		spec := newXRule()
		spec.restored = restored
		var r rule
		if err := json.Unmarshal([]byte(spec.json()), &r); err != nil {
			t.Fatal(err)
		}
		r.Range = rng
		return r
	}
	coherent := &VersionRange{From: VersionBound{Gte: "1.24.0", Lt: "1.25.0"}, To: VersionBound{Gte: "1.25.0", Lt: "1.26.0"}}
	if err := validateCrossingRule(build("1.26.0", coherent)); err != nil {
		t.Fatalf("baseline restored at the end of the range: %v", err)
	}
	// The width cap keeps a restoration that is a minor-line start above C at
	// or above the end of the range, so the range floor is only reachable
	// with a range the width guard would refuse; the check is made on its own.
	wide := &VersionRange{From: VersionBound{Gte: "1.24.0", Lt: "1.25.0"}, To: VersionBound{Gte: "1.25.0", Lt: "1.28.0"}}
	reject := map[string]rule{
		"restored inside the range target": build("1.26.0", wide),
		"restored is a patch":              build("1.27.4", nil),
		"restored equals change":           build("1.25.0", nil),
		"range boundary is not C":          build("", &VersionRange{From: VersionBound{Gte: "1.24.0", Lt: "1.24.5"}, To: VersionBound{Gte: "1.25.0", Lt: "1.26.0"}}),
		"range target is not C":            build("", &VersionRange{From: VersionBound{Gte: "1.24.0", Lt: "1.25.0"}, To: VersionBound{Gte: "1.25.1", Lt: "1.26.0"}}),
	}
	for name, r := range reject {
		if err := validateCrossingRule(r); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: accepted (err=%v)", name, err)
		}
	}
	if CrossingHorizonWithinLimit("1.25.0", "999.0.0") || CrossingHorizonWithinLimit("1.25.0", "2.0.0") || CrossingHorizonWithinLimit("1.25.0", "1.38.0") || CrossingHorizonWithinLimit("1.25.0", "1.24.0") || !CrossingHorizonWithinLimit("1.25.0", "1.37.0") || !CrossingHorizonWithinLimit("1.25.0", "1.26.0") {
		t.Fatal("horizon limit does not hold")
	}
}

func TestCrossingSetOperatorAndRangeCoexist(t *testing.T) {
	spec := newXRule()
	spec.rng = `{"from":{"gte":"1.24.0","lt":"1.25.0"},"to":{"gte":"1.25.0","lt":"1.26.0"},"bounds":[{"bound":"from.gte","basis":"PREVIOUS_MINOR_LINE","sourceId":"upstream-doc"},{"bound":"from.lt","basis":"REMOVED_IN_RELEASE","sourceId":"upstream-doc"},{"bound":"to.gte","basis":"REMOVED_IN_RELEASE","sourceId":"upstream-doc"},{"bound":"to.lt","basis":"REVIEWED_THROUGH_MINOR_LINE","sourceId":"upstream-doc"}]}`
	rules := parseCrossing(t, spec.json())
	now := testNow(t)
	// Order is anchor, range, crossing: each hop reports its own mode.
	for _, tc := range []struct {
		from, to, mode string
	}{{"1.24.0", "1.25.0", "anchor"}, {"1.24.5", "1.25.2", "range"}, {"1.21.0", "1.35.0", "crossing"}} {
		report, err := Evaluate(xInput(t, tc.from, tc.to, "", "", true), rules, now)
		if err != nil {
			t.Fatal(err)
		}
		c := report.Claims[0]
		got := "anchor"
		if c.SubjectMatch != nil {
			got = "range"
		}
		if c.CrossingMatch != nil {
			got = "crossing"
		}
		if got != tc.mode || c.Status != "BLOCKED" {
			t.Errorf("%s->%s: mode %s status %s, want %s BLOCKED", tc.from, tc.to, got, c.Status, tc.mode)
		}
	}
}

func TestCrossingOverlapLint(t *testing.T) {
	// Two crossing rules over one fact whose regions overlap double-count it.
	a := newXRule()
	b := newXRule()
	b.id = "crossing-rule-b"
	b.from, b.to, b.change, b.horizon = "1.25.0", "1.26.0", "1.26.0", "1.36.0"
	if _, err := ParseRuleSet(xDocument(RulesSchemaCrossing, a.json(), b.json()), scopeRegistry(t)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("overlapping crossing regions accepted: %v", err)
	}
	// A crossing rule and an exact anchor rule on the same fact overlap too.
	exact := scopeRule("exact-rule", "forbid_predicate_value", scopeComponentA, "1.24.0", "1.26.0", "active", activeUntil, forbidFact(scopeComponentA, scopeFactA))
	if _, err := ParseRuleSet(xDocument(RulesSchemaCrossing, a.json(), exact), scopeRegistry(t)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("crossing and exact overlap accepted: %v", err)
	}
	// A distinct fact, or a region wholly above the other cap, is fine.
	c := newXRule()
	c.id = "crossing-rule-c"
	c.horizon = "1.30.0"
	d := newXRule()
	d.id = "crossing-rule-d"
	d.from, d.to, d.change, d.horizon = "1.40.0", "1.41.0", "1.41.0", "1.50.0"
	if _, err := ParseRuleSet(xDocument(RulesSchemaCrossing, c.json(), d.json()), scopeRegistry(t)); err != nil {
		t.Fatalf("disjoint crossing regions rejected: %v", err)
	}
}

func TestCrossingForgedReportsAreRefused(t *testing.T) {
	rules := parseCrossing(t, newXRule().json())
	now := testNow(t)
	report, err := Evaluate(xInput(t, "1.21.0", "1.35.0", "", "", false), rules, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := MarshalReport(report); err != nil {
		t.Fatal(err)
	}
	reseal := func(mutate func(*Report)) error {
		forged := report
		forged.Claims = append([]Claim(nil), report.Claims...)
		scope := *report.ScopeCompleteness
		forged.ScopeCompleteness = &scope
		mutate(&forged)
		_, err := MarshalReport(issueReport(forged))
		return err
	}
	forgeries := map[string]func(*Report){
		"crossing claim relabelled PASS": func(r *Report) { r.Claims[0].Status, r.Claims[0].ReasonCode = "PASS", "FEATURE_REMOVED" },
		"disclosure dropped":             func(r *Report) { r.Claims[0].CrossingMatch = nil },
		"disclosure under severity contract": func(r *Report) {
			r.EngineContractDigest = EngineContractDigestSeverity()
			r.ScopeCompleteness.ContractDigest = ScopeContractDigestSeverity()
		},
		"disclosure under exact contract": func(r *Report) {
			r.EngineContractDigest = EngineContractDigest()
			r.ScopeCompleteness.ContractDigest = ScopeContractDigest()
		},
		"not-reviewed reason on a plain claim under another contract": func(r *Report) {
			r.Claims[0].CrossingMatch = nil
			r.Claims[0].ReasonCode = ReasonCrossingNotReviewed
			r.EngineContractDigest = EngineContractDigestSeverity()
			r.ScopeCompleteness.ContractDigest = ScopeContractDigestSeverity()
		},
		"not-reviewed reason on a blocked plain claim": func(r *Report) {
			r.Claims[0].CrossingMatch = nil
			r.Claims[0].Status, r.Claims[0].ReasonCode = "BLOCKED", ReasonCrossingNotReviewed
		},
		"not-reviewed reason with a crossing disclosure": func(r *Report) {
			r.Claims[0].Status, r.Claims[0].ReasonCode = "UNKNOWN", ReasonCrossingNotReviewed
		},
		"change above the anchor target": func(r *Report) { r.Claims[0].CrossingMatch.Change = "1.26.0" },
		"cap below change":               func(r *Report) { r.Claims[0].CrossingMatch.CappedAt = "1.24.0" },
		"wrong mode":                     func(r *Report) { r.Claims[0].CrossingMatch.Mode = "range" },
		"scope complete pass claimed": func(r *Report) {
			r.Assessment = AssessmentScopeCompletePass
			r.ScopeCompleteness.Resolved, r.ScopeCompleteness.UnresolvedReason = true, ""
			r.Omissions = requiredOmissions(AssessmentScopeCompletePass)
		},
	}
	for name, mutate := range forgeries {
		if err := reseal(mutate); !errors.Is(err, ErrIntegrity) {
			t.Errorf("%s: sealed report accepted (err=%v)", name, err)
		}
	}
}

func TestCrossingContractIdentity(t *testing.T) {
	if EngineContractDigestCrossing() == EngineContractDigestSeverity() || ScopeContractDigestCrossing() == ScopeContractDigestSeverity() || scopeDigestFor(EngineContractDigestCrossing()) != ScopeContractDigestCrossing() {
		t.Fatal("crossing contract identity must be distinct and paired")
	}
	if EngineContractDigestCrossing() != pinnedEngineContractDigestCrossing || ScopeContractDigestCrossing() != pinnedScopeContractDigestCrossing {
		t.Fatalf("crossing contract identity changed: engine=%s scope=%s", EngineContractDigestCrossing(), ScopeContractDigestCrossing())
	}
	// Every earlier contract keeps its identity.
	if EngineContractDigest() != pinnedEngineContractDigest || ScopeContractDigest() != pinnedScopeContractDigest || EngineContractDigestSeverity() != pinnedEngineContractDigestSeverity || ScopeContractDigestSeverity() != pinnedScopeContractDigestSeverity {
		t.Fatal("an earlier contract identity moved")
	}
	// Raw-rule schema selection puts crossing above severity.
	withSeverity := json.RawMessage(`{"severity":"unsupported"}`)
	withCrossing := json.RawMessage(`{"crossing":{}}`)
	if schema, err := RulesSchemaFor([]json.RawMessage{withSeverity, withCrossing}); err != nil || schema != RulesSchemaCrossing {
		t.Fatalf("RulesSchemaFor = %q, %v", schema, err)
	}
	if schema, err := RulesSchemaFor([]json.RawMessage{withSeverity}); err != nil || schema != RulesSchemaSeverity {
		t.Fatalf("RulesSchemaFor without crossing = %q, %v", schema, err)
	}
}

func TestInputDistributionIsClosedAndDigestStable(t *testing.T) {
	registry := scopeRegistry(t)
	base := `{"schema":"` + InputSchema + `","authority":"` + InputAuthority + `","current":{"components":[{"component":"` + scopeComponentA + `","version":"1.21.0",%s"facts":[]}]},"proposed":{"components":[{"component":"` + scopeComponentA + `","version":"1.35.0","facts":[]}]}}`
	for _, bad := range []string{`"distribution":"eks",`, `"distribution":"",`, `"distribution":null,`, `"distribution":1,`, `"distribution":"GKE",`} {
		if _, err := ParseInput([]byte(strings.Replace(base, "%s", bad, 1)), registry); err == nil {
			t.Errorf("input accepted %s", bad)
		}
	}
	withOut, err := ParseInput([]byte(strings.Replace(base, "%s", "", 1)), registry)
	if err != nil {
		t.Fatal(err)
	}
	plain, _ := withOut.Digest()
	withGKE, err := ParseInput([]byte(strings.Replace(base, "%s", `"distribution":"gke",`, 1)), registry)
	if err != nil {
		t.Fatal(err)
	}
	if gke, _ := withGKE.Digest(); gke == plain {
		t.Fatal("distribution does not move the input digest")
	}
}

// TestCrossingRefusesConsensusAndLeadBasis checks the guard directly: the
// full parser also refuses such a rule for other reasons, which would hide a
// missing crossing guard.
func TestCrossingRefusesConsensusAndLeadBasis(t *testing.T) {
	var r rule
	if err := json.Unmarshal([]byte(newXRule().json()), &r); err != nil {
		t.Fatal(err)
	}
	if err := validateCrossingRule(r); err != nil {
		t.Fatalf("baseline rejected: %v", err)
	}
	for _, basis := range []string{BasisConsensus, BasisLead} {
		r.Evidence.Basis = basis
		if err := validateCrossingRule(r); !errors.Is(err, ErrInvalid) {
			t.Errorf("basis %s accepted: %v", basis, err)
		}
	}
	r.Evidence.Basis = ""
	r.Operator = "require_component_version"
	if err := validateCrossingRule(r); !errors.Is(err, ErrInvalid) {
		t.Errorf("wrong operator accepted: %v", err)
	}
}

// TestCrossingDefencesInIsolation: each defence against a crossing PASS is
// exercised on its own, so removing one of them is noticed even though the
// forged-report table is refused by other checks.
func TestCrossingDefencesInIsolation(t *testing.T) {
	crossing := &CrossingMatch{Mode: crossingModeName, AnchorFrom: "1.24.0", AnchorTo: "1.25.0", Change: "1.25.0", CappedAt: "1.36.0"}
	base := Report{EngineContractDigest: EngineContractDigestCrossing(), Claims: []Claim{{RuleID: "r", Operator: "forbid_predicate_value", Status: "UNKNOWN", ReasonCode: ReasonCrossingPassNotReviewed, CrossingMatch: crossing}}}
	if !validCrossingClaims(base) {
		t.Fatal("baseline crossing claim refused")
	}
	// A crossing claim with PASS status is refused by validCrossingClaims
	// alone: no scope block is involved.
	passing := base
	passing.Claims = []Claim{base.Claims[0]}
	passing.Claims[0].Status, passing.Claims[0].ReasonCode = "PASS", "FEATURE_REMOVED"
	if validCrossingClaims(passing) {
		t.Error("a PASS crossing claim passed validCrossingClaims")
	}
	// deriveAssessment never counts a crossing claim as an anchor review:
	// even a crossing PASS placed in a component's evaluated list cannot
	// reach SCOPE_COMPLETE_PASS. The control without the disclosure does.
	scope := &ScopeCompleteness{Components: []ComponentScope{{Component: scopeComponentA, From: "1.24.0", To: "1.25.0", CorpusAttested: true, EvaluatedRuleIDs: []string{"r"}, NotEvaluated: []NotEvaluatedRule{}}}}
	control := []Claim{{RuleID: "r", Status: "PASS"}}
	if got, _, err := deriveAssessment(scope, control); err != nil || got != AssessmentScopeCompletePass {
		t.Fatalf("control (anchor PASS) = %q, %v", got, err)
	}
	forged := []Claim{{RuleID: "r", Status: "PASS", CrossingMatch: crossing}}
	if got, _, err := deriveAssessment(scope, forged); err != nil || got == AssessmentScopeCompletePass {
		t.Fatalf("crossing PASS reached %q (%v)", got, err)
	}
}

// TestCrossingStrippedDisclosureLimit documents what the seal gate cannot do:
// MarshalReport accepts a BLOCKED claim whose crossing disclosure was
// stripped, because nothing in the report says the claim matched by crossing
// once the disclosure is gone. Replay, which recomputes the report from the
// input and the rules, is the authority on the match mode and refuses it. The
// same holds for a range disclosure.
func TestCrossingStrippedDisclosureLimit(t *testing.T) {
	rules := parseCrossing(t, newXRule().json())
	now := testNow(t)
	input := xInput(t, "1.21.0", "1.35.0", "", "", false)
	report, err := Evaluate(input, rules, now)
	if err != nil {
		t.Fatal(err)
	}
	if report.Claims[0].Status != "UNKNOWN" || report.Claims[0].CrossingMatch == nil {
		t.Fatalf("fixture is not a crossing hop: %+v", report.Claims[0])
	}
	// The forgery: the claim is relabelled PASS with its disclosure removed,
	// and the scope block and aggregate are rewritten to agree.
	forged := report
	forged.Claims = append([]Claim(nil), report.Claims...)
	forged.Claims[0].Status, forged.Claims[0].ReasonCode, forged.Claims[0].CrossingMatch = "PASS", "FEATURE_REMOVED", nil
	scope := *report.ScopeCompleteness
	scope.Components = append([]ComponentScope(nil), scope.Components...)
	scope.Components[0].EvaluatedRuleIDs = []string{forged.Claims[0].RuleID}
	scope.Components[0].NotEvaluated = []NotEvaluatedRule{}
	scope.Resolved, scope.UnresolvedReason = true, ""
	forged.ScopeCompleteness = &scope
	forged.Assessment = AssessmentScopeCompletePass
	forged.Omissions = requiredOmissions(AssessmentScopeCompletePass)
	raw, err := MarshalReport(issueReport(forged))
	if err != nil {
		t.Skipf("the seal gate now refuses a stripped disclosure; update this test and the documentation: %v", err)
	}
	if _, err := Replay(input, rules, now, raw); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("Replay accepted a stripped crossing disclosure: %v", err)
	}
}

// TestCrossingUnreviewedIsUndeterminedInScope: a hop that crosses a cited
// removal the rule does not cover (beyond the horizon, or a distribution the
// rule does not list) is undetermined in scope, never an exclusion, so a
// wide anchor rule that passes next to it can never give SCOPE_COMPLETE_PASS
// while the removal fact is true. This is the reviewer's M3 probe.
func TestCrossingUnreviewedIsUndeterminedInScope(t *testing.T) {
	now := testNow(t)
	wide := func(to string) string {
		return scopeRule("anchor-wide", "require_component_version", scopeComponentA, "1.21.0", to, "active", activeUntil, `,"dependency":{"side":"proposed","component":"`+scopeComponentA+`","comparison":"gte","version":"1.0.0"}`)
	}
	cases := []struct {
		name, to, fromDist, toDist string
	}{
		{"distribution out of scope", "1.30.0", "gke", "gke"},
		{"beyond the horizon", "1.36.0", "", ""},
		{"far beyond the horizon", "1.40.2", "", ""},
	}
	for _, tc := range cases {
		rules := parseCrossing(t, wide(tc.to), newXRule().json())
		report, err := Evaluate(xInput(t, "1.21.0", tc.to, tc.fromDist, tc.toDist, true), rules, now)
		if err != nil {
			t.Fatal(err)
		}
		if report.Assessment == AssessmentScopeCompletePass || report.Assessment == AssessmentBlocked {
			t.Errorf("%s: assessment %s with a true removal fact", tc.name, report.Assessment)
		}
		var found bool
		for _, skipped := range report.ScopeCompleteness.Components[0].NotEvaluated {
			if skipped.RuleID == "crossing-rule" {
				found = true
				if skipped.Applicability != ApplicabilityUndetermined || skipped.ReasonCode != ReasonCrossingNotReviewed {
					t.Errorf("%s: crossing rule is %s/%s, want UNDETERMINED/%s", tc.name, skipped.Applicability, skipped.ReasonCode, ReasonCrossingNotReviewed)
				}
			}
		}
		if !found || report.ScopeCompleteness.Resolved {
			t.Errorf("%s: crossing rule not enumerated or scope resolved: %+v", tc.name, report.ScopeCompleteness)
		}
		if _, err := MarshalReport(report); err != nil {
			t.Errorf("%s: report refused: %v", tc.name, err)
		}
	}
	// A hop that does not cross C stays an exclusion and the wide anchor can
	// still pass: the new reason applies only to a hop that crosses.
	rules := parseCrossing(t, scopeRule("anchor-low", "require_component_version", scopeComponentA, "1.26.0", "1.30.0", "active", activeUntil, `,"dependency":{"side":"proposed","component":"`+scopeComponentA+`","comparison":"gte","version":"1.0.0"}`), newXRule().json())
	report, err := Evaluate(xInput(t, "1.26.0", "1.30.0", "", "", true), rules, now)
	if err != nil {
		t.Fatal(err)
	}
	if report.Assessment != AssessmentScopeCompletePass {
		t.Errorf("a hop above C with a passing anchor rule: assessment %s, want %s", report.Assessment, AssessmentScopeCompletePass)
	}
	for _, skipped := range report.ScopeCompleteness.Components[0].NotEvaluated {
		if skipped.RuleID == "crossing-rule" && (skipped.Applicability != ApplicabilityNotApplicable || skipped.ReasonCode != "RULE_TRANSITION_NOT_REVIEWED") {
			t.Errorf("a hop above C: crossing rule is %s/%s, want NOT_APPLICABLE/RULE_TRANSITION_NOT_REVIEWED", skipped.Applicability, skipped.ReasonCode)
		}
	}
}
