// SPDX-License-Identifier: AGPL-3.0-only

package upgradepath

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/constraintengine"
	"github.com/prufyx/prufyx/cli/internal/lineattest"
)

const k8s = "pkg:github/kubernetes/kubernetes"

func policy(name string) *PathPolicy { return &PathPolicy{Component: k8s, Policy: name} }

func exact(v string) Endpoint { return Endpoint{Version: v} }
func line(l string) Endpoint  { return Endpoint{Line: l} }

func hops(endpoints ...Endpoint) []Hop {
	out := []Hop{}
	for i := 0; i+1 < len(endpoints); i++ {
		out = append(out, Hop{Index: i + 1, From: endpoints[i], To: endpoints[i+1]})
	}
	return out
}

func TestPlanPathTable(t *testing.T) {
	type tc struct {
		name     string
		policy   *PathPolicy
		from, to string
		hops     []Hop
		gap      Reason
	}
	cases := []tc{
		// The worked example: 1.24.17 -> 1.30.4 visits every minor line.
		{"minor 1.24.17 to 1.30.4", policy(PolicySequentialMinor), "1.24.17", "1.30.4", hops(exact("1.24.17"), line("1.25"), line("1.26"), line("1.27"), line("1.28"), line("1.29"), exact("1.30.4")), ""},
		{"minor same line", policy(PolicySequentialMinor), "1.24.3", "1.24.17", hops(exact("1.24.3"), exact("1.24.17")), ""},
		{"minor adjacent", policy(PolicySequentialMinor), "1.24.17", "1.25.0", hops(exact("1.24.17"), exact("1.25.0")), ""},
		{"minor multi-line", policy(PolicySequentialMinor), "1.27.0", "1.29.2", hops(exact("1.27.0"), line("1.28"), exact("1.29.2")), ""},
		{"minor cross-major", policy(PolicySequentialMinor), "1.30.0", "2.0.0", nil, GapPathNotPlannable},
		{"minor downgrade", policy(PolicySequentialMinor), "1.25.0", "1.24.9", nil, GapDowngradeNotReviewed},
		{"minor equal", policy(PolicySequentialMinor), "1.25.0", "1.25.0", nil, GapPathNotPlannable},
		{"minor invalid from", policy(PolicySequentialMinor), "1.25", "1.26.0", nil, GapPathNotPlannable},
		{"minor 64 hops", policy(PolicySequentialMinor), "1.0.0", "1.64.0", nil, ""},
		{"minor 65 hops", policy(PolicySequentialMinor), "1.0.0", "1.65.0", nil, GapPathNotPlannable},
		{"minor huge span", policy(PolicySequentialMinor), "1.0.0", "1.999999999.0", nil, GapPathNotPlannable},

		{"direct same line", policy(PolicyDirect), "1.24.3", "1.24.17", hops(exact("1.24.3"), exact("1.24.17")), ""},
		{"direct adjacent", policy(PolicyDirect), "1.24.17", "1.25.0", hops(exact("1.24.17"), exact("1.25.0")), ""},
		{"direct multi-line", policy(PolicyDirect), "1.24.17", "1.30.4", hops(exact("1.24.17"), exact("1.30.4")), ""},
		{"direct cross-major", policy(PolicyDirect), "1.30.0", "3.1.0", hops(exact("1.30.0"), exact("3.1.0")), ""},
		{"direct downgrade", policy(PolicyDirect), "2.0.0", "1.30.0", nil, GapDowngradeNotReviewed},
		{"direct equal", policy(PolicyDirect), "2.0.0", "2.0.0", nil, GapPathNotPlannable},
		{"direct invalid to", policy(PolicyDirect), "1.0.0", "v2.0.0", nil, GapPathNotPlannable},
		{"direct far apart is one hop", policy(PolicyDirect), "1.0.0", "1.900.0", hops(exact("1.0.0"), exact("1.900.0")), ""},

		{"major same line", policy(PolicySequentialMajor), "1.24.3", "1.24.17", hops(exact("1.24.3"), exact("1.24.17")), ""},
		{"major adjacent minor lines", policy(PolicySequentialMajor), "1.24.17", "1.25.0", hops(exact("1.24.17"), exact("1.25.0")), ""},
		{"major multi-line same major", policy(PolicySequentialMajor), "1.24.17", "1.30.4", hops(exact("1.24.17"), exact("1.30.4")), ""},
		{"major adjacent majors", policy(PolicySequentialMajor), "1.30.0", "2.1.0", hops(exact("1.30.0"), exact("2.1.0")), ""},
		{"major multi-major", policy(PolicySequentialMajor), "1.30.0", "4.2.1", hops(exact("1.30.0"), line("2"), line("3"), exact("4.2.1")), ""},
		{"major downgrade", policy(PolicySequentialMajor), "3.0.0", "2.9.9", nil, GapDowngradeNotReviewed},
		{"major equal", policy(PolicySequentialMajor), "3.0.0", "3.0.0", nil, GapPathNotPlannable},
		{"major invalid", policy(PolicySequentialMajor), "03.0.0", "4.0.0", nil, GapPathNotPlannable},
		{"major 65 hops", policy(PolicySequentialMajor), "0.1.0", "65.0.0", nil, GapPathNotPlannable},

		{"no policy same line", nil, "1.24.3", "1.24.17", hops(exact("1.24.3"), exact("1.24.17")), ""},
		{"no policy multi-line is one hop", nil, "1.24.17", "1.30.4", hops(exact("1.24.17"), exact("1.30.4")), ""},
		{"no policy downgrade", nil, "1.30.4", "1.24.17", nil, GapDowngradeNotReviewed},
		{"no policy equal", nil, "1.30.4", "1.30.4", nil, GapPathNotPlannable},
		{"no policy invalid", nil, "1.30.4", "", nil, GapPathNotPlannable},

		{"unknown policy", policy("skip_any"), "1.24.0", "1.26.0", nil, GapPathNotPlannable},
		{"direct policy of another component", &PathPolicy{Component: "pkg:github/cilium/cilium", Policy: PolicyDirect}, "1.24.0", "1.26.0", nil, GapPathNotPlannable},
		{"policy of another component", &PathPolicy{Component: "pkg:github/cilium/cilium", Policy: PolicySequentialMinor}, "1.24.0", "1.26.0", nil, GapPathNotPlannable},
		{"invalid beats downgrade", policy(PolicySequentialMinor), "1.30.x", "1.24.0", nil, GapPathNotPlannable},
		{"leading zero patch", policy(PolicyDirect), "1.24.01", "1.25.0", nil, GapPathNotPlannable},
		{"patch beyond 32 bits", policy(PolicyDirect), "1.24.4294967296", "1.25.0", nil, GapPathNotPlannable},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := PlanPath(k8s, c.from, c.to, c.policy)
			if got.Component != k8s || got.Gap != c.gap {
				t.Fatalf("plan %+v, want gap %q", got, c.gap)
			}
			wantPolicy := ""
			if c.policy != nil {
				wantPolicy = c.policy.Policy
			}
			if got.Policy != wantPolicy {
				t.Fatalf("policy %q, want %q", got.Policy, wantPolicy)
			}
			if c.gap != "" {
				if got.Hops == nil || len(got.Hops) != 0 {
					t.Fatalf("a gap plan carries hops: %+v", got.Hops)
				}
				return
			}
			if c.hops != nil {
				if gotJSON, wantJSON := mustJSON(t, got.Hops), mustJSON(t, c.hops); gotJSON != wantJSON {
					t.Fatalf("hops\n got %s\nwant %s", gotJSON, wantJSON)
				}
			}
			checkPlanShape(t, got, c.from, c.to)
		})
	}
	if n := len(PlanPath(k8s, "1.0.0", "1.64.0", policy(PolicySequentialMinor)).Hops); n != MaxHops {
		t.Fatalf("64-line path has %d hops", n)
	}
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

// checkPlanShape asserts the path invariants: hops are numbered 1..n,
// contiguous, ordered, start at the exact from and end at the exact to, and
// every intermediate end is a whole line, never a version.
func checkPlanShape(t *testing.T, plan Plan, from, to string) {
	t.Helper()
	n := len(plan.Hops)
	if n == 0 || n > MaxHops {
		t.Fatalf("plan with %d hops", n)
	}
	if plan.Hops[0].From != (Endpoint{Version: from}) || plan.Hops[n-1].To != (Endpoint{Version: to}) {
		t.Fatalf("plan ends %v -> %v, want exact %s -> %s", plan.Hops[0].From, plan.Hops[n-1].To, from, to)
	}
	for i, h := range plan.Hops {
		if h.Index != i+1 {
			t.Fatalf("hop %d has index %d", i, h.Index)
		}
		if i+1 < n && h.To != plan.Hops[i+1].From {
			t.Fatalf("hop %d ends at %v, hop %d starts at %v", i+1, h.To, i+2, plan.Hops[i+1].From)
		}
		for _, e := range []Endpoint{h.From, h.To} {
			isEnd := e == plan.Hops[0].From || e == plan.Hops[n-1].To
			if isEnd != e.Exact() || (!isEnd && e.Version != "") || (e.Version != "" && e.Line != "") {
				t.Fatalf("hop %d endpoint %+v: an intermediate end must be a line and only the real ends exact", i+1, e)
			}
			if !e.Exact() && !e.MinorLine() && !e.MajorLine() {
				t.Fatalf("hop %d endpoint %+v is neither a version nor a line", i+1, e)
			}
		}
		if !endpointBelow(h.From, h.To) {
			t.Fatalf("hop %d goes %v -> %v, not upward", i+1, h.From, h.To)
		}
	}
}

// endpointBelow reports that every release a stands for is below every
// release b stands for.
func endpointBelow(a, b Endpoint) bool {
	low := func(e Endpoint) string {
		switch {
		case e.Exact():
			return e.Version
		case e.MinorLine():
			return e.Line + ".0"
		}
		return e.Line + ".0.0"
	}
	high := func(e Endpoint) string {
		switch {
		case e.Exact():
			return e.Version
		case e.MinorLine():
			return e.Line + ".4294967295"
		}
		return e.Line + ".4294967295.4294967295"
	}
	return constraintengine.VersionLess(high(a), low(b))
}

func TestPlanPathProperty(t *testing.T) {
	rng := rand.New(rand.NewSource(20261004))
	version := func() string {
		return fmt.Sprintf("%d.%d.%d", rng.Intn(4), rng.Intn(40), rng.Intn(30))
	}
	policies := []*PathPolicy{nil, policy(PolicySequentialMinor), policy(PolicyDirect), policy(PolicySequentialMajor)}
	planned := 0
	for i := 0; i < 20000; i++ {
		from, to := version(), version()
		p := policies[rng.Intn(len(policies))]
		plan := PlanPath(k8s, from, to, p)
		switch {
		case from == to:
			if plan.Gap != GapPathNotPlannable {
				t.Fatalf("%s -> %s: equal versions planned: %+v", from, to, plan)
			}
		case constraintengine.VersionLess(to, from):
			if plan.Gap != GapDowngradeNotReviewed || len(plan.Hops) != 0 {
				t.Fatalf("%s -> %s: downgrade planned: %+v", from, to, plan)
			}
		case plan.Gap != "":
			if p == nil || p.Policy != PolicySequentialMinor || strings.Split(from, ".")[0] == strings.Split(to, ".")[0] {
				t.Fatalf("%s -> %s %+v: unexpected gap %s", from, to, p, plan.Gap)
			}
		default:
			planned++
			checkPlanShape(t, plan, from, to)
			fromLine, _ := lineattest.LineOf(from)
			toLine, _ := lineattest.LineOf(to)
			if p != nil && p.Policy == PolicySequentialMinor {
				// One hop per minor line: every line between the ends is
				// visited exactly once.
				want := 1
				if fromLine != toLine {
					want = int(minorOf(to) - minorOf(from))
				}
				if len(plan.Hops) != want {
					t.Fatalf("%s -> %s: %d hops, want %d", from, to, len(plan.Hops), want)
				}
				for _, h := range plan.Hops[1:] {
					if !h.From.MinorLine() {
						t.Fatalf("%s -> %s: intermediate start %+v is not a minor line", from, to, h.From)
					}
				}
			}
			if p == nil || p.Policy == PolicyDirect {
				if len(plan.Hops) != 1 {
					t.Fatalf("%s -> %s: direct plan has %d hops", from, to, len(plan.Hops))
				}
			}
		}
	}
	if planned < 1000 {
		t.Fatalf("degenerate sample: %d plans", planned)
	}
}

func minorOf(version string) uint64 {
	_, minor := numbers(version)
	return minor
}

func FuzzPlanPath(f *testing.F) {
	for _, seed := range [][2]string{{"1.24.17", "1.30.4"}, {"1.0.0", "1.65.0"}, {"1.30.0", "2.0.0"}, {"2.0.0", "1.0.0"}, {"1.2", "x"}, {"0.0.0", "4294967295.4294967295.4294967295"}} {
		f.Add(seed[0], seed[1], uint8(0))
	}
	policies := []*PathPolicy{nil, policy(PolicySequentialMinor), policy(PolicyDirect), policy(PolicySequentialMajor), policy("bogus")}
	f.Fuzz(func(t *testing.T, from, to string, which uint8) {
		p := policies[int(which)%len(policies)]
		plan := PlanPath(k8s, from, to, p)
		if plan.Gap != "" {
			if len(plan.Hops) != 0 {
				t.Fatalf("gap with hops: %+v", plan)
			}
			if plan.Gap != GapPathNotPlannable && plan.Gap != GapDowngradeNotReviewed {
				t.Fatalf("gap outside the vocabulary: %s", plan.Gap)
			}
			return
		}
		if !constraintengine.VersionLess(from, to) {
			t.Fatalf("%q -> %q planned without being an upgrade", from, to)
		}
		checkPlanShape(t, plan, from, to)
		for _, h := range plan.Hops {
			for _, e := range []Endpoint{h.From, h.To} {
				if len(e.String()) > 256 {
					t.Fatal("endpoint longer than 256 bytes")
				}
			}
		}
	})
}

func TestEndpointCoverage(t *testing.T) {
	whole := constraintengine.VersionBound{Gte: "1.25.0", Lt: "1.26.0"}
	narrow := constraintengine.VersionBound{Gte: "1.25.0", Lt: "1.25.9"}
	cases := []struct {
		e     Endpoint
		bound constraintengine.VersionBound
		want  bool
	}{
		{exact("1.25.3"), whole, true},
		{exact("1.25.3"), narrow, true},
		{exact("1.26.0"), whole, false},
		{line("1.25"), whole, true},
		{line("1.25"), narrow, false},
		{line("1.24"), whole, false},
		{line("1"), constraintengine.VersionBound{Gte: "0.0.0", Lt: "9.0.0"}, false},
		{Endpoint{Version: "1.25.3", Line: "1.25"}, whole, false},
		{Endpoint{}, whole, false},
		{Endpoint{Version: "1.25"}, whole, false},
	}
	for _, c := range cases {
		if got := c.e.CoveredBy(c.bound); got != c.want {
			t.Errorf("%+v.CoveredBy([%s,%s)) = %v, want %v", c.e, c.bound.Gte, c.bound.Lt, got, c.want)
		}
	}
	for e, want := range map[Endpoint]string{exact("1.25.3"): "1.25.3", line("1.25"): "1.25.0"} {
		if got, ok := e.EngineVersion(); !ok || got != want {
			t.Errorf("%+v engine version %q %v", e, got, ok)
		}
	}
	for _, e := range []Endpoint{line("2"), {}, {Version: "1.25.3", Line: "1.25"}} {
		if _, ok := e.EngineVersion(); ok {
			t.Errorf("%+v has an engine version", e)
		}
	}
}

func TestHopCoverage(t *testing.T) {
	rangeRule := constraintengine.RuleTransition{Component: k8s, From: "1.24.0", To: "1.25.0", Range: &constraintengine.VersionRange{
		From: constraintengine.VersionBound{Gte: "1.24.0", Lt: "1.25.0"}, To: constraintengine.VersionBound{Gte: "1.25.0", Lt: "1.26.0"}}}
	anchorRule := constraintengine.RuleTransition{Component: k8s, From: "1.24.0", To: "1.25.0"}
	fromAnchorOnly := constraintengine.RuleTransition{Component: k8s, From: "1.24.0", To: "1.25.0", Range: &constraintengine.VersionRange{
		From: constraintengine.VersionBound{Gte: "1.24.0", Lt: "1.24.1"}, To: constraintengine.VersionBound{Gte: "1.25.0", Lt: "1.26.0"}}}
	cases := []struct {
		name string
		hop  Hop
		rule constraintengine.RuleTransition
		want bool
	}{
		{"exact pair in range", Hop{1, exact("1.24.17"), exact("1.25.3")}, rangeRule, true},
		{"exact pair outside range", Hop{1, exact("1.23.9"), exact("1.25.3")}, rangeRule, false},
		{"anchor pair by anchor rule", Hop{1, exact("1.24.0"), exact("1.25.0")}, anchorRule, true},
		{"other pair by anchor rule", Hop{1, exact("1.24.17"), exact("1.25.0")}, anchorRule, false},
		{"exact to line by range", Hop{1, exact("1.24.17"), line("1.25")}, rangeRule, true},
		{"line to exact by range", Hop{2, line("1.24"), exact("1.25.4")}, rangeRule, true},
		{"line to line by range", Hop{2, line("1.24"), line("1.25")}, rangeRule, true},
		{"line by anchor rule", Hop{2, line("1.24"), line("1.25")}, anchorRule, false},
		{"exact to line by anchor rule", Hop{1, exact("1.24.0"), line("1.25")}, anchorRule, false},
		{"line from by anchor-width side", Hop{2, line("1.24"), exact("1.25.0")}, fromAnchorOnly, false},
		{"exact from on anchor-width side", Hop{1, exact("1.24.0"), line("1.25")}, fromAnchorOnly, true},
		{"wrong lines", Hop{2, line("1.25"), line("1.26")}, rangeRule, false},
		{"major line", Hop{2, line("1"), exact("1.25.0")}, rangeRule, false},
	}
	for _, c := range cases {
		if got := c.hop.CoveredBy(c.rule); got != c.want {
			t.Errorf("%s: CoveredBy = %v, want %v", c.name, got, c.want)
		}
	}
}

// A hop of the line attestation family's shape (previous line into the
// line) is covered by a rule exactly when the attestation's line-wide check
// accepts that rule: the planner and the attestation agree on what a rule
// that covers a whole line is.
func TestHopCoverageAgreesWithLineAttestationFamily(t *testing.T) {
	family, ok := lineattest.LookupFamily(lineattest.FamilyKubernetesRemovedServedGVK)
	if !ok {
		t.Fatal("family missing")
	}
	rng := rand.New(rand.NewSource(7))
	bound := func() constraintengine.VersionBound {
		v := func() string {
			patch := []string{"0", "1", "4294967295"}[rng.Intn(3)]
			return fmt.Sprintf("1.%d.%s", 23+rng.Intn(5), patch)
		}
		return constraintengine.VersionBound{Gte: v(), Lt: v()}
	}
	agree := 0
	for i := 0; i < 5000; i++ {
		rule := constraintengine.RuleTransition{Component: k8s, From: "1.24.0", To: "1.25.0"}
		if rng.Intn(10) > 0 {
			rule.Range = &constraintengine.VersionRange{From: bound(), To: bound()}
		}
		hop := Hop{Index: 2, From: line("1.24"), To: line("1.25")}
		if got, want := hop.CoveredBy(rule), family.CoversLine(rule, "1.25"); got != want {
			t.Fatalf("rule %+v: hop coverage %v, family line coverage %v", rule.Range, got, want)
		}
		if hop.CoveredBy(rule) {
			agree++
		}
	}
	if agree == 0 {
		t.Fatal("degenerate sample: no rule covered the hop")
	}
}

// The rule an operator at 1.25.7 would hit on the hop 1.25 -> 1.26 does not
// match at the hop's engine versions (1.25.0 -> 1.26.0), and does not cover the
// hop, but it overlaps it: the hop must not be decided without it.
func TestHopOverlapsAnchorInsideLine(t *testing.T) {
	rule := constraintengine.RuleTransition{Component: k8s, From: "1.25.7", To: "1.26.0"}
	hop := Hop{Index: 2, From: line("1.25"), To: line("1.26")}
	from, _ := hop.From.EngineVersion()
	to, _ := hop.To.EngineVersion()
	if rule.Match(from, to) != constraintengine.MatchNone {
		t.Fatal("fixture: the rule matches at the engine versions")
	}
	if rule.Match("1.25.7", "1.26.0") == constraintengine.MatchNone {
		t.Fatal("fixture: the rule does not match the real stop")
	}
	if hop.CoveredBy(rule) {
		t.Fatal("an anchor rule covers a line hop")
	}
	if !hop.Overlaps(rule) {
		t.Fatal("a rule for 1.25.7 -> 1.26.0 does not overlap the hop 1.25 -> 1.26")
	}
	for _, other := range []Hop{{1, line("1.24"), line("1.25")}, {3, line("1.26"), line("1.27")}, {1, exact("1.25.6"), line("1.26")}} {
		if other.Overlaps(rule) {
			t.Fatalf("hop %v -> %v overlaps a rule for 1.25.7 -> 1.26.0", other.From, other.To)
		}
	}
	if !(Hop{1, exact("1.25.7"), line("1.26")}).Overlaps(rule) {
		t.Fatal("the exact start of the rule's anchor does not overlap")
	}
}

// Overlaps is exact: it holds if and only if the engine matches some concrete
// transition of the hop. The candidate releases per end are the end's own
// lowest and highest release and every rule version inside it, which contain
// a witness whenever one exists (bounds are half-open). CoveredBy implies
// Overlaps.
func TestHopOverlapsProperty(t *testing.T) {
	rng := rand.New(rand.NewSource(11))
	v := func() string {
		return fmt.Sprintf("%d.%d.%s", 1+rng.Intn(2), 23+rng.Intn(5), []string{"0", "1", "7", "4294967295"}[rng.Intn(4)])
	}
	ends := func() (Endpoint, Endpoint) {
		lines := []Endpoint{line("1.24"), line("1.25"), line("1.26"), line("2"), exact("1.24.7"), exact("1.25.0"), exact("1.26.1"), exact("2.25.0")}
		return lines[rng.Intn(len(lines))], lines[rng.Intn(len(lines))]
	}
	candidates := func(e Endpoint, rule constraintengine.RuleTransition, from bool) []string {
		if e.Exact() {
			return []string{e.Version}
		}
		low, _, _ := e.span()
		out := []string{low}
		// The highest release below high.
		if e.MinorLine() {
			out = append(out, e.Line+".4294967295")
		} else {
			out = append(out, e.Line+".4294967295.4294967295")
		}
		vals := []string{rule.To}
		if from {
			vals = []string{rule.From}
		}
		if rule.Range != nil {
			if from {
				vals = append(vals, rule.Range.From.Gte)
			} else {
				vals = append(vals, rule.Range.To.Gte)
			}
		}
		for _, x := range vals {
			if e.holds(x) {
				out = append(out, x)
			}
		}
		return out
	}
	overlaps := 0
	for i := 0; i < 50000; i++ {
		rule := constraintengine.RuleTransition{Component: k8s, From: v(), To: v()}
		if rng.Intn(4) > 0 {
			rule.Range = &constraintengine.VersionRange{From: constraintengine.VersionBound{Gte: v(), Lt: v()}, To: constraintengine.VersionBound{Gte: v(), Lt: v()}}
		}
		f, to := ends()
		hop := Hop{Index: 1, From: f, To: to}
		witness := false
		for _, a := range candidates(f, rule, true) {
			for _, b := range candidates(to, rule, false) {
				if rule.Match(a, b) != constraintengine.MatchNone {
					witness = true
				}
			}
		}
		got := hop.Overlaps(rule)
		if got != witness {
			t.Fatalf("hop %v -> %v rule %s -> %s range %+v: Overlaps %v, witness %v", f, to, rule.From, rule.To, rule.Range, got, witness)
		}
		if hop.CoveredBy(rule) && !got {
			t.Fatalf("hop %v -> %v covered but not overlapped", f, to)
		}
		if got {
			overlaps++
		}
	}
	if overlaps < 500 {
		t.Fatalf("degenerate sample: %d overlaps", overlaps)
	}
}
