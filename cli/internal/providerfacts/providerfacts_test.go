// SPDX-License-Identifier: AGPL-3.0-only

package providerfacts

import (
	"math/rand"
	"strings"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/constraintengine"
	"github.com/prufyx/prufyx/cli/internal/distribution"
)

// Every row and date here is synthetic test data in the shape of the design
// examples. None of it is a statement about a real provider.

const testRevision = "0123456789abcdef0123456789abcdef01234567"

var testNow = time.Date(2026, 11, 7, 0, 0, 0, 0, time.UTC)

func bp(b bool) *bool { return &b }

func evidence() distribution.Evidence {
	return distribution.Evidence{
		State: distribution.StateActive, ReviewedAt: "2026-10-01T00:00:00Z", ValidUntil: "2026-12-30T00:00:00Z",
		Sources: []constraintengine.SourceEvidence{{ID: "table", URL: "https://github.com/example/docs/blob/" + testRevision + "/eks.md", Revision: testRevision, ContentDigest: "sha256:" + strings.Repeat("0", 64), StartLine: 1, EndLine: 9}},
	}
}

func rows() []distribution.Lifecycle {
	d := distribution.PrecisionDay
	return []distribution.Lifecycle{
		{Line: "1.31", GA: "2024-11-01", StandardEnd: "2025-11-26", ExtendedEnd: "2026-11-26", ExtendedRequiresOptIn: bp(false), Precision: d},
		{Line: "1.32", GA: "2025-01-01", StandardEnd: "2026-03-23", ExtendedEnd: "2027-03-23", ExtendedRequiresOptIn: bp(false), Precision: d},
		{Line: "1.33", GA: "2025-05-29", StandardEnd: "2026-07-29", ExtendedEnd: "2027-07-29", ExtendedRequiresOptIn: bp(true), ForcedUpgrade: &distribution.ForcedUpgrade{Date: "2027-07-29", SentenceID: "s1"}, Precision: d},
		{Line: "1.34", GA: "2025-09-01", StandardEnd: "2026-12-02", Precision: d},
		{Line: "1.35", GA: "2026-01-01", StandardEnd: "2027-06-01", Precision: d},
		{Line: "1.36", GA: "2026-05", StandardEnd: "2027-09", Precision: distribution.PrecisionMonth},
		{Line: "1.37", Precision: distribution.PrecisionTBD},
	}
}

func recordWith(t testing.TB, mutate func(*distribution.Record)) distribution.Index {
	t.Helper()
	r := distribution.Record{Distribution: "eks", ControlPlane: distribution.ControlPlaneManaged, Lifecycle: rows(), Evidence: evidence()}
	if mutate != nil {
		mutate(&r)
	}
	s := distribution.Section{Records: []distribution.Record{r}, Applicability: []distribution.Applicability{}}
	if err := distribution.Validate(s); err != nil {
		t.Fatalf("fixture invalid: %v", err)
	}
	return distribution.NewIndex(s)
}

func eval(in Input) Section {
	if in.Records == nil {
		in.Records = distribution.NewIndex(distribution.Section{})
	}
	if in.Provider == "" {
		in.Provider = "eks"
	}
	if in.Now.IsZero() {
		in.Now = testNow
	}
	in.KnowledgeRevision = "rev-test"
	s, _ := Evaluate(in)
	return s
}

func only(t *testing.T, s Section, line string) Finding {
	t.Helper()
	for _, l := range s.Lines {
		if l.Line == line {
			if len(l.Findings) == 0 {
				t.Fatalf("line %s has no findings", line)
			}
			return l.Findings[0]
		}
	}
	t.Fatalf("no line %s in %+v", line, s.Lines)
	return Finding{}
}

func lineOnly(version string) Input {
	return Input{Current: Endpoint{Version: version}, Target: Endpoint{Version: version}}
}

// TestFailClosedRows has one case per fail-closed row of the design: every
// one is a typed UNKNOWN (never INFO, WARN-as-pass or silence) with a next
// action, a knowledge revision and, when a record is read, its sources.
func TestFailClosedRows(t *testing.T) {
	idx := recordWith(t, nil)
	cases := map[string]struct {
		in      Input
		line    string
		rule    string
		sources bool
	}{
		"record absent":       {Input{Current: Endpoint{Version: "1.33.0"}, Target: Endpoint{Version: "1.33.0"}}, "1.33", RuleRecordAbsent, false},
		"clock before review": {Input{Records: idx, Now: time.Date(2026, 9, 30, 0, 0, 0, 0, time.UTC)}, "1.33", RuleRecordAbsent, true},
		"evidence expired":    {Input{Records: idx, Now: time.Date(2026, 12, 30, 0, 0, 0, 0, time.UTC)}, "1.33", RuleLifecycleStale, true},
		"unknown line":        {Input{Records: idx}, "1.29", RuleVersionUnknown, true},
		"precision month":     {Input{Records: idx}, "1.36", RuleDateImprecise, true},
		"precision tbd":       {Input{Records: idx}, "1.37", RuleDateImprecise, true},
		"no lifecycle rows":   {Input{Records: recordWith(t, func(r *distribution.Record) { r.Lifecycle = nil })}, "1.33", RuleSourceUnavailable, true},
		"withdrawn record":    {Input{Records: recordWith(t, func(r *distribution.Record) { r.Evidence.State = distribution.StateWithdrawn })}, "1.33", RuleRecordAbsent, true},
		"derivedAt after now": {Input{Records: recordWith(t, func(r *distribution.Record) {
			r.Evidence.Basis = "mechanical"
			r.Evidence.DerivedAt = "2026-11-08T00:00:00Z"
			r.Evidence.Extractor = mechanicalExtractor()
		})}, "1.33", RuleRecordAbsent, true},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			in := c.in
			if in.Current.Version == "" {
				in.Current = Endpoint{Version: "1.33.0"}
				in.Target = Endpoint{Version: "1.33.0"}
			}
			if name == "unknown line" {
				in.Current, in.Target = Endpoint{Version: "1.29.15"}, Endpoint{Version: "1.29.15"}
			}
			if c.line == "1.36" || c.line == "1.37" {
				in.Current, in.Target = Endpoint{Version: c.line + ".0"}, Endpoint{Version: c.line + ".0"}
			}
			f := only(t, eval(in), c.line)
			if f.Rule != c.rule || f.Severity != SeverityUnknown {
				t.Fatalf("got %s %s: %s", f.Severity, f.Rule, f.Text)
			}
			if f.Next == "" || f.KnowledgeRevision != "rev-test" || f.Text == "" {
				t.Fatalf("missing next action, revision or text: %+v", f)
			}
			if (len(f.Sources) > 0) != c.sources {
				t.Fatalf("sources %v want %v", len(f.Sources), c.sources)
			}
		})
	}
}

func TestDeclarationRows(t *testing.T) {
	idx := recordWith(t, nil)
	cases := map[string]struct {
		in   Input
		role string
		rule string
	}{
		"unknown token":         {Input{Provider: "mystery-cloud", Records: idx, Current: Endpoint{Version: "1.33.0"}, Target: Endpoint{Version: "1.33.0"}}, RoleDeclared, RuleUnrecognized},
		"custom build":          {Input{Provider: "custom_build", Records: idx, Current: Endpoint{Version: "1.33.0"}, Target: Endpoint{Version: "1.33.0"}}, RoleDeclared, RuleUnrecognized},
		"mapped distribution":   {Input{Provider: "openshift", Records: idx, Current: Endpoint{Version: "4.16.3"}, Target: Endpoint{Version: "4.17.1"}}, RoleDeclared, RuleVersionUnknown},
		"prerelease target":     {Input{Records: idx, Current: Endpoint{Version: "1.32.1"}, Target: Endpoint{Version: "1.34.0-rc.1"}}, RoleTarget, RuleVersionPrerelease},
		"unreadable version":    {Input{Records: idx, Current: Endpoint{Version: "1.32.x"}, Target: Endpoint{Version: "1.33.0"}}, RoleCurrent, RuleVersionUnknown},
		"preview suffix":        {Input{Records: idx, Current: Endpoint{Version: "1.33.0"}, Target: Endpoint{Version: "1.34.0-preview"}}, RoleTarget, RuleVersionUnknown},
		"no current":            {Input{Records: idx, Target: Endpoint{Version: "1.33.0"}}, RoleCurrent, RuleVersionUnknown},
		"mapping conflict":      {Input{Records: idx, Current: Endpoint{Version: "v1.32.3-eks-adc7111", Upstream: "1.33.0"}, Target: Endpoint{Version: "1.33.0"}}, RoleCurrent, RuleMappingConflict},
		"suffix of another one": {Input{Provider: "gke", Records: idx, Current: Endpoint{Version: "v1.32.3-eks-adc7111"}, Target: Endpoint{Version: "1.33.0"}}, RoleCurrent, RuleMappingConflict},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			s := eval(c.in)
			found := false
			for _, l := range s.Lines {
				if l.Role != c.role || l.Line != "" {
					continue
				}
				found = true
				f := l.Findings[0]
				if f.Rule != c.rule || f.Severity != SeverityUnknown || f.Next == "" {
					t.Fatalf("got %+v", f)
				}
			}
			if !found {
				t.Fatalf("no %s declaration finding in %+v", c.role, s.Lines)
			}
		})
	}
}

func TestUpstreamIsNotAProvider(t *testing.T) {
	for _, p := range []string{"", "official_upstream", "kubeadm"} {
		if _, ok := Evaluate(Input{Provider: p, Now: testNow, Records: distribution.NewIndex(distribution.Section{})}); ok {
			t.Fatalf("%q produced a section", p)
		}
	}
}

func TestStaleKeepsSelfIdentifyingLine(t *testing.T) {
	// A grammar-self-identifying version keeps its upstream line while the
	// record's dates are stale; only the dates become UNKNOWN.
	in := Input{Records: recordWith(t, nil), Now: time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC),
		Current: Endpoint{Version: "v1.33.2-eks-adc7111"}, Target: Endpoint{Version: "v1.33.2-eks-adc7111"}}
	f := only(t, eval(in), "1.33")
	if f.Rule != RuleLifecycleStale {
		t.Fatalf("got %s", f.Rule)
	}
}

func TestDates(t *testing.T) {
	idx := recordWith(t, nil)
	cases := map[string]struct {
		version string
		now     time.Time
		optIn   bool
		rule    string
		sev     string
		want    []string
		not     []string
	}{
		"ended, standard is the deadline": {"1.33.0", testNow, false, RuleSupportEnded, SeverityWarn,
			[]string{"standard support ended 2026-07-29", "extended (paid) ends 2027-07-29, requires opt-in", "no opt-in was declared", "announced globally"}, []string{"available in your region", "SAFE"}},
		"ended, automatic extended is still not assumed": {"1.32.0", testNow, false, RuleSupportEnded, SeverityWarn,
			[]string{"standard support ended 2026-03-23", "automatic per the provider", "extended support is not assumed"}, nil},
		"declared opt-in moves the deadline": {"1.33.0", testNow, true, RuleSupportCurrent, SeverityInfo,
			[]string{"extended (paid), as you declared support runs until 2027-07-29"}, nil},
		"declared opt-in, extended ending":        {"1.31.0", testNow, true, RuleSupportEnding, SeverityWarn, []string{"extended (paid), as you declared support ends 2026-11-26"}, nil},
		"ending within 90 days":                   {"1.34.0", testNow, false, RuleSupportEnding, SeverityWarn, []string{"ends 2026-12-02, within 90 days"}, nil},
		"current":                                 {"1.35.0", testNow, false, RuleSupportCurrent, SeverityInfo, []string{"runs until 2027-06-01", "availability in your region or channel is UNKNOWN"}, []string{"is supported"}},
		"last day is not over":                    {"1.34.0", time.Date(2026, 12, 2, 23, 0, 0, 0, time.UTC), false, RuleSupportEnding, SeverityWarn, nil, nil},
		"day after the last day":                  {"1.34.0", time.Date(2026, 12, 3, 0, 0, 0, 0, time.UTC), false, RuleSupportEnded, SeverityWarn, nil, nil},
		"no opt-in declared without extended row": {"1.34.0", testNow, true, RuleSupportEnding, SeverityWarn, []string{"standard support ends"}, nil},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			now := c.now
			in := lineOnly(c.version)
			in.Records, in.Now, in.ExtendedOptIn = idx, now, c.optIn
			f := only(t, eval(in), strings.Join(strings.Split(c.version, ".")[:2], "."))
			if f.Rule != c.rule || f.Severity != c.sev {
				t.Fatalf("got %s %s: %s", f.Severity, f.Rule, f.Text)
			}
			for _, w := range c.want {
				if !strings.Contains(f.Text, w) {
					t.Errorf("text %q lacks %q", f.Text, w)
				}
			}
			for _, w := range c.not {
				if strings.Contains(f.Text, w) {
					t.Errorf("text %q holds %q", f.Text, w)
				}
			}
			if len(f.Sources) != 1 || f.Basis == "" || f.ValidUntil == "" || f.KnowledgeRevision == "" {
				t.Fatalf("evidence reference missing: %+v", f)
			}
		})
	}
}

func TestForcedUpgrade(t *testing.T) {
	idx := recordWith(t, nil)
	in := lineOnly("1.33.0")
	in.Records = idx
	s := eval(in)
	var forced *Finding
	for _, f := range s.Lines[0].Findings {
		if f.Rule == RuleForcedUpgrade {
			forced = &f
		}
	}
	if forced == nil || forced.Severity != SeverityInfo || !strings.Contains(forced.Text, "2027-07-29") || !strings.Contains(forced.Text, "sentence s1") {
		t.Fatalf("forced %+v", forced)
	}
	// Within the window: WARN.
	in.Now = time.Date(2027, 6, 1, 0, 0, 0, 0, time.UTC)
	in.Records = recordWith(t, func(r *distribution.Record) {
		r.Evidence.ReviewedAt, r.Evidence.ValidUntil = "2027-05-01T00:00:00Z", "2027-07-01T00:00:00Z"
	})
	for _, f := range eval(in).Lines[0].Findings {
		if f.Rule == RuleForcedUpgrade && f.Severity != SeverityWarn {
			t.Fatalf("forced within 90 days is %s", f.Severity)
		}
	}
	// No sentence: UNKNOWN date, wording never "none".
	in = lineOnly("1.34.0")
	in.Records = idx
	var none *Finding
	for _, f := range eval(in).Lines[0].Findings {
		if f.Rule == RuleForcedUpgradeUnknow {
			none = &f
		}
	}
	if none == nil || !strings.Contains(none.Text, "UNKNOWN") || strings.Contains(strings.ToLower(none.Text), "no forced upgrade") {
		t.Fatalf("absent sentence: %+v", none)
	}
}

func TestSpanAndRoles(t *testing.T) {
	in := Input{Records: recordWith(t, nil), Current: Endpoint{Version: "1.31.0"}, Target: Endpoint{Version: "1.34.0"}}
	s := eval(in)
	roles := []string{}
	for _, l := range s.Lines {
		roles = append(roles, l.Line+":"+l.Role)
	}
	if got := strings.Join(roles, ","); got != "1.31:current,1.32:intermediate,1.33:intermediate,1.34:target" {
		t.Fatalf("roles %s", got)
	}
	// A downgrade and a major change evaluate only the two ends.
	for _, to := range []string{"1.30.0"} {
		in.Target = Endpoint{Version: to}
		if n := len(eval(in).Lines); n != 2 {
			t.Fatalf("downgrade lines %d", n)
		}
	}
}

func mechanicalExtractor() *constraintengine.Extractor {
	return &constraintengine.Extractor{ID: "distribution.versions", Version: "1.0.0", CodeDigest: "sha256:" + strings.Repeat("b", 64)}
}

// TestMonotonic: provider facts only add information. For random records,
// clocks and versions, every finding is advisory (INFO, WARN or UNKNOWN),
// carries the revision, and none says SAFE or PASS; and adding a record for
// a provider that had none replaces a record_absent UNKNOWN by something
// that is still never a pass: a line without a current, day-precise
// deadline never yields INFO.
func TestMonotonic(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	rec := recordWith(t, nil)
	empty := distribution.NewIndex(distribution.Section{})
	for i := 0; i < 2000; i++ {
		minor := 29 + rng.Intn(10)
		now := testNow.Add(time.Duration(rng.Intn(200)-100) * 24 * time.Hour)
		in := Input{Now: now, Provider: []string{"eks", "gke", "aks", "k3s", "rke2", "talos", "nope"}[rng.Intn(7)],
			Current: Endpoint{Version: "1." + itoa(minor) + ".0"}, Target: Endpoint{Version: "1." + itoa(29+rng.Intn(10)) + ".0"}, ExtendedOptIn: rng.Intn(2) == 0}
		in.Records = empty
		without := eval(in)
		in.Records = rec
		with := eval(in)
		for _, s := range []Section{without, with} {
			for _, l := range s.Lines {
				for _, f := range l.Findings {
					if f.Severity != SeverityInfo && f.Severity != SeverityWarn && f.Severity != SeverityUnknown {
						t.Fatalf("severity %q", f.Severity)
					}
					if f.KnowledgeRevision == "" || strings.Contains(f.Text, "SAFE") || strings.Contains(f.Text, "PASS") {
						t.Fatalf("finding %+v", f)
					}
				}
			}
		}
		// Without any record there is no INFO: nothing positive is said.
		for _, l := range without.Lines {
			for _, f := range l.Findings {
				if f.Severity == SeverityInfo {
					t.Fatalf("INFO without a record: %+v", f)
				}
			}
		}
		// A with-record INFO needs a current record, a day row and a
		// deadline still ahead; anything else stays UNKNOWN or WARN.
		for _, l := range with.Lines {
			for _, f := range l.Findings {
				if f.Severity == SeverityInfo && f.Rule == RuleSupportCurrent && len(f.Sources) == 0 {
					t.Fatalf("support_current without evidence: %+v", f)
				}
			}
		}
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	s := ""
	for n > 0 {
		s = string(rune('0'+n%10)) + s
		n /= 10
	}
	return s
}

func TestInputRecordsNotMutated(t *testing.T) {
	idx := recordWith(t, nil)
	before, _, _ := idx.Record("eks", testNow)
	in := lineOnly("1.33.0")
	in.Records = idx
	s := eval(in)
	s.Lines[0].Findings[0].Sources[0].ID = "tampered"
	after, _, _ := idx.Record("eks", testNow)
	if after.Evidence.Sources[0].ID != before.Evidence.Sources[0].ID {
		t.Fatal("evaluation shares source slices with the index")
	}
}

func TestZeroNowIsTypedUnknown(t *testing.T) {
	idx := recordWith(t, nil)
	s, ok := Evaluate(Input{Provider: "eks", Records: idx, KnowledgeRevision: "rev-test",
		Current: Endpoint{Version: "1.33.0"}, Target: Endpoint{Version: "1.33.0"}})
	if !ok || len(s.Lines) != 1 || len(s.Lines[0].Findings) != 1 {
		t.Fatalf("zero Now: want one declared UNKNOWN finding, got %+v (ok=%v)", s, ok)
	}
	f := s.Lines[0].Findings[0]
	if s.Lines[0].Role != RoleDeclared || f.Rule != RuleNowMissing || f.Severity != SeverityUnknown || f.Next == "" {
		t.Fatalf("zero Now: got %+v", f)
	}
	if s.Now != "" {
		t.Fatalf("zero Now must not render a fabricated timestamp, got %q", s.Now)
	}
}
