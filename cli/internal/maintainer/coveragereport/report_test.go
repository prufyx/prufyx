// SPDX-License-Identifier: AGPL-3.0-only

package coveragereport

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/cncfcheck"
	"github.com/prufyx/prufyx/cli/internal/extract/supersedeids"
)

var baselineNow = time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)

func read(t *testing.T, path string) []byte {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func statuses(p Project) string {
	var b strings.Builder
	for _, pair := range p.Pairs {
		b.WriteString(pair.Status)
	}
	return b.String()
}

// The fixtures reproduce the 2026-10-08 baseline: pack revision
// cncf-2026-09-13.4 (reduced to the fields the report reads) and the lines
// snapshot of that day.
func TestBaselineReproduced(t *testing.T) {
	report, err := Compute(Input{Pack: read(t, "testdata/pack-cncf-2026-09-13.4-reduced.json"), Lines: read(t, "testdata/lines-2026-10-08.json"), Now: baselineNow})
	if err != nil {
		t.Fatal(err)
	}
	f := report.Fleet
	if f.A != 0 || f.B != 0 || f.S != 44 || f.Pairs != 275 || f.G != 231 || f.Projects != 55 {
		t.Fatalf("fleet = %+v", f)
	}
	if f.C1 != 53 || report.PackProjects != 53 {
		t.Fatalf("covered projects = %d / %d, want 53", f.C1, report.PackProjects)
	}
	if p := report.Priority; p.Projects != 30 || p.C1 != 28 || p.S != 25 || p.Pairs != 150 {
		t.Fatalf("priority = %+v", p)
	}
	if f.VCMean != 0 || f.VCPairs != 0 || f.SPairs != 0.16 {
		t.Fatalf("ratios = %+v", f)
	}
	var golden map[string]string
	if err := json.Unmarshal(read(t, "testdata/golden-pairs-cncf-2026-09-13.4.json"), &golden); err != nil {
		t.Fatal(err)
	}
	if len(golden) != len(report.Projects) {
		t.Fatalf("golden has %d projects, report %d", len(golden), len(report.Projects))
	}
	for _, p := range report.Projects {
		if got := statuses(p); got != golden[p.Project] {
			t.Errorf("%s: %s, want %s", p.Project, got, golden[p.Project])
		}
	}
}

// The fleet figures of the shipped pack, by the generation of its Kubernetes
// API-removal rules. The reviewed generation is the baseline pack itself
// (revision cncf-2026-09-13.4, clock 2026-10-08): no bounded pair, 44 spots.
// The mechanical generation (K8R-7) covers three more pairs with a bounded
// removal range and has one spot fewer per reviewed rule it does not repeat;
// its figures are those of the same lines snapshot at the shared test clock
// (supersedeids.Clock, after the rules' derivation and before their expiry),
// measured on the dry K8R-6 pack. When the real K8R-7 data changes them, this
// table changes with it in that PR: an expectation, not a skip.
type fleetFigures struct {
	Projects, Pairs, A, B, S, G, C1, C3 int
}

func fleetOf(f Totals) fleetFigures {
	return fleetFigures{f.Projects, f.Pairs, f.A, f.B, f.S, f.G, f.C1, f.C3}
}

func TestEmbeddedPackBaseline(t *testing.T) {
	pack, err := cncfcheck.EmbeddedRulePack()
	if err != nil {
		t.Fatal(err)
	}
	var head struct {
		Revision string `json:"revision"`
	}
	if err := json.Unmarshal(pack, &head); err != nil {
		t.Fatal(err)
	}
	now, want := baselineNow, fleetFigures{Projects: 55, Pairs: 275, A: 0, B: 0, S: 44, G: 231, C1: 53, C3: 0}
	if supersedeids.Superseded() {
		now, want = supersedeids.Clock(), fleetFigures{Projects: 55, Pairs: 275, A: 0, B: 3, S: 44, G: 228, C1: 53, C3: 1}
	} else if head.Revision != "cncf-2026-09-13.4" {
		// Only the reviewed generation is tied to the baseline revision: a
		// bumped revision means a new baseline, which this file records.
		t.Skipf("embedded pack is %s; the baseline pack is cncf-2026-09-13.4", head.Revision)
	}
	report, err := Compute(Input{Pack: pack, Lines: read(t, "testdata/lines-2026-10-08.json"), Now: now})
	if err != nil {
		t.Fatal(err)
	}
	if got := fleetOf(report.Fleet); got != want {
		t.Fatalf("fleet at %s = %+v, want %+v", now.Format(time.RFC3339), got, want)
	}
}

func TestDeterministic(t *testing.T) {
	in := Input{Pack: read(t, "testdata/pack-cncf-2026-09-13.4-reduced.json"), Lines: read(t, "testdata/lines-2026-10-08.json"), Now: baselineNow}
	var first []byte
	for i := 0; i < 2; i++ {
		report, err := Compute(in)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := report.JSON()
		if err != nil {
			t.Fatal(err)
		}
		raw = append(raw, report.Markdown()...)
		if first == nil {
			first = raw
		} else if !bytes.Equal(first, raw) {
			t.Fatal("two runs differ")
		}
	}
}

const (
	k8s = "pkg:github/kubernetes/kubernetes"
	rev = "1111111111111111111111111111111111111111"
)

func rangeJSON(fromGte, fromLt, toGte, toLt string) string {
	return fmt.Sprintf(`"range":{"from":{"gte":%q,"lt":%q},"to":{"gte":%q,"lt":%q}}`, fromGte, fromLt, toGte, toLt)
}

func ruleJSON(id, from, to, extra, until string) string {
	if extra != "" {
		extra = "," + extra
	}
	return fmt.Sprintf(`{"project":"kubernetes","rule":{"id":%q,"operator":"forbid_predicate_value","subject":{"component":%q,"from":%q,"to":%q}%s,"condition":{"side":"proposed","component":%q,"factId":"component.kubernetes.cronjob_v1beta1_removed_gvk_present","boolValue":true},"evidence":{"state":"active","reviewedAt":"2026-09-01T00:00:00Z","validUntil":%q}}}`, id, k8s, from, to, extra, k8s, until)
}

func attJSON(line, until string, ids ...string) string {
	quoted := make([]string, len(ids))
	for i, id := range ids {
		quoted[i] = fmt.Sprintf("%q", id)
	}
	src := func(id string) string {
		return fmt.Sprintf(`{"id":%q,"url":"https://github.com/kubernetes/kubernetes/blob/%s/api/openapi-spec/swagger.json","revision":%q,"contentDigest":"sha256:%s","startLine":1,"endLine":10}`, id, rev, rev, strings.Repeat("a", 64))
	}
	return fmt.Sprintf(`{"component":%q,"line":%q,"factFamily":"kubernetes.removed_served_gvk","completeness":"COMPLETE_REVIEWED_RULES_FOR_LINE","ruleIds":[%s],"evidence":{"basis":"reviewed","reviewedAt":"2026-09-01T00:00:00Z","validUntil":%q,"sources":[%s,%s]}}`, k8s, line, strings.Join(quoted, ","), until, src("openapi-a"), src("openapi-b"))
}

func pack(rules []string, atts []string) []byte {
	section := ""
	if len(atts) > 0 {
		section = `,"lineAttestations":[` + strings.Join(atts, ",") + `]`
	}
	return []byte(`{"schema":"test","revision":"synthetic","entries":[` + strings.Join(rules, ",") + `]` + section + `}`)
}

func lines(slug string, window ...string) []byte {
	quoted := make([]string, len(window))
	for i, l := range window {
		quoted[i] = fmt.Sprintf("%q", l)
	}
	return []byte(fmt.Sprintf(`{"schema":%q,"projects":{%q:{"lines":[%s]}}}`, LinesSchema, slug, strings.Join(quoted, ",")))
}

const (
	valid   = "2026-11-30T00:00:00Z"
	expired = "2026-09-15T00:00:00Z"
)

func run(t *testing.T, rules, atts []string, window ...string) Project {
	t.Helper()
	report, err := Compute(Input{Pack: pack(rules, atts), Lines: lines("kubernetes", window...), Now: baselineNow})
	if err != nil {
		t.Fatal(err)
	}
	return report.Projects[0]
}

func TestClassification(t *testing.T) {
	rules := []string{
		ruleJSON("range.132", "1.31.0", "1.32.0", rangeJSON("1.31.0", "1.32.0", "1.32.0", "1.33.0"), valid),
		ruleJSON("anchor.133", "1.32.4", "1.33.1", "", valid),
		ruleJSON("cross.135", "1.33.0", "1.35.0", `"crossing":{"change":{"version":"1.35.0","basis":"REMOVED_IN_RELEASE","sourceId":"s"},"horizon":{"lt":"1.40.0","basis":"REVIEWED_THROUGH_MINOR_LINE","sourceId":"s"}}`, valid),
	}
	atts := []string{attJSON("1.31", valid), attJSON("1.33", valid, "anchor.133")}
	p := run(t, rules, atts, "1.30", "1.31", "1.32", "1.33", "1.34", "1.35")
	if got, want := statuses(p), "ABSGB"; got != want {
		t.Fatalf("statuses = %s, want %s", got, want)
	}
	if p.A != 1 || p.B != 2 || p.S != 1 || p.G != 1 || p.VC != 0.6 || p.VCA != 0.2 {
		t.Fatalf("row = %+v", p)
	}
	if p.Pairs[0].Families[0] != "kubernetes.removed_served_gvk" {
		t.Fatalf("families = %v", p.Pairs[0].Families)
	}
}

// Range boundaries: a range that does not cover the whole line on both sides
// is a spot at best, never a bounded pair.
func TestRangeBoundaryMutations(t *testing.T) {
	cases := []struct {
		name  string
		rng   string
		exact bool
		want  string
	}{
		{"exact", rangeJSON("1.31.0", "1.32.0", "1.32.0", "1.33.0"), true, "B"},
		{"from starts late", rangeJSON("1.31.1", "1.32.0", "1.32.0", "1.33.0"), true, "S"},
		{"from ends early", rangeJSON("1.31.0", "1.31.9", "1.32.0", "1.33.0"), true, "S"},
		{"to starts late", rangeJSON("1.31.0", "1.32.0", "1.32.1", "1.33.0"), true, "S"},
		{"to ends early", rangeJSON("1.31.0", "1.32.0", "1.32.0", "1.32.9"), true, "S"},
		{"wider", rangeJSON("1.30.0", "1.32.0", "1.32.0", "1.34.0"), true, "B"},
		{"range elsewhere, anchor remains", rangeJSON("1.30.0", "1.31.0", "1.31.0", "1.32.0"), false, "S"},
	}
	for _, c := range cases {
		rule := ruleJSON("r", "1.31.3", "1.32.1", c.rng, valid)
		p := run(t, []string{rule}, nil, "1.31", "1.32")
		if got := statuses(p); got != c.want {
			t.Errorf("%s: %s, want %s", c.name, got, c.want)
		}
	}
}

func TestCrossingMutations(t *testing.T) {
	cross := func(change, horizon string) string {
		return ruleJSON("c", "1.33.0", "1.35.0", fmt.Sprintf(`"crossing":{"change":{"version":%q,"basis":"REMOVED_IN_RELEASE","sourceId":"s"},"horizon":{"lt":%q,"basis":"REVIEWED_THROUGH_MINOR_LINE","sourceId":"s"}}`, change, horizon), valid)
	}
	cases := []struct{ name, rule, want string }{
		{"change inside target line", cross("1.35.0", "1.40.0"), "B"},
		{"change late in target line", cross("1.35.7", "1.40.0"), "B"},
		{"change in an earlier line", cross("1.34.0", "1.40.0"), "G"},
		{"change in a later line", cross("1.36.0", "1.40.0"), "G"},
		{"horizon at the change", cross("1.35.0", "1.35.0"), "G"},
	}
	for _, c := range cases {
		p := run(t, []string{c.rule}, nil, "1.34", "1.35")
		if got := statuses(p); got != c.want {
			t.Errorf("%s: %s, want %s", c.name, got, c.want)
		}
	}
}

func TestAttestationRules(t *testing.T) {
	wide := ruleJSON("wide", "1.31.0", "1.32.0", rangeJSON("1.31.0", "1.32.0", "1.32.0", "1.33.0"), valid)
	anchor := ruleJSON("anchor", "1.31.2", "1.32.1", "", valid)
	stale := ruleJSON("old", "1.31.0", "1.32.0", rangeJSON("1.31.0", "1.32.0", "1.32.0", "1.33.0"), expired)
	cases := []struct {
		name  string
		rules []string
		atts  []string
		lines []string
		want  string
	}{
		{"empty list", nil, []string{attJSON("1.32", valid)}, []string{"1.31", "1.32"}, "A"},
		{"line-wide rule listed", []string{wide}, []string{attJSON("1.32", valid, "wide")}, []string{"1.31", "1.32"}, "A"},
		{"anchor rule listed", []string{anchor}, []string{attJSON("1.32", valid, "anchor")}, []string{"1.31", "1.32"}, "S"},
		{"one anchor among wide", []string{wide, anchor}, []string{attJSON("1.32", valid, "anchor", "wide")}, []string{"1.31", "1.32"}, "B"},
		{"listed rule expired", []string{stale}, []string{attJSON("1.32", valid, "old")}, []string{"1.31", "1.32"}, "G"},
		{"listed rule missing", nil, []string{attJSON("1.32", valid, "missing")}, []string{"1.31", "1.32"}, "G"},
		{"attestation expired", nil, []string{attJSON("1.32", expired)}, []string{"1.31", "1.32"}, "G"},
		{"attestation is for another line", nil, []string{attJSON("1.33", valid)}, []string{"1.31", "1.32"}, "G"},
		{"skipped line is not the previous line", nil, []string{attJSON("1.33", valid)}, []string{"1.31", "1.33"}, "G"},
		{"before review", nil, []string{strings.Replace(attJSON("1.32", valid), "2026-09-01T00:00:00Z", "2026-11-01T00:00:00Z", 1)}, []string{"1.31", "1.32"}, "G"},
	}
	for _, c := range cases {
		rules := c.rules
		if rules == nil {
			// An unrelated valid rule keeps the pack non-empty.
			rules = []string{ruleJSON("unrelated", "1.20.0", "1.21.0", "", valid)}
		}
		p := run(t, rules, c.atts, c.lines...)
		if got := statuses(p); got != c.want {
			t.Errorf("%s: %s, want %s", c.name, got, c.want)
		}
	}
}

func TestExpiryAndNow(t *testing.T) {
	soon := ruleJSON("soon", "1.31.2", "1.32.1", "", "2026-10-15T00:00:00Z")
	p := run(t, []string{soon}, nil, "1.31", "1.32")
	if statuses(p) != "S" || p.Expiring != 1 || !p.Covered {
		t.Fatalf("row = %+v", p)
	}
	report, err := Compute(Input{Pack: pack([]string{soon}, nil), Lines: lines("kubernetes", "1.31", "1.32"), Now: time.Date(2026, 10, 16, 0, 0, 0, 0, time.UTC)})
	if err != nil {
		t.Fatal(err)
	}
	if got := statuses(report.Projects[0]); got != "G" || report.Projects[0].Covered || len(report.WithoutLines) != 0 {
		t.Fatalf("after expiry: %s %+v", got, report.Projects[0])
	}
}

func TestWindowAndWithoutLines(t *testing.T) {
	rule := ruleJSON("r", "1.31.2", "1.32.1", "", valid)
	other := strings.Replace(ruleJSON("o", "2.1.0", "2.2.0", "", valid), `"project":"kubernetes"`, `"project":"other"`, 1)
	report, err := Compute(Input{Pack: pack([]string{rule, other}, nil), Lines: lines("kubernetes", "1.28", "1.29", "1.30", "1.31", "1.32"), Now: baselineNow, Window: 3})
	if err != nil {
		t.Fatal(err)
	}
	p := report.Projects[0]
	if strings.Join(p.Window, ",") != "1.30,1.31,1.32" || len(p.Pairs) != 2 || statuses(p) != "GS" {
		t.Fatalf("row = %+v", p)
	}
	if len(report.WithoutLines) != 1 || report.WithoutLines[0] != "other" || report.PackProjects != 2 || report.Fleet.C1 != 1 {
		t.Fatalf("without lines = %v, packProjects = %d, c1 = %d", report.WithoutLines, report.PackProjects, report.Fleet.C1)
	}
}

// Projects whose lines are not major.minor of the engine version are
// measured on exact pairs only.
func TestCloudCustodianExactPairsOnly(t *testing.T) {
	custodian := func(id, from, to, extra string) string {
		return strings.Replace(ruleJSON(id, from, to, extra, valid), `"project":"kubernetes"`, `"project":"cloud-custodian"`, 1)
	}
	rules := []string{custodian("a", "0.9.50", "0.9.51", ""), custodian("b", "0.9.40", "0.9.42", rangeJSON("0.9.40", "0.9.41", "0.9.41", "0.9.43"))}
	report, err := Compute(Input{Pack: pack(rules, nil), Lines: lines("cloud-custodian", "9.40", "9.41", "9.50", "9.51"), Now: baselineNow})
	if err != nil {
		t.Fatal(err)
	}
	if got := statuses(report.Projects[0]); got != "GGS" {
		t.Fatalf("statuses = %s", got)
	}
}

func TestInputsRejected(t *testing.T) {
	good := pack([]string{ruleJSON("r", "1.31.2", "1.32.1", "", valid)}, nil)
	goodLines := lines("kubernetes", "1.31", "1.32")
	bad := []Input{
		{Pack: good, Lines: goodLines},
		{Pack: good, Lines: goodLines, Now: baselineNow, Window: 1},
		{Pack: []byte("{"), Lines: goodLines, Now: baselineNow},
		{Pack: good, Lines: []byte(`{"schema":"x","projects":{"a":{"lines":[]}}}`), Now: baselineNow},
		{Pack: good, Lines: lines("kubernetes", "1.32", "1.31"), Now: baselineNow},
		{Pack: good, Lines: lines("kubernetes", "1.31", "1.31"), Now: baselineNow},
		{Pack: good, Lines: lines("kubernetes", "1.31", "v1.32"), Now: baselineNow},
		{Pack: good, Lines: []byte(strings.Replace(string(goodLines), `"lines"`, `"extra":1,"lines"`, 1)), Now: baselineNow},
		{Pack: pack([]string{ruleJSON("r", "1.31.2", "1.32.1", "", valid), ruleJSON("r", "1.31.2", "1.32.1", "", valid)}, nil), Lines: goodLines, Now: baselineNow},
		{Pack: pack([]string{ruleJSON("r", "1.31.2", "1.32.1", "", valid)}, []string{strings.Replace(attJSON("1.32", valid), "COMPLETE_REVIEWED_RULES_FOR_LINE", "SOMETHING", 1)}), Lines: goodLines, Now: baselineNow},
	}
	for i, in := range bad {
		if _, err := Compute(in); err == nil {
			t.Errorf("case %d accepted", i)
		}
	}
}

func TestLineOfTag(t *testing.T) {
	cases := []struct {
		project, tag, line string
	}{
		{"argo-cd", "v3.5.2", "3.5"},
		{"argo-cd", "refs/tags/v3.5.2^{}", "3.5"},
		{"argo-cd", "3.5.0", "3.5"},
		{"argo-cd", "v3.5.0-rc1", ""},
		{"argo-cd", "v03.5.0", ""},
		{"argo-cd", "stable-2.14.1", ""},
		{"argo-cd", "v3.5", ""},
		{"linkerd", "stable-2.14.10", "2.14"},
		{"linkerd", "version-2.11.5", "2.11"},
		{"linkerd", "edge-24.5.1", ""},
		{"linkerd", "v2.14.0", ""},
		{"cloud-custodian", "0.9.45", "9.45"},
		{"cloud-custodian", "0.9.45.1", "9.45"},
		{"cloud-custodian", "0.9.45.1rc1", ""},
		{"cloud-custodian", "1.9.45", ""},
		{"vitess", "v22.0.1", "22.0"},
	}
	for _, c := range cases {
		line, ok := LineOfTag(c.project, c.tag)
		if (c.line != "") != ok || line != c.line {
			t.Errorf("%s %s = %q %v, want %q", c.project, c.tag, line, ok, c.line)
		}
	}
}

func TestLinesFromTags(t *testing.T) {
	listings := map[string][]byte{
		"demo": []byte("# captured\n" +
			"aaaa\trefs/tags/v1.10.0\n" +
			"aaaa\trefs/tags/v1.10.0^{}\n" +
			"bbbb\trefs/tags/v1.9.3\n" +
			"cccc\trefs/tags/v1.11.0-rc.1\n" +
			"v1.2.0\n"),
		"empty": []byte(""),
	}
	file, err := LinesFromTags(listings, map[string]bool{"demo": true}, "2026-10-08")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := MarshalLines(file)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseLines(raw)
	if err != nil {
		t.Fatal(err)
	}
	demo := parsed.Projects["demo"]
	if strings.Join(demo.Lines, ",") != "1.2,1.9,1.10" || !demo.Priority || parsed.CapturedOn != "2026-10-08" || len(parsed.Projects["empty"].Lines) != 0 {
		t.Fatalf("parsed = %+v", parsed)
	}
	raw2, _ := MarshalLines(file)
	if !bytes.Equal(raw, raw2) {
		t.Fatal("encoding is not stable")
	}
}
