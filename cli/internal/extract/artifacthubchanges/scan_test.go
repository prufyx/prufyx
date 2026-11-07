// SPDX-License-Identifier: AGPL-3.0-only

package artifacthubchanges

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"go/parser"
	gotoken "go/token"
	"math/rand"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/extract"
)

var (
	commitA = strings.Repeat("a", 40)
	repo    = extract.RepoRef{Key: "github.com/example/charts"}
)

type memReader struct {
	files   map[string]string
	readErr error
}

func (m *memReader) Read(_ extract.RepoRef, _, p string) ([]byte, error) {
	if m.readErr != nil {
		return nil, m.readErr
	}
	if d, ok := m.files[p]; ok {
		return []byte(d), nil
	}
	return nil, fmt.Errorf("%w: %s", extract.ErrNotFound, p)
}

func (m *memReader) List(extract.RepoRef, string, string) ([]extract.TreeEntry, error) {
	return nil, errors.New("the reader must not list")
}

func chartPath(name string) string { return "charts/" + name + "/Chart.yaml" }

// fixtures loads testdata/<dir> as charts, in a shuffled order of paths.
func fixtures(t testing.TB, dir string) map[string]string {
	t.Helper()
	ents, err := os.ReadDir(filepath.Join("testdata", dir))
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	for _, e := range ents {
		b, err := os.ReadFile(filepath.Join("testdata", dir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		out[chartPath(strings.TrimSuffix(e.Name(), ".yaml"))] = string(b)
	}
	return out
}

func scanFiles(t testing.TB, files map[string]string, shuffle *rand.Rand) *Result {
	t.Helper()
	var paths []string
	for p := range files {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	if shuffle != nil {
		shuffle.Shuffle(len(paths), func(i, j int) { paths[i], paths[j] = paths[j], paths[i] })
	}
	res, err := Scan(context.Background(), &memReader{files: files}, Target{Repo: repo, Charts: paths}, commitA)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func scan(t testing.TB, files map[string]string) *Result { return scanFiles(t, files, nil) }

func TestPositiveFixtures(t *testing.T) {
	res := scan(t, fixtures(t, "ok"))
	if len(res.Ledger) != 0 {
		t.Fatalf("ledger %v", res.Ledger)
	}
	type k struct{ file, typ, action, member, comp string }
	var got []k
	for _, c := range res.Candidates {
		got = append(got, k{strings.TrimSuffix(strings.TrimPrefix(c.File, "charts/"), "/Chart.yaml"), c.Type, c.Action, c.Member, c.Component})
		if c.EvidenceBasis == "mechanical" || c.EvidenceBasis != "draft" || !c.NeedsReview {
			t.Fatalf("basis %+v", c)
		}
		if c.SourceURL != "https://github.com/example/charts/blob/"+commitA+"/"+c.File {
			t.Fatalf("url %s", c.SourceURL)
		}
		if c.Quote == "" || c.StartLine < 1 || c.EndLine < c.StartLine || c.Chart != "demo" || c.ChartVersion != "1.2.3" {
			t.Fatalf("span %+v", c)
		}
	}
	want := []k{
		{"flag-removed", "flag", "removed", "old-flag", "unknown"},
		{"future-removal", "flag", "deprecated", "legacy-mode", "unknown"},
		{"other-kinds", "flag", "removed", "gone", "unknown"},
		{"values-deprecated", "values_key", "deprecated", "ingress.legacy.enabled", ""},
		{"values-removed", "values_key", "removed", "metrics.serviceMonitor.interval", ""},
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("got %v\nwant %v", got, want)
	}
	if res.FilesRead != 5 {
		t.Fatalf("files read %d", res.FilesRead)
	}
}

func TestNegativeFixtures(t *testing.T) {
	want := map[string]string{
		"unknown-field":         ReasonParse,
		"alias":                 ReasonParse,
		"duplicate-key":         ReasonParse,
		"two-docs":              ReasonParse,
		"tag":                   ReasonParse,
		"bad-api-version":       ReasonSchema,
		"bad-name":              ReasonParse,
		"annotation-not-string": ReasonParse,
		"inner-unknown-field":   ReasonParse,
		"inner-alias":           ReasonParse,
		"inner-two-docs":        ReasonParse,
		"inner-not-list":        ReasonParse,
		"inner-not-string":      ReasonParse,
		"inner-duplicate-key":   ReasonParse,
		"bad-kind":              ReasonKindUnknown,
		"no-signal":             ReasonNoSignal,
		"no-token":              ReasonNoToken,
		"multi-token":           ReasonMultipleTokens,
		"unclassified":          ReasonUnclassified,
		"host-like":             ReasonUnclassified,
		"code-fence":            ReasonUnclassified,
		"odd-backticks":         ReasonUnclassified,
		"mixed-action":          ReasonAmbiguous,
		"kind-conflict":         ReasonAmbiguous,
		"negated":               ReasonAmbiguous,
		"may-be-removed":        ReasonAmbiguous,
		"planned":               ReasonAmbiguous,
		"removal-in":            ReasonAmbiguous,
		"next-release":          ReasonAmbiguous,
		"replacement":           ReasonAmbiguous,
		"replacement-many":      ReasonAmbiguous,
		"default":               ReasonAmbiguous,
		"not-adjacent":          ReasonAmbiguous,
	}
	files := fixtures(t, "neg")
	if len(files) != len(want) || len(want) < 15 {
		t.Fatalf("%d fixtures, %d expectations", len(files), len(want))
	}
	for name, code := range want {
		t.Run(name, func(t *testing.T) {
			p := chartPath(name)
			res := scan(t, map[string]string{p: files[p]})
			if len(res.Candidates) != 0 {
				t.Fatalf("candidates %+v", res.Candidates)
			}
			if len(res.Ledger) != 1 || res.Ledger[0] != (LedgerEntry{Code: code, Item: p}) {
				t.Fatalf("ledger %+v, want %s", res.Ledger, code)
			}
		})
	}
}

func TestNegativeDoesNotHideOthers(t *testing.T) {
	files := fixtures(t, "ok")
	neg := fixtures(t, "neg")
	for p, c := range neg {
		files[p] = c
	}
	res := scan(t, files)
	if len(res.Ledger) != len(neg) || len(res.Candidates) != 5 {
		t.Fatalf("ledger %d candidates %d", len(res.Ledger), len(res.Candidates))
	}
}

func TestDeterministic(t *testing.T) {
	files := fixtures(t, "ok")
	for p, c := range fixtures(t, "neg") {
		files[p] = c
	}
	var first []byte
	for i := 0; i < 20; i++ {
		b, err := json.Marshal(scanFiles(t, files, rand.New(rand.NewSource(int64(i)))))
		if err != nil {
			t.Fatal(err)
		}
		if first == nil {
			first = b
		} else if string(first) != string(b) {
			t.Fatalf("run %d differs", i)
		}
	}
	res := scan(t, files)
	if !sort.SliceIsSorted(res.Candidates, func(i, j int) bool { return lessCandidate(res.Candidates[i], res.Candidates[j]) }) {
		t.Fatal("candidates unsorted")
	}
}

const chartHead = "apiVersion: v2\nname: demo\nversion: 1.2.3\n"

// chartOf wraps the annotation document inner in a Chart.yaml as a literal
// block.
func chartOf(inner string) string {
	var b strings.Builder
	b.WriteString(chartHead + "annotations:\n  " + ChangesAnnotation + ": |\n")
	for _, l := range strings.Split(strings.TrimRight(inner, "\n"), "\n") {
		b.WriteString("    " + l + "\n")
	}
	return b.String()
}

func entry(kind, desc string) string {
	return "- kind: " + kind + "\n  description: " + desc + "\n"
}

func one(body string) map[string]string { return map[string]string{chartPath("a"): body} }

func removed(i int) string { return entry("removed", fmt.Sprintf("Removed `--f%d` flag.", i)) }

func TestSpan(t *testing.T) {
	// Plain description in a literal annotation: lines are real, exactness is not claimed.
	res := scan(t, fixtures(t, "ok"))
	for _, c := range res.Candidates {
		if strings.Contains(c.File, "flag-removed") && (c.StartLine != 7 || c.EndLine != 7 || c.SpanExact) {
			t.Fatalf("%+v", c)
		}
	}
	// Literal description in a literal annotation: exact.
	body := chartOf("- kind: removed\n  description: |\n    Removed `--a` flag.\n")
	res = scan(t, one(body))
	if len(res.Candidates) != 1 {
		t.Fatalf("%+v", res)
	}
	c := res.Candidates[0]
	lines := strings.Split(body, "\n")
	if !c.SpanExact || !strings.Contains(lines[c.StartLine-1], "Removed `--a` flag.") || c.StartLine != c.EndLine {
		t.Fatalf("%+v line %q", c, lines[c.StartLine-1])
	}
	// Quoted annotation: a span is given, never claimed exact.
	body = chartHead + "annotations:\n  " + ChangesAnnotation + ": \"- kind: removed\\n  description: Removed `--a` flag.\\n\"\n"
	res = scan(t, one(body))
	if len(res.Candidates) != 1 || res.Candidates[0].SpanExact || res.Candidates[0].StartLine < 1 || res.Candidates[0].EndLine < res.Candidates[0].StartLine {
		t.Fatalf("%+v", res)
	}
}

func TestNoAnnotationIsNotAnError(t *testing.T) {
	for _, body := range []string{
		chartHead,
		chartHead + "annotations:\n  other: x\n",
		chartOf("[]"),
	} {
		res := scan(t, one(body))
		if len(res.Candidates) != 0 || len(res.Ledger) != 0 || res.FilesRead != 1 {
			t.Fatalf("%+v", res)
		}
	}
}

func TestStructuralFaults(t *testing.T) {
	cases := []struct {
		name  string
		files map[string]string
		paths []string
		code  string
	}{
		{"empty file", one(""), nil, ReasonParse},
		{"not mapping", one("- a\n"), nil, ReasonParse},
		{"missing", map[string]string{}, []string{chartPath("a")}, ReasonMissing},
		{"dotdot path", one(chartHead), []string{"charts/../a/Chart.yaml"}, ReasonUnsafePath},
		{"absolute path", one(chartHead), []string{"/etc/Chart.yaml"}, ReasonUnsafePath},
		{"other file name", one(chartHead), []string{"charts/a/values.yaml"}, ReasonUnsafePath},
		{"hostile path", one(chartHead), []string{"charts/a b/Chart.yaml"}, ReasonUnsafePath},
		{"dot segment", one(chartHead), []string{"charts/./a/Chart.yaml"}, ReasonUnsafePath},
		{"member refused", one(chartOf(entry("removed", "Removed `--"+strings.Repeat("z", 150)+"`."))), nil, ReasonMember},
		{"too deep annotation", one(chartOf("- kind: removed\n  description: x\n  links: " + strings.Repeat("[", maxDepth+2) + strings.Repeat("]", maxDepth+2))), nil, ReasonParse},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			paths := c.paths
			if paths == nil {
				for p := range c.files {
					paths = append(paths, p)
				}
			}
			res, err := Scan(context.Background(), &memReader{files: c.files}, Target{Repo: repo, Charts: paths}, commitA)
			if err != nil {
				t.Fatal(err)
			}
			if len(res.Candidates) != 0 {
				t.Fatalf("candidates %+v", res.Candidates)
			}
			for _, e := range res.Ledger {
				if e.Code == c.code {
					return
				}
			}
			t.Fatalf("ledger %+v lacks %s", res.Ledger, c.code)
		})
	}
}

func TestIOErrorsAbort(t *testing.T) {
	boom := errors.New("boom")
	r := &memReader{files: one(chartHead), readErr: boom}
	if _, err := Scan(context.Background(), r, Target{Repo: repo, Charts: []string{chartPath("a")}}, commitA); !errors.Is(err, boom) {
		t.Fatalf("err %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	m := &memReader{files: one(chartHead)}
	if _, err := Scan(ctx, m, Target{Repo: repo, Charts: []string{chartPath("a")}}, commitA); !errors.Is(err, context.Canceled) {
		t.Fatalf("err %v", err)
	}
	for _, sha := range []string{"", "main", strings.Repeat("A", 40), commitA[:39]} {
		if _, err := Scan(context.Background(), m, Target{Repo: repo, Charts: []string{chartPath("a")}}, sha); err == nil {
			t.Fatalf("sha %q accepted", sha)
		}
	}
	if _, err := Scan(context.Background(), m, Target{Repo: repo}, commitA); err == nil {
		t.Fatal("empty chart list accepted")
	}
}

func TestPanicBecomesLedger(t *testing.T) {
	res, err := Scan(context.Background(), nil, Target{Repo: repo, Charts: []string{chartPath("a")}}, commitA)
	if err != nil || len(res.Candidates) != 0 || len(res.Ledger) != 1 || res.Ledger[0].Code != ReasonPanic {
		t.Fatalf("%+v %v", res, err)
	}
}

func TestDuplicatePathsReadOnce(t *testing.T) {
	p := chartPath("a")
	res, err := Scan(context.Background(), &memReader{files: map[string]string{p: chartOf(removed(1))}}, Target{Repo: repo, Charts: []string{p, p}}, commitA)
	if err != nil || res.FilesRead != 1 || len(res.Candidates) != 1 {
		t.Fatalf("%+v %v", res, err)
	}
}

func TestLedgerCanonical(t *testing.T) {
	l := ledgerSet{}
	l.add("ZED_CODE", "b")
	l.add("ALPHA_CODE", "z")
	l.add("ALPHA_CODE", "a")
	got := l.canonical()
	if len(got) != 3 || got[0].Item != "a" || got[1].Item != "z" || got[2].Code != "ZED_CODE" {
		t.Fatalf("%+v", got)
	}
	bad := ledgerSet{}
	bad.add("lower", "x")
	if g := bad.canonical(); len(g) != 1 || g[0].Code != LedgerInvalid {
		t.Fatalf("%+v", g)
	}
	bad = ledgerSet{}
	bad.add("OK_CODE", "bad item with space")
	if g := bad.canonical(); len(g) != 1 || g[0].Code != LedgerInvalid {
		t.Fatalf("%+v", g)
	}
	over := ledgerSet{}
	for i := 0; i <= MaxLedgerEntries; i++ {
		over.add("OK_CODE", fmt.Sprintf("i%d", i))
	}
	if g := over.canonical(); len(g) != 1 || g[0].Code != LedgerOverflow {
		t.Fatalf("%+v", g)
	}
}

func TestLedgerCarriesIdentifiersOnly(t *testing.T) {
	canary := "CANARYTEXT"
	files := map[string]string{
		chartPath("a"): chartOf(entry("removed", "Removed `--a` flag, use `--b` instead "+canary+".")),
		chartPath("b"): chartOf(entry("bogus", canary)),
	}
	res := scan(t, files)
	b, _ := json.Marshal(res.Ledger)
	if len(res.Ledger) != 2 || strings.Contains(string(b), canary) {
		t.Fatalf("%s", b)
	}
}

func TestResultJSONGolden(t *testing.T) {
	res := scan(t, one(chartOf("- kind: removed\n  description: |\n    Removed `--old`.\n")))
	b, _ := json.Marshal(res)
	want := `{"schema":"prufyx.io/artifacthub-changes-scan/v1","commit":"` + commitA + `","filesRead":1,"candidates":[{"type":"flag","action":"removed","member":"old","component":"unknown","chart":"demo","chartVersion":"1.2.3","file":"charts/a/Chart.yaml","changeKind":"removed","quote":"Removed ` + "`--old`" + `.","startLine":8,"endLine":8,"spanExact":true,"sourceUrl":"https://github.com/example/charts/blob/` + commitA + `/charts/a/Chart.yaml","evidenceBasis":"draft","needsReview":true}],"ledger":[]}`
	if string(b) != want {
		t.Fatalf("\n%s\n%s", b, want)
	}
}

func TestSourceSetCoversEncoder(t *testing.T) {
	files, err := extract.CodeFiles(SourceSet())
	if err != nil {
		t.Fatal(err)
	}
	var own, enc, tests int
	for _, f := range files {
		switch {
		case strings.HasSuffix(f.Path, "_test.go"):
			tests++
		case strings.Contains(f.Path, "membercode_membercode.go"):
			enc++
		case strings.Contains(f.Path, "scan.go"):
			own++
		}
	}
	if own != 1 || enc != 1 || tests != 0 {
		t.Fatalf("own %d encoder %d tests %d: %+v", own, enc, tests, files)
	}
	again, _ := extract.CodeFiles(SourceSet())
	if fmt.Sprint(files) != fmt.Sprint(again) {
		t.Fatal("source set unstable")
	}
}

func nonTestSources(t *testing.T) []string {
	t.Helper()
	m, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, f := range m {
		if !strings.HasSuffix(f, "_test.go") {
			out = append(out, f)
		}
	}
	if len(out) < 5 {
		t.Fatalf("sources %v", out)
	}
	return out
}

func TestNeverMechanical(t *testing.T) {
	if EvidenceBasis != "draft" {
		t.Fatal(EvidenceBasis)
	}
	for _, f := range nonTestSources(t) {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(strings.ToLower(string(b)), "mechanical") {
			t.Fatalf("%s mentions the mechanical basis", f)
		}
	}
	res := scan(t, fixtures(t, "ok"))
	if len(res.Candidates) == 0 {
		t.Fatal("no candidates")
	}
	for _, c := range res.Candidates {
		if c.EvidenceBasis != "draft" || !c.NeedsReview {
			t.Fatalf("%+v", c)
		}
		if c.Type == TypeFlag && c.Component != ComponentUnknown {
			t.Fatalf("flag without unknown component: %+v", c)
		}
	}
}

var importAllow = map[string]bool{
	"bytes": true, "context": true, "embed": true, "errors": true, "fmt": true,
	"io": true, "io/fs": true, "path": true, "regexp": true, "sort": true,
	"strings": true, "testing/fstest": true, "strconv": true,
	"gopkg.in/yaml.v3": true,
	"github.com/prufyx/prufyx/cli/internal/extract":            true,
	"github.com/prufyx/prufyx/cli/internal/extract/membercode": true,
}

func disallowedImports(name string, src any) ([]string, error) {
	f, err := parser.ParseFile(gotoken.NewFileSet(), name, src, parser.ImportsOnly)
	if err != nil {
		return nil, err
	}
	var bad []string
	for _, im := range f.Imports {
		p, _ := strconv.Unquote(im.Path.Value)
		if !importAllow[p] {
			bad = append(bad, p)
		}
	}
	return bad, nil
}

func TestImportAllowlist(t *testing.T) {
	for _, f := range nonTestSources(t) {
		bad, err := disallowedImports(f, nil)
		if err != nil || len(bad) > 0 {
			t.Fatalf("%s: %v %v", f, bad, err)
		}
	}
	// The guard is load-bearing: it refuses network, exec and file access.
	src := "package x\nimport (\n\"net/http\"\n\"os/exec\"\n\"os\"\n\"unsafe\"\n)\n"
	bad, err := disallowedImports("x.go", src)
	if err != nil || len(bad) != 4 {
		t.Fatalf("%v %v", bad, err)
	}
}

func padTo(prefix string, n int, fill string) string {
	return prefix + strings.Repeat(fill, n-len(prefix))
}

func TestBoundsAreEnforced(t *testing.T) {
	code := func(res *Result) string {
		if len(res.Ledger) != 1 {
			return fmt.Sprintf("%+v", res.Ledger)
		}
		return res.Ledger[0].Code
	}

	// Chart.yaml bytes: a trailing comment pads the file exactly.
	base := chartOf(removed(1)) + "#"
	at := base + strings.Repeat("x", MaxChartBytes-len(base)-1) + "\n"
	if len(at) != MaxChartBytes {
		t.Fatal(len(at))
	}
	if res := scan(t, one(at)); len(res.Candidates) != 1 || len(res.Ledger) != 0 {
		t.Fatalf("%+v", res)
	}
	if res := scan(t, one(at+"x")); code(res) != ReasonTooLarge || len(res.Candidates) != 0 {
		t.Fatalf("%+v", res)
	}

	// Annotation bytes: a comment line inside the annotation pads it exactly.
	inner := removed(1) + "#"
	annAt := inner + strings.Repeat("x", MaxAnnotationBytes-len(inner)-1) + "\n"
	if len(annAt) != MaxAnnotationBytes {
		t.Fatal(len(annAt))
	}
	// The chart itself stays under MaxChartBytes only if the limits allow it.
	if len(chartOf(annAt)) > MaxChartBytes {
		t.Skip("annotation limit above chart limit")
	}
	if res := scan(t, one(chartOf(annAt))); len(res.Candidates) != 1 || len(res.Ledger) != 0 {
		t.Fatalf("%+v", res)
	}
	if res := scan(t, one(chartOf(annAt+"x"))); code(res) != ReasonAnnotationTooLarge || len(res.Candidates) != 0 {
		t.Fatalf("%+v", res)
	}

	// Description bytes.
	desc := func(n int) string {
		return chartOf("- kind: removed\n  description: '" + padTo("Removed `--a` ", n, "y") + "'\n")
	}
	if res := scan(t, one(desc(MaxDescriptionBytes))); len(res.Candidates) != 1 {
		t.Fatalf("%+v", res)
	}
	if res := scan(t, one(desc(MaxDescriptionBytes+1))); code(res) != ReasonTextTooLarge || len(res.Candidates) != 0 {
		t.Fatalf("%+v", res)
	}

	// Entries per annotation.
	changes := func(n int) string {
		var b strings.Builder
		for i := 0; i < n; i++ {
			b.WriteString("- kind: added\n  description: a\n")
		}
		return chartOf(b.String())
	}
	if res := scan(t, one(changes(MaxChanges))); len(res.Ledger) != 0 {
		t.Fatalf("%+v", res)
	}
	if res := scan(t, one(changes(MaxChanges+1))); code(res) != ReasonTooManyChanges {
		t.Fatalf("%+v", res)
	}

	// Links per entry.
	links := func(n int) string {
		s := "- kind: removed\n  description: Removed `--a` flag.\n  links:\n"
		for i := 0; i < n; i++ {
			s += "    - name: n\n      url: u\n"
		}
		return chartOf(s)
	}
	if res := scan(t, one(links(MaxLinksPerChange))); len(res.Candidates) != 1 {
		t.Fatalf("%+v", res)
	}
	if res := scan(t, one(links(MaxLinksPerChange+1))); code(res) != ReasonParse || len(res.Candidates) != 0 {
		t.Fatalf("%+v", res)
	}

	// Candidates per chart.
	many := func(n int) string {
		var b strings.Builder
		for i := 0; i < n; i++ {
			b.WriteString(removed(i))
		}
		return chartOf(b.String())
	}
	if res := scan(t, one(many(MaxCandidatesPerChart))); len(res.Candidates) != MaxCandidatesPerChart {
		t.Fatalf("%d %+v", len(res.Candidates), res.Ledger)
	}
	if res := scan(t, one(many(MaxCandidatesPerChart+1))); len(res.Candidates) != 0 || code(res) != ReasonTooManyCandidates {
		t.Fatalf("%+v", res)
	}

	// Total candidates.
	all := map[string]string{}
	for i := 0; i < MaxCandidates/MaxCandidatesPerChart; i++ {
		all[chartPath(fmt.Sprintf("c%03d", i))] = many(MaxCandidatesPerChart)
	}
	if res := scan(t, all); len(res.Candidates) != MaxCandidates || len(res.Ledger) != 0 {
		t.Fatalf("%d %+v", len(res.Candidates), res.Ledger)
	}
	all[chartPath("extra")] = many(1)
	if res := scan(t, all); len(res.Candidates) != 0 || code(res) != ReasonTooManyCandidates {
		t.Fatalf("%d %+v", len(res.Candidates), res.Ledger)
	}

	// Charts per target.
	charts := map[string]string{}
	for i := 0; i < MaxCharts; i++ {
		charts[chartPath(fmt.Sprintf("c%03d", i))] = chartHead
	}
	if res := scan(t, charts); len(res.Ledger) != 0 || res.FilesRead != MaxCharts {
		t.Fatalf("%+v", res.Ledger)
	}
	charts[chartPath("extra")] = chartHead
	if res := scan(t, charts); code(res) != ReasonTooManyCharts || res.FilesRead != 0 {
		t.Fatalf("%+v", res)
	}
}

func TestNestingDepth(t *testing.T) {
	deep := func(n int) string {
		return chartHead + "keywords: " + strings.Repeat("[", n) + "a" + strings.Repeat("]", n) + "\n"
	}
	// Document node depth 0, mapping 1, n nested sequences, then the scalar: n+2.
	if res := scan(t, one(deep(maxDepth-2))); len(res.Ledger) != 0 {
		t.Fatalf("at limit: %+v", res)
	}
	if res := scan(t, one(deep(maxDepth-1))); len(res.Ledger) != 1 || res.Ledger[0].Code != ReasonParse {
		t.Fatalf("over limit: %+v", res)
	}
	var c chart
	err := decodeStrict([]byte(deep(maxDepth+2)), &c)
	if err == nil || !strings.Contains(err.Error(), "nested too deep") {
		t.Fatalf("%v", err)
	}
}
