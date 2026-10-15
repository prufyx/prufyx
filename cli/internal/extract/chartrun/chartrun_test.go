// SPDX-License-Identifier: AGPL-3.0-only

package chartrun

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/prufyx/prufyx/cli/internal/chartidentity"
	"github.com/prufyx/prufyx/cli/internal/constraintengine"
	"github.com/prufyx/prufyx/cli/internal/extract"
	"github.com/prufyx/prufyx/cli/internal/extract/safefs"
)

const (
	testRepo       = "github.com/example/project"
	testCommit     = "1111111111111111111111111111111111111111"
	testNext       = "2222222222222222222222222222222222222222"
	chartComponent = "pkg:github/example/project"
	kubernetes     = "pkg:github/kubernetes/kubernetes"
	valuesFact     = "component.example.chart_values_paths_set"
)

var toyTime = time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC)

var toyChart = &constraintengine.ChartRef{Source: "https://charts.example.com", Name: "project"}

func chartEntry(op string) Entry {
	ev := extract.Evidence{State: "active", Basis: constraintengine.BasisMechanical,
		Extractor: constraintengine.Extractor{ID: "toy.chart", Version: "1.0.0", CodeDigest: "sha256:" + strings.Repeat("a", 64)},
		DerivedAt: "2026-10-02T00:00:00Z", ReviewedAt: "2026-10-02T00:00:00Z", ValidUntil: "2026-12-31T00:00:00Z",
		Sources: []constraintengine.SourceEvidence{{ID: "toy", URL: "https://github.com/example/project/blob/" + testCommit + "/values.yaml", Revision: testCommit, ContentDigest: "sha256:" + strings.Repeat("b", 64), StartLine: 1, EndLine: 1}}}
	chart := *toyChart
	e := Entry{Project: "example", Description: "Toy chart rule.", Rule: RuleJSON{
		ID: "example.toy-chart.1-0-0-to-2-0-0", Operator: op,
		Subject:    Subject{Component: chartComponent, Chart: &chart, From: "1.0.0", To: "2.0.0"},
		Evidence:   ev,
		ReasonCode: "EXAMPLE_CHART", NextAction: "set the listed values",
	}}
	switch op {
	case constraintengine.OperatorRequireSetMember, constraintengine.OperatorForbidSetMember:
		e.RequiredFacts = []extract.Fact{{Side: "proposed", ID: valuesFact, Component: chartComponent, Type: "set", Description: "Values paths."}}
		e.Rule.SetCondition = &extract.SetCondition{Side: "proposed", Component: chartComponent, FactID: valuesFact, Members: []string{"a.b", "c"}}
	case dependencyOperator:
		e.RequiredFacts = []extract.Fact{}
		e.Rule.Dependency = &Dependency{Side: "proposed", Component: kubernetes, Comparison: "gte", Version: "1.25.0"}
	}
	return e
}

func TestChartVectorsAgreeWithTheEngine(t *testing.T) {
	for _, op := range []string{constraintengine.OperatorForbidSetMember, constraintengine.OperatorRequireSetMember, dependencyOperator} {
		e := chartEntry(op)
		vs, err := GenerateVectors(e, []string{"z"})
		if err != nil {
			t.Fatalf("%s: %v", op, err)
		}
		if err := CheckVectors([]Entry{e}, vs, toyTime); err != nil {
			t.Fatalf("%s: %v", op, err)
		}
		for _, v := range vs {
			var doc inputDoc
			if err := json.Unmarshal(v.Input, &doc); err != nil {
				t.Fatal(err)
			}
			for _, c := range append(doc.Current.Components, doc.Proposed.Components...) {
				if (c.Component == chartComponent) != (c.Chart != nil) {
					t.Fatalf("%s: component %s chart %v", v.Name, c.Component, c.Chart)
				}
			}
		}
		// Every expectation is checked: a flipped status is caught.
		for i := range vs {
			bad := append([]Vector(nil), vs...)
			bad[i].Expect.Status = "PASS"
			if vs[i].Expect.Status == "PASS" {
				bad[i].Expect.Status = "BLOCKED"
			}
			if err := CheckVectors([]Entry{e}, bad, toyTime); err == nil {
				t.Fatalf("%s: wrong expectation on %s accepted", op, vs[i].Kind)
			}
		}
		// Every kind is required.
		if err := CheckVectors([]Entry{e}, vs[:2], toyTime); err == nil {
			t.Fatalf("%s: missing vector kind accepted", op)
		}
	}
	// The missing members are compared, not only the status.
	e := chartEntry(constraintengine.OperatorRequireSetMember)
	vs, _ := GenerateVectors(e, nil)
	if !slices.Equal(vs[0].Expect.MissingMembers, []string{"a.b", "c"}) {
		t.Fatalf("blocked vector %+v", vs[0].Expect)
	}
	vs[0].Expect.MissingMembers = []string{"a.b"}
	if err := CheckVectors([]Entry{e}, vs, toyTime); err == nil {
		t.Fatal("wrong missing members accepted")
	}
	// And so are the matched members.
	e = chartEntry(constraintengine.OperatorForbidSetMember)
	vs, _ = GenerateVectors(e, nil)
	vs[0].Expect.MatchedMembers = []string{"c"}
	if err := CheckVectors([]Entry{e}, vs, toyTime); err == nil {
		t.Fatal("wrong matched members accepted")
	}
}

func TestChartVectorsRefuseShapesTheyCannotTest(t *testing.T) {
	e := chartEntry(constraintengine.OperatorRequireSetMember)
	if _, err := GenerateVectors(e, []string{"c"}); err == nil {
		t.Fatal("extra member that is required accepted")
	}
	f := chartEntry(constraintengine.OperatorForbidSetMember)
	if _, err := GenerateVectors(f, []string{"c"}); err == nil {
		t.Fatal("pass member that is forbidden accepted")
	}
	f.Rule.SetCondition.Side = "current"
	if _, err := GenerateVectors(f, nil); err == nil {
		t.Fatal("current-side set fact accepted")
	}
	d := chartEntry(dependencyOperator)
	d.Rule.Dependency.Version = "0.0.0"
	if _, err := GenerateVectors(d, nil); err == nil {
		t.Fatal("bound with nothing below it accepted")
	}
	d = chartEntry(dependencyOperator)
	d.Rule.Dependency.Comparison = "lt"
	if _, err := GenerateVectors(d, nil); err == nil {
		t.Fatal("non-gte bound accepted")
	}
	p := chartEntry("forbid_predicate_value")
	if _, err := GenerateVectors(p, nil); err == nil {
		t.Fatal("operator chart vectors do not cover accepted")
	}
	for in, want := range map[string]string{"1.25.3": "1.25.2", "1.25.0": "1.24.0", "2.0.0": "1.0.0"} {
		if got, ok := versionBelow(in); !ok || got != want {
			t.Fatalf("versionBelow(%s) = %s %v", in, got, ok)
		}
	}
	for _, in := range []string{"0.0.0", "1.2", "01.2.3", "a.b.c"} {
		if _, ok := versionBelow(in); ok {
			t.Fatalf("versionBelow(%s) accepted", in)
		}
	}
}

// --- a toy chart extractor exercising Run, stamping, vectors and Verify ---

type toyExtractor struct {
	op       string
	cite     string
	withhold bool
	src      string
}

func (toyExtractor) ID() string                     { return "toy.chart" }
func (toyExtractor) Version() string                { return "1.0.0" }
func (toyExtractor) Applies(r extract.RepoRef) bool { return r.Key == testRepo }
func (x toyExtractor) SourceFiles() (string, fs.FS) {
	return "toy", fstest.MapFS{"toy.go": {Data: []byte("package toy\n" + x.src)}}
}
func (toyExtractor) Pairs(ix extract.ReleaseIndex) []extract.VersionPair {
	return []extract.VersionPair{{Repo: ix.Repo, From: "1.0.0", FromTag: "v1.0.0", FromCommit: testCommit, To: "2.0.0", ToTag: "v2.0.0", ToCommit: testNext}}
}

func (x toyExtractor) Extract(_ context.Context, r extract.PinnedReader, p extract.VersionPair) (Extraction, error) {
	if _, err := r.Read(p.Repo, p.ToCommit, "values.yaml"); err != nil {
		return Extraction{}, err
	}
	if x.withhold {
		return Extraction{}, &extract.Withheld{Reason: "toy chart unreadable"}
	}
	cite := x.cite
	if cite == "" {
		cite = "values.yaml"
	}
	chart := *toyChart
	c := Candidate{Project: "example", Description: "Toy chart rule.",
		Rule: Rule{ID: "example.toy-chart.1-0-0-to-2-0-0", Operator: x.op,
			Subject:    Subject{Component: chartComponent, Chart: &chart, From: p.From, To: p.To},
			ReasonCode: "EXAMPLE_CHART", NextAction: "set the listed values"},
		Sources: []extract.SourceRef{{ID: "toy-values", Repo: p.Repo, Commit: p.ToCommit, Path: cite}},
	}
	switch x.op {
	case dependencyOperator:
		c.RequiredFacts = []extract.Fact{}
		c.Rule.Dependency = &Dependency{Side: "proposed", Component: kubernetes, Comparison: "gte", Version: "1.25.0"}
	default:
		c.RequiredFacts = []extract.Fact{{Side: "proposed", ID: valuesFact, Component: chartComponent, Type: "set", Description: "Values paths."}}
		c.Rule.SetCondition = &extract.SetCondition{Side: "proposed", Component: chartComponent, FactID: valuesFact, Members: []string{"a.b"}}
		c.PassMembers = []string{"z"}
	}
	return Extraction{Proof: map[string]any{"op": x.op}, Candidates: []Candidate{c}}, nil
}

func toyFixture(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	base := filepath.Join(root, filepath.FromSlash(testRepo))
	for commit, body := range map[string]string{testCommit: "a: 1\n", testNext: "a:\n  b: 1\n"} {
		dir := filepath.Join(base, "commits", commit)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "values.yaml"), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	tags := `{"v1.0.0":"` + testCommit + `","v2.0.0":"` + testNext + `"}`
	if err := os.WriteFile(filepath.Join(base, "tags.json"), []byte(tags), 0o644); err != nil {
		t.Fatal(err)
	}
	return root
}

func init() {
	chartSources = &chartidentity.SourceTable{Schema: "prufyx.io/chart-sources/v1alpha1", Records: []chartidentity.SourceRecord{{RepoURL: toyChart.Source, Chart: toyChart.Name, Component: chartComponent, Project: "example", Evidence: chartidentity.SourceEvidence{State: chartidentity.StateActive}}}}
}

func runToy(t *testing.T, x toyExtractor, root string) (*Output, error) {
	t.Helper()
	repo, err := extract.ParseRepo(testRepo)
	if err != nil {
		t.Fatal(err)
	}
	fr := extract.FixtureReader{Root: root}
	return Run(context.Background(), x, fr, fr, extract.Options{Repo: repo, DerivedAt: toyTime})
}

func TestRunStampsChartRulesAndChecksTheirVectors(t *testing.T) {
	root := toyFixture(t)
	for _, op := range []string{constraintengine.OperatorForbidSetMember, constraintengine.OperatorRequireSetMember, dependencyOperator} {
		out, err := runToy(t, toyExtractor{op: op}, root)
		if err != nil {
			t.Fatalf("%s: %v", op, err)
		}
		if len(out.Entries) != 1 || len(out.Vectors) != 3 || out.Manifest.Totals.Rules != 1 || out.Manifest.Totals.Vectors != 3 {
			t.Fatalf("%s: entries=%d vectors=%d", op, len(out.Entries), len(out.Vectors))
		}
		e := out.Entries[0].Rule
		data, _ := os.ReadFile(filepath.Join(root, testRepo, "commits", testNext, "values.yaml"))
		sum := sha256.Sum256(data)
		if e.Subject.Chart == nil || *e.Subject.Chart != *toyChart || e.Evidence.Basis != "mechanical" || len(e.Evidence.Sources) != 1 ||
			e.Evidence.Sources[0].ContentDigest != "sha256:"+hex.EncodeToString(sum[:]) || e.Evidence.Sources[0].EndLine != 2 {
			t.Fatalf("%s: rule %+v", op, e)
		}
		if (op == dependencyOperator) != (e.Dependency != nil) {
			t.Fatalf("%s: dependency %+v", op, e.Dependency)
		}
		files, err := CodeFiles(toyExtractor{})
		if err != nil {
			t.Fatal(err)
		}
		if e.Evidence.Extractor.CodeDigest != extract.CodeDigest(files) || !slices.Equal(out.Manifest.CodeFiles, files) {
			t.Fatalf("%s: code digest %s", op, e.Evidence.Extractor.CodeDigest)
		}
	}
}

func TestRunRefusesUnprovenCitationsAndOtherOperators(t *testing.T) {
	root := toyFixture(t)
	for name, x := range map[string]toyExtractor{
		"cites a file it did not read": {op: constraintengine.OperatorRequireSetMember, cite: "other.yaml"},
		"operator without vectors":     {op: "forbid_predicate_value"},
	} {
		if _, err := runToy(t, x, root); err == nil {
			t.Fatalf("%s: run succeeded", name)
		}
	}
	out, err := runToy(t, toyExtractor{op: dependencyOperator, withhold: true}, root)
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Entries) != 0 || out.Manifest.Totals.Withheld != 1 || out.Manifest.Pairs[0].Status != extract.PairWithheld || out.Manifest.Pairs[0].Attestation != nil {
		t.Fatalf("manifest %+v", out.Manifest)
	}
}

func TestOutputIsReproducibleAndVerifyDetectsEveryChange(t *testing.T) {
	root := toyFixture(t)
	x := toyExtractor{op: constraintengine.OperatorRequireSetMember}
	a, err := runToy(t, x, root)
	if err != nil {
		t.Fatal(err)
	}
	b, err := runToy(t, x, root)
	if err != nil {
		t.Fatal(err)
	}
	fa, _ := a.Files()
	fb, _ := b.Files()
	if len(fa) != 4 || len(fa) != len(fb) {
		t.Fatalf("file sets %d %d", len(fa), len(fb))
	}
	for name := range fa {
		if string(fa[name]) != string(fb[name]) {
			t.Fatalf("%s differs between runs", name)
		}
	}
	dir := filepath.Join(t.TempDir(), "out")
	if err := safefs.WriteTree(dir, fa); err != nil {
		t.Fatal(err)
	}
	if _, err := extract.ReadManifest(dir); err != nil {
		t.Fatal(err)
	}
	fr := extract.FixtureReader{Root: root}
	problems, err := Verify(context.Background(), x, fr, fr, dir, nil)
	if err != nil || len(problems) != 0 {
		t.Fatalf("verify: %v %v", err, problems)
	}
	problems, err = Verify(context.Background(), toyExtractor{op: x.op, src: "// v2\n"}, fr, fr, dir, nil)
	if err != nil || !slices.ContainsFunc(problems, func(p string) bool { return strings.HasPrefix(p, "extractor identity differs") }) {
		t.Fatalf("other build: %v %v", problems, err)
	}
	if err := os.WriteFile(filepath.Join(dir, "extra.json"), []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(dir, extract.DirReads, testNext+".tsv")); err != nil {
		t.Fatal(err)
	}
	problems, err = Verify(context.Background(), x, fr, fr, dir, nil)
	if err != nil || !slices.Contains(problems, "extra.json: not produced by the re-derivation") || !slices.Contains(problems, extract.DirReads+"/"+testNext+".tsv: missing") {
		t.Fatalf("tampered: %v %v", problems, err)
	}
}

// A registered chart extractor is refused by extract.Run and extract.Verify
// before anything is read, and unwraps to itself.
func TestRegisteredChartExtractorIsRefusedByTheFramework(t *testing.T) {
	root := toyFixture(t)
	repo, _ := extract.ParseRepo(testRepo)
	x := toyExtractor{op: dependencyOperator}
	reg := Register(x)
	if got, ok := Unwrap(reg); !ok || got != Extractor(x) {
		t.Fatal("unwrap")
	}
	if _, ok := Unwrap(nil); ok {
		t.Fatal("unwrap of nil")
	}
	if reg.ID() != x.ID() || reg.Version() != x.Version() {
		t.Fatal("identity")
	}
	if dir, _ := reg.(extract.CodeSource).SourceFiles(); dir != "toy" {
		t.Fatalf("source dir %s", dir)
	}
	fr := extract.FixtureReader{Root: root}
	counting := &countingReader{inner: fr}
	if _, err := extract.Run(context.Background(), reg, fr, counting, extract.Options{Repo: repo, DerivedAt: toyTime}); err == nil {
		t.Fatal("extract.Run accepted a chart extractor")
	}
	if counting.n != 0 {
		t.Fatalf("extract.Run read %d files", counting.n)
	}
	if _, err := reg.Extract(context.Background(), fr, extract.VersionPair{}); err == nil || len(reg.Pairs(extract.ReleaseIndex{Repo: repo})) != 0 {
		t.Fatal("registered extractor extracts")
	}
}

type countingReader struct {
	inner extract.PinnedReader
	n     int
}

func (c *countingReader) Read(repo extract.RepoRef, commit, p string) ([]byte, error) {
	c.n++
	return c.inner.Read(repo, commit, p)
}

func (c *countingReader) List(repo extract.RepoRef, commit, dir string) ([]extract.TreeEntry, error) {
	c.n++
	return c.inner.List(repo, commit, dir)
}

// The digest covers every non-test Go file of this package with its bytes
// on disk, next to the framework's and the extractor's own.
func TestCodeFilesCoverThisPackageOnDisk(t *testing.T) {
	files, err := CodeFiles(toyExtractor{})
	if err != nil {
		t.Fatal(err)
	}
	covered := map[string]string{}
	for _, f := range files {
		covered[f.Path] = f.SHA256
	}
	if _, ok := covered["toy/toy.go"]; !ok {
		t.Fatal("extractor's own file not covered")
	}
	fw, err := extract.CodeFiles(extract.FrameworkSource())
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range fw {
		if covered[f.Path] != f.SHA256 {
			t.Fatalf("framework file %s not covered", f.Path)
		}
	}
	goFiles, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, f := range goFiles {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		n++
		data, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(data)
		if covered[path.Join(SourceDir, f)] != hex.EncodeToString(sum[:]) {
			t.Fatalf("%s is not covered with its bytes on disk", f)
		}
	}
	if len(files) != len(fw)+n+1 {
		t.Fatalf("digest covers %d files, want %d", len(files), len(fw)+n+1)
	}
}
