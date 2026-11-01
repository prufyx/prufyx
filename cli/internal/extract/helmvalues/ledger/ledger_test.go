// SPDX-License-Identifier: AGPL-3.0-only

package ledger_test

import (
	"bytes"
	"context"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"math/rand"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/extract"
	"github.com/prufyx/prufyx/cli/internal/extract/helmvalues"
	"github.com/prufyx/prufyx/cli/internal/extract/helmvalues/internal/memchart"
	"github.com/prufyx/prufyx/cli/internal/extract/helmvalues/ledger"
)

const (
	c0 = "0000000000000000000000000000000000a90000"
	c1 = "0000000000000000000000000000000000a91000"
)

const closedA = `{"type":"object","properties":{"a":{"type":"object","additionalProperties":false,"properties":{"keep":{}}}}}`

func kedaTarget(t *testing.T) helmvalues.Target {
	t.Helper()
	for _, tg := range helmvalues.Targets {
		if tg.Project == "keda" {
			return tg
		}
	}
	t.Fatal("no keda target")
	return helmvalues.Target{}
}

// chart is the files of a chart directory, by path inside it.
type chart map[string]string

func baseChart(version, values, schema string) chart {
	c := chart{
		"Chart.yaml":  "apiVersion: v2\nname: keda\nversion: " + version + "\n",
		"values.yaml": values,
	}
	if schema != "" {
		c["values.schema.json"] = schema
	}
	return c
}

func put(r *memchart.Repo, commit string, c chart) {
	for p, content := range c {
		r.Put(commit, "keda/"+p, content)
	}
}

// proofOf runs one pair and returns the extractor's proof, withheld or not.
func proofOf(t *testing.T, r *memchart.Repo) (*helmvalues.PairProof, bool) {
	t.Helper()
	tg := kedaTarget(t)
	repo, err := extract.ParseRepo(tg.Repo)
	if err != nil {
		t.Fatal(err)
	}
	pair := extract.VersionPair{Repo: repo, From: "90.0.0", FromTag: "v90.0.0", FromCommit: c0, To: "90.1.0", ToTag: "v90.1.0", ToCommit: c1}
	got, err := helmvalues.New(tg).Extract(context.Background(), r, pair)
	if w, ok := extract.IsWithheld(err); ok {
		return w.Proof.(*helmvalues.PairProof), true
	}
	if err != nil {
		t.Fatal(err)
	}
	return got.Proof.(*helmvalues.PairProof), false
}

func manyKeys(n int, prefix string) string {
	var b strings.Builder
	for i := 0; i < n; i++ {
		fmt.Fprintf(&b, "%s%c%c: 1\n", prefix, 'a'+i%26, 'a'+i/26)
	}
	return b.String()
}

func deepTemplate() string {
	return "templates" + strings.Repeat("/d", 17) + "/x.yaml"
}

// Every refusal reason the ledger can name is reached by a real run of the
// extractor, and no refusal falls into the unclassified bucket.
func TestEveryReasonIsReachable(t *testing.T) {
	good := func() chart { return baseChart("90.1.0", "a: {keep: 1}\n", closedA) }
	from := func() chart { return baseChart("90.0.0", "a: {keep: 1, gone: 2}\n", "") }
	longKey := strings.Repeat("g.", 63)
	tests := []struct {
		name   string
		to     func() chart
		from   func() chart
		scope  ledger.Scope
		reason ledger.Reason
		key    string // "" matches any key
	}{
		{"chart dir missing", func() chart { return chart{} }, from, ledger.ScopePair, ledger.ChartDirMissing, ""},
		{"Chart.yaml is a directory", func() chart { c := good(); delete(c, "Chart.yaml"); c["Chart.yaml/x"] = "x"; return c }, from, ledger.ScopePair, ledger.ChartYAMLNotFile, ""},
		{"Chart.yaml invalid", func() chart { c := good(); c["Chart.yaml"] = "name: [\n"; return c }, from, ledger.ScopePair, ledger.ChartYAMLInvalid, ""},
		{"chart name differs", func() chart { c := good(); c["Chart.yaml"] = "name: other\nversion: 90.1.0\n"; return c }, from, ledger.ScopePair, ledger.ChartNameMismatch, ""},
		{"chart version differs", func() chart { c := good(); c["Chart.yaml"] = "name: keda\nversion: 90.9.9\n"; return c }, from, ledger.ScopePair, ledger.ChartVersionMismatch, ""},
		{"values.yaml missing", func() chart { c := good(); delete(c, "values.yaml"); return c }, from, ledger.ScopePair, ledger.ValuesNotFile, ""},
		{"values.yaml with an anchor", func() chart { c := good(); c["values.yaml"] = "a: &x {b: 1}\nc: *x\n"; return c }, from, ledger.ScopePair, ledger.ValuesOutsideSubset, ""},
		{"values.yaml is a list", func() chart { c := good(); c["values.yaml"] = "- 1\n"; return c }, from, ledger.ScopePair, ledger.ValuesNotMapping, ""},
		{"schema is a directory", func() chart { c := good(); delete(c, "values.schema.json"); c["values.schema.json/x"] = "x"; return c }, from, ledger.ScopePair, ledger.SchemaNotFile, ""},
		{"schema invalid", func() chart { c := good(); c["values.schema.json"] = "{"; return c }, from, ledger.ScopePair, ledger.SchemaInvalid, ""},
		{"requirements.yaml invalid", func() chart { c := good(); c["requirements.yaml"] = "dependencies: 5\n"; return c }, from, ledger.ScopePair, ledger.RequirementsInvalid, ""},
		{"requirements.yaml is a directory", func() chart { c := good(); c["requirements.yaml/x"] = "x"; return c }, from, ledger.ScopePair, ledger.RequirementsNotFile, ""},
		{"templates nest too deep", func() chart { c := good(); c[deepTemplate()] = "x: 1\n"; return c }, from, ledger.ScopePair, ledger.TemplatesOverBound, ""},
		{"template is a symbolic link", func() chart { return good() }, from, ledger.ScopeTemplates, ledger.TemplateNotScanned, "templates/link.yaml"},
		{"removed key under an opaque schema", func() chart {
			c := good()
			c["values.schema.json"] = `{"properties":{"a":{"$ref":"#/definitions/x","additionalProperties":false,"properties":{"keep":{}}}}}`
			return c
		}, from, ledger.ScopeRemoved, ledger.SchemaOpaque, "a.gone"},
		{"removed key under global", func() chart {
			c := good()
			c["values.schema.json"] = `{"additionalProperties":false,"properties":{"a":{}}}`
			return c
		},
			func() chart { return baseChart("90.0.0", "global: {x: 1}\n", "") }, ledger.ScopeRemoved, ledger.SubchartKey, "global"},
		{"removed key beside a packaged subchart", func() chart { c := good(); c["charts/other-1.0.0.tgz"] = "x"; return c }, from, ledger.ScopeRemoved, ledger.PackagedSubchart, "a.gone"},
		{"removed key that cannot be a member", func() chart { return good() },
			func() chart { return baseChart("90.0.0", "a: {keep: 1, \""+longKey+"\": 2}\n", "") }, ledger.ScopeRemoved, ledger.MemberUnexpressible, ""},
		{"removed keys over the member bound", func() chart { return good() },
			func() chart { return baseChart("90.0.0", "a:\n  keep: 1\n"+indent(manyKeys(65, "g")), "") }, ledger.ScopeRemoved, ledger.MemberOverBound, ""},
		{"required key under an opaque schema", func() chart { c := good(); c["values.schema.json"] = `{"required":["a"],"if":{}}`; return c }, from, ledger.ScopeRequired, ledger.SchemaOpaque, "(root)"},
		{"required key of a subchart", func() chart {
			c := good()
			c["Chart.yaml"] += "dependencies:\n  - name: dep\n    version: 1.0.0\n"
			c["values.schema.json"] = `{"properties":{"dep":{"type":"object","required":["b"]}}}`
			c["values.yaml"] = "dep: {x: 1}\n"
			return c
		}, from, ledger.ScopeRequired, ledger.SubchartKey, "dep.b"},
		{"required key that cannot be a member", func() chart { c := good(); c["values.schema.json"] = `{"required":["` + longKey + `"]}`; return c }, from, ledger.ScopeRequired, ledger.MemberUnexpressible, ""},
		{"required keys over the member bound", func() chart {
			c := good()
			var req []string
			for i := 0; i < 65; i++ {
				req = append(req, fmt.Sprintf("%q", fmt.Sprintf("k%c%c", 'a'+i%26, 'a'+i/26)))
			}
			c["values.schema.json"] = `{"required":[` + strings.Join(req, ",") + `]}`
			return c
		}, from, ledger.ScopeRequired, ledger.MemberOverBound, ""},
		{"unread notice, later chart has no templates", func() chart { return good() },
			func() chart { c := from(); c["templates/d.yaml"] = "x: {{ .Values.a.gone }}\n"; return c }, ledger.ScopeUnread, ledger.NoticeUnproven, "a.gone"},
		{"unread notice, later schema names the key", func() chart {
			c := good()
			c["templates/d.yaml"] = "kind: X\n"
			c["values.schema.json"] = `{"properties":{"a":{"type":"object","properties":{"gone":{}}}}}`
			return c
		}, func() chart { c := from(); c["templates/d.yaml"] = "x: {{ .Values.a.gone }}\n"; return c }, ledger.ScopeUnread, ledger.NoticeSchemaNamed, "a.gone"},
		{"changed default with an ambiguous reading", func() chart { return baseChart("90.1.0", "a: {v: \"no\"}\n", "") },
			func() chart { return baseChart("90.0.0", "a: {v: \"yes\"}\n", "") }, ledger.ScopeChanged, ledger.NoticeAmbiguousScalar, "a.v"},
		{"changed default the later schema refuses", func() chart {
			return baseChart("90.1.0", "a: {v: 2}\n", `{"properties":{"a":{"type":"object","additionalProperties":false,"properties":{"w":{}}}}}`)
		}, func() chart { return baseChart("90.0.0", "a: {v: 1}\n", "") }, ledger.ScopeChanged, ledger.NoticeSchemaNamed, "a.v"},
	}
	reached := map[ledger.Reason]bool{}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := memchart.New()
			put(r, c0, tc.from())
			put(r, c1, tc.to())
			if tc.name == "template is a symbolic link" {
				r.PutMode(c1, "keda/templates/link.yaml", "../elsewhere", "120000")
			}
			proof, withheld := proofOf(t, r)
			if withheld != (tc.scope == ledger.ScopePair) {
				t.Fatalf("withheld=%v for scope %s", withheld, tc.scope)
			}
			entries := ledger.Collect("90.0.0->90.1.0", proof)
			found := false
			for _, e := range entries {
				if e.Reason == ledger.UnclassifiedProblem {
					t.Errorf("unclassified refusal: %+v", e)
				}
				if e.Scope == tc.scope && e.Reason == tc.reason && (tc.key == "" || e.Key == tc.key) {
					found = true
					reached[e.Reason] = true
				}
			}
			if !found {
				t.Fatalf("no %s/%s entry (key %q) in %+v", tc.scope, tc.reason, tc.key, entries)
			}
		})
	}
	for _, r := range ledger.All() {
		if r != ledger.UnclassifiedProblem && r != ledger.UnclassifiedKey && !reached[r] {
			t.Errorf("reason %s is never reached by a case", r)
		}
	}
}

func indent(s string) string {
	return "  " + strings.ReplaceAll(strings.TrimRight(s, "\n"), "\n", "\n  ") + "\n"
}

// A problem the ledger has no name for is listed, not dropped.
func TestUnknownProblemIsListed(t *testing.T) {
	p := &helmvalues.PairProof{From: &helmvalues.SideRecord{Tag: "v1.0.0", Problem: "something new"}}
	got := ledger.Collect("1.0.0->1.1.0", p)
	if len(got) != 1 || got[0].Reason != ledger.UnclassifiedProblem || got[0].Scope != ledger.ScopePair {
		t.Fatalf("got %+v", got)
	}
	if ledger.Collect("x", nil) != nil {
		t.Fatal("a nil proof lists a refusal")
	}
}

// Decisions are not refusals: a rejected key, a key still defaulted and a
// key the earlier schema already refused stay out of the ledger.
func TestDecisionsAreNotRefusals(t *testing.T) {
	r := memchart.New()
	put(r, c0, baseChart("90.0.0", "a: {keep: 1, gone: 2, kept: 3}\n", ""))
	put(r, c1, baseChart("90.1.0", "a: {keep: 1, kept: 3}\n", `{"properties":{"a":{"type":"object","additionalProperties":false,"properties":{"keep":{},"kept":{}}}}}`))
	proof, withheld := proofOf(t, r)
	if withheld {
		t.Fatal("withheld")
	}
	if got := ledger.Collect("p", proof); len(got) != 0 {
		t.Fatalf("got %+v", got)
	}
	if proof.Removed.Counts[helmvalues.ClassRejected] != 1 {
		t.Fatalf("rejected %+v", proof.Removed.Counts)
	}
}

// The ledger is the same bytes whatever order the entries arrive in, drops
// duplicates and never renders a null list.
func TestDeterministic(t *testing.T) {
	var entries []ledger.Entry
	for i := 0; i < 40; i++ {
		entries = append(entries, ledger.Entry{Pair: fmt.Sprintf("p%d", i%3), Scope: ledger.ScopeRemoved, Key: fmt.Sprintf("k%d", i%7), Reason: ledger.SchemaOpaque})
	}
	want, err := ledger.New(entries).JSON()
	if err != nil {
		t.Fatal(err)
	}
	rng := rand.New(rand.NewSource(1))
	for i := 0; i < 20; i++ {
		rng.Shuffle(len(entries), func(a, b int) { entries[a], entries[b] = entries[b], entries[a] })
		got, _ := ledger.New(entries[:20], entries[20:]).JSON()
		if !bytes.Equal(got, want) {
			t.Fatalf("shuffle %d changed the bytes", i)
		}
	}
	l := ledger.New(entries)
	if len(l.Entries) != 21 || l.Counts()["removed/schema-opaque"] != 21 {
		t.Fatalf("%d entries, counts %v", len(l.Entries), l.Counts())
	}
	empty, _ := ledger.New().JSON()
	if !bytes.Contains(empty, []byte(`"entries": []`)) {
		t.Fatalf("empty ledger: %s", empty)
	}
}

// A stored (JSON) proof gives the same entries as the live one.
func TestFromAny(t *testing.T) {
	r := memchart.New()
	put(r, c0, baseChart("90.0.0", "a: {keep: 1}\n", ""))
	put(r, c1, chart{"Chart.yaml": "name: keda\nversion: 90.1.0\n"})
	proof, withheld := proofOf(t, r)
	if !withheld {
		t.Fatal("not withheld")
	}
	live := ledger.Collect("p", proof)
	stored, err := ledger.FromAny("p", map[string]any{"from": map[string]any{"tag": "v90.0.0"}, "to": map[string]any{"tag": "v90.1.0", "problem": proof.To.Problem}})
	if err != nil {
		t.Fatal(err)
	}
	if len(live) != 1 || len(stored) != 1 || live[0].Reason != stored[0].Reason || stored[0].Reason != ledger.ValuesNotFile {
		t.Fatalf("live %+v stored %+v", live, stored)
	}
}

// A read problem is matched on its exact wording. Text that only mentions
// a wording, or carries one after other text, is not classified by it.
func TestProblemWordingsAreAnchored(t *testing.T) {
	for _, tc := range []struct {
		problem string
		want    ledger.Reason
	}{
		{"the chart directory keda does not exist", ledger.ChartDirMissing},
		{"keda/Chart.yaml is not a file", ledger.ChartYAMLNotFile},
		{"keda/values.yaml is not a file", ledger.ValuesNotFile},
		{"keda/values.schema.json is not a file", ledger.SchemaNotFile},
		{"requirements.yaml is not a file", ledger.RequirementsNotFile},
		{"keda/values.yaml is not a mapping", ledger.ValuesNotMapping},
		{`keda/Chart.yaml names chart "x", not "keda"`, ledger.ChartNameMismatch},
		{"keda/Chart.yaml declares version 1.0.0, the tag names 1.1.0", ledger.ChartVersionMismatch},
		{"keda/Chart.yaml: anything", ledger.ChartYAMLInvalid},
		{"keda/values.yaml: anything", ledger.ValuesOutsideSubset},
		{"keda/values.schema.json: anything", ledger.SchemaInvalid},
		{"requirements.yaml: anything", ledger.RequirementsInvalid},
		{"templates: anything", ledger.TemplatesOverBound},
		// look-alikes
		{"see the chart directory keda does not exist", ledger.UnclassifiedProblem},
		{"keda/Chart.yaml: keda/values.yaml is not a file", ledger.ChartYAMLInvalid},
		{"note: Chart.yaml is not a file", ledger.UnclassifiedProblem},
		{"keda/values.yaml is not a file at all", ledger.UnclassifiedProblem},
		{"x names chart", ledger.UnclassifiedProblem},
		{"the templates: dir", ledger.UnclassifiedProblem},
	} {
		got := ledger.Collect("p", &helmvalues.PairProof{From: &helmvalues.SideRecord{Tag: "v1", Problem: tc.problem}})
		if len(got) != 1 || got[0].Reason != tc.want {
			t.Errorf("%q: %+v, want %s", tc.problem, got, tc.want)
		}
	}
}

// Detail never echoes a read error, which can quote file content, and is
// bounded.
func TestDetailEchoesNoFileContent(t *testing.T) {
	r := memchart.New()
	put(r, c0, baseChart("90.0.0", "a: 1\n", ""))
	c := baseChart("90.1.0", "a: {b: 1\nsecretish-canary: [\n", "")
	put(r, c1, c)
	proof, withheld := proofOf(t, r)
	if !withheld {
		t.Fatal("not withheld")
	}
	for _, e := range ledger.Collect("p", proof) {
		if strings.Contains(e.Detail, "canary") || len([]rune(e.Detail)) > 96 {
			t.Errorf("detail %q", e.Detail)
		}
	}
	long := &helmvalues.PairProof{Required: &helmvalues.RequiredRecord{Opaque: []helmvalues.OpaqueNode{{Path: "a", Reason: strings.Repeat("x", 500)}}}}
	if got := ledger.Collect("p", long); len(got) != 1 || len([]rune(got[0].Detail)) != 96 {
		t.Fatalf("%+v", got)
	}
}

// A key class nobody placed is listed, and every Class constant of the
// extractor is placed as a decision or a refusal.
func TestEveryKeyClassIsPlaced(t *testing.T) {
	proof := &helmvalues.PairProof{Removed: &helmvalues.RemovedRecord{Keys: []helmvalues.KeyClass{{Path: "a", Class: "brand-new"}}}}
	if got := ledger.Collect("p", proof); len(got) != 1 || got[0].Reason != ledger.UnclassifiedKey {
		t.Fatalf("got %+v", got)
	}
	fset := token.NewFileSet()
	entries, err := os.ReadDir("..")
	if err != nil {
		t.Fatal(err)
	}
	var files []*ast.File
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, filepath.Join("..", e.Name()), nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, f)
	}
	n := 0
	{
		for _, f := range files {
			for _, d := range f.Decls {
				gd, ok := d.(*ast.GenDecl)
				if !ok || gd.Tok != token.CONST {
					continue
				}
				for _, sp := range gd.Specs {
					vs := sp.(*ast.ValueSpec)
					for i, name := range vs.Names {
						if !strings.HasPrefix(name.Name, "Class") || i >= len(vs.Values) {
							continue
						}
						lit, ok := vs.Values[i].(*ast.BasicLit)
						if !ok {
							continue
						}
						v, _ := strconv.Unquote(lit.Value)
						n++
						if !ledger.KnownClass(v) {
							t.Errorf("%s (%q) is neither a decision nor a refusal in the ledger", name.Name, v)
						}
					}
				}
			}
		}
	}
	if n < 20 {
		t.Fatalf("found %d Class constants; the walk is wrong", n)
	}
}
