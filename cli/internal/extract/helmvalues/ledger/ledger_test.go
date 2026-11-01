// SPDX-License-Identifier: AGPL-3.0-only

package ledger_test

import (
	"bytes"
	"context"
	"fmt"
	"math/rand"
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
		if r != ledger.UnclassifiedProblem && !reached[r] {
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
