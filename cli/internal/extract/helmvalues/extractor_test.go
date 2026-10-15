// SPDX-License-Identifier: AGPL-3.0-only

package helmvalues

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/chartidentity"
	"github.com/prufyx/prufyx/cli/internal/cncfcheck"
	"github.com/prufyx/prufyx/cli/internal/constraintengine"
	"github.com/prufyx/prufyx/cli/internal/extract"
	"github.com/prufyx/prufyx/cli/internal/extract/chartrun"
	"github.com/prufyx/prufyx/cli/internal/extract/safefs"
)

var update = flag.Bool("update", false, "rewrite the golden files")

const (
	fixtureRoot = "testdata/fixture"
	c0          = "0000000000000000000000000000000000a90000"
	c1          = "0000000000000000000000000000000000a91000"
	c2          = "0000000000000000000000000000000000a92000"
	c3          = "0000000000000000000000000000000000a93000"
	prefix01    = "keda.helm-values.keda.90-0-0-to-90-1-0."
)

var derivedAt = time.Date(2026, 10, 11, 0, 0, 0, 0, time.UTC)

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func target(t *testing.T, project string) Target {
	t.Helper()
	for _, tg := range Targets {
		if tg.Project == project {
			return tg
		}
	}
	t.Fatalf("no target %s", project)
	return Target{}
}

func runFixture(t *testing.T, root string) (*chartrun.Output, error) {
	t.Helper()
	tg := target(t, "keda")
	repo, err := extract.ParseRepo(tg.Repo)
	must(t, err)
	fr := extract.FixtureReader{Root: root}
	return chartrun.Run(context.Background(), New(tg), fr, fr, extract.Options{Repo: repo, DerivedAt: derivedAt})
}

func fixtureOutput(t *testing.T) *chartrun.Output {
	t.Helper()
	out, err := runFixture(t, fixtureRoot)
	must(t, err)
	return out
}

func pairProof(t *testing.T, p extract.PairRecord) PairProof {
	t.Helper()
	raw, err := json.Marshal(p.Proof)
	must(t, err)
	var proof PairProof
	must(t, json.Unmarshal(raw, &proof))
	return proof
}

func byID(out *chartrun.Output) map[string]chartrun.Entry {
	m := map[string]chartrun.Entry{}
	for _, e := range out.Entries {
		m[e.Rule.ID] = e
	}
	return m
}

// The fixture's first pair raises the Kubernetes minimum, newly requires two
// keys with no default and closes an object to two keys the earlier values
// set: three rules. The second pair has a kubeVersion without -0 and nothing
// newly required: no rule. The third pair is withheld (a YAML anchor).
func TestFixtureRules(t *testing.T) {
	out := fixtureOutput(t)
	m := out.Manifest
	if len(m.Pairs) != 3 || m.Totals.Derived != 2 || m.Totals.Withheld != 1 || m.Totals.Rules != 3 || m.Totals.Vectors != 9 {
		t.Fatalf("totals %+v", m.Totals)
	}
	first, second, third := m.Pairs[0], m.Pairs[1], m.Pairs[2]
	if first.FromTag != "v90.0.0" || first.ToTag != "v90.1.0" || second.ToTag != "v90.2.0" || third.ToTag != "v90.3.0" {
		t.Fatalf("pairs %+v", m.Pairs)
	}
	if third.Status != extract.PairWithheld || !strings.Contains(third.Reason, "keda/values.yaml") || len(second.Rules) != 0 {
		t.Fatalf("second %+v third %+v", second, third)
	}
	rules := byID(out)
	chart := &constraintengine.ChartRef{Source: "https://kedacore.github.io/charts", Name: "keda"}

	kube := rules[prefix01+"kube-version"]
	if kube.Rule.Operator != "require_component_version" || *kube.Rule.Dependency != (chartrun.Dependency{Side: "proposed", Component: KubernetesComponent, Comparison: "gte", Version: "1.23.0"}) ||
		kube.Rule.Subject.Chart == nil || *kube.Rule.Subject.Chart != *chart || kube.Rule.Subject.From != "90.0.0" || kube.Rule.Subject.To != "90.1.0" || kube.Rule.ReasonCode != ReasonKubeVersion {
		t.Fatalf("kube rule %+v", kube.Rule)
	}
	src := kube.Rule.Evidence.Sources
	if len(src) != 2 || src[0].Revision != c0 || src[1].Revision != c1 || src[1].StartLine != 7 || src[1].EndLine != 7 || !strings.HasSuffix(src[1].URL, "/keda/Chart.yaml") {
		t.Fatalf("kube sources %+v", src)
	}

	req := rules[prefix01+"required-values"]
	if req.Rule.Operator != constraintengine.OperatorRequireSetMember || !slices.Equal(req.Rule.SetCondition.Members, []string{"auth.token", "rootKey"}) ||
		req.Rule.SetCondition.FactID != "component.keda.chart_keda_values_paths_set" || *req.Rule.Subject.Chart != *chart || req.Rule.ReasonCode != ReasonRequired {
		t.Fatalf("required rule %+v", req.Rule)
	}
	rem := rules[prefix01+"removed-values"]
	if rem.Rule.Operator != constraintengine.OperatorForbidSetMember || !slices.Equal(rem.Rule.SetCondition.Members, []string{"operator.legacyFlag", "operator.legacyMap"}) || rem.Rule.ReasonCode != ReasonNotAllowed {
		t.Fatalf("removed rule %+v", rem.Rule)
	}
	for _, e := range out.Entries {
		if len(e.Rule.ID) > 128 || len(e.Rule.NextAction) > 256 {
			t.Fatalf("rule %s shape", e.Rule.ID)
		}
	}

	proof := pairProof(t, first)
	classes := map[string]string{}
	for _, k := range proof.Required.Keys {
		classes[k.Path] = k.Class
	}
	want := map[string]string{"auth.enabled": ClassDefault, "auth.mode": ClassDefault, "auth.token": ClassRule, "emptyObj.k": ClassEmptyAncestor,
		"missing.deep": ClassInactive, "rootKey": ClassRule, "sub.y": ClassSubchart, "weird.bad key": ClassUnexpressible}
	if len(classes) != len(want) {
		t.Fatalf("required classes %v", classes)
	}
	for k, v := range want {
		if classes[k] != v {
			t.Fatalf("required %s: %s, want %s", k, classes[k], v)
		}
	}
	if len(proof.Required.Opaque) != 1 || proof.Required.Opaque[0].Path != "hidden" {
		t.Fatalf("opaque %+v", proof.Required.Opaque)
	}
	if c := proof.Completeness; c.EarlierKeys != c.EarlierKeysClassified || c.EarlierKeys != 12 || c.RequiredKeys != 8 || c.TemplatesRefused != 1 {
		t.Fatalf("completeness %+v", c)
	}
	if !slices.Equal(proof.Soft.DefaultsRemoved, []string{"operator.legacyFlag", "operator.legacyMap"}) || !slices.Equal(proof.Soft.ReferencesRemoved, []string{"auth.enabled", "operator.legacyFlag"}) {
		t.Fatalf("soft %+v", proof.Soft)
	}
	// A later release of a line that does not read is recorded only.
	rel := proof.Lines.From.Releases
	if len(rel) != 2 || !rel[0].Anchor || rel[1].Tag != "v90.0.1" || !strings.Contains(rel[1].Problem, "declares version 90.0.2") {
		t.Fatalf("lines %+v", proof.Lines)
	}
	p2 := pairProof(t, second)
	if !strings.Contains(p2.KubeVersion.Outcome, "no -0 suffix") {
		t.Fatalf("second kube %+v", p2.KubeVersion)
	}
	for _, k := range p2.Required.Keys {
		if k.Class == ClassRule {
			t.Fatalf("second pair: %s still a rule", k.Path)
		}
	}
	if classOf(p2.Required.Keys, "auth.token") != ClassAlready || classOf(p2.Required.Keys, "rootKey") != ClassAlready {
		t.Fatalf("second pair keys %+v", p2.Required.Keys)
	}
}

func classOf(keys []KeyClass, path string) string {
	for _, k := range keys {
		if k.Path == path {
			return k.Class
		}
	}
	return ""
}

// Pairs pair consecutive lines from MinFrom; pre-release tags and tags
// outside the prefix are not releases.
func TestPairs(t *testing.T) {
	tg := target(t, "keda")
	x := New(tg)
	fr := extract.FixtureReader{Root: fixtureRoot}
	repo, _ := extract.ParseRepo(tg.Repo)
	tags, err := fr.Tags(repo)
	must(t, err)
	pairs := x.Pairs(extract.ReleaseIndex{Repo: repo, Tags: tags})
	var got []string
	for _, p := range pairs {
		got = append(got, p.FromTag+"->"+p.ToTag)
	}
	if !slices.Equal(got, []string{"v90.0.0->v90.1.0", "v90.1.0->v90.2.0", "v90.2.0->v90.3.0"}) {
		t.Fatalf("pairs %v", got)
	}
	other := tg
	other.TagPrefix = "helm-chart-"
	if ps := New(other).Pairs(extract.ReleaseIndex{Repo: repo, Tags: tags}); len(ps) != 0 {
		t.Fatalf("prefix ignored: %v", ps)
	}
}

// The proof for a single commit (the inventory pair) reads one side and
// derives nothing.
func TestInventoryPair(t *testing.T) {
	tg := target(t, "keda")
	repo, _ := extract.ParseRepo(tg.Repo)
	fr := extract.FixtureReader{Root: fixtureRoot}
	res, err := New(tg).Extract(context.Background(), fr, extract.VersionPair{Repo: repo, From: "inventory", FromTag: "inventory", FromCommit: c1, To: "inventory", ToTag: "inventory", ToCommit: c1})
	must(t, err)
	p := res.Proof.(*PairProof)
	if len(res.Candidates) != 0 || p.From.Version != "90.1.0" || len(p.From.RequiredKeys) != 8 {
		t.Fatalf("inventory %+v", p.From)
	}
	if _, err := New(tg).Extract(context.Background(), fr, extract.VersionPair{Repo: repo, From: "inventory", FromTag: "inventory", FromCommit: c3, To: "inventory", ToTag: "inventory", ToCommit: c3}); err == nil {
		t.Fatal("unreadable commit not withheld")
	}
}

func TestFixtureGolden(t *testing.T) {
	files, err := fixtureOutput(t).Files()
	must(t, err)
	got := normalize(t, files)
	dir := "testdata/golden"
	if *update {
		_ = os.RemoveAll(dir)
		for name, data := range got {
			p := filepath.Join(dir, filepath.FromSlash(name))
			must(t, os.MkdirAll(filepath.Dir(p), 0o755))
			must(t, os.WriteFile(p, data, 0o644))
		}
	}
	var onDisk, names []string
	_ = filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			rel, _ := filepath.Rel(dir, p)
			onDisk = append(onDisk, filepath.ToSlash(rel))
		}
		return nil
	})
	for name := range got {
		names = append(names, name)
	}
	sort.Strings(names)
	sort.Strings(onDisk)
	if !slices.Equal(names, onDisk) {
		t.Fatalf("golden file set %v, output %v", onDisk, names)
	}
	for _, name := range names {
		want, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(name)))
		must(t, err)
		if !bytes.Equal(want, got[name]) {
			t.Fatalf("%s differs from the golden file (run with -update after a deliberate change, and bump Version)", name)
		}
	}
}

// normalize masks the code digest, which changes with any source edit.
func normalize(t *testing.T, files map[string][]byte) map[string][]byte {
	t.Helper()
	var m map[string]any
	must(t, json.Unmarshal(files[extract.FileManifest], &m))
	code := m["extractor"].(map[string]any)["codeDigest"].(string)
	out := map[string][]byte{}
	for name, data := range files {
		out[name] = bytes.ReplaceAll(data, []byte(code), []byte("sha256:CODE"))
	}
	m["codeFiles"] = []any{}
	m["extractor"].(map[string]any)["codeDigest"] = "sha256:CODE"
	for name := range m["outputs"].(map[string]any) {
		m["outputs"].(map[string]any)[name] = "sha256:OUTPUT"
	}
	raw, err := extract.Canonical(m)
	must(t, err)
	out[extract.FileManifest] = raw
	return out
}

func copyFixture(t *testing.T) string {
	t.Helper()
	dst := t.TempDir()
	must(t, filepath.WalkDir(fixtureRoot, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(fixtureRoot, p)
		if d.IsDir() {
			return os.MkdirAll(filepath.Join(dst, rel), 0o755)
		}
		data, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(dst, rel), data, 0o644)
	}))
	return dst
}

func TestReproducibleAndVerified(t *testing.T) {
	a, err := fixtureOutput(t).Files()
	must(t, err)
	b, err := fixtureOutput(t).Files()
	must(t, err)
	for name := range a {
		if !bytes.Equal(a[name], b[name]) {
			t.Fatalf("%s differs between runs", name)
		}
	}
	tg := target(t, "keda")
	dir := filepath.Join(t.TempDir(), "out")
	must(t, safefs.WriteTree(dir, a))
	verify := func(root string) []string {
		fr := extract.FixtureReader{Root: root}
		problems, err := chartrun.Verify(context.Background(), New(tg), fr, fr, dir, nil)
		must(t, err)
		return problems
	}
	if p := verify(fixtureRoot); len(p) != 0 {
		t.Fatalf("verify: %v", p)
	}
	root := copyFixture(t)
	p := filepath.Join(root, "github.com/kedacore/charts/commits", c1, "keda/values.yaml")
	raw, err := os.ReadFile(p)
	must(t, err)
	must(t, os.WriteFile(p, bytes.Replace(raw, []byte("mode: basic"), []byte("mode: basik"), 1), 0o644))
	if p := verify(root); len(p) == 0 {
		t.Fatal("a changed byte was not detected")
	}
}

// Without the values-path fact every set rule is UNKNOWN: the engine never
// reads absence as compliance.
func TestSetRulesAreUnknownWithoutTheFact(t *testing.T) {
	out := fixtureOutput(t)
	for _, v := range out.Vectors {
		if v.Kind == extract.VectorUnknownIncomplete && v.Expect.Status != "UNKNOWN" {
			t.Fatalf("vector %s expects %s", v.Name, v.Expect.Status)
		}
	}
	for _, e := range out.Entries {
		if e.Rule.SetCondition == nil {
			continue
		}
		doc := map[string]any{"schema": constraintengine.InputSchema, "authority": constraintengine.InputAuthority,
			"current":  map[string]any{"components": []any{map[string]any{"component": e.Rule.Subject.Component, "chart": e.Rule.Subject.Chart, "version": "90.0.0", "facts": []any{}}}},
			"proposed": map[string]any{"components": []any{map[string]any{"component": e.Rule.Subject.Component, "chart": e.Rule.Subject.Chart, "version": "90.1.0", "facts": []any{}}}},
		}
		raw, err := json.Marshal(doc)
		must(t, err)
		vs := []chartrun.Vector{
			{Name: "x/" + extract.VectorBlocked, RuleID: e.Rule.ID, Kind: extract.VectorBlocked, Input: raw, Expect: chartrun.VectorExpect{Status: "UNKNOWN", ReasonCode: "RULE_FACT_UNAVAILABLE"}},
			{Name: "x/" + extract.VectorPassComplete, RuleID: e.Rule.ID, Kind: extract.VectorPassComplete, Input: raw, Expect: chartrun.VectorExpect{Status: "UNKNOWN", ReasonCode: "RULE_FACT_UNAVAILABLE"}},
			{Name: "x/" + extract.VectorUnknownIncomplete, RuleID: e.Rule.ID, Kind: extract.VectorUnknownIncomplete, Input: raw, Expect: chartrun.VectorExpect{Status: "UNKNOWN", ReasonCode: "RULE_FACT_UNAVAILABLE"}},
		}
		if err := chartrun.CheckVectors([]chartrun.Entry{e}, vs, derivedAt); err != nil {
			t.Fatalf("%s: %v", e.Rule.ID, err)
		}
	}
}

func TestKubeVersionGrammar(t *testing.T) {
	for in, want := range map[string]KubeMinimum{
		">=1.25.0-0":           {Minimum: "1.25.0", PreRelease: true, Shape: "minimum"},
		">= 1.25-0":            {Minimum: "1.25.0", PreRelease: true, Shape: "minimum"},
		">=v1.23.0-0":          {Minimum: "1.23.0", PreRelease: true, Shape: "minimum"},
		" >= 1.25 ":            {Minimum: "1.25.0", Shape: "minimum"},
		">= 1":                 {Minimum: "1.0.0", Shape: "minimum"},
		"":                     {Shape: "absent"},
		">=1.25.0-0 <1.30.0-0": {Shape: "other"},
		">=1.20 || >=1.10":     {Shape: "other"},
		"~1.25":                {Shape: "other"},
		"^1.25":                {Shape: "other"},
		"1.25.x":               {Shape: "other"},
		"1.20 - 1.30":          {Shape: "other"},
		"=1.25.0":              {Shape: "other"},
		">1.25.0":              {Shape: "other"},
		">=1.25.0-alpha":       {Shape: "other"},
		">=01.25":              {Shape: "other"},
	} {
		got := parseKubeVersion(in)
		want.Constraint = in
		if got != want {
			t.Errorf("%q: %+v, want %+v", in, got, want)
		}
	}
}

// kubeRule runs the kubeVersion derivation on two Chart.yaml constraints.
func kubeRule(t *testing.T, from, to string) (*KubeRecord, *chartrun.Candidate) {
	t.Helper()
	x := New(target(t, "keda"))
	repo, _ := extract.ParseRepo(x.target.Repo)
	pair := extract.VersionPair{Repo: repo, From: "1.0.0", To: "1.1.0", FromCommit: c0, ToCommit: c1}
	f := &side{meta: chartMeta{KubeVersion: from}, chartYAML: "keda/Chart.yaml"}
	if from != "" {
		f.meta.KubeVersionLine = 3
	}
	g := &side{meta: chartMeta{KubeVersion: to, KubeVersionLine: 4}, chartYAML: "keda/Chart.yaml"}
	return x.kubeVersion(pair, f, g)
}

func TestKubeVersionRule(t *testing.T) {
	for _, tc := range []struct {
		from, to string
		rule     bool
		min      string
	}{
		{"", ">=1.25.0-0", true, "1.25.0"},
		{">=1.20.0-0 <1.30.0", ">=1.25.0-0", true, "1.25.0"}, // an opaque earlier bound counts as none
		{">=1.20.0", ">=1.25.0-0", true, "1.25.0"},
		{">=1.25.0-0", ">=1.25-0", false, ""},
		{">=1.26.0-0", ">=1.25.0-0", false, ""},
		{"", ">=1.25.0", false, ""},
		{"", ">=1.25.0-0 <1.32.0-0", false, ""},
		{">=1.20.0-0", "", false, ""},
		{"", ">=0.0.0-0", false, ""},
	} {
		rec, c := kubeRule(t, tc.from, tc.to)
		if (c != nil) != tc.rule || c != nil && c.Rule.Dependency.Version != tc.min {
			t.Errorf("%q -> %q: %+v %+v", tc.from, tc.to, rec, c)
		}
		if c != nil && tc.from == "" && len(c.Sources) != 1 {
			t.Errorf("%q -> %q: sources %+v", tc.from, tc.to, c.Sources)
		}
	}
}

func sideOf(t *testing.T, values, schema string, deps ...string) *side {
	t.Helper()
	s := &side{subcharts: deps}
	_, v, err := decodeOne([]byte(values))
	must(t, err)
	s.values = v
	if schema != "" {
		s.schema, err = decodeSchema([]byte(schema))
		must(t, err)
	}
	return s
}

func requiredOf(t *testing.T, from, to *side) (*RequiredRecord, *chartrun.Candidate) {
	t.Helper()
	x := New(target(t, "keda"))
	repo, _ := extract.ParseRepo(x.target.Repo)
	return x.required(extract.VersionPair{Repo: repo, From: "1.0.0", To: "1.1.0", FromCommit: c0, ToCommit: c1}, from, to)
}

func TestRequiredKeys(t *testing.T) {
	req := `{"type":"object","properties":{"a":{"type":"object","required":["b"]}}}`
	reqRoot := `{"type":"object","required":["a"]}`
	for _, tc := range []struct {
		name               string
		fromVals, fromSchm string
		toVals, toSchm     string
		members            []string
	}{
		{"new required, no default", "a: {x: 1}\n", "", "a: {x: 1}\n", req, []string{"a.b"}},
		{"null default", "a: {x: 1}\n", "", "a: {x: 1, b: null}\n", req, nil},
		{"non-null default", "a: {x: 1}\n", "", "a: {x: 1, b: 0}\n", req, nil},
		{"false default", "a: {x: 1}\n", "", "a: {x: 1, b: false}\n", req, nil},
		{"required at both, default removed", "a: {x: 1, b: 2}\n", req, "a: {x: 1}\n", req, []string{"a.b"}},
		{"required at both without default", "a: {x: 1}\n", req, "a: {x: 1}\n", req, nil},
		{"ancestor absent", "x: 1\n", "", "x: 1\n", req, nil},
		{"ancestor null", "x: 1\n", "", "a: null\n", req, nil},
		{"ancestor empty", "x: 1\n", "", "a: {}\n", req, nil},
		{"ancestor not a mapping", "x: 1\n", "", "a: [1]\n", req, nil},
		{"root key", "x: 1\n", "", "x: 1\n", reqRoot, []string{"a"}},
		{"global", "x: 1\n", "", "x: 1\n", `{"required":["global"]}`, nil},
		{"opaque ancestor", "a: {x: 1}\n", "", "a: {x: 1}\n", `{"properties":{"a":{"type":"object","required":["b"],"oneOf":[{}]}}}`, nil},
		{"remote ref", "a: {x: 1}\n", "", "a: {x: 1}\n", `{"properties":{"a":{"$ref":"https://example.com/s.json","required":["b"]}}}`, nil},
		{"type array", "a: {x: 1}\n", "", "a: {x: 1}\n", `{"properties":{"a":{"type":["object","null"],"required":["b"]}}}`, nil},
		{"unknown keyword", "a: {x: 1}\n", "", "a: {x: 1}\n", `{"properties":{"a":{"required":["b"],"unevaluatedProperties":false}}}`, nil},
		{"root opaque", "x: 1\n", "", "x: 1\n", `{"required":["a"],"if":{}}`, nil},
		{"no later schema", "x: 1\n", "", "x: 1\n", "", nil},
		{"dotted key", "x: 1\n", "", "x: 1\n", `{"required":["a.b"]}`, nil},
		{"defs allowed at root", "x: 1\n", "", "x: 1\n", `{"$schema":"x","definitions":{"d":{}},"required":["k"]}`, []string{"k"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, c := requiredOf(t, sideOf(t, tc.fromVals, tc.fromSchm), sideOf(t, tc.toVals, tc.toSchm))
			var got []string
			if c != nil {
				got = c.Rule.SetCondition.Members
			}
			if !slices.Equal(got, tc.members) {
				t.Fatalf("members %v, want %v", got, tc.members)
			}
		})
	}
	// A dependency's key is never derived from the parent's files.
	_, c := requiredOf(t, sideOf(t, "x: 1\n", ""), sideOf(t, "dep: {x: 1}\n", `{"properties":{"dep":{"type":"object","required":["b"]}}}`, "dep"))
	if c != nil {
		t.Fatalf("subchart key derived: %v", c.Rule.SetCondition.Members)
	}
	// A packaged subchart of unknown name makes every key opaque.
	packaged := sideOf(t, "a: {x: 1}\n", req)
	packaged.opaqueSubcharts = true
	if _, c := requiredOf(t, sideOf(t, "a: {x: 1}\n", ""), packaged); c != nil {
		t.Fatal("rule derived beside a packaged subchart of unknown name")
	}
}

func TestRequiredMemberBound(t *testing.T) {
	var props, required []string
	for i := 0; i < maxRuleMembers+1; i++ {
		k := "k" + strings.Repeat("x", i%3) + string(rune('a'+i%26)) + string(rune('a'+i/26))
		props = append(props, `"`+k+`":{"type":"string"}`)
		required = append(required, `"`+k+`"`)
	}
	schema := `{"properties":{` + strings.Join(props, ",") + `},"required":[` + strings.Join(required, ",") + `]}`
	rec, c := requiredOf(t, sideOf(t, "x: 1\n", ""), sideOf(t, "x: 1\n", schema))
	if c != nil || !strings.Contains(rec.Outcome, "over the bound") || classOf(rec.Keys, "kaa") != ClassOverBound {
		t.Fatalf("bound: %+v", rec)
	}
}

func removedOf(t *testing.T, from, to *side) (*RemovedRecord, *chartrun.Candidate) {
	t.Helper()
	x := New(target(t, "keda"))
	repo, _ := extract.ParseRepo(x.target.Repo)
	return x.removed(extract.VersionPair{Repo: repo, From: "1.0.0", To: "1.1.0", FromCommit: c0, ToCommit: c1}, from, to)
}

func TestRemovedKeys(t *testing.T) {
	closed := `{"type":"object","properties":{"a":{"type":"object","additionalProperties":false,"properties":{"keep":{}}}}}`
	for _, tc := range []struct {
		name               string
		fromVals, fromSchm string
		toVals, toSchm     string
		members            []string
	}{
		{"closed object drops a key", "a: {keep: 1, gone: 2}\n", "", "a: {keep: 1}\n", closed, []string{"a.gone"}},
		{"shortest prefix", "a: {keep: 1, gone: {deep: {er: 1}}}\n", "", "a: {keep: 1}\n", closed, []string{"a.gone"}},
		{"key from the earlier schema", "x: 1\n", `{"properties":{"a":{"type":"object","properties":{"old":{}}}}}`, "x: 1\n", closed, []string{"a.old"}},
		{"closed root", "a: 1\nb: 2\n", "", "a: 1\n", `{"additionalProperties":false,"properties":{"a":{}}}`, []string{"b"}},
		{"pattern properties", "a: {keep: 1, gone: 2}\n", "", "a: {keep: 1}\n", `{"properties":{"a":{"type":"object","additionalProperties":false,"patternProperties":{"^g":{}},"properties":{"keep":{}}}}}`, nil},
		{"additional properties schema", "a: {keep: 1, gone: 2}\n", "", "a: {keep: 1}\n", `{"properties":{"a":{"type":"object","additionalProperties":{"type":"string"},"properties":{"keep":{}}}}}`, nil},
		{"open object", "a: {keep: 1, gone: 2}\n", "", "a: {keep: 1}\n", `{"properties":{"a":{"type":"object","properties":{"keep":{}}}}}`, nil},
		{"key still defaulted", "a: {keep: 1, gone: 2}\n", "", "a: {keep: 1, gone: 2}\n", closed, nil},
		{"key still defaulted as null", "a: {keep: 1, gone: 2}\n", "", "a: {keep: 1, gone: null}\n", closed, nil},
		{"already refused", "a: {keep: 1, gone: 2}\n", closed, "a: {keep: 1}\n", closed, nil},
		{"null earlier value", "a: {keep: 1, gone: null}\n", "", "a: {keep: 1}\n", closed, nil},
		{"ref on the path", "a: {keep: 1, gone: 2}\n", "", "a: {keep: 1}\n", `{"properties":{"a":{"$ref":"#/definitions/x","additionalProperties":false,"properties":{"keep":{}}}}}`, nil},
		{"combinator on the path", "a: {keep: 1, gone: 2}\n", "", "a: {keep: 1}\n", `{"allOf":[{}],"properties":{"a":{"type":"object","additionalProperties":false,"properties":{"keep":{}}}}}`, nil},
		{"global", "global: {x: 1}\n", "", "x: 1\n", `{"additionalProperties":false,"properties":{"x":{}}}`, nil},
		{"unexpressible key", "a: {keep: 1, \"go.ne\": 2}\n", "", "a: {keep: 1}\n", closed, nil},
		{"no later schema", "a: {gone: 1}\n", "", "x: 1\n", "", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec, c := removedOf(t, sideOf(t, tc.fromVals, tc.fromSchm), sideOf(t, tc.toVals, tc.toSchm))
			var got []string
			if c != nil {
				got = c.Rule.SetCondition.Members
			}
			if !slices.Equal(got, tc.members) {
				t.Fatalf("members %v, want %v (%+v)", got, tc.members, rec)
			}
			n := 0
			for _, v := range rec.Counts {
				n += v
			}
			if n != rec.Candidates {
				t.Fatalf("classified %d of %d", n, rec.Candidates)
			}
		})
	}
}

func TestMemberGrammar(t *testing.T) {
	for _, tc := range []struct {
		path []string
		want string
		ok   bool
	}{
		{[]string{"a", "b"}, "a.b", true},
		{[]string{"A_1", "x-y", "p/q"}, "A_1.x-y.p/q", true},
		{[]string{"_a"}, "", false},
		{[]string{"a", "_b"}, "a._b", true},
		{[]string{"a.b"}, "", false},
		{[]string{"a b"}, "", false},
		{[]string{"ä"}, "", false},
		{[]string{strings.Repeat("a", 129)}, "", false},
		{nil, "", false},
	} {
		got, ok := memberOf(tc.path)
		if got != tc.want || ok != tc.ok {
			t.Errorf("%v: %q %v", tc.path, got, ok)
		}
		if ok {
			if !constraintengine.ValidSetMember(got) {
				t.Errorf("%v: engine refuses %q", tc.path, got)
			}
		}
	}
}

func TestStrictDecoder(t *testing.T) {
	for _, bad := range []string{
		"a: &x 1\nb: *x\n",
		"<<: {a: 1}\n",
		"a: 1\na: 2\n",
		"1: x\n",
		"on: x\n",
		"yes: x\n",
		"~: x\n",
		"a: !custom x\n",
		"a: 1\n---\nb: 2\n",
		"[unclosed\n",
	} {
		if _, _, err := decodeOne([]byte(bad)); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
	for _, good := range []string{"", "---\n", "\"on\": x\n", "a: yes\n", "a: [1, {b: null}]\n"} {
		if _, _, err := decodeOne([]byte(good)); err != nil {
			t.Errorf("refused %q: %v", good, err)
		}
	}
	for _, bad := range []string{`{"a":1,"A":2}`, `{"a":1,"a":2}`, `[1]`, `{} {}`, `true`} {
		if _, err := decodeSchema([]byte(bad)); err == nil {
			t.Errorf("schema %q accepted", bad)
		}
	}
}

func TestChartYAML(t *testing.T) {
	m, err := parseChartYAML([]byte("name: x\nversion: v1.2.3\nkubeVersion: \">=1.20.0-0\"\ndependencies:\n  - name: a\n    alias: b\n  - name: c\n"))
	must(t, err)
	if m.Version != "1.2.3" || m.KubeVersionLine != 3 || !slices.Equal(m.Dependencies, []string{"a", "b", "c"}) {
		t.Fatalf("%+v", m)
	}
	for _, bad := range []string{
		"version: 1.2.3\n",
		"name: x\nversion: 1.2\n",
		"name: x\nversion: 1.2.3-rc.1\n",
		"name: x\nversion: 1.2.3\nkubeVersion: 1\n",
		"name: x\nversion: 1.2.3\ndependencies: x\n",
		"name: x\nversion: 1.2.3\ndependencies:\n  - alias: y\n",
		"- x\n",
	} {
		if _, err := parseChartYAML([]byte(bad)); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
	if !declaredArchive("frr-k8s-0.0.25.tgz", []string{"frr-k8s"}) || declaredArchive("other-1.0.0.tgz", []string{"frr-k8s"}) || declaredArchive("frr-k8s-latest.tgz", []string{"frr-k8s"}) {
		t.Fatal("archive names")
	}
}

func TestTemplateReferences(t *testing.T) {
	var r TemplateRefs
	r.scanTemplate("a.yaml", []byte(`{{ .Values.a.b }}{{ $.Values.c }}{{ with .Values.d }}{{ .e }}{{ end }}{{ range .Values.f }}{{ end }}{{ index .Values "g" }}{{ template "x" .Values.h }}{{/* .Values.comment */}}`))
	r.scanTemplate("b.tpl", []byte(`{{ if .Values.x`))
	r.finish()
	if !slices.Equal(r.Paths, []string{"a.b", "c", "d", "f", "h"}) || !slices.Equal(r.Refused, []string{"b.tpl"}) || r.Dynamic != 1 || r.Files != 2 {
		t.Fatalf("%+v", r)
	}
}

func TestLoadTargets(t *testing.T) {
	valid := string(targetsJSON)
	for name, mutate := range map[string]func(string) string{
		"unknown field": func(s string) string {
			return strings.Replace(s, `"tagPrefix": "v",`, `"tagPrefix": "v", "extra": 1,`, 1)
		},
		"unsorted": func(s string) string { return strings.Replace(s, `"project": "cert-manager"`, `"project": "zz"`, 1) },
		"bad source": func(s string) string {
			return strings.Replace(s, "https://kedacore.github.io/charts", "https://kedacore.github.io/charts/", 1)
		},
		"bad path":     func(s string) string { return strings.Replace(s, `"path": "keda"`, `"path": "../keda"`, 1) },
		"bad line":     func(s string) string { return strings.Replace(s, `"minFrom": "2.15"`, `"minFrom": "2"`, 1) },
		"bad fact":     func(s string) string { return strings.Replace(s, `"factProject": "keda"`, `"factProject": "Keda"`, 1) },
		"wrong schema": func(s string) string { return strings.Replace(s, TargetsSchema, "x", 1) },
		"duplicate chart": func(s string) string {
			return strings.Replace(s, `{"source": "https://metallb.github.io/metallb", "name": "metallb"`, `{"source": "https://kedacore.github.io/charts", "name": "keda"`, 1)
		},
	} {
		mutated := mutate(valid)
		if mutated == valid {
			t.Fatalf("%s: mutation did not apply", name)
		}
		if _, err := LoadTargets([]byte(mutated)); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

// Every target is a catalog project with its catalog component, has an
// active reviewed chart-source row for exactly its chart, and every row is
// a target's: the two tables are reviewed together.
func TestTargetsMatchCatalogAndChartSources(t *testing.T) {
	sources, _, err := chartidentity.LoadEmbedded()
	must(t, err)
	rows := map[string]chartidentity.SourceRecord{}
	for _, r := range sources.Records {
		rows[r.RepoURL+" "+r.Chart] = r
	}
	for _, tg := range Targets {
		comp, err := cncfcheck.Component(tg.Project)
		if err != nil || comp != tg.Component {
			t.Fatalf("%s: catalog component %q, target %q (%v)", tg.Project, comp, tg.Component, err)
		}
		norm, err := chartidentity.NormalizeRepoURL(tg.Chart.Source)
		if err != nil || norm != tg.Chart.Source {
			t.Fatalf("%s: chart source %q is not normalised", tg.Project, tg.Chart.Source)
		}
		r, ok := rows[tg.Chart.Source+" "+tg.Chart.Name]
		if !ok || r.Component != tg.Component || r.Project != tg.Project || r.Evidence.State != chartidentity.StateActive {
			t.Fatalf("%s: chart-source row %+v", tg.Project, r)
		}
		delete(rows, tg.Chart.Source+" "+tg.Chart.Name)
		if !strings.HasPrefix(tg.ExtractorID(), IDPrefix) || len(tg.ExtractorID()) > 128 {
			t.Fatalf("%s: extractor id %s", tg.Project, tg.ExtractorID())
		}
	}
	if len(rows) != 0 {
		t.Fatalf("chart-source rows without a target: %v", rows)
	}
}
