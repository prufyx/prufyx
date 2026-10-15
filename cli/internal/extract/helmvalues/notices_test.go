// SPDX-License-Identifier: AGPL-3.0-only

package helmvalues

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/constraintengine"
	"github.com/prufyx/prufyx/cli/internal/extract"
	"github.com/prufyx/prufyx/cli/internal/extract/chartrun"
)

func scanned(files map[string]string) TemplateRefs {
	var r TemplateRefs
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		r.scanTemplate(n, []byte(files[n]))
	}
	r.finish()
	return r
}

func TestTemplateCounters(t *testing.T) {
	for _, tc := range []struct {
		text                          string
		dynamic, whole, tpl, indirect int
		paths                         []string
	}{
		{text: `{{ .Values.a.b }}{{ $.Values.c }}`, paths: []string{"a.b", "c"}},
		{text: `{{ index .Values "a" }}`, dynamic: 1, whole: 1},
		{text: `{{ toYaml .Values }}{{ $.Values }}`, whole: 2},
		{text: `{{ range .Values }}{{ end }}`, whole: 1},
		{text: `{{ tpl .Values.a $ }}`, tpl: 1, indirect: 1, paths: []string{"a"}},
		{text: `{{ $root := . }}{{ $root.Values.a }}`, indirect: 2},
		{text: `{{ $x := $ }}`, indirect: 1},
		{text: `{{ include "x" (dict "ctx" .) }}`, indirect: 1},
		{text: `{{ get $ "Values" }}`, indirect: 2},
		{text: `{{ (.Chart).Values }}`, indirect: 1},
		{text: `{{ range . }}{{ end }}`, indirect: 1},
		{text: `{{ include "x" . }}{{ template "y" . }}{{ template "z" $ }}{{ if . }}{{ end }}{{ with $ }}{{ .Values.a }}{{ end }}`, paths: []string{"a"}},
		{text: `{{ with .Values.a }}{{ toYaml . }}{{ .b }}{{ end }}{{ range $k, $v := .Values.m }}{{ $v.x }}{{ . }}{{ end }}`, paths: []string{"a", "m"}},
		{text: `{{ with .Values.a }}{{ else }}{{ toYaml . }}{{ end }}`, indirect: 1, paths: []string{"a"}},
		{text: `{{ define "h" }}{{ .Values.d }}{{ toYaml . }}{{ end }}`, indirect: 1, paths: []string{"d"}},
		{text: `{{ default (index .Values.a "b") .Values.c }}`, dynamic: 1, paths: []string{"a", "c"}},
	} {
		r := scanned(map[string]string{"t.yaml": tc.text})
		if len(r.Refused) != 0 || r.Dynamic != tc.dynamic || r.WholeValues != tc.whole || r.Tpl != tc.tpl || r.Indirect != tc.indirect || !slices.Equal(r.Paths, append([]string{}, tc.paths...)) {
			t.Errorf("%s: %+v", tc.text, r)
		}
	}
}

const earlierTemplates = `{{ .Values.a.b }}{{ .Values.c }}{{ .Values.d }}{{ .Values.global.g }}{{ .Values.sub.s }}`

func unreadOf(t *testing.T, to *side) (*NoticeRecord, *chartrun.Candidate) {
	t.Helper()
	from := &side{templatesDir: true, subcharts: []string{"sub"}, templates: scanned(map[string]string{"old.yaml": earlierTemplates})}
	x := New(target(t, "keda"))
	repo, _ := extract.ParseRepo(x.target.Repo)
	return x.unread(extract.VersionPair{Repo: repo, From: "1.0.0", To: "1.1.0", FromCommit: c0, ToCommit: c1}, from, to)
}

func laterSide(text string) *side {
	return &side{templatesDir: true, templates: scanned(map[string]string{"new.yaml": text})}
}

// A key the earlier templates name is a member only when the later
// templates provably do not read it: any unresolved route, a refused file,
// a dependency or a charts directory leaves every key unproven.
func TestUnreadSuppression(t *testing.T) {
	rec, c := unreadOf(t, laterSide(`{{ .Values.c }}{{ include "x" . }}{{ define "x" }}{{ with .Values.e }}{{ toYaml . }}{{ end }}{{ end }}`))
	if c == nil || !slices.Equal(c.Rule.SetCondition.Members, []string{"a.b", "d"}) || c.Rule.Operator != constraintengine.OperatorNoticeSetMemberPresent || c.Rule.ReasonCode != ReasonUnread {
		t.Fatalf("clean later templates: %+v %+v", rec, c)
	}
	if classOf(rec.Keys, "global.g") != ClassSubchart || classOf(rec.Keys, "sub.s") != ClassSubchart || classOf(rec.Keys, "a.b") != ClassNotice {
		t.Fatalf("classes %+v", rec.Keys)
	}
	if !constraintengine.ValidNoticeText(c.Rule.ID, c.Rule.NextAction) || len(c.Sources) != 2 || c.Sources[1].Path != "keda/old.yaml" {
		t.Fatalf("candidate %+v", c)
	}

	// The scan keeps a key when the later templates name it, a key above
	// it or a key below it.
	_, c = unreadOf(t, laterSide(`{{ with .Values.a }}{{ .b }}{{ end }}{{ .Values.d.x }}`))
	if c == nil || !slices.Equal(c.Rule.SetCondition.Members, []string{"c"}) {
		t.Fatalf("related keys: %+v", c)
	}

	unproven := map[string]*side{
		"index":            laterSide(`{{ index .Values "a" "b" }}`),
		"tpl":              laterSide(`{{ tpl "x" .Values.z }}`),
		"whole values":     laterSide(`{{ toYaml .Values }}`),
		"whole values $":   laterSide(`{{ $.Values | toJson }}`),
		"root variable":    laterSide(`{{ $root := . }}{{ $root.Values.a.b }}`),
		"root in dict":     laterSide(`{{ include "x" (dict "top" $) }}`),
		"string Values":    laterSide(`{{ get .Chart "Values" }}`),
		"range over root":  laterSide(`{{ range $ }}{{ end }}`),
		"refused file":     {templatesDir: true, templates: scanned(map[string]string{"new.yaml": `{{ .Values.c }}`, "bad.txt": `{{ if .Values.x }}`})},
		"no templates dir": {templates: scanned(map[string]string{})},
		"dependency":       {templatesDir: true, subcharts: []string{"lib"}, templates: scanned(map[string]string{"new.yaml": ``})},
		"charts dir":       {templatesDir: true, chartsDir: true, templates: scanned(map[string]string{"new.yaml": ``})},
		"packaged":         {templatesDir: true, opaqueSubcharts: true, templates: scanned(map[string]string{"new.yaml": ``})},
	}
	for name, to := range unproven {
		rec, c := unreadOf(t, to)
		if c != nil || !strings.HasPrefix(rec.Outcome, "no notice: ") {
			t.Errorf("%s: %+v %+v", name, rec, c)
			continue
		}
		for _, k := range rec.Keys {
			if k.Class != ClassUnproven {
				t.Errorf("%s: %+v", name, rec.Keys)
			}
		}
	}

	// A key the later schema names (required, declared, or under an
	// object the walk does not read) is never claimed unread.
	for name, schema := range map[string]string{
		"required below":   `{"type":"object","properties":{"a":{"type":"object","required":["b"]}}}`,
		"declared":         `{"type":"object","properties":{"a":{"type":"object","properties":{"b":{"type":"string"}}},"d":{"type":"string"}}}`,
		"required at root": `{"type":"object","required":["a","d"]}`,
		"opaque":           `{"type":"object","properties":{"a":{"type":"object","allOf":[{}]},"d":{"anyOf":[{}]}}}`,
	} {
		to := laterSide(`{{ .Values.c }}`)
		var err error
		to.schema, err = decodeSchema([]byte(schema))
		must(t, err)
		rec, c := unreadOf(t, to)
		if classOf(rec.Keys, "a.b") != ClassSchema || name != "required below" && classOf(rec.Keys, "d") != ClassSchema {
			t.Errorf("%s: %+v %+v", name, rec.Keys, c)
		}
	}
	to := laterSide(`{{ .Values.c }}`)
	var err error
	to.schema, err = decodeSchema([]byte(`{"type":"object","properties":{"a":{"type":"object","properties":{"other":{"type":"string"}}}}}`))
	must(t, err)
	if _, c := unreadOf(t, to); c == nil || !slices.Equal(c.Rule.SetCondition.Members, []string{"a.b", "d"}) {
		t.Fatalf("undeclared keys under a declared object: %+v", c)
	}

	if rec, c := unreadOf(t, laterSide(earlierTemplates)); c != nil || len(rec.Keys) != 0 {
		t.Fatalf("nothing removed: %+v %+v", rec, c)
	}
}

func changedOf(t *testing.T, from, to *side) (*NoticeRecord, *chartrun.Candidate) {
	t.Helper()
	x := New(target(t, "keda"))
	repo, _ := extract.ParseRepo(x.target.Repo)
	return x.changedDefaults(extract.VersionPair{Repo: repo, From: "1.0.0", To: "1.1.0", FromCommit: c0, ToCommit: c1}, from, to)
}

// Only a scalar every YAML reader reads the same way, under no subchart or
// global key, that neither schema refuses or leaves unread, is a member.
func TestChangedDefaults(t *testing.T) {
	const old = "num: 1\nstr: hello\nflag: true\nyesish: yes\nquoted: \"on\"\nversion: 1.2.3\nfloat: 1.0\nhex: 0x10\nexp: 1e3\nsame: 2\nsub:\n  k: 1\nglobal:\n  k: 1\nclosed:\n  k: 1\nopaque:\n  k: 1\nmap:\n  k: 1\nlist: [1]\nnulled: 1\n"
	const new = "num: 2\nstr: world\nflag: false\nyesish: no\nquoted: \"off\"\nversion: 1.2.4\nfloat: 1\nhex: 16\nexp: 1000\nsame: 2\nsub:\n  k: 2\nglobal:\n  k: 2\nclosed:\n  k: 2\nopaque:\n  k: 2\nmap: 3\nlist: [2]\nnulled: null\n"
	const schema = `{"type":"object","properties":{"closed":{"type":"object","additionalProperties":false,"properties":{"other":{"type":"string"}}},"opaque":{"type":"object","allOf":[{"required":["k"]}]}}}`
	rec, c := changedOf(t, sideOf(t, old, "", "sub"), sideOf(t, new, schema))
	if c == nil || !slices.Equal(c.Rule.SetCondition.Members, []string{"flag", "num", "str"}) || c.Rule.Operator != constraintengine.OperatorNoticeSetMemberAbsent || c.Rule.ReasonCode != ReasonDefaultChanged {
		t.Fatalf("%+v %+v", rec, c)
	}
	for path, want := range map[string]string{
		"num": ClassNotice, "yesish": ClassAmbiguous, "quoted": ClassAmbiguous, "version": ClassAmbiguous,
		"float": ClassSameValue, "hex": ClassAmbiguous, "exp": ClassAmbiguous, "sub.k": ClassSubchart,
		"global.k": ClassSubchart, "closed.k": ClassSchema, "opaque.k": ClassSchema,
		"same": "", "map": "", "list": "", "nulled": "",
	} {
		if got := classOf(rec.Keys, path); got != want {
			t.Errorf("%s: class %q, want %q", path, got, want)
		}
	}
	if !constraintengine.ValidNoticeText(c.Rule.ID, c.Rule.NextAction) || len(c.Sources) != 2 || strings.Contains(c.Rule.NextAction, " from ") {
		t.Fatalf("multi-key candidate %+v", c.Rule)
	}

	_, c = changedOf(t, sideOf(t, "image:\n  pullPolicy: IfNotPresent\n", ""), sideOf(t, "image:\n  pullPolicy: Always\n", ""))
	if c == nil || !strings.Contains(c.Rule.NextAction, `values key image.pullPolicy from "IfNotPresent" to "Always"`) || !constraintengine.ValidNoticeText(c.Rule.ID, c.Rule.NextAction) {
		t.Fatalf("single-key candidate %+v", c)
	}

	opaque := sideOf(t, "a: 2\n", "")
	opaque.opaqueSubcharts = true
	if rec, c := changedOf(t, sideOf(t, "a: 1\n", ""), opaque); c != nil || classOf(rec.Keys, "a") != ClassOpaqueSubcharts {
		t.Fatalf("packaged subchart: %+v %+v", rec, c)
	}
	if rec, c := changedOf(t, sideOf(t, "a: 1\n", ""), sideOf(t, "a: 1\n", "")); c != nil || len(rec.Keys) != 0 {
		t.Fatalf("no change: %+v %+v", rec, c)
	}
}

// provableFixture is a copy of the fixture whose later chart of the first
// pair is provable (no dependency, no charts directory, every template
// parsed), with one scalar default changed.
func provableFixture(t *testing.T) string {
	t.Helper()
	root := copyFixture(t)
	dir := filepath.Join(root, "github.com/kedacore/charts/commits", c1, "keda")
	must(t, os.RemoveAll(filepath.Join(dir, "charts")))
	must(t, os.Remove(filepath.Join(dir, "templates/broken.txt")))
	edit := func(name, old, new string) {
		t.Helper()
		raw, err := os.ReadFile(filepath.Join(dir, name))
		must(t, err)
		edited := strings.Replace(string(raw), old, new, 1)
		if edited == string(raw) {
			t.Fatalf("%s not edited", name)
		}
		must(t, os.WriteFile(filepath.Join(dir, name), []byte(edited), 0o644))
	}
	edit("Chart.yaml", "dependencies:\n  - name: sub\n    version: 1.0.0\n    repository: file://charts/sub\n", "")
	edit("values.yaml", "replicas: 1", "replicas: 3")
	return root
}

// With the fixture's later chart made provable (no dependency, no charts
// directory, every template parsed) and one scalar default changed, the run
// emits both notices; rulecheck admits them, and their vectors agree with
// the engine.
func TestNoticesThroughTheEngine(t *testing.T) {
	out, err := runFixture(t, provableFixture(t))
	must(t, err)
	rules := byID(out)
	unread, ok := rules[prefix01+"unread-values"]
	// auth.enabled is required by the later schema: still part of the
	// chart's interface, never claimed unread.
	if !ok || !slices.Equal(unread.Rule.SetCondition.Members, []string{"operator.legacyFlag"}) {
		t.Fatalf("unread notice %+v", unread.Rule)
	}
	if proof := pairProof(t, out.Manifest.Pairs[0]); classOf(proof.Soft.Unread.Keys, "auth.enabled") != ClassSchema {
		t.Fatalf("unread keys %+v", proof.Soft.Unread.Keys)
	}
	changed, ok := rules[prefix01+"changed-defaults"]
	if !ok || !slices.Equal(changed.Rule.SetCondition.Members, []string{"operator.replicas"}) || !strings.Contains(changed.Rule.NextAction, "from 1 to 3") {
		t.Fatalf("changed notice %+v", changed.Rule)
	}
	for _, e := range []chartrun.Entry{unread, changed} {
		for _, text := range []string{e.Rule.ID, e.Rule.NextAction, e.Description} {
			for _, word := range []string{"safe", "block", "refuse", "must"} {
				if strings.Contains(strings.ToLower(text), word) {
					t.Fatalf("%s: %q holds %q", e.Rule.ID, text, word)
				}
			}
		}
		kinds := map[string]bool{}
		for _, v := range out.Vectors {
			if v.RuleID == e.Rule.ID {
				kinds[v.Kind] = true
				if v.Expect.Status == "PASS" || v.Expect.Status == "BLOCKED" {
					t.Fatalf("notice vector %s expects %s", v.Name, v.Expect.Status)
				}
			}
		}
		if !slices.Equal(sortedKeys(kinds), []string{chartrun.VectorNoNoticeComplete, chartrun.VectorNotice, extract.VectorUnknownIncomplete}) {
			t.Fatalf("%s vector kinds %v", e.Rule.ID, kinds)
		}
	}
	if err := chartrun.CheckVectors(out.Entries, out.Vectors, derivedAt); err != nil {
		t.Fatal(err)
	}
	// The verdict rules of the pair are unchanged by the notices.
	for _, id := range []string{"kube-version", "removed-values", "required-values"} {
		if _, ok := rules[prefix01+id]; !ok {
			t.Fatalf("rule %s missing", id)
		}
	}
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// specialReader lists one extra entry in the later anchor's templates
// directory: a symbolic link (whose blob is the link target) or a
// submodule.
type specialReader struct {
	extract.FixtureReader
	entry extract.TreeEntry
}

func (r specialReader) List(repo extract.RepoRef, commit, dir string) ([]extract.TreeEntry, error) {
	entries, err := r.FixtureReader.List(repo, commit, dir)
	if err == nil && commit == c1 && dir == "keda/templates" {
		entries = append(entries, r.entry)
	}
	return entries, err
}

func (r specialReader) Read(repo extract.RepoRef, commit, p string) ([]byte, error) {
	if commit == c1 && p == r.entry.Path {
		return []byte("deployment.yaml"), nil
	}
	return r.FixtureReader.Read(repo, commit, p)
}

// A symbolic link or a submodule under templates/ is never read as a
// template: it is listed as refused, and no key is claimed unread.
func TestTemplateLinksAndSubmodulesRefuseTheUnreadNotice(t *testing.T) {
	root := provableFixture(t)
	tg := target(t, "keda")
	repo, err := extract.ParseRepo(tg.Repo)
	must(t, err)
	for _, entry := range []extract.TreeEntry{
		{Mode: "120000", Type: "blob", SHA: strings.Repeat("1", 40), Path: "keda/templates/linked.yaml"},
		{Mode: "160000", Type: "commit", SHA: strings.Repeat("2", 40), Path: "keda/templates/vendored"},
		{Mode: "100664", Type: "blob", SHA: strings.Repeat("3", 40), Path: "keda/templates/odd.yaml"},
	} {
		fr := extract.FixtureReader{Root: root}
		out, err := chartrun.Run(context.Background(), New(tg), fr, specialReader{fr, entry}, extract.Options{Repo: repo, DerivedAt: derivedAt})
		must(t, err)
		rules := byID(out)
		if _, ok := rules[prefix01+"unread-values"]; ok {
			t.Fatalf("%s: unread notice derived", entry.Mode)
		}
		if _, ok := rules[prefix01+"changed-defaults"]; !ok {
			t.Fatalf("%s: changed-defaults notice missing", entry.Mode)
		}
		proof := pairProof(t, out.Manifest.Pairs[0])
		if !slices.Contains(proof.To.Templates.Refused, strings.TrimPrefix(entry.Path, "keda/")) || proof.Soft.Unread.Outcome != "no notice: a later template file was not parsed" {
			t.Fatalf("%s: refused %v outcome %q", entry.Mode, proof.To.Templates.Refused, proof.Soft.Unread.Outcome)
		}
	}
}
