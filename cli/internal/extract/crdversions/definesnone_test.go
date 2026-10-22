// SPDX-License-Identifier: AGPL-3.0-only

package crdversions

import (
	"bytes"
	"fmt"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/extract"
)

const (
	dnFile    = "cmd/data/api.json"
	dnPattern = "cmd/data/*.json"
	// dnEmbed embeds the data directory into a program, as kyverno's CLI
	// embeds its discovery list.
	dnEmbed = "package data\n\nimport _ \"embed\"\n\n//go:embed api.json\nvar API []byte\n"
	// dnDiscovery names the kind as data: a discovery list.
	dnDiscovery = `{"groups":[{"group":"apiextensions.k8s.io","resources":[{"kind":"CustomResourceDefinition","name":"customresourcedefinitions","namespaced":false}]}]}`
)

// definesNone is an entry that declares its files define nothing.
func definesNone(p string) Exclusion {
	return Exclusion{Path: p, Repo: "github.com/argoproj/argo-cd", Reason: "data the CLI embeds for discovery", Evidence: "embedded with //go:embed by cmd/data; a list of API resources, never applied to a cluster", DefinesNone: true}
}

// dnPair runs a pair whose listed definition loses a version (one rule)
// with files under cmd/data/ that a Go package embeds, and the given extra
// files at both releases.
func dnPair(t *testing.T, extra map[string]string, exclude ...Exclusion) (extract.PairRecord, PairProof) {
	t.Helper()
	from := map[string]string{"deploy/crds/a.yaml": crd("Alpha", "v1beta1", "v1"), "cmd/data/data.go": dnEmbed}
	to := map[string]string{"deploy/crds/a.yaml": crd("Alpha", "v1"), "cmd/data/data.go": dnEmbed}
	for p, c := range extra {
		from[p], to[p] = c, c
	}
	return pairOf(t, runSynth(t, synthTarget(exclude...), newSynth(release{"v1.0.0", from}, release{"v1.1.0", to})), "1.0.0", "1.1.0")
}

// findingAt returns the later release's finding for a path.
func findingAt(proof PairProof, p string) (Finding, bool) {
	for _, f := range proof.To.Scan.Findings {
		if f.Path == p && f.Class != ClassVoided {
			return f, true
		}
	}
	return Finding{}, false
}

// A data file that names the kind but defines nothing, under an entry that
// declares so, is no-definition: the pair attests although a Go package
// embeds the file. The same entry without the declaration is void.
func TestDefinesNoneAccepted(t *testing.T) {
	for name, files := range map[string]map[string]string{
		"discovery JSON":           {dnFile: dnDiscovery},
		"YAML ignore list":         {"cmd/data/cfg.yaml": "ignore:\n- kind: CustomResourceDefinition\n  fields: [metadata.annotations]\n- kind: Deployment\n"},
		"a file without the kind":  {dnFile: `{"a":1}`},
		"a kind word in a comment": {"cmd/data/cfg.yaml": "# CustomResourceDefinition is not listed here\nitems: []\n"},
	} {
		t.Run(name, func(t *testing.T) {
			var path string
			for p := range files {
				path = p
			}
			entry := definesNone(path)
			p, proof := dnPair(t, files, entry)
			f, ok := findingAt(proof, path)
			if p.Status != extract.PairDerived || len(p.Rules) != 1 || !proof.Completeness.Attestable || len(voidFindings(proof)) != 0 {
				t.Fatalf("pair %s %q rules %v completeness %+v findings %+v", p.Status, p.Reason, p.Rules, proof.Completeness, proof.To.Scan.Findings)
			}
			if !ok || f.Class != ClassNoDefinition || f.Location != definesNonePrefix+path || !strings.HasPrefix(f.SHA256, "sha256:") {
				t.Fatalf("finding %+v", f)
			}
			if !slices.Contains(proof.To.Scan.Exclusions, definesNonePrefix+path) {
				t.Fatalf("exclusions %v", proof.To.Scan.Exclusions)
			}
		})
	}
	// The guard-skip pairing: the same entry, unchecked, is voided by the
	// embed, so the guard itself is unchanged.
	plain := definesNone(dnFile)
	plain.DefinesNone = false
	_, proof := dnPair(t, map[string]string{dnFile: dnDiscovery}, plain)
	if v := voidFindings(proof); len(v) != 1 || v[0].Path != "cmd/data/data.go" || proof.Completeness.Attestable {
		t.Fatalf("an unchecked entry the program embeds: voids %+v completeness %+v", v, proof.Completeness)
	}
	// A pattern entry covers every file it matches.
	p, proof := dnPair(t, map[string]string{dnFile: dnDiscovery, "cmd/data/more.json": `{"x":"CustomResourceDefinition"}`}, definesNone(dnPattern))
	var n int
	for _, f := range proof.To.Scan.Findings {
		if f.Class == ClassNoDefinition && f.Location == definesNonePrefix+dnPattern {
			n++
		}
	}
	if n != 2 || !proof.Completeness.Attestable || len(p.Rules) != 1 {
		t.Fatalf("pattern: %d no-definition, completeness %+v", n, proof.Completeness)
	}
}

// A file the claim does not hold for keeps its class (or is unread) and
// blocks attestation, never withholds the pair nor drops its rule.
func TestDefinesNoneRefusals(t *testing.T) {
	templated := "{{ if .x }}\nkind: CustomResourceDefinition\n{{ end }}\n"
	cases := []struct {
		name, entry, path, content string
		// class is the wanted class ("" accepts any blocking class but
		// no-definition).
		class, detail string
		// void: the entry is void at the release (a chart holds it).
		void bool
	}{
		{name: "a definition", entry: dnFile, path: dnFile, content: crd("Gamma", "v1"), class: ClassExtra},
		{name: "a copy of a listed definition", entry: "cmd/data/a.yaml", path: "cmd/data/a.yaml", content: crd("Alpha", "v1"), class: ClassUnread, detail: "declared to define nothing"},
		{name: "a nested mapping of the kind with a spec", entry: dnFile, path: dnFile, content: `{"items":[{"kind":"CustomResourceDefinition","spec":{"group":"x.example.io"}}]}`, class: ClassReference},
		{name: "the kind under another key with a spec", entry: dnFile, path: dnFile, content: `{"items":[{"type":"CustomResourceDefinition","spec":{}}]}`, class: ClassUnread, detail: "has a spec"},
		{name: "a top-level object of the kind without a spec", entry: dnFile, path: dnFile, content: `{"apiVersion":"apiextensions.k8s.io/v1","kind":"CustomResourceDefinition","metadata":{"name":"x"}}`},
		{name: "a manifest in a string", entry: dnFile, path: dnFile, content: `{"doc":"apiVersion: apiextensions.k8s.io/v1\nkind: CustomResourceDefinition\nspec: {}\n"}`, class: ClassReference},
		{name: "a JSON manifest in a string", entry: dnFile, path: dnFile, content: `{"doc":"{\"kind\":\"CustomResourceDefinition\"}"}`, class: ClassUnread, detail: "a string holds a manifest"},
		{name: "not strictly decodable, naming the kind", entry: dnFile, path: dnFile, content: `{"a":1,"a":2,"kind":"CustomResourceDefinition"}`, class: ClassUnread},
		{name: "not strictly decodable, without the kind", entry: dnFile, path: dnFile, content: `{"a":1,"a":2}`, class: ClassUnread, detail: "strict YAML subset"},
		{name: "a YAML anchor", entry: "cmd/data/a.yaml", path: "cmd/data/a.yaml", content: "a: &x 1\nb: *x\n", class: ClassUnread, detail: "strict YAML subset"},
		{name: "template syntax", entry: "cmd/data/a.yaml", path: "cmd/data/a.yaml", content: templated, class: ClassUnread},
		{name: "template syntax without the kind", entry: dnFile, path: dnFile, content: `{"a":"{{ .x }}"}`, class: ClassUnread, detail: "template syntax"},
		{name: "a v1beta1 definition", entry: "cmd/data/a.yaml", path: "cmd/data/a.yaml", content: "apiVersion: apiextensions.k8s.io/v1beta1\nkind: CustomResourceDefinition\nmetadata:\n  name: gammas.synth.example.io\nspec:\n  group: synth.example.io\n  version: v1\n  names:\n    kind: Gamma\n    plural: gammas\n  scope: Namespaced\n"},
		{name: "a kustomization field", entry: "cmd/data/a.yaml", path: "cmd/data/a.yaml", content: "resources:\n- ../../deploy/crds/a.yaml\n", class: ClassUnread, detail: "kustomization"},
		{name: "a kustomization with a remote resource (pattern the loader refuses)", entry: "cmd/data/*.yaml", path: "cmd/data/kustomization.yaml", content: "resources:\n- https://github.com/o/p//config?ref=v1\n", class: ClassExternal},
		{name: "a chart with dependencies (pattern the loader refuses)", entry: "cmd/data/*.yaml", path: "cmd/data/Chart.yaml", content: "apiVersion: v2\nname: x\nversion: 1.0.0\ndependencies:\n- name: y\n  version: 1.0.0\n  repository: https://example.com/charts\n", class: ClassExternal, void: true},
		{name: "dependencies in a data file", entry: dnFile, path: dnFile, content: `{"apiVersion":"v2","dependencies":[{"name":"y","version":"1.0.0","repository":"oci://example.com/charts"}]}`, class: ClassUnread, detail: "dependencies"},
		{name: "a local dependency list", entry: dnFile, path: dnFile, content: `{"dependencies":[]}`, class: ClassUnread, detail: "dependencies"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p, proof := dnPair(t, map[string]string{tc.path: tc.content}, definesNone(tc.entry))
			f, ok := findingAt(proof, tc.path)
			loc := definesNonePrefix + tc.entry
			if tc.void {
				loc = voidPrefix + tc.entry
			}
			if !ok || f.Class == ClassNoDefinition || !f.blocks() || f.Location != loc || (tc.class != "" && f.Class != tc.class) || !strings.Contains(f.Detail, tc.detail) {
				t.Fatalf("finding %+v (found %v), want class %q detail %q", f, ok, tc.class, tc.detail)
			}
			if f.unreadable() {
				t.Fatalf("a refused file withholds: %+v", f)
			}
			if p.Status != extract.PairDerived || len(p.Rules) != 1 || proof.Completeness.Attestable || proof.Completeness.Scan {
				t.Fatalf("pair %s %q rules %v completeness %+v", p.Status, p.Reason, p.Rules, proof.Completeness)
			}
		})
	}
}

// Every install surface but //go:embed still voids the entry: the files
// are then placed like a default-excluded directory's.
func TestDefinesNoneGuarded(t *testing.T) {
	for name, tc := range map[string]struct{ file, content string }{
		"a Makefile kubectl apply": {"Makefile", "install:\n\tkubectl apply -f cmd/data/api.json\n"},
		"a shell script":           {"hack/install.sh", "#!/bin/sh\nkubectl apply -f cmd/data/api.json\n"},
		"a document":               {"README.md", "Run `kubectl apply -f cmd/data/api.json`.\n"},
		"a kustomization":          {"deploy/kustomization.yaml", "resources:\n- ../cmd/data/api.json\n"},
		"a container build":        {"Dockerfile", "FROM scratch\nCOPY cmd/data/api.json /data/\n"},
		"a nix file":               {"nix/build.nix", "{ src = ../cmd/data/api.json; }\n"},
	} {
		t.Run(name, func(t *testing.T) {
			p, proof := dnPair(t, map[string]string{dnFile: dnDiscovery, tc.file: tc.content}, definesNone(dnFile))
			v := voidFindings(proof)
			f, _ := findingAt(proof, dnFile)
			if len(v) != 1 || v[0].Path != tc.file || v[0].Location != dnFile || proof.Completeness.Attestable {
				t.Fatalf("voids %+v completeness %+v", v, proof.Completeness)
			}
			if f.Class != ClassReference || f.Location != voidPrefix+dnFile || p.Status != extract.PairDerived || len(p.Rules) != 1 {
				t.Fatalf("pair %s finding %+v", p.Status, f)
			}
		})
	}
	// Under a chart, or a ko kodata directory.
	for name, tc := range map[string]struct{ entry, extra, content string }{
		"under a chart":  {"tools/chart/data/api.json", "tools/chart/Chart.yaml", "apiVersion: v2\nname: x\nversion: 1.0.0\n"},
		"under a kodata": {"cmd/app/kodata/api.json", "cmd/app/main.go", "package main\n"},
	} {
		t.Run(name, func(t *testing.T) {
			_, proof := dnPair(t, map[string]string{tc.entry: dnDiscovery, tc.extra: tc.content}, definesNone(tc.entry))
			if v := voidFindings(proof); len(v) != 1 || proof.Completeness.Attestable {
				t.Fatalf("voids %+v completeness %+v", v, proof.Completeness)
			}
		})
	}
}

// A file that fails the claim is opaque: a definition that left the listed
// paths is not taken to be gone while it lies there (as under a void
// entry). A no-definition file does not hold one.
func TestDefinesNoneHoldsDefinitions(t *testing.T) {
	run := func(content string) (extract.PairRecord, PairProof) {
		from := map[string]string{"deploy/crds/a.yaml": crd("Alpha", "v1"), "deploy/crds/b.yaml": crd("Beta", "v1"), dnFile: content, "cmd/data/data.go": dnEmbed}
		to := map[string]string{"deploy/crds/a.yaml": crd("Alpha", "v1"), dnFile: content, "cmd/data/data.go": dnEmbed}
		return pairOf(t, runSynth(t, synthTarget(definesNone(dnFile)), newSynth(release{"v1.0.0", from}, release{"v1.1.0", to})), "1.0.0", "1.1.0")
	}
	if p, _ := run(`{"a":1,"a":2,"kind":"CustomResourceDefinition"}`); p.Status != extract.PairWithheld || !strings.Contains(p.Reason, "a removed definition cannot be told from a moved one") {
		t.Fatalf("opaque: %s %q", p.Status, p.Reason)
	}
	if p, proof := run(dnDiscovery); p.Status != extract.PairDerived || len(proof.DefinitionsRemoved) != 1 || !proof.Completeness.Scan {
		t.Fatalf("no-definition: %s %q %+v %+v", p.Status, p.Reason, proof.DefinitionsRemoved, proof.Completeness)
	}
}

// The loader validates the member: the one value, not with copies or
// prePatch, files of YAML or JSON only, never a kustomization or chart name
// or a pattern that matches one, the bounds of every entry, sorted.
func TestDefinesNoneLoader(t *testing.T) {
	ej := func(p, more string) string {
		return fmt.Sprintf(`{"path":%q,"repo":"github.com/o/p","reason":"data the CLI embeds","evidence":"embedded with //go:embed by cmd/data; never applied to a cluster"%s}`, p, more)
	}
	for _, p := range []string{"cmd/data/api.json", "cmd/data/*.json", "pkg/engine/resources/default-config.yaml", "x/a.yml", "test/data/api.json"} {
		tg, err := LoadTarget("target-p.json", testTargetsJSON(ej(p, `,"defines":"none"`)))
		if err != nil || len(tg.Exclude) != 1 || !tg.Exclude[0].DefinesNone || tg.Exclude[0].checked() {
			t.Fatalf("%s: %v %+v", p, err, tg.Exclude)
		}
		if at := tg.placeOf(strings.Replace(p, "*", "x", 1)); !at.definesNone || at.entry != definesNonePrefix+p || at.kind != locReviewed {
			t.Fatalf("%s: place %+v", p, at)
		}
	}
	// Without the member, nothing changes.
	if tg, err := LoadTarget("target-p.json", testTargetsJSON(ej(dnFile, ""))); err != nil || tg.Exclude[0].DefinesNone {
		t.Fatalf("%v %+v", err, tg.Exclude)
	}
	for name, tc := range map[string]struct{ ej, want string }{
		"another value":              {ej(dnFile, `,"defines":"all"`), "the only value"},
		"a capitalised value":        {ej(dnFile, `,"defines":"None"`), "the only value"},
		"a boolean":                  {ej(dnFile, `,"defines":true`), "cannot unmarshal"},
		"with copies":                {ej(dnFile, `,"defines":"none","copies":true`), "copies and prePatch"},
		"with prePatch":              {ej("cmd/data/", `,"defines":"none","prePatch":"cmd/k/kustomization.yaml"`), "copies and prePatch"},
		"a directory":                {ej("cmd/data/", `,"defines":"none"`), "not a directory"},
		"a Go source":                {ej("cmd/data/data.go", `,"defines":"none"`), "YAML or JSON"},
		"a template":                 {ej("cmd/data/x.tpl", `,"defines":"none"`), "YAML or JSON"},
		"a wildcard extension":       {ej("cmd/data/x.*", `,"defines":"none"`), "YAML or JSON"},
		"a kustomization":            {ej("cmd/data/kustomization.yaml", `,"defines":"none"`), "kustomize or Helm"},
		"a kustomization (yml)":      {ej("cmd/data/kustomization.yml", `,"defines":"none"`), "kustomize or Helm"},
		"a pattern matching one":     {ej("cmd/data/*.yaml", `,"defines":"none"`), "kustomize or Helm"},
		"a pattern matching Chart":   {ej("cmd/data/[Cc]hart.yaml", `,"defines":"none"`), "kustomize or Helm"},
		"Chart.yaml":                 {ej("tools/x/Chart.yaml", `,"defines":"none"`), "kustomize or Helm"},
		"chart.yaml in another case": {ej("tools/x/chart.yaml", `,"defines":"none"`), "kustomize or Helm"},
		"requirements.yaml":          {ej("tools/x/requirements.yaml", `,"defines":"none"`), "kustomize or Helm"},
		"values.yaml":                {ej("tools/x/values.yaml", `,"defines":"none"`), "kustomize or Helm"},
		"an install location":        {ej("deploy/api.json", `,"defines":"none"`), "never excluded"},
		"a CRD location":             {ej("config/crds/api.json", `,"defines":"none"`), "never excluded"},
		"a pattern in the directory": {ej("cmd/*/api.json", `,"defines":"none"`), "last path element"},
		"short evidence":             {`{"path":"cmd/data/api.json","repo":"github.com/o/p","reason":"data the CLI embeds","evidence":"embedded","defines":"none"}`, "evidence"},
		"no reason":                  {`{"path":"cmd/data/api.json","repo":"github.com/o/p","evidence":"embedded with //go:embed by cmd/data; never applied to a cluster","defines":"none"}`, "reason"},
		"unsorted":                   {ej("cmd/data/b.json", `,"defines":"none"`) + "," + ej("cmd/data/a.json", `,"defines":"none"`), "not sorted"},
		"a duplicate":                {ej(dnFile, `,"defines":"none"`) + "," + ej(dnFile, ""), "not sorted"},
		"another repository":         {strings.Replace(ej(dnFile, `,"defines":"none"`), "github.com/o/p", "github.com/o/q", 1), "names repository"},
		"a listed path":              {ej("crds/a.yaml", `,"defines":"none"`), "covers the listed path"},
	} {
		if _, err := LoadTarget("target-p.json", testTargetsJSON(tc.ej)); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v, want %q", name, err, tc.want)
		}
	}
}

// The scan with defines-none entries is the same at any read concurrency.
func TestDefinesNoneDeterministicUnderConcurrency(t *testing.T) {
	files := map[string]string{"deploy/crds/a.yaml": crd("Alpha", "v1"), "cmd/data/data.go": "package data\n\n//go:embed *.json\n"}
	for i := 0; i < 30; i++ {
		switch i % 3 {
		case 0:
			files[fmt.Sprintf("cmd/data/d%02d.json", i)] = fmt.Sprintf(`{"n":%d,"r":[{"kind":"CustomResourceDefinition"}]}`, i)
		case 1:
			files[fmt.Sprintf("cmd/data/d%02d.json", i)] = fmt.Sprintf(`{"n":%d,"n":%d}`, i, i)
		default:
			files[fmt.Sprintf("cmd/data/d%02d.json", i)] = fmt.Sprintf(`{"n":%d,"r":[{"kind":"CustomResourceDefinition","spec":{}}]}`, i)
		}
	}
	s := newSynth(release{"v1.0.0", files}, release{"v1.1.0", files})
	tg := synthTarget(definesNone(dnPattern))
	want := outputBytes(t, runSynthConcurrent(t, tg, s, 1))
	var names []string
	for k := range want {
		names = append(names, k)
	}
	sort.Strings(names)
	for run := 0; run < 10; run++ {
		got := outputBytes(t, runSynthConcurrent(t, tg, s, 8))
		for _, k := range names {
			if !bytes.Equal(want[k], got[k]) {
				t.Fatalf("run %d: %s differs with concurrency 8", run, k)
			}
		}
	}
	_, proof := pairOf(t, runSynthConcurrent(t, tg, s, 1), "1.0.0", "1.1.0")
	classes := map[string]int{}
	for _, f := range proof.To.Scan.Findings {
		classes[f.Class]++
	}
	if classes[ClassNoDefinition] != 10 || classes[ClassUnread] != 10 || classes[ClassReference] != 10 || len(voidFindings(proof)) != 0 {
		t.Fatalf("classes %v", classes)
	}
}

// definesNothing never accepts bytes the scan's readers find a definition
// in, and depends on the bytes only.
func FuzzDefinesNothing(f *testing.F) {
	for _, s := range []string{dnDiscovery, crd("Alpha", "v1"), "", "---\n", "a: &x 1\nb: *x\n", "{{ x }}", "- kind: CustomResourceDefinition\n  spec: {}\n", `{"doc":"kind: CustomResourceDefinition"}`, "resources: [a]\n", "dependencies: []\n"} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		why := definesNothing(data)
		if why != definesNothing(data) {
			t.Fatal("not a function of the bytes")
		}
		if why != "" {
			return
		}
		info := summarize(kindNoDef, data)
		if len(info.crds) != 0 || info.legacy != nil || info.embedded || info.unread != "" || info.kust != nil && !emptyKustomization(info.kust) || len(info.chartDeps) != 0 {
			t.Fatalf("accepted bytes that hold %+v", info)
		}
		if legacy, err := parseLegacy(data); err == nil && len(legacy) != 0 {
			t.Fatalf("accepted v1beta1 definitions %+v", legacy)
		}
	})
}
