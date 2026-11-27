// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
)

func filesFetcher(files map[string]string) fetcher {
	return func(_ context.Context, _, _, p string) ([]byte, error) { return []byte(files[p]), nil }
}

func releaseOf(files ...string) CRDRelease {
	return CRDRelease{Tag: "v1", Commit: strings.Repeat("a", 40), Files: files}
}

func manifestError(files map[string]string, cited ...string) error {
	_, _, _, err := releaseManifest(context.Background(), filesFetcher(files), "github.com/f/f", releaseOf(cited...))
	return err
}

func TestReleaseManifestRefusesDroppedDocuments(t *testing.T) {
	good := string(gadget(true, false)) // CRD + ConfigMap
	cut := func(s string) string { return good + "---\n" + strings.Replace(good, s, "", 1) }
	for name, c := range map[string]struct {
		path, body string
		ok         bool
	}{
		"workload": {"c.yaml", good, true}, "no name": {"c.yaml", cut("  name: gadgets.fixture.example\n"), false},
		"no group": {"c.yaml", cut("  group: fixture.example\n"), false}, "no names.kind": {"c.yaml", cut("    kind: Gadget\n"), false},
		"list":        {"c.yaml", good + "---\napiVersion: v1\nkind: List\nitems: []\n", false},
		"unlisted":    {"c.yaml", good + "---\napiVersion: x.example/v1\nkind: Widget\n", false},
		"no kind":     {"c.yaml", good + "---\napiVersion: v1\n", false},
		"foreign crd": {"c.yaml", good + "---\napiVersion: x.example/v1\nkind: CustomResourceDefinition\n", false},
		"zero":        {"c.yaml", "apiVersion: v1\nkind: ConfigMap\nmetadata: {name: x}\n", false},
		"empty group": {"c.yaml", good + "---\napiVersion: /v1\nkind: ConfigMap\n", false}, "empty version": {"c.yaml", good + "---\napiVersion: apps/\nkind: Deployment\n", false},
		"two slashes": {"c.yaml", good + "---\napiVersion: apps/v1/x\nkind: Deployment\n", false}, "apiservice": {"c.yaml", good + "---\napiVersion: apiregistration.k8s.io/v1\nkind: APIService\n", false},
		"no apiVersion":                            {"c.yaml", good + "---\nkind: ConfigMap\n", false},
		"empty mapping":                            {"c.yaml", good + "---\n{}\n", false},
		"empty documents":                          {"c.yaml", good + "---\n---\n# comment\n---\nnull\n", true},
		"scalar document":                          {"c.yaml", good + "---\ntext\n", false},
		"sequence document":                        {"c.yaml", good + "---\n- a\n", false},
		"listed kind in another group":             {"c.yaml", good + "---\napiVersion: x.example/v1\nkind: Deployment\n", false},
		"core kind in a group":                     {"c.yaml", good + "---\napiVersion: x.example/v1\nkind: ConfigMap\n", false},
		"typed list":                               {"c.yaml", good + "---\napiVersion: apiextensions.k8s.io/v1\nkind: CustomResourceDefinitionList\n", false},
		"other apiextensions":                      {"c.yaml", good + "---\napiVersion: apiextensions.k8s.io/v1\nkind: ConversionReview\n", false},
		"no versions":                              {"c.yaml", "apiVersion: apiextensions.k8s.io/v1\nkind: CustomResourceDefinition\nmetadata: {name: a.b}\nspec: {group: b, names: {kind: A}}\n", false},
		"empty version list":                       {"c.yaml", "apiVersion: apiextensions.k8s.io/v1\nkind: CustomResourceDefinition\nmetadata: {name: a.b}\nspec: {group: b, names: {kind: A}, versions: []}\n", false},
		"empty version name":                       {"c.yaml", "apiVersion: apiextensions.k8s.io/v1\nkind: CustomResourceDefinition\nmetadata: {name: a.b}\nspec: {group: b, names: {kind: A}, versions: [{name: v1}, {name: \"\"}]}\n", false},
		"version not a mapping":                    {"c.yaml", "apiVersion: apiextensions.k8s.io/v1\nkind: CustomResourceDefinition\nmetadata: {name: a.b}\nspec: {group: b, names: {kind: A}, versions: [v1]}\n", false},
		"kustomization content under another name": {"c.yaml", good + "---\napiVersion: kustomize.config.k8s.io/v1beta1\nkind: Kustomization\nresources: [a.yaml]\n", false},
		"definitions in a kustomization file":      {"kustomization.yaml", good, false},
	} {
		if err := manifestError(map[string]string{c.path: c.body}, c.path); (err == nil) != c.ok {
			t.Errorf("%s: err %v", name, err)
		}
	}
}

func TestReleaseManifestCountsLeftOutDocuments(t *testing.T) {
	body := string(gadget(true, false))
	for key := range leftOut {
		group, kind, _ := strings.Cut(key, "/")
		apiVersion := "v1"
		if group != "" {
			apiVersion = group + "/v1"
		}
		body += "---\napiVersion: " + apiVersion + "\nkind: " + kind + "\n"
	}
	_, defs, files, err := releaseManifest(context.Background(), filesFetcher(map[string]string{"c.yaml": body}), "github.com/f/f", releaseOf("c.yaml"))
	if err != nil || len(defs) != 1 || len(files) != 1 || files[0].CRDs != 1 {
		t.Fatalf("%v %+v", err, files)
	}
	want := map[string]int{}
	for key := range leftOut {
		want[key] = 1
	}
	want["/ConfigMap"] = 2
	if len(want) != 22 || !reflect.DeepEqual(files[0].Skipped, want) {
		t.Fatalf("%d kinds, skipped %v", len(want), files[0].Skipped)
	}
}

func TestInertKustomization(t *testing.T) {
	const head = "apiVersion: kustomize.config.k8s.io/v1beta1\nkind: Kustomization\n"
	list := func(entry string) string { return head + "resources: [" + entry + "]\n" }
	gadgets := string(gadget(true, false))
	widgets := string(widgetOnly())
	for _, base := range []string{"kustomization.yaml", "kustomization.yml", "Kustomization"} {
		file := "d/" + base
		cited := []string{"d/a.yaml", file, "d/sub/b.yaml"}
		contents := map[string]string{"d/a.yaml": gadgets, "d/sub/b.yaml": widgets, file: "# lists\n" + head + "resources:\n- a.yaml\n- ./sub/b.yaml\n---\n"}
		manifest, defs, files, err := releaseManifest(context.Background(), filesFetcher(contents), "github.com/f/f", releaseOf(cited...))
		if err != nil || len(defs) != 2 || strings.Contains(string(manifest), "Kustomization") {
			t.Fatalf("%s: %v %+v", base, err, defs)
		}
		// Every cited file stays in the record.
		if len(files) != len(cited) || files[1].Path != file || !strings.HasPrefix(files[1].SHA256, "sha256:") || len(files[1].SHA256) != 71 || files[1].CRDs != 0 || !reflect.DeepEqual(files[1].Skipped, map[string]int{"kustomize.config.k8s.io/Kustomization": 1}) {
			t.Fatalf("%s: files %+v", base, files)
		}
	}
	for name, body := range map[string]string{
		"patches":            list("a.yaml") + "patches: []\n",
		"namespace":          list("a.yaml") + "namespace: x\n",
		"no resources":       head,
		"empty resources":    list(""),
		"resources a string": head + "resources: a.yaml\n",
		"other apiVersion":   strings.Replace(list("a.yaml"), "v1beta1", "v1alpha1", 1),
		"component":          strings.Replace(list("a.yaml"), "kind: Kustomization", "kind: Component", 1),
		"two documents":      list("a.yaml") + "---\n" + list("a.yaml"),
		"definition added":   list("a.yaml") + "---\n" + gadgets,
		"empty file":         "",
		"parse error":        "a: [\n",
		"remote":             list("\"https://example.invalid/a.yaml\""),
		"remote short":       list("github.com/f/f//a"),
		"directory":          list("sub"),
		"dot":                list("."),
		"dot dot":            list(".."),
		"trailing slash":     list("a.yaml/"),
		"trailing dot":       list("a.yaml/."),
		"trailing dot dot":   list("a.yaml/x/.."),
		"self":               list("kustomization.yaml"),
		"absolute":           list("/a.yaml"),
		"uncited":            list("a.yaml, missing.yaml"),
		"not a string":       list("1"),
		"empty entry":        list("\"\""),
	} {
		err := manifestError(map[string]string{"d/a.yaml": gadgets, "d/kustomization.yaml": body}, "d/a.yaml", "d/kustomization.yaml")
		var r *refusal
		if !errors.As(err, &r) || r.file != 2 || (r.cause != causeKustomization && r.cause != causeResource) {
			t.Errorf("%s: err %v", name, err)
		}
	}
	// Kustomizations alone hold no definition, whether or not they are inert.
	if err := manifestError(map[string]string{"kustomization.yaml": list("a.yaml")}, "kustomization.yaml"); err == nil {
		t.Error("a lone kustomization was accepted")
	}
	pair := map[string]string{"a/kustomization.yaml": list("../b/kustomization.yaml"), "b/kustomization.yaml": list("../a/kustomization.yaml")}
	if err := manifestError(pair, "a/kustomization.yaml", "b/kustomization.yaml"); err == nil || err.Error() != "the release holds no CustomResourceDefinition" {
		t.Errorf("kustomizations only: %v", err)
	}
	if err := manifestError(nil); err == nil {
		t.Error("a release with no files was accepted")
	}
}

// The refusal texts are stored and later matched by pattern: each is fixed,
// and nothing read from a document appears in it.
func TestRefusalTextsAreFixed(t *testing.T) {
	good := string(gadget(true, false))
	commit := strings.Repeat("a", 40)
	second := func(body string) map[string]string { return map[string]string{"c.yaml": good + "---\n" + body} }
	crd := func(meta, spec string) map[string]string {
		return second("apiVersion: apiextensions.k8s.io/v1\nkind: CustomResourceDefinition\nmetadata: {" + meta + "}\nspec: {" + spec + "}\n")
	}
	const k = "apiVersion: kustomize.config.k8s.io/v1beta1\nkind: Kustomization\n"
	at := "c.yaml@" + commit + ": file 1, document 3: "
	for _, word := range []string{"EOF", "AlreadyExists"} {
		for name, c := range map[string]struct {
			files map[string]string
			cited []string
			want  string
		}{
			"no apiVersion":     {second("kind: " + word + "\n"), nil, at + "apiVersion or kind is missing, empty or not a string: apiVersion"},
			"number apiVersion": {second("apiVersion: 1\nkind: " + word + "\n"), nil, at + "apiVersion or kind is missing, empty or not a string: apiVersion"},
			"number kind":       {second("apiVersion: v1\nkind: 1\nmetadata: {name: " + word + "}\n"), nil, at + "apiVersion or kind is missing, empty or not a string: kind"},
			"list kind":         {second("apiVersion: v1\nkind: [" + word + "]\n"), nil, at + "apiVersion or kind is missing, empty or not a string: kind"},
			"bad apiVersion":    {second("apiVersion: a/b/" + word + "\nkind: " + word + "\n"), nil, at + "apiVersion is not a version or group/version"},
			"foreign crd":       {second("apiVersion: " + word + "/v1\nkind: CustomResourceDefinition\nmetadata: {name: " + word + "}\n"), nil, at + "CustomResourceDefinition outside the apiextensions.k8s.io group"},
			"kind":              {second("apiVersion: " + word + "/v1\nkind: " + word + "\nmetadata: {name: " + word + "}\n"), nil, at + "document is of a kind this check may not leave out"},
			"name":              {crd("", "group: "+word), nil, at + "CustomResourceDefinition lacks a required field: metadata.name"},
			"group":             {crd("name: "+word, ""), nil, at + "CustomResourceDefinition lacks a required field: spec.group"},
			"names.kind":        {crd("name: "+word, "group: "+word), nil, at + "CustomResourceDefinition lacks a required field: spec.names.kind"},
			"versions":          {crd("name: "+word, "group: g, names: {kind: "+word+"}"), nil, at + "CustomResourceDefinition lacks a required field: spec.versions"},
			"version name":      {crd("name: "+word, "group: g, names: {kind: K}, versions: [{served: true}]"), nil, at + "CustomResourceDefinition lacks a required field: spec.versions[].name"},
			"duplicate": {map[string]string{"c.yaml": strings.ReplaceAll(good, "gadgets.fixture.example", word), "e.yaml": strings.ReplaceAll(good, "gadgets.fixture.example", word)}, []string{"c.yaml", "e.yaml"},
				"e.yaml@" + commit + ": file 2: CustomResourceDefinition name is defined more than once, first in file 1"},
			"duplicate in one file": {second(good), nil, "c.yaml@" + commit + ": file 1: CustomResourceDefinition name is defined more than once, first in file 1"},
			"kustomization": {map[string]string{"c.yaml": good, "kustomization.yaml": k + "namePrefix: " + word + "\nresources: [c.yaml]\n"}, []string{"c.yaml", "kustomization.yaml"},
				"kustomization.yaml@" + commit + ": file 2: kustomization is not a plain list of resources"},
			"resource": {map[string]string{"c.yaml": good, "kustomization.yaml": k + "resources: [" + word + "]\n"}, []string{"c.yaml", "kustomization.yaml"},
				"kustomization.yaml@" + commit + ": file 2: kustomization lists a resource that is not another cited file"},
			"no definition": {map[string]string{"c.yaml": good, "e.yaml": "apiVersion: v1\nkind: ConfigMap\nmetadata: {name: " + word + "}\n"}, []string{"c.yaml", "e.yaml"},
				"e.yaml@" + commit + ": file 2: the file holds no CustomResourceDefinition"},
		} {
			cited := c.cited
			if cited == nil {
				cited = []string{"c.yaml"}
			}
			err := manifestError(c.files, cited...)
			if err == nil || err.Error() != c.want {
				t.Errorf("%s %s: %v, want %s", name, word, err, c.want)
			}
		}
	}
	err := manifestError(second("apiVersion: x.example/v1\nkind: Widget\n"), "c.yaml")
	var r *refusal
	if !errors.As(err, &r) || r.apiVersion != "x.example/v1" || r.kind != "Widget" {
		t.Fatalf("refused values are not kept: %+v", r)
	}
}

func TestDroppedToDocumentNeverConfirmsRemoval(t *testing.T) {
	fetch := func(_ context.Context, _, commit, _ string) ([]byte, error) {
		if commit == gadgetFrom.Commit {
			return gadget(true, false), nil
		}
		return []byte(strings.Replace(string(gadget(true, false)), "    kind: Gadget\n", "", 1)), nil
	}
	claims := gadgetClaims(true)
	cluster := &fakeCluster{crds: map[string]CRDDef{}}
	r := runPair(context.Background(), kube{run: cluster.runner, kubeconfig: "kc"}, fetch, claims.Pairs()[0])
	got := outcomes(evalObserved(claims, crdRuns(r), Provenance{}, time.Unix(0, 0)))["removal"]
	if !strings.HasPrefix(r.Error, "to: ") || got.Outcome != OutcomeError {
		t.Fatalf("%q %+v", r.Error, got)
	}
}

func TestDroppedFromDocumentNeverConfirmsQuietPair(t *testing.T) {
	fetch := func(_ context.Context, _, commit, _ string) ([]byte, error) {
		if commit == gadgetTo.Commit {
			return gadget(true, false), nil
		}
		return []byte(strings.Replace(string(gadget(true, false)), "    kind: Gadget\n", "", 1)), nil
	}
	claims := gadgetClaims(false)
	cluster := &fakeCluster{crds: map[string]CRDDef{}}
	r := runPair(context.Background(), kube{run: cluster.runner, kubeconfig: "kc"}, fetch, claims.Pairs()[0])
	got := outcomes(evalObserved(claims, crdRuns(r), Provenance{}, time.Unix(0, 0)))["quiet"]
	if !strings.HasPrefix(r.Error, "from: ") || got.Outcome != OutcomeError {
		t.Fatalf("%q %+v", r.Error, got)
	}
}

func TestReleaseWithoutDefinitionsDecidesNothing(t *testing.T) {
	none := []byte("apiVersion: v1\nkind: ConfigMap\nmetadata: {name: x}\n")
	for _, side := range []struct{ commit, prefix string }{{gadgetFrom.Commit, "from: "}, {gadgetTo.Commit, "to: "}} {
		fetch := func(_ context.Context, _, commit, _ string) ([]byte, error) {
			if commit == side.commit {
				return none, nil
			}
			return gadget(true, false), nil
		}
		claims := gadgetClaims(true)
		cluster := &fakeCluster{crds: map[string]CRDDef{}}
		r := runPair(context.Background(), kube{run: cluster.runner, kubeconfig: "kc"}, fetch, claims.Pairs()[0])
		got := outcomes(evalObserved(claims, crdRuns(r), Provenance{}, time.Unix(0, 0)))["removal"]
		if !strings.HasPrefix(r.Error, side.prefix) || !strings.Contains(r.Error, "holds no CustomResourceDefinition") || got.Outcome != OutcomeError {
			t.Errorf("%s%q %+v", side.prefix, r.Error, got)
		}
	}
}

func TestDuplicateDefinitionNeverDecidesRemoval(t *testing.T) {
	served, gone := string(gadget(true, false)), string(gadget(false, false))
	for name, to := range map[string]string{"confirmed on main": served + "---\n" + gone, "refuted on main": gone + "---\n" + served} {
		fetch := func(_ context.Context, _, commit, _ string) ([]byte, error) {
			if commit == gadgetFrom.Commit {
				return []byte(served), nil
			}
			return []byte(to), nil
		}
		claims := gadgetClaims(true)
		cluster := &fakeCluster{crds: map[string]CRDDef{}}
		r := runPair(context.Background(), kube{run: cluster.runner, kubeconfig: "kc"}, fetch, claims.Pairs()[0])
		got := outcomes(evalObserved(claims, crdRuns(r), Provenance{}, time.Unix(0, 0)))["removal"]
		if !strings.HasPrefix(r.Error, "to: ") || got.Outcome != OutcomeError {
			t.Errorf("%s: %q %+v", name, r.Error, got)
		}
	}
}

func TestReleaseManifestRefusesAcrossFiles(t *testing.T) {
	k := "apiVersion: kustomize.config.k8s.io/v1beta1\nkind: Kustomization\nresources: [missing.yaml]\n"
	for name, second := range map[string][2]string{"duplicate": {"d/b.yaml", string(gadget(true, false))}, "uncited resource": {"d/kustomization.yaml", k}, "trailing slash": {"d/kustomization.yaml", strings.Replace(k, "missing.yaml", "a.yaml/", 1)}} {
		contents := map[string]string{"d/a.yaml": string(gadget(true, false)), second[0]: second[1]}
		if err := manifestError(contents, "d/a.yaml", second[0]); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}
