// SPDX-License-Identifier: AGPL-3.0-only

package crdversions

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/extract"
)

// crdDoc renders one CRD document with the given version entries, each
// "name served storage".
func crdDoc(group, kind, plural string, versions ...string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "apiVersion: apiextensions.k8s.io/v1\nkind: CustomResourceDefinition\nmetadata:\n  name: %s.%s\nspec:\n  group: %s\n  names:\n    kind: %s\n    plural: %s\n  scope: Namespaced\n  versions:\n", plural, group, group, kind, plural)
	for _, v := range versions {
		f := strings.Fields(v)
		fmt.Fprintf(&b, "  - name: %s\n    served: %s\n    storage: %s\n    schema:\n      openAPIV3Schema:\n        type: object\n", f[0], f[1], f[2])
	}
	return b.String()
}

// istioFixture writes one bundle file per commit for the Istio file target
// and the tags 1.30.0 (c0) and 1.31.0 (c1).
func istioFixture(t *testing.T, from, to string) string {
	t.Helper()
	root := t.TempDir()
	repo := filepath.Join(root, "github.com/istio/istio")
	for c, body := range map[string]string{c0: from, c1: to} {
		dir := filepath.Join(repo, "commits", c, "manifests/charts/base/files")
		must(t, os.MkdirAll(dir, 0o755))
		must(t, os.WriteFile(filepath.Join(dir, "crd-all.gen.yaml"), []byte(body), 0o644))
	}
	must(t, os.WriteFile(filepath.Join(repo, "tags.json"), []byte(`{"1.30.0":"`+c0+`","1.31.0":"`+c1+`"}`), 0o644))
	return root
}

func onlyPair(t *testing.T, out *extract.Output) extract.PairRecord {
	t.Helper()
	if len(out.Manifest.Pairs) != 1 {
		t.Fatalf("pairs %+v", out.Manifest.Pairs)
	}
	return out.Manifest.Pairs[0]
}

// Names that differ only by "." against "-" get different rule ids; a
// collision would withhold the pair, never fail the run.
func TestRuleIDsDoNotCollide(t *testing.T) {
	from := crdDoc("bar.x.io", "Foo", "foo", "v1alpha1 true false", "v1 true true") + "---\n" + crdDoc("x.io", "FooBar", "foo-bar", "v1alpha1 true false", "v1 true true")
	to := crdDoc("bar.x.io", "Foo", "foo", "v1 true true") + "---\n" + crdDoc("x.io", "FooBar", "foo-bar", "v1 true true")
	out := mustRun(t, "istio", extract.FixtureReader{Root: istioFixture(t, from, to)})
	p := onlyPair(t, out)
	want := []string{"istio.crd-version-removal.foo--bar-x-io.1-30-0-to-1-31-0", "istio.crd-version-removal.foo-bar-x-io.1-30-0-to-1-31-0"}
	if p.Status != extract.PairDerived || len(p.Rules) != 2 || p.Rules[0] != want[0] || p.Rules[1] != want[1] {
		t.Fatalf("%+v", p)
	}
	dup := []extract.Candidate{{Rule: extract.Rule{ID: "a"}}, {Rule: extract.Rule{ID: "b"}}, {Rule: extract.Rule{ID: "a"}}}
	if err := uniqueIDs(dup); err == nil {
		t.Fatal("duplicate ids accepted")
	} else if _, ok := asProblem(err); !ok {
		t.Fatalf("a duplicate id must withhold, not abort: %v", err)
	}
}

// A cited entry ends at its last content line, including block-scalar
// lines that look like comments; a comment between entries is not part of
// the earlier one.
func TestSpanCoversBlockScalars(t *testing.T) {
	doc := `apiVersion: apiextensions.k8s.io/v1
kind: CustomResourceDefinition
metadata:
  name: things.x.io
spec:
  group: x.io
  names:
    kind: Thing
    plural: things
  scope: Cluster
  versions:
  - name: v1beta1
    served: true
    storage: false
    deprecationWarning: old
    schema:
      openAPIV3Schema:
        description: |
          Use v1.

          # Example
          #   kubectl get things
        type: object

  # v1 replaces v1beta1.
  - name: v1
    served: true
    storage: true
    schema:
      openAPIV3Schema:
        description: |-
          Final.
          # trailing heading
---
`
	_, crds, err := parseFile("f.yaml", []byte(doc))
	must(t, err)
	v := crds[0].Versions
	if v[0].StartLine != 12 || v[0].EndLine != 23 || v[1].StartLine != 26 || v[1].EndLine != 33 {
		t.Fatalf("spans %+v", v)
	}
	// Without the closing "type: object" the block scalar's comment-like
	// lines are the entry's last lines and stay in it.
	doc2 := strings.Replace(doc, "        type: object\n\n", "\n", 1)
	_, crds, err = parseFile("f.yaml", []byte(doc2))
	must(t, err)
	if v := crds[0].Versions[0]; v.EndLine != 22 {
		t.Fatalf("block scalar cut: %+v", v)
	}
}

// More than seven versions that become served: false are cited through the
// whole later file; fewer are cited line by line.
func TestServedFalseCitations(t *testing.T) {
	var from, to, fromFew, toFew []string
	for i := 1; i <= 8; i++ {
		from = append(from, fmt.Sprintf("v1alpha%d true false", i))
		to = append(to, fmt.Sprintf("v1alpha%d false false", i))
	}
	from, to = append(from, "v1 true true"), append(to, "v1 true true")
	fromFew, toFew = append([]string{}, from[6:]...), append([]string{}, to[6:]...)
	for _, tc := range []struct {
		from, to []string
		ids      []string
	}{
		{from, to, []string{"crd-1-31-0", "crd-versions-1-30-0"}},
		{fromFew, toFew, []string{"crd-versions-1-30-0", "served-false-v1alpha7-1-31-0", "served-false-v1alpha8-1-31-0"}},
	} {
		out := mustRun(t, "istio", extract.FixtureReader{Root: istioFixture(t, crdDoc("x.io", "Thing", "things", tc.from...), crdDoc("x.io", "Thing", "things", tc.to...))})
		if len(out.Entries) != 1 {
			t.Fatalf("entries %d", len(out.Entries))
		}
		var ids []string
		for _, s := range out.Entries[0].Rule.Evidence.Sources {
			ids = append(ids, s.ID)
			if s.ID == "crd-1-31-0" && s.StartLine != 1 {
				t.Fatalf("whole file source %+v", s)
			}
			if strings.HasPrefix(s.ID, "served-false") && s.StartLine != s.EndLine {
				t.Fatalf("served-false source %+v", s)
			}
		}
		if strings.Join(ids, ",") != strings.Join(tc.ids, ",") {
			t.Fatalf("sources %v, want %v", ids, tc.ids)
		}
	}
}

// Structural checks of a definition and the bounds, each withholding.
func TestCRDWithholdStructure(t *testing.T) {
	good := crdDoc("x.io", "Thing", "things", "v1alpha1 true false", "v1 true true")
	many := func(n int) string {
		var vs []string
		for i := 0; i < n-1; i++ {
			vs = append(vs, fmt.Sprintf("v%dalpha1 true false", i+2))
		}
		return crdDoc("x.io", "Thing", "things", append(vs, "v1 true true")...)
	}
	cases := []struct {
		name, to, want string
	}{
		{"duplicate version name", crdDoc("x.io", "Thing", "things", "v1alpha1 true false", "v1 true true", "v1alpha1 false false"), "is listed twice"},
		{"duplicate group and kind", good + "---\n" + crdDoc("x.io", "Thing", "thingz", "v1 true true"), "kind x.io/Thing is defined by both"},
		{"other apiextensions kind", good + "---\napiVersion: apiextensions.k8s.io/v1\nkind: ConversionReview\n", "has apiVersion apiextensions.k8s.io/v1 and kind \"ConversionReview\""},
		{"definition list", "apiVersion: apiextensions.k8s.io/v1\nkind: CustomResourceDefinitionList\nitems: []\n", "list items are not read"},
		{"65 versions", many(65), "has 65 versions, over the bound of 64"},
		{"name is not plural.group", strings.Replace(good, "name: things.x.io", "name: thing.x.io", 1), "is not <plural>.<group>"},
		{"bad scope", strings.Replace(good, "scope: Namespaced", "scope: Global", 1), "is not Namespaced or Cluster"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := onlyPair(t, mustRun(t, "istio", extract.FixtureReader{Root: istioFixture(t, good, tc.to)}))
			if p.Status != extract.PairWithheld || !strings.Contains(p.Reason, tc.want) {
				t.Fatalf("%s %q, want %q", p.Status, p.Reason, tc.want)
			}
		})
	}
	// 64 versions are within the bound.
	if p := onlyPair(t, mustRun(t, "istio", extract.FixtureReader{Root: istioFixture(t, many(64), many(64))})); p.Status != extract.PairDerived {
		t.Fatalf("64 versions: %+v", p)
	}
	// More than 512 definitions in one tag (three files of the directory
	// target, under the per-file document bound).
	t.Run("513 definitions", func(t *testing.T) {
		root, dir := copyFixture(t)
		for f := 0; f < 3; f++ {
			var docs []string
			for i := 0; i < 171; i++ {
				docs = append(docs, crdDoc("x.io", fmt.Sprintf("K%dx%d", f, i), fmt.Sprintf("k%dx%d", f, i), "v1 true true"))
			}
			must(t, os.WriteFile(filepath.Join(dir, fmt.Sprintf("bulk-%d.yaml", f)), []byte(strings.Join(docs, "---\n")), 0o644))
		}
		out := mustRun(t, "argo-cd", extract.FixtureReader{Root: root})
		p := out.Manifest.Pairs[0]
		if p.Status != extract.PairWithheld || !strings.Contains(p.Reason, "more than 512 CustomResourceDefinitions") {
			t.Fatalf("%s %q", p.Status, p.Reason)
		}
	})
}

// Strimzi: a CRD file outside the read pattern withholds; an alphanumeric
// prefix such as 04A is read; the KafkaTopic span covers its three removed
// entries.
func TestStrimziFiles(t *testing.T) {
	copyStrimzi := func(t *testing.T) (string, string) {
		root := t.TempDir()
		err := filepath.WalkDir(strimziRoot, func(p string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return err
			}
			rel, _ := filepath.Rel(strimziRoot, p)
			raw, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			must(t, os.MkdirAll(filepath.Dir(filepath.Join(root, rel)), 0o755))
			return os.WriteFile(filepath.Join(root, rel), raw, 0o644)
		})
		must(t, err)
		return root, filepath.Join(root, "github.com/strimzi/strimzi-kafka-operator/commits/4836c7dd74ce973f06d97936916ed7f20c1a2ff0/install/cluster-operator")
	}
	t.Run("unread CRD file", func(t *testing.T) {
		root, dir := copyStrimzi(t)
		must(t, os.WriteFile(filepath.Join(dir, "04-Crd-extra.yaml"), []byte("a: 1\n"), 0o644))
		p := onlyPair(t, mustRun(t, "strimzi", extract.FixtureReader{Root: root}))
		if p.Status != extract.PairWithheld || !strings.Contains(p.Reason, "04-Crd-extra.yaml looks like a CRD manifest but is not read") {
			t.Fatalf("%s %q", p.Status, p.Reason)
		}
	})
	t.Run("alphanumeric prefix", func(t *testing.T) {
		root, dir := copyStrimzi(t)
		must(t, os.Rename(filepath.Join(dir, "045-Crd-kafkanodepool.yaml"), filepath.Join(dir, "04A-Crd-kafkanodepool.yaml")))
		out := mustRun(t, "strimzi", extract.FixtureReader{Root: root})
		p := onlyPair(t, out)
		if p.Status != extract.PairDerived || len(p.Rules) != 10 {
			t.Fatalf("%+v", p)
		}
		files := map[string]bool{}
		for _, f := range pairProof(t, p).To.Files {
			files[f.Path] = true
		}
		if !files["install/cluster-operator/04A-Crd-kafkanodepool.yaml"] {
			t.Fatalf("04A file not read: %v", files)
		}
	})
	t.Run("multi-version span", func(t *testing.T) {
		out := mustRun(t, "strimzi", extract.FixtureReader{Root: strimziRoot})
		for _, e := range out.Entries {
			if e.Rule.ID != "strimzi.crd-version-removal.kafkatopics-kafka-strimzi-io.0-51-0-to-1-0-0" {
				continue
			}
			if got := e.Rule.SetCondition.Members; strings.Join(got, ",") != "kafka.strimzi.io/v1alpha1/KafkaTopic,kafka.strimzi.io/v1beta1/KafkaTopic,kafka.strimzi.io/v1beta2/KafkaTopic" {
				t.Fatalf("members %v", got)
			}
			for _, s := range e.Rule.Evidence.Sources {
				if s.ID == "crd-versions-0-51-0" && (s.StartLine != 48 || s.EndLine != 128) {
					t.Fatalf("span %d-%d, want 48-128", s.StartLine, s.EndLine)
				}
			}
			return
		}
		t.Fatal("no KafkaTopic rule")
	})
}
