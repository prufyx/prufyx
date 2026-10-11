// SPDX-License-Identifier: AGPL-3.0-only

package crdversions

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/cncfcheck"
	"github.com/prufyx/prufyx/cli/internal/customresources"
	"github.com/prufyx/prufyx/cli/internal/extract"
)

var update = flag.Bool("update", false, "rewrite the golden files")

const (
	fixtureRoot = "testdata/fixture"
	strimziRoot = "testdata/strimzi"
	c0          = "0000000000000000000000000000000000900000"
	c1          = "0000000000000000000000000000000000901000"
	c2          = "0000000000000000000000000000000000902000"
	group       = "fixture.argoproj.io"
)

var derivedAt = time.Date(2026, 10, 4, 0, 0, 0, 0, time.UTC)

type pinnedSource interface {
	extract.PinnedReader
	extract.TagSource
}

func target(t *testing.T, project string) Target {
	t.Helper()
	tg, ok := TargetFor(project)
	if !ok {
		t.Fatalf("no target %s", project)
	}
	return tg
}

func runOn(t *testing.T, project string, src pinnedSource) (*extract.Output, error) {
	t.Helper()
	tg := target(t, project)
	repo, err := extract.ParseRepo(tg.Repo)
	if err != nil {
		t.Fatal(err)
	}
	return extract.Run(context.Background(), New(tg), src, src, extract.Options{Repo: repo, DerivedAt: derivedAt})
}

func mustRun(t *testing.T, project string, src pinnedSource) *extract.Output {
	t.Helper()
	out, err := runOn(t, project, src)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func fixtureOutput(t *testing.T) *extract.Output {
	return mustRun(t, "argo-cd", extract.FixtureReader{Root: fixtureRoot})
}

func pairProof(t *testing.T, p extract.PairRecord) PairProof {
	t.Helper()
	raw, err := json.Marshal(p.Proof)
	if err != nil {
		t.Fatal(err)
	}
	var proof PairProof
	if err := json.Unmarshal(raw, &proof); err != nil {
		t.Fatal(err)
	}
	return proof
}

func fixtureLines(t *testing.T, commit, path string) []string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(fixtureRoot, "github.com/argoproj/argo-cd/commits", commit, filepath.FromSlash(path)))
	if err != nil {
		t.Fatal(err)
	}
	return strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n")
}

// lineOf returns the 1-based line holding want exactly, after start.
func lineOf(t *testing.T, lines []string, want string, start int) int {
	t.Helper()
	for i := start; i < len(lines); i++ {
		if lines[i] == want {
			return i + 1
		}
	}
	t.Fatalf("%q not found", want)
	return 0
}

// The fixture's first pair drops Widget v1alpha2 and stops serving Gadget
// v1beta1: two rules with the right members and spans. Gizmo only moves
// its storage version: no rule, but the proof records it. The second pair
// changes nothing.
func TestCRDGolden(t *testing.T) {
	out := fixtureOutput(t)
	m := out.Manifest
	if len(m.Pairs) != 2 || m.Totals.Derived != 2 || m.Totals.Rules != 2 || m.Totals.Vectors != 6 {
		t.Fatalf("totals %+v", m.Totals)
	}
	first, second := m.Pairs[0], m.Pairs[1]
	if first.FromTag != "v90.0.0" || first.ToTag != "v90.1.0" || second.FromTag != "v90.1.0" || second.ToTag != "v90.2.0" {
		t.Fatalf("pairs %+v %+v", first, second)
	}
	if len(second.Rules) != 0 || len(pairProof(t, second).Removals) != 0 || len(pairProof(t, second).StorageChanges) != 0 {
		t.Fatalf("quiet pair %+v", second)
	}
	widgetID := "argo-cd.crd-version-removal.widgets-fixture-argoproj-io.90-0-0-to-90-1-0"
	gadgetID := "argo-cd.crd-version-removal.gadgets-fixture-argoproj-io.90-0-0-to-90-1-0"
	if !slices.Equal(first.Rules, []string{gadgetID, widgetID}) {
		t.Fatalf("rules %v", first.Rules)
	}
	byID := map[string]extract.Entry{}
	for _, e := range out.Entries {
		byID[e.Rule.ID] = e
	}
	// Widget: v1alpha2 is absent at the later tag.
	w := byID[widgetID]
	if w.Rule.Operator != "forbid_set_member" || !slices.Equal(w.Rule.SetCondition.Members, []string{group + "/v1alpha2/Widget"}) || w.Rule.SetCondition.FactID != "component.argo_cd.custom_resource_versions_set" || w.Rule.Subject.From != "90.0.0" || w.Rule.Subject.To != "90.1.0" || w.Rule.Subject.Component != "pkg:github/argoproj/argo-cd" {
		t.Fatalf("widget rule %+v", w.Rule)
	}
	if w.Rule.NextAction != "change apiVersion of Widget to fixture.argoproj.io/v1 before upgrading to 90.1.0" {
		t.Fatalf("next action %q", w.Rule.NextAction)
	}
	wl := fixtureLines(t, c0, "manifests/crds/widget-crd.yaml")
	wStart := lineOf(t, wl, "  - name: v1alpha2", 0)
	wEnd := lineOf(t, wl, "  - name: v1beta1", 0) - 1
	srcs := w.Rule.Evidence.Sources
	if len(srcs) != 2 || srcs[0].ID != "crd-90-1-0" || srcs[1].ID != "crd-versions-90-0-0" {
		t.Fatalf("widget sources %+v", srcs)
	}
	if !strings.Contains(srcs[1].URL, c0+"/manifests/crds/widget-crd.yaml") || srcs[1].StartLine != wStart || srcs[1].EndLine != wEnd {
		t.Fatalf("widget from span %+v, want %d-%d", srcs[1], wStart, wEnd)
	}
	if !strings.Contains(srcs[0].URL, c1+"/manifests/crds/widget-crd.yaml") || srcs[0].StartLine != 1 || srcs[0].EndLine != len(fixtureLines(t, c1, "manifests/crds/widget-crd.yaml")) {
		t.Fatalf("widget to source %+v", srcs[0])
	}
	// Gadget: v1beta1 becomes served: false; the later source is that line.
	g := byID[gadgetID]
	if !slices.Equal(g.Rule.SetCondition.Members, []string{group + "/v1beta1/Gadget"}) {
		t.Fatalf("gadget members %v", g.Rule.SetCondition.Members)
	}
	gl0, gl1 := fixtureLines(t, c0, "manifests/crds/gadget-crd.yaml"), fixtureLines(t, c1, "manifests/crds/gadget-crd.yaml")
	gStart := lineOf(t, gl0, "  - name: v1beta1", 0)
	served := lineOf(t, gl1, "    served: false", 0)
	srcs = g.Rule.Evidence.Sources
	if len(srcs) != 2 || srcs[0].ID != "crd-versions-90-0-0" || srcs[0].StartLine != gStart || srcs[0].EndLine != len(gl0) ||
		srcs[1].ID != "served-false-v1beta1-90-1-0" || srcs[1].StartLine != served || srcs[1].EndLine != served {
		t.Fatalf("gadget sources %+v (want %d-%d, served line %d)", srcs, gStart, len(gl0), served)
	}
	// The comment line before the entry is not part of the earlier entry.
	if v1End := gStart - 2; gl0[v1End] != "  # v1beta1 is kept for existing clients." {
		t.Fatalf("fixture layout changed: %q", gl0[v1End])
	}
	proof := pairProof(t, first)
	if len(proof.Removals) != 2 || proof.Removals[0].Reason != "unserved" || proof.Removals[1].Reason != "absent" {
		t.Fatalf("removals %+v", proof.Removals)
	}
	if !slices.Equal(proof.StorageChanges, []StorageChange{{CRD: "gizmos." + group, Earlier: "v1beta1", Later: "v1"}}) {
		t.Fatalf("storage changes %+v", proof.StorageChanges)
	}
	for _, e := range out.Entries {
		for _, mem := range e.Rule.SetCondition.Members {
			if strings.Contains(mem, "Gizmo") {
				t.Fatalf("storage-only change emitted: %s", e.Rule.ID)
			}
		}
	}
	golden(t, out)
}

// golden pins every output byte (the code digest, which changes with any
// source edit, masked). Run with -update after a deliberate output change,
// and bump Version.
func golden(t *testing.T, out *extract.Output) {
	t.Helper()
	files, err := out.Files()
	if err != nil {
		t.Fatal(err)
	}
	got := normalize(t, files)
	dir := "testdata/golden"
	if *update {
		_ = os.RemoveAll(dir)
		for name, data := range got {
			p := filepath.Join(dir, filepath.FromSlash(name))
			if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(p, data, 0o644); err != nil {
				t.Fatal(err)
			}
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
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(want, got[name]) {
			t.Fatalf("%s differs from the golden file (run with -update after a deliberate change)", name)
		}
	}
}

func normalize(t *testing.T, files map[string][]byte) map[string][]byte {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(files[extract.FileManifest], &m); err != nil {
		t.Fatal(err)
	}
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
	if err != nil {
		t.Fatal(err)
	}
	out[extract.FileManifest] = raw
	return out
}

// copyFixture copies the golden fixture into a temporary root and returns
// the directory of manifests/crds at commit c1 (the later tag of the first
// pair) for editing.
func copyFixture(t *testing.T) (string, string) {
	t.Helper()
	root := t.TempDir()
	err := filepath.WalkDir(fixtureRoot, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel, _ := filepath.Rel(fixtureRoot, p)
		raw, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		dst := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			return err
		}
		return os.WriteFile(dst, raw, 0o644)
	})
	if err != nil {
		t.Fatal(err)
	}
	return root, filepath.Join(root, "github.com/argoproj/argo-cd/commits", c1, "manifests/crds")
}

func edit(t *testing.T, path string, f func(string) string) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(f(string(raw))), 0o644); err != nil {
		t.Fatal(err)
	}
}

// Every reason a tag's CRD set cannot be read completely withholds the pair
// that reads it: no rule comes from it, and the manifest says why.
func TestCRDWithhold(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(t *testing.T, dir string)
		want   string
	}{
		{"missing listed directory", func(t *testing.T, dir string) { must(t, os.RemoveAll(dir)) }, "listed directory manifests/crds does not exist"},
		{"no manifest file", func(t *testing.T, dir string) {
			for _, f := range []string{"widget-crd.yaml", "gadget-crd.yaml", "more-crds.yaml", "kustomization.yaml"} {
				must(t, os.Remove(filepath.Join(dir, f)))
			}
		}, "holds no CRD manifest file"},
		{"templated file", func(t *testing.T, dir string) {
			edit(t, filepath.Join(dir, "gadget-crd.yaml"), func(s string) string {
				return strings.Replace(s, "app.kubernetes.io/part-of: fixture", "app.kubernetes.io/part-of: \"{{ .Release.Name }}\"", 1)
			})
		}, "contains template syntax"},
		{"v1beta1 CRD", func(t *testing.T, dir string) {
			edit(t, filepath.Join(dir, "gadget-crd.yaml"), func(s string) string {
				return strings.Replace(s, "apiextensions.k8s.io/v1\n", "apiextensions.k8s.io/v1beta1\n", 1)
			})
		}, "only apiextensions.k8s.io/v1 is read"},
		{"duplicate CRD name", func(t *testing.T, dir string) {
			raw, err := os.ReadFile(filepath.Join(dir, "widget-crd.yaml"))
			must(t, err)
			must(t, os.WriteFile(filepath.Join(dir, "widget-copy.yaml"), raw, 0o644))
		}, "is defined in both"},
		{"CRD moved out of the listed paths", func(t *testing.T, dir string) {
			root := filepath.Dir(filepath.Dir(dir))
			must(t, os.MkdirAll(filepath.Join(root, "deploy"), 0o755))
			must(t, os.Rename(filepath.Join(dir, "gadget-crd.yaml"), filepath.Join(root, "deploy", "gadget-crd.yaml")))
		}, "a removed definition cannot be told from a moved one"},
		{"CRD moved into a templated file", func(t *testing.T, dir string) {
			root := filepath.Dir(filepath.Dir(dir))
			raw, err := os.ReadFile(filepath.Join(dir, "gadget-crd.yaml"))
			must(t, err)
			must(t, os.Remove(filepath.Join(dir, "gadget-crd.yaml")))
			must(t, os.MkdirAll(filepath.Join(root, "chart/templates"), 0o755))
			must(t, os.WriteFile(filepath.Join(root, "chart/templates/crds.yaml"), append([]byte("{{- if .Values.crds }}\n"), raw...), 0o644))
		}, "a removed definition cannot be told from a moved one"},
		{"conflicting copy outside the listed paths", func(t *testing.T, dir string) {
			root := filepath.Dir(filepath.Dir(dir))
			raw, err := os.ReadFile(filepath.Join(dir, "gadget-crd.yaml"))
			must(t, err)
			must(t, os.MkdirAll(filepath.Join(root, "deploy"), 0o755))
			must(t, os.WriteFile(filepath.Join(root, "deploy/gadget-copy.yaml"), []byte(strings.Replace(string(raw), "    served: false\n", "    served: true\n", 1)), 0o644))
		}, "deploy/gadget-copy.yaml defines gadgets.fixture.argoproj.io differently from the listed paths"},
		{"anchor", func(t *testing.T, dir string) {
			edit(t, filepath.Join(dir, "gadget-crd.yaml"), func(s string) string {
				return strings.Replace(s, "  scope: Namespaced", "  scope: &s Namespaced", 1)
			})
		}, "not decodable within the strict YAML subset"},
		{"duplicate key", func(t *testing.T, dir string) {
			edit(t, filepath.Join(dir, "gadget-crd.yaml"), func(s string) string {
				return strings.Replace(s, "    served: false\n", "    served: false\n    served: true\n", 1)
			})
		}, "not decodable within the strict YAML subset"},
		{"oversized file", func(t *testing.T, dir string) {
			edit(t, filepath.Join(dir, "gadget-crd.yaml"), func(s string) string { return s + "#" + strings.Repeat("x", MaxFileBytes) + "\n" })
		}, "over the 8388608-byte bound"},
		{"two storage versions", func(t *testing.T, dir string) {
			edit(t, filepath.Join(dir, "gadget-crd.yaml"), func(s string) string {
				return strings.Replace(s, "    served: false\n    storage: false", "    served: false\n    storage: true", 1)
			})
		}, "has 2 storage versions"},
		{"served not a boolean", func(t *testing.T, dir string) {
			edit(t, filepath.Join(dir, "gadget-crd.yaml"), func(s string) string {
				return strings.Replace(s, "    served: false\n", "    served: \"false\"\n", 1)
			})
		}, "does not state served and storage as booleans"},
		{"list document", func(t *testing.T, dir string) {
			must(t, os.WriteFile(filepath.Join(dir, "list.yaml"), []byte("apiVersion: v1\nkind: List\nitems: []\n"), 0o644))
		}, "list items are not read"},
		{"group changes", func(t *testing.T, dir string) {
			edit(t, filepath.Join(dir, "gadget-crd.yaml"), func(s string) string {
				return strings.Replace(s, "    kind: Gadget\n", "    kind: Gadgetry\n", 1)
			})
		}, "names fixture.argoproj.io/Gadget at v90.0.0 and fixture.argoproj.io/Gadgetry"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root, dir := copyFixture(t)
			tc.mutate(t, dir)
			out := mustRun(t, "argo-cd", extract.FixtureReader{Root: root})
			for _, p := range out.Manifest.Pairs {
				if p.ToTag == "v90.2.0" && !strings.HasPrefix(tc.name, "CRD moved") && tc.name != "group changes" {
					// The second pair reads the same (broken) tag first.
					if p.Status != extract.PairWithheld {
						t.Fatalf("second pair %+v", p)
					}
				}
				if p.ToTag != "v90.1.0" {
					continue
				}
				if p.Status != extract.PairWithheld || !strings.Contains(p.Reason, tc.want) || len(p.Rules) != 0 {
					t.Fatalf("pair %s: %s %q, want withheld with %q", p.ToTag, p.Status, p.Reason, tc.want)
				}
				if p.Proof == nil {
					t.Fatal("withheld pair without proof")
				}
			}
			for _, e := range out.Entries {
				if e.Rule.Subject.To == "90.1.0" {
					t.Fatalf("rule %s from a withheld pair", e.Rule.ID)
				}
			}
		})
	}
	// A listed file that does not exist (a file target) withholds too.
	t.Run("missing listed file", func(t *testing.T) {
		root := t.TempDir()
		repo := filepath.Join(root, "github.com/istio/istio")
		for _, c := range []string{c0, c1} {
			must(t, os.MkdirAll(filepath.Join(repo, "commits", c, "manifests/charts/base/files"), 0o755))
		}
		src, err := os.ReadFile(filepath.Join(fixtureRoot, "github.com/argoproj/argo-cd/commits", c0, "manifests/crds/widget-crd.yaml"))
		must(t, err)
		must(t, os.WriteFile(filepath.Join(repo, "commits", c0, "manifests/charts/base/files/crd-all.gen.yaml"), src, 0o644))
		must(t, os.WriteFile(filepath.Join(repo, "tags.json"), []byte(`{"1.30.0":"`+c0+`","1.31.0":"`+c1+`"}`), 0o644))
		out := mustRun(t, "istio", extract.FixtureReader{Root: root})
		if len(out.Manifest.Pairs) != 1 || out.Manifest.Pairs[0].Status != extract.PairWithheld || !strings.Contains(out.Manifest.Pairs[0].Reason, "at 1.31.0: listed file manifests/charts/base/files/crd-all.gen.yaml does not exist") {
			t.Fatalf("%+v", out.Manifest.Pairs)
		}
	})
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

// The proof records, per tag, every CRD with each version's served and
// storage flags and lines, and every file read with its whole-file digest:
// what a later storage-version check reads.
func TestCRDProofInventory(t *testing.T) {
	out := fixtureOutput(t)
	proof := pairProof(t, out.Manifest.Pairs[0])
	for _, inv := range []*Inventory{proof.From, proof.To} {
		if inv == nil || !inv.Complete || inv.Problem != "" {
			t.Fatalf("inventory %+v", inv)
		}
		if len(inv.Paths) != 1 || inv.Paths[0].Path != "manifests/crds" || inv.Paths[0].Kind != "directory" || inv.Paths[0].Files != 4 || inv.Paths[0].Ignored != 1 {
			t.Fatalf("paths %+v", inv.Paths)
		}
		var names []string
		for _, c := range inv.CRDs {
			names = append(names, c.Name)
		}
		if !slices.Equal(names, []string{"doohickeys." + group, "gadgets." + group, "gizmos." + group, "widgets." + group}) {
			t.Fatalf("crds %v", names)
		}
		files := map[string]FileRecord{}
		for _, f := range inv.Files {
			raw, err := os.ReadFile(filepath.Join(fixtureRoot, "github.com/argoproj/argo-cd/commits", inv.Commit, filepath.FromSlash(f.Path)))
			must(t, err)
			sum := sha256.Sum256(raw)
			if f.SHA256 != "sha256:"+hex.EncodeToString(sum[:]) || f.Size != len(raw) || f.Lines != extract.CountLines(raw) {
				t.Fatalf("file record %+v", f)
			}
			files[f.Path] = f
		}
		if k := files["manifests/crds/kustomization.yaml"]; k.CRDs != 0 || k.OtherDocuments != 1 {
			t.Fatalf("kustomization %+v", k)
		}
		if m := files["manifests/crds/more-crds.yaml"]; m.CRDs != 2 || m.Documents != 2 {
			t.Fatalf("more-crds %+v", m)
		}
		for _, c := range inv.CRDs {
			lines := fixtureLines(t, inv.Commit, c.Path)
			if lines[c.VersionsLine-1] != "  versions:" || !strings.HasPrefix(lines[c.StartLine-1], "apiVersion: ") {
				t.Fatalf("%s lines %d %d", c.Name, c.StartLine, c.VersionsLine)
			}
			storage := 0
			for i, v := range c.Versions {
				if lines[v.StartLine-1] != "  - name: "+v.Name {
					t.Fatalf("%s %s starts at %q", c.Name, v.Name, lines[v.StartLine-1])
				}
				want := map[bool]string{true: "true", false: "false"}
				if lines[v.ServedLine-1] != "    served: "+want[v.Served] || lines[v.StorageLine-1] != "    storage: "+want[v.Storage] {
					t.Fatalf("%s %s flag lines", c.Name, v.Name)
				}
				if v.EndLine < v.StorageLine || v.EndLine > len(lines) || strings.HasPrefix(lines[v.EndLine-1], "  #") || lines[v.EndLine-1] == "---" {
					t.Fatalf("%s %s ends at %d", c.Name, v.Name, v.EndLine)
				}
				if i+1 < len(c.Versions) && c.Versions[i+1].StartLine <= v.EndLine {
					t.Fatalf("%s %s overlaps the next entry", c.Name, v.Name)
				}
				if v.Storage {
					storage++
					if c.StorageVersion != v.Name {
						t.Fatalf("%s storage version %s", c.Name, c.StorageVersion)
					}
				}
			}
			if storage != 1 {
				t.Fatalf("%s storage count %d", c.Name, storage)
			}
		}
	}
	// Gizmo's storage moves from v1beta1 to v1 between the inventories.
	gz := func(inv *Inventory) CRD {
		for _, c := range inv.CRDs {
			if c.Kind == "Gizmo" {
				return c
			}
		}
		t.Fatal("no Gizmo")
		return CRD{}
	}
	if gz(proof.From).StorageVersion != "v1beta1" || gz(proof.To).StorageVersion != "v1" {
		t.Fatal("storage versions not recorded")
	}
}

// The output is a pure function of the pinned bytes: two runs are
// byte-identical, extract verify passes, and any byte change of a fixture
// file read, or of an output file, fails verification.
func TestCRDReproducible(t *testing.T) {
	a, err := fixtureOutput(t).Files()
	must(t, err)
	b, err := fixtureOutput(t).Files()
	must(t, err)
	for name := range a {
		if !bytes.Equal(a[name], b[name]) {
			t.Fatalf("%s differs between runs", name)
		}
	}
	tg := target(t, "argo-cd")
	dir := filepath.Join(t.TempDir(), "out")
	must(t, fixtureOutput(t).Write(dir))
	verify := func(root string) []string {
		problems, err := extract.Verify(context.Background(), New(tg), extract.FixtureReader{Root: root}, extract.FixtureReader{Root: root}, dir, nil)
		must(t, err)
		return problems
	}
	if p := verify(fixtureRoot); len(p) != 0 {
		t.Fatalf("verify: %v", p)
	}
	// One byte of a read file: a comment, which changes no rule but the
	// digest every source and read record carries.
	for _, rel := range []string{"commits/" + c0 + "/manifests/crds/more-crds.yaml", "commits/" + c2 + "/manifests/crds/kustomization.yaml"} {
		root, _ := copyFixture(t)
		edit(t, filepath.Join(root, "github.com/argoproj/argo-cd", rel), func(s string) string { return strings.Replace(s, "i", "j", 1) })
		if p := verify(root); len(p) == 0 {
			t.Fatalf("a changed byte in %s was not detected", rel)
		}
	}
	// A changed output file.
	p := filepath.Join(dir, extract.FileCandidates)
	raw, err := os.ReadFile(p)
	must(t, err)
	must(t, os.WriteFile(p, bytes.Replace(raw, []byte("v1alpha2/Widget"), []byte("v1alpha3/Widget"), 1), 0o644))
	if p := verify(fixtureRoot); len(p) == 0 {
		t.Fatal("a tampered candidate was not detected")
	}
}

// The extractor agrees with the reviewed Strimzi rule (Kafka v1beta2 is not
// served by 1.0.0) and with the hand-checked removal and storage lists of
// both fixtures.
func TestCRDOracle(t *testing.T) {
	for _, tc := range []struct {
		project, root, expected string
		rules                   int
	}{
		{"strimzi", strimziRoot, "testdata/oracle-strimzi.json", 10},
		{"argo-cd", fixtureRoot, "testdata/oracle-fixture.json", 2},
	} {
		out := mustRun(t, tc.project, extract.FixtureReader{Root: tc.root})
		if out.Manifest.Totals.Rules != tc.rules || out.Manifest.Totals.Withheld != 0 {
			t.Fatalf("%s totals %+v", tc.project, out.Manifest.Totals)
		}
		dir := filepath.Join(t.TempDir(), "out")
		must(t, out.Write(dir))
		raw, err := os.ReadFile(tc.expected)
		must(t, err)
		diffs, err := Oracle(dir, raw)
		must(t, err)
		if len(diffs) != 0 {
			t.Fatalf("%s oracle:\n%s", tc.project, strings.Join(diffs, "\n"))
		}
		// The oracle detects a missing and an unexpected removal.
		var exp Expected
		must(t, json.Unmarshal(raw, &exp))
		dropped := exp.Removals[0].Member
		exp.Removals = append(exp.Removals[1:], ExpectedRemoval{From: exp.Removals[0].From, To: exp.Removals[0].To, Member: "x.example.io/v9/Nope", Reason: "absent"})
		changed, _ := json.Marshal(exp)
		diffs, err = Oracle(dir, changed)
		must(t, err)
		if len(diffs) != 2 || !strings.HasPrefix(diffs[0], "EXTRA "+dropped) || !strings.HasPrefix(diffs[1], "MISSING x.example.io/v9/Nope") {
			t.Fatalf("oracle diffs %v", diffs)
		}
	}
	// The expected file names the reviewed rule as the pack holds it.
	pack, err := os.ReadFile("../../cncfcheck/data/rules.json")
	must(t, err)
	var doc struct {
		Entries []struct {
			Rule struct {
				ID      string `json:"id"`
				Subject struct {
					Component, From, To string
				} `json:"subject"`
				Condition struct {
					FactID string `json:"factId"`
				} `json:"condition"`
			} `json:"rule"`
		} `json:"entries"`
	}
	must(t, json.Unmarshal(pack, &doc))
	raw, err := os.ReadFile("testdata/oracle-strimzi.json")
	must(t, err)
	var exp Expected
	must(t, json.Unmarshal(raw, &exp))
	found := false
	for _, e := range doc.Entries {
		if e.Rule.ID != exp.Rules[0].Name {
			continue
		}
		found = true
		st := target(t, "strimzi")
		if e.Rule.Subject.Component != st.Component || e.Rule.Subject.From != exp.Rules[0].From || e.Rule.Subject.To != exp.Rules[0].To || e.Rule.Condition.FactID != "component.strimzi.kafka_v1beta2_api_present" {
			t.Fatalf("reviewed rule %+v", e.Rule)
		}
	}
	if !found {
		t.Fatalf("reviewed rule %s is not in the pack", exp.Rules[0].Name)
	}
}

// The custom-resource version set of every target that is not pending
// registration is registered, and no pending target's is; every derived
// rule is UNKNOWN for an input without the fact; only a complete declared
// set can pass.
func TestCandidatesAreUnknownWithoutTheFact(t *testing.T) {
	for _, tg := range Targets {
		pending := slices.Contains(pendingRegistration, tg.Project)
		if cncfcheck.RegisteredFact(tg.FactID()) == pending {
			t.Fatalf("%s: registered %v, pending registration %v", tg.FactID(), !pending, pending)
		}
	}
	out := fixtureOutput(t)
	var vectors []extract.Vector
	for _, v := range out.Vectors {
		vectors = append(vectors, v)
		if v.Kind != extract.VectorUnknownIncomplete {
			continue
		}
		var doc map[string]any
		must(t, json.Unmarshal(v.Input, &doc))
		comp := doc["proposed"].(map[string]any)["components"].([]any)[0].(map[string]any)
		comp["facts"] = []any{}
		raw, err := json.Marshal(doc)
		must(t, err)
		vectors = append(vectors, extract.Vector{Name: v.RuleID + "/no-fact", RuleID: v.RuleID, Kind: "no-fact", Input: raw, Expect: extract.VectorExpect{Status: "UNKNOWN", ReasonCode: "RULE_FACT_UNAVAILABLE"}})
	}
	if err := extract.CheckVectors(out.Entries, vectors, derivedAt); err != nil {
		t.Fatal(err)
	}
}

func TestPairsUseConsecutiveFinalReleases(t *testing.T) {
	tags := func(names ...string) extract.ReleaseIndex {
		var out []extract.Tag
		for i, n := range names {
			out = append(out, extract.Tag{Name: n, Commit: strings.Repeat("a", 39) + string(rune('0'+i))})
		}
		return extract.ReleaseIndex{Tags: out}
	}
	got := func(project string, idx extract.ReleaseIndex) []string {
		var out []string
		for _, p := range New(target(t, project)).Pairs(idx) {
			out = append(out, p.FromTag+">"+p.ToTag)
		}
		return out
	}
	if g := got("strimzi", tags("0.48.0", "0.49.0", "0.50.0", "0.51.0", "0.51.1", "1.0.0-rc1", "1.0.0", "1.1.0", "v1.2.0")); !slices.Equal(g, []string{"0.49.0>0.50.0", "0.50.0>0.51.0", "0.51.0>1.0.0", "1.0.0>1.1.0"}) {
		t.Fatalf("strimzi pairs %v", g)
	}
	if g := got("argo-cd", tags("v2.14.0", "v2.14.1", "v3.0.0", "v3.1.0-rc1", "3.1.0", "v3.1.0", "v3.1.1")); !slices.Equal(g, []string{"v3.0.0>v3.1.0"}) {
		t.Fatalf("argo-cd pairs %v", g)
	}
	// A line is named by its first final release: a line without a .0 tag
	// still forms pairs, and a skipped minor number is skipped.
	if g := got("argo-cd", tags("v3.0.0", "v3.2.1", "v3.2.2", "v3.5.0")); !slices.Equal(g, []string{"v3.0.0>v3.2.1", "v3.2.1>v3.5.0"}) {
		t.Fatalf("argo-cd pairs with gaps %v", g)
	}
	// Two prefixes: the first listed one names a release tagged under both.
	if g := got("kuma", tags("2.9.0", "2.9.1", "v2.9.1", "2.10.0", "v2.11.0")); !slices.Equal(g, []string{"2.9.0>2.10.0", "2.10.0>v2.11.0"}) {
		t.Fatalf("kuma pairs %v", g)
	}
}

// Every final release of a line is part of it; a release tagged under two
// prefixes at different commits makes its line unusable.
func TestReleaseLines(t *testing.T) {
	x := New(target(t, "kuma"))
	idx := extract.ReleaseIndex{Tags: []extract.Tag{
		{Name: "2.9.0", Commit: strings.Repeat("a", 40)},
		{Name: "2.9.1", Commit: strings.Repeat("b", 40)},
		{Name: "v2.9.1", Commit: strings.Repeat("b", 40)},
		{Name: "2.9.2-rc1", Commit: strings.Repeat("c", 40)},
		{Name: "2.10.0", Commit: strings.Repeat("d", 40)},
		{Name: "v2.10.1", Commit: strings.Repeat("e", 40)},
		{Name: "2.10.1", Commit: strings.Repeat("f", 40)},
	}}
	lines := x.releaseLines(idx)
	if len(lines) != 2 || !slices.Equal(lines[0].Versions, []string{"2.9.0", "2.9.1"}) || lines[0].Problem != "" || lines[0].Tags[1].Name != "v2.9.1" {
		t.Fatalf("2.9: %+v", lines[0])
	}
	if !slices.Equal(lines[1].Versions, []string{"2.10.0", "2.10.1"}) || !strings.Contains(lines[1].Problem, "tagged twice") {
		t.Fatalf("2.10: %+v", lines[1])
	}
}

// Every target is a catalog project, its subject component is the
// catalog's identity for it, and ids fit the engine's bounds.
func TestTargetsAreCatalogProjects(t *testing.T) {
	components, err := cncfcheck.CatalogSubjectComponents()
	must(t, err)
	seen := map[string]bool{}
	community := 0
	for _, tg := range Targets {
		switch tg.Catalog {
		case CatalogCNCF:
			if !slices.Contains(components, tg.Component) {
				t.Fatalf("%s: %s is not a catalog subject component", tg.Project, tg.Component)
			}
		case CatalogCommunity:
			// A community target is a community project of the reviewed
			// table, with the same repository, and neither its component
			// nor its slug is a CNCF catalog one.
			community++
			p, ok := customresources.ProjectFor(tg.Project)
			if !ok || !p.Community() || p.Upstream.Repository != "https://"+tg.Repo || p.Upstream.Name != tg.Name || tg.Attest {
				t.Fatalf("%s: community target without its community table entry (%+v)", tg.Project, p)
			}
			if slices.Contains(components, tg.Component) {
				t.Fatalf("%s: %s is a CNCF catalog component", tg.Project, tg.Component)
			}
			if _, err := cncfcheck.Component(tg.Project); err == nil {
				t.Fatalf("%s is a CNCF catalog slug", tg.Project)
			}
		default:
			t.Fatalf("%s: catalog %q", tg.Project, tg.Catalog)
		}
		if _, err := extract.ParseRepo(tg.Repo); err != nil || "pkg:"+strings.Replace(strings.TrimPrefix(tg.Repo, "github.com/"), "", "", 1) != strings.Replace(tg.Component, "pkg:github/", "pkg:", 1) {
			t.Fatalf("%s: repository %s does not match component %s", tg.Project, tg.Repo, tg.Component)
		}
		if seen[tg.Project] || len(tg.ExtractorID()) > 128 || len(tg.Paths) == 0 {
			t.Fatalf("%s: duplicate or invalid", tg.Project)
		}
		seen[tg.Project] = true
	}
	if community == 0 {
		t.Fatal("no community target")
	}
}
