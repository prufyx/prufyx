// SPDX-License-Identifier: AGPL-3.0-only

package crdversions

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path"
	"slices"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/prufyx/prufyx/cli/internal/customresources"
	"github.com/prufyx/prufyx/cli/internal/extract"
)

// The code digest of each id covers the package's Go files (tests aside) and
// its own target file, and no other target file; each target file is
// covered by exactly one id, its own.
func TestCodeDigestCoversOwnTargetOnly(t *testing.T) {
	goFiles, err := fs.Glob(source, "*.go")
	must(t, err)
	var code []string
	for _, f := range goFiles {
		if !strings.HasSuffix(f, "_test.go") {
			code = append(code, path.Join(SourceDir, f))
		}
	}
	covered := map[string][]string{}
	for _, tg := range Targets {
		dir, files := New(tg).SourceFiles()
		cf, err := extract.CodeFiles(extract.SourceSet{Dir: dir, Files: files})
		must(t, err)
		var got []string
		for _, f := range cf {
			got = append(got, f.Path)
			if strings.HasSuffix(f.Path, ".json") {
				covered[f.Path] = append(covered[f.Path], tg.ExtractorID())
			}
		}
		want := append(slices.Clone(code), path.Join(SourceDir, TargetFileName(tg.Project)))
		if len(customresources.DefaultIndex().ListingsSharing(tg.Project)) > 0 {
			want = append(want, path.Join(SourceDir, AttributionFileName))
		}
		slices.Sort(want)
		if !slices.Equal(got, want) {
			t.Errorf("%s covers %v, want %v", tg.ExtractorID(), got, want)
		}
	}
	targetFiles, err := fs.Glob(source, targetFilePattern)
	must(t, err)
	if len(targetFiles) != len(Targets) {
		t.Fatalf("%d target files, %d targets", len(targetFiles), len(Targets))
	}
	for _, f := range targetFiles {
		if ids := covered[path.Join(SourceDir, f)]; len(ids) != 1 {
			t.Errorf("%s is covered by %v, want exactly its own id", f, ids)
		}
	}
}

// The view lists nothing but the Go files at its root and the own target
// file, and opens nothing else.
func TestCodeViewHidesOtherFiles(t *testing.T) {
	v := CodeView(syntheticSource(nil), "alpha")
	for _, name := range []string{"target-beta.json", "notes.json", "sub/c.go", "testdata/x.go"} {
		if _, err := fs.ReadFile(v, name); err == nil {
			t.Errorf("%s readable through the view of alpha", name)
		}
	}
	entries, err := fs.ReadDir(v, ".")
	must(t, err)
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	if want := []string{"a.go", "b.go", "b_test.go", "target-alpha.json"}; !slices.Equal(names, want) {
		t.Fatalf("view lists %v, want %v", names, want)
	}
	if _, err := fs.ReadDir(v, "sub"); err == nil {
		t.Fatal("a subdirectory is listed through the view")
	}
}

// syntheticTarget is the target file of a synthetic project.
func syntheticTarget(project, minFrom string) []byte {
	return []byte(fmt.Sprintf(`{
  "schema": %q,
  "target": {
    "project": %q,
    "name": "Synthetic %s",
    "repo": "github.com/example/%s",
    "component": "pkg:github/example/%s",
    "factProject": %q,
    "tagPrefixes": ["v"],
    "minFrom": %q,
    "paths": [
      {"path": "config/crd/bases", "directory": true, "match": "^[^.][^/]*\\.ya?ml$", "guard": "(?i)crd"}
    ],
    "exclude": []
  }
}
`, TargetSchema, project, project, project, project, project, minFrom))
}

// syntheticSource is a package source tree with two targets, alpha and beta;
// edit changes it before it is returned.
func syntheticSource(edit func(fstest.MapFS)) fstest.MapFS {
	fsys := fstest.MapFS{
		"a.go":              {Data: []byte("package synthetic\n\nconst A = 1\n")},
		"b.go":              {Data: []byte("package synthetic\n\nconst B = 2\n")},
		"b_test.go":         {Data: []byte("package synthetic\n")},
		"notes.json":        {Data: []byte("{}\n")},
		"sub/c.go":          {Data: []byte("package sub\n")},
		"target-alpha.json": {Data: syntheticTarget("alpha", "1.0")},
		"target-beta.json":  {Data: syntheticTarget("beta", "2.0")},
	}
	if edit != nil {
		edit(fsys)
	}
	return fsys
}

type syntheticDigest struct {
	Files  []extract.CodeFile `json:"files"`
	Digest string             `json:"digest"`
}

// syntheticDigests computes the per-id code digest of every target of a
// synthetic tree, over the package's own source set (the framework's set,
// shared by every id, is left out so that the golden follows this package
// only).
func syntheticDigests(t *testing.T, fsys fstest.MapFS) map[string]syntheticDigest {
	t.Helper()
	ts, err := LoadTargets(fsys)
	must(t, err)
	out := map[string]syntheticDigest{}
	for _, tg := range ts {
		files, err := extract.CodeFiles(extract.SourceSet{Dir: SourceDir, Files: CodeView(fsys, tg.Project)})
		must(t, err)
		out[tg.ExtractorID()] = syntheticDigest{Files: files, Digest: extract.CodeDigest(files)}
	}
	return out
}

// Per-id code digests on a synthetic target set, pinned in a golden file
// (run with -update after a deliberate change to the digest rule). Adding a
// target, or changing one, moves only that target's id; changing code moves
// every id; a test file or an unrelated JSON file moves none.
func TestPerIDCodeDigestsSynthetic(t *testing.T) {
	scenarios := []struct {
		name string
		edit func(fstest.MapFS)
	}{
		{"base", nil},
		{"target added", func(f fstest.MapFS) {
			f["target-gamma.json"] = &fstest.MapFile{Data: syntheticTarget("gamma", "0.5")}
		}},
		{"target changed", func(f fstest.MapFS) {
			f["target-beta.json"] = &fstest.MapFile{Data: syntheticTarget("beta", "2.1")}
		}},
		{"code changed", func(f fstest.MapFS) {
			f["a.go"] = &fstest.MapFile{Data: []byte("package synthetic\n\nconst A = 3\n")}
		}},
		{"test and other data changed", func(f fstest.MapFS) {
			f["b_test.go"] = &fstest.MapFile{Data: []byte("package synthetic // changed\n")}
			f["notes.json"] = &fstest.MapFile{Data: []byte("{\"changed\": true}\n")}
			f["sub/c.go"] = &fstest.MapFile{Data: []byte("package sub // changed\n")}
		}},
	}
	type scenario struct {
		Name    string                     `json:"name"`
		Digests map[string]syntheticDigest `json:"digests"`
	}
	var all []scenario
	got := map[string]map[string]string{}
	for _, sc := range scenarios {
		d := syntheticDigests(t, syntheticSource(sc.edit))
		all = append(all, scenario{Name: sc.name, Digests: d})
		got[sc.name] = map[string]string{}
		for id, v := range d {
			got[sc.name][id] = v.Digest
		}
	}
	const alpha, beta, gamma = IDPrefix + "alpha", IDPrefix + "beta", IDPrefix + "gamma"
	base := got["base"]
	if base[alpha] == base[beta] {
		t.Fatal("two targets share one digest")
	}
	expect := func(sc, id string, moved bool) {
		t.Helper()
		if (got[sc][id] != base[id]) != moved {
			t.Errorf("%s: %s moved=%v, want %v", sc, id, got[sc][id] != base[id], moved)
		}
	}
	expect("target added", alpha, false)
	expect("target added", beta, false)
	if got["target added"][gamma] == "" {
		t.Error("the added target has no digest")
	}
	expect("target changed", alpha, false)
	expect("target changed", beta, true)
	expect("code changed", alpha, true)
	expect("code changed", beta, true)
	expect("test and other data changed", alpha, false)
	expect("test and other data changed", beta, false)

	raw, err := json.MarshalIndent(all, "", "  ")
	must(t, err)
	raw = append(raw, '\n')
	golden := "testdata/golden-synthetic-code-digests.json"
	if *update {
		must(t, os.WriteFile(golden, raw, 0o644))
		return
	}
	want, err := os.ReadFile(golden)
	must(t, err)
	if !bytes.Equal(raw, want) {
		t.Fatalf("%s differs (run with -update after a deliberate change to the digest rule):\n%s", golden, raw)
	}
}

// The digest folds in the table listings that can change what this project's
// extraction keeps: a change of a sharing project's listing of the target's
// group moves it; an unrelated table edit, and a project without a row, do
// not.
func TestCodeDigestFollowsAttributionOfOwnGroups(t *testing.T) {
	proj := func(slug, group string, kinds []string) customresources.Project {
		return customresources.Project{Slug: slug, Groups: []customresources.Group{{Name: group, Kinds: kinds}}}
	}
	digest := func(project string, ps ...customresources.Project) string {
		t.Helper()
		files, err := extract.CodeFiles(extract.SourceSet{Dir: SourceDir, Files: CodeViewWithIndex(syntheticSource(nil), project, customresources.NewIndex(ps))})
		must(t, err)
		return extract.CodeDigest(files)
	}
	base := []customresources.Project{
		proj("alpha", "shared.example.org", []string{"A"}),
		proj("beta", "shared.example.org", []string{"B"}),
		proj("other", "other.example.org", nil),
	}
	d := digest("alpha", base...)
	if got := digest("alpha", base[0], base[1], proj("other", "other.example.org", []string{"X"}), proj("new", "new.example.org", nil)); got != d {
		t.Error("an unrelated table edit moved the digest")
	}
	if got := digest("alpha", base[0], proj("beta", "shared.example.org", []string{"B", "A2"}), base[2]); got == d {
		t.Error("a change of a sharing listing did not move the digest")
	}
	if got := digest("alpha", base[0], base[1], base[2], proj("gamma", "shared.example.org", []string{"C"})); got == d {
		t.Error("a new project sharing the group did not move the digest")
	}
	if got := digest("alpha", proj("alpha", "shared.example.org", []string{"A", "A2"}), base[1], base[2]); got == d {
		t.Error("a change of the target's own listing did not move the digest")
	}
	// No row: nothing extra is folded in.
	if digest("alpha") != digest("alpha", base[2]) {
		t.Error("a project without a row has a table-dependent digest")
	}
	files, err := extract.CodeFiles(extract.SourceSet{Dir: SourceDir, Files: CodeViewWithIndex(syntheticSource(nil), "alpha", customresources.NewIndex(nil))})
	must(t, err)
	for _, f := range files {
		if strings.HasSuffix(f.Path, AttributionFileName) {
			t.Error("attribution file present for a project without a row")
		}
	}
}
