// SPDX-License-Identifier: AGPL-3.0-only

package crdschema

import (
	"fmt"
	"io/fs"
	"os"
	"path"
	"sort"
	"strings"

	"github.com/prufyx/prufyx/cli/internal/extract"
)

var (
	commitA = strings.Repeat("a", 40)
	commitB = strings.Repeat("b", 40)
	repo    = extract.RepoRef{Key: "github.com/example/project"}
)

// memReader is an in-memory PinnedReader. Paths missing from the map are
// extract.ErrNotFound.
type memReader struct {
	files   map[string]map[string][]byte // commit -> path -> bytes
	modes   map[string]string            // path -> git mode override
	reverse bool                         // list in reverse order
	readErr error                        // returned by every Read when set
	trees   []string                     // directory entries listed at every commit
}

func newMem() *memReader {
	return &memReader{files: map[string]map[string][]byte{}, modes: map[string]string{}}
}

func (m *memReader) put(commit, p string, data []byte) {
	if m.files[commit] == nil {
		m.files[commit] = map[string][]byte{}
	}
	m.files[commit][p] = data
}

func (m *memReader) Read(_ extract.RepoRef, commit, p string) ([]byte, error) {
	if m.readErr != nil {
		return nil, m.readErr
	}
	if d, ok := m.files[commit][p]; ok {
		return d, nil
	}
	return nil, fmt.Errorf("%w: %s", extract.ErrNotFound, p)
}

func (m *memReader) List(_ extract.RepoRef, commit, dir string) ([]extract.TreeEntry, error) {
	var out []extract.TreeEntry
	for p := range m.files[commit] {
		if path.Dir(p) == dir {
			mode := "100644"
			if v, ok := m.modes[p]; ok {
				mode = v
			}
			out = append(out, extract.TreeEntry{Mode: mode, Type: "blob", Path: p})
		}
	}
	for _, t := range m.trees {
		if path.Dir(t) == dir {
			out = append(out, extract.TreeEntry{Mode: "040000", Type: "tree", Path: t})
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%w: %s", extract.ErrNotFound, dir)
	}
	sort.Slice(out, func(i, j int) bool {
		if m.reverse {
			return out[i].Path > out[j].Path
		}
		return out[i].Path < out[j].Path
	})
	return out, nil
}

type expected struct {
	Fields     []string `json:"fields"`
	Enums      []string `json:"enums"`
	Complete   bool     `json:"complete"`
	Omissions  []string `json:"omissions"`
	Exclusions []string `json:"exclusions"`
	Lossy      bool     `json:"lossy"`
}

type testCase struct {
	name     string
	from, to map[string][]byte // path -> bytes
	trees    []string
	exp      expected
}

var testTarget = Target{Repo: repo, Dirs: []string{"crd"}}

func (c testCase) reader() *memReader {
	m := newMem()
	m.trees = c.trees
	for p, d := range c.from {
		m.put(commitA, p, d)
	}
	for p, d := range c.to {
		m.put(commitB, p, d)
	}
	return m
}

func loadTestdata() ([]testCase, error) {
	entries, err := os.ReadDir("testdata")
	if err != nil {
		return nil, err
	}
	var out []testCase
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		c := testCase{name: e.Name(), from: map[string][]byte{}, to: map[string][]byte{}}
		for side, dst := range map[string]map[string][]byte{"from": c.from, "to": c.to} {
			files, err := fs.ReadDir(os.DirFS("testdata/"+e.Name()+"/"+side), "crd")
			if err != nil {
				return nil, err
			}
			for _, f := range files {
				b, err := os.ReadFile("testdata/" + e.Name() + "/" + side + "/crd/" + f.Name())
				if err != nil {
					return nil, err
				}
				dst["crd/"+f.Name()] = b
			}
		}
		raw, err := os.ReadFile("testdata/" + e.Name() + "/expected.json")
		if err != nil {
			return nil, err
		}
		if err := unmarshalStrict(raw, &c.exp); err != nil {
			return nil, fmt.Errorf("%s: %w", e.Name(), err)
		}
		out = append(out, c)
	}
	return out, nil
}

func simpleCRD(props ...string) []byte {
	var b strings.Builder
	b.WriteString("apiVersion: apiextensions.k8s.io/v1\nkind: CustomResourceDefinition\nmetadata:\n  name: widgets.example.io\nspec:\n  group: example.io\n  names:\n    kind: Widget\n    plural: widgets\n  scope: Namespaced\n  versions:\n  - name: v1\n    served: true\n    storage: true\n    schema:\n      openAPIV3Schema:\n        type: object\n        properties:\n          spec:\n            type: object\n            properties:\n")
	if len(props) == 0 {
		b.WriteString("              k:\n                type: string\n")
	}
	for _, p := range props {
		b.WriteString("              " + p + ":\n                type: string\n")
	}
	return []byte(b.String())
}

func syntheticCases() []testCase {
	var many, manyLess []string
	for i := 0; i < 300; i++ {
		many = append(many, fmt.Sprintf("f%03d", i))
	}
	manyLess = []string{"k"}
	var wantMembers []string
	for i := 0; i < 256; i++ {
		wantMembers = append(wantMembers, fmt.Sprintf("example.io/Widget/spec/f%03d", i))
	}
	nested := "              n:\n"
	for i := 0; i < 70; i++ {
		ind := strings.Repeat(" ", 16+4*i)
		nested += ind + "type: object\n" + ind + "properties:\n" + ind + "  n:\n"
	}
	nested += strings.Repeat(" ", 16+4*70) + "type: string\n"
	deepCRD := append(simpleCRD("k"), []byte(nested)...)
	huge := append(simpleCRD("k"), []byte("#"+strings.Repeat("x", maxFileBytes))...)
	return []testCase{
		{name: "dir_missing_in_to", from: map[string][]byte{"crd/crd.yaml": simpleCRD("k", "x")}, to: map[string][]byte{},
			exp: expected{Omissions: []string{"INVENTORY_FAULT_path_missing|crd|1", "CRD_PRESENCE_UNSTABLE|example.io/Widget|1"}}},
		{name: "unlisted_subtree", trees: []string{"crd/extra"}, from: map[string][]byte{"crd/crd.yaml": simpleCRD("k", "x")}, to: map[string][]byte{"crd/crd.yaml": simpleCRD("k")},
			exp: expected{Fields: []string{"example.io/Widget/spec/x"}, Omissions: []string{"INVENTORY_FAULT_unlisted_subtree|crd/extra|2"}}},
		{name: "too_large_file", from: map[string][]byte{"crd/crd.yaml": simpleCRD("k", "x")}, to: map[string][]byte{"crd/crd.yaml": huge},
			exp: expected{Omissions: []string{"CRD_TOO_LARGE|crd/crd.yaml|1", "CRD_PRESENCE_UNSTABLE|example.io/Widget|1"}}},
		{name: "too_deep_schema", from: map[string][]byte{"crd/crd.yaml": simpleCRD("k", "x")}, to: map[string][]byte{"crd/crd.yaml": deepCRD},
			exp: expected{Omissions: []string{"CRD_TOO_LARGE|example.io/Widget|1"}}},
		{name: "too_many_members", from: map[string][]byte{"crd/crd.yaml": simpleCRD(many...)}, to: map[string][]byte{"crd/crd.yaml": simpleCRD(manyLess...)},
			exp: expected{Fields: wantMembers, Omissions: []string{"MEMBER_SET_TOO_LARGE|fields|1"}}},
	}
}
