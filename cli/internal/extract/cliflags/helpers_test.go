// SPDX-License-Identifier: AGPL-3.0-only

package cliflags

import (
	"context"
	"encoding/json"
	"fmt"
	"go/token"
	"io/fs"
	"math/rand/v2"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/extract"
)

var (
	commitA = strings.Repeat("a", 40)
	repo    = extract.RepoRef{Key: "github.com/example/project"}
)

// memReader is an in-memory PinnedReader over one commit. Directories are
// derived from the file paths; commits lists gitlink (submodule) paths.
type memReader struct {
	files   map[string][]byte
	commits []string
	order   *rand.Rand // shuffle List results when set
	readErr error
	reads   int
	lists   int
	seen    map[string]bool // commits asked for
	modes   map[string]string
	noRoot  bool // List of the root reports ErrNotFound
}

func newMem(files map[string]string) *memReader {
	m := &memReader{files: map[string][]byte{}}
	for p, c := range files {
		m.files[p] = []byte(c)
	}
	return m
}

func (m *memReader) note(commit string) {
	if m.seen == nil {
		m.seen = map[string]bool{}
	}
	m.seen[commit] = true
}

func (m *memReader) Read(_ extract.RepoRef, commit, p string) ([]byte, error) {
	m.note(commit)
	m.reads++
	if m.readErr != nil {
		return nil, m.readErr
	}
	if d, ok := m.files[p]; ok {
		return d, nil
	}
	return nil, fmt.Errorf("%w: %s", extract.ErrNotFound, p)
}

func (m *memReader) List(_ extract.RepoRef, commit, dir string) ([]extract.TreeEntry, error) {
	m.note(commit)
	m.lists++
	if m.noRoot && dir == "" {
		return nil, fmt.Errorf("%w: root", extract.ErrNotFound)
	}
	seen := map[string]bool{}
	var out []extract.TreeEntry
	add := func(e extract.TreeEntry) {
		if !seen[e.Path+e.Type] {
			seen[e.Path+e.Type] = true
			out = append(out, e)
		}
	}
	prefix := ""
	if dir != "" {
		prefix = dir + "/"
	}
	for p := range m.files {
		if !strings.HasPrefix(p, prefix) {
			continue
		}
		rest := strings.TrimPrefix(p, prefix)
		if first, _, nested := strings.Cut(rest, "/"); nested {
			add(extract.TreeEntry{Mode: "040000", Type: "tree", Path: prefix + first})
		} else {
			mode := "100644"
			if v, ok := m.modes[p]; ok {
				mode = v
			}
			add(extract.TreeEntry{Mode: mode, Type: "blob", Path: p})
		}
	}
	for _, c := range m.commits {
		if !strings.HasPrefix(c, prefix) {
			continue
		}
		first, _, nested := strings.Cut(strings.TrimPrefix(c, prefix), "/")
		if nested {
			add(extract.TreeEntry{Mode: "040000", Type: "tree", Path: prefix + first})
		} else {
			add(extract.TreeEntry{Mode: "160000", Type: "commit", Path: c})
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%w: %s", extract.ErrNotFound, dir)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	if m.order != nil {
		m.order.Shuffle(len(out), func(i, j int) { out[i], out[j] = out[j], out[i] })
	}
	return out, nil
}

const goMod = "module example.com/m\n\ngo 1.22\n"

// scanFiles scans an in-memory module (a go.mod is added unless given).
func scanFiles(t testing.TB, files map[string]string, g guards) *Result {
	t.Helper()
	if _, ok := files["go.mod"]; !ok {
		files["go.mod"] = goMod
	}
	res, err := scan(context.Background(), newMem(files), Target{Repo: repo}, commitA, g)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	return res
}

// ledgerStrings renders the ledger as "CODE item".
func ledgerStrings(l []LedgerEntry) []string {
	out := []string{}
	for _, e := range l {
		out = append(out, e.Code+" "+e.Item)
	}
	return out
}

func binaryByDir(r *Result, dir string) *Binary {
	for i := range r.Binaries {
		if r.Binaries[i].Dir == dir {
			return &r.Binaries[i]
		}
	}
	return nil
}

// ---- golden fixtures ----

type expectFlag struct {
	Withheld   []string `json:"withheld"`
	Hidden     bool     `json:"hidden"`
	Deprecated bool     `json:"deprecated"`
}

type expectBinary struct {
	Dir      string                `json:"dir"`
	Members  []string              `json:"members"`
	Complete bool                  `json:"complete"`
	Class    string                `json:"class"`
	Idioms   []string              `json:"idioms"`
	Flags    map[string]expectFlag `json:"flags"`
}

type expected struct {
	Note     string         `json:"note"`
	Ledger   []string       `json:"ledger"`
	Excluded []string       `json:"excluded"`
	Binaries []expectBinary `json:"binaries"`
}

type fixture struct {
	name    string
	files   map[string]string
	target  Target
	commits []string
	exp     expected
}

func loadFixtures() ([]fixture, error) {
	entries, err := os.ReadDir("testdata")
	if err != nil {
		return nil, err
	}
	var out []fixture
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		root := filepath.Join("testdata", e.Name())
		fx := fixture{name: e.Name(), files: map[string]string{}, target: Target{Repo: repo}}
		err := filepath.WalkDir(filepath.Join(root, "src"), func(p string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return err
			}
			data, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			rel, _ := filepath.Rel(filepath.Join(root, "src"), p)
			fx.files[strings.TrimSuffix(filepath.ToSlash(rel), ".txt")] = string(data)
			return nil
		})
		if err != nil {
			return nil, err
		}
		raw, err := os.ReadFile(filepath.Join(root, "expected.json"))
		if err != nil {
			return nil, err
		}
		dec := json.NewDecoder(strings.NewReader(string(raw)))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&fx.exp); err != nil {
			return nil, fmt.Errorf("%s: %w", e.Name(), err)
		}
		if raw, err := os.ReadFile(filepath.Join(root, "target.json")); err == nil {
			var tj struct {
				Exclude []Exclusion `json:"exclude"`
				Commits []string    `json:"commits"`
			}
			if err := json.Unmarshal(raw, &tj); err != nil {
				return nil, fmt.Errorf("%s: %w", e.Name(), err)
			}
			fx.target.Exclude, fx.commits = tj.Exclude, tj.Commits
		}
		out = append(out, fx)
	}
	return out, nil
}

func (fx fixture) scan(g guards, shuffle *rand.Rand) (*Result, error) {
	m := newMem(fx.files)
	m.commits = fx.commits
	m.order = shuffle
	return scan(context.Background(), m, fx.target, commitA, g)
}

// check compares a result with the fixture's expected file.
func (fx fixture) check(r *Result) error {
	e := fx.exp
	if got := ledgerStrings(r.Ledger); !equal(got, orEmpty(e.Ledger)) {
		return fmt.Errorf("%s: ledger %v, want %v", fx.name, got, e.Ledger)
	}
	var excl []string
	for _, x := range r.Excluded {
		excl = append(excl, x.Dir)
	}
	if !equal(orEmpty(excl), orEmpty(e.Excluded)) {
		return fmt.Errorf("%s: excluded %v, want %v", fx.name, excl, e.Excluded)
	}
	var dirs []string
	for _, b := range r.Binaries {
		dirs = append(dirs, b.Dir)
	}
	var wantDirs []string
	for _, b := range e.Binaries {
		wantDirs = append(wantDirs, b.Dir)
	}
	if !equal(orEmpty(dirs), orEmpty(wantDirs)) {
		return fmt.Errorf("%s: binaries %v, want %v", fx.name, dirs, wantDirs)
	}
	for _, want := range e.Binaries {
		got := binaryByDir(r, want.Dir)
		if !equal(orEmpty(got.Set.Members), orEmpty(want.Members)) {
			return fmt.Errorf("%s %s: members %q, want %q", fx.name, want.Dir, got.Set.Members, want.Members)
		}
		if got.Set.Complete != want.Complete {
			return fmt.Errorf("%s %s: complete %v, want %v", fx.name, want.Dir, got.Set.Complete, want.Complete)
		}
		if got.Class != want.Class {
			return fmt.Errorf("%s %s: class %q, want %q", fx.name, want.Dir, got.Class, want.Class)
		}
		if !equal(orEmpty(got.Idioms), orEmpty(want.Idioms)) {
			return fmt.Errorf("%s %s: idioms %v, want %v", fx.name, want.Dir, got.Idioms, want.Idioms)
		}
		members := map[string]bool{}
		for _, m := range got.Set.Members {
			members[m] = true
		}
		for _, f := range got.Flags {
			wf, listed := want.Flags[f.Name]
			plain := len(f.Withheld) == 0 && !f.Hidden && !f.Deprecated
			switch {
			case plain && listed:
				return fmt.Errorf("%s %s: flag %q has no attributes, want %+v", fx.name, want.Dir, f.Name, wf)
			case plain && !members[f.Name]:
				return fmt.Errorf("%s %s: plain flag %q is not a member", fx.name, want.Dir, f.Name)
			case !plain && !listed:
				return fmt.Errorf("%s %s: flag %q has unexpected attributes %+v", fx.name, want.Dir, f.Name, f)
			case !plain && (!equal(orEmpty(f.Withheld), orEmpty(wf.Withheld)) || f.Hidden != wf.Hidden || f.Deprecated != wf.Deprecated):
				return fmt.Errorf("%s %s: flag %q is %+v, want %+v", fx.name, want.Dir, f.Name, f, wf)
			}
		}
		for n := range want.Flags {
			found := false
			for _, f := range got.Flags {
				found = found || f.Name == n
			}
			if !found {
				return fmt.Errorf("%s %s: flag %q missing", fx.name, want.Dir, n)
			}
		}
	}
	return nil
}

func equal(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func orEmpty(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// runFixtures checks the named fixtures (all when none are named) under g.
func runFixtures(g guards, names ...string) error {
	all, err := loadFixtures()
	if err != nil {
		return err
	}
	byName := map[string]fixture{}
	for _, f := range all {
		byName[f.name] = f
	}
	if len(names) == 0 {
		for _, f := range all {
			names = append(names, f.name)
		}
	}
	for _, n := range names {
		fx, ok := byName[n]
		if !ok {
			return fmt.Errorf("no fixture %q", n)
		}
		res, err := fx.scan(g, nil)
		if err != nil {
			return fmt.Errorf("%s: %w", n, err)
		}
		if err := fx.check(res); err != nil {
			return err
		}
	}
	return nil
}

func newFset() *token.FileSet { return token.NewFileSet() }

func nilCtx() context.Context { return context.Background() }
