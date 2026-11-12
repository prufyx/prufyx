// SPDX-License-Identifier: AGPL-3.0-only

package targetdraft

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// memTree is an in-memory tree used by the offline tests.
type memTree struct {
	files map[string][]byte
	links map[string]string
}

func newMemTree() *memTree {
	return &memTree{files: map[string][]byte{}, links: map[string]string{}}
}

func (m *memTree) clone() *memTree {
	c := newMemTree()
	for k, v := range m.files {
		c.files[k] = v
	}
	for k, v := range m.links {
		c.links[k] = v
	}
	return c
}

func (m *memTree) Entries() ([]Entry, error) {
	var out []Entry
	for p := range m.files {
		out = append(out, Entry{Path: p})
	}
	for p := range m.links {
		out = append(out, Entry{Path: p, IsLink: true})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out, nil
}

func (m *memTree) Read(p string) ([]byte, error) {
	b, ok := m.files[p]
	if !ok {
		return nil, fmt.Errorf("%s: not a file", p)
	}
	return b, nil
}

func (m *memTree) Link(p string) (string, error) {
	l, ok := m.links[p]
	if !ok {
		return "", fmt.Errorf("%s: not a link", p)
	}
	return l, nil
}

// memSource serves one tree per tag.
type memSource struct{ trees map[string]*memTree }

func (s memSource) Open(tag string) (Tree, string, error) {
	t, ok := s.trees[tag]
	if !ok {
		return nil, "", fmt.Errorf("no tag %s", tag)
	}
	sum := sha256.Sum256([]byte("commit " + tag))
	return t, hex.EncodeToString(sum[:20]), nil
}

// loadDir reads a fixture directory into a tree; linksFile (optional) lists
// "path<TAB>target" symbolic links.
func loadDir(t *testing.T, dir, linksFile string) *memTree {
	t.Helper()
	m := newMemTree()
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel, _ := filepath.Rel(dir, p)
		b, err := os.ReadFile(p)
		m.files[filepath.ToSlash(rel)] = b
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if linksFile != "" {
		f, err := os.Open(linksFile)
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			if parts := strings.SplitN(sc.Text(), "\t", 2); len(parts) == 2 {
				m.links[parts[0]] = parts[1]
			}
		}
	}
	return m
}

func readFile(t *testing.T, p string) []byte {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

var knativeTags = []string{"v0.46.9", "v0.47.3", "v0.48.3", "v0.49.1", "v0.50.0", "v0.51.0"}
var traefikTags = []string{"v3.2.5", "v3.3.7", "v3.4.5", "v3.5.6", "v3.6.25", "v3.7.18"}

// knativeSource builds the six knative tags; mutate may change one tree.
func knativeSource(t *testing.T, mutate func(tag string, m *memTree)) memSource {
	base := loadDir(t, "testdata/knative/tree", "testdata/knative/links.txt")
	s := memSource{trees: map[string]*memTree{}}
	for _, tag := range knativeTags {
		m := base.clone()
		if mutate != nil {
			mutate(tag, m)
		}
		s.trees[tag] = m
	}
	return s
}

// traefikSource builds the six traefik tags; the legacy copy exists only at
// v3.4.5 and v3.5.6 as it does upstream.
func traefikSource(t *testing.T, mutate func(tag string, m *memTree)) memSource {
	base := loadDir(t, "testdata/traefik/tree", "")
	legacy := loadDir(t, "testdata/traefik/legacy", "")
	s := memSource{trees: map[string]*memTree{}}
	for _, tag := range traefikTags {
		m := base.clone()
		if tag == "v3.4.5" || tag == "v3.5.6" {
			for k, v := range legacy.files {
				m.files[k] = v
			}
		}
		if mutate != nil {
			mutate(tag, m)
		}
		s.trees[tag] = m
	}
	return s
}

func rulesFrom(t *testing.T, p string) *Rules {
	t.Helper()
	r, err := ParseRules(readFile(t, p))
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func knativeInput(t *testing.T, src Source, rules *Rules) Input {
	return Input{Slug: "knative", Name: "Knative", Repo: "github.com/knative/serving", Catalog: "cncf", Tags: knativeTags, Source: src, Rules: rules}
}

func traefikInput(t *testing.T, src Source, rules *Rules) Input {
	return Input{Slug: "traefik", Name: "traefik", Repo: "github.com/traefik/traefik", Catalog: "community", Tags: traefikTags, Source: src, Rules: rules}
}
