// SPDX-License-Identifier: AGPL-3.0-only

package crdversions

import (
	"context"
	"crypto/sha1" //nolint:gosec // synthetic object ids only
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/extract"
)

// memReader serves files keyed "<commit>:<path>".
type memReader map[string][]byte

func (m memReader) Read(_ extract.RepoRef, commit, path string) ([]byte, error) {
	data, ok := m[commit+":"+path]
	if !ok {
		return nil, fmt.Errorf("%w: %s", extract.ErrNotFound, path)
	}
	return data, nil
}

// List derives the directory entries of one commit from the file keys
// (no object ids: nothing is reused).
func (m memReader) List(_ extract.RepoRef, commit, dir string) ([]extract.TreeEntry, error) {
	seen := map[string]bool{}
	var out []extract.TreeEntry
	prefix := commit + ":"
	if dir != "" {
		prefix += dir + "/"
	}
	for k := range m {
		rest, ok := strings.CutPrefix(k, prefix)
		if !ok {
			continue
		}
		name, _, isDir := strings.Cut(rest, "/")
		full := name
		if dir != "" {
			full = dir + "/" + name
		}
		if seen[full] {
			continue
		}
		seen[full] = true
		// Object ids: a blob's names its bytes (so the scan reuses it);
		// a tree's names the commit and directory (never shared).
		typ, id := "blob", sha1.Sum(m[k])
		if isDir {
			typ, id = "tree", sha1.Sum([]byte("tree "+commit+" "+full))
		}
		out = append(out, extract.TreeEntry{Mode: "100644", Type: typ, SHA: hex.EncodeToString(id[:]), Path: full})
	}
	if len(out) == 0 && dir != "" {
		return nil, fmt.Errorf("%w: %s", extract.ErrNotFound, dir)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out, nil
}

// FuzzCRDParse mutates CRD YAML. Parsing never panics; a file that does not
// parse completely withholds every pair that reads it; a pair that is
// derived only forbids versions the earlier file served and the later one
// does not serve.
func FuzzCRDParse(f *testing.F) {
	for _, c := range []string{c0, c1} {
		for _, name := range []string{"widget-crd.yaml", "gadget-crd.yaml", "more-crds.yaml", "kustomization.yaml"} {
			raw, err := os.ReadFile(filepath.Join(fixtureRoot, "github.com/argoproj/argo-cd/commits", c, "manifests/crds", name))
			if err != nil {
				f.Fatal(err)
			}
			f.Add(raw)
		}
	}
	raw, err := os.ReadFile(filepath.Join(strimziRoot, "github.com/strimzi/strimzi-kafka-operator/commits/54081abf97d0e5e524de773b88343756934db1a8/install/cluster-operator/043-Crd-kafkatopic.yaml"))
	if err != nil {
		f.Fatal(err)
	}
	f.Add(raw)
	for _, s := range []string{"", "---\n", "a: &x 1\nb: *x\n", "apiVersion: apiextensions.k8s.io/v1\nkind: CustomResourceDefinition\n", "{{ x }}", "- 1\n- 2\n", "kind: List\n"} {
		f.Add([]byte(s))
	}
	tg, _ := TargetFor("istio")
	repo, _ := extract.ParseRepo(tg.Repo)
	file := tg.Paths[0].Path
	later, err := os.ReadFile(filepath.Join(fixtureRoot, "github.com/argoproj/argo-cd/commits", c1, "manifests/crds/more-crds.yaml"))
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		_, crds, perr := parseFile(file, data)
		if perr != nil {
			if _, ok := asProblem(perr); !ok {
				t.Fatalf("parse error is not a withholding problem: %v", perr)
			}
		}
		pair := extract.VersionPair{Repo: repo, From: "1.30.0", FromTag: "1.30.0", FromCommit: c0, To: "1.31.0", ToTag: "1.31.0", ToCommit: c1}
		res, err := New(tg).Extract(context.Background(), memReader{c0 + ":" + file: data, c1 + ":" + file: later}, pair)
		if perr != nil {
			if _, ok := extract.IsWithheld(err); !ok || len(res.Candidates) != 0 {
				t.Fatalf("unparsable earlier file: %v %d candidates", err, len(res.Candidates))
			}
			return
		}
		if len(crds) == 0 {
			if _, ok := extract.IsWithheld(err); !ok {
				t.Fatalf("no CRD but not withheld: %v", err)
			}
			return
		}
		if _, ok := extract.IsWithheld(err); ok {
			return
		}
		if err != nil {
			t.Fatalf("run error: %v", err)
		}
		served := map[string]bool{}
		for _, c := range crds {
			for _, v := range c.Versions {
				if v.Served {
					served[member(c.Group, v.Name, c.Kind)] = true
				}
			}
		}
		_, after, _ := parseFile(file, later)
		stillServed := map[string]bool{}
		for _, c := range after {
			for _, v := range c.Versions {
				if v.Served {
					stillServed[member(c.Group, v.Name, c.Kind)] = true
				}
			}
		}
		for _, c := range res.Candidates {
			for _, m := range c.Rule.SetCondition.Members {
				if !served[m] || stillServed[m] || !strings.Contains(m, "/") {
					t.Fatalf("candidate forbids %s", m)
				}
			}
		}
	})
}
