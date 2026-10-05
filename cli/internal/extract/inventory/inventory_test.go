// SPDX-License-Identifier: AGPL-3.0-only

package inventory_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/extract"
	"github.com/prufyx/prufyx/cli/internal/extract/extractcli"
	"github.com/prufyx/prufyx/cli/internal/extract/inventory"
	"github.com/prufyx/prufyx/cli/internal/maintainer/factorymirror"
)

type kase struct{ name, id, fixture string }

var cases = []kase{
	{"feature-gates", "k8s.feature-gate-removal", "../k8sfeaturegates/testdata/fixture"},
	{"served-apis", "k8s.served-api-removal", "../k8sservedapis/testdata/fixture"}, // gitleaks:allow (fixture name, not a secret)
	{"strimzi", "crd.version-removal.strimzi", "../crdversions/testdata/strimzi"},
	{"argo-cd", "crd.version-removal.argo-cd", "../crdversions/testdata/fixture"},
}

func setup(t *testing.T, c kase) (extract.Extractor, extract.RepoRef, extract.FixtureReader) {
	t.Helper()
	spec := extractcli.Catalog()[c.id]
	repo, err := extract.ParseRepo(spec.Repo)
	if err != nil {
		t.Fatal(err)
	}
	return spec.New(0), repo, extract.FixtureReader{Root: c.fixture}
}

func build(t *testing.T, c kase, r extract.PinnedReader, commit string) ([]byte, error) {
	t.Helper()
	ex, repo, _ := setup(t, c)
	return inventory.Build(context.Background(), ex, r, repo, commit)
}

// manifest runs the extractor over its fixture and returns the pairs as the
// manifest records them, proof included.
func pairs(t *testing.T, c kase) []map[string]any {
	t.Helper()
	ex, repo, src := setup(t, c)
	out, err := extract.Run(context.Background(), ex, src, src, extract.Options{Repo: repo, DerivedAt: time.Date(2026, 10, 4, 0, 0, 0, 0, time.UTC)})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := extract.Canonical(out.Manifest.Pairs)
	if err != nil {
		t.Fatal(err)
	}
	var ps []map[string]any
	if err := json.Unmarshal(raw, &ps); err != nil {
		t.Fatal(err)
	}
	return ps
}

func strs(v any) []string {
	var out []string
	for _, x := range v.([]any) {
		out = append(out, x.(string))
	}
	return out
}

func decode(t *testing.T, raw []byte) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func eq(a, b []string) bool {
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

// Acceptance 2: on every fixture commit the inventory matches what the
// extractor itself parsed for its pairs, and is byte-identical when built
// twice.
func TestInventoryMatchesTheExtractorsOwnView(t *testing.T) {
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, _, src := setup(t, c)
			ps := pairs(t, c)
			derived := 0
			for _, p := range ps {
				if p["status"] != "derived" {
					continue
				}
				derived++
				proof := p["proof"].(map[string]any)
				from := decode(t, mustBuild(t, c, src, p["fromCommit"].(string)))
				to := decode(t, mustBuild(t, c, src, p["toCommit"].(string)))
				switch c.name {
				case "feature-gates":
					if !eq(strs(from["declared"]), strs(proof["from"].(map[string]any)["declared"])) {
						t.Fatalf("declared gates differ at %v", p["fromTag"])
					}
					if !eq(strs(to["names"]), strs(proof["to"].(map[string]any)["names"])) {
						t.Fatalf("gate names differ at %v", p["toTag"])
					}
					for _, rm := range proof["removed"].([]any) {
						name := rm.(map[string]any)["gate"].(string)
						if !contains(strs(from["declared"]), name) || contains(strs(to["names"]), name) {
							t.Fatalf("removed gate %s: not in from.declared or still in to.names", name)
						}
					}
				case "served-apis":
					if len(from["gvks"].([]any)) != int(proof["specKindsFrom"].(float64)) || len(to["gvks"].([]any)) != int(proof["specKindsTo"].(float64)) {
						t.Fatalf("served kind counts %d/%d, extractor saw %v/%v", len(from["gvks"].([]any)), len(to["gvks"].([]any)), proof["specKindsFrom"], proof["specKindsTo"])
					}
					for _, rm := range proof["removals"].([]any) {
						r := rm.(map[string]any)
						for _, kind := range strs(r["kinds"]) {
							k := gvkKey(r["group"].(string), r["version"].(string), kind)
							if !hasGVK(from, k) || hasGVK(to, k) {
								t.Fatalf("removed %s: not served at from or still served at to", k)
							}
						}
					}
				default:
					for side, doc := range map[string]map[string]any{"from": from, "to": to} {
						if !sameCRDs(t, doc["crds"], proof[side].(map[string]any)["crds"]) {
							t.Fatalf("%s custom resources differ from the extractor's inventory", side)
						}
					}
				}
				again := mustBuild(t, c, src, p["fromCommit"].(string))
				first := mustBuild(t, c, src, p["fromCommit"].(string))
				if !bytes.Equal(again, first) {
					t.Fatal("two builds differ")
				}
			}
			if derived == 0 {
				t.Fatal("no derived pair to compare with")
			}
		})
	}
}

func mustBuild(t *testing.T, c kase, r extract.PinnedReader, commit string) []byte {
	t.Helper()
	raw, err := build(t, c, r, commit)
	if err != nil {
		t.Fatalf("%s %s: %v", c.name, commit, err)
	}
	return raw
}

func contains(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

func gvkKey(g, v, k string) string { return g + "/" + v + "/" + k }

func hasGVK(doc map[string]any, key string) bool {
	for _, x := range doc["gvks"].([]any) {
		m := x.(map[string]any)
		if gvkKey(m["group"].(string), m["version"].(string), m["kind"].(string)) == key {
			return true
		}
	}
	return false
}

func sameCRDs(t *testing.T, inv, proof any) bool {
	t.Helper()
	project := func(v any) []string {
		var out []string
		for _, x := range v.([]any) {
			m := x.(map[string]any)
			var vs []string
			for _, ver := range m["versions"].([]any) {
				vm := ver.(map[string]any)
				vs = append(vs, vm["name"].(string)+"/"+boolS(vm["served"])+"/"+boolS(vm["storage"]))
			}
			sort.Strings(vs)
			out = append(out, strings.Join([]string{m["name"].(string), m["group"].(string), m["kind"].(string), m["scope"].(string), m["path"].(string), m["storageVersion"].(string), strings.Join(vs, ",")}, "|"))
		}
		sort.Strings(out)
		return out
	}
	return eq(project(inv), project(proof))
}

func boolS(v any) string {
	if v.(bool) {
		return "t"
	}
	return "f"
}

// failing makes chosen reads report a file the mirror does not hold.
type failing struct {
	inner extract.PinnedReader
	path  string
}

func (f failing) Read(repo extract.RepoRef, commit, p string) ([]byte, error) {
	if p == f.path {
		return nil, factorymirror.ErrBlobNotLocal
	}
	return f.inner.Read(repo, commit, p)
}
func (f failing) List(repo extract.RepoRef, commit, dir string) ([]extract.TreeEntry, error) {
	return f.inner.List(repo, commit, dir)
}

// Acceptance 2: any file the extractor needs but cannot read makes the
// inventory incomplete, with no list at all.
func TestInventoryIsIncompleteWhenABlobIsMissing(t *testing.T) {
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, _, src := setup(t, c)
			ps := pairs(t, c)
			var commit string
			for _, p := range ps {
				if p["status"] == "derived" {
					commit = p["fromCommit"].(string)
					break
				}
			}
			// Every file the extractor read at that commit, one at a time.
			reads := readsAt(t, c, commit)
			if len(reads) == 0 {
				t.Fatal("no reads recorded")
			}
			switch c.name {
			case "served-apis":
				// The inventory is the commit's OpenAPI specification; the
				// lifecycle files the removal extractor also reads do not
				// enter it.
				assertIncomplete(t, c, failing{src, "api/openapi-spec/swagger.json"}, commit, "swagger.json")
			case "feature-gates":
				// The walk reads many files; every seventh stands for all.
				for i, p := range reads {
					if i%7 == 0 {
						assertIncomplete(t, c, failing{src, p}, commit, p)
					}
				}
			default:
				for _, p := range reads {
					assertIncomplete(t, c, failing{src, p}, commit, p)
				}
			}
		})
	}
}

func assertIncomplete(t *testing.T, c kase, r extract.PinnedReader, commit, missing string) {
	t.Helper()
	doc, err := build(t, c, r, commit)
	if _, ok := inventory.IsIncomplete(err); !ok || doc != nil {
		t.Fatalf("without %s: doc %d bytes, err %v", missing, len(doc), err)
	}
}

func readsAt(t *testing.T, c kase, commit string) []string {
	t.Helper()
	ex, repo, src := setup(t, c)
	out, err := extract.Run(context.Background(), ex, src, src, extract.Options{Repo: repo, DerivedAt: time.Date(2026, 10, 4, 0, 0, 0, 0, time.UTC)})
	if err != nil {
		t.Fatal(err)
	}
	files, err := out.Files()
	if err != nil {
		t.Fatal(err)
	}
	var paths []string
	for _, line := range strings.Split(string(files["reads/"+commit+".tsv"]), "\n") {
		if line != "" {
			paths = append(paths, strings.SplitN(line, "\t", 2)[0])
		}
	}
	return paths
}

// An unreadable or missing fixture file is incomplete too, and misuse is an
// error, not "incomplete".
func TestInventoryMisuse(t *testing.T) {
	c := cases[2]
	ex, repo, src := setup(t, c)
	ps := pairs(t, c)
	commit := ps[0]["fromCommit"].(string)
	ctx := context.Background()
	if _, err := inventory.Build(ctx, ex, src, repo, "abc"); err == nil || errors.Is(err, nil) {
		t.Fatal("a short commit must be refused")
	} else if _, inc := inventory.IsIncomplete(err); inc {
		t.Fatal("a malformed commit is an error, not incomplete")
	}
	other, _ := extract.ParseRepo("github.com/argoproj/argo-cd")
	if _, err := inventory.Build(ctx, ex, src, other, commit); err == nil {
		t.Fatal("another extractor's repository accepted")
	}
	// A commit the fixture does not hold is an error from the reader, not an inventory.
	if doc, err := inventory.Build(ctx, ex, src, repo, strings.Repeat("a", 40)); err == nil || doc != nil {
		t.Fatalf("unknown commit: %v", err)
	}
	// A specification that does not exist at the commit is incomplete.
	sc := cases[1]
	sex, srepo, ssrc := setup(t, sc)
	dir := t.TempDir()
	copyTree(t, sc.fixture, dir)
	scommit := pairs(t, sc)[0]["fromCommit"].(string)
	if err := os.Remove(filepath.Join(dir, "github.com/kubernetes/kubernetes/commits", scommit, "api/openapi-spec/swagger.json")); err != nil {
		t.Fatal(err)
	}
	_ = ssrc
	doc, err := inventory.Build(ctx, sex, extract.FixtureReader{Root: dir}, srepo, scommit)
	if _, ok := inventory.IsIncomplete(err); !ok || doc != nil {
		t.Fatalf("missing specification: %v", err)
	}
}

func copyTree(t *testing.T, from, to string) {
	t.Helper()
	err := filepath.Walk(from, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(from, p)
		dst := filepath.Join(to, rel)
		if info.IsDir() {
			return os.MkdirAll(dst, 0o755)
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		return os.WriteFile(dst, b, 0o644)
	})
	if err != nil {
		t.Fatal(err)
	}
}
