// SPDX-License-Identifier: AGPL-3.0-only

package crdversions

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/extract"
)

func shippedRedisTarget(t *testing.T) Target {
	t.Helper()
	for _, tg := range Targets {
		if tg.Project == literalKustomizationProject {
			return tg
		}
	}
	t.Fatal("no shipped Redis Operator target")
	return Target{}
}

// Only the Redis Operator target declares the literal comment exception, with
// exactly the reviewed paths and no exclusion beside it.
func TestShippedLiteralKustomizationDeclaration(t *testing.T) {
	for _, tg := range Targets {
		if tg.Project != literalKustomizationProject && tg.LiteralKustomization != nil {
			t.Fatalf("%s declares a literal Kustomization", tg.Project)
		}
	}
	tg := shippedRedisTarget(t)
	want := &LiteralKustomization{Path: literalKustomizationPath, Makefile: "Makefile", Default: "config/default/kustomization.yaml"}
	if !reflect.DeepEqual(tg.LiteralKustomization, want) {
		t.Fatalf("declaration = %+v", tg.LiteralKustomization)
	}
	if !tg.Attest || tg.Repo != literalKustomizationRepo || tg.Catalog != CatalogCommunity || tg.MinFrom != [2]int{0, 22} || len(tg.Exclude) != 0 {
		t.Fatalf("target = %+v", tg)
	}
}

func TestShippedLiteralKustomizationRefusesChangedDeclaration(t *testing.T) {
	raw, err := os.ReadFile("target-redis-operator.json")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := LoadTarget("target-redis-operator.json", raw); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string][2]string{
		"other path":     {`"path": "config/rbac/kustomization.yaml"`, `"path": "config/manager/kustomization.yaml"`},
		"other makefile": {`"makefile": "Makefile"`, `"makefile": "hack/Makefile"`},
		"other default":  {`"default": "config/default/kustomization.yaml"`, `"default": "config/crd/kustomization.yaml"`},
		"unknown member": {`"makefile": "Makefile"`, `"makefile": "Makefile", "commit": "x"`},
		"other repo":     {`"repo": "github.com/ot-container-kit/redis-operator"`, `"repo": "github.com/example/redis-operator"`},
	} {
		t.Run(name, func(t *testing.T) {
			bad := strings.Replace(string(raw), change[0], change[1], 1)
			if bad == string(raw) {
				t.Fatal("the mutation did not apply")
			}
			if _, err := LoadTarget("target-redis-operator.json", []byte(bad)); err == nil {
				t.Fatal("changed declaration was accepted")
			}
		})
	}
}

// The shipped declaration accepts the pinned v0.23.0 sources and nothing that
// differs from them.
func TestShippedLiteralKustomizationProof(t *testing.T) {
	pin := literalKustomizationPins[0]
	repo, err := extract.ParseRepo(literalKustomizationRepo)
	if err != nil {
		t.Fatal(err)
	}
	type tree struct {
		tag, commit string
		files       map[string][]byte
		modes       map[string]string
	}
	prove := func(t *testing.T, change func(*tree)) map[string]bool {
		t.Helper()
		tr := tree{tag: pin.Tag, commit: pin.Commit, files: map[string][]byte{}, modes: map[string]string{}}
		for _, p := range []string{"Makefile", "config/default/kustomization.yaml", literalKustomizationPath} {
			b, err := os.ReadFile(filepath.Join("testdata/literal-kustomization/v023", filepath.FromSlash(p)))
			if err != nil {
				t.Fatal(err)
			}
			tr.files[p] = b
		}
		if change != nil {
			change(&tr)
		}
		reader := memReader{}
		var entries []extract.TreeEntry
		for p, b := range tr.files {
			reader[tr.commit+":"+p] = b
			mode := tr.modes[p]
			if mode == "" {
				mode = "100644"
			}
			entries = append(entries, extract.TreeEntry{Path: p, Type: "blob", Mode: mode})
		}
		got, err := New(shippedRedisTarget(t)).literalKustomizationProof(reader, repo, tr.commit, tr.tag, entries)
		if err != nil {
			t.Fatal(err)
		}
		return got
	}
	if got := prove(t, nil); !reflect.DeepEqual(got, map[string]bool{literalKustomizationPath: true}) {
		t.Fatalf("pinned sources: proof = %v", got)
	}
	add := func(p, data string) func(*tree) {
		return func(tr *tree) { tr.files[p] = []byte(data) }
	}
	appendTo := func(p string) func(*tree) {
		return func(tr *tree) { tr.files[p] = append(tr.files[p], '\n') }
	}
	for name, change := range map[string]func(*tree){
		"unpinned earlier line":  func(tr *tree) { tr.tag, tr.commit = "v0.22.2", "e23140a8522f8e6f1aac2cdf51dfe560c0e90004" },
		"unpinned patch release": func(tr *tree) { tr.tag = "v0.23.1" },
		"moved tag":              func(tr *tree) { tr.commit = strings.Repeat("0", 40) },
		"tag of another pin":     func(tr *tree) { tr.tag = literalKustomizationPins[1].Tag },
		"changed source":         appendTo(literalKustomizationPath),
		"changed Makefile":       appendTo("Makefile"),
		"changed default":        appendTo("config/default/kustomization.yaml"),
		"missing source":         func(tr *tree) { delete(tr.files, literalKustomizationPath) },
		"missing Makefile":       func(tr *tree) { delete(tr.files, "Makefile") },
		"missing default":        func(tr *tree) { delete(tr.files, "config/default/kustomization.yaml") },
		"linked source":          func(tr *tree) { tr.modes[literalKustomizationPath] = "120000" },
		// A second reference to the directory is refused, whatever reads it.
		"second directory referrer": add("config/other/kustomization.yaml", "resources:\n- ../rbac\n"),
		"second file referrer":      add("config/other/kustomization.yaml", "resources:\n- ../rbac/kustomization.yaml\n"),
		"component referrer":        add("config/other/kustomization.yaml", "components:\n- ../rbac\n"),
		"chart referrer":            add("charts/x/Chart.yaml", "dependencies:\n- repository: file://../../config/rbac\n"),
		"document command":          add("README.md", "```sh\nkubectl apply -k config/rbac\n```\n"),
		"shell command":             add("hack/install.sh", "#!/bin/sh\nkubectl apply -k config/rbac\n"),
		"container copy":            add("Dockerfile", "FROM scratch\nCOPY config/rbac /rbac\n"),
		"embedding program":         add("embed.go", "package x\n\nimport \"embed\"\n\n//go:embed config/rbac\nvar f embed.FS\n"),
	} {
		t.Run(name, func(t *testing.T) {
			if got := prove(t, change); got != nil {
				t.Fatalf("proof = %v", got)
			}
		})
	}
}
