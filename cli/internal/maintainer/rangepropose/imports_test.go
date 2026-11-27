// SPDX-License-Identifier: AGPL-3.0-only

package rangepropose

import (
	"go/parser"
	"go/token"
	"io/fs"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"
)

const (
	modulePath = "github.com/prufyx/prufyx/cli/"
	selfPath   = modulePath + "internal/maintainer/rangepropose"
)

// The package reaches no network code and nothing that publishes or signs.
// Every module package it depends on is listed here, and every listed one is
// a dependency, so the list cannot keep an entry nobody needs.
func TestDependenciesAreOnAnAllowList(t *testing.T) {
	allowed := map[string]bool{
		selfPath: true,
		// The only direct module import: the constraint key, the range types
		// and the basis names, so overlap and candidates follow the engine.
		modulePath + "internal/constraintengine": true,
		// Imported by constraintengine.
		modulePath + "internal/k8sversion": true,
		modulePath + "internal/validation": true,
		// Imported by validation.
		modulePath + "internal/noreplace": true,
	}
	// The one third-party package, imported by validation.
	const allowedThirdParty = "golang.org/x/sys/unix"
	out, err := exec.Command(filepath.Join(runtime.GOROOT(), "bin", "go"), "list", "-deps", ".").Output()
	if err != nil {
		t.Fatalf("go list: %v", err)
	}
	deps := strings.Fields(string(out))
	if !slices.Contains(deps, selfPath) {
		t.Fatalf("unexpected go list answer: %v", deps)
	}
	for dep := range allowed {
		if !slices.Contains(deps, dep) {
			t.Errorf("allow list entry that is not a dependency: %s", dep)
		}
	}
	for _, dep := range deps {
		if strings.HasPrefix(dep, modulePath) && !allowed[dep] {
			t.Errorf("module dependency not on the allow list: %s", dep)
		}
		first, _, _ := strings.Cut(dep, "/")
		if !strings.HasPrefix(dep, modulePath) && strings.Contains(first, ".") && dep != allowedThirdParty {
			t.Errorf("third-party dependency: %s", dep)
		}
		if dep == "net" || dep == "net/http" || dep == "crypto/tls" {
			t.Errorf("network dependency: %s", dep)
		}
	}
}

// Only the maintainer command may import the package.
func TestOnlyTheMaintainerCommandImportsThePackage(t *testing.T) {
	root, err := filepath.Abs("../../..")
	if err != nil {
		t.Fatal(err)
	}
	var importers []string
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == "vendor" || d.Name() == "testdata" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		parsed, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
		if err != nil {
			return err
		}
		for _, spec := range parsed.Imports {
			if name, err := strconv.Unquote(spec.Path.Value); err == nil && name == selfPath {
				rel, err := filepath.Rel(root, filepath.Dir(path))
				if err != nil {
					return err
				}
				importers = append(importers, filepath.ToSlash(rel))
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(importers) == 0 {
		t.Fatal("no importer found")
	}
	for _, dir := range importers {
		if dir != "cmd/prufyx-maintainer" {
			t.Errorf("%s imports the package", dir)
		}
	}
}
