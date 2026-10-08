// SPDX-License-Identifier: AGPL-3.0-only

package knowledgegate

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestCISyntheticPackagesAreCovered: the tagged suite (build tag
// prufyx_synthetic_knowledge) holds the tests of the first reachable PASS
// and of the pack loaders. CI must run it for every package that has a
// tagged file, and must not filter it by test name: a package or a test the
// run skips guards nothing and cannot fail a merge.
func TestCISyntheticPackagesAreCovered(t *testing.T) {
	const tag = "prufyx_synthetic_knowledge"
	cli := filepath.Join(repoRoot, "cli")
	packages := map[string]bool{}
	err := filepath.WalkDir(cli, func(path string, d fs.DirEntry, err error) error {
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
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, line := range strings.Split(string(raw), "\n") {
			if strings.HasPrefix(line, "//go:build ") && regexp.MustCompile(`\b`+tag+`\b`).MatchString(line) && !strings.Contains(line, "!"+tag) {
				rel, err := filepath.Rel(cli, filepath.Dir(path))
				if err != nil {
					return err
				}
				packages["./"+filepath.ToSlash(rel)+"/"] = true
			}
			if strings.HasPrefix(line, "package ") {
				break
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(packages) == 0 {
		t.Fatal("no file carries the tag; the guard reads the wrong tree")
	}
	raw, err := os.ReadFile(filepath.Join(repoRoot, ".github", "workflows", "ci.yml"))
	if err != nil {
		t.Fatal(err)
	}
	var tagged []string
	for _, line := range strings.Split(string(raw), "\n") {
		if strings.Contains(line, "go test") && strings.Contains(line, "-tags "+tag) {
			tagged = append(tagged, line)
		}
	}
	if len(tagged) != 1 {
		t.Fatalf("ci.yml must have exactly one tagged go test line, has %d", len(tagged))
	}
	line := tagged[0]
	if strings.Contains(line, " -run ") || strings.Contains(line, " -skip ") {
		t.Fatalf("the tagged run is filtered by test name: %s", strings.TrimSpace(line))
	}
	for pkg := range packages {
		if !strings.Contains(line+" ", " "+pkg+" ") {
			t.Errorf("package %s has tagged files, but the tagged CI run does not list it", pkg)
		}
	}
}
