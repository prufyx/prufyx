// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestRangeProposeRefusesBadInvocations(t *testing.T) {
	dir := t.TempDir()
	tree := filepath.Join(dir, "tree")
	if err := os.MkdirAll(filepath.Join(tree, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	repos := filepath.Join(dir, "repos.json")
	if err := os.WriteFile(repos, []byte(`{"projects":{"demo":{"repo":"acme/demo","path":"/nonexistent"}}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	args := func(out, reposFile string) []string {
		return []string{"range-propose", "--rules-repo", dir, "--rules-commit", "0000000000000000000000000000000000000000", "--repos", reposFile, "--out", out}
	}
	for name, argv := range map[string][]string{
		"no flags":        {"range-propose"},
		"extra argument":  append(args(filepath.Join(dir, "out"), repos), "x"),
		"unknown flag":    append(args(filepath.Join(dir, "out"), repos), "--token", "x"),
		"repeated flag":   append(args(filepath.Join(dir, "out"), repos), "--out", dir),
		"work tree out":   args(filepath.Join(tree, "out"), repos),
		"missing repos":   args(filepath.Join(dir, "out"), filepath.Join(dir, "none.json")),
		"no rules commit": args(filepath.Join(dir, "out"), repos),
	} {
		var out bytes.Buffer
		err := run(argv, &out, &out)
		var command *commandError
		if !errors.As(err, &command) || command.code != 2 {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := os.Lstat(filepath.Join(dir, "out")); !os.IsNotExist(err) {
		t.Fatal("a refused run created the output directory")
	}
}
