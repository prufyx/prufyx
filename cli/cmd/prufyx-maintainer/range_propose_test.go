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
	good := func() []string { return args(filepath.Join(dir, "out"), repos) }
	// empty returns a complete invocation with one flag's value emptied.
	empty := func(flag string) []string {
		argv := good()
		for i := range argv {
			if argv[i] == flag {
				argv[i+1] = ""
			}
		}
		return argv
	}
	const inTree = "range propose: the output directory is inside a git work tree"
	for name, tc := range map[string]struct {
		argv []string
		want string
	}{
		"no flags":        {[]string{"range-propose"}, rangeProposeUsage},
		"extra argument":  {append(good(), "x"), rangeProposeUsage},
		"unknown flag":    {append(good(), "--token", "x"), rangeProposeUsage},
		"no rules repo":   {empty("--rules-repo"), rangeProposeUsage},
		"empty commit":    {empty("--rules-commit"), rangeProposeUsage},
		"no repos file":   {empty("--repos"), rangeProposeUsage},
		"no out":          {empty("--out"), rangeProposeUsage},
		"repeated flag":   {append(good(), "--out", dir), "prufyx-maintainer: duplicate option rejected"},
		"work tree out":   {args(filepath.Join(tree, "out"), repos), inTree},
		"out comes first": {args(filepath.Join(tree, "out"), filepath.Join(dir, "none.json")), inTree},
		"missing repos":   {args(filepath.Join(dir, "out"), filepath.Join(dir, "none.json")), "range propose: projects file unreadable"},
		"no rules commit": {good(), "range propose: the rules commit is not in the rules repository"},
	} {
		var out bytes.Buffer
		err := run(tc.argv, &out, &out)
		var command *commandError
		if !errors.As(err, &command) || command.code != 2 || command.message != tc.want {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := os.Lstat(filepath.Join(dir, "out")); !os.IsNotExist(err) {
		t.Fatal("a refused run created the output directory")
	}
}
