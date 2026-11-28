// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime/debug"
	"strings"
	"testing"
)

// stampBuild makes the command see a build that recorded the given settings;
// an empty value leaves a setting out.
func stampBuild(t *testing.T, revision, modified string) {
	t.Helper()
	previous := readBuildInfo
	t.Cleanup(func() { readBuildInfo = previous })
	readBuildInfo = func() (*debug.BuildInfo, bool) {
		info := &debug.BuildInfo{}
		for key, value := range map[string]string{"vcs.revision": revision, "vcs.modified": modified} {
			if value != "" {
				info.Settings = append(info.Settings, debug.BuildSetting{Key: key, Value: value})
			}
		}
		return info, true
	}
}

func TestToolRevisionNamesOnlyACleanBuild(t *testing.T) {
	full := strings.Repeat("1", 40)
	for name, tc := range map[string]struct{ revision, modified, want string }{
		"clean":             {full, "false", full},
		"modified":          {full, "true", full + "+modified"},
		"state not stated":  {full, "", "unknown"},
		"state unreadable":  {full, "yes", "unknown"},
		"no revision":       {"", "false", "unknown"},
		"nothing":           {"", "", "unknown"},
		"modified, unnamed": {"", "true", "unknown+modified"},
	} {
		stampBuild(t, tc.revision, tc.modified)
		if got := toolRevision(); got != tc.want {
			t.Errorf("%s: %q, want %q", name, got, tc.want)
		}
	}
	readBuildInfo = func() (*debug.BuildInfo, bool) { return nil, false }
	if got := toolRevision(); got != "unknown" {
		t.Errorf("no build information: %q", got)
	}
}

func TestRangeProposeRunsOnlyFromACleanStampedBuild(t *testing.T) {
	dir := t.TempDir()
	rules := filepath.Join(dir, "rules")
	pack := filepath.Join(rules, "cli", "internal", "cncfcheck", "data", "rules.json")
	if err := os.MkdirAll(filepath.Dir(pack), 0o755); err != nil {
		t.Fatal(err)
	}
	// One withdrawn rule: the run completes without a project clone.
	entry := `{"entries":[{"project":"demo","rule":{"id":"a","operator":"forbid_predicate_value","evidence":{"state":"withdrawn"}}}]}`
	if err := os.WriteFile(pack, []byte(entry), 0o644); err != nil {
		t.Fatal(err)
	}
	git := func(args ...string) string {
		cmd := exec.Command("git", append([]string{"-C", rules}, args...)...)
		cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + dir, "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null",
			"GIT_AUTHOR_NAME=Fixture", "GIT_AUTHOR_EMAIL=fixture@example.invalid", "GIT_COMMITTER_NAME=Fixture",
			"GIT_COMMITTER_EMAIL=fixture@example.invalid"}
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
		return strings.TrimSpace(string(out))
	}
	git("init", "-q")
	git("add", "-A")
	git("commit", "-q", "-m", "rules")
	repos := filepath.Join(dir, "repos.json")
	if err := os.WriteFile(repos, []byte(`{"projects":{"demo":{"repo":"acme/demo","path":"/nonexistent"}}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "out")
	argv := []string{"range-propose", "--rules-repo", rules, "--rules-commit", git("rev-parse", "HEAD"), "--repos", repos, "--out", out}
	full := strings.Repeat("1", 40)
	for _, stamp := range [][2]string{{"", ""}, {full, "true"}, {full, ""}} {
		stampBuild(t, stamp[0], stamp[1])
		var stdout bytes.Buffer
		err := run(argv, &stdout, &stdout)
		var command *commandError
		if !errors.As(err, &command) || command.code != 2 || !strings.Contains(command.message, "tool revision") {
			t.Errorf("stamp %q: %v", stamp, err)
		}
		if _, err := os.Lstat(out); !os.IsNotExist(err) {
			t.Fatalf("stamp %q wrote output", stamp)
		}
	}
	stampBuild(t, full, "false")
	var stdout bytes.Buffer
	if err := run(argv, &stdout, &stdout); err != nil {
		t.Fatal(err)
	}
	proposals, err := os.ReadFile(filepath.Join(out, "proposals.json"))
	if err != nil || !bytes.Contains(proposals, []byte(`"toolRevision": "`+full+`"`)) || !bytes.Contains(proposals, []byte(`"evaluatedAt": "2`)) {
		t.Fatalf("proposals: %v\n%s", err, proposals)
	}
}

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
	stampBuild(t, strings.Repeat("1", 40), "false")
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
