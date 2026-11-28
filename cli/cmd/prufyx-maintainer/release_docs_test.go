// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func docsExit(t *testing.T, args ...string) (int, string) {
	t.Helper()
	var out, errOut bytes.Buffer
	err := run(append([]string{"release-docs"}, args...), &out, &errOut)
	if err == nil {
		return 0, out.String()
	}
	var ce *commandError
	if !errors.As(err, &ce) {
		t.Fatalf("not a command error: %v", err)
	}
	return ce.code, ce.message
}

func TestReleaseDocsRefusesBadUsage(t *testing.T) {
	cases := [][]string{
		{},
		{"verify"},
		{"check"},
		{"check", "--root", ".", "--mode", "warn"},
		{"check", "--root", ".", "--mode", "release", "--tag", "v1.0.0", "--previous", "v0.9.0"},
		{"check", "--root", ".", "--mode", "cut", "--tag", "v1.0.0", "--previous", "v0.9.0", "--deny-file", "/nonexistent"},
		{"check", "--root", ".", "--mode", "unreleased", "--tag", "v1.0.0"},
		{"check", "--root", ".", "--mode", "unreleased", "--mode", "release"},
		{"check", "--root", ".", "--mode", "unreleased", "extra"},
		{"check", "--root", ".", "--mode", "unreleased", "--blocks-base", ""},
		{"check", "--root", ".", "--mode", "unreleased", "--blocks-base="},
		{"check", "--root", ".", "--mode", "unreleased", "--blocks-base", "HEAD"},
		{"check", "--root", ".", "--mode", "unreleased", "--blocks-base", "0000000000000000000000000000000000000000"},
		{"regen", "--root", ".", "--mode", "unreleased", "--blocks-base", "1111111111111111111111111111111111111111"},
	}
	for _, args := range cases {
		code, msg := docsExit(t, args...)
		if code != 2 {
			t.Errorf("%v: exit %d (%s), want 2", args, code, msg)
		}
	}
	// With a readable deny file the only thing wrong is --blocks-base. The
	// usage text names every flag, so the whole refusal is matched.
	deny := filepath.Join(t.TempDir(), "deny")
	if err := os.WriteFile(deny, []byte("zorblax\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, msg := docsExit(t, "check", "--root", ".", "--mode", "release", "--tag", "v1.0.0", "--previous", "v0.9.0", "--deny-file", deny, "--blocks-base", "1111111111111111111111111111111111111111")
	if code != 2 || !strings.Contains(msg, "--blocks-base belongs to the unreleased mode") {
		t.Errorf("release mode with --blocks-base: exit %d (%s)", code, msg)
	}
}

func TestReleaseDocsFailsClosedOnAnEmptyRoot(t *testing.T) {
	code, msg := docsExit(t, "check", "--root", t.TempDir(), "--mode", "unreleased")
	if code == 0 || !strings.Contains(msg, "release-docs:") {
		t.Fatalf("an empty root passed: %d %s", code, msg)
	}
}

func TestReleaseDocsRegenRefusesBadUsage(t *testing.T) {
	cases := [][]string{
		{"regen"},
		{"regen", "--root", "."},
		{"regen", "--root", ".", "--mode", "release"},
		{"regen", "--root", ".", "--mode", "unreleased", "extra"},
		{"regen", "--root", ".", "--mode", "unreleased", "--tag", "v1.0.0"},
	}
	for _, args := range cases {
		code, msg := docsExit(t, args...)
		if code != 2 {
			t.Errorf("%v: exit %d (%s), want 2", args, code, msg)
		}
	}
}

func TestReleaseDocsRegenRefusesOutsideAGitRepository(t *testing.T) {
	code, msg := docsExit(t, "regen", "--root", t.TempDir(), "--mode", "unreleased")
	if code != 19 || !strings.Contains(msg, "git work tree") {
		t.Fatalf("exit %d: %s", code, msg)
	}
}

func TestReleaseDocsCleansTheGitEnvironmentAndRestoresIt(t *testing.T) {
	t.Setenv("GIT_DIR", "/nonexistent")
	restore, err := hardenGitEnv()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := os.LookupEnv("GIT_DIR"); ok || os.Getenv("GIT_NO_REPLACE_OBJECTS") != "1" || os.Getenv("GIT_CONFIG_GLOBAL") != os.DevNull {
		t.Error("the environment is not cleaned")
	}
	restore()
	if os.Getenv("GIT_DIR") != "/nonexistent" {
		t.Error("the environment is not restored")
	}
}
