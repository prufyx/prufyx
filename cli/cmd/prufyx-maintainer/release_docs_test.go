// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"errors"
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
	}
	for _, args := range cases {
		code, msg := docsExit(t, args...)
		if code != 2 {
			t.Errorf("%v: exit %d (%s), want 2", args, code, msg)
		}
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
