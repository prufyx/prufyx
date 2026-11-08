// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func ciReleaseArgs(parent, rootDigest, out string, extra ...string) []string {
	keys := filepath.Join(parent, "keys")
	return append([]string{"knowledge-publish", "release", "--profile", "cncf-projects", "--revision", "5", "--version", "1", "--first-release",
		"--root", filepath.Join(keys, "root.json"), "--root-digest", rootDigest,
		"--targets-key", filepath.Join(keys, "targets.key.pem"), "--snapshot-key", filepath.Join(keys, "snapshot.key.pem"), "--timestamp-key", filepath.Join(keys, "timestamp.key.pem"),
		"--passphrase-file", filepath.Join(parent, "pass"), "--output-dir", out}, extra...)
}

// The CI environment markers alone never change behaviour: without --ci the
// release behaves exactly like local mode, whatever the run attempt says.
func TestKnowledgePublishCIEnvWithoutFlagIsLocalMode(t *testing.T) {
	parent, rootDigest := perProjectFixture(t)
	t.Setenv("GITHUB_ACTIONS", "true")
	t.Setenv("CI", "true")
	t.Setenv("GITHUB_RUN_ATTEMPT", "2")
	var stdout, stderr bytes.Buffer
	if err := run(ciReleaseArgs(parent, rootDigest, filepath.Join(parent, "out")), &stdout, &stderr); err != nil {
		t.Fatalf("CI environment without --ci changed behaviour: %v", err)
	}
}

// --ci keeps the full fail-closed matrix and writes nothing when refused.
func TestKnowledgePublishCIFlagFailClosed(t *testing.T) {
	parent, rootDigest := perProjectFixture(t)
	expires := time.Now().UTC().Add(48 * time.Hour).Format(time.RFC3339)
	for name, tc := range map[string]struct {
		attempt *string
		extra   []string
	}{
		"missing expires":      {attempt: ptr("1"), extra: nil},
		"missing expectations": {attempt: ptr("1"), extra: []string{"--expires", expires}},
		"run attempt 2":        {attempt: ptr("2"), extra: []string{"--expires", expires}},
		"absent run attempt":   {attempt: nil, extra: []string{"--expires", expires}},
	} {
		t.Run(name, func(t *testing.T) {
			if tc.attempt != nil {
				t.Setenv("GITHUB_RUN_ATTEMPT", *tc.attempt)
			} else {
				t.Setenv("GITHUB_RUN_ATTEMPT", "")
			}
			out := filepath.Join(parent, "refused-"+filepath.Base(t.Name()))
			var stdout, stderr bytes.Buffer
			if err := run(ciReleaseArgs(parent, rootDigest, out, append([]string{"--ci"}, tc.extra...)...), &stdout, &stderr); err == nil {
				t.Fatal("refused case accepted under --ci")
			}
			if _, err := os.Stat(out); err == nil {
				t.Fatal("output written for a refused release")
			}
		})
	}
}

func ptr(s string) *string { return &s }

func refreshArgs(parent, rootDigest, live, out string, extra ...string) []string {
	keys := filepath.Join(parent, "keys")
	return append([]string{"knowledge-publish", "refresh-timestamp", "--profile", "cncf-projects", "--live-package", live,
		"--root", filepath.Join(keys, "root.json"), "--root-digest", rootDigest,
		"--timestamp-key", filepath.Join(keys, "timestamp.key.pem"), "--passphrase-file", filepath.Join(parent, "pass"), "--output-dir", out}, extra...)
}

// A guard refusal of refresh-timestamp names the guard; the text carries no
// path or key material. A refusal that is not a guard stays generic. Neither
// writes output.
func TestKnowledgePublishRefreshRefusalText(t *testing.T) {
	parent, rootDigest := perProjectFixture(t)
	rel := filepath.Join(parent, "rel")
	var stdout, stderr bytes.Buffer
	if err := run(ciReleaseArgs(parent, rootDigest, rel), &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	live := filepath.Join(rel, "cncf-projects-5.tar")
	zero := "sha256:" + strings.Repeat("0", 64)
	out := filepath.Join(parent, "refused-guard")
	err := run(refreshArgs(parent, rootDigest, live, out, "--expect-live-package-digest", zero), &stdout, &stderr)
	if err == nil || !strings.Contains(err.Error(), "refresh refused: live package does not verify against the pinned root") {
		t.Fatalf("guard refusal not surfaced: %v", err)
	}
	for _, bad := range []string{parent, "pem", "passphrase", "BEGIN"} {
		if strings.Contains(err.Error(), bad) {
			t.Fatalf("refusal text carries %q: %v", bad, err)
		}
	}
	// Mandatory digest: omitted is a plain rejection, not a guard.
	out2 := filepath.Join(parent, "refused-nodigest")
	err = run(refreshArgs(parent, rootDigest, live, out2), &stdout, &stderr)
	if err == nil || err.Error() != "knowledge-publish: operation rejected" {
		t.Fatalf("missing digest: %v", err)
	}
	for _, o := range []string{out, out2} {
		if _, e := os.Stat(o); e == nil {
			t.Fatal("output written for a refused refresh")
		}
	}
}
