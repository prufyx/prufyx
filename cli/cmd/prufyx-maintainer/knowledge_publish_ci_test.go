// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"encoding/json"
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

// modeArgs builds the exact option set the daily workflow passes to the CLI
// for one mode. Digests come from the keyless content-digest command.
func modeArgs(t *testing.T, parent, rootDigest, out, revision, version string, layout, live []string) []string {
	t.Helper()
	var stdout, stderr bytes.Buffer
	dig := append([]string{"knowledge-publish", "content-digest", "--profile", "cncf-projects", "--revision", revision}, layout...)
	if err := run(dig, &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	var d struct{ ContentDigest, IndexDigest string }
	if err := json.Unmarshal(stdout.Bytes(), &d); err != nil {
		t.Fatal(err)
	}
	expires := time.Now().UTC().Add(48 * time.Hour).Format(time.RFC3339)
	args := ciReleaseArgs(parent, rootDigest, out, "--ci", "--expires", expires, "--expect-content-digest", d.ContentDigest, "--expect-index-digest", d.IndexDigest)
	// ciReleaseArgs fixes revision 5, version 1 and --first-release: rebuild without them.
	var kept []string
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--first-release":
		case "--revision", "--version":
			i++
		default:
			kept = append(kept, args[i])
		}
	}
	kept = append(kept, "--revision", revision, "--version", version)
	kept = append(kept, layout...)
	return append(kept, live...)
}

func TestKnowledgePublishCIModeFlagSets(t *testing.T) {
	t.Setenv("GITHUB_RUN_ATTEMPT", "1")
	parent, rootDigest := perProjectFixture(t)
	var stdout, stderr bytes.Buffer
	first := filepath.Join(parent, "first")
	if err := run(modeArgs(t, parent, rootDigest, first, "5", "1", []string{"--first-release"}, []string{"--no-live-package"}), &stdout, &stderr); err != nil {
		t.Fatalf("first (no live package): %v", err)
	}
	var fr struct{ PackageDigest string }
	if err := json.Unmarshal(stdout.Bytes(), &fr); err != nil || fr.PackageDigest == "" {
		t.Fatalf("no package digest in %q: %v", stdout.String(), err)
	}
	live := []string{"--previous-package", filepath.Join(first, "cncf-projects-5.tar"), "--expect-previous-package-digest", fr.PackageDigest}
	index := []string{"--previous-index", filepath.Join(first, "knowledge", "cncf", "index.v1.json")}
	for name, tc := range map[string]struct{ layout, live []string }{
		"regular":    {index, live},
		"capability": {[]string{"--first-release"}, live},
		"recovery":   {index, live},
	} {
		t.Run(name, func(t *testing.T) {
			var so, se bytes.Buffer
			out := filepath.Join(parent, "ok-"+name)
			if err := run(modeArgs(t, parent, rootDigest, out, "6", "2", tc.layout, tc.live), &so, &se); err != nil {
				t.Fatalf("%s: %v", name, err)
			}
		})
	}
	zero := "sha256:" + strings.Repeat("0", 64)
	for name, tc := range map[string]struct{ layout, live []string }{
		"first layout without no-live":    {[]string{"--first-release"}, nil},
		"capability without previous":     {[]string{"--first-release"}, nil},
		"regular without previous":        {index, nil},
		"no-live with a previous package": {[]string{"--first-release"}, append([]string{"--no-live-package"}, live...)},
		"no-live over the regular set":    {index, append([]string{"--no-live-package"}, live...)},
		"no-live with only a digest":      {[]string{"--first-release"}, []string{"--no-live-package", "--expect-previous-package-digest", fr.PackageDigest}},
		"capability with a wrong digest":  {[]string{"--first-release"}, []string{"--previous-package", filepath.Join(first, "cncf-projects-5.tar"), "--expect-previous-package-digest", zero}},
	} {
		t.Run("refused "+name, func(t *testing.T) {
			var so, se bytes.Buffer
			out := filepath.Join(parent, "bad-"+strings.ReplaceAll(name, " ", "-"))
			kept := modeArgs(t, parent, rootDigest, out, "6", "2", tc.layout, tc.live)
			if err := run(kept, &so, &se); err == nil {
				t.Fatal("wrong flag set accepted")
			}
			if _, err := os.Stat(out); err == nil {
				t.Fatal("output written for a refused release")
			}
		})
	}
}
