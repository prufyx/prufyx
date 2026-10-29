// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/cncfcheck"
	"github.com/prufyx/prufyx/cli/internal/knowledge"
	"github.com/prufyx/prufyx/cli/internal/maintainer/knowledgesign"
)

// perProjectFixture creates a private directory with throwaway role keys.
func perProjectFixture(t *testing.T) (parent, rootDigest string) {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	passphrase := "throwaway cli test passphrase 1"
	init, err := knowledgesign.Init(knowledgesign.InitOptions{KeyDir: filepath.Join(dir, "keys"), RootExpires: time.Now().UTC().Add(48 * time.Hour).Format(time.RFC3339), RootPassphrase: []byte("root key passphrase 123456"), Passphrase: []byte(passphrase)})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "pass"), []byte(passphrase+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir, init.RootDigest
}

func TestMaintainerCLI_PerProjectRelease(t *testing.T) {
	parent, rootDigest := perProjectFixture(t)
	keys := filepath.Join(parent, "keys")
	args := func(revision, version string, extra ...string) []string {
		return append([]string{"knowledge-publish", "release", "--profile", "cncf-projects", "--revision", revision, "--version", version,
			"--root", filepath.Join(keys, "root.json"), "--root-digest", rootDigest,
			"--targets-key", filepath.Join(keys, "targets.key.pem"), "--snapshot-key", filepath.Join(keys, "snapshot.key.pem"), "--timestamp-key", filepath.Join(keys, "timestamp.key.pem"),
			"--passphrase-file", filepath.Join(parent, "pass")}, extra...)
	}
	var stdout, stderr bytes.Buffer
	// Neither a previous index nor --first-release: refused before any output.
	out := filepath.Join(parent, "refused")
	if err := run(args("5", "1", "--output-dir", out), &stdout, &stderr); err == nil {
		t.Fatal("release without a previous index or --first-release accepted")
	}
	if _, err := os.Stat(out); err == nil {
		t.Fatal("output written for a refused release")
	}
	out = filepath.Join(parent, "first")
	stdout.Reset()
	if err := run(args("5", "1", "--first-release", "--output-dir", out), &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout.String(), `"profile":"cncf-projects"`) {
		t.Fatalf("receipt: %.300s", stdout.String())
	}
	if _, err := knowledge.VerifyConstraintsProjects(knowledge.VerifyRequest{PackagePath: filepath.Join(out, "cncf-projects-5.tar"), BootstrapRootPath: filepath.Join(keys, "root.json"), BootstrapRootDigest: rootDigest}); err != nil {
		t.Fatalf("package does not verify: %v", err)
	}
	// The next release from the written index advances the revision; the
	// same revision does not.
	previous := filepath.Join(out, "knowledge", "cncf", "index.v1.json")
	if err := run(args("5", "2", "--previous-index", previous, "--output-dir", filepath.Join(parent, "stale")), &stdout, &stderr); err == nil {
		t.Fatal("a revision that does not advance the previous index was released")
	}
	if err := run(args("6", "2", "--previous-index", previous, "--output-dir", filepath.Join(parent, "next")), &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
}

func TestMaintainerCLI_TargetsDirFeedsPrepareTargets(t *testing.T) {
	parent, rootDigest := perProjectFixture(t)
	exported := filepath.Join(parent, "targets")
	var stdout, stderr bytes.Buffer
	if err := run([]string{"export-knowledge", "--profile", "cncf-projects", "--revision", "5", "--output", exported}, &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(parent, "keys", "root.json")
	common := []string{"knowledge-publish", "prepare-targets", "--root", root, "--root-digest", rootDigest, "--version", "1", "--expires", time.Now().UTC().Add(24 * time.Hour).Truncate(time.Second).Format(time.RFC3339)}
	if err := run(append(common, "--targets-dir", exported, "--output", filepath.Join(parent, "prep")), &stdout, &stderr); err != nil {
		t.Fatalf("targets-dir rejected: %v", err)
	}
	if _, err := os.Stat(filepath.Join(parent, "prep")); err != nil {
		t.Fatal(err)
	}
	index := filepath.Join(exported, "knowledge", "cncf", "index.v1.json")
	// --target and --targets-dir together, or neither, are refused.
	if err := run(append(common, "--target", index, "--targets-dir", exported, "--output", filepath.Join(parent, "both")), &stdout, &stderr); err == nil {
		t.Fatal("both --target and --targets-dir accepted")
	}
	if err := run(append(common, "--output", filepath.Join(parent, "neither")), &stdout, &stderr); err == nil {
		t.Fatal("neither --target nor --targets-dir accepted")
	}
	// The index alone is not a single bundle.
	if err := run(append(common, "--target", index, "--output", filepath.Join(parent, "asbundle")), &stdout, &stderr); err == nil {
		t.Fatal("index accepted as a single bundle")
	}
	// A stray file in a project directory, and a missing project target are refused.
	parsed, err := cncfcheck.ParseExternalIndex(mustRead(t, index))
	if err != nil {
		t.Fatal(err)
	}
	stray := filepath.Join(exported, "knowledge", "cncf", "projects", "stray.txt")
	if err := os.WriteFile(stray, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := run(append(common, "--targets-dir", exported, "--output", filepath.Join(parent, "stray")), &stdout, &stderr); err == nil {
		t.Fatal("stray file accepted")
	}
	if err := os.Remove(stray); err != nil {
		t.Fatal(err)
	}
	first := parsed.Entries()[0]
	if err := os.Remove(filepath.Join(exported, filepath.FromSlash(first.TargetPath))); err != nil {
		t.Fatal(err)
	}
	if err := run(append(common, "--targets-dir", exported, "--output", filepath.Join(parent, "missing")), &stdout, &stderr); err == nil {
		t.Fatal("missing project target accepted")
	}
}
