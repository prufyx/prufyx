// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/cncfcheck"
	"github.com/prufyx/prufyx/cli/internal/knowledgefixture"
)

// TestDBVerifySmokeSignedKnowledge runs the documented demo command
//
//	prufyx db verify <package> --profile cncf-projects --bootstrap-root <root.json> --bootstrap-root-digest <sha256>
//
// through the real CLI entry point against a package signed at runtime with a
// throwaway test-only root (no committed key material). A tampered copy and a
// wrong root digest must be refused.
func TestDBVerifySmokeSignedKnowledge(t *testing.T) {
	repo, err := knowledgefixture.NewProjectsRepository(time.Now().UTC().Truncate(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	defer repo.Close()
	index, projects, err := cncfcheck.BuildEmbeddedExternalTargets("4", nil)
	if err != nil {
		t.Fatal(err)
	}
	targets := map[string][]byte{index.Path: index.Bytes}
	for _, p := range projects {
		targets[p.Path] = p.Bytes
	}
	pkg, err := repo.Package(knowledgefixture.ProjectsPackage{Version: 1, Targets: targets})
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	pkgPath := filepath.Join(dir, "knowledge.tar")
	rootPath := filepath.Join(dir, "root.json")
	if err := os.WriteFile(pkgPath, pkg, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(rootPath, repo.Root, 0o600); err != nil {
		t.Fatal(err)
	}
	verify := func(pkgFile, digest string) (int, string, string) {
		var stdout, stderr bytes.Buffer
		code := run(context.Background(), []string{"db", "verify", pkgFile, "--profile", "cncf-projects", "--bootstrap-root", rootPath, "--bootstrap-root-digest", digest}, &stdout, &stderr)
		return code, stdout.String(), stderr.String()
	}

	code, out, errOut := verify(pkgPath, repo.RootDigest)
	if code != 0 || !strings.Contains(out, "knowledge package verification: VERIFIED") || !strings.Contains(out, "profile: cncf-projects") {
		t.Fatalf("verify code=%d stdout=%q stderr=%q", code, out, errOut)
	}

	// Tamper: flip one byte in each of several positions; every copy must be refused.
	for _, off := range []int{len(pkg) / 4, len(pkg) / 2, len(pkg) - 2048} {
		bad := append([]byte(nil), pkg...)
		bad[off] ^= 0xff
		badPath := filepath.Join(dir, "tampered.tar")
		if err := os.WriteFile(badPath, bad, 0o600); err != nil {
			t.Fatal(err)
		}
		code, out, _ := verify(badPath, repo.RootDigest)
		if code == 0 || strings.Contains(out, "VERIFIED") {
			t.Fatalf("tampered package at %d accepted: code=%d stdout=%q", off, code, out)
		}
	}

	// Wrong trusted root digest must refuse the untampered package.
	code, out, _ = verify(pkgPath, strings.Repeat("0", 64))
	if code == 0 || strings.Contains(out, "VERIFIED") {
		t.Fatalf("wrong root digest accepted: code=%d stdout=%q", code, out)
	}
}
