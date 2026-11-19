// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"archive/tar"
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/cncfcheck"
	"github.com/prufyx/prufyx/cli/internal/communityapp"
	"github.com/prufyx/prufyx/cli/internal/knowledge"
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

	wantRefuse := communityapp.ExitIntegrity
	// Tamper: flip the first byte of the payload of each signed member. The
	// package is rebuilt member by member, so the flip is always inside signed
	// content and never in tar padding.
	members := tarMembers(t, pkg)
	flipped := 0
	for _, name := range []string{"metadata/timestamp.json", "metadata/1.snapshot.json", "metadata/1.targets.json", "targets/"} {
		hit := false
		for _, m := range members {
			if m == name || (strings.HasSuffix(name, "/") && strings.HasPrefix(m, name)) {
				hit = true
				bad := flipMember(t, pkg, m)
				badPath := filepath.Join(dir, "tampered.tar")
				if err := os.WriteFile(badPath, bad, 0o600); err != nil {
					t.Fatal(err)
				}
				code, out, errOut := verify(badPath, repo.RootDigest)
				if code != wantRefuse || strings.Contains(out, "VERIFIED") || !strings.Contains(errOut, "knowledge package verification failed") {
					t.Fatalf("tampered member %s: code=%d stdout=%q stderr=%q", m, code, out, errOut)
				}
				flipped++
				break
			}
		}
		if !hit {
			t.Fatalf("no member matching %s in %v", name, members)
		}
	}
	if flipped != 4 {
		t.Fatalf("flipped %d members", flipped)
	}

	// Wrong trusted root digest: refused, and the refusal is the root digest check.
	wrong := strings.Repeat("0", 64)
	code, out, errOut = verify(pkgPath, wrong)
	if code != wantRefuse || strings.Contains(out, "VERIFIED") || !strings.Contains(errOut, "knowledge package verification failed") {
		t.Fatalf("wrong root digest: code=%d stdout=%q stderr=%q", code, out, errOut)
	}
	_, err = knowledge.VerifyConstraintsProjects(knowledge.VerifyRequest{PackagePath: pkgPath, BootstrapRootPath: rootPath, BootstrapRootDigest: wrong})
	if !errors.Is(err, knowledge.ErrIntegrity) || !strings.Contains(err.Error(), "bootstrap root digest mismatch") {
		t.Fatalf("wrong root digest reason: %v", err)
	}
}

func tarMembers(t *testing.T, raw []byte) []string {
	t.Helper()
	var names []string
	tr := tar.NewReader(bytes.NewReader(raw))
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return names
		}
		if err != nil {
			t.Fatal(err)
		}
		names = append(names, h.Name)
	}
}

// flipMember rebuilds the package with the first payload byte of one member inverted.
func flipMember(t *testing.T, raw []byte, member string) []byte {
	t.Helper()
	var out bytes.Buffer
	tr := tar.NewReader(bytes.NewReader(raw))
	tw := tar.NewWriter(&out)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(tr)
		if err != nil || len(body) == 0 {
			t.Fatalf("member %s: %v", h.Name, err)
		}
		if h.Name == member {
			body[0] ^= 0xff
		}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(body); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}
