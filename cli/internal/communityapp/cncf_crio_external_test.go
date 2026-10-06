// SPDX-License-Identifier: AGPL-3.0-only

package communityapp

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/knowledge"
	"github.com/prufyx/prufyx/cli/internal/knowledgefixture"
)

type crioExternalFixture struct {
	store, package2, package3 string
	manifest                  knowledgefixture.Manifest
	revision2                 knowledge.ImportReceipt
}

func makeCRIOExternalFixture(t *testing.T) crioExternalFixture {
	t.Helper()
	artifacts, err := knowledgefixture.GenerateCRIOConstraints(time.Now().UTC().Truncate(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	var manifest knowledgefixture.Manifest
	if json.Unmarshal(artifacts.Manifest, &manifest) != nil {
		t.Fatal("manifest")
	}
	dir := t.TempDir()
	store := filepath.Join(dir, "store")
	if os.Mkdir(store, 0700) != nil {
		t.Fatal("store")
	}
	root := writeCNCFFile(t, "crio-root.json", artifacts.Root, 0600)
	package1 := writeCNCFFile(t, "crio-r1.tar", artifacts.Revision1, 0600)
	package2 := writeCNCFFile(t, "crio-r2.tar", artifacts.Revision2, 0600)
	package3 := writeCNCFFile(t, "crio-r3.tar", artifacts.Revision3, 0600)
	if _, err := knowledge.ImportConstraints(knowledge.ImportRequest{PackagePath: package1, StoreRoot: store, BootstrapRootPath: root, BootstrapRootDigest: manifest.BootstrapRoot.Digest, ExpectedRevision: "1", ExpectedBundleDigest: manifest.Revisions[0].BundleDigest}); err != nil {
		t.Fatal(err)
	}
	return crioExternalFixture{store: store, package2: package2, package3: package3, manifest: manifest}
}

func (f *crioExternalFixture) import2(t *testing.T) {
	t.Helper()
	receipt, err := knowledge.ImportConstraints(knowledge.ImportRequest{PackagePath: f.package2, StoreRoot: f.store, ExpectedRevision: "2", ExpectedBundleDigest: f.manifest.Revisions[1].BundleDigest})
	if err != nil {
		t.Fatal(err)
	}
	f.revision2 = receipt
}

func (f *crioExternalFixture) import3(t *testing.T) {
	t.Helper()
	if _, err := knowledge.ImportConstraints(knowledge.ImportRequest{PackagePath: f.package3, StoreRoot: f.store, ExpectedRevision: "3", ExpectedBundleDigest: f.manifest.Revisions[2].BundleDigest}); err != nil {
		t.Fatal(err)
	}
}

func crioExternalArgs(f crioExternalFixture, path, from, to, format string) []string {
	return []string{"check", "cncf", "--project", "cri-o", "--image-status-request", path, "--from", from, "--to", to, "--artifact-operation", "named-reference-resolution", "--knowledge-db", f.store, "--format", format}
}

func TestCRIOArtifactNameRawExternalAuthorityAndHistoricalReplay(t *testing.T) {
	t.Parallel()
	f := makeCRIOExternalFixture(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "image-status-request.json")
	blockedRaw := []byte(`{"image":{"image":"widget:v1"},"secret":"PRIVATE_CRIO_EXTERNAL"}`)
	writeCNCFFileAt(t, path, blockedRaw)
	code, output, stderr := runCNCFCLI(t, crioExternalArgs(f, path, "1.34.0", "1.35.0", "human")...)
	if code != ExitUnknown || stderr != "" || !strings.Contains(output, "no embedded rule was used") {
		t.Fatalf("no fallback code=%d err=%q out=%s", code, stderr, output)
	}
	// The embedded rule's evidence is withdrawn (unverifiable vendored
	// distribution/reference citations), so the embedded route now always
	// reports UNKNOWN (RULE_EVIDENCE_WITHDRAWN) regardless of the supplied
	// reference shape; it no longer BLOCKs on a short reference.
	code, output, stderr = runCNCFCLI(t, crioRawArgs(path, "named-reference-resolution", "human")...)
	if code != ExitUnknown || stderr != "" {
		t.Fatalf("embedded code=%d err=%q out=%s", code, stderr, output)
	}
	code, output, stderr = runCNCFCLI(t, append(crioExternalArgs(f, path, "1.34.0", "1.35.0", "human"), "--now", "2026-09-11T03:00:00Z")...)
	if code != ExitUsage || output != "" || stderr == "" {
		t.Fatalf("external --now code=%d err=%q out=%s", code, stderr, output)
	}

	f.import2(t)
	// The synthetic fixture rule (knowledgefixture.GenerateCRIOConstraints)
	// clones the real embedded cri-o rule, including its now-withdrawn
	// evidence, so this external/synthetic route is UNKNOWN
	// (RULE_EVIDENCE_WITHDRAWN) the same way the embedded route is, for
	// both a short and a fully-qualified reference.
	synthetic := crioExternalArgs(f, path, knowledgefixture.SyntheticCRIOFrom, knowledgefixture.SyntheticCRIOTo, "json")
	code, report, stderr := runCNCFCLI(t, append(synthetic, "--image-status-request-digest", digestCommunityBytes(blockedRaw))...)
	if code != ExitUnknown || stderr != "" || !json.Valid([]byte(report)) || strings.Contains(report, "PRIVATE_CRIO_EXTERNAL") {
		t.Fatalf("current code=%d err=%q out=%s", code, stderr, report)
	}
	fixedRaw := []byte(`{"image":{"image":"registry.example/repository/widget:v1"},"secret":"PRIVATE_CRIO_EXTERNAL"}`)
	writeCNCFFileAt(t, path, fixedRaw)
	code, fixed, stderr := runCNCFCLI(t, append(synthetic, "--image-status-request-digest", digestCommunityBytes(fixedRaw))...)
	if code != ExitUnknown || stderr != "" || !json.Valid([]byte(fixed)) {
		t.Fatalf("fixed code=%d err=%q out=%s", code, stderr, fixed)
	}

	writeCNCFFileAt(t, path, blockedRaw)
	reportPath := filepath.Join(dir, "report.json")
	writeCNCFFileAt(t, reportPath, []byte(report))
	f.import3(t)
	replay := append(crioExternalArgs(f, path, knowledgefixture.SyntheticCRIOFrom, knowledgefixture.SyntheticCRIOTo, "human"), "--image-status-request-digest", digestCommunityBytes(blockedRaw), "--knowledge-revision", "2", "--knowledge-bundle-digest", f.manifest.Revisions[1].BundleDigest, "--knowledge-trust-receipt-digest", f.revision2.TrustReceiptDigest, "--replay-report", reportPath)
	for _, option := range []string{"--image-status-request-digest", "--knowledge-revision", "--knowledge-bundle-digest", "--knowledge-trust-receipt-digest"} {
		incomplete := omitCLIOption(replay, option)
		code, output, stderr = runCNCFCLI(t, incomplete...)
		if code != ExitUsage || output != "" || stderr == "" || strings.Contains(stderr, path) {
			t.Fatalf("missing %s code=%d stdout=%q stderr=%q", option, code, output, stderr)
		}
	}
	// The replayed report still MATCHes (it was saved from this same,
	// now-withdrawn synthetic rule), but its own aggregate readiness is
	// UNKNOWN rather than BLOCKED, so the exit code follows that.
	code, output, stderr = runCNCFCLI(t, replay...)
	if code != ExitUnknown || stderr != "" || !strings.Contains(output, "historical external CRI-O named-reference replay: MATCH") || !strings.Contains(output, "saved report binds minimized intent and reference classification") {
		t.Fatalf("replay code=%d err=%q out=%s", code, stderr, output)
	}
	assertCRIORedacted(t, output, path)
	assertStoreDoesNotContain(t, f.store, []string{"PRIVATE_CRIO_EXTERNAL", path, "secret", "widget:v1", "registry.example"})
}
