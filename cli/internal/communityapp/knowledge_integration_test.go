// SPDX-License-Identifier: AGPL-3.0-only

package communityapp

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/knowledge"
	"github.com/prufyx/prufyx/cli/internal/knowledgefixture"
)

func TestKnowledgeCLIEmptyToActiveAndHistoricalReplay(t *testing.T) {
	t.Parallel()
	artifacts, err := knowledgefixture.Generate(time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	var manifest knowledgefixture.Manifest
	if err := json.Unmarshal(artifacts.Manifest, &manifest); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	store := filepath.Join(dir, "store")
	root := writeKnowledgeFile(t, dir, knowledgefixture.RootName, artifacts.Root, 0o644)
	package1 := writeKnowledgeFile(t, dir, knowledgefixture.Revision1Name, artifacts.Revision1, 0o644)
	package2 := writeKnowledgeFile(t, dir, knowledgefixture.Revision2Name, artifacts.Revision2, 0o644)
	valuesRaw := []byte(`{"syntheticCanary":"` + knowledgefixture.SyntheticCanary() + `","prometheus":{"servicemonitor":{"path":"` + knowledgefixture.SyntheticCanary() + `"}}}`)
	values := writeKnowledgeFile(t, dir, "private-values.json", valuesRaw, 0o600)
	valuesDigest := testDigest(valuesRaw)

	code, stdout, stderr := runKnowledgeCLI(t, "db", "import", package1, "--db-root", store, "--bootstrap-root", root, "--bootstrap-root-digest", manifest.BootstrapRoot.Digest, "--expected-revision", "1", "--expected-bundle-digest", manifest.Revisions[0].BundleDigest, "--format", "json")
	if code != ExitOK || stderr != "" {
		t.Fatalf("revision 1 import code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	var receipt1 knowledge.ImportReceipt
	if err := json.Unmarshal([]byte(stdout), &receipt1); err != nil {
		t.Fatal(err)
	}
	if receipt1.Status != "IMPORTED" || receipt1.TrustReceipt.Purpose != "synthetic_test_only" || !receipt1.SelectionChanged {
		t.Fatalf("receipt1=%#v", receipt1)
	}

	selection1 := []string{"--knowledge-db", store, "--knowledge-revision", "1", "--knowledge-bundle-digest", manifest.Revisions[0].BundleDigest, "--knowledge-trust-receipt-digest", receipt1.TrustReceiptDigest}
	checkArgs := append([]string{"check", "cert-manager-values", "--from", "1.20.3", "--to", "1.21.1", "--values", values, "--values-digest", valuesDigest, "--format", "json"}, selection1...)
	code, report1, stderr := runKnowledgeCLI(t, checkArgs...)
	if code != ExitUnknown || stderr != "" || !strings.Contains(report1, `"reasonCode":"CERT_MANAGER_KNOWLEDGE_RULE_MISSING"`) {
		t.Fatalf("revision 1 check code=%d report=%s stderr=%s", code, report1, stderr)
	}
	if strings.Contains(report1, knowledgefixture.SyntheticCanary()) || strings.Contains(report1, values) {
		t.Fatal("private input crossed the revision 1 report boundary")
	}
	report1Path := writeKnowledgeFile(t, dir, "revision-1-report.json", []byte(strings.TrimSuffix(report1, "\n")), 0o600)

	code, stdout, stderr = runKnowledgeCLI(t, "db", "import", package2, "--db-root", store, "--expected-revision", "2", "--expected-bundle-digest", manifest.Revisions[1].BundleDigest, "--format", "json")
	if code != ExitOK || stderr != "" {
		t.Fatalf("revision 2 import code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	var receipt2 knowledge.ImportReceipt
	if err := json.Unmarshal([]byte(stdout), &receipt2); err != nil {
		t.Fatal(err)
	}
	selection2 := []string{"--knowledge-db", store, "--knowledge-revision", "2", "--knowledge-bundle-digest", manifest.Revisions[1].BundleDigest, "--knowledge-trust-receipt-digest", receipt2.TrustReceiptDigest}
	checkArgs = append([]string{"check", "cert-manager-values", "--from", "1.20.3", "--to", "1.21.1", "--values", values, "--values-digest", valuesDigest, "--format", "json"}, selection2...)
	code, report2, stderr := runKnowledgeCLI(t, checkArgs...)
	if code != ExitBlocked || stderr != "" || !strings.Contains(report2, `"status":"BLOCKED"`) {
		t.Fatalf("revision 2 check code=%d report=%s stderr=%s", code, report2, stderr)
	}
	if strings.Contains(report2, knowledgefixture.SyntheticCanary()) || strings.Contains(report2, values) {
		t.Fatal("private input crossed the revision 2 report boundary")
	}

	replayArgs := append([]string{"check", "cert-manager-values", "--from", "1.20.3", "--to", "1.21.1", "--values", values, "--values-digest", valuesDigest, "--replay-receipt", report1Path, "--format", "json"}, selection1...)
	code, replay, stderr := runKnowledgeCLI(t, replayArgs...)
	if code != ExitUnknown || stderr != "" || !strings.Contains(replay, `"mode":"historical"`) || !strings.Contains(replay, `"status":"MATCH"`) || !strings.Contains(replay, strings.TrimSpace(report1)) {
		t.Fatalf("replay code=%d output=%s stderr=%s", code, replay, stderr)
	}
}

func TestKnowledgeVerifyCLIIsBootstrapOnlyAndRedacted(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC().Truncate(time.Second)
	type fixture struct {
		profile, rootDigest, packageDigest, bundleDigest, revision string
		root, pkg                                                  []byte
	}
	cert, err := knowledgefixture.Generate(now)
	if err != nil {
		t.Fatal(err)
	}
	var certManifest knowledgefixture.Manifest
	if err := json.Unmarshal(cert.Manifest, &certManifest); err != nil {
		t.Fatal(err)
	}
	cncf, err := knowledgefixture.GenerateConstraints(now)
	if err != nil {
		t.Fatal(err)
	}
	var cncfManifest knowledgefixture.Manifest
	if err := json.Unmarshal(cncf.Manifest, &cncfManifest); err != nil {
		t.Fatal(err)
	}
	fixtures := []fixture{
		{profile: "cert-manager", root: cert.Root, pkg: cert.Revision1, rootDigest: certManifest.BootstrapRoot.Digest, packageDigest: testDigest(cert.Revision1), bundleDigest: certManifest.Revisions[0].BundleDigest, revision: "1"},
		{profile: "cncf", root: cncf.Root, pkg: cncf.Revision2, rootDigest: cncfManifest.BootstrapRoot.Digest, packageDigest: testDigest(cncf.Revision2), bundleDigest: cncfManifest.Revisions[1].BundleDigest, revision: "2"},
	}
	for _, f := range fixtures {
		t.Run(f.profile, func(t *testing.T) {
			dir := t.TempDir()
			root := writeKnowledgeFile(t, dir, "PRIVATE-root.json", f.root, 0o600)
			pkg := writeKnowledgeFile(t, dir, "PRIVATE-package.tar", f.pkg, 0o600)
			sentinelStore := filepath.Join(dir, "sentinel-store")
			if err := os.Mkdir(sentinelStore, 0o700); err != nil {
				t.Fatal(err)
			}
			sentinel := writeKnowledgeFile(t, sentinelStore, "unchanged", []byte("sentinel\n"), 0o600)
			before, err := os.ReadFile(sentinel)
			if err != nil {
				t.Fatal(err)
			}
			code, stdout, stderr := runKnowledgeCLI(t, "db", "verify", pkg, "--profile", f.profile,
				"--bootstrap-root", root, "--bootstrap-root-digest", f.rootDigest,
				"--expected-package-digest", f.packageDigest, "--expected-revision", f.revision,
				"--expected-bundle-digest", f.bundleDigest, "--format", "json")
			if code != ExitOK || stderr != "" {
				t.Fatalf("verify code=%d stdout=%s stderr=%s", code, stdout, stderr)
			}
			var receipt knowledge.PackageVerificationReceipt
			if err := json.Unmarshal([]byte(stdout), &receipt); err != nil {
				t.Fatal(err)
			}
			if receipt.Status != "VERIFIED" || receipt.Profile != f.profile || receipt.PackageDigest != f.packageDigest || receipt.TargetDigest != f.bundleDigest || receipt.KnowledgeRevision != f.revision || receipt.NetworkUsed || receipt.StoreUsed || receipt.StoreChanged || receipt.RollbackAgainstStoreChecked || receipt.ImportEligibility != "NOT_EVALUATED" {
				t.Fatalf("receipt=%+v", receipt)
			}
			if strings.Contains(stdout, dir) || strings.Contains(stdout, "PRIVATE-") {
				t.Fatalf("local path crossed verification output: %s", stdout)
			}
			after, err := os.ReadFile(sentinel)
			if err != nil || !bytes.Equal(before, after) {
				t.Fatalf("sentinel changed: %v", err)
			}
			entries, err := os.ReadDir(sentinelStore)
			if err != nil || len(entries) != 1 {
				t.Fatalf("store changed: entries=%v err=%v", entries, err)
			}
			code, stdout, stderr = runKnowledgeCLI(t, "db", "verify", pkg, "--profile", f.profile,
				"--bootstrap-root", root, "--bootstrap-root-digest", f.rootDigest, "--format", "human")
			if code != ExitOK || stderr != "" || !strings.Contains(stdout, "knowledge package verification: VERIFIED") || !strings.Contains(stdout, "rollback against store checked: false") || !strings.Contains(stdout, "import eligibility: NOT_EVALUATED") || strings.Contains(stdout, dir) {
				t.Fatalf("human verify code=%d stdout=%s stderr=%s", code, stdout, stderr)
			}
		})
	}
}

func TestKnowledgeVerifyCLIRejectsStoreModeAndUntrustedRoot(t *testing.T) {
	t.Parallel()
	code, stdout, stderr := runKnowledgeCLI(t, "db", "verify", "/PRIVATE/package.tar", "--db-root", "/PRIVATE/store", "--bootstrap-root", "/PRIVATE/root.json", "--bootstrap-root-digest", strings.Repeat("0", 64))
	if code != ExitUsage || stdout != "" || !strings.Contains(stderr, "invalid database verify arguments") || strings.Contains(stderr, "/PRIVATE/") {
		t.Fatalf("store-mode rejection code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	code, stdout, stderr = runKnowledgeCLI(t, "db", "verify", "/PRIVATE/package.tar", "--profile", "cncf")
	if code != ExitUsage || stdout != "" || !strings.Contains(stderr, "explicit bootstrap-root path and digest") || strings.Contains(stderr, "/PRIVATE/") {
		t.Fatalf("missing root rejection code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	code, stdout, stderr = runKnowledgeCLI(t, "db", "verify", "/PRIVATE/package.tar", "--profile", "unknown", "--bootstrap-root", "/PRIVATE/root.json", "--bootstrap-root-digest", strings.Repeat("0", 64))
	if code != ExitUsage || stdout != "" || !strings.Contains(stderr, "invalid database verify arguments") || strings.Contains(stderr, "/PRIVATE/") {
		t.Fatalf("profile rejection code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
}

func TestKnowledgeVerifyCLIRejectsPackageForOtherFixedProfile(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC().Truncate(time.Second)
	cert, err := knowledgefixture.Generate(now)
	if err != nil {
		t.Fatal(err)
	}
	cncf, err := knowledgefixture.GenerateConstraints(now)
	if err != nil {
		t.Fatal(err)
	}
	var certManifest, cncfManifest knowledgefixture.Manifest
	if err := json.Unmarshal(cert.Manifest, &certManifest); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(cncf.Manifest, &cncfManifest); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name, profile, rootDigest string
		root, pkg                 []byte
	}{
		{name: "cert package as cncf", profile: "cncf", root: cert.Root, pkg: cert.Revision1, rootDigest: certManifest.BootstrapRoot.Digest},
		{name: "cncf package as cert", profile: "cert-manager", root: cncf.Root, pkg: cncf.Revision1, rootDigest: cncfManifest.BootstrapRoot.Digest},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			root := writeKnowledgeFile(t, dir, "PRIVATE-root.json", tc.root, 0o600)
			pkg := writeKnowledgeFile(t, dir, "PRIVATE-package.tar", tc.pkg, 0o600)
			sentinelStore := filepath.Join(dir, "sentinel-store")
			if err := os.Mkdir(sentinelStore, 0o700); err != nil {
				t.Fatal(err)
			}
			sentinel := writeKnowledgeFile(t, sentinelStore, "unchanged", []byte("sentinel\n"), 0o600)
			before, err := os.ReadFile(sentinel)
			if err != nil {
				t.Fatal(err)
			}
			code, stdout, stderr := runKnowledgeCLI(t, "db", "verify", pkg, "--profile", tc.profile,
				"--bootstrap-root", root, "--bootstrap-root-digest", tc.rootDigest, "--format", "json")
			if (code != ExitUsage && code != ExitIntegrity) || stdout != "" || !strings.Contains(stderr, "knowledge package verification failed") || strings.Contains(stderr, dir) || strings.Contains(stderr, "PRIVATE-") {
				t.Fatalf("cross-profile code=%d stdout=%s stderr=%s", code, stdout, stderr)
			}
			after, err := os.ReadFile(sentinel)
			if err != nil || !bytes.Equal(before, after) {
				t.Fatalf("sentinel changed: %v", err)
			}
			entries, err := os.ReadDir(sentinelStore)
			if err != nil || len(entries) != 1 || entries[0].Name() != "unchanged" {
				t.Fatalf("store changed: entries=%v err=%v", entries, err)
			}
		})
	}
}

func TestKnowledgeStatusExitParityForNoSelectionAndReady(t *testing.T) {
	t.Parallel()
	for _, format := range []string{"human", "json"} {
		code, stdout, _ := runKnowledgeCLI(t, "db", "status", "--db-root", filepath.Join(t.TempDir(), "empty-store"), "--format", format)
		if code != ExitUnknown {
			t.Fatalf("empty status format=%s code=%d", format, code)
		}
		if !strings.Contains(stdout, "NO_SELECTION") || !strings.Contains(stdout, "no operator trust root or knowledge revision") || !strings.Contains(stdout, "import a signed package with an explicit bootstrap root") {
			t.Fatalf("empty status format=%s output=%s", format, stdout)
		}
	}
	if code := databaseStatusExit(knowledge.Status{State: "INTEGRITY_FAILURE"}); code != ExitIntegrity {
		t.Fatalf("integrity status code=%d", code)
	}
	if code := databaseStatusExit(knowledge.Status{State: "EXPIRED"}); code != ExitUnknown {
		t.Fatalf("expired status code=%d", code)
	}
	if code := databaseStatusExit(knowledge.Status{State: "READY", CurrentEligible: true}); code != ExitOK {
		t.Fatalf("ready status code=%d", code)
	}
	var human bytes.Buffer
	writeKnowledgeStatusHuman(&human, knowledge.Status{State: "TRUST_ADVANCED", Reason: "trusted metadata advanced beyond the selected revision", NextAction: "import a valid package matching the current trusted metadata", Freshness: "fresh", TrustFreshness: "fresh", SourceEvidenceFreshness: "some_or_all_expired", SourceEvidenceExpiresAt: "2026-09-12T17:00:00Z"})
	for _, want := range []string{"TRUST_ADVANCED", "trusted metadata advanced", "import a valid package", "trust freshness: fresh", "source evidence freshness: some_or_all_expired", "readiness scope: selected-store integrity only"} {
		if !strings.Contains(human.String(), want) {
			t.Fatalf("trust-advanced human output missing %q: %s", want, human.String())
		}
	}
}

func TestKnowledgeImportRecoveryMessagesRequireExactOriginalTransaction(t *testing.T) {
	t.Parallel()
	receipt := knowledge.ImportReceipt{
		APIVersion: "prufyx.io/knowledge-import-receipt/v1", Status: "REJECTED",
		TrustStateAdvanced: true, SelectionChanged: false,
		TrustStateDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	}
	for _, format := range []string{"human", "json"} {
		var stdout, stderr bytes.Buffer
		r := runtime{stdout: &stdout, stderr: &stderr}
		if code := r.databaseImportRejected(receipt, knowledge.ErrRecoveryRequired, format); code != ExitIntegrity || stderr.Len() != 0 {
			t.Fatalf("format=%s code=%d stderr=%s", format, code, stderr.String())
		}
		for _, want := range []string{"KNOWLEDGE_IMPORT_RECOVERY_REQUIRED", "exact original signed package", "same expected revision", "original bootstrap arguments"} {
			if !strings.Contains(stdout.String(), want) {
				t.Fatalf("format=%s output missing %q: %s", format, want, stdout.String())
			}
		}
	}
	var joined bytes.Buffer
	r := runtime{stdout: &joined, stderr: &bytes.Buffer{}}
	if code := r.databaseImportRejected(receipt, errors.Join(knowledge.ErrExpired, knowledge.ErrRecoveryRequired), "json"); code != ExitIntegrity {
		t.Fatalf("joined recovery code=%d", code)
	}
	if !strings.Contains(joined.String(), "KNOWLEDGE_IMPORT_RECOVERY_REQUIRED") || strings.Contains(joined.String(), "KNOWLEDGE_TRUST_METADATA_EXPIRED") {
		t.Fatalf("joined failure did not keep recovery dominant: %s", joined.String())
	}
	var stdout, stderr bytes.Buffer
	r = runtime{stdout: &stdout, stderr: &stderr}
	if code := r.knowledgeError("knowledge package import failed", knowledge.ErrRecoveryRequired); code != ExitIntegrity || stdout.Len() != 0 {
		t.Fatalf("direct recovery code=%d stdout=%s", code, stdout.String())
	}
	for _, want := range []string{"recovery required", "exact original signed package", "original assertions", "bootstrap arguments"} {
		if !strings.Contains(stderr.String(), want) {
			t.Fatalf("direct recovery missing %q: %s", want, stderr.String())
		}
	}
}

func runKnowledgeCLI(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := Run(context.Background(), args, &stdout, &stderr, "test")
	return code, stdout.String(), stderr.String()
}

func writeKnowledgeFile(t *testing.T, dir, name string, raw []byte, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, raw, mode); err != nil {
		t.Fatal(err)
	}
	return path
}

func testDigest(raw []byte) string {
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}
