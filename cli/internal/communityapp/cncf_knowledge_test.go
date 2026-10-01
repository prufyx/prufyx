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

const (
	kyvernoInputFalse = `{"schema":"prufyx.io/operator-declared-constraint-input/v1alpha1","authority":"OPERATOR_DECLARED_MINIMIZED","current":{"components":[{"component":"pkg:github/kyverno/kyverno","version":"1.12.5","facts":[]}]},"proposed":{"components":[{"component":"pkg:github/kyverno/kyverno","version":"1.13.0","facts":[{"id":"component.kyverno.distribution","state":"declared","enumValue":"official_upstream"},{"id":"component.kyverno.execution_surface","state":"declared","enumValue":"reports_controller"},{"id":"component.kyverno.reports_chunk_size_flag_present","state":"declared","boolValue":false}]}]}}`
	kyvernoInputTrue  = `{"schema":"prufyx.io/operator-declared-constraint-input/v1alpha1","authority":"OPERATOR_DECLARED_MINIMIZED","current":{"components":[{"component":"pkg:github/kyverno/kyverno","version":"1.12.5","facts":[]}]},"proposed":{"components":[{"component":"pkg:github/kyverno/kyverno","version":"1.13.0","facts":[{"id":"component.kyverno.distribution","state":"declared","enumValue":"official_upstream"},{"id":"component.kyverno.execution_surface","state":"declared","enumValue":"reports_controller"},{"id":"component.kyverno.reports_chunk_size_flag_present","state":"declared","boolValue":true}]}]}}`
)

type externalCLIFixture struct {
	dir      string
	store    string
	manifest knowledgefixture.Manifest
	package2 string
	receipt1 knowledge.ImportReceipt
	receipt2 knowledge.ImportReceipt
}

func makeExternalCLIFixture(t *testing.T) externalCLIFixture {
	t.Helper()
	artifacts, err := knowledgefixture.GenerateConstraints(time.Now().UTC().Truncate(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	var manifest knowledgefixture.Manifest
	if err := json.Unmarshal(artifacts.Manifest, &manifest); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	store := filepath.Join(dir, "generic-store")
	if err := os.Mkdir(store, 0o700); err != nil {
		t.Fatal(err)
	}
	root := writeCNCFFile(t, "root.json", artifacts.Root, 0o600)
	p1 := writeCNCFFile(t, "revision-1.tar", artifacts.Revision1, 0o600)
	p2 := writeCNCFFile(t, "revision-2.tar", artifacts.Revision2, 0o600)
	r1, err := knowledge.ImportConstraints(knowledge.ImportRequest{PackagePath: p1, StoreRoot: store, BootstrapRootPath: root, BootstrapRootDigest: manifest.BootstrapRoot.Digest, ExpectedRevision: "1", ExpectedBundleDigest: manifest.Revisions[0].BundleDigest})
	if err != nil {
		t.Fatal(err)
	}
	return externalCLIFixture{dir: dir, store: store, manifest: manifest, package2: p2, receipt1: r1}
}

func importExternalCLIRevision2(t *testing.T, fixture *externalCLIFixture) {
	t.Helper()
	r2, err := knowledge.ImportConstraints(knowledge.ImportRequest{PackagePath: fixture.package2, StoreRoot: fixture.store, ExpectedRevision: "2", ExpectedBundleDigest: fixture.manifest.Revisions[1].BundleDigest})
	if err != nil {
		t.Fatal(err)
	}
	fixture.receipt2 = r2
}

func externalCLIArgs(fixture externalCLIFixture, input, revision, bundle, receipt string) []string {
	return []string{"check", "cncf", "--project", "kyverno", "--input", input, "--knowledge-db", fixture.store, "--knowledge-revision", revision, "--knowledge-bundle-digest", bundle, "--knowledge-trust-receipt-digest", receipt}
}

func TestExternalCNCFCLIUsesSeparateStoreAndVerifierClock(t *testing.T) {
	fixture := makeExternalCLIFixture(t)
	input := writeCNCFFile(t, "empty-input.json", []byte(kyvernoInputFalse), 0o600)
	args := externalCLIArgs(fixture, input, "1", fixture.manifest.Revisions[0].BundleDigest, fixture.receipt1.TrustReceiptDigest)
	args = append(args, "--format", "json", "--now", "2026-09-08T12:10:00Z")
	code, stdout, stderr := runCNCFCLI(t, args...)
	if code != ExitUsage || stdout != "" || !strings.Contains(stderr, "external CNCF checks use verifier time") {
		t.Fatalf("--now external code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	args = externalCLIArgs(fixture, input, "1", fixture.manifest.Revisions[0].BundleDigest, fixture.receipt1.TrustReceiptDigest)
	args = append(args, "--format", "json")
	code, stdout, stderr = runCNCFCLI(t, args...)
	if code != ExitUnknown || stderr != "" || !strings.Contains(stdout, `"knowledgeOrigin":"external_declared"`) || !strings.Contains(stdout, `"purpose":"synthetic_test_only"`) || !strings.Contains(stdout, `"assessment":"UNKNOWN"`) {
		t.Fatalf("external empty code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	activeInput := writeCNCFFile(t, "active-input.json", []byte(kyvernoInputTrue), 0o600)
	importExternalCLIRevision2(t, &fixture)
	args = externalCLIArgs(fixture, activeInput, "2", fixture.manifest.Revisions[1].BundleDigest, fixture.receipt2.TrustReceiptDigest)
	args = append(args, "--format", "json")
	code, stdout, stderr = runCNCFCLI(t, args...)
	if code != ExitBlocked || stderr != "" || !strings.Contains(stdout, `"status":"BLOCKED"`) || !strings.Contains(stdout, `"knowledgeOrigin":"external_declared"`) {
		t.Fatalf("external active code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	if strings.Contains(stdout, fixture.store) || strings.Contains(stdout, "PRIVATE") {
		t.Fatalf("private path/material crossed report boundary: %q", stdout)
	}
}

func TestExternalCNCFCLIReplayRequiresAllPinsAndExactReport(t *testing.T) {
	fixture := makeExternalCLIFixture(t)
	inputRaw := []byte(kyvernoInputFalse)
	input := writeCNCFFile(t, "replay-input.json", inputRaw, 0o600)
	args := externalCLIArgs(fixture, input, "1", fixture.manifest.Revisions[0].BundleDigest, fixture.receipt1.TrustReceiptDigest)
	args = append(args, "--format", "json", "--input-digest", cncfDigest(inputRaw))
	code, original, stderr := runCNCFCLI(t, args...)
	if code != ExitUnknown || stderr != "" || !strings.Contains(original, `"knowledgeOrigin":"external_declared"`) || !strings.HasSuffix(original, "\n") {
		t.Fatalf("external initial code=%d stdout=%q stderr=%q", code, original, stderr)
	}
	report := writeCNCFFile(t, "external-report.json", []byte(original), 0o600)
	importExternalCLIRevision2(t, &fixture)
	replayArgs := externalCLIArgs(fixture, input, "1", fixture.manifest.Revisions[0].BundleDigest, fixture.receipt1.TrustReceiptDigest)
	replayArgs = append(replayArgs, "--format", "json", "--input-digest", cncfDigest(inputRaw), "--replay-report", report)
	code, replay, stderr := runCNCFCLI(t, replayArgs...)
	if code != ExitUnknown || stderr != "" || !strings.Contains(replay, `"status":"MATCH"`) || !strings.Contains(replay, `"mode":"historical"`) || !strings.Contains(replay, `"currentNonRevocation":"not_checked_offline"`) {
		t.Fatalf("external replay code=%d stdout=%q stderr=%q", code, replay, stderr)
	}
	missingPin := externalCLIArgs(fixture, input, "1", fixture.manifest.Revisions[0].BundleDigest, "")
	missingPin = append(missingPin, "--format", "json", "--input-digest", cncfDigest(inputRaw), "--replay-report", report)
	code, stdout, stderr := runCNCFCLI(t, missingPin...)
	if code != ExitUsage || stdout != "" || !strings.Contains(stderr, "invalid external CNCF knowledge selection") {
		t.Fatalf("missing replay pin code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	wrongDigest := externalCLIArgs(fixture, input, "1", fixture.manifest.Revisions[0].BundleDigest, fixture.receipt1.TrustReceiptDigest)
	wrongDigest = append(wrongDigest, "--format", "json", "--input-digest", cncfDigest([]byte("different")))
	code, stdout, stderr = runCNCFCLI(t, wrongDigest...)
	if code != ExitIntegrity || stdout != "" || !strings.Contains(stderr, "CNCF input digest does not match") {
		t.Fatalf("wrong input digest code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
}

func TestExternalCNCFCLIPrivateInputAndMalformedCanaryStayLocal(t *testing.T) {
	fixture := makeExternalCLIFixture(t)
	canary := "PRIVATE-CNCF-SECRET-CANARY-7e1a"
	malformedRaw := []byte(`{"schema":"prufyx.io/operator-declared-constraint-input/v1alpha1","authority":"OPERATOR_DECLARED_MINIMIZED","secret":"` + canary + `","current":{"components":[]},"proposed":{"components":[]}}`)
	malformed := writeCNCFFile(t, "malformed.json", malformedRaw, 0o600)
	args := externalCLIArgs(fixture, malformed, "1", fixture.manifest.Revisions[0].BundleDigest, fixture.receipt1.TrustReceiptDigest)
	code, stdout, stderr := runCNCFCLI(t, args...)
	if code != ExitUsage || stdout != "" || !strings.Contains(stderr, "external CNCF check failed") || strings.Contains(stderr, canary) || strings.Contains(stderr, malformed) {
		t.Fatalf("malformed private input code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	permissive := writeCNCFFile(t, "permissive.json", []byte(kyvernoInputFalse), 0o644)
	args = externalCLIArgs(fixture, permissive, "1", fixture.manifest.Revisions[0].BundleDigest, fixture.receipt1.TrustReceiptDigest)
	code, stdout, stderr = runCNCFCLI(t, args...)
	if code != ExitUsage || stdout != "" || !strings.Contains(stderr, "CNCF input failed local admission") {
		t.Fatalf("permissive private input code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	noFallback := []string{"check", "cncf", "--project", "helm", "--input", writeCNCFFile(t, "embedded-input.json", []byte(syntheticHelmInput), 0o600), "--now", "2026-09-08T12:10:00Z", "--format", "json"}
	code, stdout, stderr = runCNCFCLI(t, noFallback...)
	if code != ExitOK || stderr != "" || !strings.Contains(stdout, `"knowledgeOrigin":"embedded"`) || !strings.Contains(stdout, `"status":"PASS"`) {
		t.Fatalf("embedded route changed code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
}
