// SPDX-License-Identifier: AGPL-3.0-only

package communityapp

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/knowledge"
	"github.com/prufyx/prufyx/cli/internal/knowledgefixture"
)

type knativeExternalFixture struct {
	store    string
	manifest knowledgefixture.Manifest
	package2 string
	package3 string
	receipt1 knowledge.ImportReceipt
	receipt2 knowledge.ImportReceipt
}

func makeKnativeExternalFixture(t *testing.T) knativeExternalFixture {
	t.Helper()
	artifacts, err := knowledgefixture.GenerateKnativeConstraints(time.Now().UTC().Truncate(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	var manifest knowledgefixture.Manifest
	if err := json.Unmarshal(artifacts.Manifest, &manifest); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	store := filepath.Join(dir, "knative-store")
	if err := os.Mkdir(store, 0o700); err != nil {
		t.Fatal(err)
	}
	root := writeCNCFFile(t, "knative-root.json", artifacts.Root, 0o600)
	p1 := writeCNCFFile(t, "knative-revision-1.tar", artifacts.Revision1, 0o600)
	p2 := writeCNCFFile(t, "knative-revision-2.tar", artifacts.Revision2, 0o600)
	p3 := writeCNCFFile(t, "knative-revision-3.tar", artifacts.Revision3, 0o600)
	receipt1, err := knowledge.ImportConstraints(knowledge.ImportRequest{
		PackagePath: p1, StoreRoot: store, BootstrapRootPath: root,
		BootstrapRootDigest: manifest.BootstrapRoot.Digest,
		ExpectedRevision:    "1", ExpectedBundleDigest: manifest.Revisions[0].BundleDigest,
	})
	if err != nil {
		t.Fatal(err)
	}
	return knativeExternalFixture{store: store, manifest: manifest, package2: p2, package3: p3, receipt1: receipt1}
}

func (fixture *knativeExternalFixture) importRevision3(t *testing.T) {
	t.Helper()
	if _, err := knowledge.ImportConstraints(knowledge.ImportRequest{
		PackagePath: fixture.package3, StoreRoot: fixture.store,
		ExpectedRevision: "3", ExpectedBundleDigest: fixture.manifest.Revisions[2].BundleDigest,
	}); err != nil {
		t.Fatal(err)
	}
}

func (fixture *knativeExternalFixture) importRevision2(t *testing.T) {
	t.Helper()
	receipt, err := knowledge.ImportConstraints(knowledge.ImportRequest{
		PackagePath: fixture.package2, StoreRoot: fixture.store,
		ExpectedRevision: "2", ExpectedBundleDigest: fixture.manifest.Revisions[1].BundleDigest,
	})
	if err != nil {
		t.Fatal(err)
	}
	fixture.receipt2 = receipt
}

func knativeExternalArgs(fixture knativeExternalFixture, service, format string) []string {
	return []string{
		"check", "cncf", "--project", "knative", "--service", service,
		"--from", knowledgefixture.SyntheticKnativeFrom, "--to", knowledgefixture.SyntheticKnativeTo,
		"--knowledge-db", fixture.store, "--format", format,
	}
}

func TestKnativeRawExternalKnowledgeIsAuthoritativeAndUsesStableObservation(t *testing.T) {
	t.Parallel()
	fixture := makeKnativeExternalFixture(t)
	dir := t.TempDir()
	service := filepath.Join(dir, "operator-service.json")
	writeKnativeOperatorService(t, service, "http1", "h2c")

	code, empty, stderr := runCNCFCLI(t, knativeExternalArgs(fixture, service, "human")...)
	if code != ExitUnknown || stderr != "" || !strings.Contains(empty, "RULE_TRANSITION_NOT_REVIEWED") || !strings.Contains(empty, "selected external revision has no rule") || !strings.Contains(empty, "no embedded rule was used") || !strings.Contains(empty, "revision 1") {
		t.Fatalf("empty external code=%d stderr=%q output=%s", code, stderr, empty)
	}
	assertKnativeRawReviewRedacted(t, empty, service)
	realPairExternal := []string{
		"check", "cncf", "--project", "knative", "--service", service,
		"--from", "1.22.0", "--to", "1.23.0", "--knowledge-db", fixture.store, "--format", "human",
	}
	code, noFallback, stderr := runCNCFCLI(t, realPairExternal...)
	if code != ExitUnknown || stderr != "" || !strings.Contains(noFallback, "selected external revision has no rule") || !strings.Contains(noFallback, "no embedded rule was used") {
		t.Fatalf("real-pair external no-fallback code=%d stderr=%q output=%s", code, stderr, noFallback)
	}
	embeddedArgs := knativeRawReviewArgs(service, "1.22.0", "1.23.0", "human")
	code, embedded, stderr := runCNCFCLI(t, embeddedArgs...)
	if code != ExitBlocked || stderr != "" || !strings.Contains(embedded, "scoped result: BLOCKED") || !strings.Contains(embedded, "knowledge: embedded revision") {
		t.Fatalf("same real-pair embedded code=%d stderr=%q output=%s", code, stderr, embedded)
	}

	fixture.importRevision2(t)
	code, blocked, stderr := runCNCFCLI(t, knativeExternalArgs(fixture, service, "human")...)
	if code != ExitBlocked || stderr != "" || !strings.Contains(blocked, "scoped result: BLOCKED") || !strings.Contains(blocked, "external signed local revision 2") || !strings.Contains(blocked, "knowledge purpose: synthetic_test_only") || !strings.Contains(blocked, "authority: synthetic test knowledge only") || !strings.Contains(blocked, "no embedded fallback") {
		t.Fatalf("active external code=%d stderr=%q output=%s", code, stderr, blocked)
	}
	assertKnativeRawReviewRedacted(t, blocked, service)

	writeKnativeOperatorService(t, service, "http1", "http1")
	code, passed, stderr := runCNCFCLI(t, knativeExternalArgs(fixture, service, "human")...)
	if code != ExitOK || stderr != "" || !strings.Contains(passed, "scoped result: PASS") || !strings.Contains(passed, "match (read from Service)") {
		t.Fatalf("fixed external code=%d stderr=%q output=%s", code, stderr, passed)
	}
	assertKnativeRawReviewRedacted(t, passed, service)

	wrongShape := filepath.Join(dir, "unsupported-service.json")
	writeCNCFFileAt(t, wrongShape, []byte(`{"apiVersion":"v1","kind":"Service","metadata":{"name":"PRIVATE_UNSUPPORTED"}}`))
	code, unknown, stderr := runCNCFCLI(t, knativeExternalArgs(fixture, wrongShape, "human")...)
	if code != ExitUnknown || stderr != "" || !strings.Contains(unknown, "RULE_FACT_UNAVAILABLE") || !strings.Contains(unknown, "outside the selected named HTTP startup-probe port condition") || strings.Contains(unknown, "PRIVATE_UNSUPPORTED") {
		t.Fatalf("unsupported external code=%d stderr=%q output=%s", code, stderr, unknown)
	}
}

func TestKnativeRawExternalReplayBindsCanonicalObservationNotRawService(t *testing.T) {
	t.Parallel()
	fixture := makeKnativeExternalFixture(t)
	fixture.importRevision2(t)
	dir := t.TempDir()
	first := filepath.Join(dir, "first-service.json")
	firstRaw := writeKnativeOperatorService(t, first, "http1", "h2c")
	second := filepath.Join(dir, "second-service.json")
	var secondDocument map[string]any
	if err := json.Unmarshal(firstRaw, &secondDocument); err != nil {
		t.Fatal(err)
	}
	metadata := secondDocument["metadata"].(map[string]any)
	metadata["name"] = "different-private-name"
	metadata["namespace"] = "different-private-namespace"
	metadata["labels"] = map[string]any{"private.example/canary": "SECOND-RAW-ONLY-CANARY"}
	secondRaw, err := json.Marshal(secondDocument)
	if err != nil {
		t.Fatal(err)
	}
	writeCNCFFileAt(t, second, secondRaw)
	if bytes.Equal(firstRaw, secondRaw) || digestCommunityBytes(firstRaw) == digestCommunityBytes(secondRaw) {
		t.Fatal("raw identity fixture did not change")
	}

	firstArgs := append(knativeExternalArgs(fixture, first, "json"), "--service-digest", digestCommunityBytes(firstRaw))
	code, firstReport, stderr := runCNCFCLI(t, firstArgs...)
	if code != ExitBlocked || stderr != "" {
		t.Fatalf("first code=%d stderr=%q output=%s", code, stderr, firstReport)
	}
	secondArgs := append(knativeExternalArgs(fixture, second, "json"), "--service-digest", digestCommunityBytes(secondRaw))
	code, secondReport, stderr := runCNCFCLI(t, secondArgs...)
	if code != ExitBlocked || stderr != "" {
		t.Fatalf("canonical-equivalent code=%d stderr=%q output=%s", code, stderr, secondReport)
	}
	var firstDocument, secondDocumentReport struct {
		Engine struct {
			IdentityDigest string `json:"identityDigest"`
		} `json:"engine"`
		Check struct {
			InputFileDigest string `json:"inputFileDigest"`
			Check           struct {
				Claims []json.RawMessage `json:"claims"`
			} `json:"check"`
		} `json:"check"`
	}
	if json.Unmarshal([]byte(firstReport), &firstDocument) != nil || json.Unmarshal([]byte(secondReport), &secondDocumentReport) != nil || firstDocument.Check.InputFileDigest == "" || firstDocument.Check.InputFileDigest != secondDocumentReport.Check.InputFileDigest || firstDocument.Engine.IdentityDigest == "" || firstDocument.Engine.IdentityDigest != secondDocumentReport.Engine.IdentityDigest || len(firstDocument.Check.Check.Claims) != 1 || len(secondDocumentReport.Check.Check.Claims) != 1 || !bytes.Equal(firstDocument.Check.Check.Claims[0], secondDocumentReport.Check.Check.Claims[0]) {
		t.Fatalf("canonical observation or engine changed across raw-only metadata: first=%s second=%s", firstReport, secondReport)
	}
	for _, output := range []string{firstReport, secondReport} {
		assertKnativeExternalJSONRedacted(t, output, first, second)
		for _, private := range []string{"SECOND-RAW-ONLY-CANARY", "different-private-name", "different-private-namespace"} {
			if strings.Contains(output, private) {
				t.Fatalf("raw-only metadata crossed canonical report: %q", private)
			}
		}
	}

	report := filepath.Join(dir, "saved-external-report.json")
	writeCNCFFileAt(t, report, []byte(firstReport))
	fixture.importRevision3(t)
	replayArgs := append(knativeExternalArgs(fixture, second, "human"),
		"--service-digest", digestCommunityBytes(secondRaw),
		"--knowledge-revision", "2",
		"--knowledge-bundle-digest", fixture.manifest.Revisions[1].BundleDigest,
		"--knowledge-trust-receipt-digest", fixture.receipt2.TrustReceiptDigest,
		"--replay-report", report,
	)
	code, replay, stderr := runCNCFCLI(t, replayArgs...)
	if code != ExitBlocked || stderr != "" || !strings.Contains(replay, "historical external Knative Serving replay: MATCH") || !strings.Contains(replay, "saved report binds the minimized prepared observation") || !strings.Contains(replay, "retain the raw Service and its digest separately") {
		t.Fatalf("replay code=%d stderr=%q output=%s", code, stderr, replay)
	}
	assertKnativeRawReviewRedacted(t, replay, first)
	assertKnativeRawReviewRedacted(t, replay, second)

	wrongPin := append(knativeExternalArgs(fixture, second, "json"), "--service-digest", digestCommunityBytes(firstRaw))
	code, stdout, stderr := runCNCFCLI(t, wrongPin...)
	if code != ExitIntegrity || stdout != "" || !strings.Contains(stderr, "CNCF_PREPARATION_INTEGRITY_FAILURE") {
		t.Fatalf("wrong raw pin code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	assertStoreDoesNotContain(t, fixture.store, []string{"private-knative", "SECOND-RAW-ONLY-CANARY", first, second})
}

func assertKnativeExternalJSONRedacted(t *testing.T, output string, paths ...string) {
	t.Helper()
	for _, forbidden := range append(paths, "private-knative", "private.registry", "must-not-cross-output", "PRIVATE_TOKEN", "/private-health") {
		if strings.Contains(output, forbidden) {
			t.Fatalf("private or raw Service data crossed external report boundary: %q", forbidden)
		}
	}
}

func TestKnativeRawExternalModeGuards(t *testing.T) {
	t.Parallel()
	fixture := makeKnativeExternalFixture(t)
	service := filepath.Join(t.TempDir(), "service.json")
	raw := writeKnativeOperatorService(t, service, "http1", "h2c")
	base := knativeExternalArgs(fixture, service, "json")
	invalid := [][]string{
		append(append([]string(nil), base...), "--now", "2026-09-10T17:00:00Z"),
		append(append([]string(nil), base...), "--input", service),
		append(append([]string(nil), base...), "--input-digest", digestCommunityBytes(raw)),
		append(append([]string(nil), base...), "--config-map", service),
		append(append([]string(nil), base...), "--replay-report", service),
	}
	for _, args := range invalid {
		code, stdout, stderr := runCNCFCLI(t, args...)
		if code != ExitUsage || stdout != "" || stderr == "" || strings.Contains(stderr, service) {
			t.Fatalf("args=%v code=%d stdout=%q stderr=%q", args, code, stdout, stderr)
		}
	}
	wrongSelection := []string{
		"check", "cncf", "--project", "knative", "--service", service,
		"--from", "1.22.0", "--to", "1.23.0", "--knowledge-db", fixture.store,
		"--knowledge-bundle-digest", "sha256:" + strings.Repeat("0", 64), "--format", "json",
	}
	code, stdout, stderr := runCNCFCLI(t, wrongSelection...)
	if code != ExitIntegrity || stdout != "" || stderr == "" || strings.Contains(stderr, service) || strings.Contains(stderr, "PRIVATE_TOKEN") {
		t.Fatalf("wrong selection code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
}

func assertStoreDoesNotContain(t *testing.T, root string, forbidden []string) {
	t.Helper()
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil || entry.IsDir() {
			return err
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, value := range forbidden {
			if bytes.Contains(raw, []byte(value)) {
				t.Fatalf("raw Service material persisted in knowledge store: %q in %s", value, path)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
