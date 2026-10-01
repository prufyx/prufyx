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

type buildpacksExternalFixture struct {
	store     string
	manifest  knowledgefixture.Manifest
	package2  string
	package3  string
	revision2 knowledge.ImportReceipt
}

func makeBuildpacksExternalFixture(t *testing.T) buildpacksExternalFixture {
	t.Helper()
	artifacts, err := knowledgefixture.GenerateBuildpacksConstraints(time.Now().UTC().Truncate(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	var manifest knowledgefixture.Manifest
	if err := json.Unmarshal(artifacts.Manifest, &manifest); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	store := filepath.Join(dir, "buildpacks-store")
	if err := os.Mkdir(store, 0o700); err != nil {
		t.Fatal(err)
	}
	root := writeCNCFFile(t, "buildpacks-root.json", artifacts.Root, 0o600)
	p1 := writeCNCFFile(t, "buildpacks-revision-1.tar", artifacts.Revision1, 0o600)
	p2 := writeCNCFFile(t, "buildpacks-revision-2.tar", artifacts.Revision2, 0o600)
	p3 := writeCNCFFile(t, "buildpacks-revision-3.tar", artifacts.Revision3, 0o600)
	if _, err := knowledge.ImportConstraints(knowledge.ImportRequest{
		PackagePath: p1, StoreRoot: store, BootstrapRootPath: root,
		BootstrapRootDigest: manifest.BootstrapRoot.Digest,
		ExpectedRevision:    "1", ExpectedBundleDigest: manifest.Revisions[0].BundleDigest,
	}); err != nil {
		t.Fatal(err)
	}
	return buildpacksExternalFixture{store: store, manifest: manifest, package2: p2, package3: p3}
}

func (fixture *buildpacksExternalFixture) importRevision2(t *testing.T) {
	t.Helper()
	receipt, err := knowledge.ImportConstraints(knowledge.ImportRequest{
		PackagePath: fixture.package2, StoreRoot: fixture.store,
		ExpectedRevision: "2", ExpectedBundleDigest: fixture.manifest.Revisions[1].BundleDigest,
	})
	if err != nil {
		t.Fatal(err)
	}
	fixture.revision2 = receipt
}

func (fixture *buildpacksExternalFixture) importRevision3(t *testing.T) {
	t.Helper()
	if _, err := knowledge.ImportConstraints(knowledge.ImportRequest{
		PackagePath: fixture.package3, StoreRoot: fixture.store,
		ExpectedRevision: "3", ExpectedBundleDigest: fixture.manifest.Revisions[2].BundleDigest,
	}); err != nil {
		t.Fatal(err)
	}
}

func buildpacksExternalArgs(fixture buildpacksExternalFixture, current, proposed, from, to, proposedAPI, format string) []string {
	return []string{
		"check", "cncf", "--project", "buildpacks",
		"--current-lifecycle-config", current, "--proposed-lifecycle-config", proposed,
		"--from", from, "--to", to, "--current-platform-api", "0.11", "--proposed-platform-api", proposedAPI,
		"--knowledge-db", fixture.store, "--format", format,
	}
}

func TestBuildpacksRawExternalKnowledgeIsAuthoritative(t *testing.T) {
	fixture := makeBuildpacksExternalFixture(t)
	dir := t.TempDir()
	current := filepath.Join(dir, "current.json")
	proposed := filepath.Join(dir, "proposed.json")
	writeLifecycleConfig(t, current, "0.16.5", []string{"0.11"}, "CURRENT_PRIVATE")
	writeLifecycleConfig(t, proposed, "0.17.7", []string{"0.12"}, "TARGET_PRIVATE")
	realExternal := buildpacksExternalArgs(fixture, current, proposed, "0.16.5", "0.17.7", "0.13", "human")
	code, noFallback, stderr := runCNCFCLI(t, realExternal...)
	if code != ExitUnknown || stderr != "" || !strings.Contains(noFallback, "selected external revision has no rule") || !strings.Contains(noFallback, "no embedded rule was used") || !strings.Contains(noFallback, "revision 1") {
		t.Fatalf("real external code=%d stderr=%q output=%s", code, stderr, noFallback)
	}
	embedded := buildpacksRawArgs(current, proposed, "0.13", "human")
	code, embeddedOutput, stderr := runCNCFCLI(t, embedded...)
	if code != ExitBlocked || stderr != "" || !strings.Contains(embeddedOutput, "scoped result: BLOCKED") {
		t.Fatalf("embedded code=%d stderr=%q output=%s", code, stderr, embeddedOutput)
	}

	current = filepath.Join(dir, "synthetic-current.json")
	proposed = filepath.Join(dir, "synthetic-proposed.json")
	writeLifecycleConfig(t, current, knowledgefixture.SyntheticBuildpacksFrom, []string{"0.11"}, "CURRENT_PRIVATE")
	writeLifecycleConfig(t, proposed, knowledgefixture.SyntheticBuildpacksTo, []string{"0.12"}, "TARGET_PRIVATE")
	fixture.importRevision2(t)
	args := buildpacksExternalArgs(fixture, current, proposed, knowledgefixture.SyntheticBuildpacksFrom, knowledgefixture.SyntheticBuildpacksTo, "0.13", "human")
	code, blocked, stderr := runCNCFCLI(t, args...)
	if code != ExitBlocked || stderr != "" || !strings.Contains(blocked, "scoped result: BLOCKED") || !strings.Contains(blocked, "external signed local revision 2") || !strings.Contains(blocked, "knowledge trust receipt digest:") || !strings.Contains(blocked, "knowledge purpose: synthetic_test_only") || !strings.Contains(blocked, "no embedded fallback") {
		t.Fatalf("active external code=%d stderr=%q output=%s", code, stderr, blocked)
	}
	assertBuildpacksRedacted(t, blocked, current, proposed)
	args = buildpacksExternalArgs(fixture, current, proposed, knowledgefixture.SyntheticBuildpacksFrom, knowledgefixture.SyntheticBuildpacksTo, "0.12", "human")
	code, passed, stderr := runCNCFCLI(t, args...)
	if code != ExitOK || stderr != "" || !strings.Contains(passed, "scoped result: PASS") {
		t.Fatalf("fixed external code=%d stderr=%q output=%s", code, stderr, passed)
	}
	assertStoreDoesNotContain(t, fixture.store, []string{"CURRENT_PRIVATE", "TARGET_PRIVATE", current, proposed})
}

func TestBuildpacksRawExternalReplayBindsCanonicalPlanNotRawConfigs(t *testing.T) {
	fixture := makeBuildpacksExternalFixture(t)
	fixture.importRevision2(t)
	dir := t.TempDir()
	current1, current2 := filepath.Join(dir, "current-1.json"), filepath.Join(dir, "current-2.json")
	proposed1, proposed2 := filepath.Join(dir, "proposed-1.json"), filepath.Join(dir, "proposed-2.json")
	currentRaw1 := writeLifecycleConfig(t, current1, knowledgefixture.SyntheticBuildpacksFrom, []string{"0.11"}, "FIRST_RAW_PRIVATE")
	proposedRaw1 := writeLifecycleConfig(t, proposed1, knowledgefixture.SyntheticBuildpacksTo, []string{"0.12"}, "FIRST_RAW_PRIVATE")
	currentRaw2 := writeLifecycleConfig(t, current2, knowledgefixture.SyntheticBuildpacksFrom, []string{"0.11"}, "SECOND_RAW_PRIVATE")
	proposedRaw2 := writeLifecycleConfig(t, proposed2, knowledgefixture.SyntheticBuildpacksTo, []string{"0.12"}, "SECOND_RAW_PRIVATE")
	if bytes.Equal(currentRaw1, currentRaw2) || bytes.Equal(proposedRaw1, proposedRaw2) {
		t.Fatal("metadata-only raw variants did not change")
	}
	firstArgs := append(buildpacksExternalArgs(fixture, current1, proposed1, knowledgefixture.SyntheticBuildpacksFrom, knowledgefixture.SyntheticBuildpacksTo, "0.13", "json"),
		"--current-lifecycle-config-digest", digestCommunityBytes(currentRaw1), "--proposed-lifecycle-config-digest", digestCommunityBytes(proposedRaw1))
	code, firstReport, stderr := runCNCFCLI(t, firstArgs...)
	if code != ExitBlocked || stderr != "" {
		t.Fatalf("first code=%d stderr=%q output=%s", code, stderr, firstReport)
	}
	secondArgs := append(buildpacksExternalArgs(fixture, current2, proposed2, knowledgefixture.SyntheticBuildpacksFrom, knowledgefixture.SyntheticBuildpacksTo, "0.13", "json"),
		"--current-lifecycle-config-digest", digestCommunityBytes(currentRaw2), "--proposed-lifecycle-config-digest", digestCommunityBytes(proposedRaw2))
	code, secondReport, stderr := runCNCFCLI(t, secondArgs...)
	if code != ExitBlocked || stderr != "" {
		t.Fatalf("second code=%d stderr=%q output=%s", code, stderr, secondReport)
	}
	var first, second struct {
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
	if json.Unmarshal([]byte(firstReport), &first) != nil || json.Unmarshal([]byte(secondReport), &second) != nil || first.Check.InputFileDigest == "" || first.Check.InputFileDigest != second.Check.InputFileDigest || first.Engine.IdentityDigest == "" || first.Engine.IdentityDigest != second.Engine.IdentityDigest || len(first.Check.Check.Claims) != 1 || len(second.Check.Check.Claims) != 1 || !bytes.Equal(first.Check.Check.Claims[0], second.Check.Check.Claims[0]) {
		t.Fatalf("canonical plan changed across unrelated raw metadata")
	}
	report := filepath.Join(dir, "saved-report.json")
	writeCNCFFileAt(t, report, []byte(firstReport))
	fixture.importRevision3(t)
	replayArgs := append(buildpacksExternalArgs(fixture, current2, proposed2, knowledgefixture.SyntheticBuildpacksFrom, knowledgefixture.SyntheticBuildpacksTo, "0.13", "human"),
		"--current-lifecycle-config-digest", digestCommunityBytes(currentRaw2), "--proposed-lifecycle-config-digest", digestCommunityBytes(proposedRaw2),
		"--knowledge-revision", "2", "--knowledge-bundle-digest", fixture.manifest.Revisions[1].BundleDigest,
		"--knowledge-trust-receipt-digest", fixture.revision2.TrustReceiptDigest, "--replay-report", report)
	code, replay, stderr := runCNCFCLI(t, replayArgs...)
	if code != ExitBlocked || stderr != "" || !strings.Contains(replay, "historical external Buildpacks Lifecycle replay: MATCH") || !strings.Contains(replay, "saved report binds minimized API declarations") {
		t.Fatalf("replay code=%d stderr=%q output=%s", code, stderr, replay)
	}
	for _, output := range []string{firstReport, secondReport, replay} {
		assertBuildpacksRedacted(t, output, current1, current2, proposed1, proposed2)
		if strings.Contains(output, "FIRST_RAW_PRIVATE") || strings.Contains(output, "SECOND_RAW_PRIVATE") {
			t.Fatal("unrelated raw metadata crossed report boundary")
		}
	}
	assertStoreDoesNotContain(t, fixture.store, []string{"FIRST_RAW_PRIVATE", "SECOND_RAW_PRIVATE", current1, current2, proposed1, proposed2})
}

func TestBuildpacksRawExternalModeAndSelectionGuards(t *testing.T) {
	fixture := makeBuildpacksExternalFixture(t)
	dir := t.TempDir()
	current, proposed := filepath.Join(dir, "current.json"), filepath.Join(dir, "proposed.json")
	currentRaw := writeLifecycleConfig(t, current, "0.16.5", []string{"0.11"}, "CURRENT_PRIVATE")
	proposedRaw := writeLifecycleConfig(t, proposed, "0.17.7", []string{"0.12"}, "TARGET_PRIVATE")
	base := buildpacksExternalArgs(fixture, current, proposed, "0.16.5", "0.17.7", "0.13", "json")
	invalid := [][]string{
		append(append([]string{}, base...), "--now", "2026-09-10T17:00:00Z"),
		append(append([]string{}, base...), "--input", current),
		append(append([]string{}, base...), "--input-digest", digestCommunityBytes(currentRaw)),
		append(append([]string{}, base...), "--service", current),
		append(append([]string{}, base...), "--replay-report", current),
	}
	for _, args := range invalid {
		code, stdout, stderr := runCNCFCLI(t, args...)
		if code != ExitUsage || stdout != "" || stderr == "" || strings.Contains(stderr, current) {
			t.Fatalf("args=%v code=%d stdout=%q stderr=%q", args, code, stdout, stderr)
		}
	}
	badDigest := "sha256:" + strings.Repeat("0", 64)
	for _, extra := range [][]string{
		{"--current-lifecycle-config-digest", badDigest},
		{"--proposed-lifecycle-config-digest", badDigest},
		{"--knowledge-revision", "999"},
		{"--knowledge-bundle-digest", badDigest},
		{"--knowledge-trust-receipt-digest", badDigest},
	} {
		code, stdout, stderr := runCNCFCLI(t, append(append([]string{}, base...), extra...)...)
		if code != ExitIntegrity || stdout != "" || stderr == "" || strings.Contains(stderr, current) || strings.Contains(stderr, proposed) || strings.Contains(stderr, "CURRENT_PRIVATE") || strings.Contains(stderr, "TARGET_PRIVATE") {
			t.Fatalf("extra=%v code=%d stdout=%q stderr=%q", extra, code, stdout, stderr)
		}
	}
	matchingPins := append(append([]string{}, base...), "--current-lifecycle-config-digest", digestCommunityBytes(currentRaw), "--proposed-lifecycle-config-digest", digestCommunityBytes(proposedRaw))
	code, stdout, stderr := runCNCFCLI(t, matchingPins...)
	if code != ExitUnknown || stderr != "" || !json.Valid([]byte(stdout)) {
		t.Fatalf("matching pins code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
}
