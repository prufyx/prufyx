// SPDX-License-Identifier: AGPL-3.0-only

//go:build aix || darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris

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
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/cncfcheck"
	"github.com/prufyx/prufyx/cli/internal/cncfknowledge"
	"github.com/prufyx/prufyx/cli/internal/knowledge"
	"github.com/prufyx/prufyx/cli/internal/knowledgereleaseplan"
	"github.com/prufyx/prufyx/cli/internal/maintainer/knowledgepublish"
	"github.com/prufyx/prufyx/cli/internal/maintainer/knowledgesign"
	"github.com/theupdateframework/go-tuf/v2/metadata"
)

type publishedRelease struct {
	url, revision string
	targetRaw     []byte
	packageRaw    []byte
	planRaw       []byte
	finalization  knowledgepublish.FinalizationReceipt
}

const (
	kyvernoReportsChunkSizeRuleID = "kyverno.reports-chunk-size-removed.1-13"
	kyvernoReportsReviewedAt      = "2026-09-09T00:53:06Z"
	kyvernoReportsValidUntil      = "2026-12-08T00:53:06Z"
	kyvernoInputUnknown           = `{"schema":"prufyx.io/operator-declared-constraint-input/v1alpha1","authority":"OPERATOR_DECLARED_MINIMIZED","current":{"components":[{"component":"pkg:github/kyverno/kyverno","version":"1.12.5","facts":[]}]},"proposed":{"components":[{"component":"pkg:github/kyverno/kyverno","version":"1.13.0","facts":[{"id":"component.kyverno.reports_chunk_size_flag_present","state":"declared","boolValue":false}]}]}}`
)

func TestKnowledgeReleasePlanNonemptyReviewedRuleProducerToAdopter(t *testing.T) {
	rootRaw, rootDigest, releases := publishedNonemptyReleaseFixture(t)
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	rootPath := writeKnowledgeReleaseFile(t, dir, "test-root.json", rootRaw)
	store := filepath.Join(dir, "store")
	// The publisher's one-root assertion in the unsigned plan cannot bootstrap
	// a client. The package is retained, but no selection is created.
	missingBootstrapPlan := writeKnowledgeReleaseFile(t, dir, "missing-bootstrap-plan.json", releases[0].planRaw)
	missingBootstrapStore := filepath.Join(dir, "missing-bootstrap-store")
	missingBootstrapCalls := 0
	code, missingBootstrap, stderr := runReleasePlanUpdate(t, []string{
		"--release-plan", missingBootstrapPlan,
		"--package-out", filepath.Join(dir, "missing-bootstrap-package.tar"),
		"--db-root", missingBootstrapStore, "--format", "json",
	}, func(_ context.Context, source string) ([]byte, error) {
		missingBootstrapCalls++
		if source != releases[0].url {
			t.Fatalf("missing-bootstrap source=%q", source)
		}
		return bytes.Clone(releases[0].packageRaw), nil
	})
	if code != ExitUsage || stderr != "" || missingBootstrapCalls != 1 || !missingBootstrap.PackageRetained || missingBootstrap.ImportReceipt != nil || missingBootstrap.Rejection != nil || missingBootstrap.ReasonCode != "KNOWLEDGE_PACKAGE_IMPORT_REJECTED" {
		t.Fatalf("missing bootstrap: code=%d calls=%d output=%+v stderr=%q", code, missingBootstrapCalls, missingBootstrap, stderr)
	}
	missingStatus, err := knowledge.InspectConstraints(missingBootstrapStore)
	if err != nil || missingStatus.State != "NO_SELECTION" || missingStatus.CurrentEligible || missingStatus.TrustSource != "none" {
		t.Fatalf("plan supplied bootstrap authority: status=%+v err=%v", missingStatus, err)
	}
	var active knowledge.ImportReceipt
	for index, release := range releases[:2] {
		bundle, err := cncfcheck.ParseExternalBundle(release.targetRaw)
		if err != nil {
			t.Fatal(err)
		}
		admission, err := bundle.Admission()
		if err != nil {
			t.Fatal(err)
		}
		if admission.Revision != release.revision || admission.Purpose != "operator_provided" || !admission.HasRule || admission.RuleDigest == "" || admission.EvidenceExpiresAt == "" || admission.EngineCapabilityDigest == "" || bundle.BundleDigest() != releaseDigest(release.targetRaw) {
			t.Fatalf("release %d admission=%+v bundle=%q", index, admission, bundle.BundleDigest())
		}
		assertExportedKyvernoReviewIdentity(t, release.targetRaw)
		if index == 0 {
			// Deterministically exercise future source-evidence expiry on the
			// unmodified exported bundle. This is a pure rule evaluation, not a
			// claim about current signed-store or TUF freshness.
			expired, err := bundle.EvaluateRule("kyverno", kyvernoReportsChunkSizeRuleID, []byte(kyvernoInputUnknown), mustParseReleaseTime(t, kyvernoReportsValidUntil))
			if err != nil || len(expired.Check.Claims) != 1 || expired.Check.Claims[0].Status != "UNKNOWN" || expired.Check.Claims[0].ReasonCode != "RULE_EVIDENCE_STALE" || expired.Check.Claims[0].EvidenceFreshness != "stale" || cncfcheck.ClaimExit(expired) != ExitUnknown {
				t.Fatalf("explicit expiry evaluation=%+v err=%v", expired, err)
			}
		}

		plan, err := knowledgereleaseplan.Parse(release.planRaw)
		if err != nil {
			t.Fatal(err)
		}
		assertionsDigest, err := plan.VerificationAssertionsDigest()
		if err != nil {
			t.Fatal(err)
		}
		expectedVersion := int64(index + 1)
		if plan.Schema != knowledgereleaseplan.Schema || plan.Authority != knowledgereleaseplan.Authority || plan.Package.URL != release.url || plan.Package.Digest != releaseDigest(release.packageRaw) || plan.Target.Path != knowledge.ConstraintsTargetPath || plan.Target.Revision != release.revision || plan.Target.Digest != bundle.BundleDigest() || plan.Target.Purpose != admission.Purpose || plan.Target.EngineCapabilityDigest != admission.EngineCapabilityDigest || plan.PublisherVerification.PublisherInitialRootDigest != rootDigest || plan.PublisherVerification.Root.Version != 1 || plan.PublisherVerification.Timestamp.Version != expectedVersion || plan.PublisherVerification.Snapshot.Version != expectedVersion || plan.PublisherVerification.Targets.Version != expectedVersion || assertionsDigest == "" {
			t.Fatalf("release %d plan=%+v assertionDigest=%q", index, plan, assertionsDigest)
		}
		finalized := release.finalization
		if finalized.Status != "VERIFIED_FOR_PACKAGING" || finalized.Profile != "cncf" || finalized.NetworkUsed || finalized.KeysHandled || finalized.RootDigest != rootDigest || finalized.TargetDigest != bundle.BundleDigest() || finalized.PackageDigest != plan.Package.Digest || finalized.KnowledgeRevision != release.revision || finalized.CapabilityDigest != admission.EngineCapabilityDigest || finalized.Verification.Status != "VERIFIED" || finalized.Verification.NetworkUsed || finalized.Verification.StoreUsed || finalized.Verification.StoreChanged || !finalized.Verification.HasRule || finalized.Verification.RuleDigest != admission.RuleDigest || finalized.Verification.EvidenceExpiresAt != admission.EvidenceExpiresAt {
			t.Fatalf("release %d finalization=%+v", index, finalized)
		}

		planPath := writeKnowledgeReleaseFile(t, dir, "nonempty-plan-"+release.revision+".json", release.planRaw)
		outputPath := filepath.Join(dir, "nonempty-package-"+release.revision+".tar")
		args := []string{"--release-plan", planPath, "--package-out", outputPath, "--db-root", store, "--format", "json"}
		if index == 0 {
			args = append(args, "--bootstrap-root", rootPath, "--bootstrap-root-digest", rootDigest)
		}
		calls := 0
		code, output, stderr := runReleasePlanUpdate(t, args, func(_ context.Context, source string) ([]byte, error) {
			calls++
			if source != release.url {
				t.Fatalf("release %d source=%q", index, source)
			}
			return bytes.Clone(release.packageRaw), nil
		})
		if code != ExitOK || stderr != "" || calls != 1 || output.Status != "IMPORTED" || !output.NetworkAttempted || !output.TransferCompleted || !output.PackageRetained || output.ImportReceipt == nil {
			t.Fatalf("release %d update: code=%d calls=%d output=%+v stderr=%q", index, code, calls, output, stderr)
		}
		active = *output.ImportReceipt
		if active.Status != "IMPORTED" || !active.SelectionChanged || active.TrustReceipt.APIVersion != "prufyx.io/knowledge-trust-receipt/v2" || active.TrustReceipt.KnowledgeRevision != release.revision || active.TrustReceipt.ExpectedVerificationAssertionsDigest != assertionsDigest || active.TrustReceipt.TargetDigest != bundle.BundleDigest() || active.TrustReceipt.RuleDigest != admission.RuleDigest || active.TrustReceipt.EvidenceExpiresAt != admission.EvidenceExpiresAt {
			t.Fatalf("release %d import receipt=%+v", index, active)
		}
		retained, err := os.ReadFile(outputPath)
		if err != nil || !bytes.Equal(retained, release.packageRaw) {
			t.Fatalf("release %d retained package mismatch: %v", index, err)
		}
		status, err := knowledge.InspectConstraints(store)
		if err != nil || status.State != "READY" || !status.CurrentEligible || status.SelectedRevision != release.revision || status.SelectedBundleDigest != bundle.BundleDigest() || status.TrustReceiptDigest != active.TrustReceiptDigest || status.TimestampVersion != expectedVersion || status.SnapshotVersion != expectedVersion || status.TargetsVersion != expectedVersion || status.TrustFreshness != "fresh" || status.SourceEvidenceExpiresAt != admission.EvidenceExpiresAt {
			t.Fatalf("release %d status=%+v err=%v", index, status, err)
		}
		expectedSourceFreshness := "not_expired"
		if !time.Now().UTC().Before(mustParseReleaseTime(t, admission.EvidenceExpiresAt)) {
			expectedSourceFreshness = "some_or_all_expired"
		}
		if status.SourceEvidenceFreshness != expectedSourceFreshness {
			t.Fatalf("release %d source freshness=%q want=%q", index, status.SourceEvidenceFreshness, expectedSourceFreshness)
		}
		assertCurrentKyvernoRuleOutcomes(t, dir, store, release, active, mustParseReleaseTime(t, kyvernoReportsValidUntil))
	}

	beforeRejectedUpdate := snapshotUpdateTree(t, store)
	rejected := releases[2]
	rejectedPlan, err := knowledgereleaseplan.Parse(rejected.planRaw)
	if err != nil {
		t.Fatal(err)
	}
	rejectedPlan.Package.Digest = "sha256:" + strings.Repeat("0", 64)
	rejectedPlanRaw, err := knowledgereleaseplan.Marshal(rejectedPlan)
	if err != nil {
		t.Fatal(err)
	}
	rejectedPlanPath := writeKnowledgeReleaseFile(t, dir, "wrong-package-plan-"+rejected.revision+".json", rejectedPlanRaw)
	rejectedOut := filepath.Join(dir, "rejected-package-"+rejected.revision+".tar")
	calls := 0
	code, output, stderr := runReleasePlanUpdate(t, []string{"--release-plan", rejectedPlanPath, "--package-out", rejectedOut, "--db-root", store, "--format", "json"}, func(_ context.Context, source string) ([]byte, error) {
		calls++
		if source != rejected.url {
			t.Fatalf("rejected source=%q", source)
		}
		return bytes.Clone(rejected.packageRaw), nil
	})
	if code != ExitIntegrity || stderr != "" || calls != 1 || !output.NetworkAttempted || !output.TransferCompleted || !output.PackageRetained || output.PackageDigest != releaseDigest(rejected.packageRaw) || output.ImportReceipt != nil || output.Rejection != nil || output.ReasonCode != "KNOWLEDGE_PACKAGE_IMPORT_REJECTED" {
		t.Fatalf("rejected update: code=%d calls=%d output=%+v stderr=%q", code, calls, output, stderr)
	}
	if !reflect.DeepEqual(beforeRejectedUpdate, snapshotUpdateTree(t, store)) {
		t.Fatal("pre-store package/plan digest mismatch changed active store")
	}
	status, err := knowledge.InspectConstraints(store)
	if err != nil || status.State != "READY" || !status.CurrentEligible || status.SelectedRevision != releases[1].revision || status.TrustReceiptDigest != active.TrustReceiptDigest {
		t.Fatalf("rejected update changed active selection: status=%+v err=%v", status, err)
	}
	t.Run("post-rejection", func(t *testing.T) {
		assertCurrentKyvernoRuleOutcomes(t, dir, store, releases[1], active, mustParseReleaseTime(t, kyvernoReportsValidUntil))
	})
}

func TestKnowledgeReleasePlanPublisherToClientFirstAndSecondUpdate(t *testing.T) {
	rootRaw, rootDigest, releases := publishedReleaseFixture(t)
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	rootPath := writeKnowledgeReleaseFile(t, dir, "test-root.json", rootRaw)
	store := filepath.Join(dir, "store")
	packages := map[string][]byte{}
	for i, release := range releases {
		planPath := writeKnowledgeReleaseFile(t, dir, "plan-"+release.revision+".json", release.planRaw)
		plan, err := knowledgereleaseplan.Parse(release.planRaw)
		if err != nil {
			t.Fatal(err)
		}
		assertionDigest, err := plan.VerificationAssertionsDigest()
		if err != nil {
			t.Fatal(err)
		}
		packages[release.url] = release.packageRaw
		outputPath := filepath.Join(dir, "package-"+release.revision+".tar")
		args := []string{"--release-plan", planPath, "--package-out", outputPath, "--db-root", store, "--format", "json"}
		if i == 0 {
			args = append(args, "--bootstrap-root", rootPath, "--bootstrap-root-digest", rootDigest)
		}
		calls := 0
		code, output, stderr := runReleasePlanUpdate(t, args, func(_ context.Context, source string) ([]byte, error) {
			calls++
			return bytes.Clone(packages[source]), nil
		})
		if code != ExitOK || stderr != "" || calls != 1 || output.Status != "IMPORTED" || !output.NetworkAttempted || !output.TransferCompleted || !output.PackageRetained || output.ImportReceipt == nil || output.ImportReceipt.TrustReceipt.KnowledgeRevision != release.revision || output.ImportReceipt.TrustReceipt.APIVersion != "prufyx.io/knowledge-trust-receipt/v2" || output.ImportReceipt.TrustReceipt.ExpectedVerificationAssertionsDigest != assertionDigest {
			t.Fatalf("release %d: code=%d calls=%d output=%+v stderr=%q", i, code, calls, output, stderr)
		}
		retained, err := os.ReadFile(outputPath)
		if err != nil || !bytes.Equal(retained, release.packageRaw) {
			t.Fatalf("release %d retained package mismatch: %v", i, err)
		}
	}
	status, err := knowledge.InspectConstraints(store)
	if err != nil || status.SelectedRevision != releases[1].revision {
		t.Fatalf("second plan did not select revision %s: %+v err=%v", releases[1].revision, status, err)
	}
}

func TestKnowledgeReleasePlanWrongPackageDigestPrecedesStoreMutation(t *testing.T) {
	rootRaw, rootDigest, releases := publishedReleaseFixture(t)
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	rootPath := writeKnowledgeReleaseFile(t, dir, "test-root.json", rootRaw)
	plan, err := knowledgereleaseplan.Parse(releases[0].planRaw)
	if err != nil {
		t.Fatal(err)
	}
	plan.Package.Digest = "sha256:" + strings.Repeat("0", 64)
	planRaw, err := knowledgereleaseplan.Marshal(plan)
	if err != nil {
		t.Fatal(err)
	}
	planPath := writeKnowledgeReleaseFile(t, dir, "wrong-package-plan.json", planRaw)
	store := filepath.Join(dir, "store")
	outputPath := filepath.Join(dir, "retained.tar")
	calls := 0
	code, output, stderr := runReleasePlanUpdate(t, []string{
		"--release-plan", planPath, "--package-out", outputPath, "--db-root", store,
		"--bootstrap-root", rootPath, "--bootstrap-root-digest", rootDigest, "--format", "json",
	}, func(context.Context, string) ([]byte, error) {
		calls++
		return bytes.Clone(releases[0].packageRaw), nil
	})
	if code != ExitIntegrity || stderr != "" || calls != 1 || !output.NetworkAttempted || !output.TransferCompleted || !output.PackageRetained || output.PackageDigest != testDigest(releases[0].packageRaw) || output.ImportReceipt != nil || output.Rejection != nil || output.ReasonCode != "KNOWLEDGE_PACKAGE_IMPORT_REJECTED" {
		t.Fatalf("code=%d calls=%d output=%+v stderr=%q", code, calls, output, stderr)
	}
	if _, err := os.Lstat(store); !os.IsNotExist(err) {
		t.Fatalf("wrong package digest reached store: %v", err)
	}
}

func TestKnowledgeReleasePlanVerifiedBindingMismatchesCannotSelect(t *testing.T) {
	rootRaw, rootDigest, releases := publishedReleaseFixture(t)
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	rootPath := writeKnowledgeReleaseFile(t, dir, "test-root.json", rootRaw)
	store := filepath.Join(dir, "store")
	firstPlan := writeKnowledgeReleaseFile(t, dir, "first-plan.json", releases[0].planRaw)
	code, _, stderr := runReleasePlanUpdate(t, []string{
		"--release-plan", firstPlan, "--package-out", filepath.Join(dir, "first.tar"), "--db-root", store,
		"--bootstrap-root", rootPath, "--bootstrap-root-digest", rootDigest, "--format", "json",
	}, func(context.Context, string) ([]byte, error) { return bytes.Clone(releases[0].packageRaw), nil })
	if code != ExitOK || stderr != "" {
		t.Fatalf("bootstrap failed: code=%d stderr=%q", code, stderr)
	}
	base, err := knowledgereleaseplan.Parse(releases[1].planRaw)
	if err != nil {
		t.Fatal(err)
	}
	badDigest := "sha256:" + strings.Repeat("0", 64)
	tests := []struct {
		name   string
		mutate func(*knowledgereleaseplan.Plan)
	}{
		{name: "role", mutate: func(p *knowledgereleaseplan.Plan) { p.PublisherVerification.Timestamp.Digest = badDigest }},
		{name: "target digest", mutate: func(p *knowledgereleaseplan.Plan) { p.Target.Digest = badDigest }},
		{name: "revision", mutate: func(p *knowledgereleaseplan.Plan) { p.Target.Revision = "999" }},
		{name: "capability", mutate: func(p *knowledgereleaseplan.Plan) { p.Target.EngineCapabilityDigest = badDigest }},
		{name: "root", mutate: func(p *knowledgereleaseplan.Plan) {
			p.PublisherVerification.PublisherInitialRootDigest = badDigest
			p.PublisherVerification.RootHistory[0].Digest = badDigest
			p.PublisherVerification.Root.Digest = badDigest
		}},
	}
	for caseIndex, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			plan := base
			plan.PublisherVerification.RootHistory = append([]knowledge.RootHistoryEntry(nil), base.PublisherVerification.RootHistory...)
			test.mutate(&plan)
			raw, err := knowledgereleaseplan.Marshal(plan)
			if err != nil {
				t.Fatal(err)
			}
			planPath := writeKnowledgeReleaseFile(t, dir, "bad-plan-"+strings.ReplaceAll(test.name, " ", "-")+".json", raw)
			calls := 0
			code, output, stderr := runReleasePlanUpdate(t, []string{
				"--release-plan", planPath, "--package-out", filepath.Join(dir, "bad-package-"+string(rune('a'+caseIndex))+".tar"), "--db-root", store, "--format", "json",
			}, func(context.Context, string) ([]byte, error) {
				calls++
				return bytes.Clone(releases[1].packageRaw), nil
			})
			if code != ExitIntegrity || stderr != "" || calls != 1 || !output.PackageRetained || output.Rejection == nil || output.Rejection.SelectionChanged {
				t.Fatalf("code=%d calls=%d output=%+v stderr=%q", code, calls, output, stderr)
			}
			if output.Rejection.TrustStateAdvanced != (caseIndex == 0) {
				t.Fatalf("trust progress is not truthful for case %d: %+v", caseIndex, output.Rejection)
			}
			status, err := knowledge.InspectConstraints(store)
			if err != nil && !errors.Is(err, knowledge.ErrTrustAdvanced) {
				t.Fatalf("status failed: %+v err=%v", status, err)
			}
			if status.SelectedRevision != releases[0].revision {
				t.Fatalf("binding mismatch selected revision: %+v", status)
			}
		})
	}
}

func TestKnowledgeReleasePlanRejectsConflictAndMalformedPlanBeforeFetch(t *testing.T) {
	_, _, releases := publishedReleaseFixture(t)
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	validPath := writeKnowledgeReleaseFile(t, dir, "valid-plan.json", releases[0].planRaw)
	duplicatePath := writeKnowledgeReleaseFile(t, dir, "duplicate-plan.json", bytes.Replace(releases[0].planRaw, []byte(`"schema":`), []byte(`"schema":"prufyx.io/knowledge-release-plan/v1","schema":`), 1))
	unknownPath := writeKnowledgeReleaseFile(t, dir, "unknown-plan.json", append(releases[0].planRaw[:len(releases[0].planRaw)-1], []byte(`,"unknown":true}`)...))
	oversizedPath := writeKnowledgeReleaseFile(t, dir, "oversized-plan.json", bytes.Repeat([]byte{'x'}, knowledgereleaseplan.MaxBytes+1))
	unsupportedProfilePath := writeKnowledgeReleaseFile(t, dir, "unsupported-profile-plan.json", bytes.Replace(releases[0].planRaw, []byte(`"profile":"cncf"`), []byte(`"profile":"cert-manager"`), 1))
	wrongTargetPath := writeKnowledgeReleaseFile(t, dir, "wrong-target-plan.json", bytes.Replace(releases[0].planRaw, []byte(`"path":"knowledge/constraints.v1.json"`), []byte(`"path":"knowledge/other.json"`), 1))
	cases := [][]string{
		{"--release-plan", validPath, "--source", releases[0].url},
		{"--release-plan", validPath, "--profile", "cncf"},
		{"--release-plan", validPath, "--expected-revision", "1"},
		{"--release-plan", validPath, "--expected-bundle-digest", testDigest(releases[0].packageRaw)},
		{"--release-plan", duplicatePath},
		{"--release-plan", unknownPath},
		{"--release-plan", oversizedPath},
		{"--release-plan", unsupportedProfilePath},
		{"--release-plan", wrongTargetPath},
	}
	for i, prefix := range cases {
		args := append(append([]string{}, prefix...), "--package-out", filepath.Join(dir, "rejected-"+string(rune('a'+i))+".tar"), "--db-root", filepath.Join(dir, "store"), "--format", "json")
		calls := 0
		code, output, stderr := runReleasePlanUpdate(t, args, func(context.Context, string) ([]byte, error) {
			calls++
			return nil, nil
		})
		if code != ExitUsage || calls != 0 || output.APIVersion != "" || strings.Contains(stderr, dir) {
			t.Fatalf("case %d: code=%d calls=%d output=%+v stderr=%q", i, code, calls, output, stderr)
		}
	}
}

func assertExportedKyvernoReviewIdentity(t *testing.T, target []byte) {
	t.Helper()
	var exported struct {
		Pack struct {
			Entries []struct {
				Project string `json:"project"`
				Rule    struct {
					ID       string `json:"id"`
					Evidence struct {
						ReviewedAt string `json:"reviewedAt"`
						ValidUntil string `json:"validUntil"`
					} `json:"evidence"`
				} `json:"rule"`
			} `json:"entries"`
		} `json:"pack"`
	}
	if err := json.Unmarshal(target, &exported); err != nil {
		t.Fatal(err)
	}
	for _, entry := range exported.Pack.Entries {
		if entry.Project != "kyverno" || entry.Rule.ID != kyvernoReportsChunkSizeRuleID {
			continue
		}
		if entry.Rule.Evidence.ReviewedAt != kyvernoReportsReviewedAt || entry.Rule.Evidence.ValidUntil != kyvernoReportsValidUntil {
			t.Fatalf("Kyverno review identity changed: reviewedAt=%q validUntil=%q", entry.Rule.Evidence.ReviewedAt, entry.Rule.Evidence.ValidUntil)
		}
		return
	}
	t.Fatalf("exported full pack omitted %s", kyvernoReportsChunkSizeRuleID)
}

func assertCurrentKyvernoRuleOutcomes(t *testing.T, dir, store string, release publishedRelease, receipt knowledge.ImportReceipt, validUntil time.Time) {
	t.Helper()
	cases := []struct {
		name        string
		input       string
		freshStatus string
		freshExit   int
	}{
		{name: "pass", input: kyvernoInputFalse, freshStatus: "PASS", freshExit: ExitOK},
		{name: "blocked", input: kyvernoInputTrue, freshStatus: "BLOCKED", freshExit: ExitBlocked},
		{name: "unknown", input: kyvernoInputUnknown, freshStatus: "UNKNOWN", freshExit: ExitUnknown},
	}
	for _, test := range cases {
		t.Run(release.revision+"-"+test.name, func(t *testing.T) {
			inputRaw := []byte(test.input)
			inputPath := writeKnowledgeReleaseFile(t, dir, "kyverno-"+release.revision+"-"+test.name+".json", inputRaw)
			selection := knowledge.SelectionRequest{
				StoreRoot: store, ExpectedRevision: release.revision,
				ExpectedBundleDigest:       receipt.TrustReceipt.TargetDigest,
				ExpectedTrustReceiptDigest: receipt.TrustReceiptDigest,
			}
			code, stdout, stderr := runCommunity(t,
				"check", "cncf", "--project", "kyverno", "--input", inputPath,
				"--input-digest", releaseDigest(inputRaw), "--knowledge-db", store,
				"--knowledge-revision", release.revision,
				"--knowledge-bundle-digest", receipt.TrustReceipt.TargetDigest,
				"--knowledge-trust-receipt-digest", receipt.TrustReceiptDigest,
				"--format", "json",
			)
			var routed cncfknowledge.Report
			if stderr != "" || json.Unmarshal([]byte(stdout), &routed) != nil {
				t.Fatalf("public route code=%d stdout=%q stderr=%q", code, stdout, stderr)
			}
			if routed.Assessment != "UNKNOWN" || routed.Knowledge.Origin != "external_signed_local" || routed.Knowledge.TrustSource != "OPERATOR_PROVISIONED" || routed.Knowledge.Purpose != "operator_provided" || routed.Knowledge.Revision != release.revision || routed.Knowledge.BundleDigest != receipt.TrustReceipt.TargetDigest || routed.Knowledge.TrustReceiptDigest != receipt.TrustReceiptDigest || routed.Knowledge.TrustReceipt.APIVersion != "prufyx.io/knowledge-trust-receipt/v2" || routed.Knowledge.TrustReceipt.ExpectedVerificationAssertionsDigest != receipt.TrustReceipt.ExpectedVerificationAssertionsDigest || routed.Knowledge.CurrentNonRevocation != "not_checked_offline" || routed.Check.KnowledgeOrigin != "external_declared" || routed.Check.KnowledgeRevision != release.revision || routed.Check.KnowledgePackDigest != receipt.TrustReceipt.TargetDigest || routed.Check.NetworkUsed || len(routed.Check.Check.Claims) != 1 || routed.Check.Check.Claims[0].RuleID != kyvernoReportsChunkSizeRuleID {
				t.Fatalf("public route binding=%+v check=%+v", routed.Knowledge, routed.Check)
			}
			claim := routed.Check.Check.Claims[0]
			if claim.EvidenceReviewedAt != kyvernoReportsReviewedAt || claim.EvidenceValidUntil != kyvernoReportsValidUntil {
				t.Fatalf("public route evidence identity=%+v", claim)
			}
			evaluatedAt := mustParseReleaseTime(t, routed.Knowledge.EvaluatedAt)
			expectedStatus, expectedExit := test.freshStatus, test.freshExit
			if !evaluatedAt.Before(validUntil) {
				expectedStatus, expectedExit = "UNKNOWN", ExitUnknown
				if claim.ReasonCode != "RULE_EVIDENCE_STALE" || claim.EvidenceFreshness != "stale" {
					t.Fatalf("expired real rule did not stay UNKNOWN: %+v", claim)
				}
			} else if claim.EvidenceFreshness != "current" {
				t.Fatalf("fresh real rule evidence=%+v", claim)
			}
			if code != expectedExit || claim.Status != expectedStatus {
				t.Fatalf("public route code=%d status=%q want code=%d status=%q report=%s", code, claim.Status, expectedExit, expectedStatus, stdout)
			}
			if strings.Contains(stdout, dir) || strings.Contains(stderr, dir) || strings.Contains(stdout, release.url) {
				t.Fatalf("private path or routing URL crossed report boundary: stdout=%q stderr=%q", stdout, stderr)
			}

			selected, err := cncfknowledge.EvaluateCurrent(cncfknowledge.Request{
				Selection: selection, Project: "kyverno", SelectedRuleID: kyvernoReportsChunkSizeRuleID,
				Input: inputRaw, InputDigest: releaseDigest(inputRaw),
			})
			if err != nil {
				t.Fatal(err)
			}
			if selected.Check.RequestedRuleID != kyvernoReportsChunkSizeRuleID || selected.Check.SelectedRuleID != kyvernoReportsChunkSizeRuleID || len(selected.Check.Check.Claims) != 1 || selected.Check.Check.Claims[0].RuleID != kyvernoReportsChunkSizeRuleID || selected.Check.Check.Claims[0].Status != expectedStatus || cncfknowledge.ClaimExit(selected) != expectedExit || selected.Check.NetworkUsed || selected.Knowledge.Origin != "external_signed_local" {
				t.Fatalf("selected rule report=%+v", selected)
			}
		})
	}
}

func mustParseReleaseTime(t *testing.T, value string) time.Time {
	t.Helper()
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil || parsed.Location() != time.UTC || parsed.Nanosecond() != 0 || parsed.Format(time.RFC3339) != value {
		t.Fatalf("invalid canonical release time %q: %v", value, err)
	}
	return parsed
}

func runReleasePlanUpdate(t *testing.T, args []string, fetch func(context.Context, string) ([]byte, error)) (int, knowledgeUpdateOutput, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	r := runtime{stdout: &stdout, stderr: &stderr}
	code := r.databaseUpdateWithFetch(context.Background(), args, fetch)
	var output knowledgeUpdateOutput
	if stdout.Len() > 0 {
		if err := json.Unmarshal(stdout.Bytes(), &output); err != nil {
			t.Fatalf("invalid update output: %s", stdout.String())
		}
	}
	return code, output, stderr.String()
}

func publishedReleaseFixture(t *testing.T) ([]byte, string, []publishedRelease) {
	t.Helper()
	return publishedReleaseFixtureForTargets(t, []string{"61", "62"}, emptyPublishedTarget)
}

func publishedNonemptyReleaseFixture(t *testing.T) ([]byte, string, []publishedRelease) {
	t.Helper()
	return publishedReleaseFixtureForTargets(t, []string{"71", "72", "73"}, func(t *testing.T, revision string) []byte {
		t.Helper()
		target, err := cncfcheck.ExportEmbeddedExternalBundle(revision)
		if err != nil {
			t.Fatal(err)
		}
		return target
	})
}

func publishedReleaseFixtureForTargets(t *testing.T, revisions []string, targetForRevision func(*testing.T, string) []byte) ([]byte, string, []publishedRelease) {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	privateParent, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(privateParent, 0o700); err != nil {
		t.Fatal(err)
	}
	keyDir := filepath.Join(privateParent, "test-keys")
	passphrase := []byte("nonempty release test passphrase 123")
	initialized, err := knowledgesign.Init(knowledgesign.InitOptions{
		KeyDir: keyDir, RootExpires: now.Add(7 * 24 * time.Hour).Format(time.RFC3339),
		Passphrase: passphrase,
	})
	if err != nil {
		t.Fatal(err)
	}
	for i := range passphrase {
		passphrase[i] = 0
	}
	rootRaw, rootDigest := initialized.Root, initialized.RootDigest
	releases := make([]publishedRelease, 0, len(revisions))
	for index, revision := range revisions {
		version := int64(index + 1)
		target := targetForRevision(t, revision)
		targetsPrep, err := knowledgepublish.PrepareTargets(knowledgepublish.TargetsOptions{Root: rootRaw, Target: target, RootDigest: rootDigest, Version: version, Expires: now.Add(72 * time.Hour).Format(time.RFC3339)})
		if err != nil {
			t.Fatal(err)
		}
		targets := finalizePublisherTestRole(t, initialized, keyDir, metadata.TARGETS, targetsPrep)
		snapshotPrep, err := knowledgepublish.PrepareSnapshot(knowledgepublish.SnapshotOptions{Root: rootRaw, Target: target, Targets: targets, RootDigest: rootDigest, Version: version, Expires: now.Add(48 * time.Hour).Format(time.RFC3339)})
		if err != nil {
			t.Fatal(err)
		}
		snapshot := finalizePublisherTestRole(t, initialized, keyDir, metadata.SNAPSHOT, snapshotPrep)
		timestampPrep, err := knowledgepublish.PrepareTimestamp(knowledgepublish.TimestampOptions{Root: rootRaw, Target: target, Targets: targets, Snapshot: snapshot, RootDigest: rootDigest, Version: version, Expires: now.Add(24 * time.Hour).Format(time.RFC3339)})
		if err != nil {
			t.Fatal(err)
		}
		timestamp := finalizePublisherTestRole(t, initialized, keyDir, metadata.TIMESTAMP, timestampPrep)
		url := "https://metadata.example.test/cncf-" + revision + ".tar"
		packageRaw, planRaw, receipt, err := knowledgepublish.FinalizePackageWithReleasePlan(knowledgepublish.FinalizePackageOptions{Root: rootRaw, Target: target, Targets: targets, Snapshot: snapshot, Timestamp: timestamp, RootDigest: rootDigest}, url)
		if err != nil || receipt.Status != "VERIFIED_FOR_PACKAGING" || receipt.KnowledgeRevision != revision {
			t.Fatalf("publisher finalization revision=%s receipt=%+v err=%v", revision, receipt, err)
		}
		releases = append(releases, publishedRelease{url: url, revision: revision, targetRaw: target, packageRaw: packageRaw, planRaw: planRaw, finalization: receipt})
	}
	return rootRaw, rootDigest, releases
}

func finalizePublisherTestRole(t *testing.T, initialized knowledgesign.InitResult, keyDir, role string, preparation knowledgepublish.Preparation) []byte {
	t.Helper()
	keyRaw, err := os.ReadFile(filepath.Join(keyDir, role+".key.pem"))
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := knowledgesign.SignRole(knowledgesign.SignOptions{
		Root: initialized.Root, RootDigest: initialized.RootDigest, Role: role,
		Unsigned: preparation.UnsignedMetadata, ExpectedPayloadDigest: releaseDigest(preparation.Payload),
		EncryptedKey: keyRaw, Passphrase: []byte("nonempty release test passphrase 123"),
	})
	if err != nil {
		t.Fatal(err)
	}
	for i := range keyRaw {
		keyRaw[i] = 0
	}
	raw, err := knowledgepublish.FinalizeRole(initialized.Root, initialized.RootDigest, role, preparation.UnsignedMetadata, envelope)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func emptyPublishedTarget(t *testing.T, revision string) []byte {
	t.Helper()
	requirements, err := cncfcheck.ExternalProfileRequirements()
	if err != nil {
		t.Fatal(err)
	}
	pack := struct {
		Schema, Revision, PolicyID, PolicyDigest, LandscapeFileDigest, RegistryDigest string
		Entries                                                                       []any `json:"entries"`
	}{
		Schema: requirements.PackSchema, Revision: revision, PolicyID: requirements.PolicyID,
		PolicyDigest: requirements.PolicyDigest, LandscapeFileDigest: requirements.LandscapeFileDigest,
		RegistryDigest: requirements.RegistryDigest, Entries: []any{},
	}
	// Use explicit tags through a map-free wrapper so production closed-shape
	// admission sees the exact field names used by the publisher contract.
	packRaw, err := json.Marshal(struct {
		Schema              string `json:"schema"`
		Revision            string `json:"revision"`
		PolicyID            string `json:"policyId"`
		PolicyDigest        string `json:"policyDigest"`
		LandscapeFileDigest string `json:"landscapeFileDigest"`
		RegistryDigest      string `json:"registryDigest"`
		Entries             []any  `json:"entries"`
	}{pack.Schema, pack.Revision, pack.PolicyID, pack.PolicyDigest, pack.LandscapeFileDigest, pack.RegistryDigest, pack.Entries})
	if err != nil {
		t.Fatal(err)
	}
	target, err := json.Marshal(struct {
		Schema                 string          `json:"schema"`
		Revision               string          `json:"revision"`
		Purpose                string          `json:"purpose"`
		EngineCapabilityDigest string          `json:"engineCapabilityDigest"`
		Pack                   json.RawMessage `json:"pack"`
	}{requirements.Schema, revision, "operator_provided", requirements.EngineCapabilityDigest, packRaw})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cncfcheck.ParseExternalBundle(target); err != nil {
		t.Fatal(err)
	}
	return target
}

func writeKnowledgeReleaseFile(t *testing.T, dir, name string, raw []byte) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func releaseDigest(raw []byte) string {
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}
