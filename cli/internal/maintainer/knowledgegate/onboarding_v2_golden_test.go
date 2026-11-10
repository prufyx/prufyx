// SPDX-License-Identifier: AGPL-3.0-only

package knowledgegate

import (
	"strings"
	"testing"
)

// goldenV2Bytes is the exact signed encoding of goldenV2Record, produced by
// the code before onboarding v3 existed. It must never change.
const goldenV2Bytes = "prufyx.io/knowledge-onboarding-batch/v2\x00{\"admissionBinding\":{\"profile\":{\"schema\":\"prufyx.io/published-gate-admission-profile/v1\",\"repository\":\"o/r\",\"baseCommit\":\"cccccccccccccccccccccccccccccccccccccccc\",\"baseTree\":\"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\",\"keysDigest\":\"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"identity\":\"tier-bot\",\"keyId\":\"k\",\"keyNotAfter\":\"2027-01-01T00:00:00Z\",\"tier\":\"onboarding-bot\",\"kind\":\"new\",\"maxProjects\":5,\"maxBatchesWindow\":0,\"maxProjectsWindow\":0,\"windowSeconds\":0,\"maxValiditySeconds\":0,\"keyMarginSeconds\":0,\"automationLogin\":\"\",\"maxLoosening\":0,\"maxWithdrawPercent\":0,\"maxWithdrawProject\":0,\"maxDailyLoosening\":0,\"restBudget\":0,\"pauseRequiredFalse\":false},\"export\":{\"planDigest\":\"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"manifestDigest\":\"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"draftDigest\":\"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"factsDigest\":\"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"bundleDigest\":\"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"exportLineHash\":\"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\",\"publicLineHash\":\"cccccccccccccccccccccccccccccccccccccccc\"},\"unsignedCommit\":\"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\",\"unsignedTree\":\"cccccccccccccccccccccccccccccccccccccccc\",\"changes\":[{\"path\":\"a/b.json\",\"status\":\"A\",\"base\":{\"mode\":\"\",\"blob\":\"\",\"digest\":\"\"},\"head\":{\"mode\":\"100644\",\"blob\":\"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\",\"digest\":\"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"}}],\"observedAt\":\"2026-10-03T11:00:00Z\",\"dailyCommits\":[{\"sha\":\"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\",\"parent\":\"cccccccccccccccccccccccccccccccccccccccc\",\"author\":null}],\"dailyCount\":0,\"historyDigest\":\"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"},\"base\":{\"packRevision\":\"rev.1\",\"registryDigest\":\"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"tableDigest\":\"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"targetsDigest\":\"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"},\"batchId\":\"ob-20261003-1\",\"candidateId\":\"pr-1\",\"changeSetDigest\":\"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"decidedAt\":\"2026-10-03T11:00:00Z\",\"decision\":\"approve\",\"head\":{\"packRevision\":\"rev.1\",\"registryDigest\":\"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"tableDigest\":\"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"targetsDigest\":\"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"},\"identity\":\"tier-bot\",\"nonce\":\"0123456789abcdef0123456789abcdef\",\"notAfter\":\"2026-10-04T11:00:00Z\",\"projects\":[{\"artifacts\":[{\"digest\":\"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"path\":\"a/b.json\"}],\"catalog\":\"cncf\",\"facts\":[\"component.x.custom_resource_versions_set\"],\"groups\":[\"x.example.com\"],\"kind\":\"new\",\"proof\":{\"claims\":{\"confirmed\":1,\"ledger\":\"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"refuted\":0,\"undetermined\":0},\"pair\":{\"fromCommit\":\"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\",\"fromTag\":\"v1\",\"toCommit\":\"cccccccccccccccccccccccccccccccccccccccc\",\"toTag\":\"v2\"},\"scan\":[]},\"slug\":\"x\"}],\"sample\":[0],\"summaryDigest\":\"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"}"

func goldenV2Record() OnboardingRecordV2 {
	d := "sha256:" + strings.Repeat("a", 64)
	sha := strings.Repeat("b", 40)
	parent := strings.Repeat("c", 40)
	st := OnboardingState{PackRevision: "rev.1", RegistryDigest: d, TableDigest: d, TargetsDigest: d}
	rec := OnboardingRecord{
		Base: st, BatchID: "ob-20261003-1", CandidateID: "pr-1", ChangeSetDigest: d, DecidedAt: "2026-10-03T11:00:00Z", Decision: ApprovalDecisionApprove,
		Head: st, Identity: "tier-bot", Nonce: "0123456789abcdef0123456789abcdef", NotAfter: "2026-10-04T11:00:00Z", Sample: []int{0}, SummaryDigest: d,
		Projects: []OnboardingProject{{
			Artifacts: []OnboardingArtifact{{Path: "a/b.json", Digest: d}}, Catalog: "cncf", Facts: []string{"component.x.custom_resource_versions_set"},
			Groups: []string{"x.example.com"}, Kind: OnboardingKindNew,
			Proof: OnboardingProof{Claims: OnboardingClaims{Confirmed: 1, Ledger: d}, Pair: OnboardingPair{FromCommit: sha, FromTag: "v1", ToCommit: parent, ToTag: "v2"}, Scan: []OnboardingFinding{}},
			Slug:  "x",
		}},
	}
	return OnboardingRecordV2{OnboardingRecord: rec, AdmissionBinding: OnboardingAdmissionBinding{
		Profile:        PublishedGateProfile{Schema: onboardingProfileSchema, Repository: "o/r", BaseCommit: parent, BaseTree: sha, KeysDigest: d, Identity: "tier-bot", KeyID: "k", KeyNotAfter: "2027-01-01T00:00:00Z", Tier: "onboarding-bot", Kind: "new", MaxProjects: 5},
		Export:         OnboardingExportBinding{PlanDigest: d, ManifestDigest: d, DraftDigest: d, FactsDigest: d, BundleDigest: d, ExportLineHash: sha, PublicLineHash: parent},
		UnsignedCommit: sha, UnsignedTree: parent,
		Changes:       []OnboardingGitChange{{Path: "a/b.json", Status: "A", Head: OnboardingBlobSide{Mode: "100644", Blob: sha, Digest: d}}},
		ObservedAt:    "2026-10-03T11:00:00Z",
		DailyCommits:  []DailyCommit{{SHA: sha, Parent: &parent}},
		DailyCount:    0,
		HistoryDigest: d,
	}}
}

func TestOnboardingV2BytesGolden(t *testing.T) {
	t.Parallel()
	got, err := SignedOnboardingV2Bytes(goldenV2Record())
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != goldenV2Bytes {
		t.Fatalf("v2 signed bytes differ from the golden literal; got %q", got)
	}
}
