// SPDX-License-Identifier: AGPL-3.0-only

package knowledgegate

import (
	"bytes"
	"encoding/json"
	"go/parser"
	"go/token"
	"os"
	"sort"
	"strings"
	"testing"
	"time"
)

const (
	admHead   = "1111111111111111111111111111111111111111"
	admBase   = "2222222222222222222222222222222222222222"
	admBot    = "prufyx-bot"
	admOwner  = "airstand"
	admDigest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	admOther  = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

func admDigests(c string) AdmissionDigests {
	d := strings.Repeat(c, 64)
	return AdmissionDigests{Registry: "sha256:" + d, Table: "sha256:" + d, Targets: "sha256:" + d, Pack: "rev1"}
}

// admOK is an input that is admitted; every negative changes one member.
func admOK() OnboardingAdmissionInput {
	return OnboardingAdmissionInput{
		Config: OnboardingAdmissionConfig{
			Enabled:      true,
			StaticPaths:  []string{"cli/data/table.json", "cli/docs/out.json"},
			ProjectPaths: []string{"cli/recipes/{slug}/"},
			TargetPath:   "cli/targets/target-{slug}.json",
		},
		Now:        time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC),
		GatePassed: true, OnboardingPresent: true, OnboardingOK: true, BatchCount: 1, PauseKnown: true,
		HeadSHA: admHead, BaseSHA: admBase, GitHeadSHA: admHead,
		Author: admBot, Sender: admBot, BotLogin: admBot, Owner: admOwner,
		CommitStatus: "ahead", CommitAheadBy: 1, CommitTotal: 1,
		Commits: []AdmissionCommit{{SHA: admHead, Author: admBot, Committer: admBot, Verified: true}},
		Batch: AdmissionBatch{
			ID: "b1", Path: "cli/onboarding/b1.json", KeyID: "k-bot", Tier: ApprovalTierOwner, Identity: "owner", Nonce: "n1",
			NotAfter: "2026-12-01T00:00:00Z", ChangeSetDigest: admDigest, SummaryDigest: admDigest,
		},
		SignatureVerified: true, KeyInBaseKeyset: true, KeysetDigest: admDigest, TrustRootDigest: admDigest,
		ComputedChangeSet: admDigest,
		BatchBaseDigests:  admDigests("1"), GateBaseDigests: admDigests("1"),
		BatchHeadDigests: admDigests("2"), GateHeadDigests: admDigests("2"),
		Projects:   []AdmissionProject{{Slug: "alpha", Kind: OnboardingKindNew, TargetSHA256: admDigest}},
		RegenKnown: true, RegenByteEqual: true, RegenOutputsSHA256: admDigest,
		ExclusionsKnown: true, RecipeExclusionsKnown: true, BaseAbsenceKnown: true, FileModesOK: true,
		ChangedPaths: []string{"cli/data/table.json", "cli/targets/target-alpha.json", "cli/recipes/alpha/recipe.json", "cli/onboarding/b1.json"},
		TrustPaths:   []string{"cli/knowledge/trust/", "cli/knowledge/reattestation/trust-root.json"},
		BatchDir:     "cli/onboarding",
		VerifyPr:     &VerifyPrResult{Outcome: "pass", BindingVerified: true, ChangedPathsSHA256: admDigest, RecipeChange: "new", BaseSHA: admBase, HeadSHA: admHead, BindingDigest: admDigest, Slugs: []string{"alpha"}},
	}
}

func TestAdmitOnboardingAutoPositive(t *testing.T) {
	t.Parallel()
	d := AdmitOnboardingAuto(admOK())
	if !d.Admitted || len(d.Reasons) != 0 || d.Schema != OnboardingAdmissionSchema {
		t.Fatalf("%+v", d)
	}
	if d.PathSetSHA == "" || d.DecisionDigest == "" || d.ObservedAt != "2026-11-15T12:00:00Z" {
		t.Fatalf("binding %+v", d)
	}
	in := admOK()
	// The bot tier is never admitted: no verified policy loader exists.
	in.Batch.Tier = ApprovalTierOnboardingBot
	if d := AdmitOnboardingAuto(in); d.Admitted {
		t.Fatal("bot tier admitted")
	}
	in = admOK()
	if d := AdmitOnboardingAuto(in); !d.Admitted {
		t.Fatalf("owner tier: %v", d.Reasons)
	}
}

func TestAdmitOnboardingAutoNegatives(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		want string
		edit func(*OnboardingAdmissionInput)
	}{
		{"flag off", AdmitReasonDisabled, func(i *OnboardingAdmissionInput) { i.Config.Enabled = false }},
		{"gate failed", AdmitReasonGateFailed, func(i *OnboardingAdmissionInput) { i.GatePassed = false }},
		{"shadow", AdmitReasonShadow, func(i *OnboardingAdmissionInput) { i.Shadow = true }},
		{"no batch", AdmitReasonNoBatch, func(i *OnboardingAdmissionInput) { i.OnboardingPresent = false }},
		{"two batches", AdmitReasonNoBatch, func(i *OnboardingAdmissionInput) { i.BatchCount = 2 }},
		{"onboarding checks failed", AdmitReasonBatchNotOK, func(i *OnboardingAdmissionInput) { i.OnboardingOK = false }},
		{"paused", AdmitReasonPaused, func(i *OnboardingAdmissionInput) { i.Paused = true }},
		{"pause unknown", AdmitReasonPauseUnknown, func(i *OnboardingAdmissionInput) { i.PauseKnown = false }},
		{"unsigned batch", AdmitReasonSignature, func(i *OnboardingAdmissionInput) { i.SignatureVerified = false }},
		{"signature not by base keyset", AdmitReasonKeyNotInBase, func(i *OnboardingAdmissionInput) { i.KeyInBaseKeyset = false }},
		{"keyset self-grant: key only in head", AdmitReasonKeyNotInBase, func(i *OnboardingAdmissionInput) {
			i.KeyInBaseKeyset = false
			i.ChangedPaths = append(i.ChangedPaths, "cli/knowledge/trust/web-approval-keys.json")
		}},
		{"keyset self-grant: trust path touched", AdmitReasonTrustPath, func(i *OnboardingAdmissionInput) {
			i.ChangedPaths = append(i.ChangedPaths, "cli/knowledge/trust/web-approval-keys.json")
		}},
		{"approval-keys by name", AdmitReasonTrustPath, func(i *OnboardingAdmissionInput) {
			i.ChangedPaths = append(i.ChangedPaths, "cli/other/x-approval-keys.json")
		}},
		{"trust root", AdmitReasonTrustPath, func(i *OnboardingAdmissionInput) {
			i.ChangedPaths = append(i.ChangedPaths, "cli/knowledge/reattestation/trust-root.json")
		}},
		{"keyset digest missing", AdmitReasonKeyset, func(i *OnboardingAdmissionInput) { i.KeysetDigest = "" }},
		{"trust root digest missing", AdmitReasonTrustRoot, func(i *OnboardingAdmissionInput) { i.TrustRootDigest = "x" }},
		{"unknown tier", AdmitReasonTier, func(i *OnboardingAdmissionInput) { i.Batch.Tier = "" }},
		{"bot tier is refused whatever is supplied", AdmitReasonBotPolicy, func(i *OnboardingAdmissionInput) { i.Batch.Tier = ApprovalTierOnboardingBot }},
		{"bot tier with every other input valid", AdmitReasonBotPolicy, func(i *OnboardingAdmissionInput) {
			i.Batch.Tier, i.Batch.KeyID, i.KeyInBaseKeyset, i.SignatureVerified = ApprovalTierOnboardingBot, "k-bot", true, true
		}},
		{"batch expired", AdmitReasonBatchExpired, func(i *OnboardingAdmissionInput) { i.Now = time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC) }},
		{"batch expired at the instant", AdmitReasonBatchExpired, func(i *OnboardingAdmissionInput) {
			i.Now = time.Date(2026, 12, 1, 0, 0, 0, 0, time.UTC)
		}},
		{"time unknown", AdmitReasonBatchExpired, func(i *OnboardingAdmissionInput) { i.Now = time.Time{} }},
		{"notAfter unparsable", AdmitReasonBatchExpired, func(i *OnboardingAdmissionInput) { i.Batch.NotAfter = "soon" }},
		{"nonce empty", AdmitReasonProjects, func(i *OnboardingAdmissionInput) { i.Batch.Nonce = "" }},
		{"change set differs (changed recipe)", AdmitReasonChangeSet, func(i *OnboardingAdmissionInput) { i.ComputedChangeSet = admOther }},
		{"change set invalid", AdmitReasonChangeSet, func(i *OnboardingAdmissionInput) { i.Batch.ChangeSetDigest, i.ComputedChangeSet = "", "" }},
		{"head digest differs (replay across batches)", AdmitReasonDigests, func(i *OnboardingAdmissionInput) { i.BatchHeadDigests = admDigests("3") }},
		{"head registry differs", AdmitReasonDigests, func(i *OnboardingAdmissionInput) { i.GateHeadDigests.Registry = admOther }},
		{"head table differs", AdmitReasonDigests, func(i *OnboardingAdmissionInput) { i.GateHeadDigests.Table = admOther }},
		{"head targets differ", AdmitReasonDigests, func(i *OnboardingAdmissionInput) { i.GateHeadDigests.Targets = admOther }},
		{"head pack differs", AdmitReasonDigests, func(i *OnboardingAdmissionInput) { i.GateHeadDigests.Pack = "rev2" }},
		{"base digest differs (replay on another base)", AdmitReasonDigests, func(i *OnboardingAdmissionInput) { i.BatchBaseDigests = admDigests("4") }},
		{"digests absent", AdmitReasonDigests, func(i *OnboardingAdmissionInput) {
			i.BatchHeadDigests, i.GateHeadDigests = AdmissionDigests{}, AdmissionDigests{}
		}},
		{"regeneration unknown", AdmitReasonRegen, func(i *OnboardingAdmissionInput) { i.RegenKnown = false }},
		{"regeneration differs", AdmitReasonRegen, func(i *OnboardingAdmissionInput) { i.RegenByteEqual = false }},
		{"regeneration digest missing", AdmitReasonRegen, func(i *OnboardingAdmissionInput) { i.RegenOutputsSHA256 = "" }},
		{"no projects", AdmitReasonProjects, func(i *OnboardingAdmissionInput) { i.Projects = nil }},
		{"duplicate slug", AdmitReasonProjects, func(i *OnboardingAdmissionInput) { i.Projects = append(i.Projects, i.Projects[0]) }},
		{"slug path injection", AdmitReasonProjects, func(i *OnboardingAdmissionInput) { i.Projects[0].Slug = "../x" }},
		{"target digest missing", AdmitReasonProjects, func(i *OnboardingAdmissionInput) { i.Projects[0].TargetSHA256 = "" }},
		{"attest is owner only", AdmitReasonOwnerOnly, func(i *OnboardingAdmissionInput) { i.Projects[0].Kind = OnboardingKindAttest }},
		{"empty kind is owner only", AdmitReasonOwnerOnly, func(i *OnboardingAdmissionInput) { i.Projects[0].Kind = "" }},
		{"exclusion added", AdmitReasonExclusion, func(i *OnboardingAdmissionInput) { i.HeadExclusions = []string{"alpha\x00e1"} }},
		{"exclusion added next to an existing one", AdmitReasonExclusion, func(i *OnboardingAdmissionInput) {
			i.BaseExclusions, i.HeadExclusions = []string{"beta\x00e1"}, []string{"beta\x00e1", "alpha\x00e2"}
		}},
		{"exclusion replaced at the same count", AdmitReasonExclusion, func(i *OnboardingAdmissionInput) {
			i.BaseExclusions, i.HeadExclusions = []string{"beta\x00e1"}, []string{"beta\x00e2"}
		}},
		{"exclusion replaced at the same count also removes", AdmitReasonExclusionRemoved, func(i *OnboardingAdmissionInput) {
			i.BaseExclusions, i.HeadExclusions = []string{"beta\x00e1"}, []string{"beta\x00e2"}
		}},
		{"exclusion removed", AdmitReasonExclusionRemoved, func(i *OnboardingAdmissionInput) {
			i.BaseExclusions, i.HeadExclusions = []string{"beta\x00e1"}, nil
		}},
		{"exclusion case variant", AdmitReasonExclusion, func(i *OnboardingAdmissionInput) {
			i.BaseExclusions, i.HeadExclusions = []string{"beta\x00Vendor/"}, []string{"beta\x00vendor/"}
		}},
		{"exclusion duplicate in head", AdmitReasonExclusionInvalid, func(i *OnboardingAdmissionInput) {
			i.BaseExclusions, i.HeadExclusions = []string{"beta\x00e1"}, []string{"beta\x00e1", "beta\x00e1"}
		}},
		{"exclusion duplicate hides a count", AdmitReasonExclusion, func(i *OnboardingAdmissionInput) {
			i.BaseExclusions, i.HeadExclusions = []string{"beta\x00e1", "beta\x00e1"}, []string{"beta\x00e1", "beta\x00e3"}
		}},
		{"exclusion empty identity", AdmitReasonExclusionInvalid, func(i *OnboardingAdmissionInput) { i.HeadExclusions = []string{""} }},
		{"exclusion unknown", AdmitReasonExclusionUnknown, func(i *OnboardingAdmissionInput) { i.ExclusionsKnown = false }},
		{"exclusion unknown despite equal lists", AdmitReasonExclusionUnknown, func(i *OnboardingAdmissionInput) {
			i.ExclusionsKnown = false
			i.BaseExclusions, i.HeadExclusions = []string{"beta\x00e1"}, []string{"beta\x00e1"}
		}},
		{"recipe exclusion not in the real target", AdmitReasonExclusionRecipe, func(i *OnboardingAdmissionInput) {
			i.RecipeExclusions = []string{"alpha\x00vendor/"}
		}},
		{"real target exclusion not in the recipe", AdmitReasonExclusionRecipe, func(i *OnboardingAdmissionInput) {
			i.TargetExclusionPaths = []string{"alpha\x00vendor/"}
		}},
		{"recipe and target differ in case", AdmitReasonExclusionRecipe, func(i *OnboardingAdmissionInput) {
			i.RecipeExclusions, i.TargetExclusionPaths = []string{"alpha\x00Vendor/"}, []string{"alpha\x00vendor/"}
		}},
		{"recipe exclusion duplicated", AdmitReasonExclusionInvalid, func(i *OnboardingAdmissionInput) {
			i.RecipeExclusions, i.TargetExclusionPaths = []string{"alpha\x00v/", "alpha\x00v/"}, []string{"alpha\x00v/"}
		}},
		{"recipe exclusions unknown", AdmitReasonRecipeExclusionUnknown, func(i *OnboardingAdmissionInput) { i.RecipeExclusionsKnown = false }},
		{"path outside allowlist", AdmitReasonPathOutside, func(i *OnboardingAdmissionInput) {
			i.ChangedPaths = append(i.ChangedPaths, "cli/other/file.json")
		}},
		{"another slug's target", AdmitReasonPathOutside, func(i *OnboardingAdmissionInput) {
			i.ChangedPaths = append(i.ChangedPaths, "cli/targets/target-beta.json")
		}},
		{"another slug's recipe dir", AdmitReasonPathOutside, func(i *OnboardingAdmissionInput) {
			i.ChangedPaths = append(i.ChangedPaths, "cli/recipes/beta/recipe.json")
		}},
		{"prefix is not a sibling", AdmitReasonPathOutside, func(i *OnboardingAdmissionInput) {
			i.ChangedPaths = append(i.ChangedPaths, "cli/recipes/alpha2/recipe.json")
		}},
		{"workflow touched", AdmitReasonForbiddenPath, func(i *OnboardingAdmissionInput) {
			i.Config.StaticPaths = append(i.Config.StaticPaths, ".github/workflows/x.yml")
			i.ChangedPaths = append(i.ChangedPaths, ".github/workflows/x.yml")
		}},
		{"codeowners touched", AdmitReasonForbiddenPath, func(i *OnboardingAdmissionInput) {
			i.Config.StaticPaths = append(i.Config.StaticPaths, ".github/CODEOWNERS", "CODEOWNERS")
			i.ChangedPaths = append(i.ChangedPaths, "CODEOWNERS")
		}},
		{"path traversal", AdmitReasonPathSet, func(i *OnboardingAdmissionInput) {
			i.ChangedPaths = append(i.ChangedPaths, "cli/recipes/alpha/../../x")
		}},
		{"duplicate path", AdmitReasonPathSet, func(i *OnboardingAdmissionInput) { i.ChangedPaths = append(i.ChangedPaths, i.ChangedPaths[0]) }},
		{"empty path set", AdmitReasonPathSet, func(i *OnboardingAdmissionInput) { i.ChangedPaths = nil }},
		{"allowlist unset", AdmitReasonAllowlistUnset, func(i *OnboardingAdmissionInput) {
			i.Config.StaticPaths, i.Config.ProjectPaths = nil, nil
		}},
		{"batch file missing from change", AdmitReasonBatchPath, func(i *OnboardingAdmissionInput) { i.ChangedPaths = i.ChangedPaths[:3] }},
		{"batch path differs", AdmitReasonBatchPath, func(i *OnboardingAdmissionInput) { i.Batch.Path = "cli/onboarding/other.json" }},
		{"batch id with slash", AdmitReasonBatchPath, func(i *OnboardingAdmissionInput) { i.Batch.ID = "a/b" }},
		{"target file missing", AdmitReasonProjects, func(i *OnboardingAdmissionInput) {
			i.ChangedPaths = []string{"cli/data/table.json", "cli/recipes/alpha/recipe.json", "cli/onboarding/b1.json"}
		}},
		{"target template unset", AdmitReasonProjects, func(i *OnboardingAdmissionInput) { i.Config.TargetPath = "" }},
		{"file modes", AdmitReasonFileModes, func(i *OnboardingAdmissionInput) { i.FileModesOK = false }},
		{"verifyPr absent", AdmitReasonVerifyAbsent, func(i *OnboardingAdmissionInput) { i.VerifyPr = nil }},
		{"verifyPr failed", AdmitReasonVerifyNotPass, func(i *OnboardingAdmissionInput) { i.VerifyPr.Outcome = "fail" }},
		{"verifyPr outcome empty", AdmitReasonVerifyNotPass, func(i *OnboardingAdmissionInput) { i.VerifyPr.Outcome = "" }},
		{"verifyPr binding not verified", AdmitReasonVerifyNotPass, func(i *OnboardingAdmissionInput) { i.VerifyPr.BindingVerified = false }},
		{"verifyPr recipe changed", AdmitReasonVerifyRecipe, func(i *OnboardingAdmissionInput) { i.VerifyPr.RecipeChange = "changed" }},
		{"verifyPr recipe unchanged is not an onboarding", AdmitReasonVerifyRecipe, func(i *OnboardingAdmissionInput) { i.VerifyPr.RecipeChange = "unchanged" }},
		{"verifyPr changed paths digest missing", AdmitReasonVerifyPaths, func(i *OnboardingAdmissionInput) { i.VerifyPr.ChangedPathsSHA256 = "" }},
		{"slug present in base", AdmitReasonBaseAbsent, func(i *OnboardingAdmissionInput) { i.BasePresent = []string{"alpha"} }},
		{"unrelated presence is not clean", AdmitReasonBaseAbsent, func(i *OnboardingAdmissionInput) { i.BasePresent = []string{"zeta"} }},
		{"base absence unknown", AdmitReasonBaseAbsentUnknown, func(i *OnboardingAdmissionInput) { i.BaseAbsenceKnown = false }},
		{"verifyPr for another base", AdmitReasonVerifyBase, func(i *OnboardingAdmissionInput) {
			i.VerifyPr.BaseSHA = "4444444444444444444444444444444444444444"
		}},
		{"verifyPr for another head", AdmitReasonVerifyHead, func(i *OnboardingAdmissionInput) {
			i.VerifyPr.HeadSHA = "3333333333333333333333333333333333333333"
		}},
		{"verifyPr binding missing", AdmitReasonVerifyBinding, func(i *OnboardingAdmissionInput) { i.VerifyPr.BindingDigest = "" }},
		{"verifyPr other slugs", AdmitReasonVerifySlugs, func(i *OnboardingAdmissionInput) { i.VerifyPr.Slugs = []string{"beta"} }},
		{"verifyPr extra slug", AdmitReasonVerifySlugs, func(i *OnboardingAdmissionInput) { i.VerifyPr.Slugs = []string{"alpha", "beta"} }},
		{"verifyPr no slugs", AdmitReasonVerifySlugs, func(i *OnboardingAdmissionInput) { i.VerifyPr.Slugs = nil }},
		{"forged author", AdmitReasonAuthor, func(i *OnboardingAdmissionInput) { i.Author = "someone" }},
		{"empty author and bot", AdmitReasonAuthor, func(i *OnboardingAdmissionInput) { i.Author, i.BotLogin = "", "" }},
		{"re-run by another sender", AdmitReasonSender, func(i *OnboardingAdmissionInput) { i.Sender = "someone" }},
		{"bot login unset", AdmitReasonBotLogin, func(i *OnboardingAdmissionInput) { i.BotLogin = "" }},
		{"owner-authored is never machine class", AdmitReasonOwnerPrincipal, func(i *OnboardingAdmissionInput) {
			i.Author, i.Sender, i.BotLogin = admOwner, admOwner, admOwner
			i.Commits[0].Author, i.Commits[0].Committer = admOwner, admOwner
		}},
		{"owner unknown", AdmitReasonOwnerPrincipal, func(i *OnboardingAdmissionInput) { i.Owner = "" }},
		{"stale head: git head differs", AdmitReasonHeadMismatch, func(i *OnboardingAdmissionInput) {
			i.GitHeadSHA = "3333333333333333333333333333333333333333"
		}},
		{"stale head: commit list ends elsewhere", AdmitReasonCommits, func(i *OnboardingAdmissionInput) {
			i.Commits[0].SHA = "3333333333333333333333333333333333333333"
		}},
		{"head sha invalid", AdmitReasonSHA, func(i *OnboardingAdmissionInput) { i.HeadSHA = "abc" }},
		{"base sha missing", AdmitReasonSHA, func(i *OnboardingAdmissionInput) { i.BaseSHA = "" }},
		{"base equals head", AdmitReasonSHA, func(i *OnboardingAdmissionInput) { i.BaseSHA = admHead }},
		{"commit not by bot", AdmitReasonCommits, func(i *OnboardingAdmissionInput) { i.Commits[0].Author = "someone" }},
		{"commit committer differs", AdmitReasonCommits, func(i *OnboardingAdmissionInput) { i.Commits[0].Committer = "web-flow" }},
		{"commit unverified", AdmitReasonCommits, func(i *OnboardingAdmissionInput) { i.Commits[0].Verified = false }},
		{"commit list absent", AdmitReasonCommits, func(i *OnboardingAdmissionInput) { i.Commits, i.CommitTotal = nil, 0 }},
		{"commit list incomplete", AdmitReasonCommits, func(i *OnboardingAdmissionInput) { i.CommitTotal = 2 }},
		{"behind base", AdmitReasonCommits, func(i *OnboardingAdmissionInput) { i.CommitBehindBy = 1 }},
		{"not ahead", AdmitReasonCommits, func(i *OnboardingAdmissionInput) { i.CommitAheadBy, i.CommitStatus = 0, "identical" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := admOK()
			tc.edit(&in)
			d := AdmitOnboardingAuto(in)
			if d.Admitted {
				t.Fatalf("admitted: %+v", d)
			}
			found := false
			for _, r := range d.Reasons {
				found = found || r == tc.want
			}
			if !found {
				t.Fatalf("want reason %q, got %v", tc.want, d.Reasons)
			}
			if tc.want == AdmitReasonDisabled && len(d.Reasons) != 1 {
				t.Fatalf("disabled must be the only reason: %v", d.Reasons)
			}
		})
	}
}

// An unchanged, reordered exclusion set (also with exclusions that exist on
// both sides) is not a change.
func TestAdmitOnboardingAutoExclusionSetOrderIrrelevant(t *testing.T) {
	t.Parallel()
	in := admOK()
	in.BaseExclusions = []string{"beta\x00e1", "gamma\x00e2", "beta\x00e3"}
	in.HeadExclusions = []string{"beta\x00e3", "beta\x00e1", "gamma\x00e2"}
	in.RecipeExclusions = []string{"alpha\x00a/", "alpha\x00b/"}
	in.TargetExclusionPaths = []string{"alpha\x00b/", "alpha\x00a/"}
	d := AdmitOnboardingAuto(in)
	if !d.Admitted {
		t.Fatalf("%v", d.Reasons)
	}
	// ... and an exclusion set that only the head carries is the target's own
	// change, never admitted.
	in.HeadExclusions = append(in.HeadExclusions, "alpha\x00a")
	if d := AdmitOnboardingAuto(in); d.Admitted {
		t.Fatal("admitted a new exclusion")
	}
	a, b := admOK(), admOK()
	b.BaseExclusions, b.HeadExclusions = []string{"x\x00y", "x\x00z"}, []string{"x\x00z", "x\x00y"}
	c := b
	c.BaseExclusions, c.HeadExclusions = []string{"x\x00z", "x\x00y"}, []string{"x\x00y", "x\x00z"}
	if AdmitOnboardingAuto(b).DecisionDigest != AdmitOnboardingAuto(c).DecisionDigest {
		t.Fatal("list order moves the decision digest")
	}
	if AdmitOnboardingAuto(a).DecisionDigest == AdmitOnboardingAuto(b).DecisionDigest {
		t.Fatal("the exclusion sets are not bound")
	}
}

// The zero input admits nothing and every unknown is a reason.
func TestAdmitOnboardingAutoZeroInputFailsClosed(t *testing.T) {
	t.Parallel()
	d := AdmitOnboardingAuto(OnboardingAdmissionInput{})
	if d.Admitted || len(d.Reasons) == 0 {
		t.Fatalf("%+v", d)
	}
	in := OnboardingAdmissionInput{Config: OnboardingAdmissionConfig{Enabled: true}}
	if d := AdmitOnboardingAuto(in); d.Admitted || len(d.Reasons) < 10 {
		t.Fatalf("%+v", d)
	}
}

// Each field the decision binds changes the decision digest, so a decision
// cannot be replayed for another head, batch, path set or key set.
func TestAdmissionDecisionDigestBindsMembers(t *testing.T) {
	t.Parallel()
	base := AdmitOnboardingAuto(admOK())
	edits := map[string]func(*OnboardingAdmissionInput){
		"head": func(i *OnboardingAdmissionInput) {
			i.HeadSHA, i.GitHeadSHA = "3333333333333333333333333333333333333333", "3333333333333333333333333333333333333333"
		},
		"base":         func(i *OnboardingAdmissionInput) { i.BaseSHA = "4444444444444444444444444444444444444444" },
		"author":       func(i *OnboardingAdmissionInput) { i.Author = "x" },
		"sender":       func(i *OnboardingAdmissionInput) { i.Sender = "x" },
		"bot":          func(i *OnboardingAdmissionInput) { i.BotLogin = "y" },
		"commit":       func(i *OnboardingAdmissionInput) { i.Commits[0].Verified = false },
		"batch id":     func(i *OnboardingAdmissionInput) { i.Batch.ID = "b2" },
		"key id":       func(i *OnboardingAdmissionInput) { i.Batch.KeyID = "k2" },
		"tier":         func(i *OnboardingAdmissionInput) { i.Batch.Tier = ApprovalTierOwner },
		"nonce":        func(i *OnboardingAdmissionInput) { i.Batch.Nonce = "n2" },
		"digests":      func(i *OnboardingAdmissionInput) { i.GateHeadDigests = admDigests("5") },
		"paths":        func(i *OnboardingAdmissionInput) { i.ChangedPaths = append(i.ChangedPaths, "cli/docs/out.json") },
		"recipe":       func(i *OnboardingAdmissionInput) { i.VerifyPr.RecipeChange = "changed" },
		"verify":       func(i *OnboardingAdmissionInput) { i.VerifyPr.BindingDigest = admOther },
		"keyset":       func(i *OnboardingAdmissionInput) { i.KeysetDigest = admOther },
		"paths digest": func(i *OnboardingAdmissionInput) { i.VerifyPr.ChangedPathsSHA256 = admOther },
		"regen":        func(i *OnboardingAdmissionInput) { i.RegenOutputsSHA256 = admOther },
		"project":      func(i *OnboardingAdmissionInput) { i.Projects[0].TargetSHA256 = admOther },
	}
	for name, edit := range edits {
		in := admOK()
		edit(&in)
		d := AdmitOnboardingAuto(in)
		if d.DecisionDigest == base.DecisionDigest {
			t.Errorf("%s does not move the decision digest", name)
		}
	}
}

func TestAdmitOnboardingAutoDeterministicAndStable(t *testing.T) {
	t.Parallel()
	a, _ := json.Marshal(AdmitOnboardingAuto(admOK()))
	b, _ := json.Marshal(AdmitOnboardingAuto(admOK()))
	if !bytes.Equal(a, b) {
		t.Fatal("not deterministic")
	}
	// Input order never matters.
	in := admOK()
	in.ChangedPaths = []string{in.ChangedPaths[3], in.ChangedPaths[1], in.ChangedPaths[0], in.ChangedPaths[2]}
	c, _ := json.Marshal(AdmitOnboardingAuto(in))
	if !bytes.Equal(a, c) {
		t.Fatal("path order changes the decision")
	}
	// The member order of the JSON is the struct order: pin it.
	var m map[string]json.RawMessage
	if err := json.Unmarshal(a, &m); err != nil {
		t.Fatal(err)
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	want := "exclusions,authorLogin,baseSha,batch,botLogin,commits,decisionDigest,digests,headSha,keysetDigest,observedAt,pathSet,pathSetSha256,paused,policyDigest,projects,reasons,regen,schema,senderLogin,shadow,trustRootDigest,verifyPr,admitted"
	wantKeys := strings.Split(want, ",")
	sort.Strings(wantKeys)
	if strings.Join(keys, ",") != strings.Join(wantKeys, ",") {
		t.Fatalf("members %v", keys)
	}
	if !bytes.HasPrefix(a, []byte(`{"schema":"onboarding-admission/v1","admitted":true,"reasons":[],"headSha":`)) {
		t.Fatalf("member order: %.120s", a)
	}
}

// AdmitOnboardingAuto is pure: its source imports no package that reaches
// the file system, the network, the clock or a process.
func TestAdmitOnboardingAutoIsPure(t *testing.T) {
	t.Parallel()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "onboarding_admission.go", nil, parser.ImportsOnly)
	if err != nil {
		t.Fatal(err)
	}
	allowed := map[string]bool{"crypto/sha256": true, "encoding/hex": true, "encoding/json": true, "regexp": true, "sort": true, "strings": true, "time": true}
	for _, imp := range f.Imports {
		if p := strings.Trim(imp.Path.Value, `"`); !allowed[p] {
			t.Errorf("onboarding_admission.go imports %s", p)
		}
	}
	raw, err := os.ReadFile("onboarding_admission.go")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte("time.Now")) || bytes.Contains(raw, []byte("os.")) {
		t.Fatal("reads the clock or the environment")
	}
}

func TestOnboardingAdmissionDefaultLayoutIsOff(t *testing.T) {
	t.Parallel()
	if DefaultLayout().OnboardingAdmission.Enabled {
		t.Fatal("the admission flag must default to off")
	}
}

// A report of an onboarding change carries the decision, reports it
// disabled by default, and never turns AutoMerge on, enabled or not.
func TestOnboardingAdmissionInGateReport(t *testing.T) {
	t.Parallel()
	f := newOnboardingFixture(t)
	f.sign(t, f.record(t))
	r := f.gate(t)
	requirePass(t, r)
	if r.AutoMerge.Eligible {
		t.Fatalf("auto merge %+v", r.AutoMerge)
	}
	// Flag off: the report carries no member at all (byte-identical shape).
	if r.OnboardingAdmission != nil {
		t.Fatalf("admission %+v", r.OnboardingAdmission)
	}
	if raw, err := json.Marshal(r); err != nil || bytes.Contains(raw, []byte("onboardingAdmission")) {
		t.Fatalf("flag-off report carries the member: %v", err)
	}
	// Enabled but without the inputs the gate cannot have: still refused,
	// and the old flag stays false.
	r = f.gateWith(t, func(o *Options) {
		o.Layout = DefaultLayout()
		o.Layout.OnboardingAdmission.Enabled = true
	})
	if r.AutoMerge.Eligible {
		t.Fatalf("auto merge %+v", r.AutoMerge)
	}
	if r.OnboardingAdmission == nil || r.OnboardingAdmission.Admitted {
		t.Fatalf("admission %+v", r.OnboardingAdmission)
	}
	have := strings.Join(r.OnboardingAdmission.Reasons, ",")
	for _, want := range []string{AdmitReasonVerifyAbsent, AdmitReasonAuthor, AdmitReasonAllowlistUnset} {
		if !strings.Contains(have, want) {
			t.Fatalf("reasons %s lack %s", have, want)
		}
	}
	raw, err := json.Marshal(r)
	if err != nil || !bytes.Contains(raw, []byte(`"onboardingAdmission":{"schema":"onboarding-admission/v1"`)) {
		t.Fatalf("report json: %v", err)
	}
}

// A change without an onboarding batch has no admission member: the report
// of every other change is byte-identical to before.
func TestOnboardingAdmissionAbsentWithoutBatch(t *testing.T) {
	t.Parallel()
	f := newOnboardingFixture(t)
	r := f.gate(t)
	if r.OnboardingAdmission != nil {
		t.Fatalf("admission %+v", r.OnboardingAdmission)
	}
	raw, err := json.Marshal(r)
	if err != nil || bytes.Contains(raw, []byte("onboardingAdmission")) {
		t.Fatalf("report json carries the member: %v", err)
	}
}
