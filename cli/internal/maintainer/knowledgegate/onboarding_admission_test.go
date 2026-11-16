// SPDX-License-Identifier: AGPL-3.0-only

package knowledgegate

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/pathset"
)

const (
	admHead   = "1111111111111111111111111111111111111111"
	admBase   = "2222222222222222222222222222222222222222"
	admBot    = "prufyx-bot"
	admOwner  = "airstand"
	admDigest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	admOther  = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

func admPaths() []string {
	return []string{"cli/data/table.json", "cli/targets/target-alpha.json", "cli/recipes/alpha/recipe.json", "cli/onboarding/b1.json"}
}

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
		ChangedPaths: admPaths(),
		TrustPaths:   []string{"cli/knowledge/trust/", "cli/knowledge/reattestation/trust-root.json"},
		BatchDir:     "cli/onboarding",
		VerifyPr:     &VerifyPrResult{Outcome: "pass", BindingVerified: true, ChangedPathsSHA256: admDig(admPaths()), RecipeChange: "new", BaseSHA: admBase, HeadSHA: admHead, BindingDigest: admDigest, Slugs: []string{"alpha"}},
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
		{"verifyPr covered another path set", AdmitReasonVerifyPathsMismatch, func(i *OnboardingAdmissionInput) { i.VerifyPr.ChangedPathsSHA256 = admOther }},
		{"verifyPr covered a subset of the paths", AdmitReasonVerifyPathsMismatch, func(i *OnboardingAdmissionInput) {
			i.VerifyPr.ChangedPathsSHA256 = admDig(admPaths()[:3])
		}},
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
		"tier":         func(i *OnboardingAdmissionInput) { i.Batch.Tier = ApprovalTierOnboardingBot },
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
	want := "exclusions,authorLogin,baseSha,batch,botLogin,commits,decisionDigest,digests,headSha,keysetDigest,observedAt,pathSet,pathSetSha256,paused,projects,reasons,regen,schema,senderLogin,shadow,trustRootDigest,verifyPr,admitted"
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
	allowed := map[string]bool{"crypto/sha256": true, "encoding/hex": true, "encoding/json": true, "errors": true, "github.com/prufyx/prufyx/cli/internal/pathset": true, "regexp": true, "sort": true, "strings": true, "time": true}
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
	// Enabled by the compiled layout alone: the plain disabled decision.
	r = f.gateWith(t, func(o *Options) {
		o.Layout = DefaultLayout()
		o.Layout.OnboardingAdmission.Enabled = true
	})
	if r.OnboardingAdmission == nil || r.OnboardingAdmission.Admitted || strings.Join(r.OnboardingAdmission.Reasons, ",") != AdmitReasonDisabled {
		t.Fatalf("one lock: %+v", r.OnboardingAdmission)
	}
	// Both locks on but without the inputs the gate cannot have: still
	// refused, and the old flag stays false.
	r = f.gateWith(t, func(o *Options) {
		o.Layout = DefaultLayout()
		o.Layout.OnboardingAdmission.Enabled = true
		o.OnboardingAdmissionInProcess = true
		o.AdmissionEvent = AdmissionEventPullRequestTarget
	})
	if r.AutoMerge.Eligible {
		t.Fatalf("auto merge %+v", r.AutoMerge)
	}
	if r.OnboardingAdmission == nil || r.OnboardingAdmission.Admitted {
		t.Fatalf("admission %+v", r.OnboardingAdmission)
	}
	have := strings.Join(r.OnboardingAdmission.Reasons, ",")
	for _, want := range []string{AdmitReasonVerifyAbsent, AdmitReasonAuthor, AdmitReasonSeamContext} {
		if !strings.Contains(have, want) {
			t.Fatalf("reasons %s lack %s", have, want)
		}
	}
	// The compiled layout names the allow-list now: it is no longer unset.
	if strings.Contains(have, AdmitReasonAllowlistUnset) {
		t.Fatalf("reasons %s: the compiled layout still has no allow-list", have)
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

// admDig is the shared digest of a valid set.
func admDig(paths []string) string {
	d, err := pathset.Digest(paths)
	if err != nil {
		panic(err)
	}
	return d
}

// The decision binds the shared package's digest of the changed paths, for
// the pinned vector, in any order.
func TestPathSetDigestCanonical(t *testing.T) {
	t.Parallel()
	sum := sha256.Sum256([]byte("a/x\nb/y"))
	want := "sha256:" + hex.EncodeToString(sum[:])
	if admDig([]string{"b/y", "a/x"}) != want || admDig([]string{"a/x", "b/y"}) != want {
		t.Fatal("shared digest differs from the pinned vector")
	}
	in := admOK()
	if d := AdmitOnboardingAuto(in); d.PathSetSHA != admDig(in.ChangedPaths) || d.VerifyPr.ChangedPathsSHA256 != d.PathSetSHA {
		t.Fatalf("decision binds %s / %s", d.PathSetSHA, d.VerifyPr.ChangedPathsSHA256)
	}
}

// Golden: the full decision of the reference fixture, byte for byte, and its
// digest. A change of any member, its order, its encoding or the digest
// algorithm fails here. The golden was produced by an independent
// implementation of the algorithm, not by this package.
func TestOnboardingAdmissionGoldenDecision(t *testing.T) {
	t.Parallel()
	const wantDigest = "sha256:b55c30e6af6154d3e4771b639118134118cd7d395c39cef82ecc96043d06bde0"
	d := AdmitOnboardingAuto(admOK())
	if d.DecisionDigest != wantDigest {
		t.Fatalf("decision digest %s", d.DecisionDigest)
	}
	got, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	want, err := os.ReadFile("testdata/onboarding_admission_golden.json")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("decision bytes differ from the golden:\n got %s\nwant %s", got, want)
	}
	// The digest is the sha256 of the same bytes with the digest member empty.
	d.DecisionDigest = ""
	pre, _ := json.Marshal(d)
	sum := sha256.Sum256(pre)
	if "sha256:"+hex.EncodeToString(sum[:]) != wantDigest {
		t.Fatal("digest is not the sha256 of the empty-digest encoding")
	}
}

// Exclusion set digest vectors: sorted, de-duplicated, compact JSON array.
func TestAdmitSetDigestGolden(t *testing.T) {
	t.Parallel()
	for name, tc := range map[string]struct {
		in   []string
		want string
	}{
		"empty":            {nil, "sha256:4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945"},
		"empty non-nil":    {[]string{}, "sha256:4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945"},
		"sorted":           {[]string{"a", "b"}, "sha256:0473ef2dc0d324ab659d3580c1134e9d812035905c4781fdd6d529b0c6860e13"},
		"unsorted":         {[]string{"b", "a"}, "sha256:0473ef2dc0d324ab659d3580c1134e9d812035905c4781fdd6d529b0c6860e13"},
		"duplicate folded": {[]string{"b", "a", "a"}, "sha256:0473ef2dc0d324ab659d3580c1134e9d812035905c4781fdd6d529b0c6860e13"},
		"nul separator":    {[]string{"p\x00x"}, "sha256:978496475acf91b2bc3e8ac5803d759b0c858f1a15480337a4d4417001ee64d8"},
	} {
		if got := admitSetDigest(tc.in); got != tc.want {
			t.Errorf("%s: %s", name, got)
		}
	}
}

// A path set lists each changed path once: a rename is the old path and the
// new path, a delete is the path itself.
func TestPathSetDigestRenameAndDelete(t *testing.T) {
	t.Parallel()
	rename := []string{"cli/old/a.json", "cli/new/a.json"}
	if got := admDig(rename); got != "sha256:d2212e911b2cb1907429cd8aaa46108fac5a1a45833937a40a610d431d343c94" {
		t.Fatalf("rename %s", got)
	}
	if got := admDig([]string{"cli/new/a.json", "cli/old/a.json", "cli/x.json"}); got != "sha256:8330e54fb1d88876b73e7ed121281cb339e4c9680a69a8507bd137fc4a8ee41d" {
		t.Fatalf("rename with another path %s", got)
	}
	if got := admDig([]string{"cli/gone.json"}); got != "sha256:86f5689f8a50b4e97590e495881dc48c3c972f868affdf0802afb5559fb5c165" {
		t.Fatalf("delete %s", got)
	}
	if admDig(rename) == admDig(rename[:1]) || admDig(rename) == admDig(rename[1:]) {
		t.Fatal("a rename digests like one of its halves")
	}
}

// The vector file at version 1 holds exactly this many vectors.
const (
	admVectorsValid   = 15
	admVectorsInvalid = 12
)

var admVectorReason = map[string]string{
	"empty-set": AdmitReasonPathSetEmpty, "too-many-paths": AdmitReasonPathSetTooMany, "empty-path": AdmitReasonPathSetEmptyPath,
	"newline": AdmitReasonPathSetNewline, "nul": AdmitReasonPathSetNUL, "invalid-utf8": AdmitReasonPathSetUTF8,
	"path-too-long": AdmitReasonPathSetTooLong, "duplicate": AdmitReasonPathSetDuplicate,
}

// Cross-test against the shared package's vectors: every valid vector digests
// to the vector's value as the decision's pathSetSha256, and every invalid one
// is refused with the typed reason of its class and is never digested.
func TestAdmissionPathSetSharedVectors(t *testing.T) {
	t.Parallel()
	raw, err := os.ReadFile("../../pathset/testdata/vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Vectors []struct {
			Name   string   `json:"name"`
			Paths  []string `json:"paths"`
			Digest string   `json:"digest"`
			Error  string   `json:"error"`
		} `json:"vectors"`
	}
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	valid, invalid := 0, 0
	seenClass := map[string]bool{}
	for _, v := range f.Vectors {
		in := admOK()
		in.ChangedPaths = v.Paths
		d := AdmitOnboardingAuto(in)
		if v.Error == "" {
			valid++
			if d.PathSetSHA != v.Digest {
				t.Errorf("%s: decision digest %s want %s", v.Name, d.PathSetSHA, v.Digest)
			}
			if d2, err := pathset.Digest(v.Paths); err != nil || d2 != v.Digest {
				t.Errorf("%s: shared digest %s %v", v.Name, d2, err)
			}
			continue
		}
		invalid++
		seenClass[v.Error] = true
		want, ok := admVectorReason[v.Error]
		if !ok {
			t.Fatalf("%s: unknown error class %s", v.Name, v.Error)
		}
		if d.Admitted || d.PathSetSHA != "" || !strings.Contains(strings.Join(d.Reasons, ","), want) {
			t.Errorf("%s: admitted %v digest %q reasons %v, want %s", v.Name, d.Admitted, d.PathSetSHA, d.Reasons, want)
		}
	}
	// Not brittle: every class must be present in the file, and the counts are
	// those of the file itself.
	if valid != admVectorsValid || invalid != admVectorsInvalid || valid+invalid != len(f.Vectors) {
		t.Fatalf("vectors: %d valid (want %d), %d invalid (want %d) of %d; a change of the vector file needs a deliberate edit of the constants", valid, admVectorsValid, invalid, admVectorsInvalid, len(f.Vectors))
	}
	// JSON cannot carry invalid UTF-8, so that class has no vector; it is
	// covered byte-wise in TestAdmissionPathSetRefusals.
	for class := range admVectorReason {
		if class != "invalid-utf8" && !seenClass[class] {
			t.Errorf("no vector of class %s", class)
		}
	}
}

// Decision-level refusal of each class, independent of the vector file, and
// agreement of the allowlist's own path cleaning with the shared validation
// for newline and NUL.
func TestAdmissionPathSetRefusals(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name  string
		want  string
		paths func() []string
	}{
		{"empty set", AdmitReasonPathSetEmpty, func() []string { return nil }},
		{"duplicate", AdmitReasonPathSetDuplicate, func() []string { return append(admPaths(), admPaths()[0]) }},
		{"newline", AdmitReasonPathSetNewline, func() []string { return append(admPaths(), "cli/data/a\nb.json") }},
		{"newline hides a second path", AdmitReasonPathSetNewline, func() []string { return append(admPaths(), "cli/data/a.json\ncli/data/b.json") }},
		{"nul", AdmitReasonPathSetNUL, func() []string { return append(admPaths(), "cli/data/a\x00b.json") }},
		{"invalid utf8", AdmitReasonPathSetUTF8, func() []string { return append(admPaths(), "cli/data/\xff.json") }},
		{"empty path", AdmitReasonPathSetEmptyPath, func() []string { return append(admPaths(), "") }},
		{"too long", AdmitReasonPathSetTooLong, func() []string { return append(admPaths(), "cli/"+strings.Repeat("a", pathset.MaxPathBytes)) }},
		{"too many", AdmitReasonPathSetTooMany, func() []string {
			p := admPaths()
			for i := 0; len(p) <= pathset.MaxPaths; i++ {
				p = append(p, "cli/many/"+strconv.Itoa(i))
			}
			return p
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in := admOK()
			in.ChangedPaths = tc.paths()
			d := AdmitOnboardingAuto(in)
			if d.Admitted || d.PathSetSHA != "" || !strings.Contains(strings.Join(d.Reasons, ","), tc.want) {
				t.Fatalf("admitted %v digest %q reasons %v, want %s", d.Admitted, d.PathSetSHA, d.Reasons, tc.want)
			}
		})
	}
	// The verify-pr digest cannot launder an invalid set: the decision
	// still refuses and carries no digest.
	in := admOK()
	in.ChangedPaths = append(admPaths(), "cli/data/a\nb.json")
	d := AdmitOnboardingAuto(in)
	if d.PathSetSHA != "" || d.Admitted {
		t.Fatalf("%+v", d)
	}
	// admitCleanPath and the shared validation agree on newline and NUL.
	for _, p := range []string{"a\nb", "a\x00b", "a\rb"} {
		if admitCleanPath(p) {
			t.Errorf("admitCleanPath accepts %q", p)
		}
	}
	for _, p := range []string{"a\nb", "a\x00b"} {
		if pathset.Valid([]string{p}) == nil {
			t.Errorf("pathset.Valid accepts %q", p)
		}
	}
}

// The tests that pin the wire. The golden decision test must read the golden
// file and none of them may skip.
var admRequiredTests = []string{"TestOnboardingAdmissionGoldenDecision", "TestAdmitSetDigestGolden", "TestPathSetDigestCanonical", "TestPathSetDigestRenameAndDelete", "TestAdmissionPathSetSharedVectors"}

const admGoldenFile = "testdata/onboarding_admission_golden.json"

// checkGoldenGuard inspects the source of the test file (AST, not text) and
// returns what is wrong: a required test missing, a skip call inside one, or a
// golden test that never calls os.ReadFile on the golden file.
func checkGoldenGuard(src []byte) []string {
	f, err := parser.ParseFile(token.NewFileSet(), "onboarding_admission_test.go", src, 0)
	if err != nil {
		return []string{"parse: " + err.Error()}
	}
	funcs := map[string]*ast.FuncDecl{}
	for _, d := range f.Decls {
		if fn, ok := d.(*ast.FuncDecl); ok && fn.Recv == nil {
			funcs[fn.Name.Name] = fn
		}
	}
	var problems []string
	for _, name := range admRequiredTests {
		fn := funcs[name]
		if fn == nil || fn.Body == nil {
			problems = append(problems, "missing "+name)
			continue
		}
		reads := false
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			switch sel.Sel.Name {
			case "Skip", "SkipNow", "Skipf":
				problems = append(problems, "skip in "+name)
			case "ReadFile":
				if pkg, ok := sel.X.(*ast.Ident); ok && pkg.Name == "os" && len(call.Args) > 0 {
					if lit, ok := call.Args[0].(*ast.BasicLit); ok && lit.Kind == token.STRING && (lit.Value == strconv.Quote(admGoldenFile) || lit.Value == "`"+admGoldenFile+"`") {
						reads = true
					}
				}
			}
			return true
		})
		if name == "TestOnboardingAdmissionGoldenDecision" && !reads {
			problems = append(problems, "no os.ReadFile of the golden file in "+name)
		}
	}
	return problems
}

func TestAdmissionGoldenTestsArePresent(t *testing.T) {
	t.Parallel()
	if _, err := os.Stat(admGoldenFile); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile("onboarding_admission_test.go")
	if err != nil {
		t.Fatal(err)
	}
	if problems := checkGoldenGuard(raw); len(problems) > 0 {
		t.Fatalf("golden guard: %v", problems)
	}
}

// The guard rejects each way of unpinning the wire, on fabricated sources.
func TestGoldenGuardRejectsBadSources(t *testing.T) {
	t.Parallel()
	body := func(golden, extra string) string {
		src := "package x\nimport (\"os\"\n\"testing\")\nvar _ = os.ReadFile\n"
		for _, n := range admRequiredTests {
			stmt := extra
			if n == "TestOnboardingAdmissionGoldenDecision" {
				stmt += golden
			}
			src += "func " + n + "(t *testing.T) {\n" + stmt + "\n}\n"
		}
		return src
	}
	read := `os.ReadFile("` + admGoldenFile + `")`
	good := body("_, _ = "+read, "")
	if p := checkGoldenGuard([]byte(good)); len(p) != 0 {
		t.Fatalf("good source rejected: %v", p)
	}
	cases := map[string]string{
		"renamed test":         strings.Replace(good, "TestAdmitSetDigestGolden", "TestAdmitSetDigestGoldenX", 1),
		"skip":                 body("_, _ = "+read, "t.Skip(\"x\")"),
		"skipnow":              body("_, _ = "+read, "t.SkipNow()"),
		"skipf":                body("_, _ = "+read, "t.Skipf(\"x\")"),
		"no ReadFile":          body("", ""),
		"ReadFile in comment":  body("// "+read, ""),
		"ReadFile in string":   body("_ = `"+read+"`", ""),
		"another file":         body(`_, _ = os.ReadFile("testdata/other.json")`, ""),
		"non-literal argument": body(`name := "x"; _, _ = os.ReadFile(name)`, ""),
		"not valid Go":         "package x\nfunc (",
	}
	for name, src := range cases {
		if p := checkGoldenGuard([]byte(src)); len(p) == 0 {
			t.Errorf("%s: accepted", name)
		}
	}
}

// An empty or duplicate changed-path set fires BOTH the older allowlist reason
// and the shared-validation reason; that is intended and pinned here (the
// older code is additive-compatible, the new code names the class).
func TestAdmissionPathSetReasonsFireTogether(t *testing.T) {
	t.Parallel()
	for name, tc := range map[string]struct {
		paths []string
		want  string
	}{
		"empty":     {nil, AdmitReasonPathSetEmpty},
		"duplicate": {append(admPaths(), admPaths()[0]), AdmitReasonPathSetDuplicate},
	} {
		in := admOK()
		in.ChangedPaths = tc.paths
		have := strings.Join(AdmitOnboardingAuto(in).Reasons, ",")
		if !strings.Contains(have, AdmitReasonPathSet) || !strings.Contains(have, tc.want) {
			t.Errorf("%s: reasons %s", name, have)
		}
	}
}
