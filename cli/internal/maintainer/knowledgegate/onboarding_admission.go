// SPDX-License-Identifier: AGPL-3.0-only

package knowledgegate

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"regexp"
	"sort"
	"strings"
	"time"
)

// OnboardingAdmissionSchema is the schema of the onboarding admission
// decision.
const OnboardingAdmissionSchema = "onboarding-admission/v1"

// Admission reason codes. A decision is admitted exactly when it has none.
const (
	AdmitReasonDisabled               = "disabled"
	AdmitReasonGateFailed             = "gate-not-passed"
	AdmitReasonShadow                 = "shadow"
	AdmitReasonNoBatch                = "no-onboarding-batch"
	AdmitReasonBatchNotOK             = "onboarding-checks-failed"
	AdmitReasonPaused                 = "paused"
	AdmitReasonPauseUnknown           = "pause-unknown"
	AdmitReasonSignature              = "batch-signature-not-verified-against-base-keyset"
	AdmitReasonKeyNotInBase           = "signing-key-not-in-base-keyset"
	AdmitReasonTier                   = "signer-tier-unknown"
	AdmitReasonBotPolicy              = "bot-tier-not-admitted-no-verified-policy"
	AdmitReasonBatchExpired           = "batch-expired-or-time-unknown"
	AdmitReasonKeyset                 = "keyset-digest-missing"
	AdmitReasonTrustRoot              = "trust-root-digest-missing"
	AdmitReasonDigests                = "digest-mismatch"
	AdmitReasonChangeSet              = "change-set-mismatch"
	AdmitReasonRegen                  = "regeneration-not-byte-equal"
	AdmitReasonProjects               = "project-set-invalid"
	AdmitReasonOwnerOnly              = "owner-merge-only"
	AdmitReasonExclusion              = "exclusion-added"
	AdmitReasonExclusionUnknown       = "exclusion-delta-unknown"
	AdmitReasonExclusionRemoved       = "exclusion-removed"
	AdmitReasonExclusionInvalid       = "exclusion-set-invalid"
	AdmitReasonExclusionRecipe        = "exclusion-recipe-target-mismatch"
	AdmitReasonRecipeExclusionUnknown = "exclusion-recipe-unknown"
	AdmitReasonPathOutside            = "path-outside-allowlist"
	AdmitReasonTrustPath              = "trust-path-touched"
	AdmitReasonForbiddenPath          = "forbidden-path-touched"
	AdmitReasonPathSet                = "path-set-invalid"
	AdmitReasonBatchPath              = "batch-path-missing"
	AdmitReasonFileModes              = "file-modes"
	AdmitReasonVerifyAbsent           = "verify-pr-absent"
	AdmitReasonVerifyNotPass          = "verify-pr-not-pass"
	AdmitReasonVerifyHead             = "verify-pr-head-mismatch"
	AdmitReasonVerifyBinding          = "verify-pr-binding-invalid"
	AdmitReasonVerifySlugs            = "verify-pr-slug-mismatch"
	AdmitReasonAuthor                 = "author-not-bot"
	AdmitReasonSender                 = "sender-not-bot"
	AdmitReasonBotLogin               = "bot-login-invalid"
	AdmitReasonOwnerPrincipal         = "owner-principal-is-never-machine-class"
	AdmitReasonCommits                = "commit-provenance"
	AdmitReasonSHA                    = "sha-invalid"
	AdmitReasonHeadMismatch           = "head-sha-mismatch"
	AdmitReasonAllowlistUnset         = "path-allowlist-unset"
	AdmitReasonVerifyPaths            = "verify-pr-changed-paths-digest-missing"
	AdmitReasonBaseAbsent             = "slug-present-in-base"
	AdmitReasonBaseAbsentUnknown      = "base-absence-unknown"
	AdmitReasonVerifyBase             = "verify-pr-base-mismatch"
	AdmitReasonVerifyRecipe           = "verify-pr-recipe-not-new"
)

// OnboardingAdmissionConfig is the layout part of the admission decision.
// Enabled is false by default: the decision is then always "disabled" and
// nothing about merging changes.
type OnboardingAdmissionConfig struct {
	Enabled bool
	// StaticPaths are exact files every admitted change may touch (the
	// table, the catalog files, regenerated outputs). No entry may be a
	// directory prefix.
	StaticPaths []string
	// ProjectPaths are per-project allowances with "{slug}" in them. An
	// entry ending in "/" allows files below that directory of the slug,
	// any other entry is one exact file.
	ProjectPaths []string
	// TargetPath is the exact target file of a project, with "{slug}"; it
	// must be among the changed paths of every project and is allowed.
	TargetPath string
}

// AdmissionCommit is one commit of the change.
type AdmissionCommit struct {
	SHA       string `json:"sha"`
	Author    string `json:"author"`
	Committer string `json:"committer"`
	Verified  bool   `json:"verified"`
}

// AdmissionDigests are the registry, table and targets digests (and the pack
// revision) of one side.
type AdmissionDigests struct {
	Registry string `json:"registry"`
	Table    string `json:"table"`
	Targets  string `json:"targets"`
	Pack     string `json:"pack"`
}

// AdmissionProject is one project of the batch.
type AdmissionProject struct {
	Slug           string `json:"slug"`
	Kind           string `json:"kind"`
	TargetSHA256   string `json:"targetSha256"`
	RecipeSHA256   string `json:"recipeSha256,omitempty"`
	TagsCommitsSHA string `json:"tagsCommitsSha256,omitempty"`
}

// AdmissionBatch is the batch as it is bound into the decision.
type AdmissionBatch struct {
	ID              string `json:"id"`
	Path            string `json:"path"`
	KeyID           string `json:"keyId"`
	Tier            string `json:"tier"`
	Identity        string `json:"identity"`
	Nonce           string `json:"nonce"`
	NotAfter        string `json:"notAfter"`
	ChangeSetDigest string `json:"changeSetDigest"`
	SummaryDigest   string `json:"summaryDigest"`
}

// The checker trusts the caller-supplied VerifyPr only for the facts it
// binds here (outcome, binding result, recipe change, base/head ids, binding
// digest, changed-paths digest); the base-absence and path conjuncts are its
// own.
//
// VerifyPrResult is what the upstream verify-pr check recorded (the
// result-json of verify-pr, schema prufyx.io/verify-pr-result/v1). Its
// interface belongs to another lane: this is the optional struct the
// admission reads, never a second network fetch. Eligible is carried and
// bound but is not required: verify-pr labels only an unchanged recipe
// eligible, and an onboarding change adds a new one, which that tool leaves
// to a separate decision. Admission needs a passing result with the upstream
// binding verified and a new recipe, for the same base and head.
type VerifyPrResult struct {
	Outcome         string
	Eligible        bool
	BindingVerified bool
	RecipeChange    string
	BaseSHA         string
	HeadSHA         string
	BindingDigest   string
	// ChangedPathsSHA256 is the digest of the exact path set the verify-pr
	// pass covered (verify-pr judges one slug, so a real onboarding diff
	// needs a filtered path input; the result itself binds no path set).
	ChangedPathsSHA256 string
	Slugs              []string
	TagsCommitsSHA     map[string]string
}

// VerifyPrBinding is the part of the verify-pr result bound into the
// decision.
type VerifyPrBinding struct {
	ChangedPathsSHA256 string `json:"changedPathsSha256"`
	Outcome            string `json:"outcome"`
	Eligible           bool   `json:"eligible"`
	BindingVerified    bool   `json:"bindingVerified"`
	RecipeChange       string `json:"recipeChange"`
	BaseSHA            string `json:"baseSha"`
	BindingDigest      string `json:"bindingDigest"`
	HeadSHA            string `json:"headSha"`
}

// ExclusionBinding binds the exclusion identity sets of both sides.
type ExclusionBinding struct {
	BaseSHA256 string `json:"baseSha256"`
	HeadSHA256 string `json:"headSha256"`
}

// RegenBinding is the regeneration evidence bound into the decision.
type RegenBinding struct {
	ByteEqual     bool   `json:"byteEqual"`
	OutputsSHA256 string `json:"outputsSha256"`
}

// OnboardingAdmissionInput is everything AdmitOnboardingAuto reads. Every
// member is data: the function does no IO, and a member left at its zero
// value never admits.
type OnboardingAdmissionInput struct {
	Config OnboardingAdmissionConfig
	// Now is the decision time; zero is unknown.
	Now time.Time

	// Gate result.
	GatePassed        bool
	Shadow            bool
	OnboardingPresent bool
	OnboardingOK      bool
	Paused            bool
	PauseKnown        bool
	// BatchCount is the number of batches the change adds.
	BatchCount int

	// Identity of the change. GitHeadSHA is the head the authenticated
	// fetch resolved, HeadSHA the head the gate checked.
	HeadSHA, BaseSHA, GitHeadSHA string
	Author, Sender, BotLogin     string
	Owner                        string
	CommitStatus                 string
	CommitAheadBy                int
	CommitBehindBy               int
	CommitTotal                  int
	Commits                      []AdmissionCommit

	// Batch and its signature, checked by the gate against the BASE keyset.
	Batch              AdmissionBatch
	SignatureVerified  bool
	KeyInBaseKeyset    bool
	KeysetDigest       string
	TrustRootDigest    string
	ComputedChangeSet  string
	BatchBaseDigests   AdmissionDigests
	BatchHeadDigests   AdmissionDigests
	GateBaseDigests    AdmissionDigests
	GateHeadDigests    AdmissionDigests
	Projects           []AdmissionProject
	RegenKnown         bool
	RegenByteEqual     bool
	RegenOutputsSHA256 string
	// Exclusion identity sets, BASE and HEAD, over every target: one opaque
	// string per exclusion. Known is false when either could not be read.
	// BaseAbsenceKnown is true when the base table, the base targets and the
	// base recipes were all read; BasePresent lists the batch slugs found in
	// any of them (an onboarding adds a project that the base lacks
	// everywhere; verify-pr's "new" only means no recipe dir in the base).
	BaseAbsenceKnown bool
	BasePresent      []string
	ExclusionsKnown  bool
	BaseExclusions   []string
	HeadExclusions   []string
	// The recipe's exclusions and the head target's exclusion paths, as
	// slug-qualified items; they must be the same set.
	RecipeExclusionsKnown bool
	RecipeExclusions      []string
	TargetExclusionPaths  []string
	FileModesOK           bool
	ChangedPaths          []string
	TrustPaths            []string
	BatchDir              string
	VerifyPr              *VerifyPrResult
}

// OnboardingAdmission is the decision. It is never a merge authorization of
// its own: the old AutoMerge member stays false for every onboarding change.
type OnboardingAdmission struct {
	Schema   string   `json:"schema"`
	Admitted bool     `json:"admitted"`
	Reasons  []string `json:"reasons"`

	HeadSHA         string             `json:"headSha"`
	BaseSHA         string             `json:"baseSha"`
	AuthorLogin     string             `json:"authorLogin"`
	SenderLogin     string             `json:"senderLogin"`
	BotLogin        string             `json:"botLogin"`
	Commits         []AdmissionCommit  `json:"commits"`
	Batch           AdmissionBatch     `json:"batch"`
	Digests         AdmissionDigests   `json:"digests"`
	Projects        []AdmissionProject `json:"projects"`
	PathSet         []string           `json:"pathSet"`
	Exclusions      ExclusionBinding   `json:"exclusions"`
	PathSetSHA      string             `json:"pathSetSha256"`
	VerifyPr        VerifyPrBinding    `json:"verifyPr"`
	Regen           RegenBinding       `json:"regen"`
	KeysetDigest    string             `json:"keysetDigest"`
	TrustRootDigest string             `json:"trustRootDigest"`
	Paused          bool               `json:"paused"`
	Shadow          bool               `json:"shadow"`
	ObservedAt      string             `json:"observedAt"`
	// DecisionDigest is the sha256 of the compact JSON of this decision with
	// the member itself empty: it binds every member above.
	DecisionDigest string `json:"decisionDigest"`
}

var (
	admitDigestRE = regexp.MustCompile(`^(sha256:)?[0-9a-f]{64}$`)
	admitSlugRE   = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)
)

func admitValidDigest(s string) bool { return admitDigestRE.MatchString(s) }

func (d AdmissionDigests) valid() bool {
	return admitValidDigest(d.Registry) && admitValidDigest(d.Table) && admitValidDigest(d.Targets) && d.Pack != ""
}

// AdmitOnboardingAuto decides whether an onboarding change may be admitted.
// It is pure: it reads only its input. Any missing, unknown or mismatching
// member is a typed reason, and the decision is admitted only with none.
func AdmitOnboardingAuto(in OnboardingAdmissionInput) OnboardingAdmission {
	d := OnboardingAdmission{
		Schema: OnboardingAdmissionSchema, HeadSHA: in.HeadSHA, BaseSHA: in.BaseSHA,
		AuthorLogin: in.Author, SenderLogin: in.Sender, BotLogin: in.BotLogin,
		Batch: in.Batch, Digests: in.GateHeadDigests,
		KeysetDigest: in.KeysetDigest, TrustRootDigest: in.TrustRootDigest,
		Paused: in.Paused, Shadow: in.Shadow,
		Regen: RegenBinding{ByteEqual: in.RegenKnown && in.RegenByteEqual, OutputsSHA256: in.RegenOutputsSHA256},
	}
	if !in.Now.IsZero() {
		d.ObservedAt = in.Now.UTC().Format(time.RFC3339)
	}
	d.Exclusions = ExclusionBinding{BaseSHA256: admitSetDigest(in.BaseExclusions), HeadSHA256: admitSetDigest(in.HeadExclusions)}
	d.Commits = append([]AdmissionCommit{}, in.Commits...)
	d.Projects = append([]AdmissionProject{}, in.Projects...)
	sort.Slice(d.Projects, func(i, j int) bool { return d.Projects[i].Slug < d.Projects[j].Slug })
	d.PathSet = append([]string{}, in.ChangedPaths...)
	sort.Strings(d.PathSet)
	d.PathSetSHA = admitSHA([]byte(strings.Join(d.PathSet, "\n")))
	if in.VerifyPr != nil {
		d.VerifyPr = VerifyPrBinding{ChangedPathsSHA256: in.VerifyPr.ChangedPathsSHA256, Outcome: in.VerifyPr.Outcome, Eligible: in.VerifyPr.Eligible, BindingVerified: in.VerifyPr.BindingVerified, RecipeChange: in.VerifyPr.RecipeChange, BaseSHA: in.VerifyPr.BaseSHA, BindingDigest: in.VerifyPr.BindingDigest, HeadSHA: in.VerifyPr.HeadSHA}
	}

	var why admitReasons
	if !in.Config.Enabled {
		why.add(AdmitReasonDisabled)
		return d.finish(why)
	}
	admitGate(in, &why)
	admitSignature(in, &why)
	admitRegeneration(in, &why)
	admitExclusions(in, &why)
	admitBaseAbsence(in, &why)
	admitPaths(in, d.PathSet, &why)
	admitVerifyPr(in, &why)
	admitPrincipals(in, &why)
	return d.finish(why)
}

type admitReasons map[string]bool

func (r *admitReasons) add(code string) {
	if *r == nil {
		*r = admitReasons{}
	}
	(*r)[code] = true
}

func (d OnboardingAdmission) finish(why admitReasons) OnboardingAdmission {
	d.Reasons = make([]string, 0, len(why))
	for code := range why {
		d.Reasons = append(d.Reasons, code)
	}
	sort.Strings(d.Reasons)
	d.Admitted = len(d.Reasons) == 0
	d.DecisionDigest = ""
	raw, err := json.Marshal(d)
	if err != nil {
		// Unreachable for these types; never admit on a failure to bind.
		d.Admitted = false
		d.Reasons = append(d.Reasons, "decision-not-encodable")
		return d
	}
	d.DecisionDigest = admitSHA(raw)
	return d
}

func admitSHA(b []byte) string {
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// A1: the gate passed, one onboarding batch, all of O1 to O8, not shadow,
// pause known and clear.
func admitGate(in OnboardingAdmissionInput, why *admitReasons) {
	if !in.GatePassed {
		why.add(AdmitReasonGateFailed)
	}
	if in.Shadow {
		why.add(AdmitReasonShadow)
	}
	if !in.OnboardingPresent || in.BatchCount != 1 {
		why.add(AdmitReasonNoBatch)
	}
	if !in.OnboardingOK {
		why.add(AdmitReasonBatchNotOK)
	}
	if !in.PauseKnown {
		why.add(AdmitReasonPauseUnknown)
	}
	if in.Paused {
		why.add(AdmitReasonPaused)
	}
}

// A2 and A3: the signature, its tier, and the batch's binding to the gate's
// own computation.
func admitSignature(in OnboardingAdmissionInput, why *admitReasons) {
	b := in.Batch
	if !in.SignatureVerified {
		why.add(AdmitReasonSignature)
	}
	if !in.KeyInBaseKeyset || b.KeyID == "" {
		why.add(AdmitReasonKeyNotInBase)
	}
	if !admitValidDigest(in.KeysetDigest) {
		why.add(AdmitReasonKeyset)
	}
	if !admitValidDigest(in.TrustRootDigest) {
		why.add(AdmitReasonTrustRoot)
	}
	switch b.Tier {
	case ApprovalTierOwner:
	case ApprovalTierOnboardingBot:
		// Fail closed: the bot tier needs an owner-signed policy that a
		// loader reads from the BASE tree, pinned by digest, like the
		// keyset. No such loader exists yet and nothing the caller can
		// supply stands in for it, so no bot-tier batch is admitted.
		why.add(AdmitReasonBotPolicy)
	default:
		why.add(AdmitReasonTier)
	}
	notAfter, err := time.Parse(time.RFC3339, b.NotAfter)
	if err != nil || in.Now.IsZero() || !in.Now.Before(notAfter) {
		why.add(AdmitReasonBatchExpired)
	}
	if b.ID == "" || b.Nonce == "" || b.Identity == "" || !admitValidDigest(b.SummaryDigest) {
		why.add(AdmitReasonProjects)
	}
	if !admitValidDigest(b.ChangeSetDigest) || b.ChangeSetDigest != in.ComputedChangeSet {
		why.add(AdmitReasonChangeSet)
	}
	if !in.BatchHeadDigests.valid() || !in.GateHeadDigests.valid() || in.BatchHeadDigests != in.GateHeadDigests ||
		!in.BatchBaseDigests.valid() || !in.GateBaseDigests.valid() || in.BatchBaseDigests != in.GateBaseDigests {
		why.add(AdmitReasonDigests)
	}
	if len(in.Projects) == 0 {
		why.add(AdmitReasonProjects)
	}
	seen := map[string]bool{}
	for _, p := range in.Projects {
		if !admitSlugRE.MatchString(p.Slug) || seen[p.Slug] || !admitValidDigest(p.TargetSHA256) {
			why.add(AdmitReasonProjects)
		}
		seen[p.Slug] = true
		if p.Kind != OnboardingKindNew {
			// attest and anything else is the owner's.
			why.add(AdmitReasonOwnerOnly)
		}
	}
}

// A3: the outputs are byte-equal their regeneration.
func admitRegeneration(in OnboardingAdmissionInput, why *admitReasons) {
	if !in.RegenKnown || !in.RegenByteEqual || !admitValidDigest(in.RegenOutputsSHA256) {
		why.add(AdmitReasonRegen)
	}
}

// admitSet returns the set of a list, and whether the list is a valid
// identity list: no empty item and no repeated item.
func admitSet(list []string) (map[string]bool, bool) {
	set := make(map[string]bool, len(list))
	ok := true
	for _, x := range list {
		if x == "" || set[x] {
			ok = false
		}
		set[x] = true
	}
	return set, ok
}

func admitSetDigest(list []string) string {
	set, _ := admitSet(list)
	items := make([]string, 0, len(set))
	for x := range set {
		items = append(items, x)
	}
	sort.Strings(items)
	raw, _ := json.Marshal(items)
	return admitSHA(raw)
}

// A4: the exclusion identity set of the head is the base's: an item the head
// has and the base lacks (added, or a replacement at the same count) and an
// item the base has and the head lacks are both refused; the order of the
// lists never matters; identities are compared exactly (no case folding); a
// repeated or empty item is invalid; an unknown set is a refusal. The
// recipe's exclusions are the head target's.
func admitExclusions(in OnboardingAdmissionInput, why *admitReasons) {
	if !in.ExclusionsKnown {
		why.add(AdmitReasonExclusionUnknown)
	} else {
		base, baseOK := admitSet(in.BaseExclusions)
		head, headOK := admitSet(in.HeadExclusions)
		if !baseOK || !headOK {
			why.add(AdmitReasonExclusionInvalid)
		}
		for x := range head {
			if !base[x] {
				why.add(AdmitReasonExclusion)
			}
		}
		for x := range base {
			if !head[x] {
				why.add(AdmitReasonExclusionRemoved)
			}
		}
	}
	if !in.RecipeExclusionsKnown {
		why.add(AdmitReasonRecipeExclusionUnknown)
		return
	}
	recipe, recipeOK := admitSet(in.RecipeExclusions)
	target, targetOK := admitSet(in.TargetExclusionPaths)
	if !recipeOK || !targetOK {
		why.add(AdmitReasonExclusionInvalid)
	}
	same := len(recipe) == len(target)
	for x := range recipe {
		same = same && target[x]
	}
	if !same {
		why.add(AdmitReasonExclusionRecipe)
	}
}

// admitCleanPath reports whether p is a plain repository-relative path.
func admitCleanPath(p string) bool {
	if p == "" || strings.HasPrefix(p, "/") || strings.HasSuffix(p, "/") || strings.Contains(p, "\\") || strings.ContainsAny(p, "\x00\n\r") {
		return false
	}
	for _, seg := range strings.Split(p, "/") {
		if seg == "" || seg == "." || seg == ".." {
			return false
		}
	}
	return true
}

func admitForbiddenPath(p string) bool {
	lower := strings.ToLower(p)
	base := lower[strings.LastIndex(lower, "/")+1:]
	return strings.HasPrefix(lower, ".github/") || base == "codeowners"
}

// A5: the exact path allowlist, no trust path, the one batch file.
func admitPaths(in OnboardingAdmissionInput, sorted []string, why *admitReasons) {
	if !in.FileModesOK {
		why.add(AdmitReasonFileModes)
	}
	if len(sorted) == 0 {
		why.add(AdmitReasonPathSet)
	}
	if len(in.Config.StaticPaths) == 0 && len(in.Config.ProjectPaths) == 0 {
		why.add(AdmitReasonAllowlistUnset)
	}
	allowExact := map[string]bool{}
	for _, p := range in.Config.StaticPaths {
		if admitCleanPath(p) {
			allowExact[p] = true
		}
	}
	var prefixes []string
	for _, p := range in.Projects {
		if !admitSlugRE.MatchString(p.Slug) {
			continue
		}
		for _, tpl := range in.Config.ProjectPaths {
			path := strings.ReplaceAll(tpl, "{slug}", p.Slug)
			if strings.HasSuffix(path, "/") {
				if admitCleanPath(strings.TrimSuffix(path, "/")) {
					prefixes = append(prefixes, path)
				}
			} else if admitCleanPath(path) {
				allowExact[path] = true
			}
		}
	}
	if in.Config.TargetPath != "" {
		for _, p := range in.Projects {
			if admitSlugRE.MatchString(p.Slug) {
				if path := strings.ReplaceAll(in.Config.TargetPath, "{slug}", p.Slug); admitCleanPath(path) {
					allowExact[path] = true
				}
			}
		}
	}
	batchPath := ""
	if in.BatchDir != "" && admitCleanPath(in.BatchDir) && in.Batch.ID != "" && !strings.Contains(in.Batch.ID, "/") {
		batchPath = in.BatchDir + "/" + in.Batch.ID + ".json"
		allowExact[batchPath] = true
	}
	trust := Layout{TrustPaths: in.TrustPaths}
	have := map[string]int{}
	for i, p := range sorted {
		if i > 0 && sorted[i-1] == p {
			why.add(AdmitReasonPathSet)
		}
		have[p]++
		switch {
		case !admitCleanPath(p):
			why.add(AdmitReasonPathSet)
		case trust.trustPath(p):
			why.add(AdmitReasonTrustPath)
		case admitForbiddenPath(p):
			why.add(AdmitReasonForbiddenPath)
		case allowExact[p]:
		default:
			inPrefix := false
			for _, pre := range prefixes {
				if strings.HasPrefix(p, pre) {
					inPrefix = true
				}
			}
			if !inPrefix {
				why.add(AdmitReasonPathOutside)
			}
		}
	}
	if batchPath == "" || have[batchPath] != 1 {
		why.add(AdmitReasonBatchPath)
	}
	if in.Batch.Path != batchPath {
		why.add(AdmitReasonBatchPath)
	}
	// Every project's own target file is in the change: a batch that names
	// a project it does not change is not the change it signs.
	for _, p := range in.Projects {
		if in.Config.TargetPath == "" || have[strings.ReplaceAll(in.Config.TargetPath, "{slug}", p.Slug)] != 1 {
			why.add(AdmitReasonProjects)
		}
	}
}

// A6: the recorded verify-pr result, bound to the same head and the same
// project set.
func admitVerifyPr(in OnboardingAdmissionInput, why *admitReasons) {
	v := in.VerifyPr
	if v == nil {
		why.add(AdmitReasonVerifyAbsent)
		return
	}
	if v.Outcome != "pass" || !v.BindingVerified {
		why.add(AdmitReasonVerifyNotPass)
	}
	if v.RecipeChange != "new" {
		why.add(AdmitReasonVerifyRecipe)
	}
	if !shaRE.MatchString(v.BaseSHA) || v.BaseSHA != in.BaseSHA {
		why.add(AdmitReasonVerifyBase)
	}
	if !shaRE.MatchString(v.HeadSHA) || v.HeadSHA != in.HeadSHA {
		why.add(AdmitReasonVerifyHead)
	}
	if !admitValidDigest(v.ChangedPathsSHA256) {
		why.add(AdmitReasonVerifyPaths)
	}
	if !admitValidDigest(v.BindingDigest) {
		why.add(AdmitReasonVerifyBinding)
	}
	want := make([]string, 0, len(in.Projects))
	for _, p := range in.Projects {
		want = append(want, p.Slug)
	}
	got := append([]string{}, v.Slugs...)
	sort.Strings(want)
	sort.Strings(got)
	if len(got) != len(want) {
		why.add(AdmitReasonVerifySlugs)
		return
	}
	for i := range got {
		if got[i] != want[i] {
			why.add(AdmitReasonVerifySlugs)
			return
		}
	}
}

// A7: principals and commit provenance. The machine class is the pinned bot
// only; the owner's own change is never machine class.
func admitPrincipals(in OnboardingAdmissionInput, why *admitReasons) {
	if in.BotLogin == "" {
		why.add(AdmitReasonBotLogin)
	}
	if in.Author == "" || in.Author != in.BotLogin {
		why.add(AdmitReasonAuthor)
	}
	if in.Sender == "" || in.Sender != in.BotLogin {
		why.add(AdmitReasonSender)
	}
	if in.Owner == "" || in.Owner == in.BotLogin || in.Owner == in.Author || in.Owner == in.Sender {
		why.add(AdmitReasonOwnerPrincipal)
	}
	if !shaRE.MatchString(in.HeadSHA) || !shaRE.MatchString(in.BaseSHA) || in.HeadSHA == in.BaseSHA {
		why.add(AdmitReasonSHA)
	}
	if in.GitHeadSHA != in.HeadSHA {
		why.add(AdmitReasonHeadMismatch)
	}
	if in.CommitBehindBy != 0 || in.CommitAheadBy < 1 || in.CommitStatus != "ahead" ||
		in.CommitTotal != len(in.Commits) || len(in.Commits) == 0 {
		why.add(AdmitReasonCommits)
	}
	for _, c := range in.Commits {
		if !shaRE.MatchString(c.SHA) || c.Author == "" || c.Author != in.BotLogin || c.Committer != in.BotLogin || !c.Verified {
			why.add(AdmitReasonCommits)
		}
	}
	if n := len(in.Commits); n > 0 && in.Commits[n-1].SHA != in.HeadSHA {
		why.add(AdmitReasonCommits)
	}
}

// admitBaseAbsence: every project of the batch is absent from the base table,
// the base targets and the base recipes; unknown is a refusal.
func admitBaseAbsence(in OnboardingAdmissionInput, why *admitReasons) {
	if !in.BaseAbsenceKnown {
		why.add(AdmitReasonBaseAbsentUnknown)
	}
	present := map[string]bool{}
	for _, x := range in.BasePresent {
		present[x] = true
	}
	if len(present) > 0 {
		for _, p := range in.Projects {
			if present[p.Slug] {
				why.add(AdmitReasonBaseAbsent)
			}
		}
		// A reported presence that matches no project is still not clean.
		why.add(AdmitReasonBaseAbsent)
	}
}
