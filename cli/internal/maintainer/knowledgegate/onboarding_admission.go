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
	AdmitReasonDisabled          = "disabled"
	AdmitReasonGateFailed        = "gate-not-passed"
	AdmitReasonShadow            = "shadow"
	AdmitReasonNoBatch           = "no-onboarding-batch"
	AdmitReasonBatchNotOK        = "onboarding-checks-failed"
	AdmitReasonPaused            = "paused"
	AdmitReasonPauseUnknown      = "pause-unknown"
	AdmitReasonSignature         = "batch-signature-not-verified-against-base-keyset"
	AdmitReasonKeyNotInBase      = "signing-key-not-in-base-keyset"
	AdmitReasonTier              = "signer-tier-unknown"
	AdmitReasonBotPolicy         = "bot-tier-without-owner-signed-policy"
	AdmitReasonBatchExpired      = "batch-expired-or-time-unknown"
	AdmitReasonKeyset            = "keyset-digest-missing"
	AdmitReasonTrustRoot         = "trust-root-digest-missing"
	AdmitReasonDigests           = "digest-mismatch"
	AdmitReasonChangeSet         = "change-set-mismatch"
	AdmitReasonRegen             = "regeneration-not-byte-equal"
	AdmitReasonProjects          = "project-set-invalid"
	AdmitReasonOwnerOnly         = "owner-merge-only"
	AdmitReasonExclusion         = "exclusion-added"
	AdmitReasonExclusionUnknown  = "exclusion-delta-unknown"
	AdmitReasonPathOutside       = "path-outside-allowlist"
	AdmitReasonTrustPath         = "trust-path-touched"
	AdmitReasonForbiddenPath     = "forbidden-path-touched"
	AdmitReasonPathSet           = "path-set-invalid"
	AdmitReasonBatchPath         = "batch-path-missing"
	AdmitReasonFileModes         = "file-modes"
	AdmitReasonVerifyAbsent      = "verify-pr-absent"
	AdmitReasonVerifyNotEligible = "verify-pr-not-eligible"
	AdmitReasonVerifyHead        = "verify-pr-head-mismatch"
	AdmitReasonVerifyBinding     = "verify-pr-binding-invalid"
	AdmitReasonVerifySlugs       = "verify-pr-slug-mismatch"
	AdmitReasonAuthor            = "author-not-bot"
	AdmitReasonSender            = "sender-not-bot"
	AdmitReasonBotLogin          = "bot-login-invalid"
	AdmitReasonOwnerPrincipal    = "owner-principal-is-never-machine-class"
	AdmitReasonCommits           = "commit-provenance"
	AdmitReasonSHA               = "sha-invalid"
	AdmitReasonHeadMismatch      = "head-sha-mismatch"
	AdmitReasonAllowlistUnset    = "path-allowlist-unset"
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

// AdmissionBotPolicy is the owner-signed bot-tier policy, modelled as data.
// The policy itself is not implemented by this package: until a verified
// policy is supplied no bot-tier batch is admitted.
type AdmissionBotPolicy struct {
	Present     bool
	OwnerSigned bool
	Digest      string
	KeyIDs      []string
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

// VerifyPrResult is what the upstream verify-pr check recorded. Its
// interface belongs to another lane: this is the optional result struct the
// admission reads, never a second network fetch.
type VerifyPrResult struct {
	Eligible       bool
	HeadSHA        string
	BindingDigest  string
	Slugs          []string
	TagsCommitsSHA map[string]string
}

// VerifyPrBinding is the part of the verify-pr result bound into the
// decision.
type VerifyPrBinding struct {
	Eligible      bool   `json:"eligible"`
	BindingDigest string `json:"bindingDigest"`
	HeadSHA       string `json:"headSha"`
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
	Policy             AdmissionBotPolicy
	ComputedChangeSet  string
	BatchBaseDigests   AdmissionDigests
	BatchHeadDigests   AdmissionDigests
	GateBaseDigests    AdmissionDigests
	GateHeadDigests    AdmissionDigests
	Projects           []AdmissionProject
	RegenKnown         bool
	RegenByteEqual     bool
	RegenOutputsSHA256 string
	ExclusionsKnown    bool
	ExclusionsAdded    int
	FileModesOK        bool
	ChangedPaths       []string
	TrustPaths         []string
	BatchDir           string
	VerifyPr           *VerifyPrResult
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
	PathSetSHA      string             `json:"pathSetSha256"`
	VerifyPr        VerifyPrBinding    `json:"verifyPr"`
	Regen           RegenBinding       `json:"regen"`
	KeysetDigest    string             `json:"keysetDigest"`
	TrustRootDigest string             `json:"trustRootDigest"`
	PolicyDigest    string             `json:"policyDigest"`
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
		KeysetDigest: in.KeysetDigest, TrustRootDigest: in.TrustRootDigest, PolicyDigest: in.Policy.Digest,
		Paused: in.Paused, Shadow: in.Shadow,
		Regen: RegenBinding{ByteEqual: in.RegenKnown && in.RegenByteEqual, OutputsSHA256: in.RegenOutputsSHA256},
	}
	if !in.Now.IsZero() {
		d.ObservedAt = in.Now.UTC().Format(time.RFC3339)
	}
	d.Commits = append([]AdmissionCommit{}, in.Commits...)
	d.Projects = append([]AdmissionProject{}, in.Projects...)
	sort.Slice(d.Projects, func(i, j int) bool { return d.Projects[i].Slug < d.Projects[j].Slug })
	d.PathSet = append([]string{}, in.ChangedPaths...)
	sort.Strings(d.PathSet)
	d.PathSetSHA = admitSHA([]byte(strings.Join(d.PathSet, "\n")))
	if in.VerifyPr != nil {
		d.VerifyPr = VerifyPrBinding{Eligible: in.VerifyPr.Eligible, BindingDigest: in.VerifyPr.BindingDigest, HeadSHA: in.VerifyPr.HeadSHA}
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
		p := in.Policy
		listed := false
		for _, id := range p.KeyIDs {
			if id != "" && id == b.KeyID {
				listed = true
			}
		}
		if !p.Present || !p.OwnerSigned || !admitValidDigest(p.Digest) || !listed {
			why.add(AdmitReasonBotPolicy)
		}
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

// A4: no exclusion is added; an unknown delta is a refusal.
func admitExclusions(in OnboardingAdmissionInput, why *admitReasons) {
	if !in.ExclusionsKnown {
		why.add(AdmitReasonExclusionUnknown)
	}
	if in.ExclusionsAdded != 0 {
		why.add(AdmitReasonExclusion)
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
	if !v.Eligible {
		why.add(AdmitReasonVerifyNotEligible)
	}
	if !shaRE.MatchString(v.HeadSHA) || v.HeadSHA != in.HeadSHA {
		why.add(AdmitReasonVerifyHead)
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
