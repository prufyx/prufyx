// SPDX-License-Identifier: AGPL-3.0-only

package knowledgegate

import (
	"bytes"
	"sort"
	"strings"

	"github.com/prufyx/prufyx/cli/internal/extract/crdversions"
)

// admissionFacts is what the onboarding run records for the admission
// decision. It is filled only after the signature verified against the BASE
// keyset (signature) and after the trees were read (state); a member never
// reached stays at its zero value, which never admits.
type admissionFacts struct {
	signatureVerified bool
	keyInBase         bool
	tier              string
	batch             AdmissionBatch
	changeSet         string
	batchBase         AdmissionDigests
	batchHead         AdmissionDigests
	gateBase          AdmissionDigests
	gateHead          AdmissionDigests
	projects          []AdmissionProject
	exclusionsKnown   bool
	exclusionsAdded   int
}

// signature records the batch and its signer. The keys are the BASE's: the
// loader reads them only from the base tree and pins their digest.
func (a *admissionFacts) signature(env OnboardingEnvelope, keys ApprovalKeys) {
	k := keys.keyByID(env.KeyID)
	if k == nil {
		return
	}
	a.keyInBase = true
	switch {
	case k.botTier():
		a.tier = ApprovalTierOnboardingBot
	case k.ownerTier():
		a.tier = ApprovalTierOwner
	}
	r := env.Record
	a.batch = AdmissionBatch{ID: r.BatchID, KeyID: env.KeyID, Tier: a.tier, Identity: r.Identity, Nonce: r.Nonce, NotAfter: r.NotAfter, ChangeSetDigest: r.ChangeSetDigest, SummaryDigest: r.SummaryDigest}
	// Reached only after verifyOnboardingSignature succeeded.
	a.signatureVerified = true
}

// state records the digests of both sides, the projects and the exclusion
// delta from the gate's own reading of the trees.
func (a *admissionFacts) state(st *onboardingState, rec OnboardingRecord) {
	a.changeSet = st.changeSetDigest
	conv := func(s OnboardingState) AdmissionDigests {
		return AdmissionDigests{Registry: s.RegistryDigest, Table: s.TableDigest, Targets: s.TargetsDigest, Pack: s.PackRevision}
	}
	a.batchBase, a.batchHead = conv(rec.Base), conv(rec.Head)
	a.gateBase, a.gateHead = conv(st.base.state), conv(st.head.state)
	baseExcl := map[string]int{}
	for _, t := range st.base.loaded {
		baseExcl[t.Project] = len(t.Exclude)
	}
	headExcl := map[string]int{}
	for _, t := range st.head.loaded {
		headExcl[t.Project] = len(t.Exclude)
	}
	a.exclusionsKnown = true
	for slug, n := range headExcl {
		if n > baseExcl[slug] {
			a.exclusionsAdded += n - baseExcl[slug]
		}
	}
	for _, p := range rec.Projects {
		file := crdversions.TargetFileName(p.Slug)
		raw, ok := st.head.targets[file]
		ap := AdmissionProject{Slug: p.Slug, Kind: p.Kind}
		if ok {
			ap.TargetSHA256 = CandidateDigest(raw)
		}
		a.projects = append(a.projects, ap)
	}
}

// admitOnboarding computes the admission decision of a change that adds an
// onboarding batch. It runs after autoMerge and never changes it.
func (r *Report) admitOnboarding(opts Options) {
	if r.onboarding == nil {
		return
	}
	in := r.admissionInput(opts)
	dec := AdmitOnboardingAuto(in)
	r.OnboardingAdmission = &dec
}

func (r *Report) admissionInput(opts Options) OnboardingAdmissionInput {
	a := r.onboarding.adm
	in := OnboardingAdmissionInput{
		Config: opts.Layout.OnboardingAdmission, Now: opts.Now,
		GatePassed: r.Passed(), Shadow: opts.Shadow || r.Mode == "shadow",
		OnboardingPresent: true, OnboardingOK: r.onboarding.ok, BatchCount: 1,
		Paused: opts.BotSignerPaused, PauseKnown: opts.OnboardingGit != nil && opts.OnboardingGit.Paused != nil,
		HeadSHA: opts.HeadSHA, Author: opts.Author, Sender: opts.Sender, BotLogin: opts.BotLogin, Owner: opts.Owner,
		Batch: a.batch, SignatureVerified: a.signatureVerified, KeyInBaseKeyset: a.keyInBase,
		KeysetDigest: opts.ApprovalKeysDigest, TrustRootDigest: opts.TrustRootDigest,
		Policy: opts.OnboardingBotPolicy, ComputedChangeSet: a.changeSet,
		BatchBaseDigests: a.batchBase, BatchHeadDigests: a.batchHead, GateBaseDigests: a.gateBase, GateHeadDigests: a.gateHead,
		Projects: a.projects, ExclusionsKnown: a.exclusionsKnown, ExclusionsAdded: a.exclusionsAdded,
		ChangedPaths: r.ChangedPaths, TrustPaths: opts.Layout.TrustPaths, BatchDir: opts.Layout.Onboarding.Dir,
		VerifyPr: opts.VerifyPr,
	}
	if in.Batch.ID != "" {
		in.Batch.Path = opts.Layout.Onboarding.Dir + "/" + in.Batch.ID + ".json"
	}
	if g := opts.OnboardingGit; g != nil {
		in.BaseSHA, in.GitHeadSHA = g.BaseCommit, g.HeadCommit
		if g.Paused != nil {
			in.Paused = in.Paused || *g.Paused
		}
	}
	if l := opts.Commits; l != nil {
		in.CommitStatus, in.CommitAheadBy, in.CommitBehindBy, in.CommitTotal = l.Status, l.AheadBy, l.BehindBy, l.TotalCommits
		for _, c := range l.Commits {
			ac := AdmissionCommit{SHA: c.SHA, Verified: c.Commit.Verification.Verified}
			if c.Author != nil {
				ac.Author = c.Author.Login
			}
			if c.Committer != nil {
				ac.Committer = c.Committer.Login
			}
			in.Commits = append(in.Commits, ac)
		}
	}
	in.FileModesOK = onboardingModes(opts, r.ChangedPaths) == ""
	in.RegenKnown, in.RegenByteEqual, in.RegenOutputsSHA256 = r.regenerationFacts(opts)
	return in
}

// regenerationFacts reports whether every generated output pair of the layout
// was checked and equals its regeneration, with a digest of the head bytes.
func (r *Report) regenerationFacts(opts Options) (known, equal bool, digest string) {
	var buf bytes.Buffer
	pairs := append([]GeneratedPair{}, opts.Layout.Generated...)
	sort.Slice(pairs, func(i, j int) bool { return pairs[i].JSONPath < pairs[j].JSONPath })
	for _, g := range pairs {
		ok := false
		for _, c := range r.Checks {
			if c.Name == "generated/"+g.JSONPath {
				ok = c.OK
			}
		}
		if !ok {
			return true, false, ""
		}
		for _, p := range []string{g.JSONPath, g.MarkdownPath} {
			raw, err := opts.Head.Read(p, MaxFileBytes)
			if err != nil {
				return false, false, ""
			}
			buf.WriteString(p + "\x00" + strings.TrimSpace(CandidateDigest(raw)) + "\n")
		}
	}
	return true, true, admitSHA(buf.Bytes())
}
