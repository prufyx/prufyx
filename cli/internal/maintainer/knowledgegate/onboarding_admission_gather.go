// SPDX-License-Identifier: AGPL-3.0-only

package knowledgegate

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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
	baseAbsenceKnown  bool
	basePresent       []string
	baseExclusions    []string
	headExclusions    []string
	recipeKnown       bool
	recipeExclusions  []string
	targetExclPaths   []string
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
	a.exclusionsKnown = true
	var err error
	if a.baseExclusions, err = exclusionIdentities(st.base.loaded); err != nil {
		a.exclusionsKnown = false
	}
	if a.headExclusions, err = exclusionIdentities(st.head.loaded); err != nil {
		a.exclusionsKnown = false
	}
	a.baseAbsence(st, rec)
	a.recipeKnown = true
	for _, p := range rec.Projects {
		for _, t := range st.head.loaded {
			if t.Project != p.Slug {
				continue
			}
			for _, e := range t.Exclude {
				a.targetExclPaths = append(a.targetExclPaths, p.Slug+"\x00"+e.Path)
			}
		}
		items, err := recipeExclusionList(st.headTree, p.Slug)
		if err != nil {
			a.recipeKnown = false
			continue
		}
		for _, x := range items {
			a.recipeExclusions = append(a.recipeExclusions, p.Slug+"\x00"+x)
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
//
// Two locks, both BASE-controlled: the compiled layout flag and the run-time
// in-process flag. With the layout flag off the report carries no member at
// all; with the layout flag on and the run-time flag off the member is the
// plain "disabled" decision, never an evaluation.
func (r *Report) admitOnboarding(ctx context.Context, opts Options) {
	if r.onboarding == nil || !opts.Layout.OnboardingAdmission.Enabled {
		return
	}
	in := r.admissionInput(opts)
	if !opts.OnboardingAdmissionInProcess {
		in.Config.Enabled = false
	} else {
		r.admissionSeam(ctx, opts, &in)
	}
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
		ComputedChangeSet: a.changeSet,
		BatchBaseDigests:  a.batchBase, BatchHeadDigests: a.batchHead, GateBaseDigests: a.gateBase, GateHeadDigests: a.gateHead,
		Projects: a.projects, ExclusionsKnown: a.exclusionsKnown, BaseAbsenceKnown: a.baseAbsenceKnown, BasePresent: a.basePresent, BaseExclusions: a.baseExclusions, HeadExclusions: a.headExclusions,
		RecipeExclusionsKnown: a.recipeKnown, RecipeExclusions: a.recipeExclusions, TargetExclusionPaths: a.targetExclPaths,
		ChangedPaths: r.ChangedPaths, TrustPaths: opts.Layout.TrustPaths, BatchDir: opts.Layout.Onboarding.Dir,
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

// regenerationFacts reports whether every generated output (pairs and
// blocks) of the layout was checked and equals its regeneration, with a
// digest of the head bytes. An empty layout set, a missing check or an
// unreadable output is not known/equal: it never passes vacuously.
func (r *Report) regenerationFacts(opts Options) (known, equal bool, digest string) {
	if len(opts.Layout.Generated) == 0 && len(opts.Layout.GeneratedBlocks) == 0 {
		return false, false, ""
	}
	// Every check of that name must have passed, and there must be one.
	checked := func(path string) bool {
		found := false
		for _, c := range r.Checks {
			if c.Name == "generated/"+path {
				if !c.OK {
					return false
				}
				found = true
			}
		}
		return found
	}
	type item struct{ check, read []string }
	var items []item
	for _, g := range opts.Layout.Generated {
		items = append(items, item{[]string{g.JSONPath}, []string{g.JSONPath, g.MarkdownPath}})
	}
	for _, g := range opts.Layout.GeneratedBlocks {
		items = append(items, item{[]string{g.Path}, []string{g.Path}})
	}
	sort.Slice(items, func(i, j int) bool { return items[i].read[0] < items[j].read[0] })
	var buf bytes.Buffer
	for _, it := range items {
		if !checked(it.check[0]) {
			return true, false, ""
		}
		for _, p := range it.read {
			raw, err := opts.Head.Read(p, MaxFileBytes)
			if err != nil {
				return false, false, ""
			}
			buf.WriteString(p + "\x00" + CandidateDigest(raw) + "\n")
		}
	}
	return true, true, admitSHA(buf.Bytes())
}

// recipesRoot is where the recipe of a project lives (read from the head tree
// as data only).
const recipesRoot = "cli/knowledge/target-recipes/"

// exclusionIdentities is one identity per scan exclusion of every target:
// the project and the digest of the whole exclusion (path, repo, reason,
// evidence and every pin), so a replacement at the same count is a different
// identity. The order is the targets' own and never matters to the decision.
func exclusionIdentities(targets []crdversions.Target) ([]string, error) {
	var out []string
	for _, t := range targets {
		for _, e := range t.Exclude {
			raw, err := json.Marshal(e)
			if err != nil {
				return nil, err
			}
			out = append(out, t.Project+"\x00"+CandidateDigest(raw))
		}
	}
	return out, nil
}

// recipeExclusionList reads the exclude list of a project's recipe from the
// head tree.
func recipeExclusionList(t Tree, slug string) ([]string, error) {
	raw, err := t.Read(recipesRoot+slug+"/recipe.json", MaxFileBytes)
	if err != nil {
		return nil, err
	}
	var rec struct {
		Exclude []string `json:"exclude"`
	}
	if err := json.Unmarshal(raw, &rec); err != nil {
		return nil, err
	}
	return rec.Exclude, nil
}

// baseAbsence records which batch slugs the BASE already has, under any
// casing, in its table, in its targets (by file name or by the project a
// target holds) or in its recipes (a directory or file of that name, with or
// without a recipe.json).
func (a *admissionFacts) baseAbsence(st *onboardingState, rec OnboardingRecord) {
	a.baseAbsenceKnown = true
	recipes, err := treeEntryNames(st.baseTree, strings.TrimSuffix(recipesRoot, "/"))
	if err != nil {
		a.baseAbsenceKnown = false
	}
	for _, p := range rec.Projects {
		present := false
		for _, row := range st.base.projects {
			present = present || strings.EqualFold(row.Slug, p.Slug)
		}
		for name := range st.base.targets {
			present = present || strings.EqualFold(name, crdversions.TargetFileName(p.Slug))
		}
		for _, t := range st.base.loaded {
			present = present || strings.EqualFold(t.Project, p.Slug)
		}
		for _, name := range recipes {
			present = present || strings.EqualFold(name, p.Slug)
		}
		if present {
			a.basePresent = append(a.basePresent, p.Slug)
		}
	}
}

// treeEntryNames lists the names directly inside dir; a missing directory
// has none.
func treeEntryNames(t Tree, dir string) ([]string, error) {
	d, err := t.openDir(dir)
	if errors.Is(err, ErrMissing) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer d.Close()
	names, err := d.Readdirnames(maxTargetFiles + 1)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	if len(names) > maxTargetFiles {
		return nil, fmt.Errorf("%s holds more than %d entries", dir, maxTargetFiles)
	}
	return names, nil
}
