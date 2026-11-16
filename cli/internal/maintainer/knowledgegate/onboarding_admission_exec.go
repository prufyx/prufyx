// SPDX-License-Identifier: AGPL-3.0-only

package knowledgegate

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/prufyx/prufyx/cli/internal/maintainer/targetdraft"
	"github.com/prufyx/prufyx/cli/internal/pathset"
)

// The onboarding admission execution seam.
//
// The verify-pr style result that the admission decision consumes is never a
// document: it does not come from a flag, an environment variable, a file, a
// label, a workflow artifact or the proposed tree. This file derives it, in
// this process, from the gate's own authenticated objects:
//
//   - the base and head trees are exported from the authenticated object store
//     at the exact base and head commits (refs checked before and after) and
//     must equal the trees the gate judged;
//   - the raw change list is captured ONCE from the same store and parsed by
//     both the gate's own change parser and the verifier;
//   - the expected project list is the signed batch's (already authenticated by
//     the gate), never read from the head tree; exactly one project;
//   - the table digest is recomputed from the authenticated head tree and must
//     equal both the gate's head digest and the signed batch's.
//
// Every failure is a typed refusal in SeamRefusals; none ever supplies a
// result. The only assignment of the VerifyPr input member in non-test code is
// in this file (pinned by a source test).
//
// This file runs only when BOTH locks are on (admitOnboarding): the compiled
// layout flag and the run-time in-process flag.

// Typed refusals of the seam (reasons of the admission decision).
const (
	// AdmitReasonSeamContext: no authenticated git context (this includes a
	// merge queue run, which has no pull request context at all).
	AdmitReasonSeamContext = "verify-pr-git-context-missing"
	// AdmitReasonSeamEvent: the run was not told it is a pull request run
	// (the authenticated event name is missing, a merge queue run, or any
	// other event).
	AdmitReasonSeamEvent = "verify-pr-event-not-pull-request"
	// AdmitReasonSeamNoPR: the run has no pull request author or sender.
	AdmitReasonSeamNoPR = "verify-pr-no-pr-context"
	// AdmitReasonSeamSlugCount: the batch does not hold exactly one project.
	AdmitReasonSeamSlugCount = "verify-pr-slug-count"
	// AdmitReasonSeamStale: the refs or the checked head do not match the
	// authenticated commits (or moved while the seam ran).
	AdmitReasonSeamStale = "verify-pr-refs-stale"
	// AdmitReasonSeamTrees: the trees cannot be authenticated.
	AdmitReasonSeamTrees = "verify-pr-trees-unauthenticated"
	// AdmitReasonSeamDiff: the raw change list cannot be captured or parsed.
	AdmitReasonSeamDiff = "verify-pr-diff-capture-failed"
	// AdmitReasonSeamTable: the head-derived table digest differs from the gate's
	// or the batch's.
	AdmitReasonSeamTable = "verify-pr-table-digest-mismatch"
	// AdmitReasonSeamPolicy: the path policy is incomplete (no trust paths, no
	// table, no batch path).
	AdmitReasonSeamPolicy = "verify-pr-policy-invalid"
	// AdmitReasonSeamHarness: the verifier or the upstream runner failed to give
	// a verdict (I/O, timeout, no runner).
	AdmitReasonSeamHarness = "verify-pr-harness-error"
	// AdmitReasonSeamFailed: the verifier judged the change and refused it.
	AdmitReasonSeamFailed = "verify-pr-verifier-failed"
	// AdmitReasonSeamResult: the verifier result contradicts the gate's own
	// facts.
	AdmitReasonSeamResult = "verify-pr-verdict-inconsistent"
	// AdmitReasonSeamSource: the result is not from the in-process source.
	AdmitReasonSeamSource = "verify-pr-source-not-inprocess"
	// AdmitReasonSeamRefusalEmpty: an empty refusal code was supplied.
	AdmitReasonSeamRefusalEmpty = "verify-pr-refusal-unnamed"
)

// AdmissionEventPullRequest is the only event name the seam accepts: the
// event the gate workflow really runs on for onboarding pull requests
// (pull_request_target: the BASE workflow and the BASE-built binary judge the
// proposed head). The name is passed by the BASE-controlled workflow step
// (--admission-event, from the workflow's own event name, never from the head
// or any proposed file). merge_group, schedule, push, workflow_dispatch and an
// empty or unknown value are all refused.
const AdmissionEventPullRequest = "pull_request_target"

// seamTimeout bounds the whole seam: tree export, diff and the upstream
// binding (three attempts of one minute and the backoff, with margin).
const seamTimeout = 8 * time.Minute

// admissionSeam runs the seam and fills the VerifyPr member (and only on a
// consistent in-process pass) or the typed refusals of the input. It does
// nothing when the batch or the gate did not pass its own checks: the decision
// then refuses on those facts, and no network is used for a change that is
// already refused.
func (r *Report) admissionSeam(ctx context.Context, opts Options, in *OnboardingAdmissionInput) {
	in.VerifyPr = nil
	in.SeamRefusals = nil
	if !r.onboarding.ok || !r.Passed() {
		return
	}
	refuse := func(code string) { in.SeamRefusals = append(in.SeamRefusals, code) }
	if opts.AdmissionEvent != AdmissionEventPullRequest {
		refuse(AdmitReasonSeamEvent)
		return
	}
	g := opts.OnboardingGit
	if g == nil {
		refuse(AdmitReasonSeamContext)
		return
	}
	if opts.Author == "" || opts.Sender == "" {
		refuse(AdmitReasonSeamNoPR)
		return
	}
	if len(in.Projects) != 1 {
		refuse(AdmitReasonSeamSlugCount)
		return
	}
	slugs := []string{in.Projects[0].Slug}
	if g.HeadCommit != opts.HeadSHA || !shaRE.MatchString(g.BaseCommit) || !shaRE.MatchString(g.HeadCommit) || g.BaseCommit == g.HeadCommit {
		refuse(AdmitReasonSeamStale)
		return
	}
	ctx, cancel := context.WithTimeout(ctx, seamTimeout)
	defer cancel()
	if err := checkAdmissionRefs(ctx, g); err != nil {
		refuse(AdmitReasonSeamStale)
		return
	}
	base, head, cleanup, err := exportAdmissionTrees(ctx, g)
	if err != nil {
		refuse(AdmitReasonSeamTrees)
		return
	}
	defer cleanup()
	if equalAdmissionTrees(base, head, opts.Base, opts.Head) != nil {
		refuse(AdmitReasonSeamTrees)
		return
	}
	// The head-derived table digest: from the authenticated head tree, equal to
	// the gate's own head digest and to the signed batch's.
	tableRaw, err := head.Read(opts.Layout.Onboarding.TablePath, MaxFileBytes)
	if err != nil {
		refuse(AdmitReasonSeamTrees)
		return
	}
	table := CandidateDigest(tableRaw)
	if table != in.GateHeadDigests.Table || table != in.BatchHeadDigests.Table || !admitValidDigest(table) {
		refuse(AdmitReasonSeamTable)
		return
	}
	// ONE capture of the raw diff, shared by the gate's change parser and the
	// verifier.
	raw, err := admissionRawDiff(ctx, g, g.HeadCommit)
	if err != nil || len(raw) == 0 {
		refuse(AdmitReasonSeamDiff)
		return
	}
	changes, err := parseAdmissionRaw(ctx, g, raw)
	if err != nil || len(changes) == 0 {
		refuse(AdmitReasonSeamDiff)
		return
	}
	policy := seamPolicy(in, opts.Layout.Onboarding.TablePath)
	if policy.TablePath == "" || policy.BatchPath == "" || len(policy.TrustPaths) == 0 {
		refuse(AdmitReasonSeamPolicy)
		return
	}
	runner := opts.AdmissionRunner
	if runner == nil {
		runner = newAdmissionRunner()
	}
	verify := opts.AdmissionVerifier
	if verify == nil {
		verify = targetdraft.VerifyOnboarding
	}
	res := verify(targetdraft.OnboardingVerifyInput{
		Base: seamTree{base}, Head: seamTree{head}, ChangedRaw: raw, Slugs: slugs, Policy: policy,
		BaseSHA: g.BaseCommit, HeadSHA: g.HeadCommit, Upstream: runner, Sleep: time.Sleep, Ctx: ctx,
	})
	// The refs must still be the authenticated ones after the network step.
	if checkAdmissionRefs(ctx, g) != nil {
		refuse(AdmitReasonSeamStale)
		return
	}
	if res.Mode != targetdraft.OnboardingVerifyMode {
		refuse(AdmitReasonSeamSource)
		return
	}
	if res.Outcome != "pass" {
		if res.Harness {
			refuse(AdmitReasonSeamHarness)
		} else {
			refuse(AdmitReasonSeamFailed)
		}
		return
	}
	if !seamConsistent(res, g, slugs, changes, opts.Layout.Onboarding) {
		refuse(AdmitReasonSeamResult)
		return
	}
	in.VerifyPr = &VerifyPrResult{
		Outcome: res.Outcome, Eligible: res.Eligible, BindingVerified: res.BindingVerified, RecipeChange: res.RecipeChange,
		BaseSHA: res.BaseSHA, HeadSHA: res.HeadSHA, BindingDigest: res.BindingDigest, ChangedPathsSHA256: res.ChangedPathsSHA256,
		Slugs: res.Slugs, TagsCommitsSHA: res.TagsCommitsSHA,
	}
}

// There is deliberately no recover anywhere in the seam: a panic in the
// verifier or the runner fails the gate step closed (no report, no admission).
// Commit ids are 40 hex only (shaRE): the admission wire and the verifier
// accept no other length, so a 64-hex object format is refused as stale.
//
// seamConsistent cross-checks a passing result against the gate's own facts.
// The admission checker repeats the checks it owns; these keep a result that
// contradicts the gate from ever being handed on.
func seamConsistent(res targetdraft.OnboardingVerifyResult, g *OnboardingGitContext, slugs []string, changes []OnboardingGitChange, ol OnboardingLayout) bool {
	if res.BaseSHA != g.BaseCommit || res.HeadSHA != g.HeadCommit || !res.BindingVerified || res.RecipeChange != "new" || res.Eligible {
		return false
	}
	if len(res.Slugs) != len(slugs) || len(res.Slugs) != 1 || res.Slugs[0] != slugs[0] {
		return false
	}
	if !admitValidDigest(res.BindingDigest) || !admitValidDigest(res.ChangedPathsSHA256) {
		return false
	}
	tc, ok := res.TagsCommitsSHA[slugs[0]]
	if !ok || len(res.TagsCommitsSHA) != 1 || !admitValidDigest(tc) {
		return false
	}
	// Two code paths read the same captured bytes and must agree on the set.
	paths := make([]string, 0, len(changes))
	for _, c := range changes {
		paths = append(paths, c.Path)
	}
	want, err := pathset.Digest(paths)
	if err != nil || want != res.ChangedPathsSHA256 {
		return false
	}
	// The judged subset, derived by the gate itself from the layout and the
	// batch's slug, never from the verifier: it must lie inside the full set
	// and its digest must equal the verifier's. The subset test is true by
	// construction (the judged paths are picked from the full set); the real
	// binding is the equality of the two judged-subset digests.
	judged := seamJudgedPaths(ol, slugs[0], paths)
	if len(judged) == 0 || judged[0] != targetPath(ol, slugs[0]) || !seamSubset(judged, paths) {
		return false
	}
	jd, err := pathset.Digest(judged)
	return err == nil && jd == res.JudgedPathsSHA256
}

// seamRecipeFiles are the files of a project's recipe directory a change may
// carry (the gate's own list; the verifier keeps a list of its own).
var seamRecipeFiles = []string{"recipe.json", "rules.json", "facts.bundle", "report.json", "table-row.json", "changelog.md"}

// seamJudgedPaths is the per-project subset an onboarding verdict covers:
// the recipe files and the real target of the slug, as far as the full changed
// set carries them (the verifier itself requires the target and the five
// non-optional recipe files).
func seamJudgedPaths(ol OnboardingLayout, slug string, full []string) []string {
	in := make(map[string]bool, len(full))
	for _, p := range full {
		in[p] = true
	}
	cand := []string{targetPath(ol, slug)}
	for _, n := range seamRecipeFiles {
		cand = append(cand, recipesRoot+slug+"/"+n)
	}
	var out []string
	for _, p := range cand {
		if in[p] {
			out = append(out, p)
		}
	}
	return out
}

// seamSubset reports whether every path of sub is in full.
func seamSubset(sub, full []string) bool {
	in := make(map[string]bool, len(full))
	for _, p := range full {
		in[p] = true
	}
	for _, p := range sub {
		if !in[p] {
			return false
		}
	}
	return true
}

// seamPolicy is the verifier's path policy, from the compiled layout only: the
// batch file, the reviewed table, the further static files the layout allows,
// and the layout's trust paths.
func seamPolicy(in *OnboardingAdmissionInput, tablePath string) targetdraft.OnboardingPolicy {
	p := targetdraft.OnboardingPolicy{BatchPath: in.Batch.Path, TablePath: tablePath, TrustPaths: append([]string(nil), in.TrustPaths...)}
	seen := map[string]bool{p.BatchPath: true, p.TablePath: true}
	for _, s := range in.Config.StaticPaths {
		if !seen[s] {
			seen[s] = true
			p.Optional = append(p.Optional, s)
		}
	}
	sort.Strings(p.Optional)
	return p
}

// seamTree adapts a gate tree to the verifier's read-only tree. It lists
// regular files and symbolic links of the exported tree and refuses anything
// else (device, socket, FIFO) instead of skipping it.
type seamTree struct{ t Tree }

func (s seamTree) Entries() ([]targetdraft.Entry, error) {
	var out []targetdraft.Entry
	err := filepath.WalkDir(s.t.Root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(s.t.Root, p)
		if err != nil {
			return err
		}
		switch {
		case d.Type()&fs.ModeSymlink != 0:
			out = append(out, targetdraft.Entry{Path: filepath.ToSlash(rel), IsLink: true})
		case d.Type().IsRegular():
			out = append(out, targetdraft.Entry{Path: filepath.ToSlash(rel)})
		default:
			return fmt.Errorf("%s is not a regular file or link", filepath.ToSlash(rel))
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out, nil
}

func (s seamTree) Read(p string) ([]byte, error) { return s.t.Read(p, MaxFileBytes) }

func (s seamTree) Link(p string) (string, error) {
	rel, err := cleanRel(p)
	if err != nil {
		return "", err
	}
	// No component but the last may be a link.
	cur := s.t.Root
	parts := strings.Split(rel, "/")
	for i, part := range parts {
		cur = filepath.Join(cur, part)
		info, err := os.Lstat(cur)
		if err != nil {
			return "", err
		}
		isLink := info.Mode()&fs.ModeSymlink != 0
		if isLink != (i == len(parts)-1) {
			return "", errors.New("not a symbolic link at that path")
		}
	}
	return os.Readlink(cur)
}
