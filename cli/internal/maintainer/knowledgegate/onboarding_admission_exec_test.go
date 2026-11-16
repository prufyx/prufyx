// SPDX-License-Identifier: AGPL-3.0-only

package knowledgegate

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/maintainer/targetdraft"
	"github.com/prufyx/prufyx/cli/internal/pathset"
)

// recordingRunner is the fake upstream runner: it counts calls and records the
// specs. The seam tests never reach a network.
type recordingRunner struct {
	mu    sync.Mutex
	specs []targetdraft.ExecSpec
}

func (r *recordingRunner) Run(_ context.Context, spec targetdraft.ExecSpec) targetdraft.ExecResult {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.specs = append(r.specs, spec)
	return targetdraft.ExecResult{Err: os.ErrPermission}
}

func (r *recordingRunner) calls() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.specs)
}

// seamRawPaths lists the paths of a raw -z diff (an independent, trivial
// parser for the fake verifier).
func seamRawPaths(t *testing.T, raw []byte) []string {
	t.Helper()
	parts := bytes.Split(raw, []byte{0})
	if len(parts) < 3 || len(parts[len(parts)-1]) != 0 {
		t.Fatalf("raw diff shape: %d parts", len(parts))
	}
	var out []string
	for i := 1; i < len(parts)-1; i += 2 {
		out = append(out, string(parts[i]))
	}
	return out
}

type seamFixture struct {
	t      *testing.T
	f      *onboardingFixture
	repo   string
	base   string
	head   string
	g      *OnboardingGitContext
	opts   Options
	runner *recordingRunner
	// verdict answers the fake verifier; nil means a consistent pass.
	verdict func(targetdraft.OnboardingVerifyInput) targetdraft.OnboardingVerifyResult
	mu      sync.Mutex
	// treeDiffs records, at call time (the exported trees are removed after
	// the seam), the differences between the handed trees and the judged ones.
	treeDiffs []string
	inputs    []targetdraft.OnboardingVerifyInput
	r         *Report
}

func (s *seamFixture) verify(in targetdraft.OnboardingVerifyInput) targetdraft.OnboardingVerifyResult {
	var diffs []string
	for _, c := range []struct {
		got  targetdraft.Tree
		have Tree
	}{{in.Base, s.f.base}, {in.Head, s.f.head}} {
		st, ok := c.got.(seamTree)
		if !ok || st.t.Root == c.have.Root {
			diffs = append(diffs, "not an exported copy")
			continue
		}
		if d, err := ChangedPaths(st.t, c.have); err != nil || len(d) != 0 {
			diffs = append(diffs, "differs from the judged tree")
		}
	}
	s.mu.Lock()
	s.inputs = append(s.inputs, in)
	s.treeDiffs = append(s.treeDiffs, diffs...)
	s.mu.Unlock()
	if s.verdict != nil {
		return s.verdict(in)
	}
	return s.passFor(in)
}

func (s *seamFixture) passFor(in targetdraft.OnboardingVerifyInput) targetdraft.OnboardingVerifyResult {
	paths := seamRawPaths(s.t, in.ChangedRaw)
	digest, err := pathset.Digest(paths)
	if err != nil {
		s.t.Fatal(err)
	}
	judged, err := pathset.Digest(seamJudgedPaths(s.opts.Layout.Onboarding, in.Slugs[0], paths))
	if err != nil {
		s.t.Fatal(err)
	}
	tc := map[string]string{}
	for _, slug := range in.Slugs {
		tc[slug] = admDigest
	}
	return targetdraft.OnboardingVerifyResult{
		Mode: "inprocess", Outcome: "pass", Reasons: []string{}, BaseSHA: in.BaseSHA, HeadSHA: in.HeadSHA,
		BindingVerified: true, RecipeChange: "new", ChangedPathsSHA256: digest, JudgedPathsSHA256: judged,
		Slugs: in.Slugs, BindingDigest: admDigest, TagsCommitsSHA: tc,
	}
}

func (s *seamFixture) calls() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.inputs)
}

// restCounts matches the request tally of the rest-budget check.
var restCounts = regexp.MustCompile(`(\d+ REST requests|"restRequests":\d+)`)

func newSeamFixture(t *testing.T) *seamFixture {
	t.Helper()
	f := newOnboardingFixture(t)
	f.sign(t, f.record(t))
	s := &seamFixture{t: t, f: f, runner: &recordingRunner{}}
	s.repo = t.TempDir()
	gitIn(t, s.repo, "init", "--bare", "-q")
	s.base = admissionCommit(t, s.repo, f.base, "")
	s.head = admissionCommit(t, s.repo, f.head, s.base)
	gitIn(t, s.repo, "update-ref", admissionBaseRef, s.base)
	gitIn(t, s.repo, "update-ref", admissionHeadRef, s.head)
	paused := false
	s.g = &OnboardingGitContext{GitDir: s.repo, BaseCommit: s.base, HeadCommit: s.head, DailyCommits: []DailyCommit{}, Paused: &paused, ObservedAt: gateNow}
	s.opts = Options{Base: f.base, Head: f.head, Source: f.src, Author: obOwner, Sender: obOwner, Layout: DefaultLayout(),
		OnboardingGit: s.g, HeadSHA: s.head, OnboardingAdmissionInProcess: true, AdmissionEvent: AdmissionEventPullRequestTarget, AdmissionRunner: s.runner, AdmissionVerifier: s.verify}
	s.opts.Layout.OnboardingAdmission.Enabled = true
	return s
}

// gate runs the whole gate with the fixture options (after mutate).
func (s *seamFixture) gate(mutate func(*Options)) *Report {
	s.t.Helper()
	o := s.opts
	if mutate != nil {
		mutate(&o)
	}
	r := runGate(s.t, o)
	requirePass(s.t, r)
	s.r = r
	return r
}

// direct runs only the seam against a gate-passed report; mutate edits the
// options and the input before.
func (s *seamFixture) direct(mutate func(*Options, *OnboardingAdmissionInput)) OnboardingAdmissionInput {
	s.t.Helper()
	if s.r == nil {
		s.gate(nil)
	}
	o := s.opts
	in := s.r.admissionInput(o)
	if mutate != nil {
		mutate(&o, &in)
	}
	s.r.admissionSeam(context.Background(), o, &in)
	return in
}

func hasSeamReason(in OnboardingAdmissionInput, code string) bool {
	for _, c := range in.SeamRefusals {
		if c == code {
			return true
		}
	}
	return false
}

func seamOnly(t *testing.T, in OnboardingAdmissionInput, code string) {
	t.Helper()
	if !reflect.DeepEqual(in.SeamRefusals, []string{code}) {
		t.Fatalf("refusals %v, want exactly %s", in.SeamRefusals, code)
	}
	if in.VerifyPr != nil {
		t.Fatalf("a refusal still supplied a result: %+v", in.VerifyPr)
	}
}

func verifyReasons(d *OnboardingAdmission) []string {
	var out []string
	for _, r := range d.Reasons {
		if strings.HasPrefix(r, "verify-pr-") {
			out = append(out, r)
		}
	}
	return out
}

// Both locks on: the seam runs the verifier on the gate's own authenticated
// trees and the one captured raw diff, with the batch's slug, and A1 sees no
// verify-pr reason.
func TestSeamBothLocksOnRunsVerifier(t *testing.T) {
	t.Parallel()
	s := newSeamFixture(t)
	r := s.gate(nil)
	if s.calls() != 1 {
		t.Fatalf("verifier called %d times", s.calls())
	}
	in := s.inputs[0]
	if !reflect.DeepEqual(in.Slugs, []string{obSlug}) || in.BaseSHA != s.base || in.HeadSHA != s.head {
		t.Fatalf("slugs %v base %s head %s", in.Slugs, in.BaseSHA, in.HeadSHA)
	}
	want := gitIn(t, s.repo, "diff", "--no-ext-diff", "--no-textconv", "--raw", "-z", "--no-abbrev", "--no-renames", s.base, s.head, "--")
	// gitIn trims; compare the trimmed form and the NUL structure.
	if strings.TrimSpace(string(in.ChangedRaw)) != want {
		t.Fatal("the verifier did not get the raw diff of the exact commits")
	}
	// The trees are the exported authenticated ones, equal to the judged ones,
	// but not the caller's directories (checked while the seam ran).
	if len(s.treeDiffs) != 0 {
		t.Fatalf("trees handed to the verifier: %v", s.treeDiffs)
	}
	if in.Policy.BatchPath != s.opts.Layout.Onboarding.Dir+"/"+r.onboarding.id+".json" || in.Policy.TablePath != s.opts.Layout.Onboarding.TablePath {
		t.Fatalf("policy %+v", in.Policy)
	}
	if len(in.Policy.TrustPaths) == 0 || !reflect.DeepEqual(in.Policy.TrustPaths, s.opts.Layout.TrustPaths) {
		t.Fatalf("trust paths %v", in.Policy.TrustPaths)
	}
	if in.Upstream != targetdraft.LsRemoteRunner(s.runner) {
		t.Fatalf("upstream runner %T", in.Upstream)
	}
	d := r.OnboardingAdmission
	if d == nil {
		t.Fatal("no decision")
	}
	if got := verifyReasons(d); len(got) != 0 {
		t.Fatalf("verify-pr reasons on a consistent in-process pass: %v", got)
	}
	if d.VerifyPr.Outcome != "pass" || !d.VerifyPr.BindingVerified || d.VerifyPr.RecipeChange != "new" || d.VerifyPr.Eligible ||
		d.VerifyPr.BaseSHA != s.base || d.VerifyPr.HeadSHA != s.head || d.VerifyPr.ChangedPathsSHA256 != d.PathSetSHA || d.VerifyPr.BindingDigest != admDigest {
		t.Fatalf("bound member %+v (path set %s)", d.VerifyPr, d.PathSetSHA)
	}
	if d.Admitted {
		t.Fatal("an owner fixture with no allowlist must not be admitted")
	}
	if r.AutoMerge.Eligible {
		t.Fatal("the seam turned auto merge on")
	}
}

// Either lock off is exactly the "disabled" decision, with no verifier and no
// network.
func TestSeamEitherLockOffIsDisabled(t *testing.T) {
	t.Parallel()
	s := newSeamFixture(t)
	// Layout off, run-time on: no member at all (the report is the pre-seam one).
	r := s.gate(func(o *Options) { o.Layout.OnboardingAdmission.Enabled = false })
	if r.OnboardingAdmission != nil {
		t.Fatalf("member with the compiled lock off: %+v", r.OnboardingAdmission)
	}
	// Layout on, run-time off: the plain disabled decision.
	r = s.gate(func(o *Options) { o.OnboardingAdmissionInProcess = false })
	d := r.OnboardingAdmission
	if d == nil || d.Admitted || !reflect.DeepEqual(d.Reasons, []string{AdmitReasonDisabled}) {
		t.Fatalf("decision %+v", d)
	}
	if d.VerifyPr != (VerifyPrBinding{}) {
		t.Fatalf("disabled decision carries a result: %+v", d.VerifyPr)
	}
	if s.calls() != 0 || s.runner.calls() != 0 {
		t.Fatalf("verifier %d runner %d with a lock off", s.calls(), s.runner.calls())
	}
	// Both off: no member, byte-identical to the layout-off report. A warm-up
	// run first (the fixture seeds a baseline on its first gate run), then the
	// same inputs three times: flag off, flag on, flag off.
	s.gate(func(o *Options) { o.Layout.OnboardingAdmission.Enabled = false })
	enc := func(mut func(*Options)) []byte {
		b, err := json.Marshal(s.gate(mut))
		if err != nil {
			t.Fatal(err)
		}
		// The fixture's upstream counts requests across runs (a counter, not
		// part of the decision): normalise that one number.
		return restCounts.ReplaceAll(b, []byte("REST"))
	}
	offA := enc(func(o *Options) { o.Layout.OnboardingAdmission.Enabled = false; o.OnboardingAdmissionInProcess = false })
	offB := enc(func(o *Options) { o.Layout.OnboardingAdmission.Enabled = false })
	offC := enc(func(o *Options) { o.Layout.OnboardingAdmission.Enabled = false; o.OnboardingAdmissionInProcess = false })
	if !bytes.Equal(offA, offC) {
		t.Fatalf("the fixture's own reports are not deterministic:\n%s\n%s", offA, offC)
	}
	if !bytes.Equal(offA, offB) || bytes.Contains(offA, []byte("onboardingAdmission")) {
		t.Fatalf("a report with the compiled lock off depends on the run-time flag:\n%s\n%s", offA, offB)
	}
	if s.calls() != 0 {
		t.Fatal("verifier ran with a lock off")
	}
}

// Nothing a caller supplies can stand in for the result: the options have no
// such member, and a result already present in the input is discarded.
func TestSeamIgnoresCallerResult(t *testing.T) {
	t.Parallel()
	if _, ok := reflect.TypeOf(Options{}).FieldByName("VerifyPr"); ok {
		t.Fatal("Options carries a verify-pr result member")
	}
	s := newSeamFixture(t)
	s.verdict = func(in targetdraft.OnboardingVerifyInput) targetdraft.OnboardingVerifyResult {
		return targetdraft.OnboardingVerifyResult{Mode: "inprocess", Outcome: "fail", Reasons: []string{"x"}}
	}
	in := s.direct(func(o *Options, in *OnboardingAdmissionInput) {
		in.VerifyPr = &VerifyPrResult{Outcome: "pass", BindingVerified: true, RecipeChange: "new", BaseSHA: s.base, HeadSHA: s.head, BindingDigest: admDigest}
		in.SeamRefusals = []string{"stale"}
	})
	seamOnly(t, in, AdmitReasonSeamFailed)
}

// Skipped (no network, no refusal of its own) when the batch or the gate
// already failed: the decision refuses on those facts.
func TestSeamSkippedWhenGateOrBatchFailed(t *testing.T) {
	t.Parallel()
	s := newSeamFixture(t)
	s.gate(nil)
	before := s.calls()
	for name, mut := range map[string]func(*Report){
		"batch not ok": func(r *Report) { r.onboarding.ok = false },
		"gate failed":  func(r *Report) { r.Result = "fail" },
	} {
		r := *s.r
		on := *s.r.onboarding
		r.onboarding = &on
		mut(&r)
		in := r.admissionInput(s.opts)
		in.VerifyPr = &VerifyPrResult{Outcome: "pass"}
		r.admissionSeam(context.Background(), s.opts, &in)
		if in.VerifyPr != nil || len(in.SeamRefusals) != 0 || s.calls() != before || s.runner.calls() != 0 {
			t.Fatalf("%s: result %v refusals %v calls %d", name, in.VerifyPr, in.SeamRefusals, s.calls())
		}
		if d := AdmitOnboardingAuto(in); d.Admitted {
			t.Fatalf("%s: admitted", name)
		}
	}
}

func TestSeamRefusals(t *testing.T) {
	t.Parallel()
	moveRef := func(t *testing.T, s *seamFixture, ref, to string) {
		t.Helper()
		gitIn(t, s.repo, "update-ref", ref, to)
	}
	cases := []struct {
		name   string
		want   string
		mutate func(t *testing.T, s *seamFixture, o *Options, in *OnboardingAdmissionInput)
		// calls is the expected verifier call count.
		calls int
	}{
		{"event missing", AdmitReasonSeamEvent, func(t *testing.T, s *seamFixture, o *Options, in *OnboardingAdmissionInput) { o.AdmissionEvent = "" }, 0},
		{"merge queue event", AdmitReasonSeamEvent, func(t *testing.T, s *seamFixture, o *Options, in *OnboardingAdmissionInput) {
			o.AdmissionEvent = "merge_group"
		}, 0},
		{"push event", AdmitReasonSeamEvent, func(t *testing.T, s *seamFixture, o *Options, in *OnboardingAdmissionInput) {
			o.AdmissionEvent = "push"
		}, 0},
		{"pull_request event (not the gate's event)", AdmitReasonSeamEvent, func(t *testing.T, s *seamFixture, o *Options, in *OnboardingAdmissionInput) {
			o.AdmissionEvent = "pull_request"
		}, 0},
		{"schedule event", AdmitReasonSeamEvent, func(t *testing.T, s *seamFixture, o *Options, in *OnboardingAdmissionInput) {
			o.AdmissionEvent = "schedule"
		}, 0},
		{"event with padding", AdmitReasonSeamEvent, func(t *testing.T, s *seamFixture, o *Options, in *OnboardingAdmissionInput) {
			o.AdmissionEvent = "pull_request_target "
		}, 0},
		{"event in another case", AdmitReasonSeamEvent, func(t *testing.T, s *seamFixture, o *Options, in *OnboardingAdmissionInput) {
			o.AdmissionEvent = "Pull_Request_Target"
		}, 0},
		{"git context missing", AdmitReasonSeamContext, func(t *testing.T, s *seamFixture, o *Options, in *OnboardingAdmissionInput) { o.OnboardingGit = nil }, 0},
		{"merge queue run: no author", AdmitReasonSeamNoPR, func(t *testing.T, s *seamFixture, o *Options, in *OnboardingAdmissionInput) { o.Author = "" }, 0},
		{"merge queue run: no sender", AdmitReasonSeamNoPR, func(t *testing.T, s *seamFixture, o *Options, in *OnboardingAdmissionInput) { o.Sender = "" }, 0},
		{"two projects", AdmitReasonSeamSlugCount, func(t *testing.T, s *seamFixture, o *Options, in *OnboardingAdmissionInput) {
			in.Projects = append(in.Projects, AdmissionProject{Slug: "beta", Kind: OnboardingKindNew})
		}, 0},
		{"no project", AdmitReasonSeamSlugCount, func(t *testing.T, s *seamFixture, o *Options, in *OnboardingAdmissionInput) { in.Projects = nil }, 0},
		{"checked head is not the authenticated head", AdmitReasonSeamStale, func(t *testing.T, s *seamFixture, o *Options, in *OnboardingAdmissionInput) {
			o.HeadSHA = s.base
		}, 0},
		{"head equals base", AdmitReasonSeamStale, func(t *testing.T, s *seamFixture, o *Options, in *OnboardingAdmissionInput) {
			g := *o.OnboardingGit
			g.BaseCommit = g.HeadCommit
			o.OnboardingGit = &g
		}, 0},
		{"malformed commit id", AdmitReasonSeamStale, func(t *testing.T, s *seamFixture, o *Options, in *OnboardingAdmissionInput) {
			g := *o.OnboardingGit
			g.BaseCommit = "HEAD"
			o.OnboardingGit = &g
		}, 0},
		{"head ref moved before the run", AdmitReasonSeamStale, func(t *testing.T, s *seamFixture, o *Options, in *OnboardingAdmissionInput) {
			moveRef(t, s, admissionHeadRef, s.base)
		}, 0},
		{"base ref moved before the run", AdmitReasonSeamStale, func(t *testing.T, s *seamFixture, o *Options, in *OnboardingAdmissionInput) {
			moveRef(t, s, admissionBaseRef, s.head)
		}, 0},
		{"head tree differs from the authenticated tree", AdmitReasonSeamTrees, func(t *testing.T, s *seamFixture, o *Options, in *OnboardingAdmissionInput) {
			writeFile(t, filepath.Join(o.Head.Root, "cli", "stowaway.txt"), []byte("x"))
		}, 0},
		{"base tree differs from the authenticated tree", AdmitReasonSeamTrees, func(t *testing.T, s *seamFixture, o *Options, in *OnboardingAdmissionInput) {
			writeFile(t, filepath.Join(o.Base.Root, "cli", "stowaway.txt"), []byte("x"))
		}, 0},
		{"table digest of the gate differs from the head tree", AdmitReasonSeamTable, func(t *testing.T, s *seamFixture, o *Options, in *OnboardingAdmissionInput) {
			in.GateHeadDigests.Table = admOther
		}, 0},
		{"table digest of the batch differs from the head tree", AdmitReasonSeamTable, func(t *testing.T, s *seamFixture, o *Options, in *OnboardingAdmissionInput) {
			in.BatchHeadDigests.Table = admOther
		}, 0},
		{"empty trust paths", AdmitReasonSeamPolicy, func(t *testing.T, s *seamFixture, o *Options, in *OnboardingAdmissionInput) { in.TrustPaths = nil }, 0},
		{"no batch path", AdmitReasonSeamPolicy, func(t *testing.T, s *seamFixture, o *Options, in *OnboardingAdmissionInput) { in.Batch.Path = "" }, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			s := newSeamFixture(t)
			s.gate(nil)
			before := s.calls()
			in := s.direct(func(o *Options, in *OnboardingAdmissionInput) { c.mutate(t, s, o, in) })
			seamOnly(t, in, c.want)
			if s.calls() != before+c.calls || s.runner.calls() != 0 {
				t.Fatalf("verifier calls %d (want %d) runner %d", s.calls()-before, c.calls, s.runner.calls())
			}
		})
	}
}

// The raw diff cannot be turned into the change vector (a deletion is not an
// onboarding change): refused before the verifier runs.
func TestSeamDiffRefusal(t *testing.T) {
	t.Parallel()
	s := newSeamFixture(t)
	s.gate(nil)
	// A second history where the head also deletes one file of the base.
	victim := "cli/docs/doomed.txt"
	writeFile(t, filepath.Join(s.f.base.Root, filepath.FromSlash(victim)), []byte("x"))
	repo := t.TempDir()
	gitIn(t, repo, "init", "--bare", "-q")
	base := admissionCommit(t, repo, s.f.base, "")
	if err := os.Remove(filepath.Join(s.f.base.Root, filepath.FromSlash(victim))); err != nil {
		t.Fatal(err)
	}
	head := admissionCommit(t, repo, s.f.head, base)
	gitIn(t, repo, "update-ref", admissionBaseRef, base)
	gitIn(t, repo, "update-ref", admissionHeadRef, head)
	// Rebuild the judged trees to match: the base keeps the file, the head lacks it.
	writeFile(t, filepath.Join(s.f.base.Root, filepath.FromSlash(victim)), []byte("x"))
	in := s.direct(func(o *Options, in *OnboardingAdmissionInput) {
		g := *o.OnboardingGit
		g.GitDir, g.BaseCommit, g.HeadCommit = repo, base, head
		o.OnboardingGit, o.HeadSHA = &g, head
	})
	seamOnly(t, in, AdmitReasonSeamDiff)
	if s.calls() != 1 {
		t.Fatalf("verifier ran on an unparsable change list: %d", s.calls()-1)
	}
	_ = os.Remove(filepath.Join(s.f.base.Root, filepath.FromSlash(victim)))
}

// The ref moving while the verifier runs (a force push during the network
// step) refuses, and so does a result that is not from the in-process source.
func TestSeamVerifierResultRefusals(t *testing.T) {
	t.Parallel()
	type tweak = func(*targetdraft.OnboardingVerifyResult)
	cases := []struct {
		name string
		want string
		fn   tweak
	}{
		{"harness failure", AdmitReasonSeamHarness, func(r *targetdraft.OnboardingVerifyResult) {
			*r = targetdraft.OnboardingVerifyResult{Mode: "inprocess", Outcome: "fail", Harness: true, Reasons: []string{"binding-timeout"}}
		}},
		{"verifier refusal", AdmitReasonSeamFailed, func(r *targetdraft.OnboardingVerifyResult) {
			*r = targetdraft.OnboardingVerifyResult{Mode: "inprocess", Outcome: "fail", Reasons: []string{"binding-tag-moved"}}
		}},
		{"unknown outcome", AdmitReasonSeamFailed, func(r *targetdraft.OnboardingVerifyResult) { r.Outcome = "NOT_APPLICABLE" }},
		{"empty outcome", AdmitReasonSeamFailed, func(r *targetdraft.OnboardingVerifyResult) { r.Outcome = "" }},
		{"zero result", AdmitReasonSeamSource, func(r *targetdraft.OnboardingVerifyResult) { *r = targetdraft.OnboardingVerifyResult{} }},
		{"other source", AdmitReasonSeamSource, func(r *targetdraft.OnboardingVerifyResult) { r.Mode = "workflow" }},
		{"other head", AdmitReasonSeamResult, func(r *targetdraft.OnboardingVerifyResult) { r.HeadSHA = strings.Repeat("a", 40) }},
		{"other base", AdmitReasonSeamResult, func(r *targetdraft.OnboardingVerifyResult) { r.BaseSHA = strings.Repeat("a", 40) }},
		{"binding not verified", AdmitReasonSeamResult, func(r *targetdraft.OnboardingVerifyResult) { r.BindingVerified = false }},
		{"recipe changed", AdmitReasonSeamResult, func(r *targetdraft.OnboardingVerifyResult) { r.RecipeChange = "changed" }},
		{"recipe unchanged", AdmitReasonSeamResult, func(r *targetdraft.OnboardingVerifyResult) { r.RecipeChange = "unchanged" }},
		{"eligible", AdmitReasonSeamResult, func(r *targetdraft.OnboardingVerifyResult) { r.Eligible = true }},
		{"other slug", AdmitReasonSeamResult, func(r *targetdraft.OnboardingVerifyResult) { r.Slugs = []string{"beta"} }},
		{"two slugs", AdmitReasonSeamResult, func(r *targetdraft.OnboardingVerifyResult) { r.Slugs = append(r.Slugs, "beta") }},
		{"no slugs", AdmitReasonSeamResult, func(r *targetdraft.OnboardingVerifyResult) { r.Slugs = nil }},
		{"binding digest malformed", AdmitReasonSeamResult, func(r *targetdraft.OnboardingVerifyResult) { r.BindingDigest = "sha256:zz" }},
		{"binding digest empty", AdmitReasonSeamResult, func(r *targetdraft.OnboardingVerifyResult) { r.BindingDigest = "" }},
		{"changed-paths digest of another set", AdmitReasonSeamResult, func(r *targetdraft.OnboardingVerifyResult) { r.ChangedPathsSHA256 = admOther }},
		{"changed-paths digest empty", AdmitReasonSeamResult, func(r *targetdraft.OnboardingVerifyResult) { r.ChangedPathsSHA256 = "" }},
		{"judged digest of another set", AdmitReasonSeamResult, func(r *targetdraft.OnboardingVerifyResult) { r.JudgedPathsSHA256 = admOther }},
		{"judged digest is the full set", AdmitReasonSeamResult, func(r *targetdraft.OnboardingVerifyResult) { r.JudgedPathsSHA256 = r.ChangedPathsSHA256 }},
		{"judged digest empty", AdmitReasonSeamResult, func(r *targetdraft.OnboardingVerifyResult) { r.JudgedPathsSHA256 = "" }},
		{"no tags/commits digest", AdmitReasonSeamResult, func(r *targetdraft.OnboardingVerifyResult) { r.TagsCommitsSHA = nil }},
		{"tags/commits digest of another project", AdmitReasonSeamResult, func(r *targetdraft.OnboardingVerifyResult) {
			for k := range r.TagsCommitsSHA {
				delete(r.TagsCommitsSHA, k)
			}
			r.TagsCommitsSHA["beta"] = admDigest
		}},
		{"extra tags/commits digest", AdmitReasonSeamResult, func(r *targetdraft.OnboardingVerifyResult) { r.TagsCommitsSHA["beta"] = admDigest }},
		{"tags/commits digest malformed", AdmitReasonSeamResult, func(r *targetdraft.OnboardingVerifyResult) {
			for k := range r.TagsCommitsSHA {
				r.TagsCommitsSHA[k] = "x"
			}
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			s := newSeamFixture(t)
			s.gate(nil)
			s.verdict = func(in targetdraft.OnboardingVerifyInput) targetdraft.OnboardingVerifyResult {
				r := s.passFor(in)
				c.fn(&r)
				return r
			}
			in := s.direct(nil)
			seamOnly(t, in, c.want)
			// The decision refuses and never admits.
			if d := AdmitOnboardingAuto(in); d.Admitted || len(verifyReasons(&d)) == 0 {
				t.Fatalf("decision %+v", d.Reasons)
			}
		})
	}
	t.Run("ref moved during the network step", func(t *testing.T) {
		t.Parallel()
		s := newSeamFixture(t)
		s.gate(nil)
		s.verdict = func(in targetdraft.OnboardingVerifyInput) targetdraft.OnboardingVerifyResult {
			gitIn(t, s.repo, "update-ref", admissionHeadRef, s.base)
			return s.passFor(in)
		}
		seamOnly(t, s.direct(nil), AdmitReasonSeamStale)
	})
	t.Run("pass", func(t *testing.T) {
		t.Parallel()
		s := newSeamFixture(t)
		s.gate(nil)
		in := s.direct(nil)
		if len(in.SeamRefusals) != 0 || in.VerifyPr == nil || in.VerifyPr.Outcome != "pass" || !reflect.DeepEqual(in.VerifyPr.Slugs, []string{obSlug}) {
			t.Fatalf("%v %+v", in.SeamRefusals, in.VerifyPr)
		}
	})
}

// The real verifier on the real adapter: the fixture is not a valid recipe
// change, so it refuses on the local checks (not as a harness error) and the
// network runner is never used.
func TestSeamRealVerifierRefusesWithoutNetwork(t *testing.T) {
	t.Parallel()
	s := newSeamFixture(t)
	s.opts.AdmissionVerifier = nil
	r := s.gate(nil)
	d := r.OnboardingAdmission
	if d == nil || d.Admitted || !strings.Contains(strings.Join(d.Reasons, ","), AdmitReasonSeamFailed) || strings.Contains(strings.Join(d.Reasons, ","), AdmitReasonSeamHarness) {
		t.Fatalf("decision %+v", d)
	}
	if s.runner.calls() != 0 {
		t.Fatal("the upstream runner ran for a change that failed the local checks")
	}
	if d.VerifyPr != (VerifyPrBinding{}) {
		t.Fatalf("a refused run bound a result %+v", d.VerifyPr)
	}
}

// The default runner is the gate's own fixed one when none is injected.
func TestSeamDefaultRunnerIsTheGateRunner(t *testing.T) {
	t.Parallel()
	s := newSeamFixture(t)
	s.opts.AdmissionRunner = nil
	s.gate(nil)
	if s.calls() != 1 {
		t.Fatal("verifier not called")
	}
	if _, ok := s.inputs[0].Upstream.(admissionRunner); !ok {
		t.Fatalf("default upstream %T", s.inputs[0].Upstream)
	}
	if s.inputs[0].Sleep == nil || s.inputs[0].Ctx == nil {
		t.Fatal("sleep or context missing")
	}
}

func TestSeamPolicyFromLayoutOnly(t *testing.T) {
	t.Parallel()
	in := &OnboardingAdmissionInput{
		Batch:        AdmissionBatch{Path: "cli/onboarding/b1.json"},
		TrustPaths:   []string{"cli/knowledge/trust/"},
		Config:       OnboardingAdmissionConfig{StaticPaths: []string{"cli/b.json", "cli/a.json", "cli/table.json", "cli/onboarding/b1.json", "cli/a.json"}},
		ChangedPaths: []string{"cli/evil.json"},
	}
	p := seamPolicy(in, "cli/table.json")
	if p.BatchPath != "cli/onboarding/b1.json" || p.TablePath != "cli/table.json" || !reflect.DeepEqual(p.TrustPaths, []string{"cli/knowledge/trust/"}) {
		t.Fatalf("%+v", p)
	}
	if !reflect.DeepEqual(p.Optional, []string{"cli/a.json", "cli/b.json"}) || len(p.Required) != 0 {
		t.Fatalf("optional %v required %v", p.Optional, p.Required)
	}
	// The policy never copies the change's own paths.
	for _, x := range append(p.Optional, p.Required...) {
		if x == "cli/evil.json" {
			t.Fatal("policy took a path from the change")
		}
	}
	// The trust list is a copy.
	p.TrustPaths[0] = "x"
	if in.TrustPaths[0] != "cli/knowledge/trust/" {
		t.Fatal("trust paths alias the layout")
	}
}

func TestSeamTreeAdapter(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "a", "b.txt"), []byte("hello"))
	writeFile(t, filepath.Join(root, "a-b.txt"), []byte("x"))
	if err := os.Symlink("b.txt", filepath.Join(root, "a", "l")); err != nil {
		t.Fatal(err)
	}
	st := seamTree{Tree{Root: root}}
	ents, err := st.Entries()
	if err != nil {
		t.Fatal(err)
	}
	want := []targetdraft.Entry{{Path: "a-b.txt"}, {Path: "a/b.txt"}, {Path: "a/l", IsLink: true}}
	sort.Slice(want, func(i, j int) bool { return want[i].Path < want[j].Path })
	if !reflect.DeepEqual(ents, want) {
		t.Fatalf("entries %v want %v", ents, want)
	}
	if b, err := st.Read("a/b.txt"); err != nil || string(b) != "hello" {
		t.Fatalf("read %q %v", b, err)
	}
	if _, err := st.Read("a/l"); err == nil {
		t.Fatal("read followed a link")
	}
	if _, err := st.Read("../x"); err == nil {
		t.Fatal("read escaped the tree")
	}
	if l, err := st.Link("a/l"); err != nil || l != "b.txt" {
		t.Fatalf("link %q %v", l, err)
	}
	if _, err := st.Link("a/b.txt"); err == nil {
		t.Fatal("a regular file is not a link")
	}
	if _, err := st.Link("a"); err == nil {
		t.Fatal("a directory is not a link")
	}
	// A link in the middle of the path is never traversed.
	if err := os.Symlink("a", filepath.Join(root, "dirlink")); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Link("dirlink/l"); err == nil {
		t.Fatal("link traversal through a linked directory")
	}
	if _, err := st.Link("/etc/passwd"); err == nil {
		t.Fatal("absolute path accepted")
	}
	if _, err := (seamTree{Tree{Root: filepath.Join(root, "missing")}}).Entries(); err == nil {
		t.Fatal("missing root listed")
	}
	if _, err := exec.LookPath("mkfifo"); err == nil {
		if err := exec.Command("mkfifo", filepath.Join(root, "pipe")).Run(); err == nil {
			if _, err := st.Entries(); err == nil {
				t.Fatal("a FIFO was skipped instead of refused")
			}
		}
	}
}

func TestSeamConsistentMutations(t *testing.T) {
	t.Parallel()
	g := &OnboardingGitContext{BaseCommit: strings.Repeat("1", 40), HeadCommit: strings.Repeat("2", 40)}
	ol := DefaultLayout().Onboarding
	tgt := targetPath(ol, "alpha")
	rec := recipesRoot + "alpha/recipe.json"
	changes := []OnboardingGitChange{{Path: "cli/b"}, {Path: tgt}, {Path: rec}}
	d, err := pathset.Digest([]string{"cli/b", tgt, rec})
	if err != nil {
		t.Fatal(err)
	}
	jd, err := pathset.Digest([]string{tgt, rec})
	if err != nil {
		t.Fatal(err)
	}
	good := func() targetdraft.OnboardingVerifyResult {
		return targetdraft.OnboardingVerifyResult{BaseSHA: g.BaseCommit, HeadSHA: g.HeadCommit, BindingVerified: true, RecipeChange: "new",
			Slugs: []string{"alpha"}, BindingDigest: admDigest, ChangedPathsSHA256: d, JudgedPathsSHA256: jd, TagsCommitsSHA: map[string]string{"alpha": admDigest}}
	}
	if !seamConsistent(good(), g, []string{"alpha"}, changes, ol) {
		t.Fatal("the consistent result is refused")
	}
	for name, f := range map[string]func(*targetdraft.OnboardingVerifyResult){
		"base": func(r *targetdraft.OnboardingVerifyResult) { r.BaseSHA = g.HeadCommit }, "head": func(r *targetdraft.OnboardingVerifyResult) { r.HeadSHA = g.BaseCommit },
		"binding": func(r *targetdraft.OnboardingVerifyResult) { r.BindingVerified = false }, "recipe": func(r *targetdraft.OnboardingVerifyResult) { r.RecipeChange = "" },
		"eligible": func(r *targetdraft.OnboardingVerifyResult) { r.Eligible = true }, "slug": func(r *targetdraft.OnboardingVerifyResult) { r.Slugs = []string{"x"} },
		"bd": func(r *targetdraft.OnboardingVerifyResult) { r.BindingDigest = "" }, "cp": func(r *targetdraft.OnboardingVerifyResult) { r.ChangedPathsSHA256 = admOther },
		"jd": func(r *targetdraft.OnboardingVerifyResult) { r.JudgedPathsSHA256 = d }, "jdx": func(r *targetdraft.OnboardingVerifyResult) { r.JudgedPathsSHA256 = "" },
		"tc": func(r *targetdraft.OnboardingVerifyResult) { r.TagsCommitsSHA = map[string]string{"alpha": ""} },
	} {
		r := good()
		f(&r)
		if seamConsistent(r, g, []string{"alpha"}, changes, ol) {
			t.Fatalf("%s: accepted", name)
		}
	}
	// An invalid path set of the gate's own parse is never digested to equal anything.
	if seamConsistent(good(), g, []string{"alpha"}, []OnboardingGitChange{{Path: "cli/a"}, {Path: "cli/a"}}, ol) {
		t.Fatal("a duplicate path set was accepted")
	}
	// No judged path in the change (no target of the slug): refused.
	if seamConsistent(good(), g, []string{"alpha"}, []OnboardingGitChange{{Path: "cli/b"}}, ol) {
		t.Fatal("a change without the project's target was accepted")
	}
	if seamConsistent(good(), g, []string{"alpha"}, nil, ol) {
		t.Fatal("an empty path set was accepted")
	}
}

func TestParseOnboardingAdmissionFlag(t *testing.T) {
	t.Parallel()
	if on, err := parseOnboardingAdmissionFlag("", ""); on || err != nil {
		t.Fatalf("empty: %v %v", on, err)
	}
	if on, err := parseOnboardingAdmissionFlag("", "/g"); on || err != nil {
		t.Fatalf("empty with context: %v %v", on, err)
	}
	if on, err := parseOnboardingAdmissionFlag("inprocess", "/g"); !on || err != nil {
		t.Fatalf("inprocess: %v %v", on, err)
	}
	for _, v := range []string{"true", "1", "yes", "InProcess", "inprocess ", "external", "workflow", "on"} {
		if on, err := parseOnboardingAdmissionFlag(v, "/g"); on || err == nil {
			t.Fatalf("%q accepted: %v", v, on)
		}
	}
	// Without the authenticated context it never runs on the unauthenticated trees.
	if on, err := parseOnboardingAdmissionFlag("inprocess", ""); on || err == nil {
		t.Fatalf("no context accepted: %v", on)
	}
}

// No command-line flag or environment variable can carry or enable the
// result; the only run-time lock is the one flag.
func TestOnboardingAdmissionCLIHasNoResultInput(t *testing.T) {
	t.Parallel()
	base, head := trees(t)
	args := []string{"verify", "--base", base.Root, "--head", head.Root, "--now", gateNow.Format("2006-01-02T15:04:05Z")}
	for _, extra := range [][]string{
		{"--verify-pr", "x.json"}, {"--verify-pr-result", "x.json"}, {"--verify-pr-file", "x.json"}, {"--onboarding-admission-result", "x"},
		{"--verify-pr=pass"}, {"--onboarding-admission=true"}, {"--onboarding-admission=external"}, {"--onboarding-admission=inprocess"}, {"--onboarding-admission", "inprocess"},
	} {
		code, out := runCLI(t, append(append([]string{}, args...), extra...)...)
		if code != 2 {
			t.Fatalf("%v: exit %d %s", extra, code, out)
		}
	}
	// The environment is never read for the lock: a getenv that answers
	// everything changes nothing (no verify-pr variable exists).
	var buf, errBuf bytes.Buffer
	code := Main(args, func(k string) string { return "inprocess" }, &buf, &errBuf)
	if code == 2 && strings.Contains(errBuf.String(), "onboarding-admission") {
		t.Fatalf("an environment variable reached the lock: %s", errBuf.String())
	}
}

func TestSeamSubsetAndJudgedDerivation(t *testing.T) {
	t.Parallel()
	if !seamSubset([]string{"a"}, []string{"a", "b"}) || !seamSubset(nil, []string{"a"}) {
		t.Fatal("a subset is refused")
	}
	if seamSubset([]string{"a", "c"}, []string{"a", "b"}) || seamSubset([]string{"a"}, nil) {
		t.Fatal("a non-subset is accepted")
	}
	ol := DefaultLayout().Onboarding
	full := []string{"cli/table", targetPath(ol, "alpha"), recipesRoot + "alpha/recipe.json", recipesRoot + "alpha/evil.sh", recipesRoot + "beta/recipe.json"}
	got := seamJudgedPaths(ol, "alpha", full)
	want := []string{targetPath(ol, "alpha"), recipesRoot + "alpha/recipe.json"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("judged %v want %v", got, want)
	}
	if len(seamJudgedPaths(ol, "alpha", []string{"cli/table"})) != 0 {
		t.Fatal("judged paths invented")
	}
}
