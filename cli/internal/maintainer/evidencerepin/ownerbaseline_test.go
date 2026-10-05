// SPDX-License-Identifier: AGPL-3.0-only

package evidencerepin

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/maintainer/repinbaselines"
)

// mixedTags makes the latest release (and the release line) of example/proj
// ambiguous: two prefixes compete on line 1.2.
var mixedTags = []string{"v1.3.0", "v1.2.5", "v1.2.0", "api/v1.2.9"}

func baselineEntry(f *lineFixture, tag string) repinbaselines.Entry {
	return repinbaselines.Entry{
		Approval: "pr-15", Commit: f.commits[tag], DecidedAt: "2026-10-05T10:00:00Z",
		Reason: "the project publishes v1.x as its stable line", Repository: "example/proj", Tag: tag,
	}
}

func baselineFile(entries ...repinbaselines.Entry) *repinbaselines.File {
	return &repinbaselines.File{Schema: repinbaselines.Schema, Entries: entries}
}

func (f *lineFixture) runWith(t *testing.T, mode string, st *State, opts BuildOptions, citations ...Citation) Worklist {
	t.Helper()
	w, err := BuildWorklistWithOptions(context.Background(), citations, nil, 0, st, f.api, f.blobs, fixedNow(), DefaultMaxAge, nil, mode, opts)
	if err != nil {
		t.Fatalf("BuildWorklistWithOptions: %v", err)
	}
	return w
}

func ambiguousFixture() (*lineFixture, Citation) {
	f := newLineFixture(mixedTags, nil, "v1.3.0")
	f.blob("v1.2.0", "x.md", "same")
	f.blob("v1.3.0", "x.md", "same")
	return f, f.citation("proj-v1-2-0-x", "v1.2.0", "x.md", "same", 1, 1)
}

func setRef(f *lineFixture, tag, commit string) {
	f.api.responses["/repos/example/proj/git/ref/tags/"+strings.ReplaceAll(tag, "/", "%2F")] = struct {
		body   []byte
		status int
	}{[]byte(`{"object":{"sha":"` + commit + `","type":"commit"}}`), 200}
}

func TestOwnerBaselineResolvesAnAmbiguousRepository(t *testing.T) {
	for _, mode := range []string{BaselineModeReleaseLine, BaselineModeLatest} {
		f, c := ambiguousFixture()
		entry := baselineEntry(f, "v1.3.0")
		w := f.runWith(t, mode, newState(), BuildOptions{Baselines: baselineFile(entry), BaselinesDigest: "sha256:abc"}, c)
		got := w.Citations[0]
		if got.Class != ClassFileIdentical || got.Baseline != BaselineOwnerChoice || got.BaselineTag != "v1.3.0" || got.NewCommit != f.commits["v1.3.0"] || got.BaselineEntryDigest != entry.Digest() {
			t.Fatalf("%s: %+v", mode, got)
		}
		if got.Resolution != "" || got.LineStatus != "" || got.PinnedTag != "" {
			t.Fatalf("%s: an owner baseline is not a release line: %+v", mode, got)
		}
		repo := w.Repos[0]
		if repo.Status != repoPendingAmbiguous || repo.OwnerBaseline == nil || repo.OwnerBaseline.Commit != f.commits["v1.3.0"] || repo.OwnerBaseline.EntryDigest != entry.Digest() {
			t.Fatalf("%s: the repository stays ambiguous and records the verified choice: %+v", mode, repo)
		}
		if len(w.Summary.PendingRepositories) != 0 || w.Summary.Pending != 0 || w.Summary.BaselineDistribution[BaselineOwnerChoice] != 1 {
			t.Fatalf("%s: summary %+v", mode, w.Summary)
		}
		if len(w.Summary.OwnerBaselines) != 1 || w.Summary.OwnerBaselines[0].Citations != 1 || w.Summary.OwnerBaselines[0].Repo != "example/proj" {
			t.Fatalf("%s: owner baselines %+v", mode, w.Summary.OwnerBaselines)
		}
		if w.BaselinesDigest != "sha256:abc" {
			t.Fatalf("%s: baselines digest %q", mode, w.BaselinesDigest)
		}
	}
}

func TestWithoutAnEntryTheAmbiguousRepositoryStaysPending(t *testing.T) {
	f, c := ambiguousFixture()
	other := baselineEntry(f, "v1.3.0")
	other.Repository = "example/other"
	for name, file := range map[string]*repinbaselines.File{"no file": nil, "empty file": baselineFile(), "other repository": baselineFile(other)} {
		w := f.runWith(t, BaselineModeReleaseLine, newState(), BuildOptions{Baselines: file}, c)
		got := w.Citations[0]
		if got.Class != ClassPending || got.Baseline != "" || w.Repos[0].OwnerBaseline != nil || !strings.Contains(got.Detail, "PENDING_AMBIGUOUS_LATEST") {
			t.Fatalf("%s: %+v", name, got)
		}
		if len(w.Summary.PendingRepositories) != 1 {
			t.Fatalf("%s: %+v", name, w.Summary)
		}
	}
}

func TestOwnerBaselineLookupIgnoresCase(t *testing.T) {
	f, c := ambiguousFixture()
	entry := baselineEntry(f, "v1.3.0")
	entry.Repository = "Example/Proj"
	w := f.runWith(t, BaselineModeLatest, newState(), BuildOptions{Baselines: baselineFile(entry)}, c)
	if got := w.Citations[0]; got.Class != ClassFileIdentical || got.Baseline != BaselineOwnerChoice {
		t.Fatalf("%+v", got)
	}
}

// A tag that moved, or an entry that records another commit, is refused:
// the citation stays pending and says why.
func TestOwnerBaselineRefusesAMovedTagOrAWrongCommit(t *testing.T) {
	other := strings.Repeat("d", 40)
	cases := map[string]struct {
		mutate func(f *lineFixture, e *repinbaselines.Entry)
		why    string
	}{
		"moved tag":    {func(f *lineFixture, e *repinbaselines.Entry) { setRef(f, "v1.3.0", other) }, "now resolves to"},
		"wrong commit": {func(f *lineFixture, e *repinbaselines.Entry) { e.Commit = other }, "now resolves to"},
		"missing tag": {func(f *lineFixture, e *repinbaselines.Entry) {
			delete(f.api.responses, "/repos/example/proj/git/ref/tags/v1.3.0")
		}, "does not exist"},
		"unreadable tag": {func(f *lineFixture, e *repinbaselines.Entry) {
			f.api.responses["/repos/example/proj/git/ref/tags/v1.3.0"] = struct {
				body   []byte
				status int
			}{[]byte(`{}`), 500}
		}, "could not be resolved"},
	}
	for name, tc := range cases {
		for _, mode := range []string{BaselineModeReleaseLine, BaselineModeLatest} {
			f, c := ambiguousFixture()
			entry := baselineEntry(f, "v1.3.0")
			tc.mutate(f, &entry)
			w := f.runWith(t, mode, newState(), BuildOptions{Baselines: baselineFile(entry)}, c)
			got := w.Citations[0]
			if got.Class != ClassPending || got.Baseline != "" || got.BaselineEntryDigest != "" {
				t.Fatalf("%s/%s: %+v", name, mode, got)
			}
			if w.Repos[0].OwnerBaseline != nil || w.Repos[0].Status != repoPendingAmbiguous || !strings.Contains(w.Repos[0].Detail, "owner baseline v1.3.0 refused") || !strings.Contains(w.Repos[0].Detail, tc.why) {
				t.Fatalf("%s/%s: %+v", name, mode, w.Repos[0])
			}
			if !strings.Contains(got.Detail, "owner baseline v1.3.0 refused") {
				t.Fatalf("%s/%s: the citation must say why: %q", name, mode, got.Detail)
			}
		}
	}
}

func TestOwnerBaselineRefusalNamesTheMovedCommit(t *testing.T) {
	f, c := ambiguousFixture()
	other := strings.Repeat("d", 40)
	setRef(f, "v1.3.0", other)
	w := f.runWith(t, BaselineModeLatest, newState(), BuildOptions{Baselines: baselineFile(baselineEntry(f, "v1.3.0"))}, c)
	if d := w.Citations[0].Detail; !strings.Contains(d, other) || !strings.Contains(d, f.commits["v1.3.0"]) {
		t.Fatalf("both commits belong in the reason: %q", d)
	}
}

func TestOwnerBaselineRateLimitIsNotARefusal(t *testing.T) {
	f, c := ambiguousFixture()
	f.api.responses["/repos/example/proj/git/ref/tags/v1.3.0"] = struct {
		body   []byte
		status int
	}{[]byte(`{"message":"rate limit"}`), 403}
	w := f.runWith(t, BaselineModeLatest, newState(), BuildOptions{Baselines: baselineFile(baselineEntry(f, "v1.3.0"))}, c)
	if w.Repos[0].Status != repoPendingRateLimited || w.Citations[0].Class != ClassPending || w.Repos[0].OwnerBaseline != nil {
		t.Fatalf("%+v %+v", w.Repos[0], w.Citations[0])
	}
}

// The owner's choice only fills in where the citation would be pending: a
// release line proven for the citation is still used.
func TestProvenReleaseLineWinsOverTheOwnerBaseline(t *testing.T) {
	f := newLineFixture([]string{"helm-chart-5.0.0", "v1.30.1", "v1.30.0"}, nil, "v1.30.1")
	f.blob("v1.30.0", "x.md", "same")
	f.blob("v1.30.1", "x.md", "same")
	f.blob("helm-chart-5.0.0", "x.md", "different")
	c := f.citation("proj-v1-30-0-x", "v1.30.0", "x.md", "same", 1, 1)
	entry := baselineEntry(f, "helm-chart-5.0.0")
	w := f.runWith(t, BaselineModeReleaseLine, newState(), BuildOptions{Baselines: baselineFile(entry)}, c)
	got := w.Citations[0]
	if w.Repos[0].Status != repoPendingAmbiguous {
		t.Skipf("fixture is not ambiguous: %+v", w.Repos[0])
	}
	if got.Baseline != BaselineReleaseLine || got.BaselineTag != "v1.30.1" || got.BaselineEntryDigest != "" {
		t.Fatalf("the proven line must win: %+v", got)
	}
}

// A result classified on an owner baseline is not resumed once the choice
// no longer holds, even within --max-age.
func TestOwnerChoiceResultIsNotResumedAfterTheTagMoves(t *testing.T) {
	f, c := ambiguousFixture()
	st := newState()
	opts := BuildOptions{Baselines: baselineFile(baselineEntry(f, "v1.3.0"))}
	if got := f.runWith(t, BaselineModeLatest, st, opts, c).Citations[0]; got.Baseline != BaselineOwnerChoice {
		t.Fatalf("first run: %+v", got)
	}
	setRef(f, "v1.3.0", strings.Repeat("d", 40))
	got := f.runWith(t, BaselineModeLatest, st, opts, c).Citations[0]
	if got.Class != ClassPending || got.Baseline == BaselineOwnerChoice {
		t.Fatalf("a stored owner-choice result must not outlive the choice: %+v", got)
	}
	// And the other direction: the entry is removed from the file.
	f2, c2 := ambiguousFixture()
	st2 := newState()
	f2.runWith(t, BaselineModeLatest, st2, opts, c2)
	if got := f2.runWith(t, BaselineModeLatest, st2, BuildOptions{}, c2).Citations[0]; got.Class != ClassPending {
		t.Fatalf("removing the entry must withdraw the baseline: %+v", got)
	}
}

func TestOwnerBaselineChangedEntryChangesTheRecordedDigest(t *testing.T) {
	f, c := ambiguousFixture()
	st := newState()
	e1 := baselineEntry(f, "v1.3.0")
	first := f.runWith(t, BaselineModeLatest, st, BuildOptions{Baselines: baselineFile(e1)}, c).Citations[0]
	e2 := e1
	e2.Reason = "another reason, same tag and commit"
	second := f.runWith(t, BaselineModeLatest, st, BuildOptions{Baselines: baselineFile(e2)}, c).Citations[0]
	if first.BaselineEntryDigest == second.BaselineEntryDigest || second.BaselineEntryDigest != e2.Digest() {
		t.Fatalf("a changed entry must be recorded with its own digest: %s %s", first.BaselineEntryDigest, second.BaselineEntryDigest)
	}
}

// The HTTP source and the mirror emulation both resolve the chosen tag and
// both refuse a moved one: one function decides.
func TestOwnerBaselineParityMirrorAndHTTP(t *testing.T) {
	fx := loadLatestFixtures(t)["calendar"]
	owner, repo, _ := strings.Cut(fx.Repo, "/")
	rl := false
	for name, fetcher := range map[string]APIFetcher{"http": &httpFixtureFetcher{f: fx}, "mirror": newMirrorAPIFetcher(fixtureMirror{f: fx}, mirrorNotes{})} {
		lookup := func(o, r, tag string) (string, error) {
			return resolveTagCommit(context.Background(), fetcher, o, r, tag)
		}
		good := baselineFile(repinbaselines.Entry{Approval: "pr-1", Commit: fixtureSHA("v3.2.1"), DecidedAt: "2026-10-05T10:00:00Z", Reason: "r", Repository: fx.Repo, Tag: "v3.2.1"})
		res := RepoResolution{Owner: owner, Repo: repo, Status: repoPendingAmbiguous}
		applyOwnerBaseline(&res, good, lookup, &rl)
		if res.OwnerBaseline == nil || res.OwnerBaseline.Commit != fixtureSHA("v3.2.1") {
			t.Fatalf("%s: %+v", name, res)
		}
		bad := baselineFile(repinbaselines.Entry{Approval: "pr-1", Commit: strings.Repeat("a", 40), DecidedAt: "2026-10-05T10:00:00Z", Reason: "r", Repository: fx.Repo, Tag: "v3.2.1"})
		res = RepoResolution{Owner: owner, Repo: repo, Status: repoPendingAmbiguous}
		applyOwnerBaseline(&res, bad, lookup, &rl)
		if res.OwnerBaseline != nil || !strings.Contains(res.Detail, "refused") {
			t.Fatalf("%s: %+v", name, res)
		}
	}
}

func TestRunReadsAndRecordsTheBaselineFile(t *testing.T) {
	f, c := ambiguousFixture()
	entry := baselineEntry(f, "v1.3.0")
	file, err := baselineFile(entry).Marshal()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	baselinesPath, rulesPath, out := dir+"/b.json", dir+"/rules.json", dir+"/w.json"
	if err := os.WriteFile(baselinesPath, file, 0o600); err != nil {
		t.Fatal(err)
	}
	pack := rulePackJSON(t, ruleEntry("proj", c.RuleID, source(c.SourceID, "example", "proj", c.OldCommit, "x.md", c.OldDigest, 1, 1)))
	if err := os.WriteFile(rulesPath, pack, 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr strings.Builder
	args := []string{"repin", "--rules", rulesPath, "--baselines", baselinesPath, "--baseline", "latest", "--output", out}
	if code := Run(context.Background(), args, &stdout, &stderr, f.api, f.blobs, fixedNow(), nil); code != 0 {
		t.Fatalf("code=%d err=%q", code, stderr.String())
	}
	raw, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	var w Worklist
	if err := json.Unmarshal(raw, &w); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(file)
	if w.BaselinesDigest != "sha256:"+hex.EncodeToString(sum[:]) || w.Citations[0].Baseline != BaselineOwnerChoice {
		t.Fatalf("%q %+v", w.BaselinesDigest, w.Citations[0])
	}
	if !strings.Contains(stdout.String(), "owner baseline example/proj -> v1.3.0") {
		t.Fatalf("stdout: %q", stdout.String())
	}
	// A malformed file is refused before anything runs.
	if err := os.WriteFile(baselinesPath, []byte(`{"schema":"x","entries":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	stderr.Reset()
	if code := Run(context.Background(), args, &stdout, &stderr, f.api, f.blobs, fixedNow(), nil); code != 2 || !strings.Contains(stderr.String(), "repin baselines") {
		t.Fatalf("code=%d err=%q", code, stderr.String())
	}
}

// The mirror build reads the same baseline file and records the verified
// choice on the repository.
func TestMirrorWorklistUsesTheOwnerBaseline(t *testing.T) {
	fx := loadLatestFixtures(t)["calendar"]
	owner, repo, _ := strings.Cut(fx.Repo, "/")
	entry := repinbaselines.Entry{Approval: "pr-1", Commit: fixtureSHA("v3.2.1"), DecidedAt: "2026-10-05T10:00:00Z", Reason: "r", Repository: fx.Repo, Tag: "v3.2.1"}
	cite := Citation{RulePack: "p", RuleID: "r1", Project: "proj", SourceID: "s1", Owner: owner, Repo: repo, Path: "x.md", OldCommit: fixtureSHA("v3.2.2"), OldDigest: "sha256:x", StartLine: 1, EndLine: 1}
	wl, _, err := BuildMirrorWorklistWithOptions(context.Background(), []Citation{cite}, nil, 0, fixtureMirror{f: fx}, fixedNow(), DefaultMaxAge, nil, BaselineModeLatest, BuildOptions{Baselines: baselineFile(entry)})
	if err != nil {
		t.Fatal(err)
	}
	if got := wl.Repos[0]; got.Status != repoPendingAmbiguous || got.OwnerBaseline == nil || got.OwnerBaseline.Commit != entry.Commit {
		t.Fatalf("%+v", got)
	}
	wl, _, err = BuildMirrorWorklistWithOptions(context.Background(), []Citation{cite}, nil, 0, fixtureMirror{f: fx}, fixedNow(), DefaultMaxAge, nil, BaselineModeLatest, BuildOptions{})
	if err != nil || wl.Repos[0].OwnerBaseline != nil {
		t.Fatalf("no file, no choice: %v %+v", err, wl.Repos[0])
	}
}
