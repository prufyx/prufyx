// SPDX-License-Identifier: AGPL-3.0-only

package evidencerepin

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/maintainer/sourcecorpus"
)

type apiResponse = struct {
	body   []byte
	status int
}

func releasesPath(page int) string {
	return "/repos/example/proj/releases?per_page=" + strconv.Itoa(releasePageSize) + "&page=" + strconv.Itoa(page)
}

func (f *lineFixture) setPage(page int, status int, body string) {
	f.api.responses[releasesPath(page)] = apiResponse{[]byte(body), status}
}

func (f *lineFixture) runState(t *testing.T, state *State, mode string, citations ...Citation) Worklist {
	t.Helper()
	w, err := BuildWorklistWithBaseline(context.Background(), citations, nil, 0, state, f.api, f.blobs, fixedNow(), DefaultMaxAge, nil, mode)
	if err != nil {
		t.Fatalf("BuildWorklistWithBaseline: %v", err)
	}
	return w
}

// truncatedPages makes every page up to maxReleasePages non-empty, with
// v1.26.0 and v1.25.0 on page 1 and v1.25.1 beyond the scan.
func (f *lineFixture) truncatedPages() {
	for page := 1; page <= maxReleasePages; page++ {
		var rs []map[string]any
		for i := 0; i < releasePageSize; i++ {
			rs = append(rs, map[string]any{"tag_name": fmt.Sprintf("v0.%d.%d", page, i)})
		}
		if page == 1 {
			rs[0] = map[string]any{"tag_name": "v1.26.0"}
			rs[1] = map[string]any{"tag_name": "v1.25.0"}
		}
		raw, _ := json.Marshal(rs)
		f.setPage(page, 200, string(raw))
	}
}

func stamp(d time.Duration) string { return fixedNow()().Add(d).UTC().Format(time.RFC3339) }

func cachedPin(c Citation) (string, PinResolution) {
	triples, pairs := versionHints(c.SourceID, c.RuleID, c.SubjectFrom, c.SubjectTo)
	return pinKey(c.Owner, c.Repo, c.OldCommit, hintSignature(triples, pairs)),
		PinResolution{Owner: c.Owner, Repo: c.Repo, Commit: c.OldCommit, Status: pinFound, Tag: "v1.25.0", Prefix: "v", Line: "1.25", ResolvedAt: stamp(0)}
}

// Finding 1: a cached pin must not let a truncated release scan produce a
// release-line baseline.
func TestLineIgnoresIncompleteListEvenWithCachedPin(t *testing.T) {
	f := newLineFixture([]string{"v1.26.0", "v1.25.1", "v1.25.0"}, nil, "v1.26.0")
	f.truncatedPages()
	pinned := "a\nb\nc"
	f.blob("v1.25.0", "doc.md", pinned)
	f.blob("v1.26.0", "doc.md", "changed")
	c := f.citation("s-v1-25-0", "v1.25.0", "doc.md", pinned, 2, 2)
	st := newState()
	key, pin := cachedPin(c)
	st.Pins[key] = pin
	got := f.runState(t, st, BaselineModeReleaseLine, c).Citations[0]
	if got.Baseline != BaselineLatest || got.Class == ClassNoNewRelease || got.BaselineTag != "v1.26.0" ||
		got.Class != ClassContentChanged || !strings.Contains(got.BaselineNote, "more releases") {
		t.Fatalf("truncated scan must fall back to latest, got %+v", got)
	}
	for _, line := range st.Lines {
		if line.Status != lineUnderivable {
			t.Fatalf("a truncated scan must record the line as underivable: %+v", line)
		}
	}
}

// Finding 3 (m4): without a cached pin, pin() itself refuses a truncated scan.
func TestPinRefusesIncompleteList(t *testing.T) {
	f := newLineFixture([]string{"v1.26.0", "v1.25.0"}, nil, "v1.26.0")
	f.truncatedPages()
	pinned := "x"
	f.blob("v1.25.0", "doc.md", pinned)
	f.blob("v1.26.0", "doc.md", "y")
	c := f.citation("s-v1-25-0", "v1.25.0", "doc.md", pinned, 1, 1)
	st := newState()
	got := f.runState(t, st, BaselineModeReleaseLine, c).Citations[0]
	if got.Baseline != BaselineLatest || !strings.HasPrefix(got.BaselineNote, "release line not derived") || !strings.Contains(got.BaselineNote, "more releases") {
		t.Fatalf("pin must be underivable on a truncated scan: %+v", got)
	}
	for _, pin := range st.Pins {
		if pin.Status != pinUnderivable {
			t.Fatalf("pin recorded as %s on a truncated scan", pin.Status)
		}
	}
	if len(st.Lines) != 0 {
		t.Fatalf("no line may be resolved: %+v", st.Lines)
	}
}

// Finding 2: only an empty page ends the scan.
func TestReleaseScanMissingLaterPageIsPendingNotComplete(t *testing.T) {
	for name, status := range map[string]int{"404": 404, "500": 500} {
		f := newLineFixture([]string{"v1.26.0", "v1.25.0"}, nil, "v1.26.0")
		f.setPage(1, 200, `[{"tag_name":"v1.26.0"},{"tag_name":"v1.25.0"}]`)
		delete(f.api.responses, releasesPath(2))
		if status != 404 {
			f.setPage(2, status, `{}`)
		}
		f.blob("v1.25.0", "doc.md", "x")
		w := f.run(t, BaselineModeReleaseLine, f.citation("s-v1-25-0", "v1.25.0", "doc.md", "x", 1, 1))
		if got := w.Citations[0]; got.Class != ClassPending {
			t.Fatalf("%s on page 2 must leave the citation pending, got %+v", name, got)
		}
	}
	// Unit level: the error is returned, not a complete list.
	f := newLineFixture([]string{"v1.25.0"}, nil, "v1.25.0")
	f.setPage(1, 200, `[{"tag_name":"v1.25.0"}]`)
	delete(f.api.responses, releasesPath(2))
	if list, err := fetchAllReleases(context.Background(), f.api, "example", "proj"); err == nil || list.complete {
		t.Fatalf("expected an error for a missing page 2, got %+v, %v", list, err)
	}
	// A real multi-page list ended by an empty page is complete.
	f.setPage(1, 200, `[{"tag_name":"v1.25.0"}]`)
	f.setPage(2, 200, `[{"tag_name":"v1.25.1"}]`)
	f.setPage(3, 200, `[]`)
	list, err := fetchAllReleases(context.Background(), f.api, "example", "proj")
	if err != nil || !list.complete || len(list.entries) != 2 {
		t.Fatalf("got %+v, %v", list, err)
	}
}

// Finding 3 (m6): one commit carrying tags of two release lines is ambiguous.
func TestPinnedCommitOnTwoReleaseLinesFallsBack(t *testing.T) {
	f := newLineFixture([]string{"v1.26.0", "v1.25.0"}, nil, "v1.26.0")
	f.api.responses["/repos/example/proj/git/ref/tags/v1.26.0"] = apiResponse{[]byte(`{"object":{"sha":"` + f.commits["v1.25.0"] + `","type":"commit"}}`), 200}
	f.blob("v1.25.0", "doc.md", "x")
	c := f.citation("proj-v1-25-0-v1-26-0-doc", "v1.25.0", "doc.md", "x", 1, 1)
	st := newState()
	got := f.runState(t, st, BaselineModeReleaseLine, c).Citations[0]
	if got.Baseline != BaselineLatest || !strings.Contains(got.BaselineNote, "more than one release line") {
		t.Fatalf("expected fallback for two lines on one commit: %+v", got)
	}
	for _, pin := range st.Pins {
		if pin.Status != pinUnderivable {
			t.Fatalf("pin must be underivable: %+v", pin)
		}
	}
}

// Finding 3 (m15): the same version listed twice is one tag; different
// patches of one line on one commit are not.
func TestPinnedCommitSameVersionHandling(t *testing.T) {
	f := newLineFixture([]string{"v1.26.0", "v1.25.0"}, nil, "v1.26.0")
	f.setPage(1, 200, `[{"tag_name":"v1.26.0"},{"tag_name":"v1.25.0"},{"tag_name":"v1.25.0"}]`)
	f.blob("v1.25.0", "doc.md", "x")
	c := f.citation("proj-v1-25-0-doc", "v1.25.0", "doc.md", "x", 1, 1)
	got := f.run(t, BaselineModeReleaseLine, c).Citations[0]
	if got.Baseline != BaselineReleaseLine || got.PinnedTag != "v1.25.0" {
		t.Fatalf("a duplicated listing of one tag must still pin: %+v", got)
	}

	g := newLineFixture([]string{"v1.26.0", "v1.25.1", "v1.25.0"}, nil, "v1.26.0")
	g.api.responses["/repos/example/proj/git/ref/tags/v1.25.1"] = apiResponse{[]byte(`{"object":{"sha":"` + g.commits["v1.25.0"] + `","type":"commit"}}`), 200}
	g.blob("v1.25.0", "doc.md", "x")
	c = g.citation("proj-v1-25-0-v1-25-1-doc", "v1.25.0", "doc.md", "x", 1, 1)
	st := newState()
	got = g.runState(t, st, BaselineModeReleaseLine, c).Citations[0]
	if got.Baseline != BaselineLatest || !strings.Contains(got.BaselineNote, "more than one release tag") {
		t.Fatalf("two patch tags on one commit must be ambiguous: %+v", got)
	}

	if !allSameVersion([]string{"v1.25.0", "v1.25.0"}) || allSameVersion([]string{"v1.25.0", "v1.25.1"}) ||
		allSameVersion([]string{"v1.25.0", "v1.25.0", "v1.25.2"}) || allSameVersion([]string{"v1.25.0", "api/v1.25.0"}) {
		t.Fatal("allSameVersion wrong")
	}
}

// Finding 3 (m16).
func TestLineStillFresh(t *testing.T) {
	now := fixedNow()()
	res := ClassResult{Owner: "example", Repo: "proj", Baseline: BaselineReleaseLine, PinnedTag: "v1.25.0", BaselineLine: "1.25", BaselineTag: "v1.25.3"}
	key := lineKey("example", "proj", "v", "1.25")
	good := LineResolution{Status: lineResolved, Tag: "v1.25.3", ResolvedAt: stamp(-time.Hour)}
	mk := func(l *LineResolution) *State {
		st := newState()
		if l != nil {
			st.Lines[key] = *l
		}
		return st
	}
	if !lineStillFresh(mk(nil), ClassResult{Baseline: BaselineLatest}, now, DefaultMaxAge) {
		t.Fatal("a latest result has no line to expire")
	}
	if !lineStillFresh(mk(&good), res, now, DefaultMaxAge) {
		t.Fatal("fresh matching line must be reusable")
	}
	stale := good
	stale.ResolvedAt = stamp(-2 * DefaultMaxAge)
	other := good
	other.Tag = "v1.25.4"
	bad := good
	bad.Status = lineUnderivable
	for name, st := range map[string]*State{"missing": mk(nil), "stale": mk(&stale), "other tag": mk(&other), "not resolved": mk(&bad)} {
		if lineStillFresh(st, res, now, DefaultMaxAge) {
			t.Errorf("%s line must not allow resuming the result", name)
		}
	}
}

func TestResumeRecomputesWhenLineResolutionExpired(t *testing.T) {
	f := newLineFixture(standardTags, nil, "v1.26.0")
	f.blob("v1.25.0", "doc.md", "x")
	f.blob("v1.25.3", "doc.md", "x")
	c := f.citation("proj-v1-25-0-doc", "v1.25.0", "doc.md", "x", 1, 1)
	st := newState()
	f.runState(t, st, BaselineModeReleaseLine, c)
	key := lineKey("example", "proj", "v", "1.25")
	line := st.Lines[key]
	line.ResolvedAt = stamp(-2 * DefaultMaxAge)
	st.Lines[key] = line
	before := len(f.api.calls)
	w := f.runState(t, st, BaselineModeReleaseLine, c)
	if len(f.api.calls) == before {
		t.Fatal("an expired line resolution must be re-resolved, not resumed")
	}
	if st.Lines[key].ResolvedAt != stamp(0) || len(w.Lines) != 1 || w.Lines[0].Stale {
		t.Fatalf("line must be refreshed: %+v %+v", st.Lines[key], w.Lines)
	}
}

// Finding 3 (m17): a result computed under another mode is recomputed,
// both when fresh and when it would otherwise be reported as stale.
func TestResultFromOtherModeIsRecomputed(t *testing.T) {
	f := newLineFixture(standardTags, nil, "v1.26.0")
	f.blob("v1.25.0", "doc.md", "x")
	f.blob("v1.25.3", "doc.md", "x")
	f.blob("v1.26.0", "doc.md", "y")
	c := f.citation("proj-v1-25-0-doc", "v1.25.0", "doc.md", "x", 1, 1)

	st := newState()
	if got := f.runState(t, st, BaselineModeLatest, c).Citations[0]; got.Baseline != BaselineLatest {
		t.Fatalf("got %+v", got)
	}
	got := f.runState(t, st, BaselineModeRelease(), c).Citations[0]
	if got.Baseline != BaselineReleaseLine || got.BaselineMode != BaselineModeReleaseLine || got.Class != ClassFileIdentical {
		t.Fatalf("a latest result must not be reused under release-line: %+v", got)
	}
	// A result with no recorded mode predates the field and means latest.
	old := st.Results[c.key()]
	old.BaselineMode, old.Baseline = "", ""
	st.Results[c.key()] = old
	if got := f.runState(t, st, BaselineModeReleaseLine, c).Citations[0]; got.Baseline != BaselineReleaseLine {
		t.Fatalf("a mode-less result must not be reused under release-line: %+v", got)
	}

	// Stale branch: a stale result from another mode is not re-emitted as
	// stale when this run cannot recompute it.
	rl := Citation{RulePack: "p", RuleID: "r0", Project: "a", SourceID: "s0", Owner: "aaa", Repo: "rate-limited", Path: "x", OldCommit: commitA, OldDigest: "sha256:x", StartLine: 1, EndLine: 1}
	sc := Citation{RulePack: "p", RuleID: "r1", Project: "a", SourceID: "s1", Owner: "bbb", Repo: "stale-repo", Path: "x", OldCommit: commitA, OldDigest: "sha256:x", StartLine: 1, EndLine: 1}
	old200 := stamp(-200 * time.Hour)
	st2 := newState()
	st2.Repos["bbb/stale-repo"] = RepoResolution{Owner: "bbb", Repo: "stale-repo", Status: repoResolved, CurrentTag: "v1", CurrentCommit: commitA, ResolvedAt: old200}
	staleOrig := ClassResult{
		RulePack: "p", RuleID: "r1", Project: "a", SourceID: "s1", Owner: "bbb", Repo: "stale-repo", Path: "x",
		OldCommit: commitA, NewCommit: commitA, OldStart: 1, OldEnd: 1, Class: ClassNoNewRelease, ClassifiedAt: old200, BaselineMode: BaselineModeLatest, Baseline: BaselineLatest,
	}
	st2.Results[sc.key()] = staleOrig
	api := &fakeAPIFetcher{responses: map[string]apiResponse{"/repos/aaa/rate-limited/releases?per_page=10": {[]byte(`{}`), 403}}}
	w, err := BuildWorklistWithBaseline(context.Background(), []Citation{rl, sc}, nil, 0, st2, api, fakeBlobFetcher{}, fixedNow(), 72*time.Hour, nil, BaselineModeReleaseLine)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range w.Citations {
		if r.Repo == "stale-repo" && (r.Class != ClassPending || r.Stale || r.BaselineMode != BaselineModeReleaseLine) {
			t.Fatalf("a stale result from another mode must be pending, not reused: %+v", r)
		}
	}
	// Same mode is still kept as stale.
	st3 := newState()
	st3.Repos = st2.Repos
	r := staleOrig
	r.BaselineMode = BaselineModeReleaseLine
	st3.Results[sc.key()] = r
	w, err = BuildWorklistWithBaseline(context.Background(), []Citation{rl, sc}, nil, 0, st3, &fakeAPIFetcher{responses: api.responses}, fakeBlobFetcher{}, fixedNow(), 72*time.Hour, nil, BaselineModeReleaseLine)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range w.Citations {
		if r.Repo == "stale-repo" && (!r.Stale || r.Class != ClassNoNewRelease) {
			t.Fatalf("a same-mode stale result is kept as stale: %+v", r)
		}
	}
}

// BaselineModeRelease keeps the call sites readable.
func BaselineModeRelease() string { return BaselineModeReleaseLine }

// Finding 4.
func TestCorpusDigestMismatchRecordsObservedDigestAndSize(t *testing.T) {
	f := newLineFixture(standardTags, nil, "v1.26.0")
	served := "served at the pinned commit"
	f.blob("v1.25.0", "doc.md", served)
	f.blob("v1.25.3", "doc.md", "changed")
	c := f.citation("proj-v1-25-0-doc", "v1.25.0", "doc.md", "what the corpus recorded", 1, 1)
	got := f.run(t, BaselineModeReleaseLine, c).Citations[0]
	size := len(served)
	if got.Class != ClassCorpusDigestMismatch || got.ObservedDigest != sourcecorpus.SHA([]byte(served)) || got.ObservedSize == nil || *got.ObservedSize != size ||
		!strings.Contains(got.Detail, got.ObservedDigest) || !strings.Contains(got.Detail, strconv.Itoa(size)) {
		t.Fatalf("observed digest and size missing: %+v", got)
	}
	raw, _ := json.Marshal(got)
	if !strings.Contains(string(raw), `"observedDigest"`) || !strings.Contains(string(raw), `"observedSize":`+strconv.Itoa(size)) {
		t.Fatalf("not serialised: %s", raw)
	}
	// An empty served file records size 0 rather than dropping it.
	f.blob("v1.25.0", "empty.md", "")
	f.blob("v1.25.3", "empty.md", "changed")
	e := f.run(t, BaselineModeReleaseLine, f.citation("proj-v1-25-0-empty", "v1.25.0", "empty.md", "recorded", 1, 1)).Citations[0]
	if e.ObservedSize == nil || *e.ObservedSize != 0 {
		t.Fatalf("empty file size must be recorded: %+v", e)
	}
}

// Finding 5.
func TestLineStatusPinnedIsLatest(t *testing.T) {
	f := newLineFixture(standardTags, nil, "v1.26.0")
	f.blob("v1.25.0", "doc.md", "x")
	f.blob("v1.25.3", "doc.md", "x")
	end := f.run(t, BaselineModeReleaseLine, f.citation("proj-v1-25-3-doc", "v1.25.3", "doc.md", "x", 1, 1)).Citations[0]
	if end.LineStatus != LineStatusPinnedIsLatest || end.Class != ClassNoNewRelease {
		t.Fatalf("got %+v", end)
	}
	open := f.run(t, BaselineModeReleaseLine, f.citation("proj-v1-25-0-doc", "v1.25.0", "doc.md", "x", 1, 1)).Citations[0]
	if open.LineStatus != LineStatusLaterReleases {
		t.Fatalf("got %+v", open)
	}
	latest := f.run(t, BaselineModeLatest, f.citation("proj-v1-25-3-doc", "v1.25.3", "doc.md", "x", 1, 1)).Citations[0]
	if latest.LineStatus != "" {
		t.Fatalf("latest baseline carries no line status: %+v", latest)
	}
}

type noBaselineResponse struct {
	body   []byte
	status int
}

func noBaselineFetcher(owner, repo string, releases, tags noBaselineResponse) *fakeAPIFetcher {
	f := &fakeAPIFetcher{responses: map[string]struct {
		body   []byte
		status int
	}{}}
	f.responses["/repos/"+owner+"/"+repo+"/releases?per_page=10"] = struct {
		body   []byte
		status int
	}(releases)
	f.responses["/repos/"+owner+"/"+repo+"/tags?per_page=30"] = struct {
		body   []byte
		status int
	}(tags)
	return f
}

func noBaselineCitations() []Citation {
	return []Citation{
		{RulePack: "p", RuleID: "r1", Project: "site", SourceID: "s1", Owner: "example", Repo: "website", Path: "a.md", OldCommit: commitA, OldDigest: "sha256:x", StartLine: 1, EndLine: 1},
	}
}

func TestResolveCurrentCommitEmptyReleasesAndTagsIsDefinitive(t *testing.T) {
	f := noBaselineFetcher("example", "website", noBaselineResponse{[]byte(`[]`), 200}, noBaselineResponse{[]byte(`[]`), 200})
	_, _, _, err := ResolveCurrentCommit(context.Background(), f, "example", "website")
	if !errors.Is(err, errNoReleaseBaseline) {
		t.Fatalf("expected the definitive no-baseline error, got %v", err)
	}
}

func TestNoReleaseBaselineIsTerminalAndNotBatchEligible(t *testing.T) {
	f := noBaselineFetcher("example", "website", noBaselineResponse{[]byte(`[]`), 200}, noBaselineResponse{[]byte(`[]`), 200})
	for _, mode := range []string{BaselineModeLatest, BaselineModeReleaseLine} {
		state := newState()
		wl, err := BuildWorklistWithBaseline(context.Background(), noBaselineCitations(), nil, 0, state, f, fakeBlobFetcher{}, fixedNow(), DefaultMaxAge, nil, mode)
		if err != nil {
			t.Fatal(err)
		}
		got := wl.Citations[0]
		if got.Class != ClassNoReleaseBaseline || got.ClassifiedAt == "" || got.Detail == "" {
			t.Fatalf("%s: expected a classified NO_RELEASE_BASELINE, got %+v", mode, got)
		}
		if wl.Summary.Pending != 0 || wl.Summary.Distribution[ClassNoReleaseBaseline] != 1 {
			t.Fatalf("%s: must not count as pending: %+v", mode, wl.Summary)
		}
		if r := wl.Repos[0]; r.Status != repoNoReleasesOrTags || r.Determination == nil || !r.Determination.definitive() {
			t.Fatalf("%s: repo resolution must carry the determination: %+v", mode, r)
		}
		if v := wl.Rules[0]; v.BatchEligible || v.PendingCitation || v.WorstClass != ClassNoReleaseBaseline {
			t.Fatalf("%s: rule must be neither batch-eligible nor pending: %+v", mode, v)
		}
	}
}

// Anything short of two successful empty lists must stay PENDING.
func TestNoBaselineNotProvenStaysPending(t *testing.T) {
	empty := noBaselineResponse{[]byte(`[]`), 200}
	cases := map[string][2]noBaselineResponse{
		"tags rate limited":         {empty, {nil, 429}},
		"tags forbidden":            {empty, {nil, 403}},
		"tags server error":         {empty, {nil, 500}},
		"tags missing":              {empty, {nil, 404}},
		"tags not an array":         {empty, {[]byte(`{}`), 200}},
		"tags null":                 {empty, {[]byte(`null`), 200}},
		"tags body empty":           {empty, {nil, 200}},
		"releases missing":          {{nil, 404}, empty},
		"releases rate limited":     {{nil, 429}, empty},
		"releases server error":     {{nil, 502}, empty},
		"releases not an array":     {{[]byte(`{"message":"x"}`), 200}, empty},
		"releases null":             {{[]byte(`null`), 200}, empty},
		"only prereleases listed":   {{[]byte(`[{"tag_name":"v1-rc1","prerelease":true}]`), 200}, empty},
		"only drafts listed":        {{[]byte(`[{"tag_name":"v1.0.0","draft":true}]`), 200}, empty},
		"tag listed but unresolved": {empty, {[]byte(`[{"name":"v1.0.0"}]`), 200}},
	}
	for name, c := range cases {
		f := noBaselineFetcher("example", "website", c[0], c[1])
		wl, err := BuildWorklist(context.Background(), noBaselineCitations(), nil, 0, newState(), f, fakeBlobFetcher{}, fixedNow(), DefaultMaxAge, nil)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if wl.Citations[0].Class != ClassPending || wl.Summary.Pending != 1 || wl.Rules[0].BatchEligible {
			t.Fatalf("%s: must stay PENDING, got %+v", name, wl.Citations[0])
		}
		if wl.Repos[0].Determination != nil {
			t.Fatalf("%s: no determination may be recorded: %+v", name, wl.Repos[0])
		}
	}
}

// A NO_RELEASE_BASELINE result is never resumed from the state file: when
// the repository later publishes a release the citation is classified
// against it.
func TestNoReleaseBaselineIsNotResumedOnceReleaseAppears(t *testing.T) {
	state := newState()
	none := noBaselineFetcher("example", "website", noBaselineResponse{[]byte(`[]`), 200}, noBaselineResponse{[]byte(`[]`), 200})
	if _, err := BuildWorklist(context.Background(), noBaselineCitations(), nil, 0, state, none, fakeBlobFetcher{}, fixedNow(), DefaultMaxAge, nil); err != nil {
		t.Fatal(err)
	}
	released := &fakeAPIFetcher{responses: map[string]struct {
		body   []byte
		status int
	}{
		"/repos/example/website/releases?per_page=10": {[]byte(`[{"tag_name":"v1.0.0"}]`), 200},
		"/repos/example/website/git/ref/tags/v1.0.0":  {[]byte(`{"object":{"sha":"` + commitA + `","type":"commit"}}`), 200},
	}}
	wl, err := BuildWorklist(context.Background(), noBaselineCitations(), nil, 0, state, released, fakeBlobFetcher{}, fixedNow(), DefaultMaxAge, nil)
	if err != nil {
		t.Fatal(err)
	}
	if wl.Citations[0].Class != ClassNoNewRelease {
		t.Fatalf("expected the new release to be used, got %+v", wl.Citations[0])
	}
}
