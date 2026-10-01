// SPDX-License-Identifier: AGPL-3.0-only

package evidencerepin

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/maintainer/sourcecapture"
	"github.com/prufyx/prufyx/cli/internal/maintainer/sourcecorpus"
)

func TestParseStrictTag(t *testing.T) {
	good := map[string]tagVersion{
		"v1.2.3":               {"v", 1, 2, 3},
		"1.2.3":                {"", 1, 2, 3},
		"release-1.2.3":        {"release-", 1, 2, 3},
		"release-v1.2.3":       {"release-v", 1, 2, 3},
		"api/v1.2.3":           {"api/v", 1, 2, 3},
		"knative-v1.23.0":      {"knative-v", 1, 23, 0},
		"mariadb-13.0.2":       {"mariadb-", 13, 0, 2},
		"kustomize/v5.4.1":     {"kustomize/v", 5, 4, 1},
		"k8s.io-release_1.0.9": {"k8s.io-release_", 1, 0, 9},
	}
	for tag, want := range good {
		got, ok := parseStrictTag(tag)
		if !ok || got != want {
			t.Errorf("parseStrictTag(%q) = %+v, %v; want %+v", tag, got, ok, want)
		}
	}
	for _, tag := range []string{
		"", "v1.2", "v1", "v1.2.3-rc1", "v1.2.3-beta.2", "v1.2.3+build", "v1.2.3.4", "v1.2.3-ee",
		"v01.2.3", "v1.02.3", "v1.2.03", "2024.10.15", "V1.2.3", "r1.2.3", "go1.2.3", "foo.v1.2.3", "v1.2.3 ",
		"release-1.2.3-hotfix", "1000.1.1",
	} {
		if got, ok := parseStrictTag(tag); ok {
			t.Errorf("parseStrictTag(%q) accepted as %+v; must not derive a line", tag, got)
		}
	}
}

func TestVersionHints(t *testing.T) {
	triples, pairs := versionHints("argo-workflows-v3-5-15-legacy-server-flag", "rule.2-55-1-to-3-14-0", "", "4.1.3")
	wantTriples := [][3]int{{2, 55, 1}, {3, 5, 15}, {3, 14, 0}, {4, 1, 3}}
	if !reflect.DeepEqual(triples, wantTriples) {
		t.Fatalf("triples = %v, want %v", triples, wantTriples)
	}
	hasPair := func(a, b int) bool {
		for _, p := range pairs {
			if p == [2]int{a, b} {
				return true
			}
		}
		return false
	}
	if !hasPair(3, 5) || !hasPair(4, 1) {
		t.Fatalf("expected pairs 3.5 and 4.1 in %v", pairs)
	}
	// Out-of-range components are dropped rather than trusted.
	triples, pairs = versionHints("2024-10-15", "source-8825a6b7f8c9-5")
	for _, tr := range triples {
		if tr[0] > maxVersionComponent {
			t.Fatalf("out-of-range triple kept: %v", tr)
		}
	}
	_ = pairs
}

func rel(tag string, prerelease bool) releaseEntry {
	return releaseEntry{Tag: tag, Prerelease: prerelease}
}

func TestNewestOnLine(t *testing.T) {
	pinned, _ := parseStrictTag("v1.25.0")
	entries := []releaseEntry{
		rel("v1.26.0", false), rel("v1.25.3", false), rel("v1.25.4-rc.1", true), rel("v1.25.2", false),
		{Tag: "v1.25.9", Draft: true}, rel("v1.25.5", true), rel("v1.25.0", false), rel("v1.250.0", false), rel("v1.2.9", false),
	}
	tag, version, reason := newestOnLine(pinned, entries)
	if reason != "" || tag != "v1.25.3" || version.Patch != 3 {
		t.Fatalf("got tag=%q patch=%d reason=%q; want v1.25.3 (pre-releases and drafts excluded)", tag, version.Patch, reason)
	}

	cases := map[string][]releaseEntry{
		"unrecognised suffix on the line":  {rel("v1.25.0", false), rel("v1.25.2-hotfix", false)},
		"four-component tag on the line":   {rel("v1.25.0", false), rel("v1.25.2.1", false)},
		"same line under another prefix":   {rel("v1.25.0", false), rel("api/v1.25.1", false)},
		"alias without v":                  {rel("v1.25.0", false), rel("1.25.1", false)},
		"pinned tag is not a release":      {rel("v1.25.1", false)},
		"pinned tag is only a pre-release": {rel("v1.25.0", true), rel("v1.25.1", false)},
		"pinned tag is only a draft":       {{Tag: "v1.25.0", Draft: true}, rel("v1.25.1", false)},
		"no releases":                      nil,
	}
	for name, entries := range cases {
		if tag, _, reason := newestOnLine(pinned, entries); reason == "" {
			t.Errorf("%s: derived %q; must be ambiguous", name, tag)
		}
	}

	// A different numeric line with a similar string prefix is not on the line.
	if onLineLoosely("v1.250.0", "v", 1, 25) {
		t.Fatal("v1.250.0 must not be treated as on line 1.25")
	}
}

// lineFixture builds a fake GitHub API plus blob store for one repository
// with the shape of a typical pinned pair: citations pinned at v1.25.0,
// patch releases v1.25.1..v1.25.3 on the same line, and a newer v1.26.0.
type lineFixture struct {
	api     *fakeAPIFetcher
	blobs   fakeBlobFetcher
	commits map[string]string
}

func commitFor(name string) string {
	h := fmt.Sprintf("%x", sha1Sum(name))
	return h
}

func sha1Sum(s string) [20]byte {
	// A deterministic 40-hex commit per name without importing crypto in
	// every test: reuse sourcecorpus.SHA and trim.
	sum := sourcecorpus.SHA([]byte(s))
	var out [20]byte
	hexPart := strings.TrimPrefix(sum, "sha256:")[:40]
	for i := 0; i < 20; i++ {
		fmt.Sscanf(hexPart[2*i:2*i+2], "%02x", &out[i])
	}
	return out
}

func newLineFixture(tags []string, prereleases map[string]bool, latestTag string) *lineFixture {
	f := &lineFixture{
		api: &fakeAPIFetcher{responses: map[string]struct {
			body   []byte
			status int
		}{}},
		blobs:   fakeBlobFetcher{},
		commits: map[string]string{},
	}
	var releases []map[string]any
	for _, tag := range tags {
		commit := commitFor("example/proj@" + tag)
		f.commits[tag] = commit
		releases = append(releases, map[string]any{"tag_name": tag, "draft": false, "prerelease": prereleases[tag]})
		f.api.responses["/repos/example/proj/git/ref/tags/"+strings.ReplaceAll(tag, "/", "%2F")] = struct {
			body   []byte
			status int
		}{[]byte(`{"object":{"sha":"` + commit + `","type":"commit"}}`), 200}
	}
	raw, _ := json.Marshal(releases)
	f.api.responses["/repos/example/proj/releases?per_page="+strconv.Itoa(releasePageSize)+"&page=1"] = struct {
		body   []byte
		status int
	}{raw, 200}
	latest, _ := json.Marshal([]map[string]any{{"tag_name": latestTag, "draft": false, "prerelease": false}})
	f.api.responses["/repos/example/proj/releases?per_page=10"] = struct {
		body   []byte
		status int
	}{latest, 200}
	return f
}

func (f *lineFixture) blob(tag, path string, body string) {
	f.blobs["/example/proj/"+f.commits[tag]+"/"+path] = sourcecapture.FetchResult{Kind: "HTTP_200", StatusCode: 200, Body: []byte(body)}
}

func (f *lineFixture) citation(sourceID, tag, path, pinnedBody string, start, end int) Citation {
	return Citation{
		RulePack: "p", RuleID: "proj.rule-1-25-to-1-26", Project: "proj", SourceID: sourceID,
		Owner: "example", Repo: "proj", Path: path, OldCommit: f.commits[tag], OldDigest: sourcecorpus.SHA([]byte(pinnedBody)),
		StartLine: start, EndLine: end,
	}
}

func (f *lineFixture) run(t *testing.T, mode string, citations ...Citation) Worklist {
	t.Helper()
	worklist, err := BuildWorklistWithBaseline(context.Background(), citations, nil, 0, newState(), f.api, f.blobs, fixedNow(), DefaultMaxAge, nil, mode)
	if err != nil {
		t.Fatalf("BuildWorklistWithBaseline: %v", err)
	}
	return worklist
}

func byClass(w Worklist, sourceID string) ClassResult {
	for _, c := range w.Citations {
		if c.SourceID == sourceID {
			return c
		}
	}
	return ClassResult{}
}

var standardTags = []string{"v1.26.0", "v1.25.3", "v1.25.2", "v1.25.1", "v1.25.0", "v1.24.9"}

func TestReleaseLineUnchangedOnLineChangedOnLatest(t *testing.T) {
	f := newLineFixture(standardTags, nil, "v1.26.0")
	pinned := "a\ncited line\nc"
	f.blob("v1.25.0", "doc.md", pinned)
	f.blob("v1.25.3", "doc.md", pinned)            // same line: file identical
	f.blob("v1.26.0", "doc.md", "a\nREWRITTEN\nc") // newest line: changed
	f.blob("v1.25.0", "span.md", "a\ncited line\nc\nd")
	f.blob("v1.25.3", "span.md", "a\ncited line\nc\nd\nappended on the line")
	f.blob("v1.26.0", "span.md", "gone entirely")
	citations := []Citation{
		f.citation("proj-v1-25-0-doc", "v1.25.0", "doc.md", pinned, 2, 2),
		f.citation("proj-v1-25-0-span", "v1.25.0", "span.md", "a\ncited line\nc\nd", 2, 2),
	}

	line := f.run(t, BaselineModeReleaseLine, citations...)
	doc := byClass(line, "proj-v1-25-0-doc")
	if doc.Class != ClassFileIdentical || doc.Baseline != BaselineReleaseLine || doc.BaselineLine != "1.25" ||
		doc.PinnedTag != "v1.25.0" || doc.BaselineTag != "v1.25.3" || doc.NewCommit != f.commits["v1.25.3"] || doc.BaselineMode != BaselineModeReleaseLine {
		t.Fatalf("unexpected release-line result: %+v", doc)
	}
	span := byClass(line, "proj-v1-25-0-span")
	if span.Class != ClassSpanIdentical || span.Baseline != BaselineReleaseLine {
		t.Fatalf("expected SPAN_IDENTICAL on the line, got %+v", span)
	}
	if len(line.Lines) != 1 || line.Lines[0].Line != "1.25" || line.Lines[0].Tag != "v1.25.3" || line.Lines[0].Status != lineResolved {
		t.Fatalf("expected one resolved line record, got %+v", line.Lines)
	}
	if line.Scope.Baseline != BaselineModeReleaseLine || line.Summary.BaselineDistribution[BaselineReleaseLine] != 2 {
		t.Fatalf("scope/summary baseline not recorded: %+v %+v", line.Scope, line.Summary)
	}
	if !line.Rules[0].BatchEligible {
		t.Fatalf("a rule whose citations are unchanged on their line must be batch-eligible: %+v", line.Rules)
	}

	latest := f.run(t, BaselineModeLatest, citations...)
	for _, id := range []string{"proj-v1-25-0-doc", "proj-v1-25-0-span"} {
		got := byClass(latest, id)
		if got.Class != ClassContentChanged || got.Baseline != BaselineLatest || got.BaselineTag != "v1.26.0" {
			t.Fatalf("latest baseline must keep reporting the newest release: %+v", got)
		}
	}
	if latest.Rules[0].BatchEligible {
		t.Fatal("latest baseline must be unchanged by this feature")
	}
}

func TestReleaseLineChangedOnSameLineStaysContentChanged(t *testing.T) {
	f := newLineFixture(standardTags, nil, "v1.26.0")
	pinned := "a\ncited line\nc"
	f.blob("v1.25.0", "doc.md", pinned)
	f.blob("v1.25.3", "doc.md", "a\nerratum applied in a patch\nc") // changed on the line
	f.blob("v1.26.0", "doc.md", pinned)                             // identical on latest: must not mask it
	w := f.run(t, BaselineModeReleaseLine, f.citation("proj-v1-25-0-doc", "v1.25.0", "doc.md", pinned, 2, 2))
	got := byClass(w, "proj-v1-25-0-doc")
	if got.Class != ClassContentChanged || got.Baseline != BaselineReleaseLine || got.BaselineTag != "v1.25.3" {
		t.Fatalf("a change on the same line must classify CONTENT_CHANGED against the line: %+v", got)
	}
	if w.Rules[0].BatchEligible {
		t.Fatal("a rule with a changed citation must not be batch-eligible")
	}
}

func TestReleaseLinePinnedAtLineNewestIsNoNewRelease(t *testing.T) {
	f := newLineFixture(standardTags, nil, "v1.26.0")
	w := f.run(t, BaselineModeReleaseLine, f.citation("proj-v1-25-3-doc", "v1.25.3", "doc.md", "x", 1, 1))
	got := byClass(w, "proj-v1-25-3-doc")
	if got.Class != ClassNoNewRelease || got.Baseline != BaselineReleaseLine || got.BaselineTag != "v1.25.3" {
		t.Fatalf("got %+v", got)
	}
}

func TestReleaseLineFallsBackWhenLineIsNotProvable(t *testing.T) {
	pinned := "a\ncited\nc"
	for name, build := range map[string]func() (*lineFixture, Citation){
		"source id names no version": func() (*lineFixture, Citation) {
			f := newLineFixture(standardTags, nil, "v1.26.0")
			f.blob("v1.25.0", "doc.md", pinned)
			f.blob("v1.26.0", "doc.md", "changed")
			c := f.citation("source-0123abcd-7", "v1.25.0", "doc.md", pinned, 2, 2)
			c.RuleID = "proj.rule-without-versions"
			return f, c
		},
		"hint names a tag at a different commit": func() (*lineFixture, Citation) {
			f := newLineFixture(standardTags, nil, "v1.26.0")
			f.blob("v1.26.0", "doc.md", "changed")
			c := f.citation("proj-v1-25-2-doc", "v1.25.0", "doc.md", pinned, 2, 2)
			c.RuleID = "proj.rule" // the id's own hint also names 1.25.2, not the pinned v1.25.0
			c.SourceID = "proj-v1-24-1-doc"
			c.OldCommit = commitFor("a commit that is no release")
			f.blobs["/example/proj/"+c.OldCommit+"/doc.md"] = sourcecapture.FetchResult{Kind: "HTTP_200", StatusCode: 200, Body: []byte(pinned)}
			return f, c
		},
		"line has an unrecognised release tag": func() (*lineFixture, Citation) {
			f := newLineFixture(append([]string{"v1.25.4-hotfix"}, standardTags...), nil, "v1.26.0")
			f.blob("v1.25.0", "doc.md", pinned)
			f.blob("v1.26.0", "doc.md", "changed")
			return f, f.citation("proj-v1-25-0-doc", "v1.25.0", "doc.md", pinned, 2, 2)
		},
	} {
		f, citation := build()
		w := f.run(t, BaselineModeReleaseLine, citation)
		got := w.Citations[0]
		if got.Baseline != BaselineLatest || got.BaselineNote == "" || got.BaselineTag != "v1.26.0" || got.Class != ClassContentChanged {
			t.Errorf("%s: expected an annotated fall back to the latest baseline, got %+v", name, got)
		}
		if got.BaselineMode != BaselineModeReleaseLine || len(w.Lines) != 0 {
			t.Errorf("%s: mode/lines wrong: %+v %+v", name, got, w.Lines)
		}
	}
}

func TestReleaseLinePrereleaseOnlyLaterPatchIsIgnored(t *testing.T) {
	f := newLineFixture([]string{"v1.26.0", "v1.25.4-rc.1", "v1.25.0"}, map[string]bool{"v1.25.4-rc.1": true}, "v1.26.0")
	f.blob("v1.25.0", "doc.md", "x")
	w := f.run(t, BaselineModeReleaseLine, f.citation("proj-v1-25-0-doc", "v1.25.0", "doc.md", "x", 1, 1))
	got := w.Citations[0]
	if got.Class != ClassNoNewRelease || got.Baseline != BaselineReleaseLine || got.BaselineTag != "v1.25.0" {
		t.Fatalf("a pre-release must not become the line baseline: %+v", got)
	}
}

func TestReleaseLineMonorepoAndReleasePrefixes(t *testing.T) {
	for _, tags := range [][]string{
		{"api/v1.3.0", "api/v1.2.5", "api/v1.2.0"},
		{"release-1.3.0", "release-1.2.5", "release-1.2.0"},
		{"release-v1.3.0", "release-v1.2.5", "release-v1.2.0"},
		{"1.3.0", "1.2.5", "1.2.0"},
	} {
		f := newLineFixture(tags, nil, tags[0])
		pinnedTag := tags[2]
		f.blob(pinnedTag, "x.md", "same")
		f.blob(tags[1], "x.md", "same")
		w := f.run(t, BaselineModeReleaseLine, f.citation("proj-v1-2-0-x", pinnedTag, "x.md", "same", 1, 1))
		got := w.Citations[0]
		if got.Baseline != BaselineReleaseLine || got.BaselineTag != tags[1] || got.PinnedTag != pinnedTag || got.Class != ClassFileIdentical {
			t.Fatalf("tags %v: got %+v", tags, got)
		}
	}
}

func TestReleaseLineMultiplePrefixesOnSameLineFallBack(t *testing.T) {
	f := newLineFixture([]string{"v1.3.0", "v1.2.5", "v1.2.0", "api/v1.2.9"}, nil, "v1.3.0")
	f.blob("v1.2.0", "x.md", "same")
	f.blob("v1.3.0", "x.md", "different")
	w := f.run(t, BaselineModeReleaseLine, f.citation("proj-v1-2-0-x", "v1.2.0", "x.md", "same", 1, 1))
	if got := w.Citations[0]; got.Baseline != BaselineLatest || got.Class != ClassContentChanged {
		t.Fatalf("a line released under two prefixes is ambiguous and must fall back: %+v", got)
	}
}

func TestReleaseLineRateLimitedLeavesCitationPending(t *testing.T) {
	f := newLineFixture(standardTags, nil, "v1.26.0")
	f.api.responses["/repos/example/proj/releases?per_page="+strconv.Itoa(releasePageSize)+"&page=1"] = struct {
		body   []byte
		status int
	}{[]byte(`{"message":"rate limit"}`), 403}
	f.blob("v1.25.0", "doc.md", "x")
	w := f.run(t, BaselineModeReleaseLine, f.citation("proj-v1-25-0-doc", "v1.25.0", "doc.md", "x", 1, 1))
	if got := w.Citations[0]; got.Class != ClassPending {
		t.Fatalf("an undecidable baseline must stay PENDING, never silently use latest: %+v", got)
	}
}

func TestReleaseLineTagFallbackRepoKeepsLatestAndMarker(t *testing.T) {
	api := &fakeAPIFetcher{responses: map[string]struct {
		body   []byte
		status int
	}{
		"/repos/example/proj/releases?per_page=10": {[]byte(`[]`), 200},
		"/repos/example/proj/tags?per_page=30":     {[]byte(`[{"name":"v1.0.0"}]`), 200},
		"/repos/example/proj/git/ref/tags/v1.0.0":  {[]byte(`{"object":{"sha":"` + commitA + `","type":"commit"}}`), 200},
	}}
	citation := Citation{RulePack: "p", RuleID: "r", Project: "proj", SourceID: "proj-v1-0-0", Owner: "example", Repo: "proj", Path: "x", OldCommit: commitA, OldDigest: "sha256:x", StartLine: 1, EndLine: 1}
	w, err := BuildWorklistWithBaseline(context.Background(), []Citation{citation}, nil, 0, newState(), api, fakeBlobFetcher{}, fixedNow(), DefaultMaxAge, nil, BaselineModeReleaseLine)
	if err != nil {
		t.Fatal(err)
	}
	got := w.Citations[0]
	if got.Baseline != BaselineLatest || got.Resolution != resolutionTagFallback || got.BaselineNote == "" {
		t.Fatalf("tag-fallback repositories keep the latest baseline and the marker: %+v", got)
	}
	for _, call := range api.calls {
		if strings.Contains(call, "&page=") {
			t.Fatalf("a no-release repository must not be scanned for lines: %v", api.calls)
		}
	}
}

func TestReleaseLineStateResumeAvoidsRepeatedAPICalls(t *testing.T) {
	f := newLineFixture(standardTags, nil, "v1.26.0")
	f.blob("v1.25.0", "doc.md", "x")
	f.blob("v1.25.3", "doc.md", "x")
	citation := f.citation("proj-v1-25-0-doc", "v1.25.0", "doc.md", "x", 1, 1)
	state := newState()
	if _, err := BuildWorklistWithBaseline(context.Background(), []Citation{citation}, nil, 0, state, f.api, f.blobs, fixedNow(), DefaultMaxAge, nil, BaselineModeReleaseLine); err != nil {
		t.Fatal(err)
	}
	first := len(f.api.calls)
	// A different mode must not reuse a result computed under another mode.
	w, err := BuildWorklistWithBaseline(context.Background(), []Citation{citation}, nil, 0, state, f.api, f.blobs, fixedNow(), DefaultMaxAge, nil, BaselineModeLatest)
	if err != nil {
		t.Fatal(err)
	}
	if got := w.Citations[0]; got.Baseline != BaselineLatest || got.BaselineMode != BaselineModeLatest {
		t.Fatalf("mode switch must recompute: %+v", got)
	}
	_ = first
	// Same mode again resumes without reclassifying.
	state2 := newState()
	state2.Repos = state.Repos
	state2.Pins, state2.Lines = state.Pins, state.Lines
	before := len(f.api.calls)
	w, err = BuildWorklistWithBaseline(context.Background(), []Citation{citation}, nil, 0, state2, f.api, f.blobs, fixedNow(), DefaultMaxAge, nil, BaselineModeReleaseLine)
	if err != nil {
		t.Fatal(err)
	}
	if len(f.api.calls) != before {
		t.Fatalf("fresh pins and lines must be reused without API calls, made %d more", len(f.api.calls)-before)
	}
	if got := w.Citations[0]; got.Baseline != BaselineReleaseLine || got.BaselineTag != "v1.25.3" {
		t.Fatalf("got %+v", got)
	}
}

func TestLineBaselineConsistent(t *testing.T) {
	if !LineBaselineConsistent("v1.25.0", "v1.25.3", "1.25") || !LineBaselineConsistent("api/v1.2.0", "api/v1.2.0", "1.2") {
		t.Fatal("expected consistent")
	}
	for _, c := range [][3]string{
		{"v1.25.0", "v1.26.0", "1.25"}, {"v1.25.3", "v1.25.0", "1.25"}, {"v1.25.0", "1.25.3", "1.25"},
		{"v1.25.0", "v1.25.3-rc1", "1.25"}, {"v1.25.0", "v1.25.3", "1.26"}, {"", "v1.25.3", "1.25"},
	} {
		if LineBaselineConsistent(c[0], c[1], c[2]) {
			t.Errorf("%v must be inconsistent", c)
		}
	}
}

func TestLoadCitationsCarriesSubjectVersionsAsHints(t *testing.T) {
	entry := ruleEntry("proj", "proj.rule", source("proj-src", "example", "proj", commitA, "VERSION", "sha256:x", 1, 1))
	entry["rule"].(map[string]any)["subject"] = map[string]any{"from": "1.24.0", "to": "1.25.0"}
	citations, err := LoadCitations("rules.json", rulePackJSON(t, entry))
	if err != nil || len(citations) != 1 || citations[0].SubjectFrom != "1.24.0" || citations[0].SubjectTo != "1.25.0" {
		t.Fatalf("got %+v, %v", citations, err)
	}
}

func TestLoadStateV1KeepsReposDropsResults(t *testing.T) {
	path := t.TempDir() + "/state.json"
	raw := `{"schema":"prufyx.io/evidence-repin-state/v1","repos":{"a/b":{"owner":"a","repo":"b","status":"RESOLVED"}},"results":{"k":{"class":"FILE_IDENTICAL"}}}`
	if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	state, err := LoadState(path)
	if err != nil {
		t.Fatal(err)
	}
	if state.Schema != StateSchema || len(state.Repos) != 1 || len(state.Results) != 0 || state.Pins == nil || state.Lines == nil {
		t.Fatalf("unexpected migrated state: %+v", state)
	}
}

func TestRunRejectsUnknownBaseline(t *testing.T) {
	var out, errOut strings.Builder
	code := Run(context.Background(), []string{"repin", "--output", t.TempDir() + "/w.json", "--baseline", "newest"}, &out, &errOut, &fakeAPIFetcher{}, fakeBlobFetcher{}, fixedNow(), nil)
	if code != 2 || !strings.Contains(errOut.String(), "--baseline") {
		t.Fatalf("code=%d err=%q", code, errOut.String())
	}
}
