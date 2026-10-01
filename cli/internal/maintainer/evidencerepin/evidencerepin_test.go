// SPDX-License-Identifier: AGPL-3.0-only

package evidencerepin

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/maintainer/sourcecapture"
	"github.com/prufyx/prufyx/cli/internal/maintainer/sourcecorpus"
)

func fixedNow() func() time.Time {
	return func() time.Time { return time.Date(2026, 9, 20, 12, 0, 0, 0, time.UTC) }
}

func rulePackJSON(t *testing.T, entries ...map[string]any) []byte {
	t.Helper()
	raw, err := json.Marshal(map[string]any{
		"schema":   "prufyx.io/rule-pack/v1",
		"revision": "test",
		"entries":  entries,
	})
	if err != nil {
		t.Fatalf("marshal fixture: %v", err)
	}
	return raw
}

func ruleEntry(project, ruleID string, sources ...map[string]any) map[string]any {
	return map[string]any{
		"project": project,
		"rule": map[string]any{
			"id": ruleID,
			"evidence": map[string]any{
				"reviewedAt": "2026-09-12T10:00:00Z",
				"validUntil": "2026-12-11T10:00:00Z",
				"state":      "active",
				"sources":    sources,
			},
		},
	}
}

func source(id, owner, repo, commit, path, digest string, start, end int) map[string]any {
	return map[string]any{
		"id":            id,
		"url":           "https://github.com/" + owner + "/" + repo + "/blob/" + commit + "/" + path,
		"revision":      commit,
		"contentDigest": digest,
		"startLine":     start,
		"endLine":       end,
	}
}

const commitA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1"
const commitB = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb2"

func TestLoadCitations(t *testing.T) {
	digest := sourcecorpus.SHA([]byte("line1\nline2"))
	raw := rulePackJSON(t, ruleEntry("argo-cd", "argo-cd.rule-1",
		source("argo-cd-src", "argoproj", "argo-cd", commitA, "VERSION", digest, 1, 2)))

	citations, err := LoadCitations("rules.json", raw)
	if err != nil {
		t.Fatalf("LoadCitations: %v", err)
	}
	if len(citations) != 1 {
		t.Fatalf("expected 1 citation, got %d", len(citations))
	}
	got := citations[0]
	if got.Owner != "argoproj" || got.Repo != "argo-cd" || got.Path != "VERSION" || got.OldCommit != commitA {
		t.Fatalf("unexpected citation: %+v", got)
	}
	if got.StartLine != 1 || got.EndLine != 2 {
		t.Fatalf("unexpected span: %+v", got)
	}
}

func TestLoadCitationsAcceptsRawGithubusercontentShape(t *testing.T) {
	digest := sourcecorpus.SHA([]byte("line1"))
	raw := rulePackJSON(t, ruleEntry("dragonfly", "dragonfly.rule-1", map[string]any{
		"id":            "old-base-options",
		"url":           "https://raw.githubusercontent.com/dragonflyoss/dragonfly/" + commitA + "/cmd/dependency/base/option.go",
		"revision":      commitA,
		"contentDigest": digest,
		"startLine":     19,
		"endLine":       19,
	}))
	citations, err := LoadCitations("rules.json", raw)
	if err != nil {
		t.Fatalf("LoadCitations: %v", err)
	}
	if len(citations) != 1 || citations[0].Owner != "dragonflyoss" || citations[0].Repo != "dragonfly" || citations[0].Path != "cmd/dependency/base/option.go" {
		t.Fatalf("unexpected citation: %+v", citations)
	}
}

func TestLoadCitationsRejectsMismatchedRevision(t *testing.T) {
	entry := ruleEntry("argo-cd", "argo-cd.rule-1",
		source("argo-cd-src", "argoproj", "argo-cd", commitA, "VERSION", "sha256:abc", 1, 1))
	// Corrupt the revision so it no longer matches the URL's embedded commit.
	entry["rule"].(map[string]any)["evidence"].(map[string]any)["sources"].([]map[string]any)[0]["revision"] = commitB
	raw := rulePackJSON(t, entry)
	if _, err := LoadCitations("rules.json", raw); err == nil {
		t.Fatal("expected rejection of mismatched revision/url commit")
	}
}

func TestClassifySpanIdentical(t *testing.T) {
	// The span (lines 2-3, "b\nc") survives untouched even though line 5
	// of the file changed elsewhere.
	oldData := []byte("a\nb\nc\nd\ne")
	newData := []byte("a\nb\nc\nd\nZ")
	class, start, end := classifySpan(oldData, 2, 3, newData)
	if class != ClassSpanIdentical || start != 2 || end != 3 {
		t.Fatalf("got class=%s start=%d end=%d", class, start, end)
	}
}

func TestClassifySpanMoved(t *testing.T) {
	oldData := []byte("a\nb\nc")
	// New file: same "a\nb" pair now appears at lines 3-4 instead of 1-2.
	newData := []byte("x\ny\na\nb\nz")
	class, start, end := classifySpan(oldData, 1, 2, newData)
	if class != ClassSpanMoved {
		t.Fatalf("expected SPAN_MOVED, got %s", class)
	}
	if start != 3 || end != 4 {
		t.Fatalf("expected new range 3-4, got %d-%d", start, end)
	}
}

func TestClassifySpanContentChanged(t *testing.T) {
	oldData := []byte("totally\noldstuff\nhere")
	newData := []byte("totally\ndifferent\ncontent")
	class, _, _ := classifySpan(oldData, 1, 2, newData)
	if class != ClassContentChanged {
		t.Fatalf("expected CONTENT_CHANGED, got %s", class)
	}
}

// fakeBlobFetcher implements sourcecapture.Fetcher over an in-memory map
// keyed by the exact raw path, so classification tests never touch the
// network.
type fakeBlobFetcher map[string]sourcecapture.FetchResult

func (f fakeBlobFetcher) Fetch(_ context.Context, path string) sourcecapture.FetchResult {
	if result, ok := f[path]; ok {
		return result
	}
	return sourcecapture.FetchResult{Kind: "HTTP_STATUS", StatusCode: 404}
}

func TestClassifyNoNewRelease(t *testing.T) {
	citation := Citation{Owner: "argoproj", Repo: "argo-cd", Path: "VERSION", OldCommit: commitA, OldDigest: "sha256:x", StartLine: 1, EndLine: 1}
	result := Classify(context.Background(), citation, commitA, fakeBlobFetcher{})
	if result.Class != ClassNoNewRelease {
		t.Fatalf("expected NO_NEW_RELEASE, got %s (%s)", result.Class, result.Detail)
	}
}

func TestClassifyPathGone(t *testing.T) {
	citation := Citation{Owner: "argoproj", Repo: "argo-cd", Path: "removed.go", OldCommit: commitA, OldDigest: "sha256:x", StartLine: 1, EndLine: 1}
	result := Classify(context.Background(), citation, commitB, fakeBlobFetcher{})
	if result.Class != ClassPathGone {
		t.Fatalf("expected PATH_GONE, got %s", result.Class)
	}
}

func TestClassifyFileIdentical(t *testing.T) {
	// contentDigest is a WHOLE-FILE digest in the shipped rule packs: when
	// the whole file at the current release commit still hashes to it, the
	// cited span is necessarily unchanged too, and no old-blob fetch is
	// needed at all.
	body := []byte("first\nsecond\nthird")
	citation := Citation{Owner: "argoproj", Repo: "argo-cd", Path: "util/helm/client.go", OldCommit: commitA, OldDigest: sourcecorpus.SHA(body), StartLine: 2, EndLine: 2}
	fetcher := fakeBlobFetcher{
		"/argoproj/argo-cd/" + commitB + "/util/helm/client.go": {Kind: "HTTP_200", StatusCode: 200, Body: body},
	}
	result := Classify(context.Background(), citation, commitB, fetcher)
	if result.Class != ClassFileIdentical {
		t.Fatalf("expected FILE_IDENTICAL, got %s (%s)", result.Class, result.Detail)
	}
	if result.NewCommit != commitB {
		t.Fatalf("expected NewCommit set, got %+v", result)
	}
}

func TestClassifyEndToEndSpanIdentical(t *testing.T) {
	// The file changed (so contentDigest, a whole-file digest, no longer
	// matches the new file), but after fetching the file at the citation's
	// own pinned commit and confirming THAT matches contentDigest, the
	// cited span (line 2, "second") is byte-identical at the same line
	// range in the new file.
	oldBody := []byte("first\nsecond\nthird")
	newBody := []byte("first\nsecond\nTHIRD")
	citation := Citation{Owner: "argoproj", Repo: "argo-cd", Path: "util/helm/client.go", OldCommit: commitA, OldDigest: sourcecorpus.SHA(oldBody), StartLine: 2, EndLine: 2}
	fetcher := fakeBlobFetcher{
		"/argoproj/argo-cd/" + commitB + "/util/helm/client.go": {Kind: "HTTP_200", StatusCode: 200, Body: newBody},
		"/argoproj/argo-cd/" + commitA + "/util/helm/client.go": {Kind: "HTTP_200", StatusCode: 200, Body: oldBody},
	}
	result := Classify(context.Background(), citation, commitB, fetcher)
	if result.Class != ClassSpanIdentical {
		t.Fatalf("expected SPAN_IDENTICAL, got %s (%s)", result.Class, result.Detail)
	}
	if result.NewCommit != commitB {
		t.Fatalf("expected NewCommit set, got %+v", result)
	}
}

func TestClassifyEndToEndSpanMoved(t *testing.T) {
	oldBody := []byte("a\nb\nc")
	newBody := []byte("x\ny\na\nb\nz")
	citation := Citation{Owner: "argoproj", Repo: "argo-cd", Path: "a.go", OldCommit: commitA, OldDigest: sourcecorpus.SHA(oldBody), StartLine: 1, EndLine: 2}
	fetcher := fakeBlobFetcher{
		"/argoproj/argo-cd/" + commitB + "/a.go": {Kind: "HTTP_200", StatusCode: 200, Body: newBody},
		"/argoproj/argo-cd/" + commitA + "/a.go": {Kind: "HTTP_200", StatusCode: 200, Body: oldBody},
	}
	result := Classify(context.Background(), citation, commitB, fetcher)
	if result.Class != ClassSpanMoved || result.NewStart != 3 || result.NewEnd != 4 {
		t.Fatalf("expected SPAN_MOVED at 3-4, got %+v", result)
	}
}

func TestClassifyCorpusDigestMismatchOnWrongDigest(t *testing.T) {
	// The corpus record claims a contentDigest for the citation's own
	// pinned commit, but the bytes actually at that commit hash to
	// something else: a corpus integrity problem, not ordinary drift.
	oldBody := []byte("first\nsecond\nthird")
	newBody := []byte("first\nsecond\nTHIRD")
	citation := Citation{Owner: "argoproj", Repo: "argo-cd", Path: "util/helm/client.go", OldCommit: commitA, OldDigest: "sha256:" + strings.Repeat("0", 64), StartLine: 2, EndLine: 2}
	fetcher := fakeBlobFetcher{
		"/argoproj/argo-cd/" + commitB + "/util/helm/client.go": {Kind: "HTTP_200", StatusCode: 200, Body: newBody},
		"/argoproj/argo-cd/" + commitA + "/util/helm/client.go": {Kind: "HTTP_200", StatusCode: 200, Body: oldBody},
	}
	result := Classify(context.Background(), citation, commitB, fetcher)
	if result.Class != ClassCorpusDigestMismatch {
		t.Fatalf("expected CORPUS_DIGEST_MISMATCH, got %s (%s)", result.Class, result.Detail)
	}
}

func TestClassifyCorpusDigestMismatchOnUnreachableOldBlob(t *testing.T) {
	// The citation's own pinned commit is immutable; a 404 fetching it
	// there means the corpus recorded a URL that does not actually
	// resolve, which is also a corpus integrity problem.
	newBody := []byte("first\nsecond\nTHIRD")
	citation := Citation{Owner: "argoproj", Repo: "argo-cd", Path: "util/helm/client.go", OldCommit: commitA, OldDigest: "sha256:" + strings.Repeat("0", 64), StartLine: 2, EndLine: 2}
	fetcher := fakeBlobFetcher{
		"/argoproj/argo-cd/" + commitB + "/util/helm/client.go": {Kind: "HTTP_200", StatusCode: 200, Body: newBody},
	}
	result := Classify(context.Background(), citation, commitB, fetcher)
	if result.Class != ClassCorpusDigestMismatch {
		t.Fatalf("expected CORPUS_DIGEST_MISMATCH, got %s (%s)", result.Class, result.Detail)
	}
}

// fakeAPIFetcher serves canned api.github.com responses keyed by path.
type fakeAPIFetcher struct {
	responses map[string]struct {
		body   []byte
		status int
	}
	calls []string
}

func (f *fakeAPIFetcher) Fetch(_ context.Context, path string) ([]byte, int, error) {
	f.calls = append(f.calls, path)
	if response, ok := f.responses[path]; ok {
		return response.body, response.status, nil
	}
	return nil, 404, nil
}

func TestResolveCurrentCommitLightweightTag(t *testing.T) {
	fetcher := &fakeAPIFetcher{responses: map[string]struct {
		body   []byte
		status int
	}{
		"/repos/argoproj/argo-cd/releases?per_page=10": {[]byte(`[{"tag_name":"v3.5.2","draft":false}]`), 200},
		"/repos/argoproj/argo-cd/git/ref/tags/v3.5.2":  {[]byte(`{"object":{"sha":"` + commitB + `","type":"commit"}}`), 200},
	}}
	tag, commit, _, err := ResolveCurrentCommit(context.Background(), fetcher, "argoproj", "argo-cd")
	if err != nil {
		t.Fatalf("ResolveCurrentCommit: %v", err)
	}
	if tag != "v3.5.2" || commit != commitB {
		t.Fatalf("got tag=%s commit=%s", tag, commit)
	}
}

func TestResolveCurrentCommitSkipsPrereleases(t *testing.T) {
	fetcher := &fakeAPIFetcher{responses: map[string]struct {
		body   []byte
		status int
	}{
		"/repos/argoproj/argo-cd/releases?per_page=10": {[]byte(`[{"tag_name":"v3.6.0-rc1","draft":false,"prerelease":true},{"tag_name":"v3.5.2","draft":false,"prerelease":false}]`), 200},
		"/repos/argoproj/argo-cd/git/ref/tags/v3.5.2":  {[]byte(`{"object":{"sha":"` + commitB + `","type":"commit"}}`), 200},
	}}
	tag, commit, _, err := ResolveCurrentCommit(context.Background(), fetcher, "argoproj", "argo-cd")
	if err != nil {
		t.Fatalf("ResolveCurrentCommit: %v", err)
	}
	if tag != "v3.5.2" || commit != commitB {
		t.Fatalf("expected the newest non-prerelease v3.5.2/%s, got tag=%s commit=%s", commitB, tag, commit)
	}
}

func TestResolveCurrentCommitAnnotatedTagPeels(t *testing.T) {
	annotatedSHA := "ccccccccccccccccccccccccccccccccccccccc3"
	fetcher := &fakeAPIFetcher{responses: map[string]struct {
		body   []byte
		status int
	}{
		"/repos/argoproj/argo-cd/releases?per_page=10":     {[]byte(`[{"tag_name":"v3.5.2","draft":false}]`), 200},
		"/repos/argoproj/argo-cd/git/ref/tags/v3.5.2":      {[]byte(`{"object":{"sha":"` + annotatedSHA + `","type":"tag"}}`), 200},
		"/repos/argoproj/argo-cd/git/tags/" + annotatedSHA: {[]byte(`{"object":{"sha":"` + commitB + `","type":"commit"}}`), 200},
	}}
	_, commit, _, err := ResolveCurrentCommit(context.Background(), fetcher, "argoproj", "argo-cd")
	if err != nil {
		t.Fatalf("ResolveCurrentCommit: %v", err)
	}
	if commit != commitB {
		t.Fatalf("expected peeled commit %s, got %s", commitB, commit)
	}
}

func TestResolveCurrentCommitFallsBackToTags(t *testing.T) {
	fetcher := &fakeAPIFetcher{responses: map[string]struct {
		body   []byte
		status int
	}{
		"/repos/example/no-releases/releases?per_page=10": {[]byte(`[]`), 200},
		"/repos/example/no-releases/tags?per_page=30":     {[]byte(`[{"name":"v1.0.0"}]`), 200},
		"/repos/example/no-releases/git/ref/tags/v1.0.0":  {[]byte(`{"object":{"sha":"` + commitA + `","type":"commit"}}`), 200},
	}}
	tag, commit, _, err := ResolveCurrentCommit(context.Background(), fetcher, "example", "no-releases")
	if err != nil {
		t.Fatalf("ResolveCurrentCommit: %v", err)
	}
	if tag != "v1.0.0" || commit != commitA {
		t.Fatalf("got tag=%s commit=%s", tag, commit)
	}
}

func TestResolveCurrentCommitRateLimited(t *testing.T) {
	fetcher := &fakeAPIFetcher{responses: map[string]struct {
		body   []byte
		status int
	}{
		"/repos/argoproj/argo-cd/releases?per_page=10": {[]byte(`{"message":"API rate limit exceeded"}`), 403},
	}}
	_, _, _, err := ResolveCurrentCommit(context.Background(), fetcher, "argoproj", "argo-cd")
	if !errors.Is(err, errRateLimited) {
		t.Fatalf("expected rate-limited error, got %v", err)
	}
}

func TestBuildWorklistBatchAttestableArithmetic(t *testing.T) {
	// Four citations against the same repo/path: one NO_NEW_RELEASE (no
	// fetch), one FILE_IDENTICAL (whole new file still matches
	// contentDigest), one SPAN_IDENTICAL (file changed, but the cited span
	// survived at the same range once verified against the citation's own
	// pinned commit), and one CONTENT_CHANGED (file changed, cited span
	// gone). Batch-attestable = FILE_IDENTICAL+SPAN_IDENTICAL+NO_NEW_RELEASE
	// = 3/4 = 0.75, so the falsification condition (<0.5) does NOT fire.
	newBody := []byte("alpha\nbeta\ngamma")
	oldBodySpanIdentical := []byte("alpha\nBETA\ngamma") // line 1 ("alpha") survives unchanged
	oldBodyContentChanged := []byte("nomatch\nnomatch2\nnomatchtail")
	commitC := "ccccccccccccccccccccccccccccccccccccccc3"
	citations := []Citation{
		{RulePack: "p", RuleID: "r1", Project: "argo-cd", SourceID: "s1", Owner: "argoproj", Repo: "argo-cd", Path: "a.go", OldCommit: commitB, OldDigest: "sha256:irrelevant", StartLine: 1, EndLine: 1},
		{RulePack: "p", RuleID: "r2", Project: "argo-cd", SourceID: "s2", Owner: "argoproj", Repo: "argo-cd", Path: "a.go", OldCommit: commitA, OldDigest: sourcecorpus.SHA(newBody), StartLine: 1, EndLine: 1},
		{RulePack: "p", RuleID: "r3", Project: "argo-cd", SourceID: "s3", Owner: "argoproj", Repo: "argo-cd", Path: "a.go", OldCommit: commitA, OldDigest: sourcecorpus.SHA(oldBodySpanIdentical), StartLine: 1, EndLine: 1},
		{RulePack: "p", RuleID: "r4", Project: "argo-cd", SourceID: "s4", Owner: "argoproj", Repo: "argo-cd", Path: "a.go", OldCommit: commitC, OldDigest: sourcecorpus.SHA(oldBodyContentChanged), StartLine: 1, EndLine: 1},
	}
	apiFetcher := &fakeAPIFetcher{responses: map[string]struct {
		body   []byte
		status int
	}{
		"/repos/argoproj/argo-cd/releases?per_page=10": {[]byte(`[{"tag_name":"v1","draft":false}]`), 200},
		"/repos/argoproj/argo-cd/git/ref/tags/v1":      {[]byte(`{"object":{"sha":"` + commitB + `","type":"commit"}}`), 200},
	}}
	blobFetcher := fakeBlobFetcher{
		"/argoproj/argo-cd/" + commitB + "/a.go": {Kind: "HTTP_200", StatusCode: 200, Body: newBody},
		"/argoproj/argo-cd/" + commitA + "/a.go": {Kind: "HTTP_200", StatusCode: 200, Body: oldBodySpanIdentical},
		"/argoproj/argo-cd/" + commitC + "/a.go": {Kind: "HTTP_200", StatusCode: 200, Body: oldBodyContentChanged},
	}
	state := newState()
	worklist, err := BuildWorklist(context.Background(), citations, nil, 0, state, apiFetcher, blobFetcher, fixedNow(), DefaultMaxAge, nil)
	if err != nil {
		t.Fatalf("BuildWorklist: %v", err)
	}
	if worklist.Summary.Classified != 4 {
		t.Fatalf("expected 4 classified, got %+v", worklist.Summary)
	}
	if worklist.Summary.Distribution[ClassNoNewRelease] != 1 {
		t.Fatalf("expected 1 NO_NEW_RELEASE, got %+v", worklist.Summary.Distribution)
	}
	if worklist.Summary.Distribution[ClassFileIdentical] != 1 {
		t.Fatalf("expected 1 FILE_IDENTICAL, got %+v", worklist.Summary.Distribution)
	}
	if worklist.Summary.Distribution[ClassSpanIdentical] != 1 {
		t.Fatalf("expected 1 SPAN_IDENTICAL, got %+v", worklist.Summary.Distribution)
	}
	if worklist.Summary.Distribution[ClassContentChanged] != 1 {
		t.Fatalf("expected 1 CONTENT_CHANGED, got %+v", worklist.Summary.Distribution)
	}
	if got, want := worklist.Summary.BatchAttestableFraction, 0.75; got != want {
		t.Fatalf("expected batch-attestable fraction %v, got %v", want, got)
	}
	if worklist.Summary.FalsificationMet {
		t.Fatalf("3/4 batch-attestable should NOT falsify, got %+v", worklist.Summary)
	}
	// Worklist must be cost-ordered: NO_NEW_RELEASE/FILE_IDENTICAL/SPAN_IDENTICAL first.
	if worklist.Citations[0].Class == ClassContentChanged {
		t.Fatalf("expected cheapest class first, got %s", worklist.Citations[0].Class)
	}
	if len(worklist.Rules) != 4 {
		t.Fatalf("expected 4 rule verdicts, got %d", len(worklist.Rules))
	}
}

func TestBuildWorklistFalsificationConditionFires(t *testing.T) {
	// One NO_NEW_RELEASE (batch-attestable) and two CONTENT_CHANGED
	// (not): 1/3 < 0.5, so the falsification condition fires.
	newBody := []byte("alpha\nbeta\ngamma")
	oldBodyContentChanged := []byte("nomatch\nnomatch2\nnomatchtail")
	citations := []Citation{
		{RulePack: "p", RuleID: "r1", Project: "argo-cd", SourceID: "s1", Owner: "argoproj", Repo: "argo-cd", Path: "a.go", OldCommit: commitB, OldDigest: "sha256:irrelevant", StartLine: 1, EndLine: 1},
		{RulePack: "p", RuleID: "r2", Project: "argo-cd", SourceID: "s2", Owner: "argoproj", Repo: "argo-cd", Path: "a.go", OldCommit: commitA, OldDigest: sourcecorpus.SHA(oldBodyContentChanged), StartLine: 1, EndLine: 1},
		{RulePack: "p", RuleID: "r3", Project: "argo-cd", SourceID: "s3", Owner: "argoproj", Repo: "argo-cd", Path: "a.go", OldCommit: commitA, OldDigest: sourcecorpus.SHA(oldBodyContentChanged), StartLine: 1, EndLine: 1},
	}
	apiFetcher := &fakeAPIFetcher{responses: map[string]struct {
		body   []byte
		status int
	}{
		"/repos/argoproj/argo-cd/releases?per_page=10": {[]byte(`[{"tag_name":"v1","draft":false}]`), 200},
		"/repos/argoproj/argo-cd/git/ref/tags/v1":      {[]byte(`{"object":{"sha":"` + commitB + `","type":"commit"}}`), 200},
	}}
	blobFetcher := fakeBlobFetcher{
		"/argoproj/argo-cd/" + commitB + "/a.go": {Kind: "HTTP_200", StatusCode: 200, Body: newBody},
		"/argoproj/argo-cd/" + commitA + "/a.go": {Kind: "HTTP_200", StatusCode: 200, Body: oldBodyContentChanged},
	}
	state := newState()
	worklist, err := BuildWorklist(context.Background(), citations, nil, 0, state, apiFetcher, blobFetcher, fixedNow(), DefaultMaxAge, nil)
	if err != nil {
		t.Fatalf("BuildWorklist: %v", err)
	}
	if !worklist.Summary.FalsificationMet {
		t.Fatalf("expected falsification condition met, got %+v", worklist.Summary)
	}
}

func TestBuildWorklistRateLimitDegradesGracefully(t *testing.T) {
	citations := []Citation{
		{RulePack: "p", RuleID: "r1", Project: "a", SourceID: "s1", Owner: "owner1", Repo: "repo1", Path: "x", OldCommit: commitA, OldDigest: "sha256:x", StartLine: 1, EndLine: 1},
		{RulePack: "p", RuleID: "r2", Project: "a", SourceID: "s2", Owner: "owner2", Repo: "repo2", Path: "x", OldCommit: commitA, OldDigest: "sha256:x", StartLine: 1, EndLine: 1},
	}
	apiFetcher := &fakeAPIFetcher{responses: map[string]struct {
		body   []byte
		status int
	}{
		"/repos/owner1/repo1/releases?per_page=10": {[]byte(`{"message":"rate limited"}`), 403},
	}}
	state := newState()
	worklist, err := BuildWorklist(context.Background(), citations, nil, 0, state, apiFetcher, fakeBlobFetcher{}, fixedNow(), DefaultMaxAge, nil)
	if err != nil {
		t.Fatalf("BuildWorklist: %v", err)
	}
	if worklist.Summary.Pending != 2 {
		t.Fatalf("expected both citations pending after rate limit, got %+v", worklist.Summary)
	}
	// Second repo must never have been attempted once the first hit the limit.
	for _, call := range apiFetcher.calls {
		if strings.Contains(call, "owner2") {
			t.Fatalf("expected no calls for owner2 after rate limit, got call %q", call)
		}
	}
	if state.Repos["owner1/repo1"].Status != repoPendingRateLimited {
		t.Fatalf("expected owner1/repo1 marked rate-limited, got %+v", state.Repos["owner1/repo1"])
	}
}

func TestStateRoundTripResumesWithoutReclassifying(t *testing.T) {
	dir := t.TempDir()
	statePath := filepath.Join(dir, "state.json")

	citation := Citation{RulePack: "p", RuleID: "r1", Project: "a", SourceID: "s1", Owner: "owner1", Repo: "repo1", Path: "x", OldCommit: commitA, OldDigest: "sha256:x", StartLine: 1, EndLine: 1}
	apiFetcher := &fakeAPIFetcher{responses: map[string]struct {
		body   []byte
		status int
	}{
		"/repos/owner1/repo1/releases?per_page=10": {[]byte(`[{"tag_name":"v1","draft":false}]`), 200},
		"/repos/owner1/repo1/git/ref/tags/v1":      {[]byte(`{"object":{"sha":"` + commitA + `","type":"commit"}}`), 200},
	}}

	state, err := LoadState(statePath)
	if err != nil {
		t.Fatalf("LoadState: %v", err)
	}
	if _, err := BuildWorklist(context.Background(), []Citation{citation}, nil, 0, state, apiFetcher, fakeBlobFetcher{}, fixedNow(), DefaultMaxAge, nil); err != nil {
		t.Fatalf("BuildWorklist: %v", err)
	}
	if err := SaveState(statePath, state); err != nil {
		t.Fatalf("SaveState: %v", err)
	}

	// Second run: reload state, wipe the api fetcher's responses so any new
	// call would 404. Resumed run must reuse the cached result rather than
	// reclassifying, and must issue zero further API calls for this repo.
	resumed, err := LoadState(statePath)
	if err != nil {
		t.Fatalf("LoadState resume: %v", err)
	}
	blankFetcher := &fakeAPIFetcher{responses: map[string]struct {
		body   []byte
		status int
	}{}}
	worklist, err := BuildWorklist(context.Background(), []Citation{citation}, nil, 0, resumed, blankFetcher, fakeBlobFetcher{}, fixedNow(), DefaultMaxAge, nil)
	if err != nil {
		t.Fatalf("BuildWorklist resume: %v", err)
	}
	if len(blankFetcher.calls) != 0 {
		t.Fatalf("expected resumed run to make no API calls, got %v", blankFetcher.calls)
	}
	if worklist.Summary.Classified != 1 {
		t.Fatalf("expected resumed classification preserved, got %+v", worklist.Summary)
	}
}

func TestFilterCitationsByProjectAndLimit(t *testing.T) {
	citations := []Citation{
		{RuleID: "b", SourceID: "1", Project: "argo-cd"},
		{RuleID: "a", SourceID: "1", Project: "argo-cd"},
		{RuleID: "a", SourceID: "1", Project: "cilium"},
	}
	filtered := filterCitations(citations, []string{"argo-cd"}, 0)
	if len(filtered) != 2 {
		t.Fatalf("expected 2 argo-cd citations, got %d", len(filtered))
	}
	// Deterministic ordering: sorted by rule id, then source id.
	if filtered[0].RuleID != "a" || filtered[1].RuleID != "b" {
		t.Fatalf("expected sorted order, got %+v", filtered)
	}
	limited := filterCitations(citations, nil, 1)
	if len(limited) != 1 {
		t.Fatalf("expected limit=1 to cap to 1 citation, got %d", len(limited))
	}
}

func TestRunWritesWorklistAndRejectsMissingOutput(t *testing.T) {
	dir := t.TempDir()
	digest := sourcecorpus.SHA([]byte("v1"))
	rulesPath := filepath.Join(dir, "rules.json")
	raw := rulePackJSON(t, ruleEntry("argo-cd", "argo-cd.rule-1",
		source("argo-cd-src", "argoproj", "argo-cd", commitA, "VERSION", digest, 1, 1)))
	if err := os.WriteFile(rulesPath, raw, 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	apiFetcher := &fakeAPIFetcher{responses: map[string]struct {
		body   []byte
		status int
	}{
		"/repos/argoproj/argo-cd/releases?per_page=10": {[]byte(`[{"tag_name":"v1","draft":false}]`), 200},
		"/repos/argoproj/argo-cd/git/ref/tags/v1":      {[]byte(`{"object":{"sha":"` + commitA + `","type":"commit"}}`), 200},
	}}

	var stdout, stderr strings.Builder
	code := Run(context.Background(), []string{"repin"}, &stdout, &stderr, apiFetcher, fakeBlobFetcher{}, fixedNow(), []string{rulesPath})
	if code != 2 {
		t.Fatalf("expected rejection without --output, got code=%d stderr=%s", code, stderr.String())
	}

	outputPath := filepath.Join(dir, "worklist.json")
	stdout.Reset()
	stderr.Reset()
	code = Run(context.Background(), []string{"repin", "--output", outputPath}, &stdout, &stderr, apiFetcher, fakeBlobFetcher{}, fixedNow(), []string{rulesPath})
	if code != 0 {
		t.Fatalf("expected success, got code=%d stderr=%s", code, stderr.String())
	}
	written, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("read output: %v", err)
	}
	var worklist Worklist
	if err := json.Unmarshal(written, &worklist); err != nil {
		t.Fatalf("decode worklist: %v", err)
	}
	if worklist.Schema != Schema {
		t.Fatalf("unexpected schema: %s", worklist.Schema)
	}
	if worklist.Summary.Distribution[ClassNoNewRelease] != 1 {
		t.Fatalf("expected NO_NEW_RELEASE for a citation already at the current commit, got %+v", worklist.Summary)
	}
}

func TestRunNeverWritesRulePack(t *testing.T) {
	dir := t.TempDir()
	digest := sourcecorpus.SHA([]byte("v1"))
	rulesPath := filepath.Join(dir, "rules.json")
	raw := rulePackJSON(t, ruleEntry("argo-cd", "argo-cd.rule-1",
		source("argo-cd-src", "argoproj", "argo-cd", commitA, "VERSION", digest, 1, 1)))
	if err := os.WriteFile(rulesPath, raw, 0o444); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	before, err := os.ReadFile(rulesPath)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	apiFetcher := &fakeAPIFetcher{responses: map[string]struct {
		body   []byte
		status int
	}{
		"/repos/argoproj/argo-cd/releases?per_page=10": {[]byte(`[{"tag_name":"v1","draft":false}]`), 200},
		"/repos/argoproj/argo-cd/git/ref/tags/v1":      {[]byte(`{"object":{"sha":"` + commitA + `","type":"commit"}}`), 200},
	}}
	var stdout, stderr strings.Builder
	outputPath := filepath.Join(dir, "worklist.json")
	code := Run(context.Background(), []string{"repin", "--output", outputPath}, &stdout, &stderr, apiFetcher, fakeBlobFetcher{}, fixedNow(), []string{rulesPath})
	if code != 0 {
		t.Fatalf("expected success, got code=%d stderr=%s", code, stderr.String())
	}
	after, err := os.ReadFile(rulesPath)
	if err != nil {
		t.Fatalf("read fixture after run: %v", err)
	}
	if string(before) != string(after) {
		t.Fatalf("rule pack was modified by evidence repin")
	}
}

// --- Freshness (--max-age) regression tests -------------------------------

// TestFreshStateResumesWithoutReclassifying pins down the "still fresh"
// half of the freshness contract: a repo resolution and citation
// classification recorded well within --max-age must resume exactly as
// before (no API calls, no reclassification, timestamps untouched).
func TestFreshStateResumesWithoutReclassifying(t *testing.T) {
	citation := Citation{RulePack: "p", RuleID: "r1", Project: "a", SourceID: "s1", Owner: "owner1", Repo: "repo1", Path: "x", OldCommit: commitA, OldDigest: "sha256:x", StartLine: 1, EndLine: 1}
	resolvedAt := fixedNow()().Add(-1 * time.Hour).UTC().Format(time.RFC3339)
	classifiedAt := resolvedAt

	state := newState()
	state.Repos["owner1/repo1"] = RepoResolution{
		Owner: "owner1", Repo: "repo1", Status: repoResolved,
		CurrentTag: "v1", CurrentCommit: commitA, ResolvedAt: resolvedAt,
	}
	state.Results[citation.key()] = ClassResult{
		RulePack: "p", RuleID: "r1", Project: "a", SourceID: "s1",
		Owner: "owner1", Repo: "repo1", Path: "x",
		OldCommit: commitA, NewCommit: commitA, OldStart: 1, OldEnd: 1,
		Class: ClassNoNewRelease, ClassifiedAt: classifiedAt,
	}

	blankAPIFetcher := &fakeAPIFetcher{responses: map[string]struct {
		body   []byte
		status int
	}{}}
	worklist, err := BuildWorklist(context.Background(), []Citation{citation}, nil, 0, state, blankAPIFetcher, fakeBlobFetcher{}, fixedNow(), 72*time.Hour, nil)
	if err != nil {
		t.Fatalf("BuildWorklist: %v", err)
	}
	if len(blankAPIFetcher.calls) != 0 {
		t.Fatalf("expected a fresh repo resolution to resume with no API calls, got %v", blankAPIFetcher.calls)
	}
	if len(worklist.Citations) != 1 {
		t.Fatalf("expected 1 citation, got %+v", worklist.Citations)
	}
	got := worklist.Citations[0]
	if got.Stale {
		t.Fatalf("fresh result must not be marked stale, got %+v", got)
	}
	if got.ClassifiedAt != classifiedAt {
		t.Fatalf("fresh result's ClassifiedAt must be preserved untouched, want %s got %s", classifiedAt, got.ClassifiedAt)
	}
	if worklist.Repos[0].ResolvedAt != resolvedAt || worklist.Repos[0].Stale {
		t.Fatalf("fresh repo resolution must be preserved untouched, got %+v", worklist.Repos[0])
	}
}

// TestStaleStateIsRecomputedNotReStamped is the core regression for the
// "stale state reused as fresh" bug: a repo resolution and its dependent
// citation classification recorded well outside --max-age must never be
// silently re-emitted under this run's fresh GeneratedAt timestamp. When
// this run CAN reach the repo (no earlier rate limit), it must recompute
// the resolution and the classification, picking up a new current commit
// and a new timestamp - not just repeat the old answer.
//
// This test fails on the pre-fix code: the old code's only check before
// reusing a repo resolution was `existing.Status == repoResolved`, with no
// age check at all, so it would skip re-resolution entirely and the
// citation result would be reused unchanged (still pointing at the OLD
// commit) while GeneratedAt on the worklist moved forward to "now" -
// exactly the stale-reported-as-fresh defect this fix closes.
func TestStaleStateIsRecomputedNotReStamped(t *testing.T) {
	citation := Citation{RulePack: "p", RuleID: "r1", Project: "a", SourceID: "s1", Owner: "owner1", Repo: "repo1", Path: "x", OldCommit: commitA, OldDigest: "sha256:x", StartLine: 1, EndLine: 1}
	staleResolvedAt := fixedNow()().Add(-100 * time.Hour).UTC().Format(time.RFC3339) // older than the 72h bound

	state := newState()
	state.Repos["owner1/repo1"] = RepoResolution{
		Owner: "owner1", Repo: "repo1", Status: repoResolved,
		CurrentTag: "v1", CurrentCommit: commitA, ResolvedAt: staleResolvedAt,
	}
	state.Results[citation.key()] = ClassResult{
		RulePack: "p", RuleID: "r1", Project: "a", SourceID: "s1",
		Owner: "owner1", Repo: "repo1", Path: "x",
		OldCommit: commitA, NewCommit: commitA, OldStart: 1, OldEnd: 1,
		Class: ClassNoNewRelease, ClassifiedAt: staleResolvedAt,
	}

	// Upstream has since published a new release: this run must actually
	// see it once it re-resolves, rather than trusting the stale cache.
	apiFetcher := &fakeAPIFetcher{responses: map[string]struct {
		body   []byte
		status int
	}{
		"/repos/owner1/repo1/releases?per_page=10": {[]byte(`[{"tag_name":"v2","draft":false}]`), 200},
		"/repos/owner1/repo1/git/ref/tags/v2":      {[]byte(`{"object":{"sha":"` + commitB + `","type":"commit"}}`), 200},
	}}

	worklist, err := BuildWorklist(context.Background(), []Citation{citation}, nil, 0, state, apiFetcher, fakeBlobFetcher{}, fixedNow(), 72*time.Hour, nil)
	if err != nil {
		t.Fatalf("BuildWorklist: %v", err)
	}
	if len(apiFetcher.calls) == 0 {
		t.Fatalf("expected a stale repo resolution to be re-resolved (an API call), got none")
	}
	if got := worklist.Repos[0]; got.CurrentCommit != commitB || got.ResolvedAt == staleResolvedAt {
		t.Fatalf("expected the stale repo resolution to be recomputed against the new release, got %+v", got)
	}
	if len(worklist.Citations) != 1 {
		t.Fatalf("expected 1 citation, got %+v", worklist.Citations)
	}
	got := worklist.Citations[0]
	if got.NewCommit != commitB {
		t.Fatalf("expected the stale classification to be recomputed against the new commit %s, got %+v", commitB, got)
	}
	if got.ClassifiedAt == staleResolvedAt || got.ClassifiedAt == "" {
		t.Fatalf("expected a fresh ClassifiedAt, got %q (stale was %q)", got.ClassifiedAt, staleResolvedAt)
	}
	if got.Stale {
		t.Fatalf("a successfully recomputed result must not be marked stale, got %+v", got)
	}
}

// TestStaleStateMarkedStaleWhenUnrecomputable covers the other half of the
// stale-state contract: when this run truly cannot recompute a stale entry
// (an earlier repository in the same run hit the GitHub API rate limit,
// so no further api.github.com requests are attempted), the stale entry
// must be reported as stale rather than silently re-stamped as current.
func TestStaleStateMarkedStaleWhenUnrecomputable(t *testing.T) {
	// "aaa/rate-limited" sorts first alphabetically and has no prior state,
	// so BuildWorklist attempts it first and hits the rate limit,
	// preventing any further repo-resolution attempts this run.
	rateLimitedCitation := Citation{RulePack: "p", RuleID: "r0", Project: "a", SourceID: "s0", Owner: "aaa", Repo: "rate-limited", Path: "x", OldCommit: commitA, OldDigest: "sha256:x", StartLine: 1, EndLine: 1}
	// "bbb/stale-repo" sorts second and already has a stale resolved entry
	// in state; it must never be attempted (rate limit already tripped),
	// so it must come out marked stale, with its original timestamps.
	staleCitation := Citation{RulePack: "p", RuleID: "r1", Project: "a", SourceID: "s1", Owner: "bbb", Repo: "stale-repo", Path: "x", OldCommit: commitA, OldDigest: "sha256:x", StartLine: 1, EndLine: 1}

	staleResolvedAt := fixedNow()().Add(-200 * time.Hour).UTC().Format(time.RFC3339)
	state := newState()
	state.Repos["bbb/stale-repo"] = RepoResolution{
		Owner: "bbb", Repo: "stale-repo", Status: repoResolved,
		CurrentTag: "v1", CurrentCommit: commitA, ResolvedAt: staleResolvedAt,
	}
	state.Results[staleCitation.key()] = ClassResult{
		RulePack: "p", RuleID: "r1", Project: "a", SourceID: "s1",
		Owner: "bbb", Repo: "stale-repo", Path: "x",
		OldCommit: commitA, NewCommit: commitA, OldStart: 1, OldEnd: 1,
		Class: ClassNoNewRelease, ClassifiedAt: staleResolvedAt,
	}

	apiFetcher := &fakeAPIFetcher{responses: map[string]struct {
		body   []byte
		status int
	}{
		"/repos/aaa/rate-limited/releases?per_page=10": {[]byte(`{"message":"rate limited"}`), 403},
	}}

	worklist, err := BuildWorklist(context.Background(), []Citation{rateLimitedCitation, staleCitation}, nil, 0, state, apiFetcher, fakeBlobFetcher{}, fixedNow(), 72*time.Hour, nil)
	if err != nil {
		t.Fatalf("BuildWorklist: %v", err)
	}
	for _, call := range apiFetcher.calls {
		if strings.Contains(call, "stale-repo") {
			t.Fatalf("expected no attempt on the repo behind the rate limit, got call %q", call)
		}
	}

	var staleRepo *RepoResolution
	for i := range worklist.Repos {
		if worklist.Repos[i].Repo == "stale-repo" {
			staleRepo = &worklist.Repos[i]
		}
	}
	if staleRepo == nil {
		t.Fatalf("expected a repo resolution for stale-repo, got %+v", worklist.Repos)
	}
	if !staleRepo.Stale {
		t.Fatalf("expected the unrecomputable stale repo resolution to be marked stale, got %+v", staleRepo)
	}
	if staleRepo.ResolvedAt != staleResolvedAt {
		t.Fatalf("a stale-but-unrecomputable repo resolution must never be re-stamped, want %s got %s", staleResolvedAt, staleRepo.ResolvedAt)
	}

	var staleResult *ClassResult
	for i := range worklist.Citations {
		if worklist.Citations[i].Repo == "stale-repo" {
			staleResult = &worklist.Citations[i]
		}
	}
	if staleResult == nil {
		t.Fatalf("expected a classification for the stale-repo citation, got %+v", worklist.Citations)
	}
	if !staleResult.Stale {
		t.Fatalf("expected the unrecomputable stale classification to be marked stale, got %+v", staleResult)
	}
	if staleResult.ClassifiedAt != staleResolvedAt {
		t.Fatalf("a stale-but-unrecomputable classification must never be re-stamped, want %s got %s", staleResolvedAt, staleResult.ClassifiedAt)
	}

	if worklist.Summary.OldestResolvedAt != staleResolvedAt {
		t.Fatalf("expected the worklist summary to report the oldest resolution time %s, got %q", staleResolvedAt, worklist.Summary.OldestResolvedAt)
	}
}

// --- Tag-fallback marker regression tests ----------------------------------

// TestResolveCurrentCommitTagFallbackReportsResolution locks down that
// ResolveCurrentCommit itself reports when it had to fall back to the tags
// list (no GitHub Releases published) versus resolving from Releases.
func TestResolveCurrentCommitTagFallbackReportsResolution(t *testing.T) {
	fetcher := &fakeAPIFetcher{responses: map[string]struct {
		body   []byte
		status int
	}{
		"/repos/example/no-releases/releases?per_page=10": {[]byte(`[]`), 200},
		"/repos/example/no-releases/tags?per_page=30":     {[]byte(`[{"name":"v1.0.0"}]`), 200},
		"/repos/example/no-releases/git/ref/tags/v1.0.0":  {[]byte(`{"object":{"sha":"` + commitA + `","type":"commit"}}`), 200},
	}}
	_, _, resolution, err := ResolveCurrentCommit(context.Background(), fetcher, "example", "no-releases")
	if err != nil {
		t.Fatalf("ResolveCurrentCommit: %v", err)
	}
	if resolution != resolutionTagFallback {
		t.Fatalf("expected resolution marker %q for a tags-fallback resolution, got %q", resolutionTagFallback, resolution)
	}

	releasesFetcher := &fakeAPIFetcher{responses: map[string]struct {
		body   []byte
		status int
	}{
		"/repos/argoproj/argo-cd/releases?per_page=10": {[]byte(`[{"tag_name":"v3.5.2","draft":false}]`), 200},
		"/repos/argoproj/argo-cd/git/ref/tags/v3.5.2":  {[]byte(`{"object":{"sha":"` + commitB + `","type":"commit"}}`), 200},
	}}
	_, _, releaseResolution, err := ResolveCurrentCommit(context.Background(), releasesFetcher, "argoproj", "argo-cd")
	if err != nil {
		t.Fatalf("ResolveCurrentCommit: %v", err)
	}
	if releaseResolution != "" {
		t.Fatalf("expected no resolution marker for a Releases-based resolution, got %q", releaseResolution)
	}
}

// TestBuildWorklistMarksTagFallbackInOutput proves the marker required so
// downstream batch re-attestation can refuse a tag-fallback resolution
// actually reaches the worklist: both the RepoResolution and every
// ClassResult classified against it must carry
// resolution: "tag_fallback".
func TestBuildWorklistMarksTagFallbackInOutput(t *testing.T) {
	citation := Citation{RulePack: "p", RuleID: "r1", Project: "a", SourceID: "s1", Owner: "example", Repo: "no-releases", Path: "x", OldCommit: commitA, OldDigest: "sha256:x", StartLine: 1, EndLine: 1}
	apiFetcher := &fakeAPIFetcher{responses: map[string]struct {
		body   []byte
		status int
	}{
		"/repos/example/no-releases/releases?per_page=10": {[]byte(`[]`), 200},
		"/repos/example/no-releases/tags?per_page=30":     {[]byte(`[{"name":"v1.0.0"}]`), 200},
		"/repos/example/no-releases/git/ref/tags/v1.0.0":  {[]byte(`{"object":{"sha":"` + commitA + `","type":"commit"}}`), 200},
	}}
	state := newState()
	worklist, err := BuildWorklist(context.Background(), []Citation{citation}, nil, 0, state, apiFetcher, fakeBlobFetcher{}, fixedNow(), DefaultMaxAge, nil)
	if err != nil {
		t.Fatalf("BuildWorklist: %v", err)
	}
	if len(worklist.Repos) != 1 || worklist.Repos[0].Resolution != resolutionTagFallback {
		t.Fatalf("expected the repo resolution to carry the tag_fallback marker, got %+v", worklist.Repos)
	}
	if len(worklist.Citations) != 1 || worklist.Citations[0].Resolution != resolutionTagFallback {
		t.Fatalf("expected the citation classification to carry the tag_fallback marker, got %+v", worklist.Citations)
	}
}

// TestLatestTagPicksHighestVersionNotFirstListed guards the correctness
// fix to the tags fallback itself: GitHub's tags-list endpoint has no
// documented recency ordering, so trusting positional order (as the old
// per_page=1 code did) can select an old tag whenever the API happens to
// return it first, e.g. "v9.0.0" ahead of "v10.0.0" under a lexicographic
// ordering. latestTag must rank candidates by parsed version instead.
func TestLatestTagPicksHighestVersionNotFirstListed(t *testing.T) {
	fetcher := &fakeAPIFetcher{responses: map[string]struct {
		body   []byte
		status int
	}{
		// v9.0.0 listed first (as an arbitrarily-ordered API response
		// might return it), v10.0.0 numerically newer but listed second.
		"/repos/example/versioned/tags?per_page=30": {[]byte(`[{"name":"v9.0.0"},{"name":"v10.0.0"},{"name":"v2.0.0"}]`), 200},
	}}
	got, err := latestTag(context.Background(), fetcher, "example", "versioned")
	if err != nil {
		t.Fatalf("latestTag: %v", err)
	}
	if got != "v10.0.0" {
		t.Fatalf("expected the numerically highest version v10.0.0, got %q", got)
	}
}

func TestLoadCitationsEvidenceBasis(t *testing.T) {
	digest := sourcecorpus.SHA([]byte("line1\nline2"))
	build := func(mutate func(evidence map[string]any)) []byte {
		entry := ruleEntry("argo-cd", "argo-cd.rule-1", source("argo-cd-src", "argoproj", "argo-cd", commitA, "VERSION", digest, 1, 2))
		mutate(entry["rule"].(map[string]any)["evidence"].(map[string]any))
		return rulePackJSON(t, entry)
	}
	mechanical := func(e map[string]any) {
		e["basis"] = "mechanical"
		e["extractor"] = map[string]any{"id": "example.removal", "version": "1.0.0", "codeDigest": "sha256:" + strings.Repeat("ab", 32)}
		e["derivedAt"] = "2026-01-01T00:00:00Z"
	}
	for name, test := range map[string]struct {
		mutate func(map[string]any)
		valid  bool
	}{
		"absent":                       {func(map[string]any) {}, true},
		"reviewed":                     {func(e map[string]any) { e["basis"] = "reviewed" }, true},
		"mechanical":                   {mechanical, true},
		"unknown basis":                {func(e map[string]any) { e["basis"] = "automatic" }, false},
		"mechanical without extractor": {func(e map[string]any) { e["basis"] = "mechanical" }, false},
		"extractor without mechanical": {func(e map[string]any) { mechanical(e); delete(e, "basis") }, false},
	} {
		t.Run(name, func(t *testing.T) {
			citations, err := LoadCitations("rules.json", build(test.mutate))
			if test.valid && (err != nil || len(citations) != 1) {
				t.Fatalf("citations=%v err=%v", citations, err)
			}
			if !test.valid && err == nil {
				t.Fatal("expected a rejection")
			}
		})
	}
}
