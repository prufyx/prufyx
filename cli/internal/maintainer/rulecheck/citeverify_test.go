// SPDX-License-Identifier: AGPL-3.0-only

package rulecheck

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/constraintengine"
)

const (
	citeCommit = "d25610acbea3cd0e57f924f9f6bd9df99a7e33a3"
	citeTag    = "7a501744aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	citeOther  = "1111111111111111111111111111111111111111"
	// citeFork is served as a commit but is not in the repository's history.
	citeFork = "6666666666666666666666666666666666666666"
	// citeReachErr is a commit whose reachability cannot be established.
	citeReachErr = "7777777777777777777777777777777777777777"
)

var citeFileBytes = []byte("line one\nline two\n")

type citeResolver map[string]ObjectKind // "owner/repo@sha" -> kind; absent -> error

func (f citeResolver) ResolveRevision(_ context.Context, owner, repo, sha string) (ObjectKind, error) {
	if kind, ok := f[owner+"/"+repo+"@"+sha]; ok {
		return kind, nil
	}
	return ObjectKind{}, errors.New("not found")
}

func (f citeResolver) RevisionReachable(_ context.Context, owner, repo, sha string) (bool, error) {
	switch sha {
	case citeFork:
		return false, nil
	case citeReachErr:
		return false, errors.New("compare: HTTP 502")
	}
	return true, nil
}

type citeFetcher map[string][]byte // raw URL -> bytes; absent -> error

func (f citeFetcher) FetchRawBlob(_ context.Context, rawURL string) ([]byte, error) {
	if body, ok := f[rawURL]; ok {
		return body, nil
	}
	return nil, errors.New("404")
}

func citeRule(id, revision, digest string) json.RawMessage {
	return json.RawMessage(fmt.Sprintf(`{"id":%q,"evidence":{"state":"active","sources":[{"id":"s1","url":"https://github.com/acme/widget/blob/%s/a/b.go","revision":%q,"contentDigest":%q,"startLine":1,"endLine":2}]}}`, id, revision, revision, digest))
}

func citeRuleSpan(id, revision, digest string, start, end int) json.RawMessage {
	return json.RawMessage(fmt.Sprintf(`{"id":%q,"evidence":{"state":"active","sources":[{"id":"s1","url":"https://github.com/acme/widget/blob/%s/a/b.go","revision":%q,"contentDigest":%q,"startLine":%d,"endLine":%d}]}}`, id, revision, revision, digest, start, end))
}

func citeRaw(revision string) string {
	return "https://raw.githubusercontent.com/acme/widget/" + revision + "/a/b.go"
}

func TestCitationVerifierTable(t *testing.T) {
	good := digestOf(citeFileBytes)
	bad := "sha256:" + strings.Repeat("0", 64)
	tests := []struct {
		name      string
		rule      json.RawMessage
		resolver  citeResolver
		fetcher   citeFetcher
		wantPass  bool
		wantCheck []string
		wantSub   string
	}{
		{"commit and digest match", citeRule("r.ok", citeCommit, good),
			citeResolver{"acme/widget@" + citeCommit: {Commit: true}}, citeFetcher{citeRaw(citeCommit): citeFileBytes}, true, nil, ""},
		{"digest mismatch", citeRule("r.digest", citeCommit, bad),
			citeResolver{"acme/widget@" + citeCommit: {Commit: true}}, citeFetcher{citeRaw(citeCommit): citeFileBytes}, false, []string{CheckCitationDigest}, good},
		{"tag object rejected with peeled commit", citeRule("r.tag", citeTag, good),
			citeResolver{"acme/widget@" + citeTag: {PeeledCommit: citeCommit}}, citeFetcher{citeRaw(citeCommit): citeFileBytes}, false, []string{CheckRevisionNotCommit}, "use the peeled commit " + citeCommit},
		{"tag object whose peeled digest differs", citeRule("r.tag2", citeTag, bad),
			citeResolver{"acme/widget@" + citeTag: {PeeledCommit: citeCommit}}, citeFetcher{citeRaw(citeCommit): citeFileBytes}, false, []string{CheckRevisionNotCommit}, "does NOT match"},
		{"span past the end of the file", citeRuleSpan("r.span", citeCommit, good, 1, 4),
			citeResolver{"acme/widget@" + citeCommit: {Commit: true}}, citeFetcher{citeRaw(citeCommit): citeFileBytes}, false, []string{CheckCitationLineRange}, "3 line positions"},
		{"span ending on the empty position after the final newline", citeRuleSpan("r.span3", citeCommit, good, 1, 3),
			citeResolver{"acme/widget@" + citeCommit: {Commit: true}}, citeFetcher{citeRaw(citeCommit): citeFileBytes}, true, nil, ""},
		{"span starting at zero", citeRuleSpan("r.span0", citeCommit, good, 0, 2),
			citeResolver{"acme/widget@" + citeCommit: {Commit: true}}, citeFetcher{citeRaw(citeCommit): citeFileBytes}, false, []string{CheckCitationLineRange}, ""},
		{"reversed span", citeRuleSpan("r.span21", citeCommit, good, 2, 1),
			citeResolver{"acme/widget@" + citeCommit: {Commit: true}}, citeFetcher{citeRaw(citeCommit): citeFileBytes}, false, []string{CheckCitationLineRange}, ""},
		{"unresolvable revision fails closed", citeRule("r.gone", citeOther, good),
			citeResolver{}, citeFetcher{citeRaw(citeOther): citeFileBytes}, false, []string{CheckRevisionUnresolved}, ""},
		{"neither commit nor tag fails closed", citeRule("r.zero", citeOther, good),
			citeResolver{"acme/widget@" + citeOther: {}}, citeFetcher{citeRaw(citeOther): citeFileBytes}, false, []string{CheckRevisionUnresolved}, ""},
		{"fetch failure fails closed", citeRule("r.fetch", citeCommit, good),
			citeResolver{"acme/widget@" + citeCommit: {Commit: true}}, citeFetcher{}, false, []string{CheckCitationFetch}, ""},
		{"non-github url fails closed", json.RawMessage(`{"id":"r.url","evidence":{"sources":[{"id":"s1","url":"https://example.com/x","revision":"` + citeCommit + `","contentDigest":"x"}]}}`),
			citeResolver{}, citeFetcher{}, false, []string{CheckCitationURL}, ""},
		{"revision differing from url fails closed", json.RawMessage(`{"id":"r.rev","evidence":{"sources":[{"id":"s1","url":"https://github.com/acme/widget/blob/` + citeCommit + `/a/b.go","revision":"` + citeOther + `","contentDigest":"x"}]}}`),
			citeResolver{}, citeFetcher{}, false, []string{CheckCitationURL}, ""},
		{"span made only of the position after the final newline", citeRuleSpan("r.span33", citeCommit, good, 3, 3),
			citeResolver{"acme/widget@" + citeCommit: {Commit: true}}, citeFetcher{citeRaw(citeCommit): citeFileBytes}, false, []string{CheckCitationLineRange}, "2 lines"},
		{"1..1 on an empty file", citeRuleSpan("r.empty11", citeCommit, digestOf(nil), 1, 1),
			citeResolver{"acme/widget@" + citeCommit: {Commit: true}}, citeFetcher{citeRaw(citeCommit): nil}, false, []string{CheckCitationLineRange}, "0 lines"},
		{"fork-only commit is not upstream", citeRule("r.fork", citeFork, good),
			citeResolver{"acme/widget@" + citeFork: {Commit: true}}, citeFetcher{citeRaw(citeFork): citeFileBytes}, false, []string{CheckRevisionUnreachable}, "only in a fork"},
		{"reachability error fails closed", citeRule("r.reach", citeReachErr, good),
			citeResolver{"acme/widget@" + citeReachErr: {Commit: true}}, citeFetcher{citeRaw(citeReachErr): citeFileBytes}, false, []string{CheckRevisionUnreachable}, "could not establish"},
		{"rule without sources is not a pass", json.RawMessage(`{"id":"r.empty","evidence":{"sources":[]}}`),
			citeResolver{}, citeFetcher{}, false, []string{CheckCitationNoSources}, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			verifier := &CitationVerifier{Resolver: tc.resolver, Fetcher: tc.fetcher}
			report, err := verifier.Verify(context.Background(), []json.RawMessage{tc.rule})
			if err != nil {
				t.Fatal(err)
			}
			if report.Pass != tc.wantPass {
				t.Fatalf("pass = %v, want %v: %+v", report.Pass, tc.wantPass, report.Findings)
			}
			var got []string
			for _, finding := range report.Findings {
				got = append(got, finding.Check)
				if tc.wantSub != "" && !strings.Contains(finding.Message+finding.ActualDigest, tc.wantSub) {
					t.Errorf("finding %q lacks %q", finding.Message, tc.wantSub)
				}
			}
			if strings.Join(got, ",") != strings.Join(tc.wantCheck, ",") {
				t.Fatalf("checks = %v, want %v", got, tc.wantCheck)
			}
			if tc.name == "tag object rejected with peeled commit" && report.Findings[0].PeeledCommit != citeCommit {
				t.Fatalf("peeled commit = %q", report.Findings[0].PeeledCommit)
			}
		})
	}
}

// An item without a source is a finding of its own, even when another item
// in the list has sources.
func TestCitationVerifierItemWithoutSourcesIsAFinding(t *testing.T) {
	good := digestOf(citeFileBytes)
	var withSources CitationItem
	items, err := RuleCitationItems([]json.RawMessage{citeRule("r.ok", citeCommit, good)})
	if err != nil {
		t.Fatal(err)
	}
	withSources = items[0]
	verifier := &CitationVerifier{Resolver: citeResolver{"acme/widget@" + citeCommit: {Commit: true}}, Fetcher: citeFetcher{citeRaw(citeCommit): citeFileBytes}}
	report, err := verifier.VerifyItems(context.Background(), []CitationItem{withSources, {ID: "r.empty"}})
	if err != nil {
		t.Fatal(err)
	}
	if report.Pass || len(report.Findings) != 1 || report.Findings[0].Check != CheckCitationNoSources || report.Findings[0].RuleID != "r.empty" {
		t.Fatalf("report %+v", report)
	}
}

// The run has an overall deadline; hitting it is an error, not a pass.
func TestCitationVerifierDeadlineFailsClosed(t *testing.T) {
	good := digestOf(citeFileBytes)
	items, err := RuleCitationItems([]json.RawMessage{citeRule("r.ok", citeCommit, good)})
	if err != nil {
		t.Fatal(err)
	}
	hang := slowFetcher{}
	verifier := &CitationVerifier{Resolver: citeResolver{"acme/widget@" + citeCommit: {Commit: true}}, Fetcher: hang, Timeout: 50 * time.Millisecond}
	report, err := verifier.VerifyItems(context.Background(), items)
	if err == nil || report.Pass {
		t.Fatalf("report %+v err %v", report, err)
	}
}

type slowFetcher struct{}

func (slowFetcher) FetchRawBlob(ctx context.Context, _ string) ([]byte, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

func TestCitationVerifierRequiresDependencies(t *testing.T) {
	if _, err := (&CitationVerifier{}).Verify(context.Background(), nil); err == nil {
		t.Fatal("expected an error without a resolver and fetcher")
	}
}

func TestGitHubObjectsAgainstHTTPTest(t *testing.T) {
	annotated := "2222222222222222222222222222222222222222"
	nested := "3333333333333333333333333333333333333333"
	blobTarget := "4444444444444444444444444444444444444444"
	mux := http.NewServeMux()
	base := "/repos/acme/widget/git/"
	mux.HandleFunc(base+"commits/"+citeCommit, func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintf(w, `{"sha":%q}`, citeCommit)
	})
	mux.HandleFunc(base+"commits/"+citeOther, func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, `{"sha":"9999999999999999999999999999999999999999"}`) // wrong echo
	})
	mux.HandleFunc(base+"tags/"+annotated, func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintf(w, `{"sha":%q,"object":{"type":"commit","sha":%q}}`, annotated, citeCommit)
	})
	mux.HandleFunc(base+"tags/"+nested, func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintf(w, `{"sha":%q,"object":{"type":"tag","sha":%q}}`, nested, annotated)
	})
	mux.HandleFunc(base+"tags/"+blobTarget, func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintf(w, `{"sha":%q,"object":{"type":"tree","sha":%q}}`, blobTarget, citeCommit)
	})
	var sawAuth string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawAuth = r.Header.Get("Authorization")
		if strings.HasSuffix(r.URL.Path, "/commits/"+annotated) || strings.HasSuffix(r.URL.Path, "/commits/"+nested) || strings.HasSuffix(r.URL.Path, "/commits/"+blobTarget) {
			http.Error(w, `{"message":"No commit found"}`, http.StatusUnprocessableEntity)
			return
		}
		mux.ServeHTTP(w, r)
	}))
	defer server.Close()
	objects := GitHubObjects{APIBase: server.URL, Token: "t0ken", Client: server.Client()}
	tests := []struct {
		name    string
		sha     string
		want    ObjectKind
		wantErr bool
	}{
		{"commit", citeCommit, ObjectKind{Commit: true}, false},
		{"commit echo mismatch", citeOther, ObjectKind{}, true},
		{"annotated tag peels to commit", annotated, ObjectKind{PeeledCommit: citeCommit}, false},
		{"nested tag peels to commit", nested, ObjectKind{PeeledCommit: citeCommit}, false},
		{"tag of a tree", blobTarget, ObjectKind{}, true},
		{"unknown object", "5555555555555555555555555555555555555555", ObjectKind{}, true},
		{"short sha", "d25610a", ObjectKind{}, true},
		{"uppercase sha", strings.ToUpper(citeCommit), ObjectKind{}, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := objects.ResolveRevision(context.Background(), "acme", "widget", tc.sha)
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tc.wantErr)
			}
			if err == nil && got != tc.want {
				t.Fatalf("got %+v, want %+v", got, tc.want)
			}
		})
	}
	if sawAuth != "Bearer t0ken" {
		t.Fatalf("authorization header = %q", sawAuth)
	}
}

// Reachability against a fake GitHub: a tag commit, identical and ahead (the branch is ahead of the commit) are upstream;
// ahead, diverged and 404 are not; API errors and odd bodies are errors.
// The default branch is looked up once per repository with the cache, and a
// commit is compared once per verifier run however many sources cite it.
func TestGitHubObjectsRevisionReachable(t *testing.T) {
	apiRetryDelay = 0
	t.Cleanup(func() { apiRetryDelay = 2 * time.Second })
	statusOf := map[string]string{
		"1000000000000000000000000000000000000001": "identical",
		"1000000000000000000000000000000000000002": "ahead",
		"1000000000000000000000000000000000000003": "behind",
		"1000000000000000000000000000000000000004": "diverged",
		"1000000000000000000000000000000000000005": "weird",
	}
	var repoCalls, compareCalls, tagCalls int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/repos/acme/widget/tags":
			tagCalls++
			fmt.Fprint(w, `[{"name":"v1","commit":{"sha":"1000000000000000000000000000000000000009"}}]`)
		case r.URL.Path == "/repos/acme/widget":
			repoCalls++
			fmt.Fprint(w, `{"default_branch":"main"}`)
		case strings.HasPrefix(r.URL.Path, "/repos/acme/widget/compare/"):
			compareCalls++
			rest := strings.TrimPrefix(r.URL.Path, "/repos/acme/widget/compare/")
			sha, head, _ := strings.Cut(rest, "...")
			if head != "main" || r.URL.Query().Get("per_page") != "1" {
				http.Error(w, "bad request", http.StatusBadRequest)
				return
			}
			switch {
			case sha == "1000000000000000000000000000000000000006":
				http.Error(w, `{"message":"Not Found"}`, http.StatusNotFound)
			case sha == "1000000000000000000000000000000000000007":
				http.Error(w, "boom", http.StatusForbidden)
			case sha == "1000000000000000000000000000000000000008":
				fmt.Fprint(w, `not json`)
			default:
				fmt.Fprintf(w, `{"status":%q}`, statusOf[sha])
			}
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	objects := NewGitHubObjects("t")
	objects.APIBase, objects.Client = server.URL, server.Client()
	tests := []struct {
		sha     string
		want    bool
		wantErr bool
	}{
		{"1000000000000000000000000000000000000009", true, false}, // a tag commit, not on the default branch
		{"1000000000000000000000000000000000000001", true, false},
		{"1000000000000000000000000000000000000002", true, false},
		{"1000000000000000000000000000000000000003", false, false},
		{"1000000000000000000000000000000000000004", false, false},
		{"1000000000000000000000000000000000000005", false, true},
		{"1000000000000000000000000000000000000006", false, false},
		{"1000000000000000000000000000000000000007", false, true},
		{"1000000000000000000000000000000000000008", false, true},
		{"short", false, true},
	}
	for _, tc := range tests {
		got, err := objects.RevisionReachable(context.Background(), "acme", "widget", tc.sha)
		if got != tc.want || (err != nil) != tc.wantErr {
			t.Fatalf("%s: got %v err %v, want %v err %v", tc.sha, got, err, tc.want, tc.wantErr)
		}
	}
	if repoCalls != 1 || tagCalls != 1 {
		t.Fatalf("default branch looked up %d times and tags %d times, want once each", repoCalls, tagCalls)
	}
	// A failing tag listing fails closed, even for a commit that a compare
	// would have accepted.
	// An unknown repository fails closed.
	if ok, err := objects.RevisionReachable(context.Background(), "acme", "gone", "1000000000000000000000000000000000000001"); ok || err == nil {
		t.Fatalf("unknown repo: %v %v", ok, err)
	}
	// Per-commit cache in the verifier: three sources, one compare call.
	compareCalls = 0
	sha := "1000000000000000000000000000000000000001"
	src := func(id string) constraintengine.SourceEvidence {
		return constraintengine.SourceEvidence{ID: id, URL: "https://github.com/acme/widget/blob/" + sha + "/a/b.go", Revision: sha, ContentDigest: digestOf(citeFileBytes), StartLine: 1, EndLine: 2}
	}
	verifier := &CitationVerifier{Resolver: commitOnly{objects}, Fetcher: citeFetcher{"https://raw.githubusercontent.com/acme/widget/" + sha + "/a/b.go": citeFileBytes}}
	report, err := verifier.VerifyItems(context.Background(), []CitationItem{{ID: "r.a", Sources: []constraintengine.SourceEvidence{src("s1"), src("s2")}}, {ID: "r.b", Sources: []constraintengine.SourceEvidence{src("s3")}}})
	if err != nil || !report.Pass || compareCalls != 1 {
		t.Fatalf("report %+v err %v compare calls %d", report, err, compareCalls)
	}
}

// commitOnly answers ResolveRevision locally and delegates reachability.
type commitOnly struct{ GitHubObjects }

func (commitOnly) ResolveRevision(context.Context, string, string, string) (ObjectKind, error) {
	return ObjectKind{Commit: true}, nil
}

func TestGitHubObjectsServerErrorFailsClosed(t *testing.T) {
	apiRetryDelay = 0
	t.Cleanup(func() { apiRetryDelay = 2 * time.Second })
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer server.Close()
	if _, err := (GitHubObjects{APIBase: server.URL, Client: server.Client()}).ResolveRevision(context.Background(), "acme", "widget", citeCommit); err == nil {
		t.Fatal("HTTP 500 must not resolve")
	}
}

func TestVerifyCitationsCLI(t *testing.T) {
	good := digestOf(citeFileBytes)
	dir := t.TempDir()
	pack := filepath.Join(dir, "rules.json")
	doc := `{"entries":[{"rule":` + string(citeRule("r.ok", citeCommit, good)) + `},{"rule":` + string(citeRule("r.tag", citeTag, good)) + `}]}`
	if err := os.WriteFile(pack, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	deps := &citationDeps{
		resolver: citeResolver{"acme/widget@" + citeCommit: {Commit: true}, "acme/widget@" + citeTag: {PeeledCommit: citeCommit}},
		fetcher:  citeFetcher{citeRaw(citeCommit): citeFileBytes},
	}
	out := filepath.Join(dir, "report.json")
	var stdout, stderr bytes.Buffer
	code := runVerifyCitations([]string{"--rules", pack, "--out", out}, &stdout, &stderr, CLIOptions{}, deps)
	if code != 1 {
		t.Fatalf("exit = %d, stderr: %s", code, stderr.String())
	}
	raw, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	var report CitationReport
	if err := json.Unmarshal(raw, &report); err != nil {
		t.Fatal(err)
	}
	if report.Pass || report.RulesChecked != 2 || len(report.FailedRules) != 1 || report.FailedRules[0] != "r.tag" {
		t.Fatalf("unexpected report: %+v", report)
	}
	// A clean pack exits 0.
	clean := filepath.Join(dir, "clean.json")
	if err := os.WriteFile(clean, []byte(`{"entries":[{"rule":`+string(citeRule("r.ok", citeCommit, good))+`}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	stdout.Reset()
	if code := runVerifyCitations([]string{"--rules", clean}, &stdout, &stderr, CLIOptions{}, deps); code != 0 {
		t.Fatalf("clean exit = %d", code)
	}
	for _, args := range [][]string{{}, {"--rules", filepath.Join(dir, "missing.json")}, {"--bogus"}, {"--rules", clean, "extra"}} {
		if code := runVerifyCitations(args, &stdout, &stderr, CLIOptions{}, deps); code != 2 {
			t.Fatalf("args %v exit = %d, want 2", args, code)
		}
	}
}

// PackCitationItems lists the rules and every source-bearing record, and
// refuses what is not a pack.
func TestPackCitationItems(t *testing.T) {
	src := `{"id":"s1","url":"https://github.com/acme/widget/blob/` + citeCommit + `/a/b.go","revision":"` + citeCommit + `","contentDigest":"sha256:` + strings.Repeat("ab", 32) + `","startLine":1,"endLine":2}`
	pack := `{"entries":[{"rule":{"id":"r.one","evidence":{"sources":[` + src + `]}}}],"pathPolicies":[{"component":"pkg:github/acme/widget","policy":"sequential_minor","evidence":{"state":"active","reviewedAt":"2026-10-01T00:00:00Z","validUntil":"2026-10-20T00:00:00Z","sources":[` + src + `]}}]}`
	items, err := PackCitationItems([]byte(pack))
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 2 || items[0].ID != "r.one" || items[0].Record || items[1].ID != "pathPolicy pkg:github/acme/widget" || !items[1].Record || len(items[1].Sources) != 1 {
		t.Fatalf("items %+v", items)
	}
	for name, bad := range map[string]string{
		"not json":        `nope`,
		"no entries":      `{"entries":[]}`,
		"bad policy":      `{"entries":[{"rule":{"id":"r.one"}}],"pathPolicies":[{"component":"x"}]}`,
		"case variant":    `{"entries":[{"rule":{"id":"r.one"}}],"PathPolicies":[]}`,
		"rule without id": `{"entries":[{"rule":{}}]}`,
	} {
		if _, err := PackCitationItems([]byte(bad)); err == nil {
			t.Errorf("%s: want an error", name)
		}
	}
}

// The verifier covers records too, and counts them apart from rules.
func TestCitationVerifierItemsCountRecords(t *testing.T) {
	good := digestOf(citeFileBytes)
	source := constraintengineSource(citeCommit, good)
	v := &CitationVerifier{
		Resolver: citeResolver{"acme/widget@" + citeCommit: {Commit: true}},
		Fetcher:  citeFetcher{citeRaw(citeCommit): citeFileBytes},
	}
	report, err := v.VerifyItems(context.Background(), []CitationItem{
		{ID: "r.one", Sources: []constraintengine.SourceEvidence{source}},
		{Record: true, ID: "pathPolicy x", Sources: []constraintengine.SourceEvidence{source}},
	})
	if err != nil || !report.Pass || report.RulesChecked != 1 || report.RecordsChecked != 1 || report.SourcesChecked != 2 {
		t.Fatalf("report %+v err %v", report, err)
	}
}

func constraintengineSource(revision, digest string) constraintengine.SourceEvidence {
	return constraintengine.SourceEvidence{ID: "s1", URL: "https://github.com/acme/widget/blob/" + revision + "/a/b.go", Revision: revision, ContentDigest: digest, StartLine: 1, EndLine: 2}
}

// A transient API failure is retried; a persistent one still fails closed
// after the bounded number of attempts, and a redirect to another host is
// refused.
func TestGitHubObjectsRetriesTransientFailures(t *testing.T) {
	apiRetryDelay = 0
	t.Cleanup(func() { apiRetryDelay = 2 * time.Second })
	calls := 0
	flaky := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		if calls < 3 {
			http.Error(w, "boom", http.StatusBadGateway)
			return
		}
		fmt.Fprintf(w, `{"sha":%q}`, citeCommit)
	}))
	defer flaky.Close()
	got, err := (GitHubObjects{APIBase: flaky.URL, Client: flaky.Client()}).ResolveRevision(context.Background(), "acme", "widget", citeCommit)
	if err != nil || !got.Commit || calls != 3 {
		t.Fatalf("got %+v err %v after %d calls", got, err, calls)
	}

	calls = 0
	down := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		http.Error(w, "boom", http.StatusServiceUnavailable)
	}))
	defer down.Close()
	if _, err := (GitHubObjects{APIBase: down.URL, Client: down.Client()}).ResolveRevision(context.Background(), "acme", "widget", citeCommit); err == nil || calls != maxAPIAttempts {
		t.Fatalf("err %v after %d calls", err, calls)
	}

	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintf(w, `{"sha":%q}`, citeCommit)
	}))
	defer other.Close()
	redirecting := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL+r.URL.Path, http.StatusFound)
	}))
	defer redirecting.Close()
	if _, err := (GitHubObjects{APIBase: redirecting.URL, Token: "t0ken"}).ResolveRevision(context.Background(), "acme", "widget", citeCommit); err == nil {
		t.Fatal("a redirect to another host must be refused")
	}
}
