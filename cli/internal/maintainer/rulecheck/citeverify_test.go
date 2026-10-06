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
)

const (
	citeCommit = "d25610acbea3cd0e57f924f9f6bd9df99a7e33a3"
	citeTag    = "7a501744aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	citeOther  = "1111111111111111111111111111111111111111"
)

var citeFileBytes = []byte("line one\nline two\n")

type citeResolver map[string]ObjectKind // "owner/repo@sha" -> kind; absent -> error

func (f citeResolver) ResolveRevision(_ context.Context, owner, repo, sha string) (ObjectKind, error) {
	if kind, ok := f[owner+"/"+repo+"@"+sha]; ok {
		return kind, nil
	}
	return ObjectKind{}, errors.New("not found")
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
		{"rule without sources is not a pass", json.RawMessage(`{"id":"r.empty","evidence":{"sources":[]}}`),
			citeResolver{}, citeFetcher{}, false, nil, ""},
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

func TestGitHubObjectsServerErrorFailsClosed(t *testing.T) {
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
