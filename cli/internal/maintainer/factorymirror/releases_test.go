// SPDX-License-Identifier: AGPL-3.0-only

package factorymirror

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type fakeReleases struct {
	calls   atomic.Int32
	results map[string]ReleaseResult
	err     error
	etags   []string
}

func (f *fakeReleases) List(_ context.Context, repo Repo, etag string) (ReleaseResult, error) {
	f.calls.Add(1)
	f.etags = append(f.etags, etag)
	if f.err != nil {
		return ReleaseResult{}, f.err
	}
	if etag != "" && etag == f.results[repo.Key()].ETag {
		return ReleaseResult{NotModified: true, ETag: etag}, nil
	}
	return f.results[repo.Key()], nil
}

func TestReleasesAreRevalidatedOnEveryRunEvenWhenRefsAreUnchanged(t *testing.T) {
	e := newEnv(t, k1)
	u := e.remote[k1]
	u.commit("one", map[string]string{"a": "1"})
	u.tag("v1", false)
	fake := &fakeReleases{results: map[string]ReleaseResult{k1: {ETag: `W/"e1"`, Items: []Release{{ID: 1, Tag: "v1"}, {ID: 2, Tag: "v1.1"}}}}}
	e.opts.Releases = fake
	res := e.run()
	rel := e.index().Repos[k1].Releases
	if res.Repos[0].ReleasesStatus != ReleasesKnown || rel.ETag != `W/"e1"` || len(rel.Items) != 2 || rel.Items[0].ID != 2 {
		t.Fatalf("%+v", rel)
	}
	// Unchanged git refs: still a conditional call, answered by a 304.
	e.git.reset()
	e.run()
	if fake.calls.Load() != 2 || fake.etags[1] != `W/"e1"` || e.git.count("fetch") != 0 {
		t.Fatalf("calls=%d etags=%v git=%v", fake.calls.Load(), fake.etags, e.git.calls)
	}
	if rel := e.index().Repos[k1].Releases; rel.Status != ReleasesKnown || len(rel.Items) != 2 {
		t.Fatalf("%+v", rel)
	}

	// A release published after the tag push (no ref moved) is picked up.
	fake.results[k1] = ReleaseResult{ETag: `W/"e2"`, Items: []Release{{ID: 1, Tag: "v1"}, {ID: 2, Tag: "v1.1"}, {ID: 3, Tag: "v1", Prerelease: true}}}
	e.run()
	rel = e.index().Repos[k1].Releases
	if rel.ETag != `W/"e2"` || len(rel.Items) != 3 || rel.Items[0].ID != 3 {
		t.Fatalf("new release missed: %+v", rel)
	}
	// A prerelease flip is picked up.
	fake.results[k1] = ReleaseResult{ETag: `W/"e3"`, Items: []Release{{ID: 1, Tag: "v1"}, {ID: 2, Tag: "v1.1"}, {ID: 3, Tag: "v1", Prerelease: false}}}
	e.run()
	if rel = e.index().Repos[k1].Releases; rel.Items[0].Prerelease || rel.ETag != `W/"e3"` {
		t.Fatalf("prerelease flip missed: %+v", rel)
	}
	// A deleted release is dropped.
	fake.results[k1] = ReleaseResult{ETag: `W/"e4"`, Items: []Release{{ID: 1, Tag: "v1"}}}
	e.run()
	if rel = e.index().Repos[k1].Releases; len(rel.Items) != 1 || rel.Status != ReleasesKnown {
		t.Fatalf("deleted release kept: %+v", rel)
	}
}

func TestKnownReleasesExpireWithoutACredential(t *testing.T) {
	e := newEnv(t, k1)
	u := e.remote[k1]
	u.commit("one", map[string]string{"a": "1"})
	e.opts.Releases = &fakeReleases{results: map[string]ReleaseResult{k1: {ETag: "e", Items: []Release{{ID: 1, Tag: "v1"}}}}}
	e.run()
	e.opts.Releases = nil
	// Unchanged refs, fresh metadata: kept as known.
	e.run()
	if rel := e.index().Repos[k1].Releases; rel.Status != ReleasesKnown {
		t.Fatalf("%+v", rel)
	}
	// Past the TTL it can no longer be called known.
	later := fixedNow()().Add(DefaultReleasesTTL + time.Hour)
	e.opts.Now = func() time.Time { return later }
	e.run()
	if rel := e.index().Repos[k1].Releases; rel.Status != ReleasesStale || rel.Reason != ReasonNoToken {
		t.Fatalf("expired metadata still known: %+v", rel)
	}
}

func TestReaderCompleteReleasesRefusesIncompleteLists(t *testing.T) {
	e := newEnv(t, k1)
	e.remote[k1].commit("one", map[string]string{"a": "1"})
	fake := &fakeReleases{results: map[string]ReleaseResult{k1: {ETag: "e", Truncated: true, Items: []Release{{ID: 1, Tag: "v1"}}}}}
	e.opts.Releases = fake
	e.run()
	r, _ := OpenReader(e.state)
	if rel, err := r.Releases(k1); err != nil || !rel.Truncated || rel.Status != ReleasesKnown {
		t.Fatalf("%+v %v", rel, err)
	}
	if _, err := r.CompleteReleases(k1); !errors.Is(err, ErrReleasesIncomplete) {
		t.Fatalf("truncated list accepted: %v", err)
	}
	fake.results[k1] = ReleaseResult{ETag: "f", Items: []Release{{ID: 1, Tag: "v1"}}}
	e.run()
	r, _ = OpenReader(e.state)
	if rel, err := r.CompleteReleases(k1); err != nil || len(rel.Items) != 1 {
		t.Fatalf("%+v %v", rel, err)
	}
	// Unknown (no credential ever) is incomplete too.
	e2 := newEnv(t, k1)
	e2.remote[k1].commit("one", map[string]string{"a": "1"})
	e2.run()
	r2, _ := OpenReader(e2.state)
	if _, err := r2.CompleteReleases(k1); !errors.Is(err, ErrReleasesIncomplete) {
		t.Fatalf("unknown accepted: %v", err)
	}
}

func TestReleasesBecomeStaleWhenCredentialIsLost(t *testing.T) {
	e := newEnv(t, k1)
	u := e.remote[k1]
	u.commit("one", map[string]string{"a": "1"})
	e.opts.Releases = &fakeReleases{results: map[string]ReleaseResult{k1: {ETag: "e", Items: []Release{{ID: 1, Tag: "v1"}}}}}
	e.run()
	e.opts.Releases = nil
	u.commit("two", map[string]string{"a": "2"})
	e.run()
	rel := e.index().Repos[k1].Releases
	if rel.Status != ReleasesStale || rel.Reason != ReasonNoToken {
		t.Fatalf("must be marked stale, not silently kept: %+v", rel)
	}
}

func TestRateLimitStopsFurtherCallsAndNeverGuesses(t *testing.T) {
	keys := []string{"github.com/a/r1", "github.com/a/r2", "github.com/a/r3"}
	e := newEnv(t, keys...)
	for _, k := range keys {
		e.remote[k].commit("c", map[string]string{"f": k})
	}
	fake := &fakeReleases{err: ErrRateLimited}
	e.opts.Releases = fake
	e.opts.Concurrency = 1
	e.run()
	if fake.calls.Load() != 1 {
		t.Fatalf("calls after rate limit = %d", fake.calls.Load())
	}
	for _, k := range keys {
		if rel := e.index().Repos[k].Releases; rel.Status != ReleasesUnknown || rel.Reason != ReasonRateLimited || len(rel.Items) != 0 {
			t.Fatalf("%s: %+v", k, rel)
		}
	}
}

// ghFake is a minimal GitHub releases endpoint: pages of releases, a
// per-page ETag derived from the page content, and request accounting.
type ghFake struct {
	mu       sync.Mutex
	srv      *httptest.Server
	pages    [][]map[string]any
	requests []string // "page=N inm=..." per request
	auth     []string
	// redirectTo, when set, is where the redirect endpoints send clients.
	redirectTo string
}

func newGHFake(t *testing.T, pages [][]map[string]any) *ghFake {
	t.Helper()
	g := &ghFake{pages: pages}
	g.srv = httptest.NewServer(http.HandlerFunc(g.serve))
	t.Cleanup(g.srv.Close)
	return g
}

func (g *ghFake) set(pages [][]map[string]any) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.pages = pages
}

func (g *ghFake) take() []string {
	g.mu.Lock()
	defer g.mu.Unlock()
	out := g.requests
	g.requests = nil
	return out
}

func (g *ghFake) serve(w http.ResponseWriter, r *http.Request) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if r.URL.Path != "/repos/acme/widget/releases" {
		switch r.URL.Path {
		case "/repos/acme/limited/releases":
			w.Header().Set("X-RateLimit-Remaining", "0")
			w.WriteHeader(http.StatusForbidden)
		case "/repos/acme/redirect/releases", "/app/installations/7/access_tokens":
			http.Redirect(w, r, g.redirectTo, http.StatusFound)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
		return
	}
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if page < 1 {
		page = 1
	}
	g.auth = append(g.auth, r.Header.Get("Authorization"))
	g.requests = append(g.requests, "page="+strconv.Itoa(page)+" inm="+r.Header.Get("If-None-Match"))
	if page > len(g.pages) {
		_, _ = w.Write([]byte("[]"))
		return
	}
	body, _ := json.Marshal(g.pages[page-1])
	sum := sha256.Sum256(body)
	etag := `"` + hex.EncodeToString(sum[:6]) + `"`
	if r.Header.Get("If-None-Match") == etag {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	w.Header().Set("ETag", etag)
	if page < len(g.pages) {
		w.Header().Set("Link", `<`+g.srv.URL+`/repos/acme/widget/releases?per_page=100&page=`+strconv.Itoa(page+1)+`>; rel="next"`)
	}
	_, _ = w.Write(body)
}

func rel(id int, tag string, pre bool) map[string]any {
	return map[string]any{"id": id, "tag_name": tag, "prerelease": pre}
}

func TestGitHubReleasesPaginatesAndRevalidatesEveryPage(t *testing.T) {
	fake := newGHFake(t, [][]map[string]any{
		{rel(9, "v9", false), rel(8, "v8", false)},
		{rel(7, "v7", true)},
		{rel(1, "v1", false)},
	})
	c := GitHubReleases{Tokens: StaticToken("tok"), BaseURL: fake.srv.URL}
	repo := mustRepo(t, "acme/widget")
	res, err := c.List(context.Background(), repo, "")
	if err != nil || len(res.Items) != 4 || res.Truncated || res.NotModified || res.Items[0].Tag != "v9" || !res.Items[2].Prerelease {
		t.Fatalf("%+v %v", res, err)
	}
	if got := len(strings.Split(res.ETag, "\n")); got != 3 {
		t.Fatalf("ETag must cover all 3 pages: %q", res.ETag)
	}
	for _, a := range fake.auth {
		if a != "Bearer tok" {
			t.Fatalf("auth = %q", a)
		}
	}
	fake.take()

	// Nothing changed: every page is revalidated (3 requests), all 304.
	again, err := c.List(context.Background(), repo, res.ETag)
	if err != nil || !again.NotModified || again.ETag != res.ETag {
		t.Fatalf("%+v %v", again, err)
	}
	if reqs := fake.take(); len(reqs) != 3 || !strings.HasPrefix(reqs[2], "page=3 inm=") || strings.HasSuffix(reqs[2], "inm=") {
		t.Fatalf("requests: %v", reqs)
	}

	// A change on the LAST page only (page 1 still answers 304) is noticed.
	fake.set([][]map[string]any{
		{rel(9, "v9", false), rel(8, "v8", false)},
		{rel(7, "v7", true)},
		{rel(1, "v1", true)},
	})
	changed, err := c.List(context.Background(), repo, res.ETag)
	if err != nil || changed.NotModified || len(changed.Items) != 4 || !changed.Items[3].Prerelease {
		t.Fatalf("change on a later page missed: %+v %v", changed, err)
	}
	if changed.ETag == res.ETag {
		t.Fatal("ETag must change")
	}
	fake.take()

	// A page that disappears (releases deleted) is noticed as well.
	fake.set([][]map[string]any{{rel(9, "v9", false), rel(8, "v8", false)}, {rel(7, "v7", true)}})
	shrunk, err := c.List(context.Background(), repo, changed.ETag)
	if err != nil || shrunk.NotModified || len(shrunk.Items) != 3 || len(strings.Split(shrunk.ETag, "\n")) != 2 {
		t.Fatalf("%+v %v", shrunk, err)
	}
}

func TestGitHubReleasesPageBoundAndCompleteScan(t *testing.T) {
	var pages [][]map[string]any
	for i := 0; i < 25; i++ {
		pages = append(pages, []map[string]any{rel(100-i, "v"+strconv.Itoa(i), false)})
	}
	fake := newGHFake(t, pages)
	repo := mustRepo(t, "acme/widget")
	def := GitHubReleases{Tokens: StaticToken("t"), BaseURL: fake.srv.URL}
	res, err := def.List(context.Background(), repo, "")
	if err != nil || !res.Truncated || len(res.Items) != DefaultReleasePages {
		t.Fatalf("default bound: truncated=%v items=%d err=%v", res.Truncated, len(res.Items), err)
	}
	small := GitHubReleases{Tokens: StaticToken("t"), BaseURL: fake.srv.URL, MaxPages: 2}
	if res, _ = small.List(context.Background(), repo, ""); !res.Truncated || len(res.Items) != 2 {
		t.Fatalf("explicit bound: %+v", res)
	}
	full := GitHubReleases{Tokens: StaticToken("t"), BaseURL: fake.srv.URL, MaxPages: 2, CompleteScan: true}
	if res, err = full.List(context.Background(), repo, ""); err != nil || res.Truncated || len(res.Items) != 25 {
		t.Fatalf("complete scan: truncated=%v items=%d err=%v", res.Truncated, len(res.Items), err)
	}
}

func TestGitHubReleasesStatusMapping(t *testing.T) {
	fake := newGHFake(t, nil)
	c := GitHubReleases{Tokens: StaticToken("tok"), BaseURL: fake.srv.URL}
	ctx := context.Background()
	if _, err := c.List(ctx, mustRepo(t, "acme/limited"), ""); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("%v", err)
	}
	if _, err := c.List(ctx, mustRepo(t, "acme/gone"), ""); !errors.Is(err, ErrReleasesNotFound) {
		t.Fatalf("%v", err)
	}
	if _, err := c.List(ctx, mustRepo(t, "gitlab.example/acme/widget"), ""); err == nil {
		t.Fatal("non-github hosts must be rejected")
	}
}

// A Link header pointing somewhere else must not be followed, and the token
// must never be sent there.
func TestGitHubReleasesPaginationNeverLeavesTheAPIHost(t *testing.T) {
	var evilHits atomic.Int32
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		evilHits.Add(1)
		_, _ = w.Write([]byte(`[{"id":666,"tag_name":"evil"}]`))
	}))
	defer evil.Close()
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("ETag", `"x"`)
		w.Header().Set("Link", `<`+evil.URL+`/repos/acme/widget/releases?page=2>; rel="next"`)
		_, _ = w.Write([]byte(`[{"id":1,"tag_name":"v1"}]`))
	}))
	defer api.Close()
	c := GitHubReleases{Tokens: StaticToken("secret-token"), BaseURL: api.URL}
	res, err := c.List(context.Background(), mustRepo(t, "acme/widget"), "")
	if err == nil || len(res.Items) != 0 {
		t.Fatalf("pagination to another host accepted: %+v %v", res, err)
	}
	if evilHits.Load() != 0 {
		t.Fatalf("foreign host was contacted %d times", evilHits.Load())
	}
	// A host that merely shares the API host as a prefix is foreign too.
	if err := (GitHubReleases{}).guardForTest(api.URL, api.URL+".evil.example/x"); err == nil {
		t.Fatal("prefix lookalike host accepted")
	}
}

func (g GitHubReleases) guardForTest(base, target string) error {
	_, err := g.fetchPage(context.Background(), http.DefaultClient, base, target, "t", "")
	return err
}

// Redirects are never followed, so a token cannot be bounced elsewhere.
func TestGitHubClientsNeverFollowRedirects(t *testing.T) {
	var evilHits atomic.Int32
	var evilAuth atomic.Value
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		evilHits.Add(1)
		evilAuth.Store(r.Header.Get("Authorization"))
		_, _ = w.Write([]byte(`[]`))
	}))
	defer evil.Close()
	fake := newGHFake(t, nil)
	fake.redirectTo = evil.URL + "/steal"

	c := GitHubReleases{Tokens: StaticToken("secret-token"), BaseURL: fake.srv.URL} // default client
	if _, err := c.List(context.Background(), mustRepo(t, "acme/redirect"), ""); err == nil {
		t.Fatal("a redirect must be an error")
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	pemKey := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	app, err := NewAppTokenSource("1", "7", pemKey, fake.srv.URL, nil, fixedNow())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := app.Token(context.Background()); err == nil {
		t.Fatal("a redirect on the token exchange must be an error")
	}
	if evilHits.Load() != 0 {
		t.Fatalf("redirect target was contacted with %v", evilAuth.Load())
	}
	if err := newAPIClient().CheckRedirect(&http.Request{}, nil); !errors.Is(err, http.ErrUseLastResponse) {
		t.Fatalf("redirect policy: %v", err)
	}
}

func TestTokenSourceSelection(t *testing.T) {
	env := func(m map[string]string) func(string) string { return func(k string) string { return m[k] } }
	ts, err := TokenSourceFromEnv(env(nil), time.Now)
	if ts != nil || err != nil {
		t.Fatalf("no credential must give nil: %v %v", ts, err)
	}
	ts, err = TokenSourceFromEnv(env(map[string]string{"GITHUB_TOKEN": " abc "}), time.Now)
	if tok, _ := ts.Token(context.Background()); err != nil || tok != "abc" {
		t.Fatalf("%q %v", tok, err)
	}
	ts, _ = TokenSourceFromEnv(env(map[string]string{"GH_TOKEN": "gh"}), time.Now)
	if tok, _ := ts.Token(context.Background()); tok != "gh" {
		t.Fatal("GH_TOKEN fallback")
	}
	if _, err := TokenSourceFromEnv(env(map[string]string{"PRUFYX_GITHUB_APP_ID": "1"}), time.Now); err == nil {
		t.Fatal("incomplete app configuration must be rejected")
	}
}

func TestAppTokenSourceSignsJWTAndCaches(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	var calls atomic.Int32
	now := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Method != http.MethodPost || r.URL.Path != "/app/installations/77/access_tokens" {
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		parts := strings.Split(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "), ".")
		if len(parts) != 3 {
			t.Errorf("not a jwt")
			return
		}
		sig, _ := base64.RawURLEncoding.DecodeString(parts[2])
		sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
		if err := rsa.VerifyPKCS1v15(&key.PublicKey, crypto.SHA256, sum[:], sig); err != nil {
			t.Errorf("bad signature: %v", err)
		}
		claims, _ := base64.RawURLEncoding.DecodeString(parts[1])
		var c struct {
			Iss string `json:"iss"`
			Exp int64  `json:"exp"`
			Iat int64  `json:"iat"`
		}
		_ = json.Unmarshal(claims, &c)
		if c.Iss != "42" || c.Exp-c.Iat > 600+60 || c.Exp <= now.Unix() {
			t.Errorf("claims: %+v", c)
		}
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"token":"inst-token","expires_at":"` + now.Add(time.Hour).Format(time.RFC3339) + `"}`))
	}))
	defer srv.Close()
	src, err := NewAppTokenSource("42", "77", pemBytes, srv.URL, nil, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		tok, err := src.Token(context.Background())
		if err != nil || tok != "inst-token" {
			t.Fatalf("%q %v", tok, err)
		}
	}
	if calls.Load() != 1 {
		t.Fatalf("token not cached: %d calls", calls.Load())
	}
	if _, err := NewAppTokenSource("1", "2", []byte("not pem"), "", nil, nil); err == nil {
		t.Fatal("bad key accepted")
	}
}
