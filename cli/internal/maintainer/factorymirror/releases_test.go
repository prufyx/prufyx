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
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
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

func TestReleasesCachedWithETagAndOnlyForChangedRepos(t *testing.T) {
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
	// Unchanged upstream, releases known: no API call at all.
	e.run()
	if fake.calls.Load() != 1 {
		t.Fatalf("calls = %d", fake.calls.Load())
	}
	// Changed upstream: conditional call, 304 keeps the cache.
	u.commit("two", map[string]string{"a": "2"})
	e.run()
	if fake.calls.Load() != 2 || fake.etags[1] != `W/"e1"` {
		t.Fatalf("calls=%d etags=%v", fake.calls.Load(), fake.etags)
	}
	if rel := e.index().Repos[k1].Releases; rel.Status != ReleasesKnown || len(rel.Items) != 2 {
		t.Fatalf("%+v", rel)
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

func TestGitHubReleasesClientAgainstLocalServer(t *testing.T) {
	var gotAuth, gotINM string
	mux := http.NewServeMux()
	var srv *httptest.Server
	mux.HandleFunc("/repos/acme/widget/releases", func(w http.ResponseWriter, r *http.Request) {
		gotAuth, gotINM = r.Header.Get("Authorization"), r.Header.Get("If-None-Match")
		if r.URL.Query().Get("page") == "2" {
			_, _ = w.Write([]byte(`[{"id":1,"tag_name":"v1.0.0"}]`))
			return
		}
		if gotINM == `"abc"` {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", `"abc"`)
		w.Header().Set("Link", `<`+srv.URL+`/repos/acme/widget/releases?per_page=100&page=2>; rel="next"`)
		_, _ = w.Write([]byte(`[{"id":2,"tag_name":"v2.0.0","draft":false,"prerelease":true,"target_commitish":"main","published_at":"2024-01-01T00:00:00Z"}]`))
	})
	mux.HandleFunc("/repos/acme/limited/releases", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-RateLimit-Remaining", "0")
		w.WriteHeader(http.StatusForbidden)
	})
	mux.HandleFunc("/repos/acme/gone/releases", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNotFound) })
	mux.HandleFunc("/repos/acme/redirect/releases", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://evil.invalid/", http.StatusFound)
	})
	srv = httptest.NewServer(mux)
	defer srv.Close()
	c := GitHubReleases{Tokens: StaticToken("tok"), BaseURL: srv.URL}
	res, err := c.List(context.Background(), mustRepo(t, "acme/widget"), "")
	if err != nil || len(res.Items) != 2 || res.ETag != `"abc"` || res.Items[0].Tag != "v2.0.0" || !res.Items[0].Prerelease {
		t.Fatalf("%+v %v", res, err)
	}
	if gotAuth != "Bearer tok" {
		t.Fatalf("auth header = %q", gotAuth)
	}
	res, err = c.List(context.Background(), mustRepo(t, "acme/widget"), `"abc"`)
	if err != nil || !res.NotModified {
		t.Fatalf("%+v %v", res, err)
	}
	c.MaxPages = 1
	if res, _ = c.List(context.Background(), mustRepo(t, "acme/widget"), ""); !res.Truncated || len(res.Items) != 1 {
		t.Fatalf("truncation: %+v", res)
	}
	if _, err := c.List(context.Background(), mustRepo(t, "acme/limited"), ""); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("%v", err)
	}
	if _, err := c.List(context.Background(), mustRepo(t, "acme/gone"), ""); !errors.Is(err, ErrReleasesNotFound) {
		t.Fatalf("%v", err)
	}
	if _, err := c.List(context.Background(), mustRepo(t, "acme/redirect"), ""); err == nil {
		t.Fatal("redirects must not be followed with a token attached")
	}
	if _, err := c.List(context.Background(), mustRepo(t, "gitlab.example/acme/widget"), ""); err == nil {
		t.Fatal("non-github hosts must be rejected")
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
