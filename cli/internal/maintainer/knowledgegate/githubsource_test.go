// SPDX-License-Identifier: AGPL-3.0-only

package knowledgegate

import (
	"bytes"
	"context"
	"crypto/sha1" //nolint:gosec // test tree ids only
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/extract"
	"github.com/prufyx/prufyx/cli/internal/extract/k8sservedapis"
)

// fakeGitHub serves a fixture tree the way GitHub's git API and
// raw.githubusercontent.com serve a repository: commits, tree objects by id
// and raw files by commit and path. Tree ids are synthetic; blob ids are
// the real git ids of the bytes.
type fakeGitHub struct {
	fixture  extract.FixtureReader
	mu       sync.Mutex
	trees    map[string][2]string // tree id -> commit, dir
	tamper   map[string][]byte    // path -> bytes served instead
	truncate bool
	// truncateRecursive truncates only ?recursive=1 listings.
	truncateRecursive bool
	requests          int // every request
	rest              int // api requests (commits and trees)
	recursive         int // tree requests with ?recursive=1
	raw               int // raw file requests
}

func newFakeGitHub(root string) *fakeGitHub {
	return &fakeGitHub{fixture: extract.FixtureReader{Root: root}, trees: map[string][2]string{}, tamper: map[string][]byte{}}
}

func fakeTreeID(commit, dir string) string {
	sum := sha1.Sum([]byte("tree\x00" + commit + "\x00" + dir)) //nolint:gosec // test ids only
	return hex.EncodeToString(sum[:])
}

func (f *fakeGitHub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.requests++
	if len(r.URL.Path) > 4 && r.URL.Path[:5] == "/raw/" {
		f.raw++
	} else {
		f.rest++
	}
	rec := r.URL.Query().Get("recursive") == "1"
	if rec {
		f.recursive++
	}
	f.mu.Unlock()
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/"), "/")
	switch {
	case len(parts) == 6 && parts[0] == "repos" && parts[3] == "git" && parts[4] == "commits":
		repo, _ := extract.ParseRepo("github.com/" + parts[1] + "/" + parts[2])
		commit := parts[5]
		if _, err := f.fixture.List(repo, commit, ""); err != nil {
			http.NotFound(w, r)
			return
		}
		id := fakeTreeID(commit, "")
		f.mu.Lock()
		f.trees[id] = [2]string{commit, ""}
		f.mu.Unlock()
		_ = json.NewEncoder(w).Encode(map[string]any{"sha": commit, "tree": map[string]string{"sha": id}})
	case len(parts) == 6 && parts[0] == "repos" && parts[3] == "git" && parts[4] == "trees":
		repo, _ := extract.ParseRepo("github.com/" + parts[1] + "/" + parts[2])
		f.mu.Lock()
		loc, ok := f.trees[parts[5]]
		f.mu.Unlock()
		if !ok {
			http.NotFound(w, r)
			return
		}
		entries, err := f.fixture.List(repo, loc[0], loc[1])
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		trunc := f.truncate || (rec && f.truncateRecursive)
		var out []map[string]string
		var emit func(loc [2]string, prefix string, entries []extract.TreeEntry) error
		emit = func(loc [2]string, prefix string, entries []extract.TreeEntry) error {
			for _, e := range entries {
				sha := e.SHA
				if e.Type == "tree" {
					f.mu.Lock()
					f.trees[sha] = [2]string{loc[0], e.Path}
					f.mu.Unlock()
				}
				out = append(out, map[string]string{"path": prefix + path.Base(e.Path), "mode": e.Mode, "type": e.Type, "sha": sha})
				if rec && e.Type == "tree" {
					sub, err := f.fixture.List(repo, loc[0], e.Path)
					if err != nil {
						return err
					}
					if err := emit(loc, prefix+path.Base(e.Path)+"/", sub); err != nil {
						return err
					}
				}
			}
			return nil
		}
		if err := emit(loc, "", entries); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"sha": parts[5], "tree": out, "truncated": trunc})
	case len(parts) >= 5 && parts[0] == "raw":
		repo, _ := extract.ParseRepo("github.com/" + parts[1] + "/" + parts[2])
		p := strings.Join(parts[4:], "/")
		if b, ok := f.tamper[p]; ok {
			_, _ = w.Write(b)
			return
		}
		data, err := f.fixture.Read(repo, parts[3], p)
		if errors.Is(err, extract.ErrNotFound) {
			http.NotFound(w, r)
			return
		}
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		_, _ = w.Write(data)
	default:
		http.NotFound(w, r)
	}
}

// lsRemoteFrom renders a fixture's tags.json as "git ls-remote --tags"
// output, with every tag annotated (the peeled line names the commit).
func lsRemoteFrom(t *testing.T, root string) func(context.Context, string) ([]byte, error) {
	return func(_ context.Context, repoURL string) ([]byte, error) {
		raw, err := os.ReadFile(filepath.Join(root, strings.TrimPrefix(repoURL, "https://"), "tags.json"))
		if err != nil {
			return nil, err
		}
		var tags map[string]string
		if err := json.Unmarshal(raw, &tags); err != nil {
			return nil, err
		}
		names := make([]string, 0, len(tags))
		for n := range tags {
			names = append(names, n)
		}
		sort.Strings(names)
		var b strings.Builder
		for _, n := range names {
			obj := sha1.Sum([]byte("tag " + n)) //nolint:gosec // test ids only
			fmt.Fprintf(&b, "%s\trefs/tags/%s\n%s\trefs/tags/%s^{}\n", hex.EncodeToString(obj[:]), n, tags[n], n)
		}
		return []byte(b.String()), nil
	}
}

func githubSourceFor(t *testing.T, fake *fakeGitHub) *GitHubSource {
	t.Helper()
	srv := httptest.NewServer(fake)
	t.Cleanup(srv.Close)
	return &GitHubSource{APIBase: srv.URL, RawBase: srv.URL + "/raw", LsRemote: lsRemoteFrom(t, servedFixture)}
}

// The gate re-derives mechanical rules from bytes it fetches itself over
// the GitHub API and raw file endpoints, exactly as from a fixture tree.
func TestGateRederivesFromGitHub(t *testing.T) {
	t.Parallel()
	base, head, _ := mechanicalTrees(t, nil)
	fake := newFakeGitHub(servedFixture)
	r := runGate(t, Options{Base: base, Head: head, Source: githubSourceFor(t, fake), Concurrency: 4})
	requirePass(t, r)
	if fake.requests == 0 {
		t.Fatal("no upstream request was made")
	}
}

// Bytes that do not hash to the blob id the commit's tree records are
// refused, so a re-derivation can never run on altered upstream bytes.
func TestGitHubSourceRefusesAlteredBytes(t *testing.T) {
	t.Parallel()
	fake := newFakeGitHub(servedFixture)
	src := githubSourceFor(t, fake)
	repo, _ := extract.ParseRepo("github.com/kubernetes/kubernetes")
	tags, err := src.Tags(repo)
	if err != nil || len(tags) == 0 {
		t.Fatalf("tags: %v %v", tags, err)
	}
	commit := tags[0].Commit
	entries, err := src.List(repo, commit, "")
	if err != nil {
		t.Fatal(err)
	}
	var file string
	var walk func(dir string)
	walk = func(dir string) {
		es, err := src.List(repo, commit, dir)
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range es {
			if file != "" {
				return
			}
			if e.Type == "blob" {
				file = e.Path
			} else {
				walk(e.Path)
			}
		}
	}
	_ = entries
	walk("")
	if file == "" {
		t.Fatal("no file in the fixture")
	}
	if _, err := src.Read(repo, commit, file); err != nil {
		t.Fatalf("read: %v", err)
	}
	fake.tamper[file] = []byte("altered\n")
	fresh := githubSourceFor(t, fake)
	if _, err := fresh.Read(repo, commit, file); err == nil || !strings.Contains(err.Error(), "hash to blob") {
		t.Fatalf("altered bytes accepted: %v", err)
	}
	if _, err := fresh.Read(repo, commit, "no/such/file.go"); !errors.Is(err, extract.ErrNotFound) {
		t.Fatalf("missing file: %v", err)
	}
	if _, err := fresh.Read(repo, "v1.0.0", file); err == nil {
		t.Fatal("a tag name was accepted as a commit")
	}
	fake.truncate = true
	if _, err := githubSourceFor(t, fake).List(repo, commit, ""); err == nil || !strings.Contains(err.Error(), "truncated") {
		t.Fatalf("truncated listing accepted: %v", err)
	}
}

func TestParseLsRemoteTags(t *testing.T) {
	t.Parallel()
	a, c1, c2 := strings.Repeat("a", 40), strings.Repeat("1", 40), strings.Repeat("2", 40)
	raw := a + "\trefs/tags/v1.0.0\n" + c1 + "\trefs/tags/v1.0.0^{}\n" + c2 + "\trefs/tags/v1.1.0\n"
	tags, err := parseLsRemoteTags([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	if len(tags) != 2 || tags[0] != (extract.Tag{Name: "v1.0.0", Commit: c1}) || tags[1] != (extract.Tag{Name: "v1.1.0", Commit: c2}) {
		t.Fatalf("tags %v", tags)
	}
	for _, bad := range []string{"xyz\trefs/tags/v1\n", a + "\trefs/heads/main\n", a + " refs/tags/v1\n"} {
		if _, err := parseLsRemoteTags([]byte(bad)); err == nil {
			t.Fatalf("%q accepted", bad)
		}
	}
}

func deriveFiles(t *testing.T, r interface {
	extract.PinnedReader
	extract.TagSource
}) map[string][]byte {
	t.Helper()
	repo, err := extract.ParseRepo(k8sservedapis.Repo)
	if err != nil {
		t.Fatal(err)
	}
	derived := time.Date(2026, 10, 5, 0, 0, 0, 0, time.UTC)
	out, err := extract.Run(context.Background(), k8sservedapis.New(0), r, r, extract.Options{Repo: repo, DerivedAt: derived, Lease: 90 * 24 * time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	files, err := out.Files()
	if err != nil {
		t.Fatal(err)
	}
	return files
}

func requireSameFiles(t *testing.T, want, got map[string][]byte) {
	t.Helper()
	if len(want) == 0 || len(want) != len(got) {
		t.Fatalf("file sets differ: %d vs %d\n%s", len(want), len(got), string(got["manifest.json"]))
	}
	for name, w := range want {
		if g, ok := got[name]; !ok || !bytes.Equal(w, g) {
			t.Fatalf("%s differs between the sources", name)
		}
	}
}

// The GitHub source (recursive trees, cached) derives byte for byte what
// the mirror-backed reader derives: the fixture tree stands in for the
// mirror, which serves the same pinned bytes.
func TestGitHubSourceDerivesLikeTheMirror(t *testing.T) {
	t.Parallel()
	want := deriveFiles(t, extract.FixtureReader{Root: servedFixture})
	for name, mod := range map[string]func(*fakeGitHub){
		"recursive":           func(*fakeGitHub) {},
		"recursive truncated": func(f *fakeGitHub) { f.truncateRecursive = true },
	} {
		fake := newFakeGitHub(servedFixture)
		mod(fake)
		got := deriveFiles(t, githubSourceFor(t, fake))
		requireSameFiles(t, want, got)
		t.Logf("%s: %d files identical, rest=%d recursive=%d raw=%d", name, len(want), fake.rest, fake.recursive, fake.raw)
	}
}

// Call budget for the fixture: one commit lookup per tag, a few non
// recursive tree lookups to reach each directory, one recursive lookup per
// distinct directory subtree, and nothing for any directory below it. The
// per-directory reader needed one call per directory per commit.
func TestGitHubSourceRequestBudget(t *testing.T) {
	t.Parallel()
	run := func(truncateRecursive bool) (rest, rec, raw int, st GitHubStats) {
		fake := newFakeGitHub(servedFixture)
		fake.truncateRecursive = truncateRecursive
		src := githubSourceFor(t, fake)
		deriveFiles(t, src)
		return fake.rest, fake.recursive, fake.raw, src.Stats()
	}
	rest, rec, raw, st := run(false)
	if int64(rest) != st.RESTCalls || int64(raw) != st.RawFetches || int64(rec) != st.RecursiveTreeCalls {
		t.Fatalf("stats disagree with the server: server rest=%d rec=%d raw=%d, stats %+v", rest, rec, raw, st)
	}
	if st.TruncatedFallbacks != 0 {
		t.Fatalf("unexpected truncation %+v", st)
	}
	tfRest, _, _, tfSt := run(true)
	if tfSt.TruncatedFallbacks == 0 || tfRest <= rest {
		t.Fatalf("a truncated listing must fall back to per-directory reads: rest %d vs %d, %+v", tfRest, rest, tfSt)
	}
	t.Logf("recursive: %+v; truncated fallback: %+v", st, tfSt)
	if rest > budgetRest || raw > budgetRaw {
		t.Fatalf("over budget: rest=%d (max %d) raw=%d (max %d) %+v", rest, budgetRest, raw, budgetRaw, st)
	}
	if rest >= tfRest {
		t.Fatalf("recursive reads (%d) are not cheaper than the fallback (%d)", rest, tfRest)
	}
}

const budgetRest, budgetRaw = 44, 23

// The same tree or blob is read once, however many callers ask.
func TestGitHubSourceCachesAcrossCallers(t *testing.T) {
	t.Parallel()
	fake := newFakeGitHub(servedFixture)
	src := githubSourceFor(t, fake)
	deriveFiles(t, src)
	before := src.Stats()
	again := deriveFiles(t, src)
	after := src.Stats()
	if after.RESTCalls != before.RESTCalls || after.RawFetches != before.RawFetches {
		t.Fatalf("a second derivation repeated requests: %+v then %+v", before, after)
	}
	requireSameFiles(t, again, deriveFiles(t, extract.FixtureReader{Root: servedFixture}))
}

// refusalServer answers requests through handle(w, authed, n): n is the
// 1-based count of requests of the same kind (authenticated or anonymous).
type refusalServer struct {
	srv        *httptest.Server
	auth, anon atomic.Int64
	sleeps     []time.Duration
	handle     func(w http.ResponseWriter, authed bool, n int64)
}

func newRefusalServer(t *testing.T, handle func(w http.ResponseWriter, authed bool, n int64)) *refusalServer {
	t.Helper()
	rs := &refusalServer{handle: handle}
	rs.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			rs.handle(w, true, rs.auth.Add(1))
			return
		}
		rs.handle(w, false, rs.anon.Add(1))
	}))
	t.Cleanup(rs.srv.Close)
	return rs
}

func (rs *refusalServer) source() *GitHubSource {
	return &GitHubSource{APIBase: rs.srv.URL, Token: "test-token-value", MaxRESTRequests: 50,
		Sleep: func(_ context.Context, d time.Duration) error { rs.sleeps = append(rs.sleeps, d); return nil }}
}

func refuse(w http.ResponseWriter, status int, msg string, hdr map[string]string) {
	for k, v := range hdr {
		w.Header().Set(k, v)
	}
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"message": msg})
}

func TestGitHubGetRefusals(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	diagHdr := map[string]string{"X-RateLimit-Remaining": "4000", "X-RateLimit-Resource": "core", "X-RateLimit-Reset": "1700000000", "X-GitHub-Request-Id": "ABCD:1234"}
	secondaryHdr := map[string]string{"X-RateLimit-Remaining": "4000", "X-RateLimit-Resource": "core", "X-GitHub-Request-Id": "SEC:1"}

	t.Run("unclassified 403 then anonymous 200", func(t *testing.T) {
		t.Parallel()
		rs := newRefusalServer(t, func(w http.ResponseWriter, authed bool, _ int64) {
			if authed {
				refuse(w, 403, "Resource not accessible by integration", diagHdr)
				return
			}
			_, _ = w.Write([]byte("ok"))
		})
		body, status, err := rs.source().get(ctx, rs.srv.URL+"/x", true, 1<<10)
		if err != nil || status != 200 || string(body) != "ok" {
			t.Fatalf("got %q %d %v", body, status, err)
		}
		if rs.auth.Load() != 1 || rs.anon.Load() != 1 {
			t.Fatalf("auth=%d anon=%d", rs.auth.Load(), rs.anon.Load())
		}
	})

	t.Run("unclassified 403 and anonymous 403 carry both diagnostics", func(t *testing.T) {
		t.Parallel()
		rs := newRefusalServer(t, func(w http.ResponseWriter, authed bool, _ int64) {
			if authed {
				refuse(w, 403, "Resource not accessible by integration", diagHdr)
				return
			}
			refuse(w, 403, "Forbidden anon", map[string]string{"X-GitHub-Request-Id": "ANON:9"})
		})
		_, _, err := rs.source().get(ctx, rs.srv.URL+"/x", true, 1<<10)
		if !errors.Is(err, errAnonRefused) {
			t.Fatalf("want errAnonRefused, got %v", err)
		}
		for _, want := range []string{"authenticated: HTTP 403", "Resource not accessible by integration", "resource=core", "reset=1700000000", "ABCD:1234", "anonymous: HTTP 403", "Forbidden anon", "ANON:9"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("error lacks %q: %v", want, err)
			}
		}
		if strings.Contains(err.Error(), "test-token-value") {
			t.Errorf("token in error: %v", err)
		}
	})

	t.Run("anonymous rate limit keeps the authenticated diagnostics", func(t *testing.T) {
		t.Parallel()
		rs := newRefusalServer(t, func(w http.ResponseWriter, authed bool, _ int64) {
			if authed {
				refuse(w, 403, "Resource not accessible by integration", diagHdr)
				return
			}
			refuse(w, 403, "API rate limit exceeded for 10.0.0.1", map[string]string{"X-RateLimit-Remaining": "0", "X-RateLimit-Resource": "core"})
		})
		src := rs.source()
		_, _, err := src.get(ctx, rs.srv.URL+"/x", true, 1<<10)
		if !errors.Is(err, ErrBudgetExhausted) {
			t.Fatalf("want exhausted, got %v", err)
		}
		for _, want := range []string{"anonymous retry", "Resource not accessible by integration", "API rate limit exceeded"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("error lacks %q: %v", want, err)
			}
		}
		if !src.Stats().BudgetExhausted {
			t.Fatal("run must be latched exhausted")
		}
	})

	t.Run("secondary rate limit then 200 backs off without anonymous request", func(t *testing.T) {
		t.Parallel()
		rs := newRefusalServer(t, func(w http.ResponseWriter, authed bool, n int64) {
			if !authed {
				t.Error("anonymous request must never happen for a secondary limit")
			}
			if n == 1 {
				refuse(w, 403, "You have exceeded a secondary rate limit. Please wait.", secondaryHdr)
				return
			}
			_, _ = w.Write([]byte("ok"))
		})
		src := rs.source()
		body, _, err := src.get(ctx, rs.srv.URL+"/x", true, 1<<10)
		if err != nil || string(body) != "ok" {
			t.Fatalf("got %q %v", body, err)
		}
		if rs.anon.Load() != 0 || len(rs.sleeps) != 1 || rs.sleeps[0] != secondaryBaseWait {
			t.Fatalf("anon=%d sleeps=%v", rs.anon.Load(), rs.sleeps)
		}
		if st := src.Stats(); st.APIRequests != 2 || st.BudgetExhausted {
			t.Fatalf("each try must count against the budget: %+v", st)
		}
	})

	t.Run("Retry-After is honoured and capped", func(t *testing.T) {
		t.Parallel()
		rs := newRefusalServer(t, func(w http.ResponseWriter, _ bool, n int64) {
			switch n {
			case 1:
				refuse(w, 429, "slow down", map[string]string{"Retry-After": "7"})
			case 2:
				refuse(w, 403, "slow down", map[string]string{"Retry-After": "9999"})
			default:
				_, _ = w.Write([]byte("ok"))
			}
		})
		if _, _, err := rs.source().get(ctx, rs.srv.URL+"/x", true, 1<<10); err != nil {
			t.Fatal(err)
		}
		if len(rs.sleeps) != 2 || rs.sleeps[0] != 7*time.Second || rs.sleeps[1] != secondaryMaxWait {
			t.Fatalf("sleeps=%v", rs.sleeps)
		}
	})

	t.Run("persistent secondary limit exhausts after bounded tries", func(t *testing.T) {
		t.Parallel()
		rs := newRefusalServer(t, func(w http.ResponseWriter, authed bool, _ int64) {
			if !authed {
				t.Error("anonymous request must never happen for a secondary limit")
			}
			refuse(w, 403, "You have exceeded a SECONDARY RATE LIMIT", secondaryHdr)
		})
		src := rs.source()
		_, _, err := src.get(ctx, rs.srv.URL+"/x", true, 1<<10)
		if !errors.Is(err, ErrBudgetExhausted) {
			t.Fatalf("want exhausted, got %v", err)
		}
		for _, want := range []string{"3 tries", "SECONDARY RATE LIMIT", "resource=core", "SEC:1"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("error lacks %q: %v", want, err)
			}
		}
		if rs.auth.Load() != secondaryTries || len(rs.sleeps) != secondaryTries-1 || rs.sleeps[1] != 2*secondaryBaseWait {
			t.Fatalf("auth=%d sleeps=%v", rs.auth.Load(), rs.sleeps)
		}
		if st := src.Stats(); !st.BudgetExhausted || st.APIRequests != secondaryTries {
			t.Fatalf("%+v", st)
		}
	})

	t.Run("back-off that does not fit the deadline exhausts without waiting", func(t *testing.T) {
		t.Parallel()
		rs := newRefusalServer(t, func(w http.ResponseWriter, _ bool, _ int64) {
			refuse(w, 403, "secondary rate limit", secondaryHdr)
		})
		src := rs.source()
		deadline := time.Now().Add(time.Hour) // real deadline; the fake clock is 2s before it
		src.Now = func() time.Time { return deadline.Add(-2 * time.Second) }
		dctx, cancel := context.WithDeadline(ctx, deadline)
		defer cancel()
		_, _, err := src.get(dctx, rs.srv.URL+"/x", true, 1<<10)
		if !errors.Is(err, ErrBudgetExhausted) || !strings.Contains(err.Error(), "deadline") || len(rs.sleeps) != 0 {
			t.Fatalf("err=%v sleeps=%v", err, rs.sleeps)
		}
	})

	t.Run("primary limit is unchanged", func(t *testing.T) {
		t.Parallel()
		rs := newRefusalServer(t, func(w http.ResponseWriter, authed bool, _ int64) {
			if !authed {
				t.Error("anonymous request must never happen for a primary limit")
			}
			refuse(w, 403, "API rate limit exceeded", map[string]string{"X-RateLimit-Remaining": "0", "X-RateLimit-Resource": "core"})
		})
		src := rs.source()
		_, status, err := src.get(ctx, rs.srv.URL+"/x", true, 1<<10)
		if !errors.Is(err, ErrBudgetExhausted) || status != 403 {
			t.Fatalf("status=%d err=%v", status, err)
		}
		if !strings.Contains(err.Error(), "GitHub refused the request (HTTP 403, rate limit)") || rs.auth.Load() != 1 || len(rs.sleeps) != 0 {
			t.Fatalf("auth=%d sleeps=%v err=%v", rs.auth.Load(), rs.sleeps, err)
		}
	})
}

func TestOneLineCapsAndSanitizes(t *testing.T) {
	t.Parallel()
	got := oneLine("a\nb\r\n\tc\x00"+strings.Repeat("x", 300), maxDiagBody)
	if strings.ContainsAny(got, "\n\r\t\x00") || len(got) > maxDiagBody+3 || !strings.HasPrefix(got, "a b c ") {
		t.Fatalf("%q", got)
	}
}
