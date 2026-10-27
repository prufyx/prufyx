// SPDX-License-Identifier: AGPL-3.0-only

package knowledgegate

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/extract"
	"github.com/prufyx/prufyx/cli/internal/maintainer/gitread"
	"github.com/prufyx/prufyx/cli/internal/maintainer/gitread/gitreadtest"
)

const ipAllowListBody = `{"message":"Although you appear to have the correct authorization credentials, the ` + "`acme`" + ` organization has an IP allow list enabled, and your IP address is not permitted to access this resource."}`

// ipAllowServer answers every REST request for owner "acme" with the IP allow
// list 403 (rate limit headers show plenty left) and records every request;
// a request without a token fails the test, other owners get a 404.
type ipAllowServer struct {
	*httptest.Server
	mu            sync.Mutex
	paths         []string
	unauthed, hit int
}

func newIPAllowServer(t *testing.T) *ipAllowServer {
	s := &ipAllowServer{}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		s.paths = append(s.paths, r.URL.Path)
		if r.Header.Get("Authorization") == "" {
			s.unauthed++
		}
		s.mu.Unlock()
		if strings.HasPrefix(r.URL.Path, "/repos/acme/") {
			w.Header().Set("X-RateLimit-Remaining", "4475")
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(ipAllowListBody))
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(s.Close)
	return s
}

func ipAllowSource(t *testing.T, s *ipAllowServer, base string) *GitHubSource {
	g := &GitHubSource{APIBase: s.URL, RawBase: s.URL + "/raw", Token: "tok", Git: &gitread.Remote{Base: base, Dir: t.TempDir()}}
	t.Cleanup(func() { _ = g.Close() })
	return g
}

func TestIPAllowListedOwnerReadsOverGit(t *testing.T) {
	repo := gitreadtest.New(t, "acme", "widget")
	srv := newIPAllowServer(t)
	g := ipAllowSource(t, srv, repo.Base)
	ref, _ := extract.ParseRepo("github.com/acme/widget")

	root, err := g.List(ref, repo.C1, "")
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, e := range root {
		got = append(got, e.Type+" "+e.Mode+" "+e.Path)
	}
	if want := "blob 100644 README.md|tree 040000 docs|blob 120000 link|blob 100755 run.sh|tree 040000 vendor"; strings.Join(got, "|") != want {
		t.Fatalf("root listing\n got %s\nwant %s", strings.Join(got, "|"), want)
	}
	docs, err := g.List(ref, repo.C1, "docs") // recursive leaf-dir listing
	if err != nil {
		t.Fatal(err)
	}
	got = nil
	for _, e := range docs {
		got = append(got, e.Type+" "+e.Path)
	}
	if want := "blob docs/a.txt|tree docs/sub"; strings.Join(got, "|") != want {
		t.Fatalf("docs listing %s, want %s", strings.Join(got, "|"), want)
	}
	if _, err := g.List(ref, repo.C2, "vendor"); err != nil {
		t.Fatal(err)
	}
	if _, err := g.List(ref, repo.C2, "nope"); !errors.Is(err, extract.ErrNotFound) {
		t.Fatalf("missing directory: want ErrNotFound, got %v", err)
	}

	srv.mu.Lock()
	defer srv.mu.Unlock()
	if len(srv.paths) != 1 {
		t.Fatalf("want only the one detecting REST request, got %v", srv.paths)
	}
	if srv.unauthed != 0 {
		t.Fatalf("%d anonymous REST requests", srv.unauthed)
	}
	st := g.Stats()
	if st.RESTCalls != 0 || st.CommitCalls != 0 || st.TreeCalls != 0 || st.BudgetExhausted || st.APIRequests != 1 {
		t.Fatalf("REST accounting changed: %+v", st)
	}
	if st.GitFetches == 0 || st.GitReads == 0 || len(st.IPAllowListed) != 1 || st.IPAllowListed[0] != "acme" {
		t.Fatalf("git accounting missing: %+v", st)
	}
}

func TestIPAllowListGitFailureIsAFailureNotNotFound(t *testing.T) {
	repo := gitreadtest.New(t, "acme", "widget")
	srv := newIPAllowServer(t)
	g := ipAllowSource(t, srv, repo.Base+"/gone")
	ref, _ := extract.ParseRepo("github.com/acme/widget")
	_, err := g.List(ref, repo.C1, "docs")
	if err == nil {
		t.Fatal("a git failure must fail the read")
	}
	if errors.Is(err, extract.ErrNotFound) || errors.Is(err, ErrBudgetExhausted) {
		t.Fatalf("git failure classified as not found or budget: %v", err)
	}
	if !strings.Contains(err.Error(), "over git") {
		t.Fatalf("reason does not say git: %v", err)
	}
	if st := g.Stats(); st.BudgetExhausted {
		t.Fatalf("budget latched: %+v", st)
	}
	srv.mu.Lock()
	defer srv.mu.Unlock()
	if srv.unauthed != 0 || len(srv.paths) != 1 {
		t.Fatalf("unexpected REST traffic: %v (%d anonymous)", srv.paths, srv.unauthed)
	}
}

func TestOtherOwnersKeepREST(t *testing.T) {
	repo := gitreadtest.New(t, "acme", "widget")
	srv := newIPAllowServer(t)
	g := ipAllowSource(t, srv, repo.Base)
	other, _ := extract.ParseRepo("github.com/other/thing")
	if _, err := g.List(other, repo.C1, ""); err == nil {
		t.Fatal("fake answers 404 for other owners")
	}
	if g.Stats().CommitCalls != 1 || g.git().Listed("other") {
		t.Fatalf("other owner left REST: %+v", g.Stats())
	}
	if g.git().Stats().Fetches != 0 {
		t.Fatal("git used for a non-listed owner")
	}
}
