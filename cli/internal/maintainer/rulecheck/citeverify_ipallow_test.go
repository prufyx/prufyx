// SPDX-License-Identifier: AGPL-3.0-only

package rulecheck

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/maintainer/gitread"
	"github.com/prufyx/prufyx/cli/internal/maintainer/gitread/gitreadtest"
)

const citeIPAllowBody = `{"message":"Although you appear to have the correct authorization credentials, the ` + "`acme`" + ` organization has an IP allow list enabled, and your IP address is not permitted to access this resource."}`

func TestCitationsOfIPAllowListedOwnerUseGit(t *testing.T) {
	repo := gitreadtest.New(t, "acme", "widget")
	var mu sync.Mutex
	var paths []string
	var anon int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		paths = append(paths, r.URL.Path)
		if r.Header.Get("Authorization") == "" {
			anon++
		}
		mu.Unlock()
		w.Header().Set("X-RateLimit-Remaining", "4475")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(citeIPAllowBody))
	}))
	defer srv.Close()
	git := &gitread.Remote{Base: repo.Base, Dir: t.TempDir()}
	defer git.Close()
	g := NewGitHubObjects("tok")
	g.APIBase, g.Git = srv.URL, git
	ctx := context.Background()

	if k, err := g.ResolveRevision(ctx, "acme", "widget", repo.C2); err != nil || !k.Commit || k.PeeledCommit != "" {
		t.Fatalf("commit: %+v %v", k, err)
	}
	if k, err := g.ResolveRevision(ctx, "acme", "widget", repo.TagObj); err != nil || k.Commit || k.PeeledCommit != repo.C1 {
		t.Fatalf("tag object: %+v %v", k, err)
	}
	if _, err := g.ResolveRevision(ctx, "acme", "widget", strings.Repeat("b", 40)); err == nil {
		t.Fatal("an unresolvable revision must be an error")
	}
	for name, tc := range map[string]struct {
		sha  string
		want bool
	}{"tag commit": {repo.C1, true}, "history": {repo.C2, true}, "other branch": {repo.Side, false}} {
		got, err := g.RevisionReachable(ctx, "acme", "widget", tc.sha)
		if err != nil || got != tc.want {
			t.Errorf("%s: %v, %v want %v", name, got, err, tc.want)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if len(paths) != 1 || anon != 0 {
		t.Fatalf("want exactly one authenticated detecting request and no anonymous retry, got %v (%d anonymous)", paths, anon)
	}
}

func TestCitationGitFailureIsAnError(t *testing.T) {
	repo := gitreadtest.New(t, "acme", "widget")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(citeIPAllowBody))
	}))
	defer srv.Close()
	g := NewGitHubObjects("tok")
	g.APIBase, g.Git = srv.URL, &gitread.Remote{Base: repo.Base + "/gone", Dir: t.TempDir()}
	if _, err := g.RevisionReachable(context.Background(), "acme", "widget", repo.C1); err == nil {
		t.Fatal("a git failure must not read as 'not reachable'")
	}
	if _, err := g.ResolveRevision(context.Background(), "acme", "widget", repo.C1); err == nil {
		t.Fatal("a git failure must not read as 'not a commit'")
	}
}
