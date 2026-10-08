// SPDX-License-Identifier: AGPL-3.0-only

package knowledgegate

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/extract"
)

func TestShardPartitionsExtractorsDeterministically(t *testing.T) {
	var ids []string
	for i := 0; i < 300; i++ {
		ids = append(ids, fmt.Sprintf("crd-versions/project-%d", i))
	}
	for _, n := range []int{1, 2, 7, 13} {
		counts := make([]int, n)
		for _, id := range ids {
			hit := 0
			for i := 0; i < n; i++ {
				if (Shard{Index: i, Count: n}).Has(id) {
					hit++
					counts[i]++
				}
			}
			if hit != 1 {
				t.Fatalf("n=%d: %q is in %d shards, want exactly 1", n, id, hit)
			}
		}
		if n == 7 {
			for i, c := range counts {
				if c < 20 || c > 70 {
					t.Fatalf("shard %d of 7 holds %d of 300 ids: badly unbalanced", i, c)
				}
			}
		}
	}
	// The assignment depends on the id alone, not on the other ids.
	a := (Shard{Index: 3, Count: 7}).Has("crd-versions/project-5")
	if b := (Shard{Index: 3, Count: 7}).Has("crd-versions/project-5"); a != b {
		t.Fatal("shard assignment is not stable")
	}
}

func TestParseShard(t *testing.T) {
	now := time.Date(2026, 10, 8, 4, 23, 0, 0, time.UTC)
	for _, s := range []string{"", "all"} {
		if sh, err := ParseShard(s, now); err != nil || !sh.All() {
			t.Fatalf("%q: %+v %v", s, sh, err)
		}
	}
	if sh, err := ParseShard("2/5", now); err != nil || sh.Index != 2 || sh.Count != 5 {
		t.Fatalf("%+v %v", sh, err)
	}
	// Seven consecutive days cover seven different shards.
	seen := map[int]bool{}
	for d := 0; d < 7; d++ {
		sh, err := ParseShard("day/7", now.AddDate(0, 0, d))
		if err != nil || !sh.Day {
			t.Fatalf("%+v %v", sh, err)
		}
		seen[sh.Index] = true
	}
	if len(seen) != 7 {
		t.Fatalf("day/7 covered %d shards in 7 days", len(seen))
	}
	for _, bad := range []string{"7/7", "-1/3", "x/3", "1/0", "1", "day/0", "1/1000"} {
		if _, err := ParseShard(bad, now); err == nil {
			t.Fatalf("%q must be refused", bad)
		}
	}
}

// A sharded full re-derivation touches only the rules of its shard; the
// union of all shards is the unsharded run.
func TestGateRederiveAllShards(t *testing.T) {
	_, head, entries := mechanicalTrees(t, nil)
	src := extract.FixtureReader{Root: servedFixture}
	total := 0
	for i := 0; i < 3; i++ {
		r := runGate(t, Options{Base: head, Head: head, Source: src, RederiveAll: true, Shard: Shard{Index: i, Count: 3}})
		requirePass(t, r)
		if r.Shard != fmt.Sprintf("%d/3", i) {
			t.Fatalf("shard %q", r.Shard)
		}
		total += r.rederivedUnchanged
	}
	if total != len(entries) {
		t.Fatalf("the shards re-derived %d rules, want %d", total, len(entries))
	}
}

func apiServer(t *testing.T, h http.HandlerFunc) (*GitHubSource, *atomic.Int64) {
	t.Helper()
	var n atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n.Add(1)
		h(w, r)
	}))
	t.Cleanup(srv.Close)
	return &GitHubSource{APIBase: srv.URL, RawBase: srv.URL + "/raw"}, &n
}

func commitHandler(w http.ResponseWriter, r *http.Request) {
	c := r.URL.Path[strings.LastIndex(r.URL.Path, "/")+1:]
	fmt.Fprintf(w, `{"sha":%q,"tree":{"sha":%q}}`, c, strings.Repeat("a", 40))
}

func sha(c byte) string { return strings.Repeat(string(c), 40) }

func TestGitHubSourceRESTCapStopsBeforeSending(t *testing.T) {
	g, n := apiServer(t, commitHandler)
	g.MaxRESTRequests = 2
	repo, _ := extract.ParseRepo("github.com/o/r")
	ctx := context.Background()
	for _, c := range []byte("12") {
		if _, err := g.rootTree(ctx, repo, sha(c)); err != nil {
			t.Fatal(err)
		}
	}
	_, err := g.rootTree(ctx, repo, sha('3'))
	if !errors.Is(err, ErrBudgetExhausted) {
		t.Fatalf("err = %v, want ErrBudgetExhausted", err)
	}
	if n.Load() != 2 {
		t.Fatalf("the server saw %d requests, want exactly the cap of 2", n.Load())
	}
	st := g.Stats()
	if !st.BudgetExhausted || st.APIRequests != 2 || st.BudgetReason == "" {
		t.Fatalf("%+v", st)
	}
	// Once exhausted nothing more is sent, even for a cached-miss.
	if _, err := g.rootTree(ctx, repo, sha('4')); !errors.Is(err, ErrBudgetExhausted) || n.Load() != 2 {
		t.Fatalf("%v %d", err, n.Load())
	}
	// A commit already answered still is.
	if id, err := g.rootTree(ctx, repo, sha('1')); err != nil || id == "" {
		t.Fatalf("cached answer lost: %q %v", id, err)
	}
}

func TestGitHubSourceKeepsAReserveOfGitHubsRemaining(t *testing.T) {
	g, n := apiServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-RateLimit-Remaining", "30")
		commitHandler(w, r)
	})
	g.RESTReserve = 25
	repo, _ := extract.ParseRepo("github.com/o/r")
	if _, err := g.rootTree(context.Background(), repo, sha('1')); err != nil {
		t.Fatal(err)
	}
	// 30 left: one more is fine, then the header says 30 again (fixed
	// server), so lower it by switching the handler's view of the world.
	if g.Stats().RateLimitRemaining != 30 {
		t.Fatalf("%+v", g.Stats())
	}
	g.RESTReserve = 30
	if _, err := g.rootTree(context.Background(), repo, sha('2')); !errors.Is(err, ErrBudgetExhausted) {
		t.Fatalf("err = %v", err)
	}
	if n.Load() != 1 {
		t.Fatalf("%d requests", n.Load())
	}
}

func TestGitHubSourceRateLimitRefusalIsBudgetExhausted(t *testing.T) {
	for name, set := range map[string]func(http.Header){
		"primary":   func(h http.Header) { h.Set("X-RateLimit-Remaining", "0") },
		"secondary": func(h http.Header) { h.Set("Retry-After", "60") },
	} {
		t.Run(name, func(t *testing.T) {
			g, _ := apiServer(t, func(w http.ResponseWriter, r *http.Request) {
				set(w.Header())
				http.Error(w, "rate limited", http.StatusForbidden)
			})
			repo, _ := extract.ParseRepo("github.com/o/r")
			_, err := g.rootTree(context.Background(), repo, sha('1'))
			if !errors.Is(err, ErrBudgetExhausted) || !g.Stats().BudgetExhausted {
				t.Fatalf("err = %v", err)
			}
		})
	}
	// A plain 403 (no rate limit signal) is an ordinary failure.
	g, _ := apiServer(t, func(w http.ResponseWriter, r *http.Request) { http.Error(w, "no", http.StatusForbidden) })
	repo, _ := extract.ParseRepo("github.com/o/r")
	if _, err := g.rootTree(context.Background(), repo, sha('1')); err == nil || errors.Is(err, ErrBudgetExhausted) {
		t.Fatalf("err = %v", err)
	}
}

// When the budget runs out the gate reports "could not run" and never
// passes, whatever the rules said.
func TestGateFailsClosedWhenTheBudgetRunsOut(t *testing.T) {
	_, head, _ := mechanicalTrees(t, nil)
	fake := newFakeGitHub(servedFixture)
	src := githubSourceFor(t, fake)
	src.MaxRESTRequests = 1
	r := runGate(t, Options{Base: head, Head: head, Source: src, RederiveAll: true, Concurrency: 1})
	if r.Passed() {
		t.Fatal("a starved run passed")
	}
	requireFail(t, r, "rest-budget")
	if r.CouldNotRun == "" || exitFor(r) != ExitCouldNotRun {
		t.Fatalf("couldNotRun %q exit %d", r.CouldNotRun, exitFor(r))
	}
	if r.Upstream == nil || !r.Upstream.BudgetExhausted || r.Upstream.RESTRequests != 1 {
		t.Fatalf("%+v", r.Upstream)
	}
	if fake.rest != 1 {
		t.Fatalf("GitHub saw %d REST requests, want 1", fake.rest)
	}
	m := NewMetrics(r, 0)
	if !m.CouldNotRun || m.RESTRequests != 1 {
		t.Fatalf("%+v", m)
	}
}

func TestGateReportsRESTRequestsOnAPassingRun(t *testing.T) {
	_, head, _ := mechanicalTrees(t, nil)
	fake := newFakeGitHub(servedFixture)
	src := githubSourceFor(t, fake)
	r := runGate(t, Options{Base: head, Head: head, Source: src, RederiveAll: true, Concurrency: 2})
	requirePass(t, r)
	if r.CouldNotRun != "" || r.Upstream == nil || r.Upstream.RESTRequests != int64(fake.rest) || fake.rest == 0 {
		t.Fatalf("%+v rest=%d", r.Upstream, fake.rest)
	}
	if c, ok := check(r, "rest-budget"); !ok || !c.OK {
		t.Fatalf("%+v", c)
	}
}

func realTreeID(t *testing.T, entries []extract.TreeEntry) string {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	dir := t.TempDir()
	run := func(stdin string, args ...string) string {
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL="+os.DevNull, "GIT_CONFIG_NOSYSTEM=1")
		cmd.Stdin = strings.NewReader(stdin)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %v: %v %s", args, err, out)
		}
		return strings.TrimSpace(string(out))
	}
	run("", "init", "-q")
	var in strings.Builder
	for _, e := range entries {
		fmt.Fprintf(&in, "%s %s %s\t%s\n", e.Mode, e.Type, e.SHA, e.Path)
	}
	// mktree needs the objects to exist for blobs/trees; --missing allows it.
	return run(in.String(), "mktree", "--missing")
}

func TestDiskCacheTreesAreVerifiedAgainstTheirIDs(t *testing.T) {
	entries := []extract.TreeEntry{
		{Mode: "100644", Type: "blob", SHA: sha('1'), Path: "a.txt"},
		{Mode: "040000", Type: "tree", SHA: sha('2'), Path: "dir"},
		{Mode: "100755", Type: "blob", SHA: sha('3'), Path: "run.sh"},
	}
	id := realTreeID(t, entries)
	if got, ok := treeObjectID(entries); !ok || got != id {
		t.Fatalf("rebuilt tree id %s, git says %s", got, id)
	}
	g := &GitHubSource{CacheDir: t.TempDir()}
	g.diskStoreTree(id, entries)
	if got, ok := g.diskLoadTree(id); !ok || len(got) != 3 || got[1].Path != "dir" {
		t.Fatalf("%v %v", got, ok)
	}
	// Tampering with the file makes it a miss, never a wrong answer.
	p := g.diskPath("tree", id)
	raw, _ := os.ReadFile(p)
	if err := os.WriteFile(p, []byte(strings.Replace(string(raw), "run.sh", "evil.sh", 1)), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, ok := g.diskLoadTree(id); ok {
		t.Fatal("a tampered tree was accepted")
	}
	// An entry list that does not hash to the id is never written.
	other := &GitHubSource{CacheDir: t.TempDir()}
	other.diskStoreTree(id, entries[:2])
	if _, err := os.Stat(other.diskPath("tree", id)); err == nil {
		t.Fatal("an unverifiable tree was written")
	}
	// No cache directory: no-op.
	if _, ok := (&GitHubSource{}).diskLoadTree(id); ok {
		t.Fatal("hit without a cache")
	}
}

func TestDiskCacheBlobsAreVerified(t *testing.T) {
	g := &GitHubSource{CacheDir: t.TempDir()}
	data := []byte("hello\n")
	id := gitBlobID(data)
	g.diskStoreBlob(id, data)
	if b, ok := g.diskLoadBlob(id); !ok || string(b) != "hello\n" {
		t.Fatalf("%q %v", b, ok)
	}
	if err := os.WriteFile(g.diskPath("blob", id), []byte("HELLO\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, ok := g.diskLoadBlob(id); ok {
		t.Fatal("a tampered blob was accepted")
	}
	// A symlink in the cache is not followed.
	link := g.diskPath("blob", sha('9'))
	_ = os.MkdirAll(filepath.Dir(link), 0o755)
	_ = os.Symlink("/etc/hosts", link)
	if _, ok := g.diskLoadBlob(sha('9')); ok {
		t.Fatal("a symlink was followed")
	}
}

// The second run over the same commits is answered from the disk cache.
func TestGateUsesTheDiskCacheAcrossRuns(t *testing.T) {
	_, head, _ := mechanicalTrees(t, nil)
	dir := t.TempDir()
	run := func() (*Report, *fakeGitHub) {
		fake := newFakeGitHub(servedFixture)
		src := githubSourceFor(t, fake)
		src.CacheDir = dir
		return runGate(t, Options{Base: head, Head: head, Source: src, RederiveAll: true, Concurrency: 1}), fake
	}
	r1, f1 := run()
	requirePass(t, r1)
	r2, f2 := run()
	requirePass(t, r2)
	// Only trees that hash to their own id are cached (the fake's root
	// tree ids are synthetic and are not), so the second run is cheaper
	// but not free, and it must reach the same verdict.
	if f2.rest >= f1.rest || r2.Upstream.DiskTreeHits == 0 {
		t.Fatalf("requests %d then %d; disk tree hits %d", f1.rest, f2.rest, r2.Upstream.DiskTreeHits)
	}
}
