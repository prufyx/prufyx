// SPDX-License-Identifier: AGPL-3.0-only

package knowledgegate

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/extract"
	"github.com/prufyx/prufyx/cli/internal/maintainer/rulecheck"
)

// F1: the stored Mode and Type are bound by the verification, not only the
// names and ids.
func TestDiskCacheTreeBindsModeAndType(t *testing.T) {
	entries := []extract.TreeEntry{
		{Mode: "100644", Type: "blob", SHA: sha('1'), Path: "a.txt"},
		{Mode: "040000", Type: "tree", SHA: sha('2'), Path: "dir"},
	}
	id := realTreeID(t, entries)
	for name, forged := range map[string][]extract.TreeEntry{
		"type tree on a file, padded mode": {{Mode: "0100644", Type: "tree", SHA: sha('1'), Path: "a.txt"}, entries[1]},
		"type only":                        {{Mode: "100644", Type: "tree", SHA: sha('1'), Path: "a.txt"}, entries[1]},
		"blob type on a directory":         {entries[0], {Mode: "040000", Type: "blob", SHA: sha('2'), Path: "dir"}},
		"padded file mode":                 {{Mode: "0100644", Type: "blob", SHA: sha('1'), Path: "a.txt"}, entries[1]},
		"unknown mode":                     {{Mode: "100664", Type: "blob", SHA: sha('1'), Path: "a.txt"}, entries[1]},
		"empty type":                       {{Mode: "100644", SHA: sha('1'), Path: "a.txt"}, entries[1]},
	} {
		t.Run(name, func(t *testing.T) {
			g := &GitHubSource{CacheDir: t.TempDir()}
			g.diskStoreTree(id, entries)
			raw, _ := json.Marshal(forged)
			if err := os.WriteFile(g.diskPath("tree", id), raw, 0o644); err != nil {
				t.Fatal(err)
			}
			if _, ok := g.diskLoadTree(id); ok {
				t.Fatal("a forged tree entry was accepted")
			}
			// And it is never written either.
			h := &GitHubSource{CacheDir: t.TempDir()}
			h.diskStoreTree(id, forged)
			if _, err := os.Stat(h.diskPath("tree", id)); err == nil {
				t.Fatal("a forged tree was written")
			}
		})
	}
	// The genuine entries still load, and a commit entry is canonical too.
	g := &GitHubSource{CacheDir: t.TempDir()}
	g.diskStoreTree(id, entries)
	if _, ok := g.diskLoadTree(id); !ok {
		t.Fatal("genuine tree refused")
	}
	sub := []extract.TreeEntry{{Mode: "160000", Type: "commit", SHA: sha('3'), Path: "mod"}, {Mode: "120000", Type: "blob", SHA: sha('4'), Path: "ln"}}
	if _, ok := treeObjectID(sub); !ok {
		t.Fatal("canonical submodule and symlink entries refused")
	}
}

// F7: no write through a symlinked directory, no read of a swapped-in
// symlink or FIFO.
func TestDiskCacheDoesNotFollowSymlinkedDirectories(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	data := []byte("hello\n")
	id := gitBlobID(data)
	g := &GitHubSource{CacheDir: root}
	// root/blob is a link out of the cache.
	if err := os.Symlink(outside, filepath.Join(root, "blob")); err != nil {
		t.Skip("no symlinks")
	}
	g.diskStoreBlob(id, data)
	if entries, _ := os.ReadDir(outside); len(entries) != 0 {
		t.Fatalf("wrote through a symlinked directory: %v", entries)
	}
	// A symlinked second-level directory too.
	os.Remove(filepath.Join(root, "blob"))
	if err := os.MkdirAll(filepath.Join(root, "blob"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "blob", id[:2])); err != nil {
		t.Fatal(err)
	}
	g.diskStoreBlob(id, data)
	if entries, _ := os.ReadDir(outside); len(entries) != 0 {
		t.Fatalf("wrote through a symlinked directory: %v", entries)
	}
	// A cache dir that is itself a link is the caller's choice and works.
	link := filepath.Join(t.TempDir(), "cache")
	if err := os.Symlink(outside, link); err != nil {
		t.Fatal(err)
	}
	h := &GitHubSource{CacheDir: link}
	h.diskStoreBlob(id, data)
	if b, ok := h.diskLoadBlob(id); !ok || string(b) != "hello\n" {
		t.Fatalf("%q %v", b, ok)
	}
}

// F4: the cap holds under concurrency (increment, then compare, roll back).
func TestAdmitAPIDoesNotOvershootTheCapUnderConcurrency(t *testing.T) {
	g := &GitHubSource{MaxRESTRequests: 10}
	g.nAPI.Store(9)
	var wg sync.WaitGroup
	var admitted atomic.Int64
	start := make(chan struct{})
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			if g.admitAPI() == nil {
				admitted.Add(1)
			}
		}()
	}
	close(start)
	wg.Wait()
	if admitted.Load() != 1 || g.Stats().APIRequests != 10 {
		t.Fatalf("admitted %d, counted %d, want 1 and 10", admitted.Load(), g.Stats().APIRequests)
	}
	if !g.Stats().BudgetExhausted {
		t.Fatal("not marked exhausted")
	}
}

// F5: the citation verifier's GitHub calls draw on the same budget.
func TestCitationRequestsCountAgainstTheSharedBudget(t *testing.T) {
	var served atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		served.Add(1)
		w.Header().Set("X-RateLimit-Remaining", "500")
		if strings.HasSuffix(r.URL.Path, "/tags") {
			fmt.Fprint(w, `[]`)
			return
		}
		fmt.Fprint(w, `{"default_branch":"main","status":"ahead"}`)
	}))
	defer srv.Close()
	src := &GitHubSource{MaxRESTRequests: 2}
	objects := rulecheck.NewGitHubObjects("t")
	objects.APIBase = srv.URL
	objects.Admit, objects.Observe = src.CitationAdmit, src.CitationObserve
	_, err := objects.RevisionReachable(context.Background(), "o", "r", sha('a'))
	if !errors.Is(err, ErrBudgetExhausted) {
		t.Fatalf("err = %v, want ErrBudgetExhausted", err)
	}
	st := src.Stats()
	if served.Load() != 2 || st.APIRequests != 2 || !st.BudgetExhausted {
		t.Fatalf("served %d, counted %+v", served.Load(), st)
	}
	if st.RateLimitRemaining != 500 {
		t.Fatalf("the citation client's rate limit reading was lost: %+v", st)
	}
}

type drainingCitations struct{ src *GitHubSource }

func (d drainingCitations) VerifyItems(_ context.Context, items []rulecheck.CitationItem) (rulecheck.CitationReport, error) {
	if err := d.src.CitationAdmit(); err != nil {
		return rulecheck.CitationReport{}, err
	}
	return rulecheck.CitationReport{Pass: true, SourcesChecked: len(items)}, nil
}

// A run starved during the citation check is could-not-run, with an alarm.
func TestStarvationDuringCitationsIsCouldNotRun(t *testing.T) {
	base, head, _ := mechanicalTrees(t, nil)
	probe := newFakeGitHub(servedFixture)
	r0 := runGate(t, Options{Base: base, Head: head, Source: githubSourceFor(t, probe), Concurrency: 1})
	requirePass(t, r0)
	used := r0.Upstream.RESTRequests
	fake := newFakeGitHub(servedFixture)
	src := githubSourceFor(t, fake)
	src.MaxRESTRequests = used // exactly enough for the re-derivation
	r := runGate(t, Options{Base: base, Head: head, Source: src, Concurrency: 1, Citations: drainingCitations{src}})
	if r.Passed() || r.CouldNotRun == "" || exitFor(r) != ExitCouldNotRun {
		t.Fatalf("couldNotRun %q exit %d passed %v", r.CouldNotRun, exitFor(r), r.Passed())
	}
	requireFail(t, r, "citations")
	requireFail(t, r, "rest-budget")
}

// F2: a starved run raises the could-not-run alarm, in the alarms file too.
func TestCouldNotRunRaisesAnAlarm(t *testing.T) {
	_, head, _ := mechanicalTrees(t, nil)
	src := githubSourceFor(t, newFakeGitHub(servedFixture))
	src.MaxRESTRequests = 1
	r := runGate(t, Options{Base: head, Head: head, Source: src, RederiveAll: true, Concurrency: 1, Shard: Shard{}})
	doc := NewAlarmsDocument(r)
	if len(doc.Alarms) != 1 || doc.Alarms[0].Kind != AlarmCouldNotRun || !strings.Contains(doc.Alarms[0].Detail, "shard all") {
		t.Fatalf("%+v", doc.Alarms)
	}
	// A passing run raises none.
	src2 := githubSourceFor(t, newFakeGitHub(servedFixture))
	if r2 := runGate(t, Options{Base: head, Head: head, Source: src2, RederiveAll: true, Concurrency: 1}); len(r2.Alarms) != 0 {
		t.Fatalf("%v", r2.Alarms)
	}
}

func TestShardStateRecordsAttemptsAndSuccessesAndAlarmsWhenStale(t *testing.T) {
	now := time.Date(2026, 10, 8, 4, 0, 0, 0, time.UTC)
	pass := &Report{Result: "pass", Shard: "3/7"}
	if !pass.Passed() {
		pass.Checks = nil
	}
	fail := &Report{Result: "fail", Shard: "3/7"}
	st := ShardState{}.Update(fail, Shard{Index: 3, Count: 7}, now)
	if rec := st["3/7"]; rec.LastAttempt != now || !rec.LastSuccess.IsZero() || rec.LastResult != "fail" {
		t.Fatalf("%+v", rec)
	}
	cnr := &Report{Result: "fail", Shard: "3/7", CouldNotRun: "x"}
	if rec := st.Update(cnr, Shard{Index: 3, Count: 7}, now)["3/7"]; rec.LastResult != "could-not-run" {
		t.Fatalf("%+v", rec)
	}
	// An unsharded run records nothing.
	if got := st.Update(pass, Shard{}, now); len(got) != 1 {
		t.Fatalf("%v", got)
	}
	// Round trip, strict parsing.
	raw, err := st.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	back, err := ParseShardState(raw)
	if err != nil || !back["3/7"].LastAttempt.Equal(now) {
		t.Fatalf("%v %v", back, err)
	}
	for _, bad := range []string{`{"schema":"other","shards":{}}`, `{"schema":"prufyx.io/knowledge-gate-shards/v1","x":1}`, `nonsense`} {
		if _, err := ParseShardState([]byte(bad)); err == nil {
			t.Fatalf("%q accepted", bad)
		}
	}
	if s, err := ParseShardState(nil); err != nil || len(s) != 0 {
		t.Fatalf("%v %v", s, err)
	}

	// Staleness: shard 3 never passed, shard 5 passed 20 days ago, shard 6
	// yesterday, shard 0 unknown (no record).
	state := ShardState{
		"3/7": {LastAttempt: now, LastResult: "could-not-run"},
		"5/7": {LastAttempt: now, LastSuccess: now.AddDate(0, 0, -20), LastResult: "pass"},
		"6/7": {LastAttempt: now, LastSuccess: now.AddDate(0, 0, -1), LastResult: "pass"},
	}
	r := &Report{}
	r.shardStaleCheck(Options{RederiveAll: true, Shard: Shard{Index: 1, Count: 7}, ShardState: state, Now: now})
	if len(r.Alarms) != 2 || r.alarmKinds[0] != AlarmShardStale || !strings.Contains(r.Alarms[0], "3/7") || !strings.Contains(r.Alarms[1], "5/7") {
		t.Fatalf("%v", r.Alarms)
	}
	// No state: inert.
	r = &Report{}
	r.shardStaleCheck(Options{RederiveAll: true, Shard: Shard{Index: 1, Count: 7}, Now: now})
	if len(r.Alarms) != 0 {
		t.Fatalf("%v", r.Alarms)
	}
}

// F3: least/n picks the shard that went longest without a pass.
func TestLeastShardPicksTheLeastRecentlySuccessful(t *testing.T) {
	now := time.Date(2026, 10, 8, 4, 0, 0, 0, time.UTC)
	sh, err := ParseShard("least/3", now)
	if err != nil || !sh.Least || sh.Count != 3 {
		t.Fatalf("%+v %v", sh, err)
	}
	st := ShardState{
		"0/3": {LastSuccess: now.AddDate(0, 0, -1)},
		"1/3": {LastSuccess: now.AddDate(0, 0, -5)},
		"2/3": {LastSuccess: now.AddDate(0, 0, -2)},
	}
	if got := sh.Resolve(st); got.Index != 1 || got.Count != 3 {
		t.Fatalf("%+v", got)
	}
	// Never succeeded counts as oldest; ties go to the lowest index.
	delete(st, "2/3")
	if got := sh.Resolve(st); got.Index != 2 {
		t.Fatalf("%+v", got)
	}
	if got := sh.Resolve(ShardState{}); got.Index != 0 {
		t.Fatalf("%+v", got)
	}
}

// F9: a changed rule is re-derived whatever the shard, so a tampered changed
// rule fails in every shard of a --rederive-all run.
func TestChangedRuleIsRederivedInEveryShard(t *testing.T) {
	base, head, entries := mechanicalTrees(t, func(entries []map[string]any) { ruleOf(entries[0])["nextAction"] = "Changed." })
	id := ruleID(entries[0])
	src := extract.FixtureReader{Root: servedFixture}
	for i := 0; i < 7; i++ {
		r := runGate(t, Options{Base: base, Head: head, Source: src, RederiveAll: true, Shard: Shard{Index: i, Count: 7}})
		if r.Passed() {
			t.Fatalf("shard %d/7 passed a tampered changed rule", i)
		}
		if c := change(t, r, id); c.OK || !strings.Contains(c.Detail, "differs from what extractor") {
			t.Fatalf("shard %d/7: %+v", i, c)
		}
	}
}

// The CLI reads the shard state, runs the least recently successful shard and
// writes the state back.
func TestCLIShardStateRoundTrip(t *testing.T) {
	_, head, _ := mechanicalTrees(t, nil)
	state := filepath.Join(t.TempDir(), "shards.json")
	now := "2026-10-08T04:00:00Z"
	older := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	seed := ShardState{"0/3": {LastSuccess: older.AddDate(0, 0, 5)}, "1/3": {LastSuccess: older}, "2/3": {LastSuccess: older.AddDate(0, 0, 2)}}
	raw, _ := seed.Marshal()
	if err := os.WriteFile(state, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	code, out := runCLI(t, "verify", "--base", head.Root, "--head", head.Root, "--source", "fixture:"+servedFixture,
		"--rederive-all", "--shard", "least/3", "--shard-state", state, "--now", now, "--json")
	if code != 0 && code != 1 {
		t.Fatalf("exit %d: %s", code, out)
	}
	if !strings.Contains(out, `"shard": "1/3"`) {
		t.Fatalf("the least recently successful shard was not chosen:\n%s", out)
	}
	back, err := os.ReadFile(state)
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseShardState(back)
	if err != nil {
		t.Fatal(err)
	}
	if got["1/3"].LastAttempt.Format(time.RFC3339) != now || got["0/3"].LastAttempt != (time.Time{}) {
		t.Fatalf("%+v", got)
	}
}
