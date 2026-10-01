// SPDX-License-Identifier: AGPL-3.0-only

package factorymirror

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type env struct {
	t      *testing.T
	root   string
	state  string
	git    *countingGit
	opts   Options
	remote map[string]*upstream
}

func newEnv(t *testing.T, keys ...string) *env {
	t.Helper()
	requireGit(t)
	e := &env{t: t, root: t.TempDir(), state: filepath.Join(t.TempDir(), "state"), git: newCountingGit(), remote: map[string]*upstream{}}
	var repos []Repo
	for _, k := range keys {
		e.remote[k] = newUpstream(t, e.root, k)
		repos = append(repos, mustRepo(t, k))
	}
	e.opts = Options{StateDir: e.state, Repos: repos, RemoteBase: fileBase(e.root), Git: e.git, Now: fixedNow(), Concurrency: 2}
	return e
}

func (e *env) run() *Result {
	e.t.Helper()
	res, err := Run(context.Background(), e.opts)
	if err != nil {
		e.t.Fatalf("Run: %v", err)
	}
	return res
}

func (e *env) index() *Index {
	e.t.Helper()
	idx, err := LoadIndex(e.state)
	if err != nil {
		e.t.Fatal(err)
	}
	return idx
}

const k1 = "github.com/acme/widget"

func TestFreshRunClonesAndIndexesTags(t *testing.T) {
	e := newEnv(t, k1, "github.com/acme/gadget")
	c1 := e.remote[k1].commit("one", map[string]string{"README.md": "hello\n", "docs/a.txt": "a\n"})
	e.remote[k1].tag("v1.0.0", false)
	c2 := e.remote[k1].commit("two", map[string]string{"README.md": "hello2\n"})
	e.remote[k1].tag("v1.1.0", true)
	e.remote["github.com/acme/gadget"].commit("g", map[string]string{"x": "1"})

	res := e.run()
	if res.Cloned != 2 || res.Failed != 0 || res.NewAlarms != 0 {
		t.Fatalf("unexpected result %+v", res)
	}
	info := e.index().Repos[k1]
	if info == nil || info.Status != "ok" || info.Tags["v1.0.0"].Commit != c1 || info.Tags["v1.1.0"].Commit != c2 {
		t.Fatalf("bad tag index: %+v", info)
	}
	if info.Tags["v1.1.0"].Object == "" || info.Tags["v1.0.0"].Object != "" {
		t.Fatalf("annotated/lightweight object tracking wrong: %+v", info.Tags)
	}
	if info.Heads["main"] != c2 {
		t.Fatalf("head not recorded: %+v", info.Heads)
	}
	if info.Releases.Status != ReleasesUnknown || info.Releases.Reason != ReasonNoToken {
		t.Fatalf("releases must be unknown without a token: %+v", info.Releases)
	}
	if _, err := os.Stat(filepath.Join(e.state, "mirror", "github.com", "acme", "widget.git", "HEAD")); err != nil {
		t.Fatal(err)
	}
	// the clone is partial
	cfg := runGit(t, filepath.Join(e.state, "mirror", "github.com", "acme", "widget.git"), "config", "--get", "remote.origin.partialclonefilter")
	if cfg != "blob:none" {
		t.Fatalf("clone is not blobless: %q", cfg)
	}
}

func TestSecondRunWithoutUpstreamChangeDoesNotFetch(t *testing.T) {
	e := newEnv(t, k1)
	e.remote[k1].commit("one", map[string]string{"a": "1"})
	e.remote[k1].tag("v1", false)
	e.run()
	e.git.reset()
	res := e.run()
	if res.Unchanged != 1 || res.Cloned+res.Fetched != 0 {
		t.Fatalf("expected unchanged: %+v", res)
	}
	if e.git.count("clone") != 0 || e.git.count("fetch") != 0 {
		t.Fatalf("network fetch happened: %v", e.git.calls)
	}
	if e.git.count("ls-remote") != 1 {
		t.Fatalf("expected exactly one ls-remote, got %v", e.git.calls)
	}
}

func TestUpstreamChangeTriggersFetchAndKeepsHistory(t *testing.T) {
	e := newEnv(t, k1)
	e.remote[k1].commit("one", map[string]string{"a": "1"})
	e.remote[k1].tag("v1", false)
	e.run()
	e.git.reset()
	c2 := e.remote[k1].commit("two", map[string]string{"a": "2"})
	e.remote[k1].tag("v2", false)
	res := e.run()
	if res.Fetched != 1 || e.git.count("fetch") != 1 || e.git.count("clone") != 0 {
		t.Fatalf("expected one fetch: %+v %v", res, e.git.calls)
	}
	if got := e.index().Repos[k1].Tags["v2"].Commit; got != c2 {
		t.Fatalf("new tag not indexed: %q", got)
	}
	if res.NewAlarms != 0 {
		t.Fatal("a new tag is not an alarm")
	}
}

func TestTagMutationRaisesAlarmFreezesAndPreservesOldCommit(t *testing.T) {
	e := newEnv(t, k1)
	u := e.remote[k1]
	c1 := u.commit("one", map[string]string{"f.txt": "original\n"})
	u.tag("v1.0.0", false)
	u.tag("v0.9.0", false)
	e.opts.Wants = []Want{{Repo: k1, Commit: c1, Paths: []string{"f.txt"}}}
	e.run()
	e.opts.Wants = nil

	// Move v1.0.0 to a different commit, then also delete v0.9.0.
	c2 := u.commit("two", map[string]string{"f.txt": "changed\n"})
	u.tag("v1.0.0", false)
	u.deleteTag("v0.9.0")
	res := e.run()
	if res.NewAlarms != 2 || res.OpenAlarms != 2 {
		t.Fatalf("expected 2 alarms: %+v", res)
	}
	idx := e.index()
	var moved *Alarm
	for i := range idx.Alarms {
		if idx.Alarms[i].Kind == AlarmTagMoved {
			moved = &idx.Alarms[i]
		}
	}
	if moved == nil || moved.Tag != "v1.0.0" || moved.OldCommit != c1 || moved.NewCommit != c2 || moved.Acknowledged {
		t.Fatalf("bad moved alarm: %+v", idx.Alarms)
	}
	if !idx.Repos[k1].Frozen {
		t.Fatal("repository must be frozen")
	}
	// A further run must not duplicate the alarm and stays frozen.
	res = e.run()
	if res.NewAlarms != 0 || len(e.index().Alarms) != 2 {
		t.Fatalf("alarm duplicated: %+v", e.index().Alarms)
	}
	// The pinned bytes of the old commit stay readable offline.
	r, err := OpenReader(e.state)
	if err != nil {
		t.Fatal(err)
	}
	got, err := r.Read(k1, c1, "f.txt")
	if err != nil || string(got) != "original\n" {
		t.Fatalf("old commit unreadable: %q %v", got, err)
	}
	if frozen, _ := r.Frozen(k1); !frozen {
		t.Fatal("reader must report frozen")
	}
	// Acknowledgement lifts the freeze and survives the next run.
	if _, err := Acknowledge(e.state, k1, "", "reviewed upstream announcement", fixedNow()); err != nil {
		t.Fatal(err)
	}
	e.run()
	idx = e.index()
	if idx.Repos[k1].Frozen || len(idx.OpenAlarms()) != 0 || len(idx.Alarms) != 2 {
		t.Fatalf("ack failed: %+v", idx)
	}
	if _, err := Acknowledge(e.state, k1, "", "again", fixedNow()); err == nil {
		t.Fatal("acknowledging nothing must fail")
	}
}

func TestAnnotatedRetagToSameCommitIsNotAMutation(t *testing.T) {
	e := newEnv(t, k1)
	u := e.remote[k1]
	u.commit("one", map[string]string{"a": "1"})
	u.tag("v1", true)
	e.run()
	u.tag("v1", true) // new tag object, same commit
	res := e.run()
	if res.NewAlarms != 0 || res.Fetched != 1 {
		t.Fatalf("%+v", res)
	}
}

func TestFailureIsRecordedAndNextRunResumes(t *testing.T) {
	e := newEnv(t, k1, "github.com/acme/gadget")
	e.remote[k1].commit("one", map[string]string{"a": "1"})
	e.remote["github.com/acme/gadget"].commit("g", map[string]string{"b": "1"})
	e.git.failFirst = func(args []string) bool {
		return args[0] == "clone" && strings.Contains(strings.Join(args, " "), "widget")
	}
	e.opts.Concurrency = 1
	res := e.run()
	if res.Failed != 1 || res.Cloned != 1 {
		t.Fatalf("expected one failure, one clone: %+v", res)
	}
	idx := e.index()
	if idx.Repos[k1].Status != "error" || idx.Repos[k1].RemoteFingerprint != "" {
		t.Fatalf("failed repo must not look fetched: %+v", idx.Repos[k1])
	}
	if _, err := os.Stat(filepath.Join(e.state, "mirror", "github.com", "acme", "widget.git.partial")); err == nil {
		t.Fatal("partial clone left behind")
	}
	e.git.reset()
	res = e.run()
	if res.Failed != 0 || res.Cloned != 1 || res.Unchanged != 1 || e.git.count("clone") != 1 {
		t.Fatalf("resume wrong: %+v %v", res, e.git.calls)
	}
}

func TestStaleLeftoverPartialCloneIsReplaced(t *testing.T) {
	e := newEnv(t, k1)
	e.remote[k1].commit("one", map[string]string{"a": "1"})
	junk := filepath.Join(e.state, "mirror", "github.com", "acme", "widget.git.partial")
	if err := os.MkdirAll(junk, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(junk, "junk"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if res := e.run(); res.Cloned != 1 {
		t.Fatalf("%+v", res)
	}
	if _, err := os.Stat(junk); err == nil {
		t.Fatal("leftover remained")
	}
}

func TestConcurrencyIsBounded(t *testing.T) {
	keys := []string{"github.com/a/r1", "github.com/a/r2", "github.com/a/r3", "github.com/a/r4", "github.com/a/r5", "github.com/a/r6"}
	e := newEnv(t, keys...)
	for _, k := range keys {
		e.remote[k].commit("c", map[string]string{"f": k})
	}
	e.git.delay = 30e6
	e.opts.Concurrency = 3
	res := e.run()
	if res.Cloned != 6 {
		t.Fatalf("%+v", res)
	}
	if e.git.max > 3 || e.git.max < 2 {
		t.Fatalf("max concurrent git commands = %d, want 2..3", e.git.max)
	}
}

func TestSecondRunIsLockedOut(t *testing.T) {
	e := newEnv(t, k1)
	e.remote[k1].commit("one", map[string]string{"a": "1"})
	lock, err := AcquireLock(filepath.Join(e.state, "locks", "mirror.lock"), 0, e.opts.Now)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Release()
	if _, err := Run(context.Background(), e.opts); !errors.Is(err, ErrLocked) {
		t.Fatalf("want ErrLocked, got %v", err)
	}
}

func TestUnreachableRemoteIsReportedNotFatal(t *testing.T) {
	e := newEnv(t, k1)
	e.opts.Repos = append(e.opts.Repos, mustRepo(t, "github.com/acme/missing"))
	e.remote[k1].commit("one", map[string]string{"a": "1"})
	res := e.run()
	if res.Cloned != 1 || res.Failed != 1 {
		t.Fatalf("%+v", res)
	}
	for _, r := range res.Repos {
		if strings.Contains(r.Error, e.root) {
			t.Fatalf("remote URL leaked in error: %q", r.Error)
		}
	}
}

func TestScrubRemovesTheRemoteFromErrorText(t *testing.T) {
	url := "https://github.com/acme/widget.git"
	for _, msg := range []string{
		"git ls-remote: exit status 128: fatal: unable to access 'https://github.com/acme/widget.git/': could not resolve host",
		"fatal: repository 'https://github.com/acme/widget.git' not found",
		"fatal: 'github.com/acme/widget' does not appear to be a git repository",
		"remote: Repository not found at https://github.com/acme/widget.git twice https://github.com/acme/widget.git",
	} {
		got := scrub(msg, url)
		if strings.Contains(got, "acme/widget") || !strings.Contains(got, "<remote>") {
			t.Fatalf("scrub(%q) = %q", msg, got)
		}
	}
	// The whole remote is replaced, scheme and suffix included.
	if got := scrub("fatal: repository 'https://github.com/acme/widget.git' not found", url); got != "fatal: repository '<remote>' not found" {
		t.Fatalf("%q", got)
	}
	if got := scrub("unrelated failure", url); got != "unrelated failure" {
		t.Fatalf("%q", got)
	}
}

func TestFailedRunsNeverLeakTheRemoteInTheIndex(t *testing.T) {
	e := newEnv(t, k1)
	e.opts.Repos = []Repo{mustRepo(t, "github.com/acme/missing"), mustRepo(t, k1)}
	e.remote[k1].commit("one", map[string]string{"a": "1"})
	e.git.failFirst = func(args []string) bool { return args[0] == "clone" }
	e.run()
	e.run()
	raw, err := os.ReadFile(filepath.Join(e.state, "mirror-index.json"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), e.root) {
		t.Fatalf("remote location persisted in the index: %s", raw)
	}
	if msg := e.index().Repos["github.com/acme/missing"].Error; !strings.Contains(msg, "<remote>") {
		t.Fatalf("expected a scrubbed error in the index: %q", msg)
	}
}
