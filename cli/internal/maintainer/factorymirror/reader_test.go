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

func TestReaderReadListAndOfflineGuarantee(t *testing.T) {
	e := newEnv(t, k1)
	u := e.remote[k1]
	c1 := u.commit("one", map[string]string{"README.md": "hello\n", "docs/a.txt": "a\n", "docs/b.txt": "b\n"})
	u.tag("v1", false)
	c2 := u.commit("two", map[string]string{"docs/a.txt": "a2\n", "big/new.txt": "n\n"})

	// First run without wants: trees are local, blobs are not.
	e.run()
	r, err := OpenReader(e.state)
	if err != nil {
		t.Fatal(err)
	}
	entries, err := r.List(k1, c1, "docs")
	if err != nil || len(entries) != 2 || entries[0].Path != "docs/a.txt" || entries[0].Type != "blob" {
		t.Fatalf("list: %+v %v", entries, err)
	}
	if root, err := r.List(k1, c2, ""); err != nil || len(root) != 3 {
		t.Fatalf("root list: %+v %v", root, err)
	}
	if _, err := r.Read(k1, c1, "docs/a.txt"); !errors.Is(err, ErrBlobNotLocal) {
		t.Fatalf("reader must not fetch blobs, got %v", err)
	}
	// The failed read must not have materialized anything.
	if _, err := r.Read(k1, c1, "docs/a.txt"); !errors.Is(err, ErrBlobNotLocal) {
		t.Fatalf("reader fetched lazily: %v", err)
	}

	// The mirror command materializes what is wanted.
	e.opts.Wants = []Want{
		{Repo: k1, Commit: c1, Paths: []string{"docs/a.txt", "README.md", "nope.txt", "docs"}},
		{Repo: k1, Commit: c2, Paths: []string{"docs/a.txt"}},
	}
	e.git.reset()
	res := e.run()
	if len(res.Wants) != 2 {
		t.Fatalf("%+v", res.Wants)
	}
	if res.Wants[0].Complete || len(res.Wants[0].Missing) != 2 || res.Wants[0].Fetched != 2 {
		t.Fatalf("want 0: %+v", res.Wants[0])
	}
	if !res.Wants[1].Complete || res.Wants[1].Fetched != 1 {
		t.Fatalf("want 1: %+v", res.Wants[1])
	}
	if e.git.count("fetch") != 0 {
		t.Fatalf("unexpected fetch: %v", e.git.calls)
	}

	r, _ = OpenReader(e.state)
	for _, tc := range []struct {
		commit, path, want string
	}{{c1, "docs/a.txt", "a\n"}, {c1, "README.md", "hello\n"}, {c2, "docs/a.txt", "a2\n"}} {
		got, err := r.Read(k1, tc.commit, tc.path)
		if err != nil || string(got) != tc.want {
			t.Fatalf("read %s %s: %q %v", tc.commit[:7], tc.path, got, err)
		}
	}
	// docs/b.txt was never requested.
	if _, err := r.Read(k1, c1, "docs/b.txt"); !errors.Is(err, ErrBlobNotLocal) {
		t.Fatalf("want ErrBlobNotLocal, got %v", err)
	}
	if _, err := r.Read(k1, c1, "docs"); !errors.Is(err, ErrNotAFile) {
		t.Fatalf("dir read: %v", err)
	}
	if _, err := r.Read(k1, c1, "missing.txt"); !errors.Is(err, ErrPathNotFound) {
		t.Fatalf("missing: %v", err)
	}
	if _, err := r.Read(k1, "0123456789012345678901234567890123456789", "README.md"); !errors.Is(err, ErrCommitUnknown) {
		t.Fatalf("unknown commit: %v", err)
	}
	if _, err := r.Read(k1, "v1", "README.md"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("tag names are not commits: %v", err)
	}
	for _, bad := range []string{"../x", "/etc/passwd", "a/../b", "a//b", ""} {
		if _, err := r.Read(k1, c1, bad); !errors.Is(err, ErrInvalid) {
			t.Fatalf("path %q accepted: %v", bad, err)
		}
	}
	if _, err := r.Read("github.com/acme/other", c1, "README.md"); !errors.Is(err, ErrRepoNotMirrored) {
		t.Fatalf("unmirrored repo: %v", err)
	}
	if c, err := r.ResolveTag(k1, "v1"); err != nil || c != c1 {
		t.Fatalf("resolve tag: %q %v", c, err)
	}
	if tags, _ := r.Tags(k1); len(tags) != 1 {
		t.Fatalf("tags: %+v", tags)
	}
	if !r.HasCommit(k1, c2) || r.HasCommit(k1, "0123456789012345678901234567890123456789") {
		t.Fatal("HasCommit wrong")
	}
	if rel, err := r.Releases(k1); err != nil || rel.Status != ReleasesUnknown {
		t.Fatalf("releases: %+v %v", rel, err)
	}
}

func TestWantForUnreachableCommitIsFetchedAndPreserved(t *testing.T) {
	e := newEnv(t, k1)
	u := e.remote[k1]
	c1 := u.commit("one", map[string]string{"f": "one\n"})
	c2 := u.commit("two", map[string]string{"f": "two\n"})
	u.resetTo(c1)
	u.commit("rewritten", map[string]string{"f": "three\n"}) // c2 now unreachable upstream refs? push -f below
	_ = c2
	e.run()
	// c2 is unreachable from any ref, but the server allows any SHA in want.
	e.opts.Wants = []Want{{Repo: k1, Commit: c2, Paths: []string{"f"}}}
	res := e.run()
	if len(res.Wants) != 1 || !res.Wants[0].Complete {
		t.Fatalf("%+v", res.Wants)
	}
	r, _ := OpenReader(e.state)
	if got, err := r.Read(k1, c2, "f"); err != nil || string(got) != "two\n" {
		t.Fatalf("%q %v", got, err)
	}
}

func TestWantForUnmirroredRepoFailsSafely(t *testing.T) {
	e := newEnv(t, k1)
	e.remote[k1].commit("one", map[string]string{"f": "x"})
	e.opts.Wants = []Want{{Repo: "github.com/acme/else", Commit: "0123456789012345678901234567890123456789", Paths: []string{"f"}}}
	res := e.run()
	if len(res.Wants) != 1 || res.Wants[0].Complete || res.Wants[0].Error == "" {
		t.Fatalf("%+v", res.Wants)
	}
}

// The default Reader must stay offline even where a lazy fetch would work:
// here the upstream is a local file:// repository with partial-clone filters
// enabled, so an online git would happily download the missing blob.
func TestReaderStaysOfflineWhereLazyFetchWouldSucceed(t *testing.T) {
	e := newEnv(t, k1)
	c1 := e.remote[k1].commit("one", map[string]string{"a.txt": "alpha\n"})
	e.run()

	r, err := OpenReader(e.state)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if _, err := r.Read(k1, c1, "a.txt"); !errors.Is(err, ErrBlobNotLocal) {
			t.Fatalf("offline reader (attempt %d): %v", i, err)
		}
	}
	// Control: the same call with an online runner that allows file://
	// does fetch the blob, so the failure above is the Reader's doing.
	online, err := OpenReader(e.state)
	if err != nil {
		t.Fatal(err)
	}
	online.git = ExecGit{AllowProtocols: "file", StateDir: e.state}
	if got, err := online.Read(k1, c1, "a.txt"); err != nil || string(got) != "alpha\n" {
		t.Fatalf("control (online) read should lazily fetch: %q %v", got, err)
	}
}

// Every git process of the Reader carries all three offline switches.
func TestOfflineRunnerPassesEveryOfflineSwitch(t *testing.T) {
	shim := t.TempDir()
	log := filepath.Join(shim, "log")
	script := "#!/bin/sh\n{ echo \"ARGS $*\"; env | grep -E '^GIT_(NO_LAZY_FETCH|ALLOW_PROTOCOL)=' | sed 's/^/ENV /'; } >> '" + log + "'\nexit 0\n"
	if err := os.WriteFile(filepath.Join(shim, "git"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", shim+string(os.PathListSeparator)+os.Getenv("PATH"))
	if _, err := (ExecGit{Offline: true, AllowProtocols: "https"}).Run(context.Background(), t.TempDir(), "cat-file", "-p", "HEAD"); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(log)
	if err != nil {
		t.Fatal(err)
	}
	got := string(raw)
	if !strings.Contains(got, "ARGS -c protocol.allow=never cat-file -p HEAD") {
		t.Fatalf("protocol.allow=never missing: %s", got)
	}
	if !strings.Contains(got, "ENV GIT_NO_LAZY_FETCH=1") {
		t.Fatalf("GIT_NO_LAZY_FETCH missing: %s", got)
	}
	if !strings.Contains(got, "ENV GIT_ALLOW_PROTOCOL=none") || strings.Contains(got, "GIT_ALLOW_PROTOCOL=https") {
		t.Fatalf("GIT_ALLOW_PROTOCOL must be none: %s", got)
	}
}

func TestOpenReaderUsesTheOfflineRunner(t *testing.T) {
	r, err := OpenReader(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	g, ok := r.git.(ExecGit)
	if !ok || !g.Offline {
		t.Fatalf("reader runner is not offline: %#v", r.git)
	}
}
