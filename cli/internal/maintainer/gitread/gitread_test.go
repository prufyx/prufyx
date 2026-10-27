// SPDX-License-Identifier: AGPL-3.0-only

package gitread_test

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"reflect"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/maintainer/gitread"
	"github.com/prufyx/prufyx/cli/internal/maintainer/gitread/gitreadtest"
)

func TestTreeAndCommitMatchGit(t *testing.T) {
	repo := gitreadtest.New(t, "acme", "widget")
	r := &gitread.Remote{Base: repo.Base, Dir: t.TempDir()}
	defer r.Close()
	ctx := context.Background()
	tree, err := r.Commit(ctx, "acme", "widget", repo.C1)
	if err != nil {
		t.Fatal(err)
	}
	if want := gitreadtest.Git(t, repo.Root+"/acme/widget", "rev-parse", repo.C1+"^{tree}"); tree != want {
		t.Fatalf("tree %s, want %s", tree, want)
	}
	blob := func(p string) string { return gitreadtest.Git(t, repo.Root+"/acme/widget", "rev-parse", repo.C1+":"+p) }
	docs := blob("docs")
	root, err := r.Tree(ctx, "acme", "widget", tree, false)
	if err != nil {
		t.Fatal(err)
	}
	wantRoot := []gitread.Entry{
		{Path: "README.md", Mode: "100644", Type: "blob", SHA: blob("README.md")},
		{Path: "docs", Mode: "040000", Type: "tree", SHA: docs},
		{Path: "link", Mode: "120000", Type: "blob", SHA: blob("link")},
		{Path: "run.sh", Mode: "100755", Type: "blob", SHA: blob("run.sh")},
		{Path: "vendor", Mode: "040000", Type: "tree", SHA: blob("vendor")},
	}
	if !reflect.DeepEqual(root, wantRoot) {
		t.Fatalf("root listing\n got %+v\nwant %+v", root, wantRoot)
	}
	rec, err := r.Tree(ctx, "acme", "widget", tree, true)
	if err != nil {
		t.Fatal(err)
	}
	var paths []string
	for _, e := range rec {
		paths = append(paths, e.Type+" "+e.Mode+" "+e.Path)
	}
	want := "blob 100644 README.md|tree 040000 docs|blob 100644 docs/a.txt|tree 040000 docs/sub|blob 100644 docs/sub/b.txt|blob 120000 link|blob 100755 run.sh|tree 040000 vendor|commit 160000 vendor/mod"
	if got := strings.Join(paths, "|"); got != want {
		t.Fatalf("recursive listing\n got %s\nwant %s", got, want)
	}
}

func TestKindAndReachable(t *testing.T) {
	repo := gitreadtest.New(t, "acme", "widget")
	r := &gitread.Remote{Base: repo.Base, Dir: t.TempDir()}
	defer r.Close()
	ctx := context.Background()
	if c, p, err := r.Kind(ctx, "acme", "widget", repo.C2); err != nil || !c || p != "" {
		t.Fatalf("commit: %v %q %v", c, p, err)
	}
	if c, p, err := r.Kind(ctx, "acme", "widget", repo.TagObj); err != nil || c || p != repo.C1 {
		t.Fatalf("tag object: %v %q %v", c, p, err)
	}
	if _, _, err := r.Kind(ctx, "acme", "widget", strings.Repeat("a", 40)); err == nil {
		t.Fatal("unknown object must be an error")
	}
	for name, tc := range map[string]struct {
		sha  string
		want bool
	}{"tag commit": {repo.C1, true}, "ancestor": {repo.C2, true}, "tip": {repo.C3, true}, "other branch": {repo.Side, false}} {
		got, err := r.Reachable(ctx, "acme", "widget", tc.sha)
		if err != nil || got != tc.want {
			t.Errorf("%s: got %v, %v want %v", name, got, err, tc.want)
		}
	}
}

func TestFailuresAreErrors(t *testing.T) {
	repo := gitreadtest.New(t, "acme", "widget")
	ctx := context.Background()
	r := &gitread.Remote{Base: repo.Base + "/missing", Dir: t.TempDir()}
	if _, err := r.Commit(ctx, "acme", "widget", repo.C1); err == nil {
		t.Fatal("unreachable remote must be an error")
	}
	if _, err := r.Reachable(ctx, "acme", "widget", repo.C1); err == nil {
		t.Fatal("unreachable remote must not read as not reachable")
	}
	for _, bad := range [][2]string{{"..", "x"}, {"a/b", "x"}, {"-o", "x"}, {"a", ""}} {
		if _, err := r.Commit(ctx, bad[0], bad[1], repo.C1); err == nil {
			t.Errorf("%v accepted", bad)
		}
	}
	capped := &gitread.Remote{Base: repo.Base, Dir: t.TempDir(), MaxCommands: 2}
	_, err := capped.Commit(ctx, "acme", "widget", repo.C1)
	if !errors.Is(err, gitread.ErrCap) {
		t.Fatalf("want ErrCap, got %v", err)
	}
	if _, err := exec.LookPath("git"); err != nil {
		t.Fatal(err)
	}
}

func TestIsIPAllowListRefusal(t *testing.T) {
	for body, want := range map[string]bool{
		`{"message":"Although you appear to have the correct authorization credentials, the ` + "`x`" + ` organization has an IP allow list enabled, and your IP address is not permitted to access this resource."}`: true,
		`{"message":"Resource not accessible by integration"}`: false,
		`{"message":"API rate limit exceeded"}`:                false,
		`not json, IP allow list`:                              true,
		``:                                                     false,
	} {
		if got := gitread.IsIPAllowListRefusal([]byte(body)); got != want {
			t.Errorf("%q: %v", body, got)
		}
	}
}

// gitCommand never runs in the working directory and drops ambient config.
func TestGitCommandIgnoresAmbientConfig(t *testing.T) {
	environ := []string{"PATH=/bin", "HOME=/h", "GIT_DIR=/x", "GIT_CONFIG_COUNT=1", "GIT_CONFIG_KEY_0=http.extraheader", "GIT_CONFIG_VALUE_0=AUTHORIZATION: basic x"}
	argv, env := gitread.GitCommandForTest("/scratch/r.git", environ, []string{"fetch", "--", "u"})
	joined := " " + strings.Join(argv, " ") + " "
	for _, want := range []string{" -C /scratch/r.git ", " http.extraheader= ", " credential.helper= ", " gc.auto=0 ", " fetch.writeCommitGraph=false "} {
		if !strings.Contains(joined, want) {
			t.Errorf("argv lacks %q: %v", want, argv)
		}
	}
	got := map[string]bool{}
	for _, e := range env {
		got[e] = true
		if strings.HasPrefix(e, "GIT_DIR=") || strings.HasPrefix(e, "GIT_CONFIG_KEY") || strings.HasPrefix(e, "GIT_CONFIG_COUNT") || strings.HasPrefix(e, "GIT_CONFIG_VALUE") {
			t.Errorf("inherited %q", e)
		}
	}
	for _, want := range []string{"GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null", "GIT_CONFIG_NOSYSTEM=1", "PATH=/bin"} {
		if !got[want] {
			t.Errorf("env lacks %s", want)
		}
	}
}

// A cwd repository with an http.extraheader must not affect a run.
func TestRunIgnoresCwdRepoConfig(t *testing.T) {
	repo := gitreadtest.New(t, "acme", "widget")
	cwd := t.TempDir()
	gitreadtest.Git(t, cwd, "init", "--quiet")
	gitreadtest.Git(t, cwd, "config", "http.extraheader", "AUTHORIZATION: basic secret")
	old, _ := os.Getwd()
	if err := os.Chdir(cwd); err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(old)
	r := &gitread.Remote{Base: repo.Base, Dir: t.TempDir()}
	defer r.Close()
	if _, err := r.Commit(context.Background(), "acme", "widget", repo.C1); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(cwd + "/.git/objects/" + repo.C1[:2]); err == nil {
		t.Fatal("objects were written into the working directory repository")
	}
}

func TestCommitRejectsTagObject(t *testing.T) {
	repo := gitreadtest.New(t, "acme", "widget")
	r := &gitread.Remote{Base: repo.Base, Dir: t.TempDir()}
	defer r.Close()
	if _, err := r.Commit(context.Background(), "acme", "widget", repo.TagObj); err == nil || !strings.Contains(err.Error(), "not a commit") {
		t.Fatalf("tag object must fail like REST /git/commits: %v", err)
	}
}
