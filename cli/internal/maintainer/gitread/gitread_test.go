// SPDX-License-Identifier: AGPL-3.0-only

package gitread_test

import (
	"context"
	"errors"
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
