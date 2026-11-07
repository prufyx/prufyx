// SPDX-License-Identifier: AGPL-3.0-only

package knowledgegate

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// mergeRepo builds main (a, b), a branch that edits a only, and a branch
// that edits b only (clean merge) or a too (conflict).
func mergeRepo(t *testing.T) (gitDir, tip, cleanHead, conflictHead string) {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not installed")
	}
	repo := t.TempDir()
	gitIn(t, repo, "init", "-q")
	writeFile(t, filepath.Join(repo, "a.txt"), []byte("a1\n"))
	writeFile(t, filepath.Join(repo, "b.txt"), []byte("b1\n"))
	gitIn(t, repo, "add", "-A")
	gitIn(t, repo, "commit", "-q", "-m", "root")
	root := gitIn(t, repo, "rev-parse", "HEAD")

	gitIn(t, repo, "checkout", "-q", "-b", "clean", root)
	writeFile(t, filepath.Join(repo, "b.txt"), []byte("b2\n"))
	gitIn(t, repo, "commit", "-q", "-am", "clean")
	cleanHead = gitIn(t, repo, "rev-parse", "HEAD")

	gitIn(t, repo, "checkout", "-q", "-b", "conflict", root)
	writeFile(t, filepath.Join(repo, "a.txt"), []byte("a-conflict\n"))
	gitIn(t, repo, "commit", "-q", "-am", "conflict")
	conflictHead = gitIn(t, repo, "rev-parse", "HEAD")

	gitIn(t, repo, "checkout", "-q", "-b", "tip", root)
	writeFile(t, filepath.Join(repo, "a.txt"), []byte("a2\n"))
	gitIn(t, repo, "commit", "-q", "-am", "tip")
	tip = gitIn(t, repo, "rev-parse", "HEAD")
	return filepath.Join(repo, ".git"), tip, cleanHead, conflictHead
}

// The change is gated as it would land on the live tip: a clean merge
// yields a synthetic tree that holds both sides, a conflict fails.
func TestMergeTreeCleanAndConflict(t *testing.T) {
	t.Parallel()
	gitDir, tip, clean, conflict := mergeRepo(t)
	ctx := context.Background()
	tree, err := MergeTree(ctx, ExportOptions{GitDir: gitDir}, tip, clean)
	if err != nil {
		t.Fatal(err)
	}
	if !shaRE.MatchString(tree) {
		t.Fatalf("tree %q", tree)
	}
	out := filepath.Join(t.TempDir(), "merged")
	if err := Export(ctx, ExportOptions{GitDir: gitDir, Tree: tree, Out: out}); err != nil {
		t.Fatal(err)
	}
	for file, want := range map[string]string{"a.txt": "a2\n", "b.txt": "b2\n"} {
		got, err := os.ReadFile(filepath.Join(out, file))
		if err != nil || string(got) != want {
			t.Fatalf("%s = %q, %v (want both sides)", file, got, err)
		}
	}
	if _, err := MergeTree(ctx, ExportOptions{GitDir: gitDir}, tip, conflict); err == nil || !strings.Contains(err.Error(), "conflict") {
		t.Fatalf("a conflicting change must fail the merge, got %v", err)
	}
	for _, bad := range [][2]string{{"main", clean}, {tip, "HEAD"}, {"", clean}, {tip, ""}, {tip, "--help"}} {
		if _, err := MergeTree(ctx, ExportOptions{GitDir: gitDir}, bad[0], bad[1]); err == nil {
			t.Fatalf("merge of %q and %q accepted", bad[0], bad[1])
		}
	}
	if _, err := MergeTree(ctx, ExportOptions{GitDir: gitDir}, tip, otherSHA); err == nil {
		t.Fatal("an unknown commit must fail")
	}
}

func TestExportTreeOptionIsStrict(t *testing.T) {
	t.Parallel()
	gitDir, tip, clean, _ := mergeRepo(t)
	ctx := context.Background()
	out := func() string { return filepath.Join(t.TempDir(), "x") }
	tree := gitIn(t, filepath.Dir(gitDir), "rev-parse", clean+"^{tree}")
	if err := Export(ctx, ExportOptions{GitDir: gitDir, Tree: tree, Out: out()}); err != nil {
		t.Fatal(err)
	}
	// Exactly one of commit and tree; a tree option must name a tree.
	if err := Export(ctx, ExportOptions{GitDir: gitDir, Tree: tree, Commit: clean, Out: out()}); err == nil {
		t.Fatal("commit and tree together accepted")
	}
	if err := Export(ctx, ExportOptions{GitDir: gitDir, Out: out()}); err == nil {
		t.Fatal("neither commit nor tree accepted")
	}
	if err := Export(ctx, ExportOptions{GitDir: gitDir, Tree: tip, Out: out()}); err == nil {
		t.Fatal("a commit id given as a tree accepted")
	}
	if err := Export(ctx, ExportOptions{GitDir: gitDir, Tree: "HEAD^{tree}", Out: out()}); err == nil {
		t.Fatal("a tree expression accepted")
	}
	// CLI: --tree and --commit are exclusive, merge-tree prints the tree.
	code, o := runCLI(t, "merge-tree", "--git-dir", gitDir, "--base", tip, "--head", clean)
	if code != 0 || !shaRE.MatchString(strings.TrimSpace(o)) {
		t.Fatalf("merge-tree: %d %s", code, o)
	}
	if code, o = runCLI(t, "export", "--git-dir", gitDir, "--tree", tree, "--commit", clean, "--out", out()); code != 2 {
		t.Fatalf("both: %d %s", code, o)
	}
	if code, o = runCLI(t, "export", "--git-dir", gitDir, "--tree", tree, "--out", out()); code != 0 {
		t.Fatalf("tree export: %d %s", code, o)
	}
}
