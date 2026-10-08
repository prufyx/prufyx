// SPDX-License-Identifier: AGPL-3.0-only

//go:build aix || darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris

package corpusattest

import (
	"bytes"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// runWithin fails the test when the command blocks (a FIFO that was opened
// for reading would hang forever).
func runWithin(t *testing.T, args []string, root string) (int, string) {
	t.Helper()
	type result struct {
		code int
		err  string
	}
	done := make(chan result, 1)
	go func() {
		var stdout, stderr bytes.Buffer
		code := Run(args, &stdout, &stderr, root)
		done <- result{code, stderr.String()}
	}()
	select {
	case r := <-done:
		return r.code, r.err
	case <-time.After(20 * time.Second):
		t.Fatalf("%v blocked", args)
		return 0, ""
	}
}

// snapshot lists every entry below dir with its size, so a test can prove
// that nothing outside a tree was created, removed or changed.
func snapshot(t *testing.T, dir string) string {
	t.Helper()
	var b strings.Builder
	_ = filepath.Walk(dir, func(p string, info os.FileInfo, err error) error {
		if err == nil {
			rel, _ := filepath.Rel(dir, p)
			b.WriteString(rel + "|" + info.Mode().String() + "|" + strconv.FormatInt(info.Size(), 10) + "\n")
		}
		return nil
	})
	return b.String()
}

// generate --tree and check --tree must not follow a link on the output
// asset or on any directory above it (data/, the pack dir, internal/, cli/),
// and must not hang on a FIFO; nothing outside the tree is touched.
func TestTreeModeNeverFollowsLinksOrBlocks(t *testing.T) {
	type mutation struct {
		name  string
		apply func(t *testing.T, tree, outside string)
	}
	assetRel := filepath.Join("cli", "internal", "cncfcheck", "data", "corpus-attestation.json")
	mutations := []mutation{
		{"symlinked output file", func(t *testing.T, tree, outside string) {
			target := filepath.Join(outside, "victim.json")
			if err := os.WriteFile(target, []byte("victim"), 0o644); err != nil {
				t.Fatal(err)
			}
			asset := filepath.Join(tree, assetRel)
			os.Remove(asset)
			if err := os.Symlink(target, asset); err != nil {
				t.Skip("symlinks unavailable")
			}
		}},
		{"dangling symlinked output file", func(t *testing.T, tree, outside string) {
			asset := filepath.Join(tree, assetRel)
			os.Remove(asset)
			if err := os.Symlink(filepath.Join(outside, "not-yet.json"), asset); err != nil {
				t.Skip("symlinks unavailable")
			}
		}},
		{"FIFO output file", func(t *testing.T, tree, outside string) {
			asset := filepath.Join(tree, assetRel)
			os.Remove(asset)
			if err := syscall.Mkfifo(asset, 0o600); err != nil {
				t.Skip("fifo unavailable")
			}
		}},
	}
	for _, dirRel := range []string{
		filepath.Join("cli", "internal", "cncfcheck", "data"),
		filepath.Join("cli", "internal", "cncfcheck"),
		filepath.Join("cli", "internal"),
		"cli",
	} {
		dirRel := dirRel
		mutations = append(mutations, mutation{"symlinked " + dirRel, func(t *testing.T, tree, outside string) {
			// Move the real directory outside and leave a link to it: the
			// content outside is complete, so only the link itself is wrong.
			real := filepath.Join(outside, "moved")
			link := filepath.Join(tree, dirRel)
			if err := os.Rename(link, real); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(real, link); err != nil {
				t.Skip("symlinks unavailable")
			}
		}})
	}
	for _, m := range mutations {
		m := m
		t.Run(m.name, func(t *testing.T) {
			tree := treeCopy(t)
			outside := t.TempDir()
			m.apply(t, tree, outside)
			before := snapshot(t, outside)
			for _, mode := range []string{"generate", "check"} {
				code, stderr := runWithin(t, []string{mode, "--pack", PackCNCF, "--tree", tree}, "")
				if code == 0 {
					t.Fatalf("%s accepted the tree (stderr=%q)", mode, stderr)
				}
			}
			if snapshot(t, outside) != before {
				t.Fatal("something outside the tree was created, removed or changed")
			}
			if raw, err := os.ReadFile(filepath.Join(outside, "victim.json")); err == nil && string(raw) != "victim" {
				t.Fatalf("a file outside the tree was overwritten: %q", raw)
			}
		})
	}
}

// A FIFO as a pack input is refused without blocking, in both modes.
func TestTreeModeRefusesAFIFOInput(t *testing.T) {
	tree := treeCopy(t)
	rules := filepath.Join(tree, "cli", "internal", "cncfcheck", "data", "rules.json")
	if err := os.Remove(rules); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(rules, 0o600); err != nil {
		t.Skip("fifo unavailable")
	}
	for _, mode := range []string{"generate", "check"} {
		if code, _ := runWithin(t, []string{mode, "--pack", PackCNCF, "--tree", tree}, ""); code == 0 {
			t.Fatalf("%s accepted a FIFO pack", mode)
		}
	}
}

// An explicit --output that is a link or a FIFO is not written through or
// read, without --tree as well.
func TestExplicitOutputIsNotFollowed(t *testing.T) {
	dir := t.TempDir()
	victim := filepath.Join(t.TempDir(), "victim.json")
	if err := os.WriteFile(victim, []byte("victim"), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "out.json")
	if err := os.Symlink(victim, link); err != nil {
		t.Skip("symlinks unavailable")
	}
	for _, mode := range []string{"generate", "check"} {
		if code, _ := runWithin(t, []string{mode, "--output", link}, cliRoot(t)); code == 0 {
			t.Fatalf("%s followed a symlinked --output", mode)
		}
	}
	if raw, _ := os.ReadFile(victim); string(raw) != "victim" {
		t.Fatalf("symlink target overwritten: %q", raw)
	}
	fifo := filepath.Join(dir, "out.fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Skip("fifo unavailable")
	}
	for _, mode := range []string{"generate", "check"} {
		if code, _ := runWithin(t, []string{mode, "--output", fifo}, cliRoot(t)); code == 0 {
			t.Fatalf("%s accepted a FIFO --output", mode)
		}
	}
}

// A FIFO as --tree, --output's directory or --rules is refused at once.
func TestFIFOAsTreeOutputDirOrRulesDoesNotHang(t *testing.T) {
	fifo := filepath.Join(t.TempDir(), "pipe")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Skip("fifo unavailable")
	}
	for _, args := range [][]string{
		{"generate", "--tree", fifo},
		{"check", "--tree", fifo},
		{"generate", "--output", filepath.Join(fifo, "x.json")},
		{"generate", "--rules", fifo},
		{"check", "--rules", fifo},
	} {
		if code, _ := runWithin(t, args, cliRoot(t)); code == 0 {
			t.Fatalf("%v accepted a FIFO", args)
		}
	}
}

// --output naming a directory (trailing slash or existing) is an error and
// writes nothing inside it.
func TestOutputDirectoryIsRefused(t *testing.T) {
	dir := t.TempDir()
	for _, value := range []string{dir + "/", dir, dir + "//"} {
		for _, mode := range []string{"generate", "check"} {
			code, msg := runWithin(t, []string{mode, "--output", value}, cliRoot(t))
			if code == 0 || !strings.Contains(msg, "is a directory") {
				t.Fatalf("%s --output %q: code %d, %q", mode, value, code, msg)
			}
		}
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Fatalf("directory target was written into: %v", entries)
	}
}
