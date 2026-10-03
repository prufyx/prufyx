// SPDX-License-Identifier: AGPL-3.0-only

//go:build darwin || linux

package fix

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"testing"
)

const applySource = "apiVersion: batch/v1beta1 # keep\nkind: CronJob\nmetadata:\n  name: job\n"

var applyRequests = []Request{setRequest("value", "batch/v1beta1", "batch/v1", "apiVersion")}

// workspace creates root/manifests/job.yaml with the given mode and returns
// the root, the file path and the plan for it.
func workspace(t *testing.T, mode os.FileMode) (string, string, FilePlan) {
	t.Helper()
	root := t.TempDir()
	dir := filepath.Join(root, "manifests")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(dir, "job.yaml")
	writeMode(t, file, applySource, mode)
	plan, err := Plan("manifests/job.yaml", []byte(applySource), applyRequests, Options{})
	if err != nil {
		t.Fatal(err)
	}
	return root, file, plan
}

func writeMode(t *testing.T, file, content string, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(file, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(file, mode); err != nil {
		t.Fatal(err)
	}
}

// listing returns every entry below root with its content, to prove that a
// refused apply wrote nothing.
func listing(t *testing.T, root string) string {
	t.Helper()
	var entries []string
	_ = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		entry := strings.TrimPrefix(path, root) + " " + info.Mode().String()
		if info.Mode().IsRegular() {
			content, _ := os.ReadFile(path)
			entry += " " + string(content)
		}
		entries = append(entries, entry)
		return nil
	})
	sort.Strings(entries)
	return strings.Join(entries, "\n")
}

func TestApplyFileSafety(t *testing.T) {
	t.Run("writes and keeps mode", func(t *testing.T) {
		for _, mode := range []os.FileMode{0o600, 0o640, 0o644, 0o400, 0o755} {
			root, file, plan := workspace(t, mode)
			results := Apply([]Target{{Path: file, Plan: plan}}, ApplyOptions{Roots: []string{root}})
			if results[0].Err != nil || !results[0].Written {
				t.Fatalf("mode %v: %+v", mode, results[0])
			}
			content, _ := os.ReadFile(file)
			if string(content) != strings.Replace(applySource, "batch/v1beta1", "batch/v1", 1) {
				t.Fatalf("content %q", content)
			}
			info, _ := os.Lstat(file)
			if info.Mode() != mode {
				t.Fatalf("mode %v, want %v", info.Mode(), mode)
			}
			entries, _ := os.ReadDir(filepath.Dir(file))
			if len(entries) != 1 {
				t.Fatalf("leftover files: %v", entries)
			}
			if results[0].Diff == "" {
				t.Fatal("no diff reported")
			}
		}
	})

	refusals := []struct {
		name  string
		setup func(t *testing.T, root, file string) (string, ApplyOptions)
		want  Reason
	}{
		{name: "symlink file", want: ReasonUnsafeFile, setup: func(t *testing.T, root, file string) (string, ApplyOptions) {
			real := filepath.Join(root, "real.yaml")
			if err := os.Rename(file, real); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(real, file); err != nil {
				t.Fatal(err)
			}
			return file, ApplyOptions{Roots: []string{root}}
		}},
		{name: "symlinked directory", want: ReasonUnsafeFile, setup: func(t *testing.T, root, file string) (string, ApplyOptions) {
			link := filepath.Join(root, "linked")
			if err := os.Symlink(filepath.Join(root, "manifests"), link); err != nil {
				t.Fatal(err)
			}
			return filepath.Join(link, "job.yaml"), ApplyOptions{Roots: []string{root}}
		}},
		{name: "group writable", want: ReasonUnsafeFile, setup: func(t *testing.T, root, file string) (string, ApplyOptions) {
			chmod(t, file, 0o664)
			return file, ApplyOptions{Roots: []string{root}}
		}},
		{name: "other writable", want: ReasonUnsafeFile, setup: func(t *testing.T, root, file string) (string, ApplyOptions) {
			chmod(t, file, 0o646)
			return file, ApplyOptions{Roots: []string{root}}
		}},
		{name: "setuid bit", want: ReasonUnsafeFile, setup: func(t *testing.T, root, file string) (string, ApplyOptions) {
			chmod(t, file, 0o644|os.ModeSetuid)
			return file, ApplyOptions{Roots: []string{root}}
		}},
		{name: "hard link", want: ReasonUnsafeFile, setup: func(t *testing.T, root, file string) (string, ApplyOptions) {
			if err := os.Link(file, filepath.Join(root, "other.yaml")); err != nil {
				t.Fatal(err)
			}
			return file, ApplyOptions{Roots: []string{root}}
		}},
		{name: "fifo", want: ReasonUnsafeFile, setup: func(t *testing.T, root, file string) (string, ApplyOptions) {
			fifo := filepath.Join(root, "manifests", "pipe.yaml")
			if err := syscall.Mkfifo(fifo, 0o600); err != nil {
				t.Fatal(err)
			}
			return fifo, ApplyOptions{Roots: []string{root}}
		}},
		{name: "directory", want: ReasonUnsafeFile, setup: func(t *testing.T, root, file string) (string, ApplyOptions) {
			return filepath.Join(root, "manifests"), ApplyOptions{Roots: []string{root}}
		}},
		{name: "outside roots", want: ReasonOutsideRoots, setup: func(t *testing.T, root, file string) (string, ApplyOptions) {
			other := filepath.Join(root, "other")
			if err := os.Mkdir(other, 0o755); err != nil {
				t.Fatal(err)
			}
			return file, ApplyOptions{Roots: []string{other}}
		}},
		{name: "dot dot escapes root", want: ReasonOutsideRoots, setup: func(t *testing.T, root, file string) (string, ApplyOptions) {
			other := filepath.Join(root, "other")
			if err := os.Mkdir(other, 0o755); err != nil {
				t.Fatal(err)
			}
			return filepath.Join(other, "..", "manifests", "job.yaml"), ApplyOptions{Roots: []string{other}}
		}},
		{name: "root name prefix", want: ReasonOutsideRoots, setup: func(t *testing.T, root, file string) (string, ApplyOptions) {
			return file, ApplyOptions{Roots: []string{filepath.Join(root, "manif")}}
		}},
		{name: "no roots", want: ReasonOutsideRoots, setup: func(t *testing.T, root, file string) (string, ApplyOptions) {
			return file, ApplyOptions{}
		}},
		{name: "digest mismatch", want: ReasonFileChanged, setup: func(t *testing.T, root, file string) (string, ApplyOptions) {
			writeMode(t, file, applySource+"# edited\n", 0o644)
			return file, ApplyOptions{Roots: []string{root}}
		}},
		{name: "missing file", want: ReasonUnsafeFile, setup: func(t *testing.T, root, file string) (string, ApplyOptions) {
			return filepath.Join(root, "manifests", "absent.yaml"), ApplyOptions{Roots: []string{root}}
		}},
	}
	for _, tc := range refusals {
		t.Run(tc.name, func(t *testing.T) {
			root, file, plan := workspace(t, 0o644)
			target, opts := tc.setup(t, root, file)
			before := listing(t, root)
			results := Apply([]Target{{Path: target, Plan: plan}}, opts)
			if got := ReasonOf(results[0].Err); got != tc.want || results[0].Written {
				t.Fatalf("result %+v, want %s", results[0], tc.want)
			}
			if after := listing(t, root); after != before {
				t.Fatalf("files changed:\n%s\n---\n%s", before, after)
			}
		})
	}

	t.Run("secret file with forged plan", func(t *testing.T) {
		root := t.TempDir()
		file := filepath.Join(root, "s.yaml")
		secret := "apiVersion: v1\nkind: Secret\nmetadata:\n  name: s\n"
		writeMode(t, file, secret, 0o600)
		plan := FilePlan{Display: "s.yaml", Digest: digestOf([]byte(secret)), Edits: []Edit{{File: "s.yaml", StartByte: 37, EndByte: 38, Replacement: "t"}}}
		results := Apply([]Target{{Path: file, Plan: plan}}, ApplyOptions{Roots: []string{root}})
		if ReasonOf(results[0].Err) != ReasonSecretDocument {
			t.Fatalf("%+v", results[0])
		}
		if content, _ := os.ReadFile(file); string(content) != secret {
			t.Fatal("secret file changed")
		}
	})

	failures := []struct {
		name string
		hook func(t *testing.T, file string) func(*os.File, string) error
		want Reason
	}{
		{name: "rename fails", want: ReasonWriteFailed, hook: func(t *testing.T, file string) func(*os.File, string) error {
			return func(*os.File, string) error { return errors.New("injected") }
		}},
		{name: "content changes before rename", want: ReasonFileChanged, hook: func(t *testing.T, file string) func(*os.File, string) error {
			return func(*os.File, string) error {
				f, err := os.OpenFile(file, os.O_WRONLY|os.O_APPEND, 0)
				if err != nil {
					return err
				}
				_, err = f.WriteString("# concurrent\n")
				_ = f.Close()
				return err
			}
		}},
		{name: "file replaced before rename", want: ReasonFileChanged, hook: func(t *testing.T, file string) func(*os.File, string) error {
			return func(*os.File, string) error {
				other := file + ".new"
				if err := os.WriteFile(other, []byte(applySource), 0o644); err != nil {
					return err
				}
				return os.Rename(other, file)
			}
		}},
		{name: "file swapped for symlink before rename", want: ReasonFileChanged, hook: func(t *testing.T, file string) func(*os.File, string) error {
			return func(*os.File, string) error {
				if err := os.Remove(file); err != nil {
					return err
				}
				return os.Symlink("/etc/hosts", file)
			}
		}},
	}
	for _, tc := range failures {
		t.Run(tc.name, func(t *testing.T) {
			root, file, plan := workspace(t, 0o644)
			original := beforeRename
			beforeRename = tc.hook(t, file)
			defer func() { beforeRename = original }()
			results := Apply([]Target{{Path: file, Plan: plan}}, ApplyOptions{Roots: []string{root}})
			if ReasonOf(results[0].Err) != tc.want || results[0].Written {
				t.Fatalf("%+v", results[0])
			}
			entries, _ := os.ReadDir(filepath.Dir(file))
			for _, entry := range entries {
				if strings.Contains(entry.Name(), ".prufyx-") {
					t.Fatalf("temporary file left behind: %s", entry.Name())
				}
			}
			if content, err := os.ReadFile(file); err == nil && bytes.Contains(content, []byte("batch/v1 ")) {
				t.Fatal("the fix was written")
			}
		})
	}

	t.Run("batch reports per file", func(t *testing.T) {
		root, file, plan := workspace(t, 0o644)
		bad := filepath.Join(root, "manifests", "bad.yaml")
		writeMode(t, bad, applySource, 0o666)
		results := Apply([]Target{{Path: bad, Plan: plan}, {Path: file, Plan: plan}}, ApplyOptions{Roots: []string{root}})
		if ReasonOf(results[0].Err) != ReasonUnsafeFile || results[1].Err != nil || !results[1].Written {
			t.Fatalf("%+v", results)
		}
		if content, _ := os.ReadFile(bad); string(content) != applySource {
			t.Fatal("refused file changed")
		}
	})
	t.Run("same file twice", func(t *testing.T) {
		root, file, plan := workspace(t, 0o644)
		before := listing(t, root)
		results := Apply([]Target{{Path: file, Plan: plan}, {Path: filepath.Join(root, "manifests", ".", "job.yaml"), Plan: plan}}, ApplyOptions{Roots: []string{root}})
		if ReasonOf(results[0].Err) != ReasonConflictingEdits || ReasonOf(results[1].Err) != ReasonConflictingEdits {
			t.Fatalf("%+v", results)
		}
		if listing(t, root) != before {
			t.Fatal("files changed")
		}
	})
	t.Run("nothing to change", func(t *testing.T) {
		root, file, _ := workspace(t, 0o644)
		plan, err := Plan("manifests/job.yaml", []byte(applySource), nil, Options{})
		if err != nil {
			t.Fatal(err)
		}
		results := Apply([]Target{{Path: file, Plan: plan}}, ApplyOptions{Roots: []string{root}})
		if results[0].Err != nil || results[0].Written {
			t.Fatalf("%+v", results[0])
		}
	})
}

func chmod(t *testing.T, file string, mode os.FileMode) {
	t.Helper()
	if err := os.Chmod(file, mode); err != nil {
		t.Fatal(err)
	}
}
