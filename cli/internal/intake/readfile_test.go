// SPDX-License-Identifier: AGPL-3.0-only

package intake

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// TestReadFileAccepts: a private regular file is read whole, undecoded, with
// its digest and the policy result.
func TestReadFileAccepts(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "values.yaml")
	if err := os.WriteFile(path, []byte("a: 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	record, raw, err := ReadFile(path, Options{Permissions: Strict})
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != "a: 1\n" || record.Size != 5 || record.Policy != ModePrivate || !strings.HasPrefix(record.Digest, "sha256:") || record.Display != path {
		t.Fatalf("record %+v", record)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if record, _, err := ReadFile(path, Options{Permissions: RefuseWritable}); err != nil || record.Policy != ModeReadableByOthers {
		t.Fatalf("readable by others: %+v %v", record, err)
	}
}

// TestReadFileRefuses (the zero Options are Strict): everything but one regular file the policy admits,
// within the byte bound, is refused, and nothing is returned.
func TestReadFileRefuses(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string, mode os.FileMode) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(content), mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
		return path
	}
	target := write("target.yaml", "a: 1\n", 0o600)
	link := filepath.Join(dir, "link.yaml")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	sub := filepath.Join(dir, "sub")
	if err := os.Mkdir(sub, 0o700); err != nil {
		t.Fatal(err)
	}
	big := write("big.yaml", strings.Repeat("a", 65), 0o600)
	writable := write("writable.yaml", "a: 1\n", 0o622)
	group := write("group.yaml", "a: 1\n", 0o640)

	for name, tc := range map[string]struct {
		path string
		opts Options
		want error
		text string
	}{
		"symlink":            {link, Options{}, ErrInput, "symlink"},
		"directory":          {sub, Options{}, ErrInput, "not a regular file"},
		"over the bound":     {big, Options{Limits: Limits{FileBytes: 64}}, ErrLimit, "more than 64 bytes per file"},
		"stdin":              {"-", Options{}, ErrInput, "empty or invalid path"},
		"empty":              {"", Options{}, ErrInput, "empty or invalid path"},
		"nul in path":        {target + "\x00x", Options{}, ErrInput, "empty or invalid path"},
		"missing":            {filepath.Join(dir, "missing.yaml"), Options{}, ErrInput, ""},
		"writable by others": {writable, Options{Permissions: RefuseWritable}, ErrPermissions, "writable by group or other"},
		"strict group read":  {group, Options{Permissions: Strict}, ErrPermissions, "accessible by group or other"},
	} {
		record, raw, err := ReadFile(tc.path, tc.opts)
		if !errors.Is(err, tc.want) || !strings.Contains(err.Error(), tc.text) || raw != nil || record != (FileRecord{}) {
			t.Errorf("%s: %+v %q %v", name, record, raw, err)
		}
	}
	// The bound itself is accepted.
	if _, raw, err := ReadFile(big, Options{Limits: Limits{FileBytes: 65}}); err != nil || len(raw) != 65 {
		t.Fatalf("at the bound: %d %v", len(raw), err)
	}
}

// TestReadFileFIFO: a named pipe is refused before it is opened, so the
// read never blocks.
func TestReadFileFIFO(t *testing.T) {
	fifo := filepath.Join(t.TempDir(), "values.yaml")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Skipf("no named pipes here: %v", err)
	}
	if _, raw, err := ReadFile(fifo, Options{}); !errors.Is(err, ErrInput) || !strings.Contains(err.Error(), "not a regular file") || raw != nil {
		t.Fatalf("fifo: %v", err)
	}
}

// TestReadFileStrictOwnerAndLinks: under Strict a file owned by another
// user, or with more than one hard link, is refused.
func TestReadFileStrictOwnerAndLinks(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "values.yaml")
	if err := os.WriteFile(path, []byte("a: 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	real := effectiveUID
	effectiveUID = func() uint64 { return real() + 1 }
	_, _, err := ReadFile(path, Options{Permissions: Strict})
	effectiveUID = real
	if !errors.Is(err, ErrPermissions) || !strings.Contains(err.Error(), "owned by another user") {
		t.Fatalf("owner: %v", err)
	}
	if _, _, err := ReadFile(path, Options{Permissions: RefuseWritable}); err != nil {
		t.Fatalf("refuse-writable checks no owner: %v", err)
	}
	if err := os.Link(path, filepath.Join(dir, "other.yaml")); err != nil {
		t.Skipf("no hard links here: %v", err)
	}
	if _, _, err := ReadFile(path, Options{Permissions: Strict}); !errors.Is(err, ErrPermissions) || !strings.Contains(err.Error(), "hard link") {
		t.Fatalf("hard link: %v", err)
	}
}
