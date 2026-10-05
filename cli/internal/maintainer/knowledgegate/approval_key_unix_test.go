// SPDX-License-Identifier: AGPL-3.0-only

//go:build darwin || linux

package knowledgegate

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// A key file owned by another user is refused even with mode 0600.
func TestApprovalSignKeyFileOwner(t *testing.T) {
	f := newRuleFixture(t)
	path := f.key.keyFile(t, 0o600)
	defer func(orig func() int) { currentUID = orig }(currentUID)
	currentUID = func() int { return os.Getuid() + 1 }
	requireCode(t, runApproval(t, nil, signNow, f.signArgs("--key", path)...), 2, "not owned by the current user")
}

// --key-stdin takes only a pipe: a terminal or other device would echo the
// key, and a regular file redirected to standard input would skip the
// checks --key applies to files.
func TestCheckKeyStdin(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()
	if err := checkKeyStdin(r); err != nil {
		t.Fatalf("pipe refused: %v", err)
	}
	devNull, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer devNull.Close()
	file, err := os.Open(newApprovalKey(t).keyFile(t, 0o600))
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	for name, tc := range map[string]struct {
		in   io.Reader
		want string
	}{
		"device":       {devNull, "not a terminal or device"},
		"regular file": {file, "not a file; give the file with --key FILE"},
		"not a file":   {bytes.NewReader(nil), "standard input is not one"},
	} {
		if err := checkKeyStdin(tc.in); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Fatalf("%s: %v", name, err)
		}
	}
}

// The production standard-input check, end to end: a key piped in signs; the
// same key file redirected to standard input is refused.
func TestApprovalSignKeyStdinProductionCheck(t *testing.T) {
	run := func(stdin *os.File, f signFixture) approvalRun {
		var out, errOut bytes.Buffer
		env := approvalEnv{stdin: stdin, now: func() time.Time { return signNow }, checkStdin: checkKeyStdin}
		code := approvalMain(f.signArgs("--key-stdin"), env, DefaultLayout(), &out, &errOut)
		return approvalRun{code, out.String(), errOut.String()}
	}
	f := newRuleFixture(t)
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	go func() { _, _ = w.Write(f.key.pemKey(t)); _ = w.Close() }()
	requireCode(t, run(r, f), 0, "approval written")
	_ = r.Close()

	g := newRuleFixture(t)
	file, err := os.Open(g.key.keyFile(t, 0o644))
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	requireCode(t, run(file, g), 2, "not a file")
}

// The approval is written as a new file with mode 0644 whatever the umask,
// missing directories are created, and no directory of the output path may
// be a symbolic link.
func TestApprovalSignOutputFile(t *testing.T) {
	old := syscall.Umask(0o077)
	defer syscall.Umask(old)
	f := newRuleFixture(t)
	out := filepath.Join(t.TempDir(), "new", "approvals", "cncf", f.id+".json")
	args := f.signArgs("--key-stdin")
	args[len(args)-2] = out
	requireCode(t, runApproval(t, f.key.pemKey(t), signNow, args...), 0, "approval written")
	info, err := os.Lstat(out)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode() != 0o644 {
		t.Fatalf("mode %v, want -rw-r--r--", info.Mode())
	}

	g := newRuleFixture(t)
	real := t.TempDir()
	if err := os.MkdirAll(filepath.Join(real, "approvals", "cncf"), 0o755); err != nil {
		t.Fatal(err)
	}
	for name, out := range map[string]string{
		"linked parent":   filepath.Join(t.TempDir(), "link", "cncf", g.id+".json"),
		"linked ancestor": filepath.Join(t.TempDir(), "link", "approvals", "cncf", g.id+".json"),
	} {
		linkDir := filepath.Dir(filepath.Dir(out))
		if name == "linked ancestor" {
			linkDir = filepath.Dir(linkDir)
		}
		target := filepath.Join(real, "approvals")
		if name == "linked ancestor" {
			target = real
		}
		if err := os.Symlink(target, linkDir); err != nil {
			t.Fatal(err)
		}
		args := g.signArgs("--key-stdin")
		args[len(args)-2] = out
		requireCode(t, runApproval(t, g.key.pemKey(t), signNow, args...), 2, "symbolic link")
		if _, err := os.Lstat(filepath.Join(real, "approvals", "cncf", g.id+".json")); !os.IsNotExist(err) {
			t.Fatalf("%s: written through the link", name)
		}
	}
}
