// SPDX-License-Identifier: AGPL-3.0-only

//go:build unix

package offlineboundary

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeSudo puts a stand-in for sudo on PATH. It scans its arguments for the
// strace "-o <prefix>" option and, when body is not empty, writes
// "<prefix>.100" containing body, as a real `strace -ff` would.
func fakeSudo(t *testing.T, body string) {
	t.Helper()
	bin := t.TempDir()
	script := "#!/bin/sh\nwhile [ $# -gt 0 ]; do if [ \"$1\" = -o ]; then shift; "
	if body != "" {
		script += "printf '" + body + "\\n' > \"$1.100\"; "
	}
	script += "fi; shift; done\nexit 0\n"
	if err := os.WriteFile(filepath.Join(bin, "sudo"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
}

func privateWorkDir(t *testing.T) string {
	t.Helper()
	work := t.TempDir()
	if err := os.Chmod(work, 0o700); err != nil {
		t.Fatal(err)
	}
	return work
}

// SEC-G (fail-open): a stale or planted "strace-<name>..." file in WorkDir
// containing network calls must not be read as evidence for this trace, and a
// clean trace must stay clean. Reverting trace() to a WorkDir glob fails this.
func TestTraceIgnoresPlantedFilesInWorkDir(t *testing.T) {
	fakeSudo(t, "read(3)")
	work := privateWorkDir(t)
	for _, name := range []string{"strace-help.1", "strace-help", "strace-help-more.9"} {
		if err := os.WriteFile(filepath.Join(work, name), []byte("socket(AF_INET, SOCK_STREAM, 0) = 3\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	result, err := trace(context.Background(), Config{WorkDir: work, UID: 1, GID: 1}, "help", []string{"/bin/true"})
	if err != nil {
		t.Fatal(err)
	}
	if result.NetworkObserved {
		t.Fatal("a planted file in WorkDir was read as trace evidence")
	}
	items, _ := os.ReadDir(work)
	for _, item := range items {
		if strings.HasPrefix(item.Name(), "strace-help-") && item.Name() != "strace-help-more.9" {
			t.Fatalf("trace directory %q was not removed", item.Name())
		}
	}
}

// A trace with no output must be an error, never an implicit "no network":
// planted files cannot stand in for the missing evidence.
func TestTraceWithoutOutputFailsClosed(t *testing.T) {
	fakeSudo(t, "")
	work := privateWorkDir(t)
	if err := os.WriteFile(filepath.Join(work, "strace-help.1"), []byte("read(3)\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := trace(context.Background(), Config{WorkDir: work, UID: 1, GID: 1}, "help", []string{"/bin/true"})
	if err == nil || !strings.Contains(err.Error(), "read isolated help trace") {
		t.Fatalf("err = %v, want read isolated help trace", err)
	}
}

// A genuine network call in the isolated trace is still reported.
func TestTraceReportsNetworkInIsolatedTrace(t *testing.T) {
	fakeSudo(t, "socket(AF_INET, SOCK_STREAM, 0) = 3")
	result, err := trace(context.Background(), Config{WorkDir: privateWorkDir(t), UID: 1, GID: 1}, "help", []string{"/bin/true"})
	if err != nil || !result.NetworkObserved {
		t.Fatalf("observed=%v err=%v, want network observed", result.NetworkObserved, err)
	}
}
