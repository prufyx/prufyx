// SPDX-License-Identifier: AGPL-3.0-only

package communityapp

import (
	"bytes"
	"context"
	"path/filepath"
	"strings"
	"testing"
)

func runCLIForTest(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var out, errout bytes.Buffer
	code := RunCLI(context.Background(), args, &out, &errout, "dev")
	return code, out.String(), errout.String()
}

// A check that exits 0 is a scoped PASS and the whole upgrade stays UNKNOWN.
// The command line says so on standard error; the exit status and standard
// output are those of Run.
func TestRunCLINotesAScopedPassExit(t *testing.T) {
	dir := privateDir(t)
	values := filepath.Join(dir, "values.json")
	writePrivate(t, values, []byte(`{"prometheus":{"servicemonitor":{"enabled":true}}}`))
	base := []string{"check", "cert-manager-values", "--from", "1.20.3", "--to", "1.21.1", "--values", values, "--format", "json"}

	plainCode, plainOut, plainErr := runCommunity(t, base...)
	if plainCode != ExitOK || plainErr != "" {
		t.Fatalf("fixture is not a scoped pass: code=%d stderr=%q", plainCode, plainErr)
	}
	code, out, errout := runCLIForTest(t, base...)
	if code != ExitOK || out != plainOut {
		t.Fatalf("RunCLI changed the result: code=%d", code)
	}
	if strings.TrimSpace(errout) != ScopedPassExitNote || !strings.Contains(errout, "--strict-exit") || !strings.Contains(errout, "UNKNOWN") {
		t.Fatalf("stderr=%q", errout)
	}

	strictCode, strictOut, strictErr := runCLIForTest(t, append(append([]string(nil), base...), "--strict-exit")...)
	if strictCode != ExitScopedPass || strictOut != plainOut || strings.Contains(strictErr, ScopedPassExitNote) {
		t.Fatalf("strict code=%d stderr=%q", strictCode, strictErr)
	}
	// The last --strict-exit form decides, for the note as for the exit status.
	lastFalse := append(append([]string(nil), base...), "--strict-exit", "--strict-exit=false")
	if code, _, errout := runCLIForTest(t, lastFalse...); code != ExitOK || !strings.Contains(errout, ScopedPassExitNote) {
		t.Fatalf("--strict-exit then =false: code=%d stderr=%q", code, errout)
	}
	if code, _, errout := runCLIForTest(t, append(append([]string(nil), base...), "--strict-exit=false", "--strict-exit")...); code != ExitScopedPass || strings.Contains(errout, ScopedPassExitNote) {
		t.Fatalf("=false then --strict-exit: code=%d stderr=%q", code, errout)
	}
	if code, _, errout := runCLIForTest(t, "check", "--help"); code != ExitOK || strings.Contains(errout, ScopedPassExitNote) {
		t.Fatalf("help code=%d stderr=%q", code, errout)
	}
	blocked := filepath.Join(dir, "blocked.json")
	writePrivate(t, blocked, []byte(`{"prometheus":{"servicemonitor":{"path":"x"}}}`))
	args := append([]string(nil), base...)
	args[7] = blocked
	if code, _, errout := runCLIForTest(t, args...); code != ExitBlocked || strings.Contains(errout, ScopedPassExitNote) {
		t.Fatalf("blocked code=%d stderr=%q", code, errout)
	}
}
