// SPDX-License-Identifier: AGPL-3.0-only

package communityapp

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeInTotoArgv(t *testing.T, path, keyOption, marker string, tail ...string) []byte {
	t.Helper()
	argv := []string{"in-toto-run", "--step-name", "PRIVATE_STEP_" + marker, keyOption, "/private/key-" + marker, "--", "private-command-" + marker}
	argv = append(argv, tail...)
	raw, err := json.Marshal(argv)
	if err != nil {
		t.Fatal(err)
	}
	writeCNCFFileAt(t, path, raw)
	return raw
}

func inTotoRawArgs(path, from, to, format string) []string {
	return []string{"check", "cncf", "--project", "in-toto", "--in-toto-run-argv", path, "--from", from, "--to", to, "--now", "2026-09-10T21:00:00Z", "--format", format}
}

func TestInTotoRunRawArgvEditAndRepeat(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "operator-argv.json")
	writeInTotoArgv(t, path, "--key", "BEFORE", "--key", "wrapped", "--", "later")
	args := inTotoRawArgs(path, "2.2.0", "3.0.0", "human")
	code, before, stderr := runCNCFCLI(t, args...)
	if code != ExitBlocked || stderr != "" || !strings.Contains(before, "pre-boundary key option: -k/--key") || !strings.Contains(before, "scoped result: BLOCKED") || !strings.Contains(before, "aggregate: UNKNOWN") || !strings.Contains(before, "standard PEM/PKCS8") || !strings.Contains(before, "raw argv digest: sha256:") || !strings.Contains(before, "prepared input digest: sha256:") {
		t.Fatalf("code=%d stderr=%q output=%s", code, stderr, before)
	}
	assertInTotoRedacted(t, before, path, "BEFORE")
	writeInTotoArgv(t, path, "--signing-key", "AFTER", "--key", "wrapped", "--", "later")
	code, after, stderr := runCNCFCLI(t, args...)
	if code != ExitOK || stderr != "" || !strings.Contains(after, "pre-boundary key option: --signing-key") || !strings.Contains(after, "scoped result: PASS") || !strings.Contains(after, "aggregate: UNKNOWN") {
		t.Fatalf("code=%d stderr=%q output=%s", code, stderr, after)
	}
	assertInTotoRedacted(t, after, path, "AFTER")
	code, repeated, stderr := runCNCFCLI(t, args...)
	if code != ExitOK || stderr != "" || repeated != after {
		t.Fatalf("repeat code=%d stderr=%q equal=%t", code, stderr, repeated == after)
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Fatalf("persisted intermediates: %v", entries)
	}
}

func TestInTotoRunRawUnknownAndModeGuards(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "argv.json")
	raw := writeInTotoArgv(t, path, "--key", "PRIVATE")
	for _, tc := range []struct {
		name, from, to string
		raw            []byte
	}{
		{"wrong pair", "2.2.1", "3.0.0", raw},
		{"unsupported order", "2.2.0", "3.0.0", []byte(`["in-toto-run","--key","private","-n","step","--","cmd"]`)},
		{"gpg excluded", "2.2.0", "3.0.0", []byte(`["in-toto-run","-n","step","--gpg","id","--","cmd"]`)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			writeCNCFFileAt(t, path, tc.raw)
			code, out, errout := runCNCFCLI(t, inTotoRawArgs(path, tc.from, tc.to, "human")...)
			if code != ExitUnknown || errout != "" || !strings.Contains(out, "UNKNOWN") {
				t.Fatalf("code=%d stderr=%q output=%s", code, errout, out)
			}
			assertInTotoRedacted(t, out, path, "PRIVATE")
		})
	}
	writeCNCFFileAt(t, path, []byte(`["unterminated]`))
	code, out, errout := runCNCFCLI(t, inTotoRawArgs(path, "2.2.0", "3.0.0", "human")...)
	if code != ExitUsage || out != "" || errout != "prufyx: IN_TOTO_RUN_PREPARATION_INPUT_INVALID\n" {
		t.Fatalf("malformed code=%d stdout=%q stderr=%q", code, out, errout)
	}
	writeCNCFFileAt(t, path, raw)
	base := inTotoRawArgs(path, "2.2.0", "3.0.0", "json")
	matching := append(append([]string{}, base...), "--in-toto-run-argv-digest", digestCommunityBytes(raw))
	code, out, errout = runCNCFCLI(t, matching...)
	if code != ExitBlocked || errout != "" || !json.Valid([]byte(out)) {
		t.Fatalf("matching code=%d stderr=%q output=%s", code, errout, out)
	}
	badDigest := "sha256:" + strings.Repeat("0", 64)
	code, out, errout = runCNCFCLI(t, append(base, "--in-toto-run-argv-digest", badDigest)...)
	if code != ExitIntegrity || out != "" || errout != "prufyx: CNCF_PREPARATION_INTEGRITY_FAILURE\n" {
		t.Fatalf("digest code=%d stdout=%q stderr=%q", code, out, errout)
	}
	for _, extra := range [][]string{{"--input", path}, {"--service", path}, {"--current-lifecycle-config", path}, {"--knowledge-db", dir}, {"--replay-report", path}} {
		a := append(append([]string{}, base...), extra...)
		code, out, errout = runCNCFCLI(t, a...)
		if code != ExitUsage || out != "" || errout == "" || strings.Contains(errout, path) {
			t.Fatalf("extra=%v code=%d out=%q err=%q", extra, code, out, errout)
		}
	}
}

func assertInTotoRedacted(t *testing.T, output string, forbidden ...string) {
	t.Helper()
	for _, v := range append(forbidden, "PRIVATE_STEP", "/private/key", "private-command", `"in-toto-run"`) {
		if strings.Contains(output, v) {
			t.Fatalf("private argv crossed output: %q in %s", v, output)
		}
	}
}
