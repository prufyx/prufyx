// SPDX-License-Identifier: AGPL-3.0-only

package communityapp

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func cubeFSRawArgs(path, from, to, phase, format string) []string {
	args := []string{"check", "cncf", "--project", "cubefs", "--metanode-config", path, "--from", from, "--to", to, "--now", "2026-09-10T22:00:00Z", "--format", format}
	if phase != "" {
		args = append(args, "--phase", phase)
	}
	return args
}

func TestCubeFSMetaNodeRawConfigEditAndRepeat(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "metanode.json")
	beforeRaw := []byte(`{"role":"metanode","listen":"17210","masterAddr":["private.example:17010"],"secretKey":"PRIVATE_CUBEFS"}`)
	writeCNCFFileAt(t, path, beforeRaw)
	args := cubeFSRawArgs(path, "3.2.1", "3.3.2", "metanode-upgrade", "human")
	code, before, stderr := runCNCFCLI(t, args...)
	if code != ExitBlocked || stderr != "" || !strings.Contains(before, "planned config raftSyncSnapFormatVersion: absent in supplied planned config (target source-defined default is 1)") || !strings.Contains(before, "scoped result: BLOCKED") || !strings.Contains(before, "aggregate: UNKNOWN") || !strings.Contains(before, "Removing the setting after all MetaNodes upgrade") {
		t.Fatalf("code=%d stderr=%q output=%s", code, stderr, before)
	}
	assertCubeFSRedacted(t, before, path)
	got, _ := os.ReadFile(path)
	if string(got) != string(beforeRaw) {
		t.Fatal("checker modified the supplied planned config")
	}
	oneRaw := []byte(`{"role":"metanode","raftSyncSnapFormatVersion":1,"secretKey":"PRIVATE_CUBEFS"}`)
	writeCNCFFileAt(t, path, oneRaw)
	code, one, stderr := runCNCFCLI(t, args...)
	if code != ExitBlocked || stderr != "" || !strings.Contains(one, "explicit numeric 1 in supplied planned config") || strings.Contains(one, "absent in supplied") {
		t.Fatalf("one code=%d stderr=%q output=%s", code, stderr, one)
	}
	zeroRaw := []byte(`{"role":"metanode","raftSyncSnapFormatVersion":0,"secretKey":"PRIVATE_CUBEFS"}`)
	writeCNCFFileAt(t, path, zeroRaw)
	code, after, stderr := runCNCFCLI(t, args...)
	if code != ExitOK || stderr != "" || !strings.Contains(after, "explicit numeric 0 in supplied planned config") || !strings.Contains(after, "scoped result: PASS") || !strings.Contains(after, "aggregate: UNKNOWN") || !strings.Contains(after, "already declares numeric 0") {
		t.Fatalf("code=%d stderr=%q output=%s", code, stderr, after)
	}
	assertCubeFSRedacted(t, after, path)
	code, repeated, stderr := runCNCFCLI(t, args...)
	if code != ExitOK || stderr != "" || repeated != after {
		t.Fatalf("repeat code=%d stderr=%q equal=%t", code, stderr, repeated == after)
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Fatalf("persisted intermediates: %v", entries)
	}
}

func TestCubeFSMetaNodeRawUnknownPrivacyAndModeGuards(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "metanode.json")
	tests := []struct {
		name, raw, from, to, phase string
	}{
		{"missing phase", `{"role":"metanode","raftSyncSnapFormatVersion":0,"secretKey":"PRIVATE_CUBEFS"}`, "3.2.1", "3.3.2", ""},
		{"other phase", `{"role":"metanode","raftSyncSnapFormatVersion":0,"secretKey":"PRIVATE_CUBEFS"}`, "3.2.1", "3.3.2", "master-upgrade"},
		{"wrong role", `{"role":"master","raftSyncSnapFormatVersion":0,"secretKey":"PRIVATE_CUBEFS"}`, "3.2.1", "3.3.2", "metanode-upgrade"},
		{"string value", `{"role":"metanode","raftSyncSnapFormatVersion":"0","secretKey":"PRIVATE_CUBEFS"}`, "3.2.1", "3.3.2", "metanode-upgrade"},
		{"range value", `{"role":"metanode","raftSyncSnapFormatVersion":2,"secretKey":"PRIVATE_CUBEFS"}`, "3.2.1", "3.3.2", "metanode-upgrade"},
		{"case ambiguity", `{"role":"metanode","Role":"metanode","raftSyncSnapFormatVersion":0,"secretKey":"PRIVATE_CUBEFS"}`, "3.2.1", "3.3.2", "metanode-upgrade"},
		{"wrong tuple", `{"role":"metanode","raftSyncSnapFormatVersion":0,"secretKey":"PRIVATE_CUBEFS"}`, "3.2.0", "3.3.2", "metanode-upgrade"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			writeCNCFFileAt(t, path, []byte(tc.raw))
			code, out, errout := runCNCFCLI(t, cubeFSRawArgs(path, tc.from, tc.to, tc.phase, "human")...)
			if code != ExitUnknown || errout != "" || !strings.Contains(out, "UNKNOWN") {
				t.Fatalf("code=%d stderr=%q output=%s", code, errout, out)
			}
			assertCubeFSRedacted(t, out, path)
		})
	}
	writeCNCFFileAt(t, path, []byte(`{"role":`))
	code, out, errout := runCNCFCLI(t, cubeFSRawArgs(path, "3.2.1", "3.3.2", "metanode-upgrade", "human")...)
	if code != ExitUsage || out != "" || errout != "prufyx: CUBEFS_METANODE_PREPARATION_INPUT_INVALID\n" {
		t.Fatalf("malformed code=%d stdout=%q stderr=%q", code, out, errout)
	}
	raw := []byte(`{"role":"metanode","raftSyncSnapFormatVersion":0,"secretKey":"PRIVATE_CUBEFS"}`)
	writeCNCFFileAt(t, path, raw)
	base := cubeFSRawArgs(path, "3.2.1", "3.3.2", "metanode-upgrade", "json")
	matching := append(append([]string{}, base...), "--metanode-config-digest", digestCommunityBytes(raw))
	code, out, errout = runCNCFCLI(t, matching...)
	if code != ExitOK || errout != "" || !json.Valid([]byte(out)) || strings.Contains(out, "PRIVATE_CUBEFS") {
		t.Fatalf("matching code=%d stderr=%q output=%s", code, errout, out)
	}
	badDigest := "sha256:" + strings.Repeat("0", 64)
	code, out, errout = runCNCFCLI(t, append(base, "--metanode-config-digest", badDigest)...)
	if code != ExitIntegrity || out != "" || errout != "prufyx: CNCF_PREPARATION_INTEGRITY_FAILURE\n" {
		t.Fatalf("digest code=%d stdout=%q stderr=%q", code, out, errout)
	}
	for _, extra := range [][]string{{"--input", path}, {"--service", path}, {"--in-toto-run-argv", path}, {"--knowledge-db", dir}, {"--replay-report", path}} {
		args := append(append([]string{}, base...), extra...)
		code, out, errout = runCNCFCLI(t, args...)
		if code != ExitUsage || out != "" || errout == "" || strings.Contains(errout, path) {
			t.Fatalf("extra=%v code=%d out=%q err=%q", extra, code, out, errout)
		}
	}
}

func assertCubeFSRedacted(t *testing.T, output string, path string) {
	t.Helper()
	for _, value := range []string{path, "PRIVATE_CUBEFS", "private.example", "masterAddr", "secretKey", "17210"} {
		if strings.Contains(output, value) {
			t.Fatalf("private config leaked: %q in %s", value, output)
		}
	}
}
