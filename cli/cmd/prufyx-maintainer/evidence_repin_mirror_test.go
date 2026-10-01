// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The mirror source is wired into the command: an empty mirror is valid
// input and leaves every citation pending, with no network involved.
func TestEvidenceRepinMirrorSourceIsWired(t *testing.T) {
	dir := t.TempDir()
	commit := strings.Repeat("a", 40)
	pack, _ := json.Marshal(map[string]any{"schema": "prufyx.io/rule-pack/v1", "revision": "t", "entries": []any{map[string]any{
		"project": "p", "rule": map[string]any{"id": "p.rule", "evidence": map[string]any{
			"reviewedAt": "2026-09-12T10:00:00Z", "validUntil": "2026-12-11T10:00:00Z", "state": "active",
			"sources": []any{map[string]any{
				"id": "s", "url": "https://github.com/acme/widget/blob/" + commit + "/VERSION", "revision": commit,
				"contentDigest": "sha256:" + strings.Repeat("0", 64), "startLine": 1, "endLine": 1,
			}},
		}},
	}}})
	rules := filepath.Join(dir, "rules.json")
	if err := os.WriteFile(rules, pack, 0o644); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "worklist.json")
	wants := filepath.Join(dir, "wants.json")
	var stdout, stderr strings.Builder
	err := run([]string{"evidence", "repin", "--source", "mirror", "--mirror-state", filepath.Join(dir, "mirror"),
		"--rules", rules, "--output", out, "--wants-out", wants}, &stdout, &stderr)
	if err != nil {
		t.Fatalf("%v: %s", err, stderr.String())
	}
	raw, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	var wl struct {
		Source  string                `json:"source"`
		Summary struct{ Pending int } `json:"summary"`
	}
	if err := json.Unmarshal(raw, &wl); err != nil || wl.Source != "mirror" || wl.Summary.Pending != 1 {
		t.Fatalf("%v %+v", err, wl)
	}
	if err := run([]string{"evidence", "repin", "--source", "mirror", "--rules", rules, "--output", out}, &stdout, &stderr); err == nil {
		t.Fatal("--source mirror without --mirror-state must be rejected")
	}
}
