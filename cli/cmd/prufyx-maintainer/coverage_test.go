// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

const coverageFixtures = "../../internal/maintainer/coveragereport/testdata/"

func coverageArgs(extra ...string) []string {
	return append([]string{"coverage", "report", "--pack", coverageFixtures + "pack-cncf-2026-09-13.4-reduced.json", "--lines", coverageFixtures + "lines-2026-10-08.json", "--now", "2026-10-08T12:00:00Z"}, extra...)
}

func TestMaintainerCLI_CoverageReport(t *testing.T) {
	dir := t.TempDir()
	jsonPath, mdPath := filepath.Join(dir, "r.json"), filepath.Join(dir, "r.md")
	var out, errOut bytes.Buffer
	if err := run(coverageArgs("--json-out", jsonPath, "--md-out", mdPath), &out, &errOut); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(jsonPath)
	if err != nil {
		t.Fatal(err)
	}
	var report struct {
		Fleet struct{ A, B, S, Pairs, C1 int }
	}
	if err := json.Unmarshal(raw, &report); err != nil {
		t.Fatal(err)
	}
	if f := report.Fleet; f.A != 0 || f.B != 0 || f.S != 44 || f.Pairs != 275 || f.C1 != 53 {
		t.Fatalf("fleet = %+v", f)
	}
	if md, err := os.ReadFile(mdPath); err != nil || !bytes.Contains(md, []byte("# Coverage report")) {
		t.Fatalf("markdown: %v", err)
	}
	// Without output files the JSON goes to stdout, byte-identical.
	out.Reset()
	if err := run(coverageArgs(), &out, &errOut); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out.Bytes(), raw) {
		t.Fatal("stdout differs from the written report")
	}
}

func TestMaintainerCLI_CoverageRejectsBadUsage(t *testing.T) {
	for _, args := range [][]string{
		{"coverage"},
		{"coverage", "nope"},
		{"coverage", "report"},
		{"coverage", "report", "--lines", coverageFixtures + "lines-2026-10-08.json"},
		{"coverage", "report", "--lines", coverageFixtures + "lines-2026-10-08.json", "--now", "yesterday"},
		{"coverage", "report", "--lines", "/nonexistent", "--now", "2026-10-08T12:00:00Z"},
		{"coverage", "report", "--lines", coverageFixtures + "lines-2026-10-08.json", "--now", "2026-10-08T12:00:00Z", "--window", "1"},
		{"coverage", "report", "--lines", coverageFixtures + "lines-2026-10-08.json", "--lines", "x", "--now", "2026-10-08T12:00:00Z"},
	} {
		var out, errOut bytes.Buffer
		if err := run(args, &out, &errOut); err == nil {
			t.Errorf("%v accepted", args)
		}
	}
}

func TestMaintainerCLI_CoverageLinesFromTags(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "demo.tags"), []byte("aaaa\trefs/tags/v1.2.0\nbbbb\trefs/tags/v1.3.1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "lines.json")
	var stdout, stderr bytes.Buffer
	if err := run([]string{"coverage", "lines-from-tags", "--tags-dir", dir, "--out", out, "--priority", "demo", "--captured-on", "2026-10-08"}, &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(out)
	if err != nil || !bytes.Contains(raw, []byte(`"1.3"`)) || !bytes.Contains(raw, []byte(`"priority": true`)) {
		t.Fatalf("lines file: %v %s", err, raw)
	}
}
