// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/constraintengine"
	"github.com/prufyx/prufyx/cli/internal/extract"
	"github.com/prufyx/prufyx/cli/internal/extract/k8sservedapis"
	"github.com/prufyx/prufyx/cli/internal/lineattest"
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

func TestMaintainerCLI_CoverageWindow(t *testing.T) {
	var def, six, all, errOut bytes.Buffer
	if err := run(coverageArgs(), &def, &errOut); err != nil {
		t.Fatal(err)
	}
	if err := run(coverageArgs("--window", "6"), &six, &errOut); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(def.Bytes(), six.Bytes()) || !bytes.Contains(def.Bytes(), []byte(`"window": 6`)) {
		t.Fatal("--window 6 differs from the default")
	}
	if err := run(coverageArgs("--window", "ALL"), &all, &errOut); err != nil {
		t.Fatal(err)
	}
	var report struct {
		Window    int
		WindowAll bool
		Projects  []struct {
			Project  string
			Complete bool
			Pairs    []struct{}
		}
	}
	if err := json.Unmarshal(all.Bytes(), &report); err != nil {
		t.Fatal(err)
	}
	if report.Window != 0 || !report.WindowAll || len(report.Projects) == 0 {
		t.Fatalf("ALL report = window %d all %v projects %d", report.Window, report.WindowAll, len(report.Projects))
	}
	for _, p := range report.Projects {
		if p.Complete {
			t.Errorf("%s is complete without any attestation", p.Project)
		}
	}
}

func TestMaintainerCLI_CoverageCompleteUsage(t *testing.T) {
	dir := t.TempDir()
	badDeclared := filepath.Join(dir, "declared.json")
	if err := os.WriteFile(badDeclared, []byte(`{"schema":"x","declarations":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, extra := range [][]string{
		{"--complete", "--json-out", filepath.Join(dir, "r.json")},
		{"--complete", "--md-out", filepath.Join(dir, "r.md")},
		{"--complete", "--window", "6"},
		{"--window", "many"},
		{"--declared", badDeclared},
		{"--window", "ALL", "--declared", badDeclared},
		{"--window", "ALL", "--declared", filepath.Join(dir, "missing.json")},
	} {
		var out, errOut bytes.Buffer
		err := run(coverageArgs(extra...), &out, &errOut)
		if err == nil {
			t.Errorf("%v accepted", extra)
			continue
		}
		var ce *commandError
		if !errors.As(err, &ce) || ce.code != 2 || out.Len() != 0 {
			t.Errorf("%v: err %v, stdout %q", extra, err, out.String())
		}
	}
}

// --complete prints one project per line, only complete ones; none gives an
// empty output and exit 0.
func TestMaintainerCLI_CoverageComplete(t *testing.T) {
	var out, errOut bytes.Buffer
	if err := run(coverageArgs("--complete"), &out, &errOut); err != nil || out.Len() != 0 {
		t.Fatalf("no complete project: err %v stdout %q", err, out.String())
	}
	ex := k8sservedapis.New(0)
	dir, files := ex.SourceFiles()
	set, err := extract.CodeFiles(extract.FrameworkSource(), extract.SourceSet{Dir: dir, Files: files})
	if err != nil {
		t.Fatal(err)
	}
	rev := strings.Repeat("1", 40)
	var atts []lineattest.LineAttestation
	for _, line := range []string{"1.20", "1.21"} {
		atts = append(atts, lineattest.LineAttestation{
			Component: "pkg:github/kubernetes/kubernetes", Line: line, FactFamily: lineattest.FamilyKubernetesRemovedServedGVK,
			Completeness: lineattest.Completeness, RuleIDs: []string{},
			Evidence: lineattest.Evidence{
				Basis:      constraintengine.BasisMechanical,
				Extractor:  &constraintengine.Extractor{ID: ex.ID(), Version: ex.Version(), CodeDigest: extract.CodeDigest(set)},
				DerivedAt:  "2026-10-01T00:00:00Z",
				ReviewedAt: "2026-10-01T00:00:00Z",
				ValidUntil: "2026-12-15T00:00:00Z",
				Sources:    []constraintengine.SourceEvidence{{ID: "src-a", URL: "https://github.com/kubernetes/kubernetes/blob/" + rev + "/api/file.go", Revision: rev, ContentDigest: "sha256:" + strings.Repeat("a", 64), StartLine: 1, EndLine: 2}},
			},
		})
	}
	section, err := lineattest.Marshal(atts)
	if err != nil {
		t.Fatal(err)
	}
	tmp := t.TempDir()
	packPath, linesPath := filepath.Join(tmp, "pack.json"), filepath.Join(tmp, "lines.json")
	if err := os.WriteFile(packPath, []byte(`{"schema":"test","revision":"synthetic","entries":[],"lineAttestations":`+string(section)+`}`), 0o600); err != nil {
		t.Fatal(err)
	}
	lines := `{"schema":"prufyx.io/coverage-lines/v1","capturedOn":"2026-10-08","projects":{"kubernetes":{"lines":["1.19","1.20","1.21"]},"other-project":{"lines":["1.0","1.1"]}}}`
	if err := os.WriteFile(linesPath, []byte(lines), 0o600); err != nil {
		t.Fatal(err)
	}
	complete := func(now string) string {
		var out bytes.Buffer
		if err := run([]string{"coverage", "report", "--pack", packPath, "--lines", linesPath, "--now", now, "--complete"}, &out, &errOut); err != nil {
			t.Fatal(err)
		}
		return out.String()
	}
	if got := complete("2026-10-08T12:00:00Z"); got != "kubernetes\n" {
		t.Fatalf("complete = %q", got)
	}
	// Two weeks on the snapshot is stale: nothing is complete.
	if got := complete("2026-10-23T12:00:00Z"); got != "" {
		t.Fatalf("stale snapshot: complete = %q", got)
	}
}
