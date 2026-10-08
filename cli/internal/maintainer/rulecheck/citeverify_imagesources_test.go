// SPDX-License-Identifier: AGPL-3.0-only

package rulecheck

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func imageTable(digest string, endLine int) string {
	return fmt.Sprintf(`{"schema":"prufyx.io/image-sources/v1alpha1","records":[{"project":"widget","evidence":{"sources":[{"id":"s1","url":"https://github.com/acme/widget/blob/%s/a/b.go","revision":%q,"contentDigest":%q,"startLine":1,"endLine":%d}]}}]}`, citeCommit, citeCommit, digest, endLine)
}

func TestVerifyCitationsImageSources(t *testing.T) {
	good := digestOf(citeFileBytes)
	dir := t.TempDir()
	deps := &citationDeps{
		resolver: citeResolver{"acme/widget@" + citeCommit: {Commit: true}},
		fetcher:  citeFetcher{citeRaw(citeCommit): citeFileBytes},
	}
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	var stdout, stderr bytes.Buffer
	if code := runVerifyCitations([]string{"--image-sources", write("ok.json", imageTable(good, 2))}, &stdout, &stderr, CLIOptions{}, deps); code != 0 {
		t.Fatalf("clean table exit = %d: %s", code, stderr.String())
	}
	for name, table := range map[string]string{
		"digest.json": imageTable("sha256:"+strings.Repeat("0", 64), 2),
		"span.json":   imageTable(good, 3),
	} {
		stdout.Reset()
		stderr.Reset()
		if code := runVerifyCitations([]string{"--image-sources", write(name, table)}, &stdout, &stderr, CLIOptions{}, deps); code != 1 {
			t.Fatalf("%s exit = %d: %s", name, code, stderr.String())
		}
		var report CitationReport
		if err := json.Unmarshal(stdout.Bytes(), &report); err != nil || report.Pass || len(report.FailedRules) != 1 || report.FailedRules[0] != "image-source:widget" {
			t.Fatalf("%s report: %v %+v", name, err, report)
		}
	}
	// Both inputs at once, or a table that is not one, is a usage error.
	for _, args := range [][]string{
		{"--image-sources", filepath.Join(dir, "ok.json"), "--rules", filepath.Join(dir, "ok.json")},
		{"--image-sources", write("empty.json", `{"records":[]}`)},
		{"--image-sources", filepath.Join(dir, "missing.json")},
	} {
		if code := runVerifyCitations(args, &stdout, &stderr, CLIOptions{}, deps); code != 2 {
			t.Fatalf("args %v exit = %d, want 2", args, code)
		}
	}
}

// The embedded table is always convertible, so the CI citation job never
// silently checks nothing.
func TestImageSourceRulesCoverTheEmbeddedTable(t *testing.T) {
	path := filepath.Join("..", "..", "imageidentity", "data", "image-sources.json")
	rules, err := imageSourceRules(path)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(path)
	var table struct {
		Records []json.RawMessage `json:"records"`
	}
	if err := json.Unmarshal(raw, &table); err != nil || len(rules) != len(table.Records) || len(rules) < 10 {
		t.Fatalf("rules=%d records=%d err=%v", len(rules), len(table.Records), err)
	}
}
