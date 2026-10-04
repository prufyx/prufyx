// SPDX-License-Identifier: AGPL-3.0-only

package scanreport

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

// storeReport is the full report as a --knowledge-db scan of a per-project
// database gives it, with one present and one absent project target.
func storeReport(path string) Report {
	report := fullReport()
	report.Provenance.KnowledgeOrigin = "external_signed_local"
	report.Provenance.KnowledgeStore = &KnowledgeStore{
		Path: path, Layout: "cncf-projects", TargetPath: "knowledge/cncf/index.v1.json",
		TrustReceiptDigest: "sha256:" + strings.Repeat("5", 64), Purpose: "operator_provided", ImportedVerifiedAt: "2026-10-03T00:00:00Z",
		Projects: []KnowledgeStoreProject{
			{Project: "etcd", Status: "absent_from_index"},
			{Project: "kubernetes", Status: "present", TargetPath: "knowledge/cncf/projects/kubernetes.v1.json", Revision: "5", Digest: "sha256:" + strings.Repeat("6", 64)},
		},
	}
	return report
}

// TestStoreProvenanceInEveryFormat: SARIF run properties and the Markdown
// provenance block name the knowledge database exactly as the human footer
// and the JSON report do (goldens), and the SARIF log stays valid.
func TestStoreProvenanceInEveryFormat(t *testing.T) {
	report := storeReport("/var/lib/prufyx/knowledge-db")
	raw, err := SARIF(report)
	golden(t, "sarif-store.json", must(t, raw, err))
	if err := validateSARIF(raw); err != nil {
		t.Fatal(err)
	}
	var log struct {
		Runs []struct {
			Properties struct {
				KnowledgeStore *KnowledgeStore `json:"knowledgeStore"`
			} `json:"properties"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(raw, &log); err != nil || log.Runs[0].Properties.KnowledgeStore == nil || log.Runs[0].Properties.KnowledgeStore.Path != "/var/lib/prufyx/knowledge-db" || len(log.Runs[0].Properties.KnowledgeStore.Projects) != 2 {
		t.Fatalf("sarif knowledge store: %v", err)
	}
	md := Markdown(report, MarkdownOptions{})
	golden(t, "markdown-store.md", md)
	human := Human(report, HumanOptions{})
	for _, want := range knowledgeStoreLines(report.Provenance.KnowledgeStore) {
		if !bytes.Contains(md, []byte(want+"\n")) || !bytes.Contains(human, []byte(want+"\n")) {
			t.Errorf("line %q missing from Markdown or human output", want)
		}
	}
	// The embedded knowledge renders no database line in any format.
	for _, format := range []string{"sarif", "markdown", "human"} {
		out, err := Render(fullReport(), format, RenderOptions{})
		if err != nil || bytes.Contains(out, []byte("knowledgeStore")) || bytes.Contains(out, []byte("knowledge database")) {
			t.Errorf("%s: embedded report names a database (%v)", format, err)
		}
	}
}

// TestRedactedStoreProvenance: after Redact no format holds the database
// path; each holds its digest.
func TestRedactedStoreProvenance(t *testing.T) {
	path := "/home/canary-user/canary-db"
	report := storeReport(path)
	Redact(&report)
	for _, format := range []string{"sarif", "markdown", "human", "json"} {
		out, err := Render(report, format, RenderOptions{ShowPasses: true, Verbose: true})
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(out, []byte("canary")) || !bytes.Contains(out, []byte(RedactValue(path))) {
			t.Errorf("%s: database path not redacted:\n%s", format, out)
		}
	}
}
