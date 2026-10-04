// SPDX-License-Identifier: AGPL-3.0-only

package communityapp

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/knowledge"
	"github.com/prufyx/prufyx/cli/internal/knowledgefixture"
	"github.com/prufyx/prufyx/cli/internal/scanreport"
)

// TestScanKnowledgeDB: prufyx scan --knowledge-db reads a verified
// per-project database. Holding the embedded pack, it gives the embedded
// answer at the same instant; any verification failure exits 3 with nothing
// on standard output.
func TestScanKnowledgeDB(t *testing.T) {
	repo, err := knowledgefixture.NewProjectsRepository(time.Now().UTC().Truncate(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	defer repo.Close()
	dir := t.TempDir()
	store := filepath.Join(dir, "store")
	root := writeCNCFFile(t, "root.json", repo.Root, 0o600)
	pkg := writeCNCFFile(t, "package.tar", perProjectPackage(t, repo, 1, "5"), 0o600)
	if _, err := knowledge.ImportConstraintsProjects(knowledge.ImportRequest{PackagePath: pkg, StoreRoot: store, BootstrapRootPath: root, BootstrapRootDigest: repo.RootDigest}); err != nil {
		t.Fatal(err)
	}
	input := filepath.Join(dir, "applyset.yaml")
	if err := os.WriteFile(input, []byte(scanCronJob), 0o600); err != nil {
		t.Fatal(err)
	}
	scanArgs := []string{input, "--from", "kubernetes=1.24.17", "--to", "kubernetes=1.25.3", "--distribution", "official_upstream", "--resource-scope-complete", "--target-api-apply-required"}

	code, stdout, stderr := runScan(t, append(scanArgs, "--knowledge-db", store, "--format", "json")...)
	selected, err := scanreport.DecodeJSON([]byte(stdout))
	if err != nil || stderr != "" || selected.Provenance.KnowledgeOrigin != "external_signed_local" || selected.Provenance.KnowledgeStore == nil || selected.Provenance.KnowledgeStore.Layout != "cncf-projects" {
		t.Fatalf("database scan: %d %v\n%s\n%s", code, err, stdout, stderr)
	}
	embeddedCode, embeddedOut, _ := runScan(t, append(scanArgs, "--now", selected.Provenance.EvaluatedAt, "--format", "json")...)
	if code != embeddedCode || !bytes.Equal(dropProvenance(t, stdout), dropProvenance(t, embeddedOut)) {
		t.Fatalf("database %d and embedded %d differ:\n%s\n%s", code, embeddedCode, stdout, embeddedOut)
	}
	code, stdout, _ = runScan(t, append(scanArgs, "--knowledge-db", store, "--redact")...)
	if code != embeddedCode || strings.Contains(stdout, store) || !strings.Contains(stdout, "knowledge database sha256:") || !strings.Contains(stdout, "knowledge for kubernetes: target knowledge/cncf/projects/kubernetes.v1.json revision 5") {
		t.Fatalf("human: %d\n%s", code, stdout)
	}

	code, stdout, stderr = runScan(t, append(scanArgs, "--knowledge-db", store, "--now", "2026-10-04T00:00:00Z")...)
	if code != ExitUsage || stdout != "" || !strings.Contains(stderr, "--now cannot be used with --knowledge-db") {
		t.Fatalf("--now: %d %q %q", code, stdout, stderr)
	}
	code, stdout, _ = runScan(t, "--help")
	if code != ExitOK || !strings.Contains(stdout, "--knowledge-db DIR") {
		t.Fatalf("help: %s", stdout)
	}

	targets, err := filepath.Glob(filepath.Join(store, "admissions", "*", "*", "projects", "kubernetes.json"))
	if err != nil || len(targets) != 1 {
		t.Fatalf("stored target %v %v", targets, err)
	}
	raw, err := os.ReadFile(targets[0])
	if err != nil {
		t.Fatal(err)
	}
	raw[len(raw)/2] ^= 0x01
	if err := os.Chmod(targets[0], 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(targets[0], raw, 0o600); err != nil {
		t.Fatal(err)
	}
	empty := filepath.Join(dir, "empty")
	if err := os.Mkdir(empty, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ store, reason string }{{store, scanreport.KnowledgeDBIntegrity}, {empty, scanreport.KnowledgeDBNotAStore}} {
		for _, format := range []string{"human", "json"} {
			code, stdout, stderr = runScan(t, append(scanArgs, "--knowledge-db", tc.store, "--format", format)...)
			want := "prufyx: " + scanreport.Text(scanreport.UsageKnowledgeDBFailed, tc.reason) + "\n"
			if code != ExitIntegrity || stdout != "" || stderr != want {
				t.Fatalf("%s %s: %d %q %q", tc.store, format, code, stdout, stderr)
			}
		}
	}
}

func dropProvenance(t *testing.T, raw string) []byte {
	t.Helper()
	var members map[string]json.RawMessage
	if err := json.Unmarshal([]byte(raw), &members); err != nil {
		t.Fatal(err)
	}
	delete(members, "provenance")
	out, err := json.Marshal(members)
	if err != nil {
		t.Fatal(err)
	}
	return out
}
