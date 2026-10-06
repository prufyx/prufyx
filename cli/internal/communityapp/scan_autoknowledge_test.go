// SPDX-License-Identifier: AGPL-3.0-only

package communityapp

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/scanreport"
)

// TestScanAutoKnowledge: scan with no --knowledge-db and no --now uses the
// verified database of the default store, embedded knowledge when none is
// installed, refuses an unusable one, and keeps --now and
// --knowledge=embedded on the embedded knowledge.
func TestScanAutoKnowledge(t *testing.T) {
	useDefaultStoreHome(t)
	input := filepath.Join(t.TempDir(), "applyset.yaml")
	if err := os.WriteFile(input, []byte(scanCronJob), 0o600); err != nil {
		t.Fatal(err)
	}
	args := []string{input, "--from", "kubernetes=1.24.17", "--to", "kubernetes=1.25.3", "--distribution", "official_upstream", "--resource-scope-complete", "--target-api-apply-required", "--format", "json"}

	code, stdout, stderr := runScan(t, args...)
	report, err := scanreport.DecodeJSON([]byte(stdout))
	if err != nil || report.Provenance.KnowledgeOrigin == "external_signed_local" || !strings.Contains(stderr, "prufyx: knowledge source: embedded, no local knowledge database installed") {
		t.Fatalf("no store: %d %v %q\n%s", code, err, stderr, stdout)
	}
	embeddedCode := code

	fixture := installDefaultStore(t)
	code, stdout, stderr = runScan(t, args...)
	report, err = scanreport.DecodeJSON([]byte(stdout))
	if err != nil || code != embeddedCode || report.Provenance.KnowledgeOrigin != "external_signed_local" || report.Provenance.KnowledgeStore == nil ||
		report.Provenance.KnowledgeRevision != "5" || !strings.Contains(stderr, "prufyx: knowledge source: local-db, revision 5, bundle digest "+report.Provenance.KnowledgeDigest) {
		t.Fatalf("store: %d %v %q\n%s", code, err, stderr, stdout)
	}

	// --now and --knowledge=embedded keep the embedded knowledge.
	for _, extra := range [][]string{{"--now", "2026-10-04T00:00:00Z"}, {"--knowledge=embedded"}, {"--knowledge", "embedded"}} {
		_, out, errText := runScan(t, append(append([]string{}, args...), extra...)...)
		got, err := scanreport.DecodeJSON([]byte(out))
		if err != nil || got.Provenance.KnowledgeOrigin == "external_signed_local" || strings.Contains(errText, "local-db") {
			t.Fatalf("%v: %v %q\n%s", extra, err, errText, out)
		}
	}
	if code, _, stderr := runScan(t, append(append([]string{}, args...), "--knowledge=embedded", "--knowledge-db", fixture.root)...); code != ExitUsage || !strings.Contains(stderr, "--knowledge=embedded cannot be used") {
		t.Fatalf("conflict: %d %q", code, stderr)
	}

	// Pinned to another root: refused with the way out, nothing on stdout.
	pinProjects(t, "sha256:"+strings.Repeat("cd", 32))
	code, stdout, stderr = runScan(t, args...)
	if code != ExitIntegrity || stdout != "" || !strings.Contains(stderr, "pinned in this build") || !strings.Contains(stderr, "--knowledge=embedded") {
		t.Fatalf("pin: %d %q %q", code, stdout, stderr)
	}
	pinProjects(t, fixture.rootDigest)

	// Present but unusable: refused, never embedded.
	if err := os.Chmod(fixture.root, 0o755); err != nil {
		t.Fatal(err)
	}
	code, stdout, stderr = runScan(t, args...)
	if code != ExitIntegrity || stdout != "" || !strings.Contains(stderr, "embedded knowledge was not used") || !strings.Contains(stderr, "--knowledge=embedded") {
		t.Fatalf("unusable: %d %q %q", code, stdout, stderr)
	}
	if code, out, _ := runScan(t, append(append([]string{}, args...), "--knowledge=embedded")...); code != embeddedCode || out == "" {
		t.Fatalf("forced embedded: %d", code)
	}
}
