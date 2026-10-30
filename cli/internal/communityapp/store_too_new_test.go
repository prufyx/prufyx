// SPDX-License-Identifier: AGPL-3.0-only

package communityapp

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/knowledge"
	"github.com/prufyx/prufyx/cli/internal/scanreport"
	"github.com/prufyx/prufyx/cli/internal/scanrun"
)

// forceOpenError makes the default store fail to open with err; the store's
// real trust root is read as for a real store.
func forceOpenError(t *testing.T, err error) {
	t.Helper()
	old := autoOpenStore
	autoOpenStore = func(knowledge.SelectionRequest, []string) (knowledge.VerifiedRevision, error) {
		return knowledge.VerifiedRevision{}, err
	}
	t.Cleanup(func() { autoOpenStore = old })
}

// advanceTrustBehindSelection leaves the installed store as an older client
// would after a rejected import: the trust state is ahead of the selection.
func advanceTrustBehindSelection(t *testing.T, fixture autoStoreFixture) {
	t.Helper()
	path := filepath.Join(fixture.root, "selection.json")
	kept, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	pkg := writeCNCFFile(t, "package.tar", perProjectPackage(t, fixture.repo, 2, "6"), 0o600)
	if _, err := knowledge.ImportConstraintsProjects(knowledge.ImportRequest{PackagePath: pkg, StoreRoot: fixture.root}); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, kept, 0o600); err != nil {
		t.Fatal(err)
	}
}

const tooNewWarning = "prufyx: warning: knowledge source: embedded, the local database cannot be used: a newer prufyx is needed for this knowledge (min version v0.3.0)"

// A store this build cannot read falls back to the embedded knowledge for
// check and scan: warning, reason, verdict unchanged. A pin mismatch and any
// hard failure in the same error still exit 3.
func TestAutoKnowledgeTooNewStoreFallsBackForCheckAndScan(t *testing.T) {
	tooNew := fmt.Errorf("open: %w", &knowledge.UnsupportedError{Reason: "index target parse", MinVersion: "v0.3.0"})
	t.Run("check", func(t *testing.T) {
		useDefaultStoreHome(t)
		installDefaultStore(t)
		_, nowOut, _ := runCNCFCLI(t, autoCheckArgs(t, "--format", "json", "--now", autoFixedNow)...)
		forceOpenError(t, tooNew)
		code, out, stderr := runCNCFCLI(t, autoCheckArgs(t, "--format", "json")...)
		if code == ExitIntegrity || out != nowOut || !strings.Contains(stderr, tooNewWarning) {
			t.Fatalf("too new: %d %q\n%s", code, stderr, out)
		}
	})
	t.Run("scan", func(t *testing.T) {
		useDefaultStoreHome(t)
		installDefaultStore(t)
		old := scanOpenStore
		scanOpenStore = func(string, []string) (*scanrun.Store, error) {
			return nil, &scanrun.StoreError{Reason: scanreport.KnowledgeDBIntegrity, Fallback: "store-too-new", FallbackMin: "v0.3.0"}
		}
		t.Cleanup(func() { scanOpenStore = old })
		code, stdout, stderr := runScan(t, autoScanArgs(t)...)
		report, err := scanreport.DecodeJSON([]byte(stdout))
		if err != nil || code == ExitIntegrity || report.Provenance.KnowledgeOrigin == "external_signed_local" || report.Provenance.KnowledgeSelection == nil ||
			report.Provenance.KnowledgeSelection.Reason != "store-too-new" || !strings.Contains(stderr, tooNewWarning) {
			t.Fatalf("too new: %d %v %q\n%s", code, err, stderr, stdout)
		}
		pinProjects(t, "sha256:"+strings.Repeat("ab", 32))
		if code, stdout, stderr := runScan(t, autoScanArgs(t)...); code != ExitIntegrity || stdout != "" || !strings.Contains(stderr, "pinned in this build") {
			t.Fatalf("too new+pin: %d %q %q", code, stdout, stderr)
		}
	})
	t.Run("check too new and pin mismatch", func(t *testing.T) {
		useDefaultStoreHome(t)
		installDefaultStore(t)
		pinProjects(t, "sha256:"+strings.Repeat("ab", 32))
		forceOpenError(t, tooNew)
		code, stdout, stderr := runCNCFCLI(t, autoCheckArgs(t, "--format", "json")...)
		if code != ExitIntegrity || stdout != "" || !strings.Contains(stderr, "pinned in this build") {
			t.Fatalf("%d %q %q", code, stdout, stderr)
		}
	})
	t.Run("check too new joined with integrity or rollback", func(t *testing.T) {
		for _, hard := range []error{knowledge.ErrIntegrity, knowledge.ErrRollback, knowledge.ErrNoSelection} {
			useDefaultStoreHome(t)
			installDefaultStore(t)
			forceOpenError(t, errors.Join(tooNew, hard))
			if code, stdout, stderr := runCNCFCLI(t, autoCheckArgs(t, "--format", "json")...); code != ExitIntegrity || stdout != "" || !strings.Contains(stderr, "KNOWLEDGE INTEGRITY FAILURE") {
				t.Fatalf("%v: %d %q %q", hard, code, stdout, stderr)
			}
		}
	})
}

// A store an older client left TRUST_ADVANCED (real files, no stub) falls back
// to embedded for check and scan, names the directory to remove and never
// removes it. A pin mismatch still exits 3.
func TestAutoKnowledgeTrustAdvancedStoreFallsBackForCheckAndScan(t *testing.T) {
	useDefaultStoreHome(t)
	fixture := installDefaultStore(t)
	_, nowOut, _ := runCNCFCLI(t, autoCheckArgs(t, "--format", "json", "--now", autoFixedNow)...)
	advanceTrustBehindSelection(t, fixture)
	want := "the local database's trust state is ahead of or differs from its selection (written by a newer prufyx, or the selection was modified); if you did not run another prufyx on this store, treat this as tampering. To continue: upgrade prufyx, or remove " + fixture.root + " and run `prufyx db update` (removing the store also resets its rollback protection: only do it if you trust where the store came from)"

	code, out, stderr := runCNCFCLI(t, autoCheckArgs(t, "--format", "json")...)
	if code == ExitIntegrity || out != nowOut || !strings.Contains(stderr, "prufyx: warning: knowledge source: embedded, "+want) {
		t.Fatalf("check: %d %q\n%s", code, stderr, out)
	}
	code, stdout, stderr := runScan(t, autoScanArgs(t)...)
	report, err := scanreport.DecodeJSON([]byte(stdout))
	if err != nil || code == ExitIntegrity || report.Provenance.KnowledgeSelection == nil ||
		report.Provenance.KnowledgeSelection.Reason != "store-trust-advanced" || !strings.Contains(stderr, "prufyx: warning: knowledge source: embedded, "+want) {
		t.Fatalf("scan: %d %v %q\n%s", code, err, stderr, stdout)
	}
	if _, err := os.Stat(filepath.Join(fixture.root, "selection.json")); err != nil {
		t.Fatalf("store was touched: %v", err)
	}

	pinProjects(t, "sha256:"+strings.Repeat("ab", 32))
	if code, stdout, stderr := runCNCFCLI(t, autoCheckArgs(t, "--format", "json")...); code != ExitIntegrity || stdout != "" || !strings.Contains(stderr, "pinned in this build") {
		t.Fatalf("check+pin: %d %q %q", code, stdout, stderr)
	}
	if code, stdout, stderr := runScan(t, autoScanArgs(t)...); code != ExitIntegrity || stdout != "" || !strings.Contains(stderr, "pinned in this build") {
		t.Fatalf("scan+pin: %d %q %q", code, stdout, stderr)
	}
}
