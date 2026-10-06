// SPDX-License-Identifier: AGPL-3.0-only

package communityapp

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/knowledge"
	"github.com/prufyx/prufyx/cli/internal/knowledgeauto"
	"github.com/prufyx/prufyx/cli/internal/knowledgefixture"
)

const autoScanInput = scanCronJob

func autoScanArgs(t *testing.T) []string {
	t.Helper()
	input := filepath.Join(t.TempDir(), "applyset.yaml")
	if err := os.WriteFile(input, []byte(autoScanInput), 0o600); err != nil {
		t.Fatal(err)
	}
	return []string{input, "--from", "kubernetes=1.24.17", "--to", "kubernetes=1.25.3", "--distribution", "official_upstream", "--resource-scope-complete", "--target-api-apply-required", "--format", "json"}
}

// importProjectsInto imports a per-project package of the given revision into
// root with a repository created at repoNow.
func importProjectsInto(t *testing.T, root string, repoNow time.Time, revision string) (*knowledgefixture.ProjectsRepository, error) {
	t.Helper()
	repo, err := knowledgefixture.NewProjectsRepository(repoNow)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(repo.Close)
	rootFile := writeCNCFFile(t, "root.json", repo.Root, 0o600)
	pkg := writeCNCFFile(t, "package.tar", perProjectPackage(t, repo, 1, revision), 0o600)
	_, err = knowledge.ImportConstraintsProjects(knowledge.ImportRequest{PackagePath: pkg, StoreRoot: root, BootstrapRootPath: rootFile, BootstrapRootDigest: repo.RootDigest})
	return repo, err
}

// B1: the store that is evaluated is the store that was verified. A store
// swapped in after verification (or a concurrent db update) is refused.
func TestAutoKnowledgeCheckRefusesStoreSwappedAfterVerification(t *testing.T) {
	useDefaultStoreHome(t)
	fixture := installDefaultStore(t)
	pinProjects(t, "") // the swapped store has another root: only the binding can stop it
	old := autoOpenStore
	swapped := false
	autoOpenStore = func(req knowledge.SelectionRequest, projects []string) (knowledge.VerifiedRevision, error) {
		selected, err := old(req, projects)
		if err == nil && !swapped {
			swapped = true
			if rmErr := os.RemoveAll(fixture.root); rmErr != nil {
				t.Fatal(rmErr)
			}
			root, ensureErr := knowledgeauto.EnsureRoot()
			if ensureErr != nil {
				t.Fatal(ensureErr)
			}
			if _, impErr := importProjectsInto(t, root, time.Now().UTC().Truncate(time.Second), "7"); impErr != nil {
				t.Fatal(impErr)
			}
		}
		return selected, err
	}
	t.Cleanup(func() { autoOpenStore = old })
	for _, format := range []string{"human", "json"} {
		code, stdout, stderr := runCNCFCLI(t, autoCheckArgs(t, "--format", format)...)
		if !swapped || code != ExitIntegrity || stdout != "" {
			t.Fatalf("%s: swapped=%v code=%d stdout=%q stderr=%q", format, swapped, code, stdout, stderr)
		}
		swapped = false
		if err := os.RemoveAll(fixture.root); err != nil {
			t.Fatal(err)
		}
		root, _ := knowledgeauto.EnsureRoot()
		if _, err := importProjectsInto(t, root, time.Now().UTC().Truncate(time.Second), "5"); err != nil {
			t.Fatal(err)
		}
	}
}

// A store that changes revision between verification and evaluation (a
// concurrent db update) is refused too, never reported under the old source.
func TestAutoKnowledgeCheckRefusesConcurrentUpdate(t *testing.T) {
	useDefaultStoreHome(t)
	fixture := installDefaultStore(t)
	old := autoOpenStore
	autoOpenStore = func(req knowledge.SelectionRequest, projects []string) (knowledge.VerifiedRevision, error) {
		selected, err := old(req, projects)
		if err == nil {
			pkg := writeCNCFFile(t, "package2.tar", perProjectPackage(t, fixture.repo, 2, "6"), 0o600)
			if _, impErr := knowledge.ImportConstraintsProjects(knowledge.ImportRequest{PackagePath: pkg, StoreRoot: fixture.root}); impErr != nil {
				t.Fatal(impErr)
			}
		}
		return selected, err
	}
	t.Cleanup(func() { autoOpenStore = old })
	code, stdout, stderr := runCNCFCLI(t, autoCheckArgs(t, "--format", "json")...)
	if code != ExitIntegrity || stdout != "" {
		t.Fatalf("concurrent update: %d %q %q", code, stdout, stderr)
	}
}

// M2: a first db update that never committed a revision leaves only
// bootstrap artefacts, and the store counts as absent (embedded knowledge);
// anything committed but invalid is still refused.
func TestAutoKnowledgeFailedFirstInstallIsAbsent(t *testing.T) {
	useDefaultStoreHome(t)
	root, err := knowledgeauto.EnsureRoot()
	if err != nil {
		t.Fatal(err)
	}
	repo, err := knowledgefixture.NewProjectsRepository(time.Now().UTC().Truncate(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(repo.Close)
	rootFile := writeCNCFFile(t, "root.json", repo.Root, 0o600)
	pkg := writeCNCFFile(t, "package.tar", perProjectPackage(t, repo, 1, "5"), 0o600)
	_, err = knowledge.ImportConstraintsProjects(knowledge.ImportRequest{PackagePath: pkg, StoreRoot: root, BootstrapRootPath: rootFile, BootstrapRootDigest: "sha256:" + strings.Repeat("00", 32)})
	if err == nil {
		t.Fatal("a wrong bootstrap digest was accepted")
	}
	if entries, _ := os.ReadDir(root); len(entries) == 0 {
		t.Fatal("the failed import left nothing: the test no longer covers M2")
	}
	args := autoCheckArgs(t, "--format", "json")
	if code, out, stderr := runCNCFCLI(t, args...); code == ExitIntegrity || !strings.Contains(stderr, "embedded, no local knowledge database installed") || decodeAutoJSON(t, out).KnowledgeOrigin != "embedded" {
		t.Fatalf("check after failed install: %d %q\n%s", code, stderr, out)
	}
	scanArgs := autoScanArgs(t)
	if code, _, stderr := runScan(t, scanArgs...); code == ExitIntegrity || !strings.Contains(stderr, "embedded, no local knowledge database installed") {
		t.Fatalf("scan after failed install: %d %q", code, stderr)
	}
	// The next, correct install works in the same directory.
	pinProjects(t, repo.RootDigest)
	if _, err := knowledge.ImportConstraintsProjects(knowledge.ImportRequest{PackagePath: pkg, StoreRoot: root, BootstrapRootPath: rootFile, BootstrapRootDigest: repo.RootDigest}); err != nil {
		t.Fatalf("install after a failed one: %v", err)
	}
	if code, out, _ := runCNCFCLI(t, args...); decodeAutoJSON(t, out).Knowledge.Revision != "5" {
		t.Fatalf("after install: %d\n%s", code, out)
	}
}

func TestAutoKnowledgeCommittedButInvalidStaysRefused(t *testing.T) {
	refused := func(t *testing.T) {
		t.Helper()
		if code, out, _ := runCNCFCLI(t, autoCheckArgs(t, "--format", "json")...); code != ExitIntegrity || out != "" {
			t.Fatalf("check: %d %q", code, out)
		}
		if code, out, _ := runScan(t, autoScanArgs(t)...); code != ExitIntegrity || out != "" {
			t.Fatalf("scan: %d %q", code, out)
		}
	}
	t.Run("selection removed", func(t *testing.T) {
		useDefaultStoreHome(t)
		fixture := installDefaultStore(t)
		if err := os.Remove(filepath.Join(fixture.root, "selection.json")); err != nil {
			t.Fatal(err)
		}
		refused(t)
	})
	t.Run("pending import", func(t *testing.T) {
		useDefaultStoreHome(t)
		fixture := installDefaultStore(t)
		if err := os.WriteFile(filepath.Join(fixture.root, "import-pending.json"), []byte("{}"), 0o600); err != nil {
			t.Fatal(err)
		}
		refused(t)
	})
	t.Run("only a marker but a stray file", func(t *testing.T) {
		useDefaultStoreHome(t)
		root, _ := knowledgeauto.EnsureRoot()
		os.WriteFile(filepath.Join(root, "profile.json"), []byte("{}"), 0o600)
		os.WriteFile(filepath.Join(root, "stray"), []byte("x"), 0o600)
		refused(t)
	})
}

// Real expiry and real clock rollback (no stub): the store is signed so its
// timestamp expires a few seconds after the import.
func TestAutoKnowledgeExpiredStoreIsRefusedByCheckAndScan(t *testing.T) {
	useDefaultStoreHome(t)
	root, err := knowledgeauto.EnsureRoot()
	if err != nil {
		t.Fatal(err)
	}
	repoNow := time.Now().UTC().Truncate(time.Second).Add(-24*time.Hour + 6*time.Second) // timestamp expires at repoNow+24h
	repo, err := importProjectsInto(t, root, repoNow, "5")
	if err != nil {
		t.Fatal(err)
	}
	pinProjects(t, repo.RootDigest)
	if code, out, _ := runCNCFCLI(t, autoCheckArgs(t, "--format", "json")...); code == ExitIntegrity {
		t.Skipf("the store expired before the first use (slow machine): %s", out)
	}
	time.Sleep(time.Until(repoNow.Add(24*time.Hour)) + 1500*time.Millisecond)
	for _, format := range []string{"human", "json"} {
		code, stdout, stderr := runCNCFCLI(t, autoCheckArgs(t, "--format", format)...)
		if code != ExitIntegrity || stdout != "" || !strings.Contains(stderr, "expired") || !strings.Contains(stderr, "embedded knowledge was not used") {
			t.Fatalf("check %s: %d %q %q", format, code, stdout, stderr)
		}
	}
	code, stdout, stderr := runScan(t, autoScanArgs(t)...)
	if code != ExitIntegrity || stdout != "" || !strings.Contains(stderr, "embedded knowledge was not used") {
		t.Fatalf("scan: %d %q %q", code, stdout, stderr)
	}
	if code, out, _ := runCNCFCLI(t, autoCheckArgs(t, "--format", "json", "--knowledge=embedded")...); decodeAutoJSON(t, out).KnowledgeOrigin != "embedded" {
		t.Fatalf("way out: %d", code)
	}
}

func TestAutoKnowledgeClockRollbackIsRefusedByCheckAndScan(t *testing.T) {
	useDefaultStoreHome(t)
	fixture := installDefaultStore(t)
	// Move the stored clock floor into the future, in the stored encoding.
	path := filepath.Join(fixture.root, "clock-floor.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var floor struct {
		CheckedAt string `json:"checkedAt"`
	}
	if err := json.Unmarshal(raw, &floor); err != nil {
		t.Fatal(err)
	}
	future := time.Now().UTC().Add(48 * time.Hour).Format(time.RFC3339)
	moved := strings.Replace(string(raw), floor.CheckedAt, future, 1)
	if moved == string(raw) {
		t.Fatalf("floor not changed: %s", raw)
	}
	os.Chmod(path, 0o600)
	if err := os.WriteFile(path, []byte(moved), 0o600); err != nil {
		t.Fatal(err)
	}
	code, stdout, stderr := runCNCFCLI(t, autoCheckArgs(t, "--format", "json")...)
	if code != ExitIntegrity || stdout != "" || !strings.Contains(stderr, "rollback") {
		t.Fatalf("check: %d %q %q", code, stdout, stderr)
	}
	code, stdout, stderr = runScan(t, autoScanArgs(t)...)
	if code != ExitIntegrity || stdout != "" || !strings.Contains(stderr, "embedded knowledge was not used") {
		t.Fatalf("scan: %d %q %q", code, stdout, stderr)
	}
}

// m7: a single-target (cncf) layout in the default per-project location is
// refused, whatever the pin.
func TestAutoKnowledgeWrongProfileLayoutIsRefused(t *testing.T) {
	useDefaultStoreHome(t)
	pinProjects(t, "")
	external := makeExternalCLIFixture(t)
	root, err := knowledgeauto.EnsureRoot()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(root); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(external.store, root); err != nil {
		t.Fatal(err)
	}
	code, stdout, stderr := runCNCFCLI(t, autoCheckArgs(t, "--format", "json")...)
	if code != ExitIntegrity || stdout != "" || !strings.Contains(stderr, "KNOWLEDGE INTEGRITY FAILURE") {
		t.Fatalf("check: %d %q %q", code, stdout, stderr)
	}
	code, stdout, stderr = runScan(t, autoScanArgs(t)...)
	if code != ExitIntegrity || stdout != "" || !strings.Contains(stderr, "layout") {
		t.Fatalf("scan: %d %q %q", code, stdout, stderr)
	}
}

// M4: the age of the database in use is visible on standard error.
func TestAutoKnowledgeStatesDatabaseAge(t *testing.T) {
	useDefaultStoreHome(t)
	installDefaultStore(t)
	_, _, stderr := runCNCFCLI(t, autoCheckArgs(t, "--format", "json")...)
	if !strings.Contains(stderr, "prufyx: note: local database last verified at 20") || !strings.Contains(stderr, "signed evidence expires") {
		t.Fatalf("check: %q", stderr)
	}
	_, _, stderr = runScan(t, autoScanArgs(t)...)
	if !strings.Contains(stderr, "prufyx: note: local database last verified at 20") {
		t.Fatalf("scan: %q", stderr)
	}
}
