// SPDX-License-Identifier: AGPL-3.0-only

package communityapp

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/knowledge"
	"github.com/prufyx/prufyx/cli/internal/knowledgeauto"
	"github.com/prufyx/prufyx/cli/internal/knowledgefixture"
)

const autoFixedNow = "2026-10-04T12:00:00Z"

type autoStoreFixture struct {
	root       string // default store root
	rootDigest string
	repo       *knowledgefixture.ProjectsRepository
}

// useDefaultStoreHome points the default store location at a new directory
// and fixes the clock of automatic embedded evaluations.
func useDefaultStoreHome(t *testing.T) {
	t.Helper()
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	old := autoClock
	autoClock = func() time.Time { return time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC) }
	t.Cleanup(func() { autoClock = old })
}

func pinProjects(t *testing.T, digest string) {
	t.Helper()
	old := pinnedRootDigest
	pinnedRootDigest = func(profile string) string {
		if profile == knowledgeauto.Profile {
			return digest
		}
		return ""
	}
	t.Cleanup(func() { pinnedRootDigest = old })
}

// installDefaultStore installs a verified per-project database (revision 5)
// in the default store location, as db update would.
func installDefaultStore(t *testing.T) autoStoreFixture {
	t.Helper()
	repo, err := knowledgefixture.NewProjectsRepository(time.Now().UTC().Truncate(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(repo.Close)
	root, err := knowledgeauto.EnsureRoot()
	if err != nil {
		t.Fatal(err)
	}
	rootFile := writeCNCFFile(t, "root.json", repo.Root, 0o600)
	pkg := writeCNCFFile(t, "package.tar", perProjectPackage(t, repo, 1, "5"), 0o600)
	if _, err := knowledge.ImportConstraintsProjects(knowledge.ImportRequest{PackagePath: pkg, StoreRoot: root, BootstrapRootPath: rootFile, BootstrapRootDigest: repo.RootDigest}); err != nil {
		t.Fatal(err)
	}
	pinProjects(t, repo.RootDigest)
	return autoStoreFixture{root: root, rootDigest: repo.RootDigest, repo: repo}
}

func autoCheckArgs(t *testing.T, extra ...string) []string {
	t.Helper()
	input := writeCNCFFile(t, "input.json", []byte(kyvernoInputFalse), 0o600)
	return append([]string{"check", "cncf", "--project", "kyverno", "--input", input}, extra...)
}

type autoKnowledgeJSON struct {
	Knowledge struct {
		Origin       string `json:"origin"`
		Revision     string `json:"revision"`
		BundleDigest string `json:"bundleDigest"`
	} `json:"knowledge"`
	KnowledgeOrigin string `json:"knowledgeOrigin"`
}

func decodeAutoJSON(t *testing.T, raw string) autoKnowledgeJSON {
	t.Helper()
	var out autoKnowledgeJSON
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		t.Fatalf("json: %v\n%s", err, raw)
	}
	return out
}

func TestAutoKnowledgeUsesInstalledLocalDB(t *testing.T) {
	useDefaultStoreHome(t)
	installDefaultStore(t)
	code, stdout, stderr := runCNCFCLI(t, autoCheckArgs(t, "--format", "json")...)
	report := decodeAutoJSON(t, stdout)
	if report.Knowledge.Origin == "" || report.Knowledge.Revision != "5" || report.Knowledge.BundleDigest == "" {
		t.Fatalf("not the local database: %d\n%s\n%s", code, stdout, stderr)
	}
	if want := "prufyx: knowledge source: local-db, revision 5, bundle digest " + report.Knowledge.BundleDigest; !strings.Contains(stderr, want) || !strings.Contains(stderr, "embedded would be") {
		t.Fatalf("source line: %q", stderr)
	}
	// The same verdict as an explicit --knowledge-db of the same store.
	explicitCode, explicitOut, explicitErr := runCNCFCLI(t, autoCheckArgs(t, "--format", "json", "--knowledge-db", os.Getenv("XDG_DATA_HOME")+"/prufyx/knowledge/cncf-projects")...)
	if explicitCode != code || explicitErr != "" || decodeAutoJSON(t, explicitOut).Knowledge.BundleDigest != report.Knowledge.BundleDigest {
		t.Fatalf("explicit differs: %d %q\n%s", explicitCode, explicitErr, explicitOut)
	}
	// Human output states the source too.
	_, human, _ := runCNCFCLI(t, autoCheckArgs(t)...)
	if !strings.Contains(human, "knowledge source: local-db (revision 5, bundle digest sha256:") {
		t.Fatalf("human: %s", human)
	}
}

func TestAutoKnowledgeEmbeddedWhenNoStoreOrForcedOrNow(t *testing.T) {
	useDefaultStoreHome(t)
	// --now is the replayable embedded form and is never changed.
	nowCode, nowOut, nowErr := runCNCFCLI(t, autoCheckArgs(t, "--format", "json", "--now", autoFixedNow)...)
	if nowErr != "" || decodeAutoJSON(t, nowOut).KnowledgeOrigin != "embedded" {
		t.Fatalf("--now: %d %q\n%s", nowCode, nowErr, nowOut)
	}
	// No store: embedded at the (fixed) clock, byte-identical to --now.
	code, out, stderr := runCNCFCLI(t, autoCheckArgs(t, "--format", "json")...)
	if code != nowCode || out != nowOut || !strings.Contains(stderr, "knowledge source: embedded, no local knowledge database installed") {
		t.Fatalf("no store: %d %q\n%s", code, stderr, out)
	}
	// An empty default directory is no store.
	if _, err := knowledgeauto.EnsureRoot(); err != nil {
		t.Fatal(err)
	}
	if code, out, _ := runCNCFCLI(t, autoCheckArgs(t, "--format", "json")...); code != nowCode || out != nowOut {
		t.Fatalf("empty dir: %d\n%s", code, out)
	}
	// With a store installed: --now and --knowledge=embedded stay embedded.
	installDefaultStore(t)
	if code, out, stderr := runCNCFCLI(t, autoCheckArgs(t, "--format", "json", "--now", autoFixedNow)...); code != nowCode || out != nowOut || stderr != "" {
		t.Fatalf("--now with store: %d %q\n%s", code, stderr, out)
	}
	code, out, stderr = runCNCFCLI(t, autoCheckArgs(t, "--format", "json", "--knowledge=embedded")...)
	if code != nowCode || out != nowOut || !strings.Contains(stderr, "knowledge source: embedded, forced by --knowledge=embedded") {
		t.Fatalf("forced: %d %q\n%s", code, stderr, out)
	}
	// Conflicts are usage errors.
	if code, out, _ := runCNCFCLI(t, autoCheckArgs(t, "--knowledge=embedded", "--knowledge-db", "/x")...); code != ExitUsage || out != "" {
		t.Fatalf("embedded+db: %d", code)
	}
	if code, _, _ := runCNCFCLI(t, autoCheckArgs(t, "--knowledge=bogus")...); code != ExitUsage {
		t.Fatalf("bogus: %d", code)
	}
}

func TestAutoKnowledgeExplicitDBWins(t *testing.T) {
	useDefaultStoreHome(t)
	installDefaultStore(t)
	other := makeExternalCLIFixture(t)
	input := writeCNCFFile(t, "empty-input.json", []byte(kyvernoInputFalse), 0o600)
	args := []string{"check", "cncf", "--project", "kyverno", "--input", input, "--knowledge-db", other.store, "--format", "json"}
	code, out, stderr := runCNCFCLI(t, args...)
	report := decodeAutoJSON(t, out)
	if stderr != "" || report.Knowledge.Revision != "1" {
		t.Fatalf("explicit store not used: %d %q\n%s", code, stderr, out)
	}
}

func TestAutoKnowledgePresentButUnusableIsRefused(t *testing.T) {
	assertRefused := func(t *testing.T, name string, wantReason string) {
		t.Helper()
		for _, format := range []string{"human", "json"} {
			code, stdout, stderr := runCNCFCLI(t, autoCheckArgs(t, "--format", format)...)
			if code != ExitIntegrity || stdout != "" || !strings.Contains(stderr, "KNOWLEDGE INTEGRITY FAILURE") ||
				!strings.Contains(stderr, "embedded knowledge was not used") || !strings.Contains(stderr, "--knowledge=embedded") || !strings.Contains(stderr, wantReason) {
				t.Fatalf("%s %s: %d %q %q", name, format, code, stdout, stderr)
			}
		}
		// The documented way out works.
		if code, out, _ := runCNCFCLI(t, autoCheckArgs(t, "--format", "json", "--knowledge=embedded")...); decodeAutoJSON(t, out).KnowledgeOrigin != "embedded" {
			t.Fatalf("%s: forced embedded: %d\n%s", name, code, out)
		}
	}
	t.Run("corrupted target", func(t *testing.T) {
		useDefaultStoreHome(t)
		fixture := installDefaultStore(t)
		targets, err := filepath.Glob(filepath.Join(fixture.root, "admissions", "*", "*", "projects", "kyverno.json"))
		if err != nil || len(targets) != 1 {
			t.Fatalf("targets %v %v", targets, err)
		}
		raw, _ := os.ReadFile(targets[0])
		raw[len(raw)/2] ^= 1
		os.Chmod(targets[0], 0o600)
		if err := os.WriteFile(targets[0], raw, 0o600); err != nil {
			t.Fatal(err)
		}
		assertRefused(t, "corrupted", "verification failed")
	})
	t.Run("wrong mode", func(t *testing.T) {
		useDefaultStoreHome(t)
		fixture := installDefaultStore(t)
		if err := os.Chmod(fixture.root, 0o755); err != nil {
			t.Fatal(err)
		}
		assertRefused(t, "mode", "mode 0700")
	})
	t.Run("not a store", func(t *testing.T) {
		useDefaultStoreHome(t)
		root, _ := knowledgeauto.EnsureRoot()
		os.WriteFile(filepath.Join(root, "stray"), []byte("x"), 0o600)
		assertRefused(t, "stray", "not a knowledge database")
	})
	t.Run("different trust root than the pin", func(t *testing.T) {
		useDefaultStoreHome(t)
		installDefaultStore(t)
		pinProjects(t, "sha256:"+strings.Repeat("ab", 32))
		assertRefused(t, "pin", "pinned in this build")
	})
	t.Run("expired", func(t *testing.T) {
		useDefaultStoreHome(t)
		installDefaultStore(t)
		old := autoOpenStore
		autoOpenStore = func(knowledge.SelectionRequest, []string) (knowledge.VerifiedRevision, error) {
			return knowledge.VerifiedRevision{}, errors.Join(knowledge.ErrExpired, knowledge.ErrIntegrity)
		}
		t.Cleanup(func() { autoOpenStore = old })
		assertRefused(t, "expired", "expired")
	})
}

func TestAutoKnowledgeEmbeddedOnlyRoutesKeepRequiringNow(t *testing.T) {
	useDefaultStoreHome(t)
	installDefaultStore(t)
	cm := writeCNCFFile(t, "cm.json", []byte("{}"), 0o600)
	code, out, _ := runCNCFCLI(t, "check", "cncf", "--project", "argo-cd", "--config-map", cm, "--from", "2.14.0", "--to", "3.0.0")
	if code != ExitUsage || out != "" {
		t.Fatalf("embedded-only route without --now: %d %q", code, out)
	}
}

func TestDBUpdateDefaultRootOnlyForOfficialProfile(t *testing.T) {
	useDefaultStoreHome(t)
	out := filepath.Join(t.TempDir(), "pkg.tar")
	var stdout, stderr bytes.Buffer
	code := Run(t.Context(), []string{"db", "update", "--source", "https://example.invalid/p.tar", "--profile", "cert-manager", "--package-out", out}, &stdout, &stderr, "test")
	if code != ExitUsage || !strings.Contains(stderr.String(), "--db-root is required") {
		t.Fatalf("%d %q", code, stderr.String())
	}
	if _, err := os.Stat(filepath.Join(os.Getenv("XDG_DATA_HOME"), "prufyx")); err == nil {
		t.Fatal("default location created for a refused update")
	}
}
