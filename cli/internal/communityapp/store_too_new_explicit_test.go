// SPDX-License-Identifier: AGPL-3.0-only

package communityapp

import (
	"bytes"
	"os"
	"path/filepath"
	goruntime "runtime"
	"strings"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/buildidentity"
	"github.com/prufyx/prufyx/cli/internal/cncfcheck"
	"github.com/prufyx/prufyx/cli/internal/knowledge"
	"github.com/prufyx/prufyx/cli/internal/knowledgefixture"
)

// tooNewExplicitStore imports, with a development build, a real signed
// per-project store whose index names minClientVersion v0.2.0, then makes this
// build a release that cannot read it.
func tooNewExplicitStore(t *testing.T) string {
	t.Helper()
	old := buildidentity.Version
	buildidentity.Version = buildidentity.DevelopmentVersion
	t.Cleanup(func() { buildidentity.Version = old })
	repo, err := knowledgefixture.NewProjectsRepository(time.Now().UTC().Truncate(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(repo.Close)
	index, projects, err := cncfcheck.BuildEmbeddedExternalTargets("5", nil)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasSuffix(index.Bytes, []byte("}")) {
		t.Fatal("index is not a JSON object")
	}
	targets := map[string][]byte{index.Path: append(append([]byte(nil), index.Bytes[:len(index.Bytes)-1]...), []byte(`,"minClientVersion":"v0.2.0"}`)...)}
	for _, project := range projects {
		targets[project.Path] = project.Bytes
	}
	raw, err := repo.Package(knowledgefixture.ProjectsPackage{Version: 1, Targets: targets})
	if err != nil {
		t.Fatal(err)
	}
	store := filepath.Join(t.TempDir(), "store")
	rootFile := writeCNCFFile(t, "root.json", repo.Root, 0o600)
	pkg := writeCNCFFile(t, "package.tar", raw, 0o600)
	if r, err := knowledge.ImportConstraintsProjects(knowledge.ImportRequest{PackagePath: pkg, StoreRoot: store, BootstrapRootPath: rootFile, BootstrapRootDigest: repo.RootDigest}); err != nil || r.Status != "IMPORTED" {
		t.Fatalf("dev import: %+v err=%v", r, err)
	}
	releaseIdentity(t, "v0.1.0-beta.0")
	return store
}

// releaseIdentity makes this build a release candidate of the given version
// with a complete linker identity, as scan reads it before opening knowledge.
func releaseIdentity(t *testing.T, version string) {
	t.Helper()
	oldVersion, oldRev, oldTree, oldAllow, oldProfile, oldEpoch, oldRoot, oldEmbedded := buildidentity.Version, buildidentity.SourceRevision, buildidentity.SourceTreeDigest, buildidentity.AllowlistDigest, buildidentity.BuildProfile, buildidentity.BuildEpoch, buildidentity.TrustRootDigest, buildidentity.EmbeddedIdentity
	t.Cleanup(func() {
		buildidentity.Version, buildidentity.SourceRevision, buildidentity.SourceTreeDigest, buildidentity.AllowlistDigest, buildidentity.BuildProfile, buildidentity.BuildEpoch, buildidentity.TrustRootDigest, buildidentity.EmbeddedIdentity = oldVersion, oldRev, oldTree, oldAllow, oldProfile, oldEpoch, oldRoot, oldEmbedded
	})
	buildidentity.Version = version
	buildidentity.SourceRevision = "0123456789abcdef0123456789abcdef01234567"
	buildidentity.SourceTreeDigest = "sha256:" + strings.Repeat("a", 64)
	buildidentity.AllowlistDigest = "sha256:" + strings.Repeat("b", 64)
	buildidentity.BuildProfile = "community-linux-amd64"
	buildidentity.BuildEpoch = "1700000000"
	buildidentity.TrustRootDigest = buildidentity.UnpinnedTrustRoot
	buildidentity.EmbeddedIdentity = buildidentity.Marker(buildidentity.Identity{Version: version, ReleaseState: buildidentity.ReleaseStateRelease, SourceRevision: buildidentity.SourceRevision, SourceTreeDigest: buildidentity.SourceTreeDigest, AllowlistDigest: buildidentity.AllowlistDigest, BuildProfile: buildidentity.BuildProfile, BuildEpoch: "2023-11-14T22:13:20Z", GoVersion: goruntime.Version(), TrustRootDigest: buildidentity.TrustRootDigest, CandidateOnly: true})
}

func flipStoreFile(t *testing.T, store, suffix string) {
	t.Helper()
	var victim string
	err := filepath.WalkDir(store, func(p string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() && strings.HasSuffix(filepath.ToSlash(p), suffix) && victim == "" {
			victim = p
		}
		return err
	})
	if err != nil || victim == "" {
		t.Fatalf("no %s in store: %v", suffix, err)
	}
	raw, err := os.ReadFile(victim)
	if err != nil {
		t.Fatal(err)
	}
	raw[len(raw)/2] ^= 0x01
	if err := os.WriteFile(victim, raw, 0o600); err != nil {
		t.Fatal(err)
	}
}

// An explicit --knowledge-db that holds a real signed store this build cannot
// read exits 15 with a too-new message for scan and check cncf, evaluates
// nothing and never uses the embedded knowledge; tampering with the same
// store still exits 3.
func TestExplicitKnowledgeDBTooNewExitsFifteen(t *testing.T) {
	useDefaultStoreHome(t)
	store := tooNewExplicitStore(t)
	scan := func() (int, string, string) {
		return runScan(t, append(autoScanArgs(t), "--knowledge-db", store)...)
	}
	check := func() (int, string, string) {
		return runCNCFCLI(t, autoCheckArgs(t, "--format", "json", "--knowledge-db", store)...)
	}
	for name, run := range map[string]func() (int, string, string){"scan": scan, "check cncf": check} {
		code, stdout, stderr := run()
		if code != ExitKnowledgeTooNew || stdout != "" || !strings.Contains(strings.ToLower(stderr), "too new") || !strings.Contains(stderr, "upgrade prufyx") || !strings.Contains(stderr, "drop --knowledge-db") || strings.Contains(stderr, "INTEGRITY FAILURE") {
			t.Fatalf("%s too new: %d %q %q", name, code, stdout, stderr)
		}
	}
	if _, _, stderr := scan(); !strings.Contains(stderr, "v0.2.0") {
		t.Fatalf("scan does not name the minimum: %q", stderr)
	}
	flipStoreFile(t, store, "/target.json")
	for name, run := range map[string]func() (int, string, string){"scan": scan, "check cncf": check} {
		if code, stdout, stderr := run(); code != ExitIntegrity || stdout != "" || strings.Contains(strings.ToLower(stderr), "too new") {
			t.Fatalf("%s tampered: %d %q %q", name, code, stdout, stderr)
		}
	}
}
