// SPDX-License-Identifier: AGPL-3.0-only

package communityapp

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/buildidentity"
	"github.com/prufyx/prufyx/cli/internal/cncfcheck"
	"github.com/prufyx/prufyx/cli/internal/knowledge"
	"github.com/prufyx/prufyx/cli/internal/knowledgefixture"
	"github.com/prufyx/prufyx/cli/internal/knowledgepin"
)

// withOfficialRoot makes the build pin and embed the given throwaway root for
// cncf-projects, as a shipped build will after the root ceremony.
func withOfficialRoot(t *testing.T, root []byte, digest string) {
	t.Helper()
	oldPin, oldRoot := pinnedRootDigest, embeddedRoot
	pinnedRootDigest = func(profile string) string {
		if profile == "cncf-projects" {
			return digest
		}
		return ""
	}
	embeddedRoot = func(profile string) ([]byte, bool) {
		if profile == "cncf-projects" && root != nil {
			return root, true
		}
		return nil, false
	}
	t.Cleanup(func() { pinnedRootDigest, embeddedRoot = oldPin, oldRoot })
}

// runDefaultUpdate runs `db update` with extra args and a fetcher that only
// accepts the official feed URL.
func runDefaultUpdate(t *testing.T, raw []byte, args ...string) (int, knowledgeUpdateOutput, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	r := runtime{stdout: &stdout, stderr: &stderr}
	fetch := func(_ context.Context, source string) ([]byte, error) {
		if source != knowledgepin.FeedURL {
			t.Fatalf("fetched %q, not the official feed", source)
		}
		if raw == nil {
			t.Fatal("fetch must not happen")
		}
		return raw, nil
	}
	code := r.databaseUpdateWithFetches(context.Background(), append(args, "--format", "json"), fetch, fetch)
	var output knowledgeUpdateOutput
	if stdout.Len() > 0 && json.Unmarshal(stdout.Bytes(), &output) != nil {
		t.Fatalf("invalid update JSON: %s", stdout.String())
	}
	return code, output, stderr.String()
}

type defaultUpdateEnv struct {
	repo        *knowledgefixture.ProjectsRepository
	data        string
	store, pkgs string
}

func newDefaultUpdateEnv(t *testing.T) defaultUpdateEnv {
	t.Helper()
	repo, err := knowledgefixture.NewProjectsRepository(time.Now().UTC().Truncate(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(repo.Close)
	data := t.TempDir()
	t.Setenv("XDG_DATA_HOME", data)
	withOfficialRoot(t, repo.Root, repo.RootDigest)
	return defaultUpdateEnv{repo: repo, data: data,
		store: filepath.Join(data, "prufyx", "knowledge", "cncf-projects"),
		pkgs:  filepath.Join(data, "prufyx", "knowledge", "packages")}
}

func (e defaultUpdateEnv) packageNames(t *testing.T) []string {
	t.Helper()
	entries, err := os.ReadDir(e.pkgs)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	sort.Strings(names)
	return names
}

func TestKnowledgeUpdateNoArgDefaults(t *testing.T) {
	env := newDefaultUpdateEnv(t)
	raw := perProjectPackage(t, env.repo, 1, "4")
	code, out, stderr := runDefaultUpdate(t, raw)
	if code != ExitOK || stderr != "" || out.Status != "IMPORTED" || out.Profile != "cncf-projects" || out.NewRevision != "4" || out.CurrentRevision != "" || out.UpToDate || out.ExpiresAt == "" {
		t.Fatalf("code=%d out=%+v stderr=%s", code, out, stderr)
	}
	// Installed into the default store through the embedded root: no root flag.
	if st, err := knowledge.InspectConstraintsProjects(env.store); err != nil || st.State != "READY" || st.SelectedRevision != "4" {
		t.Fatalf("store: %+v %v", st, err)
	}
	// The package is kept in a private default directory as <revision>-<digest>.tar.
	info, err := os.Stat(env.pkgs)
	if err != nil || info.Mode().Perm() != 0o700 {
		t.Fatalf("package dir: %v %v", info, err)
	}
	want := "4-" + strings.TrimPrefix(out.PackageDigest, "sha256:") + ".tar"
	if names := env.packageNames(t); len(names) != 1 || names[0] != want {
		t.Fatalf("packages = %v, want [%s]", names, want)
	}
	fi, err := os.Stat(filepath.Join(env.pkgs, want))
	if err != nil || fi.Mode().Perm() != 0o600 || !out.PackageRetained {
		t.Fatalf("package file: %v %v", fi, err)
	}
	got, _ := os.ReadFile(filepath.Join(env.pkgs, want))
	if !bytes.Equal(got, raw) {
		t.Fatal("kept package differs from the fetched bytes")
	}
}

func TestKnowledgeUpdateKeepsLastTwoPackages(t *testing.T) {
	env := newDefaultUpdateEnv(t)
	var names []string
	for i, rev := range []string{"4", "5", "6"} {
		code, out, stderr := runDefaultUpdate(t, perProjectPackage(t, env.repo, int64(i+1), rev))
		if code != ExitOK || out.NewRevision != rev {
			t.Fatalf("update %s: code=%d out=%+v stderr=%s", rev, code, out, stderr)
		}
		names = append(names, rev+"-"+strings.TrimPrefix(out.PackageDigest, "sha256:")+".tar")
		if i == 0 {
			// A leftover from a failed run and an unrelated file.
			for _, n := range []string{"incoming-0011223344556677.tar", "notes.txt"} {
				if err := os.WriteFile(filepath.Join(env.pkgs, n), []byte("x"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
		}
	}
	got := env.packageNames(t)
	want := []string{"notes.txt", names[1], names[2]}
	sort.Strings(want)
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("packages = %v, want %v", got, want)
	}
}

func TestKnowledgeUpdateAlreadyUpToDate(t *testing.T) {
	env := newDefaultUpdateEnv(t)
	raw := perProjectPackage(t, env.repo, 1, "4")
	code, first, stderr := runDefaultUpdate(t, raw)
	if code != ExitOK || first.UpToDate {
		t.Fatalf("first: code=%d out=%+v stderr=%s", code, first, stderr)
	}
	var firstHuman bytes.Buffer
	if (runtime{stdout: &firstHuman, stderr: &bytes.Buffer{}}).writeKnowledgeUpdate(first, "human", ExitOK) != ExitOK || !strings.Contains(firstHuman.String(), "knowledge update: IMPORTED\n") {
		t.Fatalf("real import header must stay IMPORTED:\n%s", firstHuman.String())
	}
	code, out, _ := runDefaultUpdate(t, raw)
	if code != ExitOK || !out.UpToDate || out.CurrentRevision != "4" || out.NewRevision != "4" || out.ReasonCode != "KNOWLEDGE_ALREADY_UP_TO_DATE" {
		t.Fatalf("second: code=%d out=%+v", code, out)
	}
	if names := env.packageNames(t); len(names) != 1 {
		t.Fatalf("packages = %v", names)
	}
	var human bytes.Buffer
	if runtime := (runtime{stdout: &human, stderr: &bytes.Buffer{}}); runtime.writeKnowledgeUpdate(out, "human", ExitOK) != ExitOK {
		t.Fatal("human output failed")
	}
	for _, want := range []string{"knowledge update: local database already up to date (nothing imported)", "current revision: 4", "new revision: 4", "trust metadata expires: ", "already up to date"} {
		if !strings.Contains(human.String(), want) {
			t.Fatalf("human output lacks %q:\n%s", want, human.String())
		}
	}
}

func TestKnowledgeUpdateFeedBehindIsNotAnIntegrityFailure(t *testing.T) {
	env := newDefaultUpdateEnv(t)
	old := perProjectPackage(t, env.repo, 1, "4")
	if code, _, stderr := runDefaultUpdate(t, old); code != ExitOK {
		t.Fatal(code, stderr)
	}
	if code, _, stderr := runDefaultUpdate(t, perProjectPackage(t, env.repo, 2, "5")); code != ExitOK {
		t.Fatal(code, stderr)
	}
	before := env.packageNames(t)
	code, out, stderr := runDefaultUpdate(t, old)
	if code != ExitFeedBehind || out.Status != "FEED_BEHIND" || out.ReasonCode != "KNOWLEDGE_FEED_BEHIND" || out.PackageRetained || out.Rejection != nil || stderr != "" {
		t.Fatalf("code=%d out=%+v stderr=%s", code, out, stderr)
	}
	if !strings.Contains(out.NextAction, "retry") {
		t.Fatalf("next action = %q", out.NextAction)
	}
	if after := env.packageNames(t); strings.Join(after, ",") != strings.Join(before, ",") {
		t.Fatalf("packages changed: %v -> %v", before, after)
	}
	if st, err := knowledge.InspectConstraintsProjects(env.store); err != nil || st.SelectedRevision != "5" {
		t.Fatalf("store moved: %+v %v", st, err)
	}
}

func TestKnowledgeUpdateRootMismatchTellsToRemoveStore(t *testing.T) {
	env := newDefaultUpdateEnv(t)
	raw := perProjectPackage(t, env.repo, 1, "4")
	if code, _, stderr := runDefaultUpdate(t, raw); code != ExitOK {
		t.Fatal(code, stderr)
	}
	other, err := knowledgefixture.NewProjectsRepository(time.Now().UTC().Truncate(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	withOfficialRoot(t, other.Root, other.RootDigest)
	code, out, _ := runDefaultUpdate(t, perProjectPackage(t, env.repo, 2, "5"))
	if code != ExitIntegrity || out.ReasonCode != "KNOWLEDGE_STORE_ROOT_NOT_PINNED" || !strings.Contains(out.NextAction, "remove the store directory "+env.store) || out.PackageRetained {
		t.Fatalf("code=%d out=%+v", code, out)
	}
	if st, err := knowledge.InspectConstraintsProjects(env.store); err != nil || st.SelectedRevision != "4" {
		t.Fatalf("store changed: %+v %v", st, err)
	}
}

func TestKnowledgeUpdateNoArgNeedsAnEmbeddedRootAndPin(t *testing.T) {
	repo, err := knowledgefixture.NewProjectsRepository(time.Now().UTC().Truncate(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	defer repo.Close()
	for name, setup := range map[string]func(){
		"no pin, no embedded root":  func() { withOfficialRoot(t, nil, "") },
		"pin without embedded root": func() { withOfficialRoot(t, nil, repo.RootDigest) },
		"embedded root not the pin": func() { withOfficialRoot(t, repo.Root, "sha256:"+strings.Repeat("ab", 32)) },
	} {
		t.Run(name, func(t *testing.T) {
			t.Setenv("XDG_DATA_HOME", t.TempDir())
			setup()
			// A nil package makes the fetcher fail the test: nothing may be fetched.
			var stderr bytes.Buffer
			r := runtime{stdout: &bytes.Buffer{}, stderr: &stderr}
			fetch := func(context.Context, string) ([]byte, error) {
				t.Fatal("fetched without a trust root")
				return nil, nil
			}
			if code := r.databaseUpdateWithFetches(context.Background(), nil, fetch, fetch); code != ExitUsage || !strings.Contains(stderr.String(), "no trust root") {
				t.Fatalf("code=%d stderr=%s", code, stderr.String())
			}
		})
	}
}

func TestKnowledgeUpdateExplicitFlagsKeepTodaysRules(t *testing.T) {
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	for name, args := range map[string][]string{
		"source without package-out":       {"--source", "https://metadata.example.test/knowledge.tar"},
		"cncf profile without package-out": {"--source", "https://metadata.example.test/knowledge.tar", "--profile", "cncf"},
		"other profile without source":     {"--profile", "cert-manager", "--package-out", filepath.Join(t.TempDir(), "p.tar")},
		"release plan without package-out": {"--release-plan", filepath.Join(t.TempDir(), "plan.json")},
		"empty explicit source":            {"--source", ""},
	} {
		var stderr bytes.Buffer
		r := runtime{stdout: &bytes.Buffer{}, stderr: &stderr}
		fetch := func(context.Context, string) ([]byte, error) { t.Fatalf("%s: fetched", name); return nil, nil }
		if code := r.databaseUpdateWithFetches(context.Background(), args, fetch, fetch); code != ExitUsage {
			t.Fatalf("%s: code=%d stderr=%s", name, code, stderr.String())
		}
	}
}

// A newer signed timestamp that carries an older revision is an anomaly, not a
// stale feed: it stays a rollback refusal (exit 3).
func TestKnowledgeUpdateRevisionRegressionIsARollback(t *testing.T) {
	env := newDefaultUpdateEnv(t)
	if code, _, stderr := runDefaultUpdate(t, perProjectPackage(t, env.repo, 1, "5")); code != ExitOK {
		t.Fatal(code, stderr)
	}
	code, out, _ := runDefaultUpdate(t, perProjectPackage(t, env.repo, 2, "4"))
	if code != ExitIntegrity || out.Status == "FEED_BEHIND" || out.ReasonCode == "KNOWLEDGE_FEED_BEHIND" {
		t.Fatalf("code=%d out=%+v", code, out)
	}
	if st, err := knowledge.InspectConstraintsProjects(env.store); err != nil || st.SelectedRevision != "5" {
		t.Fatalf("store moved: %+v %v", st, err)
	}
}

// A package signed by the pinned root that names a newer minimum client is
// reported as too new: exit 15, trust not advanced, the store untouched.
func TestKnowledgeUpdateTooNewForThisClient(t *testing.T) {
	old := buildidentity.Version
	buildidentity.Version = "v0.1.0-beta.0"
	t.Cleanup(func() { buildidentity.Version = old })
	env := newDefaultUpdateEnv(t)
	if code, _, stderr := runDefaultUpdate(t, perProjectPackage(t, env.repo, 1, "4")); code != ExitOK {
		t.Fatal(code, stderr)
	}
	index, projects, err := cncfcheck.BuildEmbeddedExternalTargets("5", nil)
	if err != nil {
		t.Fatal(err)
	}
	indexRaw := append(append([]byte(nil), index.Bytes[:len(index.Bytes)-1]...), []byte(`,"minClientVersion":"v0.3.0"}`)...)
	targets := map[string][]byte{index.Path: indexRaw}
	for _, project := range projects {
		targets[project.Path] = project.Bytes
	}
	raw, err := env.repo.Package(knowledgefixture.ProjectsPackage{Version: 2, Targets: targets})
	if err != nil {
		t.Fatal(err)
	}
	code, out, _ := runDefaultUpdate(t, raw)
	if code != ExitKnowledgeTooNew || out.ReasonCode != "KNOWLEDGE_TOO_NEW_FOR_THIS_CLIENT" || out.Rejection == nil || out.Rejection.TrustStateAdvanced || out.ImportReceipt != nil {
		t.Fatalf("code=%d out=%+v", code, out)
	}
	if !strings.Contains(out.NextAction, "upgrade prufyx to >= v0.3.0") || !strings.Contains(out.NextAction, "stay in use") {
		t.Fatalf("next action = %q", out.NextAction)
	}
	if st, err := knowledge.InspectConstraintsProjects(env.store); err != nil || st.State != "READY" || st.SelectedRevision != "4" {
		t.Fatalf("store changed: %+v %v", st, err)
	}
}
