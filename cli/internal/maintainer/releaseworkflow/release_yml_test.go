// SPDX-License-Identifier: AGPL-3.0-only

package releaseworkflow

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/prufyx/prufyx/cli/internal/buildidentity"
)

// The public release workflow (.github/workflows/release.yml) builds the
// attested Community archives. These tests pin the properties of that file
// that the trust chain rests on. They need the repository checkout; the
// staged release source tree (`release test`) contains only cli/, so there
// they are skipped.

type workflowStep struct {
	Name string            `yaml:"name"`
	Uses string            `yaml:"uses"`
	With map[string]any    `yaml:"with"`
	Env  map[string]string `yaml:"env"`
	Run  string            `yaml:"run"`
}

type workflowFile struct {
	Jobs map[string]struct {
		Environment any            `yaml:"environment"`
		Steps       []workflowStep `yaml:"steps"`
	} `yaml:"jobs"`
}

func releaseWorkflow(t *testing.T) workflowFile {
	t.Helper()
	return loadWorkflow(t, "release.yml")
}

func loadWorkflow(t *testing.T, file string) workflowFile {
	t.Helper()
	_, self, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate the test source")
	}
	repo := filepath.Join(filepath.Dir(self), "..", "..", "..", "..")
	if _, err := os.Stat(filepath.Join(repo, "cli", "go.mod")); err != nil {
		t.Fatalf("repository root not found: %v", err)
	}
	path := filepath.Join(repo, ".github", "workflows", file)
	if _, err := os.Stat(filepath.Join(repo, ".github")); os.IsNotExist(err) {
		t.Skip("no .github directory: staged release source tree")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var wf workflowFile
	if err := yaml.Unmarshal(raw, &wf); err != nil {
		t.Fatal(err)
	}
	if len(wf.Jobs) == 0 {
		t.Fatalf("%s has no jobs", file)
	}
	return wf
}

func workflowStepNamed(t *testing.T, wf workflowFile, job, name string) workflowStep {
	t.Helper()
	for _, step := range wf.Jobs[job].Steps {
		if step.Name == name {
			return step
		}
	}
	t.Fatalf("release workflow job %s has no step %q", job, name)
	return workflowStep{}
}

// A tag-triggered build whose archives are attested must not restore a
// cache that another workflow run (any run on the default branch can write
// one the tag can read) may have written: a poisoned Go build cache entry
// would be linked into the binary and then attested as built from the tag.
// actions/setup-go enables its module and build cache unless told not to.
// Checkout must not leave the job token in .git/config while repository
// code is built.
func TestReleaseWorkflowRestoresNoCacheAndKeepsNoToken(t *testing.T) {
	wf := releaseWorkflow(t)
	setupGo, checkouts := 0, 0
	for job, def := range wf.Jobs {
		for _, step := range def.Steps {
			switch {
			case strings.HasPrefix(step.Uses, "actions/setup-go@"):
				setupGo++
				if v, ok := step.With["cache"].(bool); !ok || v {
					t.Errorf("job %s step %q: actions/setup-go must set cache: false", job, step.Name)
				}
			case strings.HasPrefix(step.Uses, "actions/checkout@"):
				checkouts++
				if v, ok := step.With["persist-credentials"].(bool); !ok || v {
					t.Errorf("job %s step %q: actions/checkout must set persist-credentials: false", job, step.Name)
				}
			case strings.HasPrefix(step.Uses, "actions/cache"):
				t.Errorf("job %s step %q: the release workflow must not use actions/cache", job, step.Name)
			}
		}
	}
	if setupGo == 0 || checkouts == 0 {
		t.Fatalf("expected setup-go and checkout steps, found %d and %d", setupGo, checkouts)
	}
}

// The release toolchain is an exact patch release, not whatever 1.26.x the
// runner has: the attested identity embeds the Go version and the binary
// bytes depend on it.
func TestReleaseWorkflowPinsTheExactGoToolchain(t *testing.T) {
	step := workflowStepNamed(t, releaseWorkflow(t), "build", "Set up Go")
	if v, _ := step.With["go-version"].(string); v != "1.26.8" {
		t.Errorf("go-version = %v, want the exact release \"1.26.8\"", step.With["go-version"])
	}
	if _, ok := step.With["go-version-file"]; ok {
		t.Error("go-version-file must not be set next to an exact go-version")
	}
	if v, ok := step.With["cache"].(bool); !ok || v {
		t.Error("cache must be false")
	}
}

// Both go build lines use -trimpath (without it the linker flags are
// recorded in the build info and the identity grep proves nothing), and the
// workflow rejects a binary that records them anyway.
func TestReleaseWorkflowRequiresTrimpathAndGuardsLdflags(t *testing.T) {
	build := workflowStepNamed(t, releaseWorkflow(t), "build", "Build binaries").Run
	builds := 0
	for _, line := range strings.Split(strings.ReplaceAll(build, "\\\n", " "), "\n") {
		if strings.Contains(line, "go build ") {
			builds++
			if !strings.Contains(line, "-trimpath") {
				t.Errorf("go build without -trimpath: %s", strings.TrimSpace(line))
			}
		}
	}
	if builds != 2 {
		t.Errorf("found %d go build lines, want 2", builds)
	}
	if !strings.Contains(build, `if go version -m "${bin}" | grep -q -- '-ldflags='`) {
		t.Error("Build binaries step lacks the build-info -ldflags guard")
	}
}

// The draft release takes its text from the committed notes file (and fails
// without it), marks hyphenated tags as pre-releases, and its checkout keeps
// no token. The tag must also be on main.
func TestReleaseWorkflowDraftUsesNotesFileAndPrerelease(t *testing.T) {
	wf := releaseWorkflow(t)
	draft := workflowStepNamed(t, wf, "draft-release", "Create draft GitHub release").Run
	for _, want := range []string{"--notes-file", "cli/docs/release-notes-${GITHUB_REF_NAME}.md", "--prerelease", "*-*)", "exit 1"} {
		if !strings.Contains(draft, want) {
			t.Errorf("draft release step lacks %q", want)
		}
	}
	if strings.Contains(draft, "--notes ") {
		t.Error("draft release must not use inline --notes text")
	}
	checkout := workflowStepNamed(t, wf, "draft-release", "Checkout release notes")
	if v, ok := checkout.With["persist-credentials"].(bool); !ok || v {
		t.Error("the draft-release checkout must set persist-credentials: false")
	}
	onMain := workflowStepNamed(t, wf, "build", "Check the tagged commit is on main").Run
	if !strings.Contains(onMain, "git merge-base --is-ancestor") || !strings.Contains(onMain, "origin/main") {
		t.Error("tagged-commit-on-main check is missing")
	}
}

// The workflow that holds the TUF signing secrets restores no cache, keeps
// no token in the checkout and runs in a protected environment.
func TestKnowledgeReleaseWorkflowIsHardened(t *testing.T) {
	wf := loadWorkflow(t, "knowledge-release.yml")
	job, ok := wf.Jobs["release"]
	if !ok {
		t.Fatal("knowledge-release.yml has no release job")
	}
	if env, _ := job.Environment.(string); env != "knowledge-release" {
		t.Errorf("environment = %v, want knowledge-release", job.Environment)
	}
	setupGo, checkouts := 0, 0
	for _, step := range job.Steps {
		switch {
		case strings.HasPrefix(step.Uses, "actions/setup-go@"):
			setupGo++
			if v, ok := step.With["cache"].(bool); !ok || v {
				t.Error("knowledge release: setup-go must set cache: false")
			}
		case strings.HasPrefix(step.Uses, "actions/checkout@"):
			checkouts++
			if v, ok := step.With["persist-credentials"].(bool); !ok || v {
				t.Error("knowledge release: checkout must set persist-credentials: false")
			}
		case strings.HasPrefix(step.Uses, "actions/cache"):
			t.Error("knowledge release must not use actions/cache")
		}
	}
	if setupGo != 1 || checkouts != 1 {
		t.Errorf("expected one setup-go and one checkout, found %d and %d", setupGo, checkouts)
	}
}

// The build identity a release binary carries is fixed by
// internal/buildidentity: its trust root field is the canonical UNPINNED.
// The workflow must inject exactly that value, in the linker flag and in
// the embedded marker, and must check that the binary it built carries the
// identity it computed before the archive is attested.
func TestReleaseWorkflowInjectsAndChecksTheCanonicalIdentity(t *testing.T) {
	build := workflowStepNamed(t, releaseWorkflow(t), "build", "Build binaries").Run
	for _, want := range []string{
		"buildidentity.TrustRootDigest=" + buildidentity.UnpinnedTrustRoot + "\"",
		"|${GO_VERSION}|" + buildidentity.UnpinnedTrustRoot + "|true|PRUFYX_BUILD_IDENTITY_V1_END\"",
		`grep -q -a -F -- "${EMBEDDED_IDENTITY}"`,
		`"${bin}" version`,
	} {
		if !strings.Contains(build, want) {
			t.Errorf("Build binaries step lacks %q", want)
		}
	}
	if strings.Count(build, "TrustRootDigest=") != 1 {
		t.Error("Build binaries step must set the trust root digest exactly once")
	}
}

// A tag that the binary's own identity check would refuse must stop the
// workflow before anything is built or attested. The check step is run
// here with bash and compared with buildidentity's version grammar.
func TestReleaseWorkflowRefusesTagsTheIdentityRejects(t *testing.T) {
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash unavailable")
	}
	step := workflowStepNamed(t, releaseWorkflow(t), "build", "Check the tag")
	if step.Env["VERSION"] != "${{ github.ref_name }}" {
		t.Fatalf("Check the tag must read the tag name from env, got %q", step.Env["VERSION"])
	}
	for _, tag := range []string{
		"v1.2.3", "v0.0.1-alpha.1", "v1.2.3+build.7", "v10.20.30-rc.1+meta", "v1.2.3-rc.1+x",
		"v1.2", "1.2.3", "v01.2.3", "v1.2.3-", "v1.2.3|release", "v1.2.3\nx", "v1.2.3 ", "v1.2.3-a..b", "vfoo", "v1.2.3$(id)",
	} {
		cmd := exec.Command(bash, "-c", step.Run)
		cmd.Env = []string{"VERSION=" + tag, "PATH=" + os.Getenv("PATH")}
		var out bytes.Buffer
		cmd.Stdout, cmd.Stderr = &out, &out
		accepted := cmd.Run() == nil
		// install.sh refuses build metadata, so the workflow must too.
		want := strings.HasPrefix(tag, "v") && buildidentity.ValidVersion(tag) && !strings.Contains(tag, "+")
		if accepted != want {
			t.Errorf("tag %q: workflow accepted=%v, identity accepts=%v (%s)", tag, accepted, want, strings.TrimSpace(out.String()))
		}
	}
}

// The archives are byte-reproducible: fixed member order, the tagged
// commit's time as every mtime, numeric root ownership, normalized modes
// and no gzip name or time. The archive lines of the workflow are executed
// twice over trees that differ in file times, umask-derived modes and
// creation order, and must produce identical bytes. GNU tar is required
// (the workflow runs on ubuntu); elsewhere the test is skipped.
func TestReleaseWorkflowArchivesAreReproducible(t *testing.T) {
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash unavailable")
	}
	build := workflowStepNamed(t, releaseWorkflow(t), "build", "Build binaries").Run
	if strings.Contains(build, "-czf") {
		t.Fatal("Build binaries step still creates archives with tar -czf (stores file times and gzip header time)")
	}
	const begin, end = "# BEGIN deterministic archives", "# END deterministic archives"
	i, j := strings.Index(build, begin), strings.Index(build, end)
	if i < 0 || j < i {
		t.Fatal("Build binaries step has no deterministic archive block")
	}
	script := build[i:j]
	for _, want := range []string{"--sort=name", "--mtime=\"@${BUILD_EPOCH}\"", "--owner=0", "--group=0", "--numeric-owner", "gzip -n"} {
		if !strings.Contains(script, want) {
			t.Errorf("archive block lacks %s", want)
		}
	}
	if version, err := exec.Command("tar", "--version").Output(); err != nil || !bytes.Contains(version, []byte("GNU tar")) {
		t.Skip("GNU tar unavailable")
	}
	digests := map[string][sha256.Size]byte{}
	for round, variant := range []struct {
		mtime time.Time
		mode  os.FileMode
	}{
		{time.Unix(1_000_000_000, 0), 0o755},
		{time.Unix(1_900_000_000, 0), 0o775},
	} {
		dir := t.TempDir()
		names := []string{"prufyx_v1.2.3_linux_amd64", "prufyx-collector_v1.2.3_linux_amd64"}
		files := []string{"prufyx", "prufyx-collector"}
		for k, name := range names {
			pkg := filepath.Join(dir, "dist", name)
			if err := os.MkdirAll(pkg, 0o700); err != nil {
				t.Fatal(err)
			}
			members := []string{files[k], "b-extra", "a-extra"}
			if round == 1 {
				members = []string{"a-extra", files[k], "b-extra"}
			}
			for _, m := range members {
				p := filepath.Join(pkg, m)
				if err := os.WriteFile(p, []byte("content of "+m), 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(p, variant.mode); err != nil {
					t.Fatal(err)
				}
				if err := os.Chtimes(p, variant.mtime, variant.mtime); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.Chmod(pkg, variant.mode); err != nil {
				t.Fatal(err)
			}
		}
		cmd := exec.Command(bash, "-c", "set -euo pipefail\n"+script)
		cmd.Dir = dir
		cmd.Env = []string{"VERSION=v1.2.3", "GOOS=linux", "GOARCH=amd64", "BUILD_EPOCH=1700000000", "PATH=" + os.Getenv("PATH")}
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("archive block failed: %v %s", err, out)
		}
		for _, name := range names {
			raw, err := os.ReadFile(filepath.Join(dir, "dist", name+".tar.gz"))
			if err != nil {
				t.Fatal(err)
			}
			checkArchiveMembers(t, name, raw)
			sum := sha256.Sum256(raw)
			if previous, ok := digests[name]; ok && previous != sum {
				t.Errorf("%s.tar.gz differs between two builds of the same tree", name)
			}
			digests[name] = sum
		}
	}
}

// checkArchiveMembers requires the layout install.sh expects (NAME/ and
// NAME/<binary>) with normalized metadata on every member.
func checkArchiveMembers(t *testing.T, name string, raw []byte) {
	t.Helper()
	zr, err := gzip.NewReader(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	if zr.Name != "" || !zr.ModTime.IsZero() {
		t.Errorf("%s: gzip header stores name %q or time %v", name, zr.Name, zr.ModTime)
	}
	tr := tar.NewReader(zr)
	var members []string
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		members = append(members, h.Name)
		if h.Uid != 0 || h.Gid != 0 || h.Uname != "" || h.Gname != "" || h.ModTime.Unix() != 1700000000 || h.Mode&0o7777 != 0o755 {
			t.Errorf("%s: member %s has uid %d gid %d uname %q gname %q mtime %v mode %o", name, h.Name, h.Uid, h.Gid, h.Uname, h.Gname, h.ModTime, h.Mode)
		}
	}
	binary := strings.SplitN(name, "_", 2)[0]
	want := []string{name + "/", name + "/a-extra", name + "/b-extra", name + "/" + binary}
	if strings.Join(members, ",") != strings.Join(want, ",") {
		t.Errorf("%s: members %v, want %v", name, members, want)
	}
}
