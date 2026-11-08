// SPDX-License-Identifier: AGPL-3.0-only

package releaseworkflow

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/maintainer/knowledgesign"
)

// Contract between the Sign step of the daily workflow and the real publisher.
//
// The shell tests of the workflow stub the publisher and cannot see a flag
// mismatch. This test runs the REAL text of the Sign step (taken from the
// workflow file, nothing re-typed here) against the REAL prufyx-maintainer
// binary, with throwaway keys, for every mode, and requires the signature to
// succeed with the flag set the step builds for that mode. A flag the
// publisher does not know, or a combination its guards refuse (--ci without a
// previous package or --no-live-package, --no-live-package with a previous
// package, a layout that does not reproduce the planned digests), fails here.
//
// Dependency: the publisher flags (--no-live-package, index layout separated
// from the predecessor check) come from the publisher change that must merge
// before this workflow (merge order). PRUFYX_MAINTAINER_BIN may name a binary
// built from that change; otherwise the binary is built from this tree. The
// test skips, with a message, ONLY when the binary does not know
// --no-live-package; every other problem (build failure, refusal, wrong
// output) fails.
func maintainerForContract(t *testing.T, repo string) string {
	t.Helper()
	bin := os.Getenv("PRUFYX_MAINTAINER_BIN")
	if bin == "" {
		bin = filepath.Join(t.TempDir(), "prufyx-maintainer")
		build := exec.Command("go", "build", "-trimpath", "-o", bin, "./cmd/prufyx-maintainer")
		build.Dir = filepath.Join(repo, "cli")
		if out, err := build.CombinedOutput(); err != nil {
			t.Fatalf("building the publisher failed: %v\n%s", err, out)
		}
	}
	help, err := exec.Command(bin, "knowledge-publish", "release", "--help").CombinedOutput()
	if err != nil {
		t.Fatalf("the publisher does not answer release --help: %v\n%s", err, help)
	}
	if !strings.Contains(string(help), "--no-live-package") {
		t.Skip("the publisher in this build has no --no-live-package: the publisher change it depends on is not merged yet; set PRUFYX_MAINTAINER_BIN to a build of that change")
	}
	return bin
}

type contractFixture struct {
	t         *testing.T
	bin       string
	signRun   string
	dir       string // RUNNER_TEMP
	workspace string // GITHUB_WORKSPACE holding the pinned root at its fixed path
	rootDig   string
	keys      map[string]string
	pass      string
}

func newContractFixture(t *testing.T) *contractFixture {
	t.Helper()
	repo := repoRoot(t)
	for _, tool := range []string{"bash", "jq", "go"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skip(tool + " not available")
		}
	}
	bin := maintainerForContract(t, repo)
	wf, _ := loadPublishWorkflow(t)
	var signRun string
	for _, st := range wf.Jobs["sign"].Steps {
		if st.Name == "Sign" {
			signRun = st.Run
		}
	}
	if signRun == "" {
		t.Fatal("the Sign step is not in the sign job")
	}
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	pass := "throwaway contract passphrase 1"
	init, err := knowledgesign.Init(knowledgesign.InitOptions{KeyDir: filepath.Join(dir, "keys"),
		RootExpires: time.Now().UTC().Add(72 * time.Hour).Format(time.RFC3339), RootPassphrase: []byte("root key passphrase 123456"), Passphrase: []byte(pass)})
	if err != nil {
		t.Fatal(err)
	}
	f := &contractFixture{t: t, bin: bin, signRun: signRun, dir: dir, rootDig: init.RootDigest, pass: pass, keys: map[string]string{}}
	for _, r := range []string{"targets", "snapshot", "timestamp"} {
		raw, err := os.ReadFile(filepath.Join(dir, "keys", r+".key.pem"))
		if err != nil {
			t.Fatal(err)
		}
		// The secret is stored without the final newline (the step adds one).
		f.keys[r] = strings.TrimRight(string(raw), "\n")
	}
	f.workspace = filepath.Join(dir, "ws")
	pin := filepath.Join(f.workspace, "cli", "internal", "knowledgepin")
	if err := os.MkdirAll(pin, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pin, "root.json"), init.Root, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "bin"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(bin, filepath.Join(dir, "bin", "prufyx-maintainer")); err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *contractFixture) publisher(args ...string) []byte {
	f.t.Helper()
	cmd := exec.Command(f.bin, args...)
	cmd.Dir = repoRoot(f.t)
	out, err := cmd.Output()
	if err != nil {
		f.t.Fatalf("publisher %v: %v", args, err)
	}
	return out
}

type contractPlan struct {
	layout        []string // the layout the plan computed its digests with
	previousTar   string   // "" for the first release
	previousDigit string
}

// sign runs the real Sign step text for one mode and returns whether it
// succeeded and the work directory it announced.
func (f *contractFixture) sign(mode, revision, version string, p contractPlan, layoutIndex string, mutate func(string) string) (ok bool, work, output string) {
	f.t.Helper()
	d := f.publisher(append([]string{"knowledge-publish", "content-digest", "--profile", "cncf-projects", "--revision", revision}, p.layout...)...)
	var dig struct{ ContentDigest, IndexDigest string }
	if err := json.Unmarshal(d, &dig); err != nil || dig.ContentDigest == "" || dig.IndexDigest == "" {
		f.t.Fatalf("content-digest output %q: %v", d, err)
	}
	return f.signWith(mode, revision, version, dig.ContentDigest, dig.IndexDigest, p, layoutIndex, mutate)
}

func (f *contractFixture) signWith(mode, revision, version, content, index string, p contractPlan, layoutIndex string, mutate func(string) string) (bool, string, string) {
	f.t.Helper()
	planDir := filepath.Join(f.dir, "plan")
	_ = os.RemoveAll(planDir)
	if err := os.MkdirAll(planDir, 0o700); err != nil {
		f.t.Fatal(err)
	}
	plan := map[string]any{"contentDigest": content, "indexDigest": index, "previous": map[string]any{"packageDigest": p.previousDigit}}
	raw, _ := json.Marshal(plan)
	if err := os.WriteFile(filepath.Join(planDir, "plan.json"), raw, 0o600); err != nil {
		f.t.Fatal(err)
	}
	if p.previousTar != "" {
		tar, err := os.ReadFile(p.previousTar)
		if err != nil {
			f.t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(planDir, "previous.tar"), tar, 0o600); err != nil {
			f.t.Fatal(err)
		}
	}
	script := f.signRun
	if mutate != nil {
		script = mutate(script)
		if script == f.signRun {
			f.t.Fatal("the mutation did not change the Sign step")
		}
	}
	gho := filepath.Join(f.dir, "gho-"+mode)
	_ = os.Remove(gho)
	cmd := exec.Command("bash", "-c", script)
	cmd.Dir = repoRoot(f.t) // the workflow runs at the repository root
	cmd.Env = append(os.Environ(),
		"RUNNER_TEMP="+f.dir, "GITHUB_WORKSPACE="+f.workspace, "GITHUB_OUTPUT="+gho, "GITHUB_RUN_ATTEMPT=1",
		"TARGETS_KEY="+f.keys["targets"], "SNAPSHOT_KEY="+f.keys["snapshot"], "TIMESTAMP_KEY="+f.keys["timestamp"], "PASSPHRASE="+f.pass,
		"ROOT_DIGEST="+f.rootDig, "MODE="+mode, "REVISION="+revision, "VERSION="+version,
		"EXPIRES="+time.Now().UTC().Add(60*time.Hour).Format("2006-01-02T15:04:05Z"), "LAYOUT_INDEX="+layoutIndex)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return false, "", string(out)
	}
	g, _ := os.ReadFile(gho)
	work := ""
	for _, l := range strings.Split(string(g), "\n") {
		if strings.HasPrefix(l, "work=") {
			work = strings.TrimPrefix(l, "work=")
		}
	}
	if work == "" {
		f.t.Fatalf("the Sign step succeeded without announcing its work directory: %s", out)
	}
	return true, work, string(out)
}

func findFile(t *testing.T, root, suffix string) string {
	t.Helper()
	var found string
	_ = filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() && strings.HasSuffix(p, suffix) && found == "" {
			found = p
		}
		return nil
	})
	if found == "" {
		t.Fatalf("no %s under %s", suffix, root)
	}
	return found
}

func TestKnowledgePublishSignCallContractPerMode(t *testing.T) {
	f := newContractFixture(t)
	first := contractPlan{layout: []string{"--first-release"}}
	ok, work, out := f.sign("first", "1", "1", first, "", nil)
	if !ok {
		t.Fatalf("mode first (nothing live): the Sign step was refused by the publisher:\n%s", out)
	}
	final := filepath.Join(work, "final")
	tar := findFile(t, final, "cncf-projects-1.tar")
	idx := findFile(t, final, "index.v1.json")
	var rel struct{ PackageDigest string }
	rawRel, err := os.ReadFile(filepath.Join(work, "release.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(rawRel, &rel); err != nil || rel.PackageDigest == "" {
		t.Fatalf("release receipt %q: %v", rawRel, err)
	}
	live := contractPlan{previousTar: tar, previousDigit: rel.PackageDigest}
	withIndex := func(p contractPlan, layout ...string) contractPlan { p.layout = layout; return p }
	for _, tc := range []struct {
		mode   string
		plan   contractPlan
		layout string // LAYOUT_INDEX of the sign job
	}{
		{"state", withIndex(live, "--previous-index", idx), idx},
		{"capability", withIndex(live, "--first-release"), ""},
		{"recovery", withIndex(live, "--previous-index", idx), idx},
	} {
		t.Run(tc.mode, func(t *testing.T) {
			ok, _, out := f.sign(tc.mode, "2", "2", tc.plan, tc.layout, nil)
			if !ok {
				t.Fatalf("mode %s: the Sign step was refused by the publisher:\n%s", tc.mode, out)
			}
		})
	}

	// The test has teeth: a wrong flag set or a wrong plan is refused by the
	// same real publisher, so a green run above is not vacuous.
	t.Run("refused", func(t *testing.T) {
		drop := func(old, new string) func(string) string {
			return func(s string) string { return strings.Replace(s, old, new, -1) }
		}
		if ok, _, _ := f.sign("first", "1", "1", first, "", drop("--no-live-package", "")); ok {
			t.Error("mode first without --no-live-package was accepted under --ci")
		}
		if ok, _, _ := f.sign("state", "2", "2", withIndex(live, "--previous-index", idx), idx, drop("--expect-previous-package-digest", "--ignored-flag")); ok {
			t.Error("a flag the publisher does not know was accepted")
		}
		if ok, _, _ := f.sign("capability", "2", "2", withIndex(live, "--first-release"), "", drop("--first-release", "--no-live-package")); ok {
			t.Error("--no-live-package together with a previous package was accepted")
		}
		zero := "sha256:" + strings.Repeat("0", 64)
		if ok, _, _ := f.signWith("state", "2", "2", zero, zero, withIndex(live, "--previous-index", idx), idx, nil); ok {
			t.Error("a plan whose digests do not match the export was accepted")
		}
		bad := live
		bad.previousDigit = zero
		if ok, _, _ := f.sign("state", "2", "2", withIndex(bad, "--previous-index", idx), idx, nil); ok {
			t.Error("a wrong expected previous package digest was accepted")
		}
		// A layout that differs from the planned one does not reproduce the digests.
		if ok, _, _ := f.sign("recovery", "2", "2", withIndex(live, "--first-release"), idx, nil); ok {
			t.Error("recovery signed with a layout other than the planned previous-index layout")
		}
	})
}
