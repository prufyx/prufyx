// SPDX-License-Identifier: AGPL-3.0-only

package releaseworkflow

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// The release-docs gate must be a separate release job that everything else
// needs, a CI step that cannot be skipped, and the same command line in the
// dry run. These tests read the workflow files and the script.

const (
	gateJob  = "release-docs-gate"
	gateStep = "Check release docs"
)

func needsOf(v any) []string {
	switch n := v.(type) {
	case string:
		return []string{n}
	case []any:
		var out []string
		for _, x := range n {
			if s, ok := x.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

func commandLine(t *testing.T, run, mode string) string {
	t.Helper()
	var found []string
	for _, l := range strings.Split(run, "\n") {
		l = strings.TrimSpace(l)
		if strings.HasPrefix(l, "go run ./cmd/prufyx-maintainer release-docs check") {
			found = append(found, l)
		}
	}
	if len(found) != 1 {
		t.Fatalf("want exactly one release-docs command line, got %d", len(found))
	}
	if !strings.Contains(found[0], "--mode "+mode) {
		t.Fatalf("command line is not in %s mode: %s", mode, found[0])
	}
	return found[0]
}

func TestReleaseDocsGateIsASeparateJobEveryJobNeeds(t *testing.T) {
	wf := releaseWorkflow(t)
	gate, ok := wf.Jobs[gateJob]
	if !ok {
		t.Fatalf("no %s job", gateJob)
	}
	if len(needsOf(gate.Needs)) != 0 {
		t.Error("the gate must not wait for another job")
	}
	for name, job := range wf.Jobs {
		if name == gateJob {
			continue
		}
		if !reaches(wf, name, gateJob, map[string]bool{}) {
			t.Errorf("job %s does not (transitively) need %s", name, gateJob)
		}
		_ = job
	}
	// The jobs that build or publish need it directly where their own tests allow.
	for _, name := range []string{"build", "provenance", "draft-release"} {
		direct := false
		for _, n := range needsOf(wf.Jobs[name].Needs) {
			if n == gateJob {
				direct = true
			}
		}
		if !direct {
			t.Errorf("job %s does not need %s directly", name, gateJob)
		}
	}
	// The gate job is not part of the build matrix and has no condition.
	raw := workflowText(t, "release.yml")
	jobBlock := raw[strings.Index(raw, "\n  "+gateJob+":"):]
	jobBlock = jobBlock[:strings.Index(jobBlock[1:], "\n  build:")+1]
	for _, bad := range []string{"matrix", "continue-on-error", "\n    if:", "if: "} {
		if strings.Contains(jobBlock, bad) {
			t.Errorf("the gate job contains %q", bad)
		}
	}
	if !strings.Contains(jobBlock, "fetch-depth: 0") {
		t.Error("the gate needs the full history and the tags")
	}
	step := workflowStepNamed(t, wf, gateJob, gateStep)
	if step.If != "" || step.ContinueOnError != nil {
		t.Error("the gate step must have no if and no continue-on-error")
	}
	line := commandLine(t, step.Run, "release")
	for _, flag := range []string{"--tag ", "--previous ", "--deny-file "} {
		if !strings.Contains(line, flag) {
			t.Errorf("the release command line has no %s", flag)
		}
	}
	if strings.Contains(line, "unreleased") {
		t.Error("the release job must not run the CI mode")
	}
}

func reaches(wf workflowFile, from, target string, seen map[string]bool) bool {
	if seen[from] {
		return false
	}
	seen[from] = true
	for _, n := range needsOf(wf.Jobs[from].Needs) {
		if n == target || reaches(wf, n, target, seen) {
			return true
		}
	}
	return false
}

func TestCIRunsTheReleaseDocsCheckWithoutAWayToSkipIt(t *testing.T) {
	wf := loadWorkflow(t, "ci.yml")
	var found bool
	for name, job := range wf.Jobs {
		for _, step := range job.Steps {
			if step.Name != gateStep {
				continue
			}
			found = true
			if step.If != "" || step.ContinueOnError != nil {
				t.Errorf("job %s: the step must have no if and no continue-on-error", name)
			}
			commandLine(t, step.Run, "unreleased")
		}
	}
	if !found {
		t.Fatalf("ci.yml has no %q step", gateStep)
	}
	raw := workflowText(t, "ci.yml")
	// The pinned notes check it replaces is gone.
	for _, old := range []string{"--previous-counts-sha256", "--to-label", "Check generated release-notes block", "4bf4942da51e"} {
		if strings.Contains(raw, old) {
			t.Errorf("ci.yml still has %q", old)
		}
	}
	// No path filter on the triggers: the gate runs on every pull request.
	head := raw[:strings.Index(raw, "\njobs:")]
	if regexp.MustCompile(`(?m)^\s+paths(-ignore)?:`).MatchString(head) {
		t.Error("ci.yml triggers have a paths filter")
	}
	// The job that holds the step has no condition.
	for name, job := range wf.Jobs {
		for _, step := range job.Steps {
			if step.Name == gateStep {
				block := raw[strings.Index(raw, "\n  "+name+":"):]
				if end := strings.Index(block[1:], "\n  "); end >= 0 {
					rest := block[1:]
					if m := regexp.MustCompile(`\n  [a-z0-9-]+:\n`).FindStringIndex(rest); m != nil {
						block = rest[:m[0]]
					}
				}
				if regexp.MustCompile(`(?m)^    if:`).MatchString(block) {
					t.Errorf("job %s has a condition", name)
				}
			}
		}
	}
}

func workflowText(t *testing.T, file string) string {
	t.Helper()
	repo := repoRootForTest(t)
	raw, err := os.ReadFile(filepath.Join(repo, ".github", "workflows", file))
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

// The dry run pins the release command line as a literal and fails when the
// workflow step differs; this test keeps the literal equal to the workflow's.
func TestReleaseDryRunPinsTheReleaseCommandLine(t *testing.T) {
	repo := repoRootForTest(t)
	step := workflowStepNamed(t, releaseWorkflow(t), gateJob, gateStep)
	want := commandLine(t, step.Run, "release")
	raw, err := os.ReadFile(filepath.Join(repo, "scripts", "release-dry-run.sh"))
	if err != nil {
		t.Fatal(err)
	}
	script := string(raw)
	m := regexp.MustCompile(`(?m)^gate_cmd='([^\n]*)'$`).FindStringSubmatch(script)
	if m == nil {
		t.Fatal("the dry run does not pin the release command line")
	}
	if m[1] != want {
		t.Fatalf("command lines differ:\n workflow: %s\n dry run:  %s", want, m[1])
	}
	// The dry run takes the step from the workflow, never a copy of it, and
	// has no second release-mode command line.
	if !strings.Contains(script, `step_script `+gateJob+` "`+gateStep+`"`) {
		t.Error("the dry run does not run the workflow's own step")
	}
	if n := strings.Count(script, "--mode release"); n != 1 {
		t.Errorf("the dry run mentions --mode release %d times, want only the pinned line", n)
	}
	if !strings.Contains(script, "--mode unreleased") || !strings.Contains(script, "RELEASE_TAG") {
		t.Error("the dry run must run CI mode without RELEASE_TAG and release mode with it")
	}
}

// A pull request run of the dry run may keep stale blocks only as its base
// commit has them; every other run requires them current.
func TestReleaseDryRunPassesBlocksBaseOnlyWhenSet(t *testing.T) {
	wf, _, repo := loadDryRun(t)
	found := 0
	for _, job := range wf.Jobs {
		for _, step := range job.Steps {
			if strings.Contains(step.Run, "scripts/release-dry-run.sh") {
				found++
			}
		}
	}
	line := "\n          BLOCKS_BASE: ${{ github.event.pull_request.base.sha }}\n"
	yml := workflowText(t, "release-dry-run.yml")
	if found != 1 || strings.Count(yml, line) != 1 || strings.Count(yml, "BLOCKS_BASE:") != 1 {
		t.Error("the dry run step must set BLOCKS_BASE to the pull request base commit and nothing else")
	}

	raw, err := os.ReadFile(filepath.Join(repo, "scripts", "release-dry-run.sh"))
	if err != nil {
		t.Fatal(err)
	}
	_, rest, ok := strings.Cut(string(raw), "\nelse\n  deny_args=()\n")
	if !ok {
		t.Fatal("no CI mode branch")
	}
	branch, _, ok := strings.Cut(rest, "\nfi\n\n# 2. ")
	if !ok {
		t.Fatal("no end of the CI mode branch")
	}
	if strings.Count(string(raw), "--blocks-base \"") != 1 || !strings.Contains(branch, "--blocks-base \"") {
		t.Error("--blocks-base belongs to the CI mode branch only")
	}
	base := strings.Repeat("a", 40)
	for name, c := range map[string]struct {
		env  []string
		want string
	}{
		"unset":     {nil, ""},
		"empty":     {[]string{"BLOCKS_BASE="}, ""},
		"set":       {[]string{"BLOCKS_BASE=" + base}, " <--blocks-base> <" + base + ">"},
		"malformed": {[]string{"BLOCKS_BASE=HEAD --mode x"}, " <--blocks-base> <HEAD --mode x>"},
	} {
		work := t.TempDir()
		if err := os.Mkdir(filepath.Join(work, "cli"), 0o700); err != nil {
			t.Fatal(err)
		}
		// go prints its arguments and fails, as a refusing check would.
		stub := "set -uo pipefail\ngo() { printf ' <%s>' \"$@\"; return 1; }\nrecord() { echo \"RESULT $2\"; }\ntail_log() { cat \"$1\"; }\n" +
			"root=\"$1\"; work=\"$1\"; logs=\"$1\"\ndeny_args=()\n"
		cmd := exec.Command("bash", "-c", stub+branch, "bash", work)
		cmd.Env = append([]string{"PATH=" + os.Getenv("PATH")}, c.env...)
		out, err := cmd.CombinedOutput()
		want := " <run> <./cmd/prufyx-maintainer> <release-docs> <check> <--root> <..> <--mode> <unreleased>" + c.want
		if err != nil || !strings.Contains(string(out), "RESULT FAIL\n") || !strings.HasSuffix(strings.TrimRight(string(out), "\n"), want) {
			t.Errorf("%s: want arguments %q: %v %s", name, want, err, out)
		}
	}
}

func TestReleaseDocsGateIsOwned(t *testing.T) {
	repo := repoRootForTest(t)
	raw, err := os.ReadFile(filepath.Join(repo, ".github", "CODEOWNERS"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	for _, p := range []string{
		"/cli/internal/maintainer/releasedocs/ ",
		"/cli/cmd/prufyx-maintainer/release_docs.go ",
		"/cli/internal/maintainer/releaseworkflow/release_docs_gate_test.go ",
		"/scripts/release-dry-run.sh ",
		"/.github/ ",
	} {
		if !strings.Contains(text, "\n"+p+"@airstand\n") {
			t.Errorf("CODEOWNERS has no owner line for %s", p)
		}
	}
}
