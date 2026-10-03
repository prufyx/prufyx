// SPDX-License-Identifier: AGPL-3.0-only

package knowledgegate

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

var workflowPath = filepath.Join(repoRoot, ".github", "workflows", "knowledge-gate.yml")

type workflow struct {
	On          map[string]any    `yaml:"on"`
	Permissions map[string]string `yaml:"permissions"`
	Jobs        map[string]struct {
		Permissions map[string]string `yaml:"permissions"`
		Env         map[string]string `yaml:"env"`
		Outputs     map[string]string `yaml:"outputs"`
		Steps       []struct {
			ID               string            `yaml:"id"`
			Name             string            `yaml:"name"`
			Uses             string            `yaml:"uses"`
			Run              string            `yaml:"run"`
			With             map[string]any    `yaml:"with"`
			Env              map[string]string `yaml:"env"`
			WorkingDirectory string            `yaml:"working-directory"`
		} `yaml:"steps"`
	} `yaml:"jobs"`
}

// TestWorkflowShape pins the properties the gate's safety rests on: the
// gate is built from the base checkout only, the proposed change is
// checked out without credentials and never built or run, the token is
// read-only, every action is pinned by commit, and nothing merges.
func TestWorkflowShape(t *testing.T) {
	raw, err := os.ReadFile(workflowPath)
	if err != nil {
		t.Fatal(err)
	}
	var wf workflow
	if err := yaml.Unmarshal(raw, &wf); err != nil {
		t.Fatal(err)
	}
	if _, ok := wf.On["pull_request_target"]; !ok {
		t.Fatal("the gate must run its base-branch definition (pull_request_target)")
	}
	if _, ok := wf.On["pull_request"]; ok {
		t.Fatal("pull_request would run the change's own workflow definition")
	}
	// No merge queue is in use: a merge_group run would take its workflow
	// definition from the queued commit, and has no pull request author.
	if _, ok := wf.On["merge_group"]; ok {
		t.Fatal("merge_group runs the queued commit's own workflow definition")
	}
	for trigger := range wf.On {
		switch trigger {
		case "pull_request_target", "schedule", "workflow_dispatch":
		default:
			t.Fatalf("unexpected trigger %s", trigger)
		}
	}
	if strings.Contains(string(raw), "head.ref") {
		t.Fatal("the gate must check the head commit, never a branch name")
	}
	if len(wf.Permissions) != 1 || wf.Permissions["contents"] != "read" {
		t.Fatalf("permissions %v, want contents: read only", wf.Permissions)
	}
	if strings.Contains(string(raw), "secrets.") {
		t.Fatal("the gate must not use secrets")
	}
	for _, forbidden := range []string{"gh pr merge", "--auto", "pulls/merge", "enable-auto-merge"} {
		if strings.Contains(string(raw), forbidden) {
			t.Fatalf("the workflow must not merge (%q)", forbidden)
		}
	}
	job, ok := wf.Jobs["gate"]
	if !ok {
		t.Fatal("no gate job")
	}
	if len(job.Permissions) != 0 {
		t.Fatal("the job must not widen permissions")
	}
	// The head is the exact commit the event names; a branch name would
	// let the checked commit differ from the one the result is for.
	if v := job.Env["HEAD_SHA"]; !strings.HasPrefix(v, "${{ github.event.pull_request.head.sha ||") {
		t.Fatalf("HEAD_SHA = %q, want the pull request's head commit first", v)
	}
	if v := job.Outputs["head-sha"]; !strings.Contains(v, "steps.verify.outputs.head_sha") {
		t.Fatalf("the job must output the head commit it checked, got %q", v)
	}
	if !strings.Contains(job.Env["WEB_APPROVAL_KEYS_DIGEST"], "vars.WEB_APPROVAL_KEYS_DIGEST") || !strings.Contains(job.Env["EVENT_SENDER"], "github.event.sender.login") {
		t.Fatal("the approval key digest and the event sender must reach the gate")
	}
	all := ""
	for _, s := range job.Steps {
		all += s.Run + "\n"
	}
	for _, want := range []string{
		// Up to date with the current tip of main.
		`git ls-remote "https://github.com/${GITHUB_REPOSITORY}.git" refs/heads/main`,
		`if [ "${PR_BASE_SHA}" != "${tip}" ]; then`,
		// The head contains the base.
		`merge-base --is-ancestor "${BASE_SHA}" "${HEAD_SHA}"`,
		// Both trees from git objects, at exactly these commits.
		`gate export --git-dir "${RUNNER_TEMP}/objects.git" --commit "${BASE_SHA}" --out base`,
		`gate export --git-dir "${RUNNER_TEMP}/objects.git" --commit "${HEAD_SHA}" --out head`,
		// The gate is told the head, sender and commits.
		`--head-sha "${HEAD_SHA}"`, `--sender "${EVENT_SENDER}"`, `--commits "${RUNNER_TEMP}/commits.json"`,
		`--approval-keys-digest "${WEB_APPROVAL_KEYS_DIGEST}"`,
		// Output from the change cannot form workflow commands.
		`echo "::stop-commands::${token}"`,
		`echo "head_sha=${HEAD_SHA}"`,
	} {
		if !strings.Contains(all, want) {
			t.Fatalf("the workflow no longer runs %s", want)
		}
	}
	for _, s := range job.Steps {
		if s.ID == "verify" || s.ID == "classify" {
			if !strings.Contains(s.Run, "::stop-commands::") {
				t.Fatalf("%s: gate output is printed without stopping workflow commands", s.Name)
			}
		}
	}
	sawBuild := false
	for _, s := range job.Steps {
		if s.Uses != "" {
			at := strings.Index(s.Uses, "@")
			if at < 0 || len(s.Uses[at+1:]) < 40 {
				t.Fatalf("%s: action not pinned by commit", s.Name)
			}
		}
		if strings.HasPrefix(s.Uses, "actions/checkout@") {
			if s.With["persist-credentials"] != false {
				t.Fatalf("%s: checkout must not persist credentials", s.Name)
			}
			// Only the base is checked out (to build the gate); the
			// change is only ever exported from git objects.
			if s.With["ref"] != "${{ steps.base.outputs.sha }}" || s.With["repository"] != nil {
				t.Fatalf("%s: checks out something other than the resolved base", s.Name)
			}
		}
		if strings.HasPrefix(s.Uses, "actions/setup-go@") && s.With["cache"] != false {
			t.Fatal("setup-go caching must be off (a change could poison it)")
		}
		if strings.Contains(s.Run, "go build") || strings.Contains(s.Run, "go run") || strings.Contains(s.Run, "go test") {
			if s.WorkingDirectory != "gate-src/cli" {
				t.Fatalf("%s: builds outside the base checkout", s.Name)
			}
			sawBuild = true
		}
		if strings.Contains(s.WorkingDirectory, "head") || strings.Contains(s.Run, "head/cli/") || strings.Contains(s.Run, "./head") {
			t.Fatalf("%s: executes or builds from the proposed change", s.Name)
		}
		if strings.Contains(s.Run, "${{") {
			t.Fatalf("%s: expressions must reach scripts through env, never inline", s.Name)
		}
	}
	if !sawBuild {
		t.Fatal("the workflow never builds the gate")
	}
}

// TestWorkflowLint runs actionlint when it is installed.
func TestWorkflowLint(t *testing.T) {
	bin, err := exec.LookPath("actionlint")
	if err != nil {
		t.Skip("actionlint is not installed")
	}
	out, err := exec.Command(bin, workflowPath).CombinedOutput()
	if err != nil {
		t.Fatalf("actionlint: %v\n%s", err, out)
	}
}
