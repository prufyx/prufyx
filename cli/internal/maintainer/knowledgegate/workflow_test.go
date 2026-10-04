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
		Needs       any               `yaml:"needs"`
		If          string            `yaml:"if"`
		Environment string            `yaml:"environment"`
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
	// The gate job holds no secret. The only secret in the file is the
	// alarm channel's token, in the separate alarm job (checked below).
	if strings.Contains(string(raw), "secrets.") && strings.Count(string(raw), "secrets.") != 1 {
		t.Fatal("the gate must not use secrets")
	}
	if n := strings.Count(string(raw), "secrets.OPS_ISSUES_TOKEN"); n != strings.Count(string(raw), "secrets.") {
		t.Fatal("the only secret the workflow may name is OPS_ISSUES_TOKEN")
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
	// Monitoring: breakers, shadow mode, the daily count and the files.
	for _, want := range []string{
		`--max-withdraw-percent "${MAX_WITHDRAW_PERCENT}" --max-withdraw-project "${MAX_WITHDRAW_PROJECT}"`,
		`--max-daily-loosening "${MAX_DAILY_LOOSENING}"`,
		`--metrics "${RUNNER_TEMP}/gate-metrics.json"`,
		`--alarms "${RUNNER_TEMP}/gate-alarms.json"`,
		`args+=(--shadow)`,
		`args+=(--daily-loosening-count "$(cat "${RUNNER_TEMP}/daily-count.txt")")`,
		// The count comes from main's history, with the gate's own code,
		// and only when the API and the count both succeed.
		`gate daily-count --git-dir "${RUNNER_TEMP}/objects.git" --commits "${list}" --bot-login "${BOT_LOGIN}"`,
		`commits?sha=${BASE_SHA}&since=`,
		`rm -f "${RUNNER_TEMP}/daily-count.txt"`,
	} {
		if !strings.Contains(all, want) {
			t.Fatalf("the workflow no longer runs %s", want)
		}
	}
	if !strings.Contains(job.Env["SHADOW_VAR"], "vars.KNOWLEDGE_GATE_SHADOW") || !strings.Contains(job.Env["SHADOW_LABEL"], "labels.*.name, 'shadow'") {
		t.Fatalf("shadow mode must come from the variable or the label: %q %q", job.Env["SHADOW_VAR"], job.Env["SHADOW_LABEL"])
	}
	if !strings.Contains(all, `if [ "${SHADOW_VAR}" = "true" ] || [ "${SHADOW_LABEL}" = "true" ]; then`) {
		t.Fatal("either source switches shadow mode on")
	}
	// Defaults of the limits, as the gate documents them.
	for name, want := range map[string]string{"MAX_DAILY_LOOSENING": "'400'", "MAX_WITHDRAW_PERCENT": "'5'", "MAX_WITHDRAW_PROJECT": "'20'"} {
		if !strings.HasSuffix(strings.TrimSuffix(job.Env[name], " }}"), "|| "+want) {
			t.Fatalf("%s = %q, want default %s", name, job.Env[name], want)
		}
	}
	if !strings.Contains(job.Outputs["alarm-count"], "steps.verify.outputs.alarm_count") {
		t.Fatal("the job must output the number of alarms")
	}
	// Nothing in the gate job uses a secret or an environment.
	if job.Environment != "" {
		t.Fatal("the gate job must not run in an environment")
	}
	for _, s := range job.Steps {
		for _, e := range s.Env {
			if strings.Contains(e, "secrets.") {
				t.Fatalf("%s: a secret in the gate job", s.Name)
			}
		}
		if strings.Contains(s.Run, "OPS_ISSUES") || strings.Contains(s.Run, "gh issue") {
			t.Fatalf("%s: alarm posting belongs to the alarm job", s.Name)
		}
	}
	// The alarm job: no repository permission, no checkout, no code of
	// the change, one pinned download, and the secret only in the one
	// step that posts, which does nothing when the channel is not set up.
	alarm, ok := wf.Jobs["alarm"]
	if !ok {
		t.Fatal("no alarm job")
	}
	if alarm.Permissions == nil || len(alarm.Permissions) != 0 {
		t.Fatalf("the alarm job must declare empty permissions, got %v", alarm.Permissions)
	}
	if alarm.Needs != "gate" || !strings.Contains(alarm.If, "needs.gate.outputs.alarm-count") || !strings.Contains(alarm.If, "always()") {
		t.Fatalf("the alarm job runs after the gate on its alarms: needs=%v if=%q", alarm.Needs, alarm.If)
	}
	if !strings.Contains(alarm.If, "github.event.pull_request.user.login == (vars.KNOWLEDGE_BOT_LOGIN") {
		t.Fatal("pull request alarms are for the automation's own pull requests")
	}
	if alarm.Environment != "knowledge-alarms" {
		t.Fatalf("the alarm token lives in its own environment, got %q", alarm.Environment)
	}
	secretSteps := 0
	for _, s := range alarm.Steps {
		if strings.Contains(s.Run, "${{") {
			t.Fatalf("%s: expressions must reach scripts through env, never inline", s.Name)
		}
		if s.Uses != "" {
			at := strings.Index(s.Uses, "@")
			if at < 0 || len(s.Uses[at+1:]) < 40 {
				t.Fatalf("%s: action not pinned by commit", s.Name)
			}
			if !strings.HasPrefix(s.Uses, "actions/download-artifact@") {
				t.Fatalf("%s: the alarm job may only download the report", s.Name)
			}
		}
		for _, e := range s.Env {
			if strings.Contains(e, "secrets.") {
				secretSteps++
				if !strings.Contains(s.Run, `if [ -z "${OPS_ISSUES_TOKEN}" ] || [ -z "${OPS_ISSUES_REPO}" ]; then`) || !strings.Contains(s.Run, "exit 0") {
					t.Fatalf("%s: must do nothing when the channel is not configured", s.Name)
				}
			}
		}
		if strings.Contains(s.Run, "gh pr") || strings.Contains(s.Run, "--auto") || strings.Contains(s.Run, "merge") || strings.Contains(s.Run, "gh api") {
			t.Fatalf("%s: the alarm job only opens or comments on an issue", s.Name)
		}
	}
	if secretSteps != 1 {
		t.Fatalf("the secret must appear in exactly one step, found %d", secretSteps)
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
