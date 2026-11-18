// SPDX-License-Identifier: AGPL-3.0-only

package knowledgegate

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// secretRef matches any way of reaching the secrets context, not only the
// dotted form: secrets['X'], toJSON(secrets) and "secrets: inherit" all
// contain the bare word.
var secretRef = regexp.MustCompile(`\bsecrets\b`)

// yamlComment matches whole-line YAML comments, which prose may fill with
// the word "secrets" without naming one.
var yamlComment = regexp.MustCompile(`(?m)^[ \t]*#.*$`)

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
			If               string            `yaml:"if"`
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
	t.Parallel()
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
	// merge_group is allowed only in the checked, fail-closed form pinned by
	// TestWorkflowMergeGroup: its run takes the queued commit's workflow
	// definition and has no pull request payload.
	for trigger := range wf.On {
		switch trigger {
		case "pull_request_target", "merge_group", "schedule", "workflow_dispatch":
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
	// The workflow names two secrets, once each: the alarm channel's token
	// in the separate alarm job, and the private key of the read-only App
	// in the gate job's token step (both checked below).
	code := yamlComment.ReplaceAllString(string(raw), "")
	if len(secretRef.FindAllString(code, -1)) != 2 ||
		strings.Count(code, "secrets.OPS_ISSUES_TOKEN") != 1 ||
		strings.Count(code, "secrets.KNOWLEDGE_GATE_APP_PRIVATE_KEY") != 1 {
		t.Fatal("the only secrets the workflow may name are OPS_ISSUES_TOKEN and KNOWLEDGE_GATE_APP_PRIVATE_KEY, once each")
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
	// In the gate job the App key reaches only the pinned token action,
	// which mints a read-only token; no run step sees the key.
	keySteps := 0
	for _, s := range job.Steps {
		key := false
		for _, v := range s.With {
			if str, ok := v.(string); ok && secretRef.MatchString(str) {
				key = true
			}
		}
		for _, v := range s.Env {
			if secretRef.MatchString(v) {
				t.Fatalf("%s: a gate step's environment names a secret", s.Name)
			}
		}
		if secretRef.MatchString(s.Run) {
			t.Fatalf("%s: a gate run step names a secret", s.Name)
		}
		if !key {
			continue
		}
		keySteps++
		if !strings.HasPrefix(s.Uses, "actions/create-github-app-token@") {
			t.Fatalf("%s: only the App token action may receive the key, got %q", s.Name, s.Uses)
		}
		for _, widen := range []string{"owner", "repositories", "skip-token-revoke"} {
			if _, ok := s.With[widen]; ok {
				t.Fatalf("%s: App token input %q would widen or extend the token", s.Name, widen)
			}
		}
		for k, v := range s.With {
			if strings.HasPrefix(k, "permission-") && v != "read" {
				t.Fatalf("%s: App token permission %s=%v, want read", s.Name, k, v)
			}
		}
		if s.With["permission-contents"] != "read" {
			t.Fatalf("%s: the App token must be limited to contents: read", s.Name)
		}
	}
	if keySteps != 1 {
		t.Fatalf("the App key must reach exactly one gate step, got %d", keySteps)
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
		`"+${BASE_SHA}:refs/admission/base"`, `"+${HEAD_SHA}:refs/admission/head"`,
		`--admission-git-dir "${RUNNER_TEMP}/objects.git"`,
		`--admission-observed-at "${ADMISSION_OBSERVED_AT}"`,
		// The gate's clock is the observation time, never the host default.
		`--now "${ADMISSION_OBSERVED_AT}"`,
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
	for name, want := range map[string]string{"MAX_DAILY_LOOSENING": "'50'", "MAX_WITHDRAW_PERCENT": "'5'", "MAX_WITHDRAW_PROJECT": "'20'"} {
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
			if secretRef.MatchString(e) {
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
	// The skip decision must not depend on a repository variable: the bot login is a literal in the
	// digest-pinned workflow (the merge policy pins the same literal).
	if strings.Contains(alarm.If, "vars.") || strings.Count(alarm.If, "user.login") != 1 ||
		!strings.Contains(alarm.If, "github.event.pull_request.user.login == 'prufyx-bot'") {
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
			if secretRef.MatchString(e) {
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
	t.Parallel()
	bin, err := exec.LookPath("actionlint")
	if err != nil {
		t.Skip("actionlint is not installed")
	}
	out, err := exec.Command(bin, workflowPath).CombinedOutput()
	if err != nil {
		t.Fatalf("actionlint: %v\n%s", err, out)
	}
}

// The scheduled and manual runs check every pinned citation on its release
// line, from the base checkout: pinned rules have no lease end, so this is
// what keeps them current. A change's own run does not need it.
func TestWorkflowChecksPinnedCitationsOnSchedule(t *testing.T) {
	t.Parallel()
	raw, err := os.ReadFile(workflowPath)
	if err != nil {
		t.Fatal(err)
	}
	var wf workflow
	if err := yaml.Unmarshal(raw, &wf); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, s := range wf.Jobs["gate"].Steps {
		if s.Name != "Check the pinned citations on their release line" {
			continue
		}
		found = true
		for _, want := range []string{"evidence repin", "--pinned-only", "--baseline release-line", "set -euo pipefail"} {
			if !strings.Contains(s.Run, want) {
				t.Errorf("pinned check lacks %q", want)
			}
		}
		if s.WorkingDirectory != "base" {
			t.Errorf("pinned check runs in %q, want the base checkout", s.WorkingDirectory)
		}
		if strings.Contains(s.Run, "|| true") {
			t.Error("pinned check must not swallow its status")
		}
	}
	if !found {
		t.Fatal("no pinned-citation check step in the gate job")
	}
	if !strings.Contains(string(raw), "if: github.event_name == 'schedule' || github.event_name == 'workflow_dispatch'\n        working-directory: base\n        env:\n          GITHUB_TOKEN: ${{ steps.app-token.outputs.token || github.token }}\n        run: |\n          set -euo pipefail\n          baselines=()\n          if [ -f cli/knowledge/repin-baselines.json ]; then\n            baselines=(--baselines cli/knowledge/repin-baselines.json)\n          fi\n          \"${RUNNER_TEMP}/prufyx-maintainer\" evidence repin \\\n            --pinned-only") {
		t.Error("the pinned check must run on schedule and manual runs only")
	}
}

// TestWorkflowMergeGroup pins the merge queue mode: the trigger exists, the
// queue entry is read and verified before the gate runs, the gate is still
// built from the group base, and no step can be skipped or turned into a
// pass.
func TestWorkflowMergeGroup(t *testing.T) {
	t.Parallel()
	raw, err := os.ReadFile(workflowPath)
	if err != nil {
		t.Fatal(err)
	}
	var wf workflow
	if err := yaml.Unmarshal(raw, &wf); err != nil {
		t.Fatal(err)
	}
	if _, ok := wf.On["merge_group"]; !ok {
		t.Fatal("the gate must run on merge_group (it is a required check of the queue)")
	}
	code := yamlComment.ReplaceAllString(string(raw), "")
	for _, forbidden := range []string{"continue-on-error", "neutral"} {
		if strings.Contains(code, forbidden) {
			t.Fatalf("the workflow contains %q: no step may be allowed to fail or report neutral", forbidden)
		}
	}
	job := wf.Jobs["gate"]
	if job.If != "" {
		t.Fatalf("the gate job must not be conditional (a skipped required check can pass): %q", job.If)
	}
	if !strings.Contains(job.Env["HEAD_SHA"], "github.event.merge_group.head_sha") || !strings.Contains(job.Env["MQ_BASE_SHA"], "github.event.merge_group.base_sha") {
		t.Fatal("a merge_group run checks the group head against the group base")
	}
	var all string
	queueAt, exportAt := -1, -1
	for i, s := range job.Steps {
		all += s.Run + "\n"
		if s.ID == "queue" {
			queueAt = i
			if s.If != "github.event_name == 'merge_group'" {
				t.Fatalf("the queue step condition is %q", s.If)
			}
		}
		if strings.Contains(s.Run, "gate export") && exportAt < 0 {
			exportAt = i
		}
		if s.ID == "verify" && s.If != "" {
			t.Fatal("the verify step must always run")
		}
	}
	if queueAt < 0 || exportAt < 0 || queueAt > exportAt {
		t.Fatalf("the queue entry must be verified before the trees are exported (queue %d, export %d)", queueAt, exportAt)
	}
	for _, want := range []string{
		`gh api "repos/${GITHUB_REPOSITORY}/pulls/${pr}" > "${RUNNER_TEMP}/queue-pr.json"`,
		`gate queue-context`,
		`--pr-json "${RUNNER_TEMP}/queue-pr.json"`,
		`merge_group)`, `base="${MQ_BASE_SHA}"`,
		`merge-base --is-ancestor refs/admission/main "${BASE_SHA}"`,
		`compare_head="${QUEUE_PR_HEAD}"`,
		`author="${QUEUE_AUTHOR}"`, `SHADOW_LABEL="${QUEUE_SHADOW}"`,
		`The queue context is missing.`,
		`The commit list or the daily count is missing in a queue run.`,
	} {
		if !strings.Contains(all, want) {
			t.Fatalf("the merge queue mode no longer runs %s", want)
		}
	}
	// The queue run never posts alarms, re-derives everything, or merges.
	if !strings.Contains(wf.Jobs["alarm"].If, "github.event_name != 'merge_group'") {
		t.Fatal("a queue run must not open alarm issues")
	}
	if strings.Contains(all, `"merge_group" ] ||`) {
		t.Fatal("merge_group must not take the re-derivation path")
	}
}

var nightlyWorkflowPath = filepath.Join(repoRoot, ".github", "workflows", "nightly-main.yml")

func TestNightlyWorkflowShape(t *testing.T) {
	t.Parallel()
	raw, err := os.ReadFile(nightlyWorkflowPath)
	if err != nil {
		t.Fatal(err)
	}
	var wf workflow
	if err := yaml.Unmarshal(raw, &wf); err != nil {
		t.Fatal(err)
	}
	if _, ok := wf.On["merge_group"]; !ok {
		t.Fatal("the nightly check must run on merge_group")
	}
	for trigger := range wf.On {
		if trigger != "merge_group" && trigger != "pull_request" {
			t.Fatalf("unexpected trigger %s", trigger)
		}
	}
	code := yamlComment.ReplaceAllString(string(raw), "")
	if strings.Contains(code, "continue-on-error") || strings.Contains(code, "neutral") || secretRef.MatchString(code) {
		t.Fatal("no continue-on-error, neutral result or secret in the nightly check")
	}
	if len(wf.Permissions) != 3 || wf.Permissions["contents"] != "read" || wf.Permissions["actions"] != "read" || wf.Permissions["pull-requests"] != "read" {
		t.Fatalf("permissions %v", wf.Permissions)
	}
	job := wf.Jobs["nightly"]
	if len(wf.Jobs) != 1 || job.If != "" || job.Environment != "" {
		t.Fatal("one unconditional job without an environment")
	}
	// Name of the required context.
	if !strings.Contains(string(raw), "name: Nightly main\n\n#") && !strings.Contains(string(raw), "    name: Nightly main\n") {
		t.Fatal("the job must be named Nightly main")
	}
	enforce := 0
	for i, s := range job.Steps {
		if strings.Contains(s.Run, "${{") {
			t.Fatalf("%s: expressions must reach scripts through env", s.Name)
		}
		if i == 0 {
			if s.ID != "mode" || s.If != "" || !strings.Contains(s.Run, "Unexpected event") || !strings.Contains(s.Run, "exit 1") {
				t.Fatal("the first step must classify the event and fail on any other")
			}
			continue
		}
		if s.If != "steps.mode.outputs.enforce == 'true'" {
			t.Fatalf("%s: every later step runs exactly when the queue entry is judged, got %q", s.Name, s.If)
		}
		enforce++
		if s.Uses != "" {
			if at := strings.Index(s.Uses, "@"); at < 0 || len(s.Uses[at+1:]) < 40 {
				t.Fatalf("%s: action not pinned by commit", s.Name)
			}
		}
		if strings.HasPrefix(s.Uses, "actions/checkout@") && (s.With["persist-credentials"] != false || s.With["ref"] != "${{ github.event.merge_group.base_sha }}") {
			t.Fatalf("%s: checkout must be the group base without credentials", s.Name)
		}
	}
	if enforce == 0 {
		t.Fatal("no enforcing steps")
	}
	var all string
	for _, s := range job.Steps {
		all += s.Run + "\n"
	}
	for _, want := range []string{
		`actions/workflows/ci.yml/runs?branch=main&event=schedule&status=completed`,
		`gate queue-context`, `gate nightly --runs "${dir}/runs.json"`,
		`head_sha=${PR_HEAD}`, `--select`, `--fix --pr-head "${PR_HEAD}"`,
		`The nightly-fix label could not be read.`,
	} {
		if !strings.Contains(all, want) {
			t.Fatalf("the nightly check no longer runs %s", want)
		}
	}
}
