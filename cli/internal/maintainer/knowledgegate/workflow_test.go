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
		Permissions     map[string]string `yaml:"permissions"`
		Env             map[string]string `yaml:"env"`
		Outputs         map[string]string `yaml:"outputs"`
		Needs           any               `yaml:"needs"`
		If              string            `yaml:"if"`
		Environment     string            `yaml:"environment"`
		Name            string            `yaml:"name"`
		ContinueOnError any               `yaml:"continue-on-error"`
		Steps           []struct {
			If               string            `yaml:"if"`
			ContinueOnError  any               `yaml:"continue-on-error"`
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
	// merge_group runs the queued commit's own workflow definition, so it is
	// a correctness check only (see TestWorkflowQueueRun for what keeps it
	// from being trusted or holding a secret).
	if _, ok := wf.On["merge_group"]; !ok {
		t.Fatal("the gate must also run for the merge queue (a correctness re-check of what lands)")
	}
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
		// The live tip of main, resolved by the job itself.
		`git ls-remote "https://github.com/${GITHUB_REPOSITORY}.git" refs/heads/main`,
		// Whether the head contains the base; a change that does not is
		// gated through the tree of merging it onto the live tip.
		`merge-base --is-ancestor "${BASE_SHA}" "${HEAD_SHA}"`,
		`gate merge-tree --git-dir "${RUNNER_TEMP}/objects.git" --base "${BASE_SHA}" --head "${HEAD_SHA}"`,
		`gate export --git-dir "${RUNNER_TEMP}/objects.git" --tree "${tree}" --out head`,
		`"+${BASE_SHA}:refs/admission/base"`, `"+${HEAD_SHA}:refs/admission/head"`,
		`--admission-git-dir "${RUNNER_TEMP}/objects.git"`,
		`--admission-observed-at "${ADMISSION_OBSERVED_AT}"`,
		// Both trees from git objects, at exactly these commits.
		`gate export --git-dir "${RUNNER_TEMP}/objects.git" --commit "${BASE_SHA}" --out base`,
		`gate export --git-dir "${RUNNER_TEMP}/objects.git" --commit "${HEAD_SHA}" --out head`, // queue and scheduled runs
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
	// The gate job's environment holds the App key for the pull request
	// run; the queue run gets one that holds none.
	if job.Environment != queueEnvironment {
		t.Fatalf("the gate job environment = %q, want %q", job.Environment, queueEnvironment)
	}
	if strings.Contains(string(raw), "PR_BASE_SHA") || strings.Contains(all, `"${PR_BASE_SHA}" != "${tip}"`) {
		t.Fatal("the gate no longer requires the pull request base to be the live tip: it gates the merge of the live tip and the head")
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
			if s.With["ref"] != "${{ steps.base.outputs.gate_sha }}" || s.With["repository"] != nil {
				t.Fatalf("%s: checks out something other than the live main tip", s.Name)
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

const queueEnvironment = "${{ github.event_name == 'merge_group' && 'knowledge-gate-queue' || 'knowledge-gate' }}"

// resolveArms returns the arms of the event switch of the "Resolve the base"
// step, by pattern.
func resolveArms(t *testing.T, run string) map[string]string {
	t.Helper()
	start := strings.Index(run, `case "${GITHUB_EVENT_NAME}" in`)
	end := strings.Index(run, "esac")
	if start < 0 || end < start {
		t.Fatal("the base step no longer switches on the event")
	}
	body := run[start+len(`case "${GITHUB_EVENT_NAME}" in`) : end]
	arm := regexp.MustCompile(`(?m)^\s*([a-z_|*]+)\)\s*$`)
	idx := arm.FindAllStringSubmatchIndex(body, -1)
	out := map[string]string{}
	for i, m := range idx {
		stop := len(body)
		if i+1 < len(idx) {
			stop = idx[i+1][0]
		}
		out[body[m[2]:m[3]]] = body[m[1]:stop]
	}
	return out
}

// TestWorkflowQueueRun pins what makes the merge_group run safe to have: it
// is a correctness check (never a trust control), it holds no secret, its
// required job cannot be skipped or softened, it cannot pass vacuously, and
// the gate code always comes from the live tip of main.
func TestWorkflowQueueRun(t *testing.T) {
	t.Parallel()
	raw, err := os.ReadFile(workflowPath)
	if err != nil {
		t.Fatal(err)
	}
	var wf workflow
	if err := yaml.Unmarshal(raw, &wf); err != nil {
		t.Fatal(err)
	}
	job := wf.Jobs["gate"]

	// The required check is the same job in every run: no job-level if and
	// no continue-on-error on it or on any step, so a skipped or softened
	// job cannot satisfy the queue.
	if job.Name != "Knowledge gate" || job.If != "" || ciSoftFail(job.ContinueOnError) {
		t.Fatalf("the required job must always run and fail hard: name=%q if=%q coe=%v", job.Name, job.If, job.ContinueOnError)
	}
	for _, s := range job.Steps {
		if ciSoftFail(s.ContinueOnError) {
			t.Fatalf("%s: continue-on-error would soften the required check", s.Name)
		}
	}

	// No secret on the queue path. Every step that names a secret is
	// skipped for merge_group; the job env and outputs name none; the only
	// secrets are the two known ones; the alarm job never runs for a queue.
	code := yamlComment.ReplaceAllString(string(raw), "")
	for name, v := range job.Env {
		if secretRef.MatchString(v) {
			t.Fatalf("job env %s names a secret", name)
		}
	}
	for name, v := range job.Outputs {
		if secretRef.MatchString(v) {
			t.Fatalf("job output %s names a secret", name)
		}
	}
	named := 0
	for _, s := range job.Steps {
		uses := secretRef.MatchString(s.Run) || secretRef.MatchString(s.Uses) || secretRef.MatchString(s.If)
		for _, v := range s.With {
			if str, ok := v.(string); ok && secretRef.MatchString(str) {
				uses = true
			}
		}
		for _, v := range s.Env {
			if secretRef.MatchString(v) {
				uses = true
			}
		}
		if !uses {
			continue
		}
		named++
		if !strings.HasPrefix(s.If, "github.event_name != 'merge_group' && ") {
			t.Fatalf("%s: names a secret and may run in a merge_group run (if: %q)", s.Name, s.If)
		}
	}
	if named != 1 {
		t.Fatalf("exactly the App token step may name a secret in the gate job, got %d", named)
	}
	if strings.Contains(code, "secrets.") && len(regexp.MustCompile(`secrets\.([A-Z_]+)`).FindAllStringSubmatch(code, -1)) != 2 {
		t.Fatal("the workflow names a secret besides the two known ones")
	}
	// The only token a queue step may use is the workflow's own.
	for _, s := range job.Steps {
		for _, v := range s.Env {
			if strings.Contains(v, "secrets.") && !strings.Contains(v, "secrets.GITHUB_TOKEN") {
				t.Fatalf("%s: names a secret", s.Name)
			}
		}
	}
	alarm := wf.Jobs["alarm"]
	if !strings.Contains(alarm.If, "github.event_name != 'merge_group'") {
		t.Fatalf("the alarm job must skip merge_group runs: %q", alarm.If)
	}
	if alarm.Environment != "knowledge-alarms" {
		t.Fatalf("alarm environment %q", alarm.Environment)
	}

	// No vacuous pass: the event switch.
	var resolve string
	var checkoutRef any
	for _, s := range job.Steps {
		if s.ID == "base" {
			resolve = s.Run
		}
		if strings.HasPrefix(s.Uses, "actions/checkout@") {
			checkoutRef = s.With["ref"]
		}
	}
	arms := resolveArms(t, resolve)
	star, ok := arms["*"]
	if !ok || !strings.Contains(star, "exit 1") || strings.Contains(star, "base=") {
		t.Fatalf("the catch-all event arm must fail, never choose a base: %q", star)
	}
	if v, ok := arms["schedule|workflow_dispatch"]; !ok || !strings.Contains(v, `base="${HEAD_SHA}"`) {
		t.Fatalf("only scheduled and manual runs may compare a commit with itself: %q", v)
	}
	mg, ok := arms["merge_group"]
	if !ok || !strings.Contains(mg, `base="${MQ_BASE_SHA}"`) || !strings.Contains(mg, `"${MQ_BASE_REF}" != "refs/heads/main"`) ||
		!strings.Contains(mg, `[ "${base}" = "${HEAD_SHA}" ]`) {
		t.Fatalf("the merge_group arm must take the queue's base, require main and refuse base == head: %q", mg)
	}
	if strings.Contains(mg, "tip") && strings.Contains(mg, `!= "${tip}"`) {
		t.Fatal("the queue base is a chain of queue entries: it is not required to equal the live tip")
	}
	if prt := arms["pull_request_target"]; !strings.Contains(prt, `base="${tip}"`) {
		t.Fatalf("a pull request is gated against the live tip: %q", prt)
	}
	if strings.Contains(job.Env["HEAD_SHA"], "merge_group.head_sha") == false {
		t.Fatal("the queue head must come from the merge_group event")
	}
	if len(arms) != 4 {
		t.Fatalf("unexpected event arms %v", arms)
	}

	// The gate code: the live tip of main, from ls-remote, only.
	if checkoutRef != "${{ steps.base.outputs.gate_sha }}" {
		t.Fatalf("the gate source ref is %v", checkoutRef)
	}
	if !strings.Contains(resolve, `echo "gate_sha=${tip}" >> "${GITHUB_OUTPUT}"`) || strings.Count(resolve, "gate_sha=") != 1 ||
		!strings.Contains(resolve, `tip="$(git ls-remote "https://github.com/${GITHUB_REPOSITORY}.git" refs/heads/main | cut -f1)"`) {
		t.Fatal("the gate source commit must be the live tip of main and nothing else")
	}

	// The queue chain contains the live tip; the queue evidence is gathered
	// and handed to the gate; the commit list and daily count are not
	// skipped for the queue.
	all := ""
	byName := map[string]string{}
	ifs := map[string]string{}
	for _, s := range job.Steps {
		all += s.Run + "\n"
		byName[s.Name] = s.Run
		ifs[s.Name] = s.If
	}
	for _, want := range []string{
		`merge-base --is-ancestor "${LIVE_TIP}" "${BASE_SHA}"`,
		`args+=(--queue-merge "${RUNNER_TEMP}/queue-merge.json")`,
		`actions/runs?event=pull_request_target&head_sha=${head_sha}`,
		`pulls/${number}/commits`,
		`rev-list --parents -n 1 "${HEAD_SHA}"`,
	} {
		if !strings.Contains(all, want) {
			t.Fatalf("the workflow no longer runs %s", want)
		}
	}
	if ifs["Collect the queue entry's evidence"] != "github.event_name == 'merge_group'" {
		t.Fatal("the queue evidence is collected for merge_group runs")
	}
	if !strings.Contains(ifs["Count the loosening changes the automation merged in the last day"], "merge_group") {
		t.Fatal("the daily count must also run for the queue")
	}
	if ifs["List the change's commits"] != "github.event_name == 'pull_request_target'" {
		t.Fatal("the compare-API commit list is for pull request runs; a queue run's list comes from the evidence")
	}
	verify := byName["Verify the change"]
	i := strings.Index(verify, `if [ "${GITHUB_EVENT_NAME}" = "merge_group" ]; then`)
	j := strings.Index(verify, `--sender "${EVENT_SENDER}"`)
	if i < 0 || j < i || strings.Count(verify, `--sender "${EVENT_SENDER}"`) != 1 || strings.Contains(verify[i:j], "else") == false {
		t.Fatal("the sender of a queue run is the queue's own account and must never be passed to the gate")
	}
	arm := verify[i:j]
	if k := strings.Index(arm, "else"); k > 0 {
		arm = arm[:k]
	}
	if strings.Contains(arm, "--author") || strings.Contains(arm, "--commits") || strings.Contains(arm, "--sender") {
		t.Fatal("a queue run takes author and commits from the evidence only")
	}
}
