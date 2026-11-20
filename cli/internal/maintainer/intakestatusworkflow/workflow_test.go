// SPDX-License-Identifier: AGPL-3.0-only

// Package intakestatusworkflow holds the offline lint of
// .github/workflows/intake-status.yml and runs the script test of
// scripts/intake-status.py. The workflow writes comments with a repository
// token, so the properties it rests on are pinned here: it starts only on a
// schedule or by hand (never on an issue, comment or pull request event), the
// token holds issues write and contents read only, every action is pinned by
// full commit id, the checkout keeps no credentials, no event value is ever
// expanded into a shell line, and the only code that runs is the committed
// standard-library script. The tests need the repository checkout; in the
// staged release source (cli/ only) they are skipped. Nothing here touches the
// network.
package intakestatusworkflow

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

type step struct {
	Name string            `yaml:"name"`
	If   string            `yaml:"if"`
	Uses string            `yaml:"uses"`
	With map[string]any    `yaml:"with"`
	Env  map[string]string `yaml:"env"`
	Run  string            `yaml:"run"`
}

type job struct {
	Name           string            `yaml:"name"`
	If             string            `yaml:"if"`
	RunsOn         string            `yaml:"runs-on"`
	TimeoutMinutes int               `yaml:"timeout-minutes"`
	Permissions    map[string]string `yaml:"permissions"`
	Env            map[string]string `yaml:"env"`
	Steps          []step            `yaml:"steps"`
}

type workflow struct {
	On          map[string]any    `yaml:"on"`
	Permissions map[string]string `yaml:"permissions"`
	Concurrency map[string]any    `yaml:"concurrency"`
	Env         map[string]string `yaml:"env"`
	Jobs        map[string]job    `yaml:"jobs"`
}

const (
	workflowRel = ".github/workflows/intake-status.yml"
	scriptRel   = "scripts/intake-status.py"
	checkoutPin = "actions/checkout@11d5960a326750d5838078e36cf38b85af677262"
	runLine     = "python3 -I scripts/intake-status.py"
)

var (
	pinnedRE = regexp.MustCompile(`^[A-Za-z0-9_.-]+/[A-Za-z0-9_./-]+@[0-9a-f]{40}$`)
	// the only expression a step may contain: the job token, handed over through env, never inside a run line
	exprRE = regexp.MustCompile(`\$\{\{[^}]*\}\}`)
)

func stripComments(text string) string {
	var b strings.Builder
	for _, l := range strings.Split(text, "\n") {
		if strings.HasPrefix(strings.TrimSpace(l), "#") {
			continue
		}
		b.WriteString(l)
		b.WriteString("\n")
	}
	return b.String()
}

// lint returns one code per violated property; empty means the file is fine.
func lint(text string) []string {
	var v []string
	add := func(c string) { v = append(v, c) }
	var wf workflow
	if err := yaml.Unmarshal([]byte(text), &wf); err != nil {
		return []string{"unparseable"}
	}
	code := stripComments(text)

	// Triggers: schedule and workflow_dispatch, nothing else.
	if len(wf.On) != 2 {
		add("trigger-set")
	}
	if _, ok := wf.On["schedule"]; !ok {
		add("trigger-no-schedule")
	}
	if _, ok := wf.On["workflow_dispatch"]; !ok {
		add("trigger-no-dispatch")
	}
	for k := range wf.On {
		if k != "schedule" && k != "workflow_dispatch" {
			add("trigger-forbidden")
		}
	}
	if m, ok := wf.On["workflow_dispatch"].(map[string]any); ok && len(m) > 0 {
		add("dispatch-inputs") // an input would be attacker-shaped text
	}
	for _, bad := range []string{"pull_request_target", "issue_comment", "workflow_run", "repository_dispatch", "pull_request:"} {
		if strings.Contains(code, bad) {
			add("forbidden-event-text")
		}
	}

	// Permissions: contents read at workflow level; the job adds issues write and nothing else.
	if len(wf.Permissions) != 1 || wf.Permissions["contents"] != "read" {
		add("workflow-permissions")
	}
	if len(wf.Env) != 0 {
		add("workflow-env")
	}
	if len(wf.Jobs) != 1 {
		add("job-count")
		return v
	}
	var j job
	for _, x := range wf.Jobs {
		j = x
	}
	if len(j.Permissions) != 2 || j.Permissions["contents"] != "read" || j.Permissions["issues"] != "write" {
		add("job-permissions")
	}
	if len(j.Env) != 0 {
		add("job-env")
	}
	if j.If != "github.repository == 'prufyx/prufyx'" {
		add("job-repository-guard")
	}
	if j.RunsOn != "ubuntu-latest" || j.TimeoutMinutes < 1 || j.TimeoutMinutes > 10 {
		add("job-runner-or-timeout")
	}
	if wf.Concurrency["group"] != "intake-status" || wf.Concurrency["cancel-in-progress"] != false {
		add("concurrency")
	}

	// Steps: the pinned checkout without credentials, then the script. Nothing else.
	if len(j.Steps) != 2 {
		add("step-count")
		return v
	}
	co, run := j.Steps[0], j.Steps[1]
	if co.Uses != checkoutPin || !pinnedRE.MatchString(co.Uses) {
		add("checkout-pin")
	}
	if len(co.With) != 1 || co.With["persist-credentials"] != false || co.Run != "" || co.If != "" || len(co.Env) != 0 {
		add("checkout-credentials")
	}
	if run.Uses != "" || strings.TrimSpace(run.Run) != runLine || run.If != "" {
		add("run-step")
	}
	if len(run.Env) != 1 || run.Env["GH_TOKEN"] != "${{ github.token }}" {
		add("run-env")
	}
	// No expression anywhere except the token handed over through env; none inside a run line.
	for _, e := range exprRE.FindAllString(code, -1) {
		if e != "${{ github.token }}" {
			add("expression")
		}
	}
	if exprRE.MatchString(run.Run) || strings.Contains(code, "github.event") {
		add("expression-in-run")
	}
	// Every uses is pinned by full commit id.
	for _, line := range strings.Split(code, "\n") {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "- uses:") || strings.HasPrefix(t, "uses:") {
			ref := strings.TrimSpace(strings.SplitN(strings.TrimPrefix(strings.TrimPrefix(t, "- "), "uses:"), "#", 2)[0])
			if !pinnedRE.MatchString(ref) {
				add("unpinned-action")
			}
		}
	}
	// No secret other than the job token, no other write path.
	if strings.Contains(code, "secrets.") || strings.Contains(code, "gh api") || strings.Contains(code, "curl ") {
		add("other-credential-or-client")
	}
	return v
}

func has(v []string, c string) bool {
	for _, x := range v {
		if x == c {
			return true
		}
	}
	return false
}

func repoFile(t *testing.T, rel string) string {
	t.Helper()
	_, self, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("no caller")
	}
	p := filepath.Join(filepath.Dir(self), "..", "..", "..", "..", filepath.FromSlash(rel))
	if _, err := os.Stat(filepath.Join(filepath.Dir(p))); err != nil {
		if os.IsNotExist(err) {
			t.Skip("repository checkout not present")
		}
		t.Fatal(err)
	}
	return p
}

func readWorkflow(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile(repoFile(t, workflowRel))
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func TestIntakeStatusWorkflowIsClean(t *testing.T) {
	if v := lint(readWorkflow(t)); len(v) != 0 {
		t.Fatalf("workflow lint: %v", v)
	}
}

// Each mutation breaks one property in the real file; lint must name it.
func TestIntakeStatusWorkflowMutationsAreCaught(t *testing.T) {
	text := readWorkflow(t)
	cases := []struct{ name, from, to, code string }{
		{"issues trigger", "  workflow_dispatch:\n", "  workflow_dispatch:\n  issues:\n    types: [opened]\n", "trigger-set"},
		{"issue comment trigger", "  workflow_dispatch:\n", "  workflow_dispatch:\n  issue_comment:\n", "trigger-forbidden"},
		{"pull_request_target", "  workflow_dispatch:\n", "  workflow_dispatch:\n  pull_request_target:\n", "trigger-forbidden"},
		{"no schedule", "  schedule:\n    - cron: \"7,22,37,52 * * * *\"\n", "", "trigger-no-schedule"},
		{"dispatch input", "  workflow_dispatch:\n", "  workflow_dispatch:\n    inputs:\n      note:\n        type: string\n", "dispatch-inputs"},
		{"workflow write", "permissions:\n  contents: read\n\nconcurrency", "permissions:\n  contents: write\n\nconcurrency", "workflow-permissions"},
		{"workflow issues", "permissions:\n  contents: read\n\nconcurrency", "permissions:\n  contents: read\n  issues: write\n\nconcurrency", "workflow-permissions"},
		{"job extra permission", "      issues: write\n", "      issues: write\n      pull-requests: write\n", "job-permissions"},
		{"job no issues", "      issues: write\n", "", "job-permissions"},
		{"job contents write", "      contents: read\n      issues: write\n", "      contents: write\n      issues: write\n", "job-permissions"},
		{"job id token", "      issues: write\n", "      issues: write\n      id-token: write\n", "job-permissions"},
		{"no repository guard", "    if: github.repository == 'prufyx/prufyx'\n", "", "job-repository-guard"},
		{"unpinned checkout", "actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4.4.0", "actions/checkout@v4", "checkout-pin"},
		{"other action", "actions/checkout@11d5960a326750d5838078e36cf38b85af677262", "someone/checkout@11d5960a326750d5838078e36cf38b85af677262", "checkout-pin"},
		{"credentials kept", "          persist-credentials: false\n", "          persist-credentials: true\n", "checkout-credentials"},
		{"credentials default", "        with:\n          persist-credentials: false\n", "", "checkout-credentials"},
		{"event value in run", "        run: python3 -I scripts/intake-status.py\n", "        run: python3 -I scripts/intake-status.py ${{ github.event.issue.title }}\n", "run-step"},
		{"expression in env", "          GH_TOKEN: ${{ github.token }}\n", "          GH_TOKEN: ${{ github.token }}\n          TITLE: ${{ github.event.issue.title }}\n", "run-env"},
		{"not isolated python", "python3 -I scripts", "python3 scripts", "run-step"},
		{"other script", "scripts/intake-status.py\n", "scripts/other.py\n", "run-step"},
		{"secret", "          GH_TOKEN: ${{ github.token }}\n", "          GH_TOKEN: ${{ secrets.PAT }}\n", "run-env"},
		{"extra step", "      - name: Post the status comments\n", "      - name: Label\n        run: gh api -X POST repos/prufyx/prufyx/issues/1/labels\n      - name: Post the status comments\n", "step-count"},
		{"long timeout", "timeout-minutes: 10", "timeout-minutes: 360", "job-runner-or-timeout"},
		{"cancel in progress", "cancel-in-progress: false", "cancel-in-progress: true", "concurrency"},
	}
	for _, c := range cases {
		if !strings.Contains(text, c.from) {
			t.Errorf("%s: pattern not in the workflow", c.name)
			continue
		}
		mut := strings.Replace(text, c.from, c.to, 1)
		if v := lint(mut); !has(v, c.code) {
			t.Errorf("%s: lint says %v, want %s", c.name, v, c.code)
		}
	}
	if v := lint("not: [valid"); !has(v, "unparseable") {
		t.Errorf("garbage: %v", v)
	}
}

// The script test: a fixture feed and a mocked API (bad schema, id mismatch, unknown state, duplicate run, hostile text, wrong
// targets, write cap, stale feed). The interpreter must exist: a missing one is a failure, never a silent pass.
func TestIntakeStatusScriptTest(t *testing.T) {
	script := repoFile(t, "scripts/intake_status_test.py")
	if _, err := os.Stat(script); err != nil {
		t.Fatal(err)
	}
	py, err := exec.LookPath("python3")
	if err != nil {
		t.Fatalf("python3 is required to run the script test: %v", err)
	}
	cmd := exec.Command(py, "-I", script)
	cmd.Env = []string{"PATH=" + os.Getenv("PATH")}
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("script test failed: %v\n%s", err, out)
	}
}

// The script file exists next to the workflow that runs it.
func TestIntakeStatusScriptExists(t *testing.T) {
	p := repoFile(t, scriptRel)
	if fi, err := os.Stat(p); err != nil || fi.IsDir() {
		t.Fatalf("%s: %v", scriptRel, err)
	}
}
