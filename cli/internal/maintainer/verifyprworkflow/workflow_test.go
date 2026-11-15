// SPDX-License-Identifier: AGPL-3.0-only

// Package verifyprworkflow holds the offline lint of
// .github/workflows/verify-pr.yml. The workflow is a report-only check that
// feeds a later admission decision, so the properties it rests on are pinned
// here: it runs from the base branch, holds no secret, never checks out the
// change, never swallows a failure and never lets event text into a shell.
// The tests need the repository checkout; in the staged release source (cli/
// only) they are skipped. Nothing here touches the network.
package verifyprworkflow

import (
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

type step struct {
	ID               string            `yaml:"id"`
	If               string            `yaml:"if"`
	Name             string            `yaml:"name"`
	Uses             string            `yaml:"uses"`
	With             map[string]any    `yaml:"with"`
	Env              map[string]string `yaml:"env"`
	Run              string            `yaml:"run"`
	WorkingDirectory string            `yaml:"working-directory"`
}

type job struct {
	Name        string            `yaml:"name"`
	If          string            `yaml:"if"`
	RunsOn      string            `yaml:"runs-on"`
	Permissions map[string]string `yaml:"permissions"`
	Steps       []step            `yaml:"steps"`
}

type workflow struct {
	On          map[string]any    `yaml:"on"`
	If          string            `yaml:"if"`
	Permissions map[string]string `yaml:"permissions"`
	Concurrency map[string]any    `yaml:"concurrency"`
	Jobs        map[string]job    `yaml:"jobs"`
}

const (
	baseRef     = "${{ github.event.pull_request.base.sha }}"
	workflowRel = ".github/workflows/verify-pr.yml"
)

// The exact steps, in order, with the only action each may use and the only
// condition and environment each may carry. A new, renamed, moved or removed
// step is a change to this authority and must change this table too.
var wantSteps = []struct{ name, uses, ifc, env string }{
	{"Validate the event values and start a failing result", "", "", ""},
	{"Check out the base (tool code only)", "actions/checkout@11d5960a326750d5838078e36cf38b85af677262", "", ""},
	{"Set up Go", "actions/setup-go@40f1582b2485089dde7abd97c1529aa768e1baff", "", ""},
	{"Build the tool from the base", "", "", ""},
	{"Fetch both commits as objects and require the head to contain the base", "", "", ""},
	{"Export both trees and the changed paths from the same two commits", "", "", ""},
	{"Classify the change", "", "", ""},
	{"Run verify-pr (reads the upstream tags from github.com)", "", "steps.classify.outputs.class == 'applicable'", ""},
	{"Re-resolve the head of the pull request and the tip of main", "", "", "GH_TOKEN=${{ github.token }}"},
	{"Write the result", "", "", "CLASS=${{ steps.classify.outputs.class }}"},
	{"Upload the result", "actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02", "always()", ""},
	{"Fail unless eligible or not applicable", "", "", ""},
}

// Byte-exact decision texts: the ELIGIBLE condition, the stale rule and the
// final verdict filter.
const (
	eligibleJQ = `'.eligible == true and .autoMerge == false and .headSha == $head and .baseSha == $base'`
	verdictJQ  = `'(.result == "ELIGIBLE" or .result == "NOT_APPLICABLE") and .stale == false and .headSha == $head and .baseSha == $base and .mainTip == $base'`
	staleCond  = `if [ "${live_head}" != "${HEAD_SHA}" ] || [ "${live_state}" != "open" ] || [ "${main_tip}" != "${BASE_SHA}" ]; then`
)

var pinnedRE = regexp.MustCompile(`^[A-Za-z0-9_.-]+/[A-Za-z0-9_./-]+@[0-9a-f]{40}$`)

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

func wantPerms(m map[string]string) bool {
	return len(m) == 2 && m["contents"] == "read" && m["pull-requests"] == "read"
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

	// Trigger: pull_request_target only, no path filter.
	if len(wf.On) != 1 {
		add("trigger-not-single")
	}
	prt, ok := wf.On["pull_request_target"]
	if !ok {
		add("trigger-not-pull_request_target")
	}
	if m, isMap := prt.(map[string]any); isMap {
		if _, has := m["paths"]; has {
			add("path-filter")
		}
		if _, has := m["paths-ignore"]; has {
			add("path-filter")
		}
	}

	// Permissions: exactly contents:read and pull-requests:read, workflow and job.
	if !wantPerms(wf.Permissions) {
		add("workflow-permissions")
	}
	if len(wf.Jobs) != 1 {
		add("job-count")
	}
	var j job
	for _, jj := range wf.Jobs {
		j = jj
		if !wantPerms(jj.Permissions) {
			add("job-permissions")
		}
	}
	if j.Name != "Verify PR" {
		add("job-name")
	}

	// No secrets, no App token, no id token.
	for _, bad := range []string{"secrets.", "secrets[", "app-token", "app-id", "private-key", "id-token", "GITHUB_TOKEN", "client-id"} {
		if strings.Contains(code, bad) {
			add("credential-reference")
			break
		}
	}
	if n := strings.Count(code, "github.token"); n > 1 {
		add("token-reference")
	}

	// Concurrency without cancel-in-progress.
	if c, has := wf.Concurrency["cancel-in-progress"]; has && c != false {
		add("cancel-in-progress")
	}
	if wf.Concurrency["group"] == nil {
		add("concurrency-group")
	}

	// continue-on-error anywhere.
	if strings.Contains(code, "continue-on-error") {
		add("continue-on-error")
	}

	checkouts := 0
	for _, s := range j.Steps {
		if s.Uses != "" && !pinnedRE.MatchString(s.Uses) {
			add("unpinned-uses")
		}
		if strings.HasPrefix(s.Uses, "actions/checkout@") {
			checkouts++
			if s.With["ref"] != baseRef {
				add("checkout-not-base")
			}
			if _, has := s.With["repository"]; has {
				add("checkout-other-repository")
			}
			if s.With["persist-credentials"] != false {
				add("checkout-persists-credentials")
			}
		}
		if strings.Contains(s.Run, "${{") {
			add("expression-in-run")
		}
		if s.ID == "verify" && strings.Contains(s.Run, "|| true") {
			add("verify-swallowed")
		}
	}
	if checkouts != 1 {
		add("checkout-count")
	}
	for _, bad := range []string{"head.sha }}", "head.ref", "head_ref", "refs/pull/", "head.repo }}"} {
		for _, s := range j.Steps {
			for _, val := range s.With {
				if str, isStr := val.(string); isStr && strings.Contains(str, bad) {
					add("head-in-with")
				}
			}
		}
	}

	// Exact step list, actions, conditions and environments.
	if len(j.Steps) != len(wantSteps) {
		add("step-list")
	} else {
		for i, w := range wantSteps {
			s := j.Steps[i]
			if s.Name != w.name {
				add("step-list")
			}
			if s.Uses != w.uses {
				add("step-action")
			}
			if s.If != w.ifc {
				add("step-condition")
			}
			var envs []string
			for k, val := range s.Env {
				envs = append(envs, k+"="+val)
			}
			if strings.Join(envs, ",") != w.env {
				add("step-env")
			}
		}
	}
	if wf.If != "" || j.If != "" {
		add("job-condition")
	}
	if j.RunsOn != "ubuntu-24.04" {
		add("runner")
	}
	for _, bad := range []string{"GITHUB_PATH", "GITHUB_ENV", "GITHUB_STATE"} {
		if strings.Contains(code, bad) {
			add("runner-env-write")
		}
	}
	if strings.Count(code, "github.token") != 1 || strings.Count(code, "GH_TOKEN") != 1 {
		add("token-placement")
	}
	headRefs := 0
	for _, s := range j.Steps {
		n := strings.Count(s.Run, "work}/head")
		headRefs += n
		switch s.Name {
		case "Export both trees and the changed paths from the same two commits":
			if n != 1 || !strings.Contains(s.Run, `--out "${work}/head"`) || !strings.Contains(s.Run, "::stop-commands::") {
				add("head-path")
			}
		case "Run verify-pr (reads the upstream tags from github.com)":
			if n != 1 || !strings.Contains(s.Run, `--head "${work}/head"`) || !strings.Contains(s.Run, "::stop-commands::") {
				add("head-path")
			}
		default:
			if n != 0 {
				add("head-path")
			}
		}
		if s.Name != "Build the tool from the base" && s.WorkingDirectory != "" {
			add("working-directory")
		}
		switch s.Name {
		case "Write the result":
			if !strings.Contains(s.Run, eligibleJQ) || !strings.Contains(s.Run, staleCond) || !strings.Contains(s.Run, "mainTip:$mainTip") {
				add("result-logic")
			}
		case "Fail unless eligible or not applicable":
			if !strings.Contains(s.Run, verdictJQ) {
				add("verdict-logic")
			}
		case "Classify the change":
			if !strings.Contains(s.Run, "grep -i -z -c -e 'target-recipes' -e 'crdversions'") {
				add("classify-case")
			}
		case "Fetch both commits as objects and require the head to contain the base":
			if strings.Count(s.Run, "fetch --no-tags") != 2 || !strings.Contains(s.Run, "config transfer.fsckObjects true") {
				add("fetch-fsck")
			}
		case "Re-resolve the head of the pull request and the tip of main":
			if !strings.Contains(s.Run, "/pulls/${PR_NUMBER}") || !strings.Contains(s.Run, "/branches/main") {
				add("reresolve")
			}
		}
	}
	if headRefs != 2 {
		add("head-path")
	}

	// The build step runs inside the base checkout.
	built := false
	for _, s := range j.Steps {
		if strings.Contains(s.Run, "go build") {
			built = true
			if s.WorkingDirectory != "tool-src/cli" {
				add("build-not-in-base-checkout")
			}
		}
	}
	if !built {
		add("no-build-step")
	}
	for _, s := range j.Steps {
		if strings.HasPrefix(s.Uses, "actions/checkout@") && s.With["path"] != "tool-src" {
			add("checkout-path")
		}
	}

	// The verdict step is last and cannot be skipped into green.
	if len(j.Steps) == 0 {
		add("no-steps")
	} else {
		last := j.Steps[len(j.Steps)-1]
		if last.Name != "Fail unless eligible or not applicable" || last.If != "" || !strings.Contains(last.Run, "jq -e") {
			add("verdict-step")
		}
	}
	return v
}

func readWorkflow(t *testing.T) string {
	t.Helper()
	_, self, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("no caller")
	}
	p := filepath.Join(filepath.Dir(self), "..", "..", "..", "..", filepath.FromSlash(workflowRel))
	raw, err := os.ReadFile(p)
	if err != nil {
		if os.IsNotExist(err) {
			t.Skip("repository checkout not present")
		}
		t.Fatal(err)
	}
	return string(raw)
}

func TestVerifyPRWorkflowIsClean(t *testing.T) {
	if v := lint(readWorkflow(t)); len(v) != 0 {
		t.Fatalf("workflow lint: %v", v)
	}
}

func has(v []string, c string) bool {
	for _, x := range v {
		if x == c {
			return true
		}
	}
	return false
}

// Each mutation breaks exactly one property in the real file; lint must name it.
func TestVerifyPRWorkflowMutationsAreCaught(t *testing.T) {
	text := readWorkflow(t)
	sha := "actions/setup-go@40f1582b2485089dde7abd97c1529aa768e1baff"
	cases := []struct {
		name, from, to, code string
	}{
		{"second trigger", "  pull_request_target:\n", "  pull_request:\n    branches: [main]\n  pull_request_target:\n", "trigger-not-single"},
		{"plain pull_request", "  pull_request_target:\n", "  pull_request:\n", "trigger-not-pull_request_target"},
		{"path filter", "    branches: [main]\n    types:", "    paths: [\"cli/**\"]\n    types:", "path-filter"},
		{"workflow write", "permissions:\n  contents: read\n  pull-requests: read\n\n# A run", "permissions:\n  contents: write\n  pull-requests: read\n\n# A run", "workflow-permissions"},
		{"workflow extra", "permissions:\n  contents: read\n  pull-requests: read\n\n# A run", "permissions:\n  contents: read\n  pull-requests: read\n  checks: write\n\n# A run", "workflow-permissions"},
		{"job extra", "    permissions:\n      contents: read\n      pull-requests: read\n", "    permissions:\n      contents: read\n      pull-requests: read\n      id-token: write\n", "job-permissions"},
		{"job missing perms", "    permissions:\n      contents: read\n      pull-requests: read\n", "", "job-permissions"},
		{"job renamed", "    name: Verify PR\n", "    name: Verify\n", "job-name"},
		{"secret", "          path: tool-src\n", "          path: tool-src\n          token: ${{ secrets.X }}\n", "credential-reference"},
		{"app token", "      - name: Set up Go\n", "      - name: t\n        uses: actions/create-github-app-token@bcd2ba49218906704ab6c1aa796996da409d3eb1\n      - name: Set up Go\n", "credential-reference"},
		{"second token use", "          GH_TOKEN: ${{ github.token }}\n", "          GH_TOKEN: ${{ github.token }}\n          OTHER: ${{ github.token }}\n", "token-reference"},
		{"cancel in progress", "  cancel-in-progress: false", "  cancel-in-progress: true", "cancel-in-progress"},
		{"continue on error", "        id: classify\n", "        id: classify\n        continue-on-error: true\n", "continue-on-error"},
		{"continue on error false", "    timeout-minutes: 15\n", "    timeout-minutes: 15\n    continue-on-error: false\n", "continue-on-error"},
		{"tag pin", sha, "actions/setup-go@v5", "unpinned-uses"},
		{"short pin", sha, "actions/setup-go@40f1582", "unpinned-uses"},
		{"docker uses", sha, "docker://alpine:3", "unpinned-uses"},
		{"checkout head sha", "ref: " + baseRef, "ref: ${{ github.event.pull_request.head.sha }}", "checkout-not-base"},
		{"checkout head ref", "ref: " + baseRef, "ref: ${{ github.head_ref }}", "checkout-not-base"},
		{"checkout fork", "          path: tool-src\n", "          path: tool-src\n          repository: ${{ github.event.pull_request.head.repo.full_name }}\n", "checkout-other-repository"},
		{"checkout persists", "          persist-credentials: false\n", "          persist-credentials: true\n", "checkout-persists-credentials"},
		{"second checkout", "      - name: Set up Go\n", "      - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262\n        with:\n          ref: ${{ github.event.pull_request.base.sha }}\n          path: tool-src\n          persist-credentials: false\n      - name: Set up Go\n", "checkout-count"},
		{"event in run", "          sha_re='^[0-9a-f]{40}$'\n", "          x='${{ github.event.pull_request.title }}'\n          sha_re='^[0-9a-f]{40}$'\n", "expression-in-run"},
		{"expression in run", "          set -euo pipefail\n          objects=\"${RUNNER_TEMP}/objects.git\"\n          git init", "          set -euo pipefail\n          echo ${{ env.HEAD_SHA }}\n          objects=\"${RUNNER_TEMP}/objects.git\"\n          git init", "expression-in-run"},
		{"build elsewhere", "        working-directory: tool-src/cli\n", "        working-directory: head\n", "build-not-in-base-checkout"},
		{"checkout path", "          path: tool-src\n", "          path: head\n", "checkout-path"},
		{"verify swallowed", "            --json --require-eligible \\\n", "            --json --require-eligible \\\n            || true \\\n", "verify-swallowed"},
		{"verdict not last", "      - name: Fail unless eligible or not applicable\n        run: |", "      - name: Fail unless eligible or not applicable\n        if: always()\n        run: |", "verdict-step"},
		{"verdict renamed", "      - name: Fail unless eligible or not applicable\n", "      - name: Report\n", "verdict-step"},
		{"job condition", "    timeout-minutes: 15\n", "    timeout-minutes: 15\n    if: github.actor != 'x'\n", "job-condition"},
		{"self hosted", "    runs-on: ubuntu-24.04\n", "    runs-on: self-hosted\n", "runner"},
		{"larger runner", "    runs-on: ubuntu-24.04\n", "    runs-on: ubuntu-latest-xl\n", "runner"},
		{"path write", "          set -euo pipefail\n          objects=\"${RUNNER_TEMP}/objects.git\"\n          git init", "          set -euo pipefail\n          echo /x >> \"${GITHUB_PATH}\"\n          objects=\"${RUNNER_TEMP}/objects.git\"\n          git init", "runner-env-write"},
		{"env write", "          sha_re='^[0-9a-f]{40}$'\n", "          echo X=1 >> \"${GITHUB_ENV}\"\n          sha_re='^[0-9a-f]{40}$'\n", "runner-env-write"},
		{"extra action", "      - name: Set up Go\n", "      - name: Extra\n        uses: actions/cache@0057852bfaa89a56745cba8c7296529d2fc39830\n      - name: Set up Go\n", "step-list"},
		{"swapped action sha", "actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02", "actions/upload-artifact@0000000000000000000000000000000000000000", "step-action"},
		{"other action same pin", "actions/setup-go@40f1582b2485089dde7abd97c1529aa768e1baff", "actions/cache@40f1582b2485089dde7abd97c1529aa768e1baff", "step-action"},
		{"deleted re-resolve", "      - name: Re-resolve the head of the pull request and the tip of main\n        env:\n          GH_TOKEN: ${{ github.token }}\n", "      - name: Re-resolve (moved)\n        env:\n          GH_TOKEN: ${{ github.token }}\n", "step-list"},
		{"step condition added", "      - name: Classify the change\n        id: classify\n", "      - name: Classify the change\n        id: classify\n        if: github.event.action == 'opened'\n", "step-condition"},
		{"verify always", "        if: steps.classify.outputs.class == 'applicable'\n", "        if: always()\n", "step-condition"},
		{"token moved to job", "      PR_NUMBER: ${{ github.event.pull_request.number }}\n", "      PR_NUMBER: ${{ github.event.pull_request.number }}\n      GH_TOKEN: ${{ github.token }}\n", "token-placement"},
		{"token in other step", "          CLASS: ${{ steps.classify.outputs.class }}\n", "          CLASS: ${{ steps.classify.outputs.class }}\n          GH_TOKEN: ${{ github.token }}\n", "token-placement"},
		{"extra env", "          CLASS: ${{ steps.classify.outputs.class }}\n", "          CLASS: ${{ steps.classify.outputs.class }}\n          EXTRA: x\n", "step-env"},
		{"head executed", "          echo \"${code}\" > \"${RUNNER_TEMP}/out/tool.exit\"\n", "          echo \"${code}\" > \"${RUNNER_TEMP}/out/tool.exit\"\n          bash \"${work}/head/run.sh\"\n", "head-path"},
		{"head in write step", "          out=\"${RUNNER_TEMP}/out\"\n", "          out=\"${RUNNER_TEMP}/out\"\n          . \"${RUNNER_TEMP}/work/head/x\" # work}/head\n", "head-path"},
		{"widened eligible", ".eligible == true and .autoMerge == false", ".eligible != null and .autoMerge == false", "result-logic"},
		{"dropped head match", " and .headSha == $head and .baseSha == $base'", " and .baseSha == $base'", "result-logic"},
		{"stale ignores main", " || [ \"${main_tip}\" != \"${BASE_SHA}\" ]; then", "; then", "result-logic"},
		{"mainTip not recorded", "mainTip:$mainTip, ", "", "result-logic"},
		{"verdict weakened", " and .stale == false and .headSha == $head and .baseSha == $base and .mainTip == $base'", " and .headSha == $head and .baseSha == $base and .mainTip == $base'", "verdict-logic"},
		{"verdict no main tip", " and .mainTip == $base'", "'", "verdict-logic"},
		{"verdict allows eligible only", "(.result == \"ELIGIBLE\" or .result == \"NOT_APPLICABLE\")", "(.result != \"ERROR\")", "verdict-logic"},
		{"case sensitive classify", "grep -i -z -c", "grep -z -c", "classify-case"},
		{"no fsck", "          git -C \"${objects}\" config transfer.fsckObjects true\n", "", "fetch-fsck"},
		{"export not stopped", "          echo \"::stop-commands::${token}\"\n          \"${RUNNER_TEMP}/prufyx-maintainer\" gate export", "          \"${RUNNER_TEMP}/prufyx-maintainer\" gate export", "head-path"},
		{"re-resolve without main", "/branches/main", "/branches/dev", "reresolve"},
		{"workdir elsewhere", "      - name: Classify the change\n        id: classify\n", "      - name: Classify the change\n        id: classify\n        working-directory: tool-src\n", "working-directory"},
		{"verdict no check", "          jq -e --arg head \"${HEAD_SHA}\" --arg base \"${BASE_SHA}\" \\\n            '(.result", "          jq --arg head \"${HEAD_SHA}\" --arg base \"${BASE_SHA}\" \\\n            '(.result", "verdict-step"},
	}
	for _, c := range cases {
		if !strings.Contains(text, c.from) {
			t.Fatalf("%s: mutation anchor not found (workflow changed; update the test)", c.name)
		}
		mutated := strings.Replace(text, c.from, c.to, 1)
		if mutated == text {
			t.Fatalf("%s: mutation changed nothing", c.name)
		}
		if v := lint(mutated); !has(v, c.code) {
			t.Errorf("%s: lint missed %q (got %v)", c.name, c.code, v)
		}
	}
}

func TestVerifyPRWorkflowLintRejectsGarbage(t *testing.T) {
	if v := lint("on: [push\n  :"); !has(v, "unparseable") {
		t.Fatalf("garbage accepted: %v", v)
	}
	if v := lint("name: x\n"); len(v) == 0 {
		t.Fatal("an empty workflow passed")
	}
}
