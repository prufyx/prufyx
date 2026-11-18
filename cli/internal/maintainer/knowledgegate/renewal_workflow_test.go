// SPDX-License-Identifier: AGPL-3.0-only

package knowledgegate

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

var renewalWorkflowPath = filepath.Join(repoRoot, ".github", "workflows", "evidence-renewal.yml")

var renewalPinned = regexp.MustCompile(`^[A-Za-z0-9._/-]+@[0-9a-f]{40}$`)

type renewalStep struct {
	ID   string            `yaml:"id"`
	Name string            `yaml:"name"`
	Uses string            `yaml:"uses"`
	Run  string            `yaml:"run"`
	If   string            `yaml:"if"`
	With map[string]any    `yaml:"with"`
	Env  map[string]string `yaml:"env"`
}

type renewalJob struct {
	Permissions map[string]string `yaml:"permissions"`
	If          string            `yaml:"if"`
	Environment string            `yaml:"environment"`
	Env         map[string]string `yaml:"env"`
	Steps       []renewalStep     `yaml:"steps"`
}

type renewalWorkflow struct {
	On          map[string]any        `yaml:"on"`
	Permissions map[string]string     `yaml:"permissions"`
	Jobs        map[string]renewalJob `yaml:"jobs"`
}

// renewalProblems returns every way the renewal workflow text breaks the
// properties its safety rests on. An empty result means it holds them.
func renewalProblems(raw string) []string {
	var out []string
	bad := func(msg string, detail ...string) {
		out = append(out, strings.TrimSpace(msg+" "+strings.Join(detail, " ")))
	}
	var wf renewalWorkflow
	if err := yaml.Unmarshal([]byte(raw), &wf); err != nil {
		return []string{"unparseable: " + err.Error()}
	}
	for trigger := range wf.On {
		switch trigger {
		case "schedule", "workflow_dispatch":
		default:
			bad("unexpected trigger", trigger)
		}
	}
	if _, ok := wf.On["schedule"]; !ok {
		bad("no schedule trigger")
	}
	dispatch, _ := wf.On["workflow_dispatch"].(map[string]any)
	inputs, _ := dispatch["inputs"].(map[string]any)
	dry, _ := inputs["dry_run"].(map[string]any)
	if def, ok := dry["default"].(bool); !ok || !def {
		bad("dry_run must default to true")
	}
	if wf.Permissions == nil || len(wf.Permissions) != 0 {
		bad("top-level permissions must be empty")
	}
	if !strings.Contains(raw, "group: evidence-renewal") {
		bad("concurrency group evidence-renewal missing")
	}
	if strings.Contains(raw, "github.event.pull_request") || strings.Contains(raw, "head.ref") {
		bad("the workflow must not read pull request data")
	}
	for _, forbidden := range []string{"gh pr merge", "--auto", "pulls/merge", "enable-auto-merge", "git push", "persist-credentials: true"} {
		if strings.Contains(raw, forbidden) {
			bad("forbidden text", forbidden)
		}
	}

	prepare, sign, pr := wf.Jobs["prepare"], wf.Jobs["sign"], wf.Jobs["pr"]
	if len(wf.Jobs) != 3 || prepare.Steps == nil || sign.Steps == nil || pr.Steps == nil {
		return append(out, "jobs must be exactly prepare, sign and pr")
	}
	if prepare.Environment != "" {
		bad("prepare must not name an environment")
	}
	if pr.Environment != "renewal-pr" {
		bad("pr must run in the renewal-pr environment (the bot token)")
	}
	if sign.Environment != "renewal" {
		bad("sign must run in the renewal environment")
	}
	if len(prepare.Permissions) != 2 || prepare.Permissions["contents"] != "read" || prepare.Permissions["pull-requests"] != "read" {
		bad("prepare must hold contents: read and pull-requests: read only")
	}
	if len(sign.Permissions) != 1 || sign.Permissions["contents"] != "read" {
		bad("sign must hold contents: read only")
	}
	if pr.Permissions == nil || len(pr.Permissions) != 0 {
		bad("pr must hold no token permissions (it uses the bot token)")
	}
	if !strings.Contains(sign.If, "dry_run") || !strings.Contains(sign.If, "has-rules") {
		bad("sign must be skipped on a dry run and on an empty statement")
	}
	if !strings.Contains(pr.If, "needs.sign.outputs.signed == 'true'") {
		bad("pr must need a signed statement")
	}

	code := yamlComment.ReplaceAllString(raw, "")
	if n := len(secretRef.FindAllString(code, -1)); n != 4 ||
		strings.Count(code, "secrets.REATTEST_AUTOMATION_KEY }}") != 1 ||
		strings.Count(code, "secrets.REATTEST_AUTOMATION_KEY_PASSPHRASE") != 1 ||
		strings.Count(code, "secrets.KNOWLEDGE_BOT_TOKEN") != 2 {
		bad("the only secrets are the automation key, its passphrase and the bot token (twice, in the pr job)")
	}
	for _, s := range prepare.Steps {
		if secretRef.MatchString(s.Run) || secretRef.MatchString(strings.Join(mapValues(s.Env), " ")) {
			bad("prepare step names a secret", s.Name)
		}
	}
	keySteps := 0
	for _, s := range sign.Steps {
		if secretRef.MatchString(s.Run) {
			bad("a sign run step names a secret", s.Name)
		}
		if secretRef.MatchString(strings.Join(mapValues(s.Env), " ")) {
			keySteps++
			if s.ID != "key" || !strings.Contains(s.Run, "${RUNNER_TEMP}/renewal-key") || !strings.Contains(s.Run, "chmod 0600") {
				bad("the key may only be written, mode 0600, under RUNNER_TEMP in the key step", s.Name)
			}
		}
	}
	if keySteps != 1 {
		bad("exactly one sign step may hold the key")
	}
	botTokenSteps := 0
	for _, s := range pr.Steps {
		if secretRef.MatchString(s.Run) {
			bad("a pr run step names a secret", s.Name)
		}
		if env := strings.Join(mapValues(s.Env), " "); secretRef.MatchString(env) {
			botTokenSteps++
			if s.Env["GH_TOKEN"] != "${{ secrets.KNOWLEDGE_BOT_TOKEN }}" || strings.Count(env, "secrets") != 1 {
				bad("a pr step may name only the bot token, as GH_TOKEN", s.Name)
			}
		}
		if s.Uses != "" && secretRef.MatchString(fmt.Sprint(s.With)) {
			bad("a pr action step names a secret", s.Name)
		}
		if s.Uses != "" && strings.HasPrefix(s.Uses, "actions/checkout@") {
			bad("pr must not check out the repository")
		}
	}

	if botTokenSteps != 2 {
		bad("exactly the login guard and the open step may hold the bot token")
	}
	guard := -1
	for i, s := range pr.Steps {
		if s.Name == "Require the pinned bot account" {
			guard = i
		}
	}
	if guard < 0 {
		bad("pr: login guard step missing")
	} else {
		g := pr.Steps[guard]
		if g.Env["GH_TOKEN"] != "${{ secrets.KNOWLEDGE_BOT_TOKEN }}" || g.Env["PINNED_LOGIN"] != "${{ vars.KNOWLEDGE_BOT_LOGIN }}" ||
			!strings.Contains(g.Run, `gh api user --jq .login`) ||
			!strings.Contains(g.Run, `[ "${login}" != "${PINNED_LOGIN}" ]`) ||
			!strings.Contains(g.Run, `[ -z "${PINNED_LOGIN}" ]`) {
			bad("pr: the login guard must compare the token's login with the pinned login and refuse an empty pin")
		}
		if guard != 0 {
			bad("pr: the login guard must be the first step")
		}
		if pr.Steps[len(pr.Steps)-1].Name != "Open the pull request" || guard > len(pr.Steps)-2 {
			bad("pr: the open step must come after the login guard")
		}
	}
	if pr.Env["BOT_LOGIN"] != "${{ vars.KNOWLEDGE_BOT_LOGIN }}" {
		bad("pr: the author check must use the pinned login without a fallback")
	}

	// Order in sign: build, then key written, then sign, then removal.
	idx := func(sub string) int {
		for i, s := range sign.Steps {
			if strings.Contains(s.Name, sub) {
				return i
			}
		}
		return -1
	}
	build, write, signStep, remove := idx("Build the CLI"), idx("Write the key material"), idx("Sign as the automation role"), idx("Remove the key material")
	if build < 0 || write < 0 || signStep < 0 || remove < 0 || !(build < write && write < signStep && signStep < remove) {
		bad("sign step order must be build, write key, sign, remove key")
	} else if sign.Steps[remove].If != "always()" || !strings.Contains(sign.Steps[remove].Run, "rm -rf") {
		bad("the key must be removed in an always() step")
	}
	checksDigest := false
	for _, s := range sign.Steps {
		if strings.Contains(s.Run, "sha256sum") && strings.Contains(s.Run, "PREPARED_SHA256") {
			checksDigest = true
		}
	}
	if !checksDigest {
		bad("sign must check the prepared files against the prepare digest")
	}

	// Refusals and checks that fail closed, by the text of the step that
	// carries them.
	runs := func(steps []renewalStep) string {
		var b strings.Builder
		for _, s := range steps {
			b.WriteString(s.Run)
			b.WriteString("\n")
		}
		return b.String()
	}
	need := func(job string, steps []renewalStep, why string, subs ...string) {
		text := runs(steps)
		for _, sub := range subs {
			if !strings.Contains(text, sub) {
				bad(job+": missing check ("+why+")", sub)
			}
		}
	}
	need("prepare", prepare.Steps, "main-ref refusal", `"${GITHUB_REF}" != "refs/heads/main"`)
	need("prepare", prepare.Steps, "open renewal pull request refusal", `startswith("factory/renewal/automated-")`, `open=true`)
	need("prepare", prepare.Steps, "cap arithmetic", `n=$(( MAX_DAILY_LOOSENING - counted ))`, `if [ "${n}" -gt 45 ]; then n=45; fi`, `if [ "${n}" -lt 1 ]; then n=0; fi`, `[ "${count}" -gt "${N}" ]`)
	need("sign", sign.Steps, "artifact digest", `"${digest}" != "${PREPARED_SHA256}"`, `.base == $base`)
	need("pr", pr.Steps, "artifact digest", `"${digest}" != "${PREPARED_SHA256}"`)
	need("pr", pr.Steps, "base check", `[ "${base}" = "${GITHUB_SHA}" ]`, `"${tip}" != "${base}"`)
	need("pr", pr.Steps, "refusals", `startswith("factory/renewal/automated-")`, `[ "${pack}" = "${PACK}" ]`, `grep -Eq '^(cncf|community)$'`)

	for _, job := range []string{"prepare", "sign", "pr"} {
		for _, s := range wf.Jobs[job].Steps {
			if s.Uses != "" && !renewalPinned.MatchString(s.Uses) {
				bad("action not pinned by commit", s.Uses)
			}
		}
	}
	return out
}

func mapValues(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for _, v := range m {
		out = append(out, v)
	}
	return out
}

func TestRenewalWorkflowShape(t *testing.T) {
	t.Parallel()
	raw, err := os.ReadFile(renewalWorkflowPath)
	if err != nil {
		t.Fatal(err)
	}
	if p := renewalProblems(string(raw)); len(p) != 0 {
		t.Fatalf("renewal workflow: %s", strings.Join(p, "; "))
	}
}

// TestRenewalWorkflowRefusesWeakening mutates the real workflow in the ways
// that would widen who can reach the key or what a run may do, and requires
// every mutation to be reported.
func TestRenewalWorkflowRefusesWeakening(t *testing.T) {
	t.Parallel()
	raw, err := os.ReadFile(renewalWorkflowPath)
	if err != nil {
		t.Fatal(err)
	}
	base := string(raw)
	mutations := map[string]func(string) string{
		"pull_request trigger": func(s string) string {
			return strings.Replace(s, "on:\n  schedule:", "on:\n  pull_request:\n  schedule:", 1)
		},
		"pull_request_target trigger": func(s string) string {
			return strings.Replace(s, "on:\n  schedule:", "on:\n  pull_request_target:\n  schedule:", 1)
		},
		"dry run defaults off": func(s string) string {
			return strings.Replace(s, "default: true", "default: false", 1)
		},
		"top-level write": func(s string) string {
			return strings.Replace(s, "permissions: {}\n\nconcurrency", "permissions:\n  contents: write\n\nconcurrency", 1)
		},
		"unpinned action": func(s string) string {
			return strings.Replace(s, "actions/checkout@11d5960a326750d5838078e36cf38b85af677262", "actions/checkout@v4", 1)
		},
		"sign without environment": func(s string) string {
			return strings.Replace(s, "    environment: renewal\n", "", 1)
		},
		"prepare in the environment": func(s string) string {
			return strings.Replace(s, "  prepare:\n    name: Prepare the statement\n", "  prepare:\n    environment: renewal\n    name: Prepare the statement\n", 1)
		},
		"secret in prepare": func(s string) string {
			return strings.Replace(s, "      REATTEST_TRUST_ROOT_DIGEST: ${{ vars.REATTEST_TRUST_ROOT_DIGEST }}\n    outputs:\n      has-rules", "      REATTEST_TRUST_ROOT_DIGEST: ${{ vars.REATTEST_TRUST_ROOT_DIGEST }}\n      LEAK: ${{ secrets.REATTEST_AUTOMATION_KEY }}\n    outputs:\n      has-rules", 1)
		},
		"key not removed always": func(s string) string {
			return strings.Replace(s, "        if: always()\n        run: |\n          set -u\n          rm -rf", "        run: |\n          set -u\n          rm -rf", 1)
		},
		"sign runs on a dry run": func(s string) string {
			return strings.Replace(s, " && !(github.event_name == 'workflow_dispatch' && inputs.dry_run)", "", 1)
		},
		"pr without a signed statement": func(s string) string {
			return strings.Replace(s, " && needs.sign.outputs.signed == 'true'", "", 1)
		},
		"pr checks out the repository": func(s string) string {
			return strings.Replace(s, "      - name: Require the pinned bot account\n", "      - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262\n      - name: Require the bot App\n", 1)
		},
		"main-ref refusal removed": func(s string) string {
			return strings.Replace(s, `"${GITHUB_REF}" != "refs/heads/main"`, `false`, 1)
		},
		"prepare open-PR refusal removed": func(s string) string {
			return strings.Replace(s, "echo \"open=true\" >> \"${GITHUB_OUTPUT}\"", "echo \"open=false\" >> \"${GITHUB_OUTPUT}\"", 1)
		},
		"cap arithmetic: no subtraction": func(s string) string {
			return strings.Replace(s, "n=$(( MAX_DAILY_LOOSENING - counted ))", "n=${MAX_DAILY_LOOSENING}", 1)
		},
		"cap arithmetic: no ceiling": func(s string) string {
			return strings.Replace(s, `if [ "${n}" -gt 45 ]; then n=45; fi`, "", 1)
		},
		"cap arithmetic: no floor": func(s string) string {
			return strings.Replace(s, `if [ "${n}" -lt 1 ]; then n=0; fi`, "", 1)
		},
		"statement over the cap accepted": func(s string) string {
			return strings.Replace(s, `if [ "${count}" -gt "${N}" ]; then`, `if false; then`, 1)
		},
		"sign digest check removed": func(s string) string {
			return strings.Replace(s, `if [ "${digest}" != "${PREPARED_SHA256}" ]; then
            echo "The downloaded files do not match the digest prepare reported."
            exit 1
          fi
          jq -e`, `jq -e`, 1)
		},
		"sign base check removed": func(s string) string {
			return strings.Replace(s, `.pack == $pack and .base == $base and`, `.pack == $pack and`, 1)
		},
		"pr digest check removed": func(s string) string {
			i := strings.Index(s, "  pr:\n")
			return s[:i] + strings.Replace(s[i:], `"${digest}" != "${PREPARED_SHA256}"`, `false`, 1)
		},
		"pr base check removed": func(s string) string {
			return strings.Replace(s, `[ "${base}" = "${GITHUB_SHA}" ]`, `true`, 1)
		},
		"pr main-moved check removed": func(s string) string {
			return strings.Replace(s, `"${tip}" != "${base}"`, `false`, 1)
		},
		"pr open-PR refusal removed": func(s string) string {
			i := strings.Index(s, "  pr:\n")
			return s[:i] + strings.Replace(s[i:], `startswith("factory/renewal/automated-")`, `startswith("zzz")`, 1)
		},
		"pr pack check removed": func(s string) string {
			return strings.Replace(s, `[ "${pack}" = "${PACK}" ]`, `true`, 1)
		},
		"pr not in its environment": func(s string) string {
			return strings.Replace(s, "    environment: renewal-pr\n", "", 1)
		},
		"login guard compares nothing": func(s string) string {
			return strings.Replace(s, `[ "${login}" != "${PINNED_LOGIN}" ]`, `false`, 1)
		},
		"login guard allows an empty pin": func(s string) string {
			return strings.Replace(s, `[ -z "${PINNED_LOGIN}" ]`, `false`, 1)
		},
		"login guard reads another login": func(s string) string {
			return strings.Replace(s, "gh api user --jq .login", "echo prufyx-bot", 1)
		},
		"login guard pinned to a fallback": func(s string) string {
			return strings.Replace(s, "PINNED_LOGIN: ${{ vars.KNOWLEDGE_BOT_LOGIN }}", "PINNED_LOGIN: ${{ vars.KNOWLEDGE_BOT_LOGIN || 'x' }}", 1)
		},
		"pr author fallback restored": func(s string) string {
			i := strings.Index(s, "  pr:\n")
			return s[:i] + strings.Replace(s[i:], "BOT_LOGIN: ${{ vars.KNOWLEDGE_BOT_LOGIN }}", "BOT_LOGIN: ${{ vars.KNOWLEDGE_BOT_LOGIN || 'x[bot]' }}", 1)
		},
		"bot token in prepare": func(s string) string {
			return strings.Replace(s, "      REATTEST_TRUST_ROOT_DIGEST: ${{ vars.REATTEST_TRUST_ROOT_DIGEST }}\n    outputs:\n      has-rules", "      REATTEST_TRUST_ROOT_DIGEST: ${{ vars.REATTEST_TRUST_ROOT_DIGEST }}\n      GH_TOKEN: ${{ secrets.KNOWLEDGE_BOT_TOKEN }}\n    outputs:\n      has-rules", 1)
		},
		"bot token in a sign step": func(s string) string {
			return strings.Replace(s, "  sign:\n", "  sign:\n    env:\n      GH_TOKEN: ${{ secrets.KNOWLEDGE_BOT_TOKEN }}\n", 1)
		},
		"bot token on a pr download step": func(s string) string {
			return strings.Replace(s, "          pattern: renewal-*\n", "          pattern: renewal-*\n          github-token: ${{ secrets.KNOWLEDGE_BOT_TOKEN }}\n", 1)
		},
		"bot token under another name": func(s string) string {
			return strings.Replace(s, "          PINNED_LOGIN: ${{ vars.KNOWLEDGE_BOT_LOGIN }}\n", "          PINNED_LOGIN: ${{ vars.KNOWLEDGE_BOT_LOGIN }}\n          OTHER: ${{ secrets.KNOWLEDGE_BOT_TOKEN }}\n", 1)
		},
		"step before the guard": func(s string) string {
			return strings.Replace(s, "      - name: Require the pinned bot account\n", "      - name: Early write\n        run: gh api -X POST repos/x/y/git/refs\n      - name: Require the pinned bot account\n", 1)
		},
		"prepare token widened": func(s string) string {
			return strings.Replace(s, "      pull-requests: read\n", "      pull-requests: write\n", 1)
		},
		"auto merge": func(s string) string {
			return s + "# gh pr merge\n"
		},
	}
	for name, mutate := range mutations {
		mutated := mutate(base)
		if mutated == base {
			t.Fatalf("%s: the mutation did not change the workflow (the test is stale)", name)
		}
		if len(renewalProblems(mutated)) == 0 {
			t.Errorf("%s: not reported", name)
		}
	}
}
