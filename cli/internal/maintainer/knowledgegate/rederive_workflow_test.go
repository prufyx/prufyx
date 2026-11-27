// SPDX-License-Identifier: AGPL-3.0-only

package knowledgegate

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

var rederiveWorkflowPath = filepath.Join(repoRoot, ".github", "workflows", "evidence-rederive.yml")

var rederivePinned = regexp.MustCompile(`^[A-Za-z0-9._/-]+@[0-9a-f]{40}$`)

type rederiveStep struct {
	Name string            `yaml:"name"`
	Uses string            `yaml:"uses"`
	Run  string            `yaml:"run"`
	With map[string]any    `yaml:"with"`
	Env  map[string]string `yaml:"env"`
}

type rederiveJob struct {
	Needs       any               `yaml:"needs"`
	Permissions map[string]string `yaml:"permissions"`
	If          string            `yaml:"if"`
	RunsOn      string            `yaml:"runs-on"`
	Environment string            `yaml:"environment"`
	Env         map[string]string `yaml:"env"`
	Strategy    struct {
		Matrix map[string][]string `yaml:"matrix"`
	} `yaml:"strategy"`
	Steps []rederiveStep `yaml:"steps"`
}

type rederiveWorkflow struct {
	On          map[string]any         `yaml:"on"`
	Permissions map[string]string      `yaml:"permissions"`
	Env         map[string]string      `yaml:"env"`
	Jobs        map[string]rederiveJob `yaml:"jobs"`
}

// rederiveProblems returns every way the re-derivation workflow text breaks
// the properties its safety rests on. An empty result means it holds them.
func rederiveProblems(raw string) []string {
	var out []string
	bad := func(msg string, detail ...string) {
		out = append(out, strings.TrimSpace(msg+" "+strings.Join(detail, " ")))
	}
	var wf rederiveWorkflow
	if err := yaml.Unmarshal([]byte(raw), &wf); err != nil {
		return []string{"unparseable: " + err.Error()}
	}
	for trigger, v := range wf.On {
		switch trigger {
		case "schedule":
		case "workflow_dispatch":
			if v != nil {
				bad("a dispatch may not take inputs")
			}
		default:
			bad("unexpected trigger", trigger)
		}
	}
	if _, ok := wf.On["schedule"]; !ok {
		bad("no schedule trigger")
	}
	if wf.Permissions == nil || len(wf.Permissions) != 0 {
		bad("top-level permissions must be empty")
	}
	if len(wf.Jobs) != 4 {
		bad("the jobs must be exactly plan, derive, assemble and pr")
	}
	code := yamlComment.ReplaceAllString(raw, "")
	for _, forbidden := range []string{"actions/cache", "restore-keys", "pr merge", "/merge", "auto-merge", "AutoMerge", "self-hosted", "continue-on-error"} {
		if strings.Contains(code, forbidden) {
			bad("forbidden text", forbidden)
		}
	}
	if n := len(secretRef.FindAllString(code, -1)); n != 2 || strings.Count(code, "secrets.KNOWLEDGE_BOT_TOKEN }}") != 2 {
		bad("the only secret is the bot token, twice, in the pr job")
	}
	for name, j := range wf.Jobs {
		if j.RunsOn != "ubuntu-24.04" {
			bad("job is not on a hosted runner", name)
		}
		if !strings.Contains(j.If, "github.ref == 'refs/heads/main'") {
			bad("job does not require main", name)
		}
		for _, s := range j.Steps {
			if s.Uses != "" && !rederivePinned.MatchString(s.Uses) {
				bad("action not pinned by commit", s.Uses)
			}
			if strings.Contains(s.Run, "${{") {
				bad("expression inside a run script", name, s.Name)
			}
			if strings.HasPrefix(s.Uses, "actions/setup-go@") && s.With["cache"] != false {
				bad("shared cache", name)
			}
			if strings.HasPrefix(s.Uses, "actions/checkout@") && (s.With["persist-credentials"] != false || s.With["ref"] != "${{ github.sha }}") {
				bad("checkout must use the triggering commit without credentials", name)
			}
		}
	}
	for _, name := range []string{"plan", "derive", "assemble"} {
		j, ok := wf.Jobs[name]
		if !ok {
			bad("missing job", name)
			continue
		}
		if j.Environment != "" {
			bad("job names an environment", name)
		}
		if len(j.Permissions) == 0 || j.Permissions["contents"] != "read" {
			bad("job must hold contents: read", name)
		}
		for scope, level := range j.Permissions {
			if level != "read" || scope != "contents" && !(name == "plan" && scope == "pull-requests") {
				bad("job holds more than it needs", name, scope, level)
			}
		}
		text, err := yaml.Marshal(j)
		if err != nil || secretRef.MatchString(string(text)) {
			bad("job names a secret", name)
		}
	}
	derive := wf.Jobs["derive"]
	if sides := derive.Strategy.Matrix["side"]; len(sides) != 2 || sides[0] == sides[1] {
		bad("there must be two derivations")
	}
	run := func(j rederiveJob) string {
		var b strings.Builder
		for _, s := range j.Steps {
			b.WriteString(s.Run)
		}
		return b.String()
	}
	for _, need := range []string{`--derived-at "${at}"`, `--lease-days "${lease}"`, "factory mirror"} {
		if !strings.Contains(run(derive), need) {
			bad("derive must mirror and derive at the planned time and lease", need)
		}
	}
	for _, need := range []string{"renewal compare", "renewal assemble", "--origin", `--max "${CAP}"`, "git status --porcelain", "ALLOWED_PATHS"} {
		if !strings.Contains(run(wf.Jobs["assemble"]), need) {
			bad("assemble must compare, keep only renewals and bound the files", need)
		}
	}
	pr := wf.Jobs["pr"]
	if pr.Environment != "renewal-pr" {
		bad("pr must run in the renewal-pr environment")
	}
	if pr.Permissions == nil || len(pr.Permissions) != 0 {
		bad("pr must hold no token permissions")
	}
	if !strings.Contains(pr.If, "vars.REDERIVE_PR_ENABLED == 'true'") || !strings.Contains(pr.If, "needs.assemble.result == 'success'") {
		bad("pr must be switched on and need the assembled bundle")
	}
	for _, s := range pr.Steps {
		if s.Uses != "" && !strings.HasPrefix(s.Uses, "actions/download-artifact@") {
			bad("pr runs an action other than the download", s.Uses)
		}
	}
	for _, forbidden := range []string{"go build", "go run", "go test", "prufyx-maintainer", "git clone", "git checkout", ".sh\n", "curl "} {
		if strings.Contains(run(pr), forbidden) {
			bad("pr runs repository code", forbidden)
		}
	}
	return out
}

func readRederiveWorkflow(t *testing.T) (string, rederiveWorkflow) {
	t.Helper()
	raw, err := os.ReadFile(rederiveWorkflowPath)
	if err != nil {
		t.Fatal(err)
	}
	var wf rederiveWorkflow
	if err := yaml.Unmarshal(raw, &wf); err != nil {
		t.Fatal(err)
	}
	return string(raw), wf
}

func TestRederiveWorkflowHoldsItsProperties(t *testing.T) {
	t.Parallel()
	raw, _ := readRederiveWorkflow(t)
	if got := rederiveProblems(raw); len(got) != 0 {
		t.Fatalf("problems:\n%s", strings.Join(got, "\n"))
	}
}

func TestRederiveWorkflowMutationsAreDetected(t *testing.T) {
	t.Parallel()
	raw, _ := readRederiveWorkflow(t)
	for name, m := range map[string]struct{ old, new, want string }{
		"pull request trigger": {"  workflow_dispatch:\n", "  workflow_dispatch:\n  pull_request:\n", "unexpected trigger"},
		"dispatch input":       {"  workflow_dispatch:\n", "  workflow_dispatch:\n    inputs:\n      at:\n        type: string\n", "may not take inputs"},
		"top permissions":      {"permissions: {}\n\nconcurrency", "permissions: write-all\n\nconcurrency", ""},
		"write in derive":      {"    permissions:\n      contents: read\n    env:\n      PLAN: ${{ needs.plan.outputs.plan }}\n    steps:", "    permissions:\n      contents: write\n    env:\n      PLAN: ${{ needs.plan.outputs.plan }}\n    steps:", "holds more than it needs"},
		"secret in derive":     {"          GITHUB_TOKEN: ${{ github.token }}\n", "          GITHUB_TOKEN: ${{ secrets.KNOWLEDGE_BOT_TOKEN }}\n", "names a secret"},
		"shared cache":         {"          cache: false", "          cache: true", "shared cache"},
		"cache action":         {"      - name: Upload the derivation\n", "      - uses: actions/cache@0000000000000000000000000000000000000000\n      - name: Upload the derivation\n", "forbidden text actions/cache"},
		"one derivation":       {"        side: [a, b]", "        side: [a]", "two derivations"},
		"non-main":             {"    if: needs.plan.outputs.work == 'true' && github.ref == 'refs/heads/main'\n", "    if: needs.plan.outputs.work == 'true'\n", "does not require main"},
		"unpinned action":      {"actions/checkout@11d5960a326750d5838078e36cf38b85af677262", "actions/checkout@v4", "not pinned"},
		"other ref":            {"          ref: ${{ github.sha }}", "          ref: refs/pull/1/head", "triggering commit"},
		"pr always on":         {" && vars.REDERIVE_PR_ENABLED == 'true'", "", "switched on"},
		"pr other environment": {"    environment: renewal-pr", "    environment: renewal", "renewal-pr environment"},
		"pr token rights":      {"    environment: renewal-pr\n    permissions: {}", "    environment: renewal-pr\n    permissions:\n      contents: write", "no token permissions"},
		"merges":               {`          echo "opened ${url%% *}"`, `          gh pr merge "${url%% *}"`, "forbidden text pr merge"},
		"no compare":           {"renewal compare", "renewal digest", "assemble must compare"},
		"no origin":            {`--origin "${RUNNER_TEMP}/origin.txt"`, "", "assemble must compare"},
		"chosen time":          {`--derived-at "${at}"`, `--derived-at "${OTHER}"`, "planned time"},
	} {
		t.Run(name, func(t *testing.T) {
			if !strings.Contains(raw, m.old) {
				t.Fatalf("mutation anchor %q is gone", m.old)
			}
			got := rederiveProblems(strings.Replace(raw, m.old, m.new, 1))
			if len(got) == 0 || !strings.Contains(strings.Join(got, "\n"), m.want) {
				t.Fatalf("not detected, want %q, got %v", m.want, got)
			}
		})
	}
}

// The workflow that carried dates forward unattended, and its signing key
// environment, are gone: no workflow reaches them.
func TestNoWorkflowCarriesDatesForward(t *testing.T) {
	t.Parallel()
	dir := filepath.Join(repoRoot, ".github", "workflows")
	files, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		raw, err := os.ReadFile(filepath.Join(dir, f.Name()))
		if err != nil {
			t.Fatal(err)
		}
		code := yamlComment.ReplaceAllString(string(raw), "")
		for _, forbidden := range []string{"REATTEST_AUTOMATION_KEY", "environment: renewal\n", "--mode automated", "--role automation"} {
			if strings.Contains(code, forbidden) {
				t.Errorf("%s holds %q", f.Name(), forbidden)
			}
		}
	}
}

const rederiveGHStub = `#!/usr/bin/env bash
set -eu
echo "$*" >> "${STUB_LOG}"
case "$*" in
  "pr list"*) echo "${STUB_OPEN}" ;;
  "api repos/o/r/git/ref/heads/main"*) echo "${STUB_TIP}" ;;
  "api repos/o/r/git/ref/heads/factory/"*) [ "${STUB_BRANCH}" = "yes" ] ;;
  "api repos/o/r/git/commits/"*) echo tree0 ;;
  "api -X POST repos/o/r/git/blobs"*) cat >/dev/null; echo blob0 ;;
  "api -X POST repos/o/r/git/trees"*) cat >/dev/null; echo tree1 ;;
  "api -X POST repos/o/r/git/commits"*) cat > "${STUB_COMMIT}"; echo commit1 ;;
  "api -X POST repos/o/r/git/refs"*) echo ref ;;
  "api -X POST repos/o/r/pulls"*) echo "https://example.invalid/pr/1 ${STUB_AUTHOR}" ;;
  *) echo "unexpected gh call" >&2; exit 1 ;;
esac
`

type prRun struct {
	bundle string
	env    map[string]string
	// afterDigest changes the bundle after its digest was taken.
	afterDigest func(t *testing.T, bundle string)
}

// The pr job's own script, run against a stub of the API: it writes nothing
// unless every check holds.
func TestRederivePullRequestScriptRefuses(t *testing.T) {
	t.Parallel()
	_, wf := readRederiveWorkflow(t)
	var script string
	for _, s := range wf.Jobs["pr"].Steps {
		if s.Name == "Open the pull request" {
			script = s.Run
		}
	}
	if script == "" {
		t.Fatal("no pull request step")
	}
	for _, tool := range []string{"bash", "jq", "sha256sum", "base64"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Fatalf("%s is required: %v", tool, err)
		}
	}
	const pack = "files/cli/internal/cncfcheck/data/rules.json"
	sha := strings.Repeat("a", 40)
	origin := func(at string) string {
		return "Origin-Run: 77\nOrigin-Attempt: 1\nOrigin-Commit: " + sha + "\nOrigin-Workflow: " + sha +
			"\nOrigin-Derived-At: " + at + "\nOrigin-Records: 1 sha256:00\nOrigin-Extractor: crd.version-removal.x version=1.0.0 codeDigest=sha256:00 leaseDays=80 output=sha256:00\n"
	}
	stamp := func(d time.Duration) string { return time.Now().UTC().Add(d).Format("2006-01-02T15:04:05Z") }
	retime := func(r *prRun, t *testing.T, d time.Duration) {
		r.env["DERIVED_AT"] = stamp(d)
		writeFile(t, filepath.Join(r.bundle, "origin.txt"), []byte(origin(r.env["DERIVED_AT"])))
	}
	addFile := func(rel string) func(t *testing.T, r *prRun) {
		return func(t *testing.T, r *prRun) {
			writeFile(t, filepath.Join(r.bundle, filepath.FromSlash(rel)), []byte("x\n"))
		}
	}
	editOrigin := func(old, new string) func(t *testing.T, r *prRun) {
		return func(t *testing.T, r *prRun) {
			p := filepath.Join(r.bundle, "origin.txt")
			writeFile(t, p, []byte(strings.Replace(origin(r.env["DERIVED_AT"]), old, new, 1)))
		}
	}
	remove := func(rel string) func(t *testing.T, r *prRun) {
		return func(t *testing.T, r *prRun) {
			if err := os.Remove(filepath.Join(r.bundle, filepath.FromSlash(rel))); err != nil {
				t.Fatal(err)
			}
		}
	}
	set := func(k, v string) func(t *testing.T, r *prRun) {
		return func(t *testing.T, r *prRun) { r.env[k] = v }
	}
	cases := map[string]struct {
		edit func(t *testing.T, r *prRun)
		want string
		// writes is true when the refusal comes after the pull request call.
		writes bool
	}{
		"good": {func(t *testing.T, r *prRun) {}, "", true},
		"flipped byte": {func(t *testing.T, r *prRun) {
			r.afterDigest = func(t *testing.T, bundle string) { writeFile(t, filepath.Join(bundle, pack), []byte("{ }\n")) }
		}, "do not match the digest", false},
		"no digest":         {set("ASSEMBLED_SHA256_OVERRIDE", "none"), "is not a sha256", false},
		"trust file":        {addFile("files/cli/knowledge/trust/web-approval-keys.json"), "outside the allow list", false},
		"workflow file":     {addFile("files/.github/workflows/x.yml"), "outside the allow list", false},
		"gate code":         {addFile("files/cli/internal/maintainer/knowledgegate/gate.go"), "outside the allow list", false},
		"carry exception":   {addFile("files/cli/knowledge/carry-exceptions/cncf/x.json"), "outside the allow list", false},
		"nested golden":     {addFile("files/cli/internal/scanrun/testdata/a/b"), "outside the allow list", false},
		"file beside files": {addFile("extra.json"), "Unexpected file", false},
		"symlink": {func(t *testing.T, r *prRun) {
			if err := os.Symlink("/etc/hosts", filepath.Join(r.bundle, "files", "README.md")); err != nil {
				t.Fatal(err)
			}
		}, "not a file", false},
		"no pack":                  {func(t *testing.T, r *prRun) { remove(pack)(t, r); addFile("files/README.md")(t, r) }, "changes no pack", false},
		"no origin":                {remove("origin.txt"), "has no origin", false},
		"origin of other run":      {editOrigin("Origin-Run: 77", "Origin-Run: 770"), "does not name this run", false},
		"origin of other base":     {editOrigin("Origin-Commit: a", "Origin-Commit: b"), "does not name this run", false},
		"origin without workflow":  {editOrigin("Origin-Workflow: "+sha+"\n", ""), "does not name this run", false},
		"origin without extractor": {editOrigin("Origin-Extractor", "Origin-Records"), "incomplete", false},
		"origin with free text":    {editOrigin("Origin-Attempt: 1\n", "Origin-Attempt: 1\nMOVES decided +9\n"), "unexpected line", false},
		"derived 25 hours ago":     {func(t *testing.T, r *prRun) { retime(r, t, -25*time.Hour) }, "outside the last 24 hours", false},
		"future time":              {func(t *testing.T, r *prRun) { retime(r, t, time.Hour) }, "outside the last 24 hours", false},
		"second open pull request": {set("STUB_OPEN", "1"), "already open", false},
		"unreadable open count":    {set("STUB_OPEN", ""), "already open", false},
		"stale base":               {set("STUB_TIP", strings.Repeat("b", 40)), "main moved", false},
		"branch exists":            {set("STUB_BRANCH", "yes"), "exists already", false},
		"other author":             {set("STUB_AUTHOR", "someone"), "is not bot", true},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			r := &prRun{bundle: filepath.Join(dir, "in"), env: map[string]string{
				"ALLOWED_PATHS": wf.Env["ALLOWED_PATHS"], "RUNNER_TEMP": dir, "DERIVED_AT": stamp(-time.Hour), "BOT_LOGIN": "bot",
				"GITHUB_REPOSITORY": "o/r", "GITHUB_SHA": sha, "GITHUB_RUN_ID": "77", "WORKFLOW_SHA": sha,
				"STUB_LOG": filepath.Join(dir, "gh.log"), "STUB_COMMIT": filepath.Join(dir, "commit.json"),
				"STUB_OPEN": "0", "STUB_TIP": sha, "STUB_BRANCH": "no", "STUB_AUTHOR": "bot",
			}}
			writeFile(t, filepath.Join(r.bundle, pack), []byte("{}\n"))
			writeFile(t, filepath.Join(r.bundle, "origin.txt"), []byte(origin(r.env["DERIVED_AT"])))
			c.edit(t, r)
			sum := exec.Command("bash", "-c", `set -euo pipefail; find . -type f -print0 | LC_ALL=C sort -z | xargs -0 sha256sum | sha256sum | cut -d' ' -f1`)
			sum.Dir = r.bundle
			digest, err := sum.Output()
			if err != nil {
				t.Fatal(err)
			}
			r.env["ASSEMBLED_SHA256"] = strings.TrimSpace(string(digest))
			if v := r.env["ASSEMBLED_SHA256_OVERRIDE"]; v != "" {
				r.env["ASSEMBLED_SHA256"] = v
			}
			if r.afterDigest != nil {
				r.afterDigest(t, r.bundle)
			}
			bin := filepath.Join(dir, "bin")
			writeFile(t, filepath.Join(bin, "gh"), []byte(rederiveGHStub))
			if err := os.Chmod(filepath.Join(bin, "gh"), 0o755); err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command("bash", "-c", script)
			cmd.Env = []string{"PATH=" + bin + string(os.PathListSeparator) + os.Getenv("PATH")}
			for k, v := range r.env {
				cmd.Env = append(cmd.Env, k+"="+v)
			}
			output, err := cmd.CombinedOutput()
			log, _ := os.ReadFile(r.env["STUB_LOG"])
			if (err == nil) != (c.want == "") || !strings.Contains(string(output), c.want) {
				t.Fatalf("err %v, want %q:\n%s", err, c.want, output)
			}
			if wrote := strings.Contains(string(log), "-X POST"); wrote != c.writes {
				t.Fatalf("wrote=%v want %v:\n%s", wrote, c.writes, log)
			}
			if name == "good" {
				commit, err := os.ReadFile(r.env["STUB_COMMIT"])
				if err != nil || !strings.Contains(string(commit), "Origin-Run: 77") || !strings.Contains(string(commit), "Origin-Extractor: ") {
					t.Fatalf("the commit message carries no origin: %s %v", commit, err)
				}
			}
		})
	}
}

// The path allow list admits the pack and generated files and nothing that
// decides what is admitted.
func TestRederiveAllowList(t *testing.T) {
	t.Parallel()
	_, wf := readRederiveWorkflow(t)
	re := regexp.MustCompile(wf.Env["ALLOWED_PATHS"])
	for _, p := range []string{"cli/internal/cncfcheck/data/rules.json", "cli/internal/cncfcheck/data/corpus-attestation.json", "cli/docs/generated/coverage-counts.json", "README.md", "cli/internal/scanrun/testdata/blocked-templated.json"} {
		if !re.MatchString(p) {
			t.Errorf("%s refused", p)
		}
	}
	l := DefaultLayout()
	for _, p := range []string{l.TrustRootPath, l.ApprovalKeysPath, l.PausePath, l.ApprovalDir + "/cncf/x.json", l.ReattestDir + "/cncf/chain/0001.statement.json",
		CarryExceptionPath("cncf", "x"), "cli/internal/projectcheck/data/rules.json", "cli/internal/cncfcheck/data/landscape-projects.json",
		"cli/internal/scanrun/testdata/../scan.go", "cli/go.mod", "scripts/readme-coverage.sh", ".github/workflows/evidence-rederive.yml"} {
		if re.MatchString(p) {
			t.Errorf("%s admitted", p)
		}
	}
}
