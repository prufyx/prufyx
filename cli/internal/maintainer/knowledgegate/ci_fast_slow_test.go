// SPDX-License-Identifier: AGPL-3.0-only

package knowledgegate

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

// The fast/slow split of ci.yml and the choice of runner. These tests read
// the workflow text; they fail closed on a workflow they cannot parse.

const (
	ciSlowIf = "github.event_name != 'pull_request' || vars.CI_FAST_PR != 'true'"
	// ciRunsOn is the only runs-on a job that may move off the hosted
	// runner carries: self-hosted labels only for events that cannot come
	// from a fork.
	ciRunsOn = "${{ (github.event_name == 'merge_group' || github.event_name == 'push' || github.event_name == 'schedule' || github.event_name == 'workflow_dispatch' || (github.event_name == 'pull_request' && github.event.pull_request.head.repo.full_name == github.repository)) && fromJSON(vars.CI_RUNNER_LABELS || '\"ubuntu-24.04\"') || 'ubuntu-24.04' }}"
	ciHosted = "ubuntu-24.04"
	// ciWatchdog is the hosted job that ends a run stuck behind an offline
	// self-hosted runner.
	ciWatchdog = "runner-watchdog"
)

// ciMovable are the only jobs allowed to read CI_RUNNER_LABELS.
var ciMovable = map[string]bool{
	"test-core": true, "test-knowledgegate": true, "test-synthetic-a": true, "test-synthetic-b": true,
	"test-synthetic-knowledgegate": true, "race": true, "race-knowledgegate": true, "staticcheck": true, "govulncheck": true,
}

// ciSlowJobs are the suites kept off the required pull request run.
var ciSlowJobs = []string{"test-synthetic-a", "test-synthetic-b", "test-synthetic-knowledgegate"}

type ciSplitJob struct {
	Name        string `yaml:"name"`
	If          string `yaml:"if"`
	RunsOn      any    `yaml:"runs-on"`
	Needs       any    `yaml:"needs"`
	Environment any    `yaml:"environment"`
	Permissions any    `yaml:"permissions"`
	Steps       []struct {
		Run string            `yaml:"run"`
		Env map[string]string `yaml:"env"`
	} `yaml:"steps"`
}

type ciSplitFile struct {
	On          map[string]any        `yaml:"on"`
	Permissions map[string]string     `yaml:"permissions"`
	Jobs        map[string]ciSplitJob `yaml:"jobs"`
}

func ciSplitProblems(raw []byte) []string {
	var wf ciSplitFile
	if err := yaml.Unmarshal(raw, &wf); err != nil {
		return []string{"ci.yml does not parse: " + err.Error()}
	}
	var problems []string
	if len(wf.Permissions) != 1 || wf.Permissions["contents"] != "read" {
		problems = append(problems, "workflow permissions must be exactly contents: read")
	}
	slow := map[string]bool{}
	for _, id := range ciSlowJobs {
		slow[id] = true
	}
	var ids []string
	for id := range wf.Jobs {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		job := wf.Jobs[id]
		runs, _ := job.RunsOn.(string)
		text, _ := yaml.Marshal(job)
		switch {
		case ciMovable[id]:
			if runs != ciRunsOn {
				problems = append(problems, "job "+id+" must use exactly the guarded CI_RUNNER_LABELS runs-on")
			}
			// A job that may run on a self-hosted runner never reaches a
			// secret, an environment, an OIDC token or a write permission.
			if secretRef.MatchString(string(text)) || job.Environment != nil || strings.Contains(string(text), "id-token") {
				problems = append(problems, "job "+id+" may run self-hosted but references secrets, an environment or id-token")
			}
			if job.Permissions != nil {
				problems = append(problems, "job "+id+" may run self-hosted and must not widen its permissions")
			}
		default:
			if runs != ciHosted {
				problems = append(problems, "job "+id+" must stay on "+ciHosted+" (hosted); only the test shards, race, staticcheck and govulncheck may move")
			}
		}
		if id != ciWatchdog && (strings.Contains(runs, "self-hosted") || strings.Contains(string(text), "self-hosted")) {
			problems = append(problems, "job "+id+" names a self-hosted label in the file: labels come only from CI_RUNNER_LABELS")
		}
		if slow[id] != (job.If == ciSlowIf) {
			problems = append(problems, "job "+id+": exactly the slow suites carry the CI_FAST_PR condition")
		}
		if !slow[id] && strings.Contains(job.If, "CI_FAST_PR") {
			problems = append(problems, "job "+id+" mentions CI_FAST_PR but is not a slow suite")
		}
	}
	// The fan-in lists the same jobs twice: the fast set must succeed, the
	// slow set may be skipped only in a fast pull request run.
	var fan *ciSplitJob
	for _, id := range ids {
		if j := wf.Jobs[id]; j.Name == ciFanInName {
			j := j
			fan = &j
		}
	}
	if fan == nil {
		return append(problems, "no fan-in job")
	}
	var needs []string
	switch n := fan.Needs.(type) {
	case []any:
		for _, v := range n {
			needs = append(needs, v.(string))
		}
	case string:
		needs = []string{n}
	}
	var fastEnv, slowEnv, mayEnv string
	for _, st := range fan.Steps {
		if v, ok := st.Env["FAST_RESULTS"]; ok {
			fastEnv, slowEnv, mayEnv = v, st.Env["SLOW_RESULTS"], st.Env["SLOW_MAY_SKIP"]
		}
	}
	if mayEnv != "${{ github.event_name == 'pull_request' && vars.CI_FAST_PR == 'true' }}" {
		problems = append(problems, "SLOW_MAY_SKIP must be true only for a pull request with CI_FAST_PR=true")
	}
	listed := func(env string) []string {
		var out []string
		for _, m := range regexp.MustCompile(`needs\.([a-z-]+)\.result`).FindAllStringSubmatch(env, -1) {
			out = append(out, m[1])
		}
		sort.Strings(out)
		return out
	}
	var wantSlow, wantFast []string
	for _, n := range needs {
		if slow[n] {
			wantSlow = append(wantSlow, n)
		} else {
			wantFast = append(wantFast, n)
		}
	}
	sort.Strings(wantSlow)
	sort.Strings(wantFast)
	if strings.Join(listed(slowEnv), ",") != strings.Join(wantSlow, ",") || len(wantSlow) != len(ciSlowJobs) {
		problems = append(problems, "SLOW_RESULTS must list exactly the slow suites of the fan-in needs")
	}
	if strings.Join(listed(fastEnv), ",") != strings.Join(wantFast, ",") || len(wantFast) == 0 {
		problems = append(problems, "FAST_RESULTS must list exactly the other needs of the fan-in")
	}
	wd, ok := wf.Jobs[ciWatchdog]
	if !ok {
		return append(problems, "no "+ciWatchdog+" job: an offline self-hosted runner would stall the fan-in")
	}
	if wd.If != "vars.CI_RUNNER_LABELS != ''" {
		problems = append(problems, ciWatchdog+" must run exactly when CI_RUNNER_LABELS is set")
	}
	if wr, _ := wd.RunsOn.(string); wr != ciHosted {
		problems = append(problems, ciWatchdog+" must run on the hosted runner")
	}
	if p, ok := wd.Permissions.(map[string]any); !ok || len(p) != 1 || p["actions"] != "write" {
		problems = append(problems, ciWatchdog+" permissions must be exactly actions: write")
	}
	if secretRef.MatchString(string(mustYAML(wd))) || wd.Environment != nil {
		problems = append(problems, ciWatchdog+" must not reference secrets or an environment")
	}
	for _, n := range needs {
		if n == ciWatchdog {
			problems = append(problems, "the fan-in must not wait for "+ciWatchdog)
		}
	}
	return problems
}

func TestCIFastSlowSplit(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(repoRoot, ".github", "workflows", "ci.yml"))
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range ciSplitProblems(raw) {
		t.Error(p)
	}
	text := string(raw)
	broken := map[string]string{
		"guard dropped from a shard":   strings.Replace(text, ciRunsOn, "${{ fromJSON(vars.CI_RUNNER_LABELS || '\"ubuntu-24.04\"') }}", 1),
		"self-hosted literal":          strings.Replace(text, ciRunsOn, "[self-hosted, pfspot]", 1),
		"secret scan moved":            strings.Replace(text, "  gitleaks:\n    name: Secret scan (gitleaks)\n    runs-on: ubuntu-24.04", "  gitleaks:\n    name: Secret scan (gitleaks)\n    runs-on: "+ciRunsOn, 1),
		"fan-in moved":                 strings.Replace(text, "    name: Build, vet, test\n    runs-on: ubuntu-24.04", "    name: Build, vet, test\n    runs-on: "+ciRunsOn, 1),
		"slow suite without condition": strings.Replace(text, "    timeout-minutes: 75\n    if: "+ciSlowIf+"\n", "    timeout-minutes: 75\n", 1),
		"fast job made slow":           strings.Replace(text, "  test-core:\n", "  test-core:\n    if: "+ciSlowIf+"\n", 1),
		"slow suite hidden from slow":  strings.Replace(text, "SLOW_RESULTS: ${{ needs.test-synthetic-a.result }} ", "SLOW_RESULTS: ", 1),
		"fast job hidden from fast":    strings.Replace(text, "FAST_RESULTS: ${{ needs.lint-build.result }} ", "FAST_RESULTS: ", 1),
		"skip allowed everywhere":      strings.Replace(text, "SLOW_MAY_SKIP: ${{ github.event_name == 'pull_request' && vars.CI_FAST_PR == 'true' }}", "SLOW_MAY_SKIP: ${{ vars.CI_FAST_PR == 'true' }}", 1),
		"shard reads a secret":         strings.Replace(text, "          GROUP: ${{ matrix.group }}\n", "          GROUP: ${{ matrix.group }}\n          TOKEN: ${{ secrets.X }}\n", 1),
		"shard gets an environment":    strings.Replace(text, "  test-core:\n", "  test-core:\n    environment: release\n", 1),
		"shard widens its permissions": strings.Replace(text, "  test-core:\n", "  test-core:\n    permissions:\n      contents: write\n", 1),
		"watchdog dropped":             strings.Replace(text, "  runner-watchdog:\n", "  runner-watchdog-x:\n", 1),
		"watchdog always on":           strings.Replace(text, "    if: vars.CI_RUNNER_LABELS != ''\n", "", 1),
		"watchdog broader permissions": strings.Replace(text, "    permissions:\n      actions: write\n", "    permissions:\n      actions: write\n      contents: write\n", 1),
		"watchdog on a self-hosted":    strings.Replace(text, "    name: Runner watchdog\n    if: vars.CI_RUNNER_LABELS != ''\n    runs-on: ubuntu-24.04", "    name: Runner watchdog\n    if: vars.CI_RUNNER_LABELS != ''\n    runs-on: "+ciRunsOn, 1),
		"workflow permissions widened": strings.Replace(text, "permissions:\n  contents: read\n", "permissions:\n  contents: write\n", 1),
	}
	for name, mutated := range broken {
		if mutated == text {
			t.Errorf("%s: the mutation changed nothing", name)
			continue
		}
		if len(ciSplitProblems([]byte(mutated))) == 0 {
			t.Errorf("%s: accepted", name)
		}
	}
}

// Nothing but ci.yml may name the runner variable or a self-hosted label:
// signing, release, publish, renewal and gate workflows stay hosted.
func TestOnlyCIReadsRunnerLabels(t *testing.T) {
	dir := filepath.Join(repoRoot, ".github", "workflows")
	files, err := filepath.Glob(filepath.Join(dir, "*.yml"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no workflows: %v", err)
	}
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if filepath.Base(f) == "ci.yml" {
			continue
		}
		s := yamlComment.ReplaceAllString(string(raw), "")
		if strings.Contains(s, "CI_RUNNER_LABELS") || strings.Contains(s, "self-hosted") {
			t.Errorf("%s names a self-hosted label or CI_RUNNER_LABELS; only ci.yml may", filepath.Base(f))
		}
	}
}

// ciFanInScript returns the run script of the fan-in check step.
func ciFanInScript(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(repoRoot, ".github", "workflows", "ci.yml"))
	if err != nil {
		t.Fatal(err)
	}
	var wf ciSplitFile
	if err := yaml.Unmarshal(raw, &wf); err != nil {
		t.Fatal(err)
	}
	for _, j := range wf.Jobs {
		if j.Name == ciFanInName {
			for _, st := range j.Steps {
				if _, ok := st.Env["FAST_RESULTS"]; ok {
					return st.Run
				}
			}
		}
	}
	t.Fatal("no fan-in step")
	return ""
}

// The fan-in script itself, run with the results GitHub would hand it.
func TestCIFanInDecisions(t *testing.T) {
	script := ciFanInScript(t)
	const ok, sk, fl = "success", "skipped", "failure"
	join := func(r ...string) string { return strings.Join(r, " ") }
	cases := []struct {
		name            string
		fast, slow      []string
		mayskip, wantOK bool
	}{
		{"queue: everything succeeded", []string{ok, ok, ok}, []string{ok, ok, ok}, false, true},
		{"queue: a slow suite was skipped", []string{ok, ok, ok}, []string{ok, sk, ok}, false, false},
		{"queue: a slow suite failed", []string{ok, ok, ok}, []string{ok, fl, ok}, false, false},
		{"queue: a fast job was skipped", []string{ok, sk, ok}, []string{ok, ok, ok}, false, false},
		{"queue: a fast job failed", []string{ok, ok, fl}, []string{ok, ok, ok}, false, false},
		{"fast pull request: slow skipped", []string{ok, ok, ok}, []string{sk, sk, sk}, true, true},
		{"fast pull request: slow succeeded", []string{ok, ok, ok}, []string{ok, ok, ok}, true, true},
		{"fast pull request: a fast job skipped", []string{ok, sk, ok}, []string{sk, sk, sk}, true, false},
		{"fast pull request: a fast job cancelled", []string{ok, "cancelled", ok}, []string{sk, sk, sk}, true, false},
		{"fast pull request: a slow suite failed", []string{ok, ok, ok}, []string{sk, fl, sk}, true, false},
		{"fast pull request: a slow suite cancelled", []string{ok, ok, ok}, []string{sk, "cancelled", sk}, true, false},
		{"pull request without the switch: slow skipped", []string{ok, ok, ok}, []string{sk, sk, sk}, false, false},
	}
	for _, c := range cases {
		all := append(append([]string{}, c.fast...), c.slow...)
		may := "false"
		if c.mayskip {
			may = "true"
		}
		cmd := exec.Command("bash", "-c", script)
		cmd.Env = append(os.Environ(), "RESULTS="+join(all...), "FAST_RESULTS="+join(c.fast...), "SLOW_RESULTS="+join(c.slow...), "SLOW_MAY_SKIP="+may)
		out, err := cmd.CombinedOutput()
		if (err == nil) != c.wantOK {
			t.Errorf("%s: ok=%v, want %v\n%s", c.name, err == nil, c.wantOK, out)
		}
	}
	// No results at all is a failure.
	cmd := exec.Command("bash", "-c", script)
	cmd.Env = append(os.Environ(), "RESULTS=", "FAST_RESULTS=", "SLOW_RESULTS=", "SLOW_MAY_SKIP=true")
	if err := cmd.Run(); err == nil {
		t.Error("empty results accepted")
	}
}

// The race plan treats a queue entry like a pull request (affected packages
// only) and falls back to every package, never to fewer, when the base of
// the group cannot be read.
func TestCIRacePlanQueueEntries(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(repoRoot, ".github", "workflows", "ci.yml"))
	if err != nil {
		t.Fatal(err)
	}
	s := string(raw)
	for _, want := range []string{
		`MERGE_GROUP_BASE_SHA: ${{ github.event.merge_group.base_sha }}`,
		`[ "${EVENT_NAME}" = "pull_request" ] || [ "${EVENT_NAME}" = "merge_group" ]`,
		`[[ "${MERGE_GROUP_BASE_SHA}" =~ ^[0-9a-f]{40}$ ]]`,
		`changed=".github/unresolved"`,
	} {
		if !strings.Contains(s, want) {
			t.Errorf("race plan lacks %q", want)
		}
	}
}

// The race run of knowledgegate is sharded, and the job name the nightly-fix
// check matches by name stays reported: by a result job that is red unless
// every shard succeeded (its plan also runs the shards for a change to the
// workflow itself, so the fixing pull request carries a green result).
func TestCIRaceKnowledgegateResult(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(repoRoot, ".github", "workflows", "ci.yml"))
	if err != nil {
		t.Fatal(err)
	}
	var wf ciWorkflowFile
	if err := yaml.Unmarshal(raw, &wf); err != nil {
		t.Fatal(err)
	}
	res, ok := wf.Jobs["race-knowledgegate-result"]
	if !ok {
		t.Fatal("job race-knowledgegate-result is missing")
	}
	if res.Name != "Race detector (./internal/maintainer/knowledgegate/)" {
		t.Errorf("result job name %q is not the stable nightly name", res.Name)
	}
	text, _ := yaml.Marshal(res)
	for _, want := range []string{"race-knowledgegate", "always()", `!= "success"`, "exit 1"} {
		if !strings.Contains(string(text), want) {
			t.Errorf("result job lacks %q", want)
		}
	}
	s := string(raw)
	for _, want := range []string{
		`[ "${EVENT_NAME}" = "workflow_dispatch" ]`,
		`scripts/ci-test-shard\.sh`,
		`knowledgegate=true`,
	} {
		if !strings.Contains(s, want) {
			t.Errorf("race plan lacks %q", want)
		}
	}
	if strings.Contains(s, `timeout_minutes: 90, go_timeout: "85m"}]`) {
		t.Error("the single-process knowledgegate race entry is back")
	}
}

// The catch-all split of test-core: part i of n takes package numbers
// i, i+n, ...; together the parts are the whole list, each package once.
func TestCIRestPartsPartition(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(repoRoot, ".github", "workflows", "ci.yml"))
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`awk -v n="\$\{REST_TOTAL\}" -v i="\$\{REST_INDEX\}" '([^']+)'`).FindStringSubmatch(string(raw))
	if m == nil {
		t.Fatal("no catch-all split in ci.yml")
	}
	pkgs := "a\nb\nc\nd\ne\nf\ng\n"
	seen := map[string]int{}
	for _, idx := range []string{"1", "2", "3"} {
		cmd := exec.Command("awk", "-v", "n=3", "-v", "i="+idx, m[1])
		cmd.Stdin = strings.NewReader(pkgs)
		out, err := cmd.Output()
		if err != nil {
			t.Fatal(err)
		}
		for _, p := range strings.Fields(string(out)) {
			seen[p]++
		}
	}
	if len(seen) != 7 {
		t.Fatalf("parts cover %d of 7 packages", len(seen))
	}
	for p, n := range seen {
		if n != 1 {
			t.Errorf("package %s in %d parts", p, n)
		}
	}
}

func mustYAML(v any) []byte {
	b, err := yaml.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}

// ciWatchdogScript returns the run script of the runner watchdog.
func ciWatchdogScript(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(repoRoot, ".github", "workflows", "ci.yml"))
	if err != nil {
		t.Fatal(err)
	}
	var wf ciSplitFile
	if err := yaml.Unmarshal(raw, &wf); err != nil {
		t.Fatal(err)
	}
	for _, st := range wf.Jobs[ciWatchdog].Steps {
		if st.Run != "" {
			return st.Run
		}
	}
	t.Fatal("no watchdog script")
	return ""
}

// runWatchdog runs the watchdog script against a fake gh whose job list is
// jobsOut (one JSON object per line) and whose api call may fail; it reports
// the exit code and whether the run was cancelled.
func runWatchdog(t *testing.T, jobsOut string, apiFails bool, maxMinutes string) (code int, cancelled bool) {
	t.Helper()
	for _, tool := range []string{"jq", "bash"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s is not installed", tool)
		}
	}
	dir := t.TempDir()
	cancelFile := filepath.Join(dir, "cancelled")
	fail := "0"
	if apiFails {
		fail = "1"
	}
	gh := "#!/bin/bash\nif [ \"$1\" = api ]; then [ \"" + fail + "\" = 0 ] || exit 1; cat \"" + filepath.Join(dir, "jobs") + "\"; exit 0; fi\nif [ \"$1 $2\" = \"run cancel\" ]; then : > \"" + cancelFile + "\"; exit 0; fi\nexit 9\n"
	for name, body := range map[string]string{"gh": gh, "sleep": "#!/bin/bash\nkill -TERM $PPID\n"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "jobs"), []byte(jobsOut), 0o644); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("bash", "-c", ciWatchdogScript(t))
	cmd.Env = append(os.Environ(), "PATH="+dir+":"+os.Getenv("PATH"), "REPO=o/r", "RUN_ID=1", "MAX_QUEUE_MINUTES="+maxMinutes)
	err := cmd.Run()
	code = 0
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	} else if err != nil {
		t.Fatal(err)
	}
	_, statErr := os.Stat(cancelFile)
	return code, statErr == nil
}

func TestCIRunnerWatchdog(t *testing.T) {
	old := time.Now().Add(-45 * time.Minute).UTC().Format("2006-01-02T15:04:05Z")
	recent := time.Now().Add(-2 * time.Minute).UTC().Format("2006-01-02T15:04:05Z")
	job := func(name, status, label, at string) string {
		return `{"name":"` + name + `","status":"` + status + `","labels":["` + label + `"],"created_at":"` + at + `"}` + "\n"
	}
	done := job("Runner watchdog", "in_progress", "ubuntu-24.04", old) + job("Test (core-evidence)", "completed", "self-hosted", old)
	cases := []struct {
		name       string
		jobs       string
		apiFails   bool
		max        string
		wantCancel bool
		wantCode   int
	}{
		{"self-hosted job queued too long", done + job("Test (core-commands)", "queued", "self-hosted", old), false, "30", true, 1},
		{"stale limit read from the variable", done + job("Test (core-commands)", "queued", "self-hosted", recent), false, "1", true, 1},
		{"junk limit falls back to 30", done + job("Test (core-commands)", "queued", "self-hosted", old), false, "abc", true, 1},
		{"job list unreadable", "", true, "30", true, 1},
		{"job list not json", "not json\n", false, "30", true, 1},
		// Nothing is stale: the script waits (the fake sleep ends it, exit -1).
		{"recently queued self-hosted job", done + job("Test (core-commands)", "queued", "self-hosted", recent), false, "30", false, -1},
		{"hosted job queued long is left to GitHub", done + job("Staticcheck", "queued", "ubuntu-24.04", old), false, "30", false, -1},
		{"everything finished", done, false, "30", false, 0},
	}
	for _, c := range cases {
		code, cancelled := runWatchdog(t, c.jobs, c.apiFails, c.max)
		if cancelled != c.wantCancel || code != c.wantCode {
			t.Errorf("%s: exit %d cancelled=%v, want exit %d cancelled=%v", c.name, code, cancelled, c.wantCode, c.wantCancel)
		}
	}
}
