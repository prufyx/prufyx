// SPDX-License-Identifier: AGPL-3.0-only

package releaseworkflow

import (
	"encoding/json"
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

type refreshJob struct {
	If          string            `yaml:"if"`
	Needs       any               `yaml:"needs"`
	Environment any               `yaml:"environment"`
	Concurrency any               `yaml:"concurrency"`
	Permissions map[string]string `yaml:"permissions"`
	Steps       []workflowStep    `yaml:"steps"`
}

type refreshWorkflow struct {
	On          map[string]any        `yaml:"on"`
	Permissions map[string]string     `yaml:"permissions"`
	Concurrency map[string]any        `yaml:"concurrency"`
	Jobs        map[string]refreshJob `yaml:"jobs"`
}

func loadRefreshWorkflow(t *testing.T) (refreshWorkflow, string) {
	t.Helper()
	repo := repoRoot(t)
	raw, err := os.ReadFile(filepath.Join(repo, ".github", "workflows", "knowledge-refresh.yml"))
	if err != nil {
		t.Fatal(err)
	}
	var wf refreshWorkflow
	if err := yaml.Unmarshal(raw, &wf); err != nil {
		t.Fatal(err)
	}
	return wf, string(raw)
}

// The refresh workflow signs with the timestamp key only: it must never name
// another key, never use pull request code and keep the key in one step.
func TestKnowledgeRefreshWorkflowIsHardened(t *testing.T) {
	wf, raw := loadRefreshWorkflow(t)
	if wf.Permissions == nil || len(wf.Permissions) != 0 {
		t.Errorf("top-level permissions = %v, want {}", wf.Permissions)
	}
	if len(wf.On) != 2 || wf.On["schedule"] == nil || wf.On["workflow_dispatch"] == nil {
		t.Errorf("triggers = %v, want schedule and workflow_dispatch only", wf.On)
	}
	if !strings.Contains(raw, "default: true") {
		t.Error("dry_run must default to true")
	}
	if wf.Concurrency["group"] != "knowledge-refresh" || wf.Concurrency["cancel-in-progress"] != false {
		t.Errorf("concurrency = %v", wf.Concurrency)
	}
	for _, banned := range []string{"KNOWLEDGE_TARGETS", "KNOWLEDGE_SNAPSHOT", "--targets-key", "--snapshot-key", "knowledge-release", "pull_request", "secrets.GITHUB_TOKEN", "prepare-targets", "prepare-snapshot", "finalize-role", "knowledge-publish release"} {
		if strings.Contains(raw, banned) {
			t.Errorf("the refresh workflow must not contain %q", banned)
		}
	}
	// Secrets are referenced in exactly one place: the signing step of the
	// refresh job, and only the timestamp key and its passphrase.
	secretRef := regexp.MustCompile(`secrets\.[A-Za-z0-9_]+`)
	var got []string
	for _, job := range wf.Jobs {
		for _, st := range job.Steps {
			for _, v := range st.Env {
				got = append(got, secretRef.FindAllString(v, -1)...)
			}
			got = append(got, secretRef.FindAllString(st.Run, -1)...)
		}
	}
	sort.Strings(got)
	if len(got) != 2 || got[0] != "secrets.KNOWLEDGE_KEY_PASSPHRASE" || got[1] != "secrets.KNOWLEDGE_TIMESTAMP_KEY" {
		t.Errorf("secret references = %v", got)
	}
	for name, job := range wf.Jobs {
		if name != "refresh" && job.Environment != nil && name != "deploy" {
			t.Errorf("job %s must not use an environment", name)
		}
		for _, st := range job.Steps {
			if strings.Contains(st.Run, "${{") {
				t.Errorf("job %s step %q: run must not interpolate expressions (use env)", name, st.Name)
			}
			for k, v := range st.Env {
				if strings.Contains(v, "secrets.") && (name != "refresh" || st.Name != "Sign the refresh") {
					t.Errorf("job %s step %q: secret %s outside the signing step", name, st.Name, k)
				}
			}
			if strings.Contains(st.Run, "set -x") || strings.Contains(st.Run, "echo \"${TIMESTAMP_KEY}\"") || strings.Contains(st.Run, "echo \"${PASSPHRASE}\"") {
				t.Errorf("job %s step %q may echo a secret", name, st.Name)
			}
			if strings.HasPrefix(st.Uses, "actions/checkout@") {
				if v, ok := st.With["persist-credentials"].(bool); !ok || v {
					t.Errorf("job %s: checkout must set persist-credentials: false", name)
				}
			}
			if strings.HasPrefix(st.Uses, "actions/setup-go@") {
				if v, ok := st.With["cache"].(bool); !ok || v {
					t.Errorf("job %s: setup-go must set cache: false", name)
				}
			}
			if st.Uses != "" && !regexp.MustCompile(`^[A-Za-z0-9._-]+/[A-Za-z0-9._/-]+@[0-9a-f]{40}$`).MatchString(st.Uses) {
				t.Errorf("action %q is not pinned by a 40-hex commit SHA", st.Uses)
			}
		}
	}
	for _, name := range []string{"decide", "refresh", "deploy", "alarm"} {
		if _, ok := wf.Jobs[name]; !ok {
			t.Fatalf("missing job %s", name)
		}
	}
	// Per-job permissions.
	want := map[string]map[string]string{
		"decide":  {"contents": "read", "actions": "read"},
		"refresh": {"contents": "read"},
		"deploy":  {"pages": "write", "id-token": "write", "contents": "read", "actions": "read"},
		"alarm":   {},
	}
	for name, p := range want {
		if !samePermissions(wf.Jobs[name].Permissions, p) {
			t.Errorf("job %s permissions = %v, want %v", name, wf.Jobs[name].Permissions, p)
		}
	}
	// Gates: main only and both switches, on the job that decides.
	for _, w := range []string{"refs/heads/main", "KNOWLEDGE_RELEASE_ENABLED", "KNOWLEDGE_REFRESH_ENABLED"} {
		if !strings.Contains(wf.Jobs["decide"].If, w) {
			t.Errorf("decide if %q lacks %s", wf.Jobs["decide"].If, w)
		}
	}
	// The refresh job: its own environment, run_attempt 1, main, not a dry run.
	r := wf.Jobs["refresh"]
	if r.Environment != "knowledge-refresh" {
		t.Errorf("refresh environment = %v", r.Environment)
	}
	for _, w := range []string{"github.run_attempt == 1", "refs/heads/main", "dry_run != 'true'", "action == 'refresh'"} {
		if !strings.Contains(r.If, w) {
			t.Errorf("refresh if %q lacks %s", r.If, w)
		}
	}
	// Deploy: Pages environment, the shared deploy mutex, no secret.
	d := wf.Jobs["deploy"]
	if m, ok := d.Concurrency.(map[string]any); !ok || m["group"] != "knowledge-deploy" || m["cancel-in-progress"] != false {
		t.Errorf("deploy concurrency = %v", d.Concurrency)
	}
	if !strings.Contains(raw, "knowledge-publish deploy-guard") || !strings.Contains(raw, "knowledge-publish refresh-timestamp") || !strings.Contains(raw, "knowledge-publish live-state") {
		t.Error("the workflow must use refresh-timestamp, live-state and deploy-guard")
	}
	// The refresh call must carry the live digest the decision verified.
	if !strings.Contains(raw, "knowledge-publish refresh-timestamp --profile cncf-projects \\\n            --live-package \"${live}\" --expect-live-package-digest \"${LIVE_DIGEST}\"") {
		t.Error("the refresh call must pass --expect-live-package-digest \"${LIVE_DIGEST}\"")
	}
	// Deploy runs only on the first attempt: a re-run of failed jobs must not redeploy.
	for _, w := range []string{"github.run_attempt == 1", "github.ref == 'refs/heads/main'", "needs.refresh.result == 'success'"} {
		if !strings.Contains(d.If, w) {
			t.Errorf("deploy if %q lacks %s", d.If, w)
		}
	}
	// Published interface (read by the content workflow): the artifact name and
	// the live digest source are defined in exactly one place each.
	if n := strings.Count(raw, "echo \"artifact_name=knowledge-refresh-${revision}-${tsver}-${hex}\""); n != 1 {
		t.Errorf("artifact name pattern defined %d times, want 1", n)
	}
	if n := strings.Count(raw, "echo \"live_digest=${digest}\""); n != 1 {
		t.Errorf("live digest source defined %d times, want 1", n)
	}
	if !strings.Contains(raw, "digest=\"$(jq -er '.packageDigest | select(test(\"^sha256:[0-9a-f]{64}$\"))' \"${state}/live.json\")\"") {
		t.Error("the live digest must come from the verified live-state packageDigest")
	}
	// The alarm job fails the run and holds nothing.
	var alarmRuns strings.Builder
	for _, st := range wf.Jobs["alarm"].Steps {
		alarmRuns.WriteString(st.Run)
	}
	if !strings.Contains(alarmRuns.String(), "exit 1") || !strings.Contains(wf.Jobs["alarm"].If, "always()") {
		t.Error("the alarm job must fail the run and run after the other jobs")
	}
}

type decideCase struct {
	name       string
	tsDays     float64 // live timestamp expires in
	contentDay float64 // live targets and snapshot expire in
	pending    []map[string]any
	threshold  string
	wantExit   int
	wantAction string
	wantAlarm  string
	badLive    bool
	badPending string
}

func TestKnowledgeRefreshDecide(t *testing.T) {
	repo := repoRoot(t)
	for _, tool := range []string{"bash", "jq"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skip(tool + " not available")
		}
	}
	if out, err := exec.Command("date", "-u", "-d", "@0", "+%s").CombinedOutput(); err != nil || strings.TrimSpace(string(out)) != "0" {
		t.Skip("GNU date required")
	}
	script := filepath.Join(repo, "scripts", "knowledge-refresh-decide.sh")
	now := time.Date(2026, 11, 8, 12, 0, 0, 0, time.UTC)
	iso := func(d time.Time) string { return d.Format("2006-01-02T15:04:05Z") }
	days := func(f float64) time.Time { return now.Add(time.Duration(f * 24 * float64(time.Hour))) }
	run := func(status string, ageHours float64) map[string]any {
		return map[string]any{"id": 11, "status": status, "created_at": iso(now.Add(-time.Duration(ageHours * float64(time.Hour))))}
	}
	cases := []decideCase{
		{name: "due, nothing pending", tsDays: 5, contentDay: 15, wantAction: "refresh"},
		{name: "not due", tsDays: 8, contentDay: 15, wantAction: "skip"},
		{name: "due exactly at the threshold is not due", tsDays: 7, contentDay: 15, wantAction: "skip"},
		{name: "custom threshold", tsDays: 8, contentDay: 15, threshold: "10", wantAction: "refresh"},
		{name: "content run waiting, timestamp has more than 3 days: refuses to run", tsDays: 5, contentDay: 15, pending: []map[string]any{run("waiting", 3)}, wantAction: "skip"},
		{name: "content run queued, timestamp has more than 3 days: refuses to run", tsDays: 5, contentDay: 15, pending: []map[string]any{run("queued", 1)}, wantAction: "skip"},
		{name: "content run waiting, timestamp under 3 days: refresh keeps the feed alive", tsDays: 2, contentDay: 15, pending: []map[string]any{run("waiting", 3)}, wantAction: "refresh"},
		{name: "waiting over 48 hours alarms", tsDays: 5, contentDay: 15, pending: []map[string]any{run("waiting", 49)}, wantAction: "skip", wantAlarm: "waited for approval for 49 hours"},
		{name: "waiting 47 hours does not alarm", tsDays: 5, contentDay: 15, pending: []map[string]any{run("waiting", 47)}, wantAction: "skip"},
		{name: "in progress for days is not an approval wait", tsDays: 5, contentDay: 15, pending: []map[string]any{run("in_progress", 100)}, wantAction: "skip"},
		{name: "targets under 5 days alarms", tsDays: 4, contentDay: 4.5, wantAction: "refresh", wantAlarm: "only a content release can renew them"},
		{name: "targets just over 5 days do not alarm", tsDays: 4, contentDay: 5.2, wantAction: "refresh"},
		{name: "both alarms", tsDays: 2, contentDay: 3, pending: []map[string]any{run("waiting", 60)}, wantAction: "refresh", wantAlarm: "; live targets or snapshot expire"},
		{name: "expired live timestamp fails closed", tsDays: -1, contentDay: 15, wantExit: 1},
		{name: "expired targets fails closed", tsDays: 5, contentDay: -1, wantExit: 1},
		{name: "unreadable live state fails closed", tsDays: 5, contentDay: 15, badLive: true, wantExit: 1},
		{name: "pending list not an array fails closed", tsDays: 5, contentDay: 15, badPending: `{"id":1}`, wantExit: 1},
		{name: "unreadable run time fails closed", tsDays: 5, contentDay: 15, pending: []map[string]any{{"id": 3, "status": "waiting", "created_at": "yesterday-ish"}}, wantExit: 1},
		{name: "threshold out of range fails closed", tsDays: 5, contentDay: 15, threshold: "14", wantExit: 1},
		{name: "threshold not a number fails closed", tsDays: 5, contentDay: 15, threshold: "7;x", wantExit: 1},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			livePath := filepath.Join(dir, "live.json")
			if c.badLive {
				_ = os.WriteFile(livePath, []byte(`{"packageDigest":"sha256:aa"}`), 0o600)
			} else {
				live := map[string]any{"packageDigest": "sha256:" + strings.Repeat("a", 64), "timestampExpires": iso(days(c.tsDays)), "targetsExpires": iso(days(c.contentDay)), "snapshotExpires": iso(days(c.contentDay))}
				raw, _ := json.Marshal(live)
				_ = os.WriteFile(livePath, raw, 0o600)
			}
			pendingPath := filepath.Join(dir, "pending.json")
			pending := c.badPending
			if pending == "" {
				raw, _ := json.Marshal(append([]map[string]any{}, c.pending...))
				pending = string(raw)
			}
			_ = os.WriteFile(pendingPath, []byte(pending), 0o600)
			outPath := filepath.Join(dir, "out")
			cmd := exec.Command("bash", script)
			cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "LIVE_STATE=" + livePath, "PENDING_RUNS=" + pendingPath, "GITHUB_OUTPUT=" + outPath, "NOW=" + strings.TrimSpace(itoa(now.Unix()))}
			if c.threshold != "" {
				cmd.Env = append(cmd.Env, "THRESHOLD_DAYS="+c.threshold)
			}
			out, err := cmd.CombinedOutput()
			code := 0
			if ee, ok := err.(*exec.ExitError); ok {
				code = ee.ExitCode()
			} else if err != nil {
				t.Fatal(err)
			}
			if code != c.wantExit {
				t.Fatalf("exit %d, want %d: %s", code, c.wantExit, out)
			}
			written, _ := os.ReadFile(outPath)
			if c.wantExit != 0 {
				if len(written) != 0 {
					t.Errorf("a failed decision wrote outputs: %s", written)
				}
				return
			}
			o := string(written)
			if !strings.Contains(o, "action="+c.wantAction+"\n") {
				t.Errorf("outputs %q lack action=%s", o, c.wantAction)
			}
			if c.wantAlarm == "" {
				if !strings.Contains(o, "alarm=false\n") {
					t.Errorf("unexpected alarm: %s", o)
				}
			} else if !strings.Contains(o, "alarm=true\n") || !strings.Contains(o, c.wantAlarm) {
				t.Errorf("outputs %q lack alarm text %q", o, c.wantAlarm)
			}
		})
	}
}

func itoa(n int64) string {
	b, _ := json.Marshal(n)
	return string(b)
}

// extractShellFunc returns the shell function `name` from the workflow text:
// from its opening line to the first line that is just its closing brace at
// the same indent.
func extractShellFunc(t *testing.T, raw, name string) string {
	t.Helper()
	lines := strings.Split(raw, "\n")
	for i, l := range lines {
		if !strings.HasSuffix(l, name+"() {") && !strings.Contains(l, name+"() { #") {
			continue
		}
		indent := l[:len(l)-len(strings.TrimLeft(l, " "))]
		for j := i + 1; j < len(lines); j++ {
			if lines[j] == indent+"}" {
				return strings.TrimSpace(strings.Join(lines[i:j+1], "\n"))
			}
		}
	}
	t.Fatalf("function %s not found in the workflow", name)
	return ""
}

const fakeGH = `#!/usr/bin/env bash
# Fake gh api: serves FAKE_DIR/runs.json (newest first) and FAKE_DIR/artifacts-<id>.json
# in pages of per_page (default 30). Without --paginate only page 1 is returned.
set -euo pipefail
paginate=false; per=30; jqx=; path=
while [ $# -gt 0 ]; do
  case "$1" in
    api) ;;
    --paginate) paginate=true ;;
    -X) shift ;;
    -f) shift; case "$1" in per_page=*) per="${1#per_page=}" ;; esac ;;
    --jq) shift; jqx="$1" ;;
    *) path="$1" ;;
  esac
  shift
done
if [[ "$path" == */runs ]]; then key=workflow_runs; src="$FAKE_DIR/runs.json"
elif [[ "$path" =~ /actions/runs/([0-9]+)/artifacts$ ]]; then key=artifacts; src="$FAKE_DIR/artifacts-${BASH_REMATCH[1]}.json"
else echo "unexpected path $path" >&2; exit 2; fi
n="$(jq length "$src")"
pages=1; [ "$paginate" = true ] && pages=$(( (n + per - 1) / per ))
for ((p = 0; p < pages; p++)); do
  jq -r --argjson s $((p * per)) --argjson e $(((p + 1) * per)) "{${key}: .[\$s:\$e]} | ${jqx}" "$src"
done
`

// The refresh decision must find the newest successful content run that still
// has a live artifact even when more than one API page of content-free
// successful runs (the daily plan-only runs) sits in front of it, and must
// find an artifact that is not on the first page of a run's artifact list.
func TestKnowledgeRefreshNewestArtifactPaginates(t *testing.T) {
	for _, tool := range []string{"bash", "jq", "sed"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skip(tool + " not available")
		}
	}
	_, raw := loadRefreshWorkflow(t)
	fn := extractShellFunc(t, raw, "newest_artifact")
	hex := strings.Repeat("c", 64)
	want := "knowledge-77-" + hex
	const re = `^knowledge-[0-9]+-[0-9a-f]{64}$`

	writeJSON := func(dir, name string, v any) {
		b, _ := json.Marshal(v)
		if err := os.WriteFile(filepath.Join(dir, name), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	type art struct {
		Name    string `json:"name"`
		Expired bool   `json:"expired"`
	}
	type run struct {
		ID int `json:"id"`
	}
	setup := func(t *testing.T, empty, tail int, arts []art) (string, string) {
		dir := t.TempDir()
		var runs []run
		for i := 0; i < empty; i++ { // newest first: content-free runs
			id := 1000 - i
			runs = append(runs, run{id})
			writeJSON(dir, "artifacts-"+itoa(int64(id))+".json", []art{{"plan-only-" + itoa(int64(id)), false}})
		}
		runs = append(runs, run{500}) // the newest content run
		writeJSON(dir, "artifacts-500.json", arts)
		for i := 0; i < tail; i++ { // older content run with a different artifact
			id := 400 - i
			runs = append(runs, run{id})
			writeJSON(dir, "artifacts-"+itoa(int64(id))+".json", []art{{"knowledge-1-" + hex, false}})
		}
		writeJSON(dir, "runs.json", runs)
		bin := filepath.Join(dir, "bin")
		if err := os.Mkdir(bin, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(bin, "gh"), []byte(fakeGH), 0o700); err != nil {
			t.Fatal(err)
		}
		return dir, bin
	}
	call := func(t *testing.T, dir, bin string) string {
		script := "set -euo pipefail\nGH_REPO=o/r\n" + fn + "\nnewest_artifact knowledge-publish.yml '" + re + "'\n"
		cmd := exec.Command("bash", "-c", script)
		cmd.Env = []string{"PATH=" + bin + ":" + os.Getenv("PATH"), "FAKE_DIR=" + dir}
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("%v: %s", err, out)
		}
		return strings.TrimSpace(string(out))
	}

	t.Run("more than 30 content-free runs before the newest content run", func(t *testing.T) {
		dir, bin := setup(t, 65, 3, []art{{want, false}})
		if got := call(t, dir, bin); got != want {
			t.Fatalf("got %q, want %q (run listing not paginated?)", got, want)
		}
	})
	t.Run("artifact beyond the first page of a run's artifacts", func(t *testing.T) {
		var arts []art
		for i := 0; i < 40; i++ {
			arts = append(arts, art{"other-" + itoa(int64(i)), false})
		}
		arts = append(arts, art{want, false})
		dir, bin := setup(t, 0, 0, arts)
		if got := call(t, dir, bin); got != want {
			t.Fatalf("got %q, want %q (artifact listing not paginated?)", got, want)
		}
	})
	t.Run("expired artifact is skipped and the next run's live one is used", func(t *testing.T) {
		dir, bin := setup(t, 35, 2, []art{{want, true}})
		if got, w := call(t, dir, bin), "knowledge-1-"+hex; got != w {
			t.Fatalf("got %q, want %q", got, w)
		}
	})
	t.Run("no live artifact anywhere yields nothing", func(t *testing.T) {
		dir, bin := setup(t, 65, 0, []art{{want, true}})
		if got := call(t, dir, bin); got != "" {
			t.Fatalf("got %q, want empty", got)
		}
	})
}

// Every run and artifact listing in the refresh workflow must paginate; an
// unpaginated list silently truncates at one page.
func TestKnowledgeRefreshListingsPaginate(t *testing.T) {
	_, raw := loadRefreshWorkflow(t)
	fn := extractShellFunc(t, raw, "newest_artifact")
	if n := strings.Count(fn, "gh api --paginate -X GET"); n != 2 {
		t.Errorf("newest_artifact has %d paginated gh api calls, want 2 (runs and artifacts)", n)
	}
	if strings.Contains(fn, "per_page=30") || strings.Count(fn, "gh api ") != 2 {
		t.Error("newest_artifact must not use an unpaginated or 30-item listing")
	}
	// The pending-run listing is not paginated but is guarded by total_count.
	if !strings.Contains(raw, `-le 100 ] || fail "more than 100 ${status} runs`) {
		t.Error("the pending-run listing must fail closed beyond one page")
	}
}

func stepRun(t *testing.T, wf refreshWorkflow, job, name string) string {
	t.Helper()
	for _, st := range wf.Jobs[job].Steps {
		if st.Name == name {
			return st.Run
		}
	}
	t.Fatalf("step %q not found in job %s", name, job)
	return ""
}

// The deploy guard repeats the artifact cross-check of the decision: a content
// deploy that finished just before, with the CDN still serving the old package,
// must not be rolled back by a refresh of the old revision.
func TestKnowledgeRefreshDeployGuardCrossCheck(t *testing.T) {
	for _, tool := range []string{"bash", "jq", "sed"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skip(tool + " not available")
		}
	}
	wf, _ := loadRefreshWorkflow(t)
	run := stepRun(t, wf, "deploy", "Deploy guard")
	newest := extractShellFunc(t, run, "newest_artifact")
	cross := extractShellFunc(t, run, "artifact_crosscheck")
	hex := strings.Repeat("d", 64)

	type art struct {
		Name    string `json:"name"`
		Expired bool   `json:"expired"`
	}
	setup := func(t *testing.T, contentRev, refreshRev, refreshVer string) (string, string) {
		dir := t.TempDir()
		write := func(name string, v any) {
			b, _ := json.Marshal(v)
			if err := os.WriteFile(filepath.Join(dir, name), b, 0o600); err != nil {
				t.Fatal(err)
			}
		}
		// The fake serves one runs.json for both workflows: run 2 holds the
		// content artifact, run 1 the refresh artifact (if any).
		type r struct {
			ID int `json:"id"`
		}
		write("runs.json", []r{{2}, {1}})
		write("artifacts-2.json", []art{{"knowledge-" + contentRev + "-" + hex, false}, {"knowledge-refresh-" + refreshRev + "-" + refreshVer + "-" + hex, false}})
		write("artifacts-1.json", []art{})
		bin := filepath.Join(dir, "bin")
		if err := os.Mkdir(bin, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(bin, "gh"), []byte(fakeGH), 0o700); err != nil {
			t.Fatal(err)
		}
		return dir, bin
	}
	call := func(t *testing.T, dir, bin, rev, ver string) (string, error) {
		script := "set -euo pipefail\nGH_REPO=o/r\nfail() { echo \"REFUSED: $*\"; exit 1; }\n" + newest + "\n" + cross + "\nartifact_crosscheck " + rev + " " + ver + "\n"
		cmd := exec.Command("bash", "-c", script)
		cmd.Env = []string{"PATH=" + bin + ":" + os.Getenv("PATH"), "FAKE_DIR=" + dir}
		out, err := cmd.CombinedOutput()
		return string(out), err
	}
	t.Run("newer content artifact refuses", func(t *testing.T) {
		dir, bin := setup(t, "20", "10", "3")
		if out, err := call(t, dir, bin, "10", "3"); err == nil || !strings.Contains(out, "REFUSED") {
			t.Fatalf("a newer content revision must refuse, got err=%v out=%s", err, out)
		}
	})
	t.Run("newer refresh artifact refuses (higher timestamp version)", func(t *testing.T) {
		dir, bin := setup(t, "10", "10", "5")
		if out, err := call(t, dir, bin, "10", "3"); err == nil || !strings.Contains(out, "REFUSED") {
			t.Fatalf("a newer refresh must refuse, got err=%v out=%s", err, out)
		}
	})
	t.Run("newer refresh artifact refuses (higher revision)", func(t *testing.T) {
		dir, bin := setup(t, "10", "11", "1")
		if out, err := call(t, dir, bin, "10", "3"); err == nil || !strings.Contains(out, "REFUSED") {
			t.Fatalf("a newer refresh revision must refuse, got err=%v out=%s", err, out)
		}
	})
	t.Run("equal passes", func(t *testing.T) {
		dir, bin := setup(t, "10", "10", "3")
		if out, err := call(t, dir, bin, "10", "3"); err != nil {
			t.Fatalf("equal must pass: %v %s", err, out)
		}
	})
	t.Run("older artifacts pass", func(t *testing.T) {
		dir, bin := setup(t, "9", "9", "2")
		if out, err := call(t, dir, bin, "10", "3"); err != nil {
			t.Fatalf("older must pass: %v %s", err, out)
		}
	})
	t.Run("no content artifact refuses", func(t *testing.T) {
		dir, bin := setup(t, "10", "10", "3")
		_ = os.WriteFile(filepath.Join(dir, "artifacts-2.json"), []byte("[]"), 0o600)
		if out, err := call(t, dir, bin, "10", "3"); err == nil || !strings.Contains(out, "REFUSED") {
			t.Fatalf("no content artifact must refuse, got err=%v out=%s", err, out)
		}
	})
	t.Run("malformed candidate refuses", func(t *testing.T) {
		dir, bin := setup(t, "10", "10", "3")
		if out, err := call(t, dir, bin, "x", "3"); err == nil || !strings.Contains(out, "REFUSED") {
			t.Fatalf("a malformed candidate revision must refuse, got err=%v out=%s", err, out)
		}
	})
	if !strings.Contains(run, "artifact_crosscheck \"${CAND_REVISION}\" \"${CAND_TS_VERSION}\"") {
		t.Error("the deploy guard must call artifact_crosscheck with the candidate revision and timestamp version")
	}
}

// The key file must end in exactly one newline whatever the secret ends in.
func TestKnowledgeRefreshKeyNormalization(t *testing.T) {
	wf, _ := loadRefreshWorkflow(t)
	run := stepRun(t, wf, "refresh", "Sign the refresh")
	var line string
	for _, l := range strings.Split(run, "\n") {
		if strings.Contains(l, `> "${keys}/timestamp.key.pem"`) {
			line = strings.TrimSpace(l)
		}
	}
	if line == "" {
		t.Fatal("the key write line was not found")
	}
	body := "-----BEGIN ENCRYPTED KEY-----\nabc\n-----END ENCRYPTED KEY-----"
	for _, tc := range []struct{ name, secret string }{
		{"no trailing newline", body},
		{"one trailing newline", body + "\n"},
		{"two trailing newlines", body + "\n\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			cmd := exec.Command("bash", "-c", "set -euo pipefail\nkeys="+dir+"\n"+line+"\n")
			cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "TIMESTAMP_KEY=" + tc.secret}
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("%v: %s", err, out)
			}
			got, err := os.ReadFile(filepath.Join(dir, "timestamp.key.pem"))
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != body+"\n" {
				t.Fatalf("key file = %q, want exactly one trailing newline", got)
			}
		})
	}
	for _, l := range strings.Split(run, "\n") {
		if strings.Contains(l, "printf") && strings.Contains(l, "key.pem") && !strings.Contains(l, `printf '%s\n' "$(printf '%s' "${TIMESTAMP_KEY}")"`) {
			t.Errorf("a key is written without normalisation: %s", l)
		}
	}
}

// A refusal before any digest check names the key file or passphrase; a
// refusal that mentions a digest or the live state keeps the generic message.
func TestKnowledgeRefreshRefusalClassification(t *testing.T) {
	wf, _ := loadRefreshWorkflow(t)
	run := stepRun(t, wf, "refresh", "Sign the refresh")
	fn := extractShellFunc(t, run, "classify_refusal")
	for _, tc := range []struct {
		name, stderr string
		result       bool
		want         string
	}{
		{"bad passphrase", "knowledge-publish: decrypt timestamp key: wrong passphrase\n", false, "key file or passphrase unusable"},
		{"bad key file", "knowledge-publish: read key file: invalid PEM\n", false, "key file or passphrase unusable"},
		{"digest mismatch", "knowledge-publish: live package digest mismatch\n", false, "the publisher refused the refresh"},
		{"state mismatch", "knowledge-publish: live state does not match; key ok\n", false, "the publisher refused the refresh"},
		{"unrelated", "knowledge-publish: no extension possible\n", false, "the publisher refused the refresh"},
		{"key text but result written", "knowledge-publish: key passphrase\n", true, "the publisher refused the refresh"},
		{"empty stderr", "", false, "the publisher refused the refresh"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			errf, res := filepath.Join(dir, "e"), filepath.Join(dir, "r")
			_ = os.WriteFile(errf, []byte(tc.stderr), 0o600)
			content := ""
			if tc.result {
				content = "{}"
			}
			_ = os.WriteFile(res, []byte(content), 0o600)
			cmd := exec.Command("bash", "-c", "set -euo pipefail\nfail() { echo \"$*\"; exit 1; }\n"+fn+"\nclassify_refusal "+errf+" "+res+"\n")
			cmd.Env = []string{"PATH=" + os.Getenv("PATH")}
			out, err := cmd.CombinedOutput()
			if err == nil || !strings.Contains(string(out), tc.want) {
				t.Fatalf("want exit 1 with %q, got err=%v out=%q", tc.want, err, out)
			}
			if tc.want == "key file or passphrase unusable" && strings.Contains(string(out), "digest") {
				t.Fatalf("key refusal must not mention a digest: %q", out)
			}
		})
	}
}
