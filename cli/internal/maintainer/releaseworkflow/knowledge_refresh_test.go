// SPDX-License-Identifier: AGPL-3.0-only

package releaseworkflow

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
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
	liveRaw    string // verbatim live state, overrides the generated one
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
		{name: "live state without timestampExpires fails closed", tsDays: 5, contentDay: 15, liveRaw: `{"packageDigest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","targetsExpires":"2026-11-30T00:00:00Z","snapshotExpires":"2026-11-30T00:00:00Z"}`, wantExit: 1},
		{name: "live state without targetsExpires fails closed", tsDays: 5, contentDay: 15, liveRaw: `{"packageDigest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","timestampExpires":"2026-11-20T00:00:00Z","snapshotExpires":"2026-11-30T00:00:00Z"}`, wantExit: 1},
		{name: "live state without snapshotExpires fails closed", tsDays: 5, contentDay: 15, liveRaw: `{"packageDigest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","timestampExpires":"2026-11-20T00:00:00Z","targetsExpires":"2026-11-30T00:00:00Z"}`, wantExit: 1},
		{name: "live state without packageDigest fails closed", tsDays: 5, contentDay: 15, liveRaw: `{"timestampExpires":"2026-11-20T00:00:00Z","targetsExpires":"2026-11-30T00:00:00Z","snapshotExpires":"2026-11-30T00:00:00Z"}`, wantExit: 1},
		{name: "empty timestampExpires fails closed", tsDays: 5, contentDay: 15, liveRaw: `{"packageDigest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","timestampExpires":"","targetsExpires":"2026-11-30T00:00:00Z","snapshotExpires":"2026-11-30T00:00:00Z"}`, wantExit: 1},
		{name: "empty targetsExpires fails closed", tsDays: 5, contentDay: 15, liveRaw: `{"packageDigest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","timestampExpires":"2026-11-20T00:00:00Z","targetsExpires":"","snapshotExpires":"2026-11-30T00:00:00Z"}`, wantExit: 1},
		{name: "empty snapshotExpires fails closed", tsDays: 5, contentDay: 15, liveRaw: `{"packageDigest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","timestampExpires":"2026-11-20T00:00:00Z","targetsExpires":"2026-11-30T00:00:00Z","snapshotExpires":""}`, wantExit: 1},
		{name: "non-date timestampExpires fails closed", tsDays: 5, contentDay: 15, liveRaw: `{"packageDigest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","timestampExpires":"soon","targetsExpires":"2026-11-30T00:00:00Z","snapshotExpires":"2026-11-30T00:00:00Z"}`, wantExit: 1},
		{name: "non-date targetsExpires fails closed", tsDays: 5, contentDay: 15, liveRaw: `{"packageDigest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","timestampExpires":"2026-11-20T00:00:00Z","targetsExpires":"tomorrow","snapshotExpires":"2026-11-30T00:00:00Z"}`, wantExit: 1},
		{name: "non-date snapshotExpires fails closed", tsDays: 5, contentDay: 15, liveRaw: `{"packageDigest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","timestampExpires":"2026-11-20T00:00:00Z","targetsExpires":"2026-11-30T00:00:00Z","snapshotExpires":"next week"}`, wantExit: 1},
		{name: "relative-date timestampExpires fails closed", tsDays: 5, contentDay: 15, liveRaw: `{"packageDigest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","timestampExpires":"now + 30 days","targetsExpires":"2026-11-30T00:00:00Z","snapshotExpires":"2026-11-30T00:00:00Z"}`, wantExit: 1},
		{name: "non-string timestampExpires fails closed", tsDays: 5, contentDay: 15, liveRaw: `{"packageDigest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","timestampExpires":1788000000,"targetsExpires":"2026-11-30T00:00:00Z","snapshotExpires":"2026-11-30T00:00:00Z"}`, wantExit: 1},
		{name: "live state not JSON fails closed", tsDays: 5, contentDay: 15, liveRaw: "not json", wantExit: 1},
		{name: "pending list not an array fails closed", tsDays: 5, contentDay: 15, badPending: `{"id":1}`, wantExit: 1},
		{name: "pending element not an object fails closed", tsDays: 5, contentDay: 15, badPending: `[1]`, wantExit: 1},
		{name: "pending missing id fails closed", tsDays: 5, contentDay: 15, badPending: `[{"status":"waiting","created_at":"2026-11-01T00:00:00Z"}]`, wantExit: 1},
		{name: "pending unknown shape fails closed", tsDays: 5, contentDay: 15, badPending: `[{}]`, wantExit: 1},
		{name: "pending string id fails closed", tsDays: 5, contentDay: 15, badPending: `[{"id":"7","status":"waiting","created_at":"2026-11-01T00:00:00Z"}]`, wantExit: 1},
		{name: "unreadable run time fails closed", tsDays: 5, contentDay: 15, pending: []map[string]any{{"id": 3, "status": "waiting", "created_at": "yesterday-ish"}}, wantExit: 1},
		{name: "threshold out of range fails closed", tsDays: 5, contentDay: 15, threshold: "14", wantExit: 1},
		{name: "threshold not a number fails closed", tsDays: 5, contentDay: 15, threshold: "7;x", wantExit: 1},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			livePath := filepath.Join(dir, "live.json")
			if c.liveRaw != "" {
				_ = os.WriteFile(livePath, []byte(c.liveRaw), 0o600)
			} else if c.badLive {
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
[ -z "${FAKE_LOG:-}" ] || echo "$path" >> "$FAKE_LOG"
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
		ID        int    `json:"id"`
		CreatedAt string `json:"created_at"`
	}
	recent := time.Now().UTC().Add(-time.Hour).Format("2006-01-02T15:04:05Z")
	setup := func(t *testing.T, empty, tail int, arts []art) (string, string) {
		dir := t.TempDir()
		var runs []run
		for i := 0; i < empty; i++ { // newest first: content-free runs
			id := 1000 - i
			runs = append(runs, run{id, recent})
			writeJSON(dir, "artifacts-"+itoa(int64(id))+".json", []art{{"plan-only-" + itoa(int64(id)), false}})
		}
		runs = append(runs, run{500, recent}) // the newest content run
		writeJSON(dir, "artifacts-500.json", arts)
		for i := 0; i < tail; i++ { // older content run with a different artifact
			id := 400 - i
			runs = append(runs, run{id, recent})
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
		script := "set -euo pipefail\nGH_REPO=o/r\nfail() { echo \"REFUSED: $*\" >&2; exit 1; }\n" + fn + "\nnewest_artifact knowledge-publish.yml '" + re + "'\n"
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

// The newest-artifact walk is bounded: a window with no matching artifact must
// not walk the API without limit, and a run older than the artifact retention
// ends the walk.
func TestKnowledgeRefreshNewestArtifactIsBounded(t *testing.T) {
	for _, tool := range []string{"bash", "jq", "sed", "date"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skip(tool + " not available")
		}
	}
	wf, raw := loadRefreshWorkflow(t)
	hex := strings.Repeat("c", 64)
	const re = `^knowledge-[0-9]+-[0-9a-f]{64}$`
	fns := map[string]string{
		"decide": extractShellFunc(t, raw, "newest_artifact"),
		"deploy": extractShellFunc(t, stepRun(t, wf, "deploy", "Deploy guard"), "newest_artifact"),
	}
	type run struct {
		ID        int    `json:"id"`
		CreatedAt string `json:"created_at"`
	}
	write := func(dir, name string, v any) {
		b, _ := json.Marshal(v)
		if err := os.WriteFile(filepath.Join(dir, name), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	setup := func(t *testing.T, n int, created func(i int) string, artifactAt int) (string, string, string) {
		dir := t.TempDir()
		var runs []run
		for i := 0; i < n; i++ {
			id := 100000 - i
			runs = append(runs, run{id, created(i)})
			name := "plan-only-" + itoa(int64(id))
			if i == artifactAt {
				name = "knowledge-5-" + hex
			}
			write(dir, "artifacts-"+itoa(int64(id))+".json", []map[string]any{{"name": name, "expired": false}})
		}
		write(dir, "runs.json", runs)
		bin := filepath.Join(dir, "bin")
		if err := os.Mkdir(bin, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(bin, "gh"), []byte(fakeGH), 0o700); err != nil {
			t.Fatal(err)
		}
		return dir, bin, filepath.Join(dir, "calls.log")
	}
	call := func(dir, bin, log, fn string) (string, string, error) {
		script := "set -euo pipefail\nGH_REPO=o/r\nfail() { echo \"REFUSED: $*\" >&2; exit 1; }\n" + fn + "\nout=\"$(newest_artifact knowledge-publish.yml '" + re + "')\"\necho \"[$out]\"\n"
		cmd := exec.Command("bash", "-c", script)
		cmd.Env = []string{"PATH=" + bin + ":" + os.Getenv("PATH"), "FAKE_DIR=" + dir, "FAKE_LOG=" + log}
		var so, se strings.Builder
		cmd.Stdout, cmd.Stderr = &so, &se
		err := cmd.Run()
		b, _ := os.ReadFile(log)
		return so.String(), se.String() + "\n" + itoa(int64(strings.Count(string(b), "\n"))), err
	}
	recent := func(int) string { return time.Now().UTC().Add(-time.Hour).Format("2006-01-02T15:04:05Z") }
	for name, fn := range fns {
		t.Run(name+"/unbounded run list stops and refuses", func(t *testing.T) {
			dir, bin, log := setup(t, 1500, recent, -1)
			out, info, err := call(dir, bin, log, fn)
			if err == nil {
				t.Fatalf("1500 recent runs without a match must refuse, got out=%q", out)
			}
			parts := strings.Split(strings.TrimSpace(info), "\n")
			calls, _ := strconv.Atoi(parts[len(parts)-1])
			if calls > 400 {
				t.Fatalf("%d API calls: the walk is not bounded", calls)
			}
		})
		t.Run(name+"/run older than 90 days ends the walk with nothing", func(t *testing.T) {
			old := func(int) string { return time.Now().UTC().AddDate(0, 0, -100).Format("2006-01-02T15:04:05Z") }
			dir, bin, log := setup(t, 5, old, 3)
			out, info, err := call(dir, bin, log, fn)
			if err != nil || strings.TrimSpace(out) != "[]" {
				t.Fatalf("old runs must yield nothing: err=%v out=%q", err, out)
			}
			if strings.Contains(info, "artifacts") {
				t.Fatalf("an old run's artifacts were listed: %s", info)
			}
		})
		t.Run(name+"/unparseable created_at refuses", func(t *testing.T) {
			dir, bin, log := setup(t, 3, func(int) string { return "garbage" }, 1)
			if out, _, err := call(dir, bin, log, fn); err == nil {
				t.Fatalf("an unparseable created_at must refuse, got %q", out)
			}
		})
		t.Run(name+"/recent match inside the bound is found", func(t *testing.T) {
			dir, bin, log := setup(t, 150, recent, 120)
			out, _, err := call(dir, bin, log, fn)
			if err != nil || strings.TrimSpace(out) != "[knowledge-5-"+hex+"]" {
				t.Fatalf("err=%v out=%q", err, out)
			}
		})
	}
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
			ID        int    `json:"id"`
			CreatedAt string `json:"created_at"`
		}
		recent := time.Now().UTC().Add(-time.Hour).Format("2006-01-02T15:04:05Z")
		write("runs.json", []r{{2, recent}, {1, recent}})
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

// The key shape preflight refuses a key secret that is not one PEM block before
// the publisher runs, names only the role and never prints key bytes.
func TestKnowledgeRefreshKeyShapePreflight(t *testing.T) {
	wf, _ := loadRefreshWorkflow(t)
	run := stepRun(t, wf, "refresh", "Sign the refresh")
	fn := extractShellFunc(t, run, "check_key_shape")
	const secretMarker = "SECRETBYTES"
	for _, tc := range []struct {
		name, body string
		ok         bool
	}{
		{"valid", "-----BEGIN ENCRYPTED KEY-----\n" + secretMarker + "\n-----END ENCRYPTED KEY-----\n", true},
		{"no END", "-----BEGIN ENCRYPTED KEY-----\n" + secretMarker + "\n", false},
		{"no BEGIN", secretMarker + "\n-----END ENCRYPTED KEY-----\n", false},
		{"blank line inside", "-----BEGIN ENCRYPTED KEY-----\n" + secretMarker + "\n\n-----END ENCRYPTED KEY-----\n", false},
		{"whitespace-only line", "-----BEGIN ENCRYPTED KEY-----\n  \n" + secretMarker + "\n-----END ENCRYPTED KEY-----\n", false},
		{"CRLF", "-----BEGIN ENCRYPTED KEY-----\r\n" + secretMarker + "\r\n-----END ENCRYPTED KEY-----\r\n", false},
		{"two blocks with a gap", "-----BEGIN ENCRYPTED KEY-----\nA\n-----END ENCRYPTED KEY-----\n\n-----BEGIN ENCRYPTED KEY-----\nB\n-----END ENCRYPTED KEY-----\n", false},
		{"empty", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := filepath.Join(t.TempDir(), "k.pem")
			if err := os.WriteFile(f, []byte(tc.body), 0o600); err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command("bash", "-c", "set -euo pipefail\nfail() { echo \"$*\"; exit 1; }\n"+fn+"\ncheck_key_shape timestamp "+f+"\n")
			cmd.Env = []string{"PATH=" + os.Getenv("PATH")}
			out, err := cmd.CombinedOutput()
			if tc.ok {
				if err != nil {
					t.Fatalf("a valid key must pass: %v %s", err, out)
				}
				return
			}
			if err == nil || !strings.Contains(string(out), "key file or passphrase unusable") || !strings.Contains(string(out), "timestamp") {
				t.Fatalf("want a refusal naming the role, got err=%v out=%q", err, out)
			}
			if strings.Contains(string(out), secretMarker) || strings.Contains(string(out), "BEGIN") {
				t.Fatalf("the refusal leaks key bytes: %q", out)
			}
			if got, _ := os.ReadFile(f); string(got) != tc.body {
				t.Fatal("the preflight modified the key file")
			}
		})
	}
	// Order and the heuristic: the preflight runs before the publisher, the
	// output-grepping classifier is gone, and one generic refusal remains.
	pre := strings.Index(run, "check_key_shape timestamp ")
	pub := strings.Index(run, `"${maint}" knowledge-publish refresh-timestamp`)
	if pre < 0 || pub < 0 || pre > pub {
		t.Error("check_key_shape must run before the publisher call")
	}
	if strings.Contains(run, "classify_refusal") || strings.Contains(run, "grep -qiE") {
		t.Error("the refusal text heuristic must be gone")
	}
	if !strings.Contains(run, "digest, state, extension or cap, or the key file or passphrase") {
		t.Error("the single generic refusal must name digest/state/extension/cap or the key file/passphrase")
	}
	if !strings.Contains(run, `[[ "${TIMESTAMP_KEY}" =~ [^[:space:]] ]]`) || !strings.Contains(run, `[[ "${PASSPHRASE}" =~ [^[:space:]] ]]`) {
		t.Error("the key and passphrase emptiness checks must reject whitespace-only values")
	}
	// The secrets leave the environment right after the key files are written,
	// before any later child process (check_key_shape, the publisher) starts.
	un := strings.Index(run, "unset TIMESTAMP_KEY PASSPHRASE")
	wr := strings.Index(run, `> "${keys}/passphrase"`)
	if un < 0 || wr < 0 || un < wr || un > pre {
		t.Error("TIMESTAMP_KEY and PASSPHRASE must be unset right after the key files are written and before any later child process")
	}
}

// The revision is validated before it is used in a pattern.
func TestKnowledgeRefreshCandidateParse(t *testing.T) {
	wf, _ := loadRefreshWorkflow(t)
	run := stepRun(t, wf, "deploy", "Deploy guard")
	fn := extractShellFunc(t, run, "parse_candidate")
	hex := strings.Repeat("a", 64)
	for _, tc := range []struct {
		name, art, rev string
		ok             bool
	}{
		{"valid", "knowledge-refresh-12-3-" + hex, "12", true},
		{"mismatching revision", "knowledge-refresh-13-3-" + hex, "12", false},
		{"wildcard revision", "knowledge-refresh-12-3-" + hex, ".*", false},
		{"alternation revision", "knowledge-refresh-12-3-" + hex, "12|13", false},
		{"empty revision", "knowledge-refresh--3-" + hex, "", false},
		{"leading zero", "knowledge-refresh-012-3-" + hex, "012", false},
		{"too long", "knowledge-refresh-1234567890123456789-3-" + hex, "1234567890123456789", false},
		{"bracket revision", "knowledge-refresh-1-3-" + hex, "[0-9]", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			script := "set -euo pipefail\nfail() { echo \"REFUSED: $*\"; exit 1; }\n" + fn + "\nparse_candidate \"$1\" \"$2\"\necho \"$CAND_REVISION $CAND_TS_VERSION\"\n"
			cmd := exec.Command("bash", "-c", script, "bash", tc.art, tc.rev)
			cmd.Env = []string{"PATH=" + os.Getenv("PATH")}
			out, err := cmd.CombinedOutput()
			if tc.ok {
				if err != nil || strings.TrimSpace(string(out)) != tc.rev+" 3" {
					t.Fatalf("err=%v out=%q", err, out)
				}
				return
			}
			if err == nil || !strings.Contains(string(out), "REFUSED") {
				t.Fatalf("must refuse, got err=%v out=%q", err, out)
			}
		})
	}
	if !strings.Contains(run, `parse_candidate "${ARTIFACT_NAME}" "${REVISION}"`) {
		t.Error("the deploy guard must parse the candidate through parse_candidate")
	}
}
