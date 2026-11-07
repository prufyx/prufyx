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
		"deploy":  {"pages": "write", "id-token": "write", "contents": "read"},
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
