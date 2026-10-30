// SPDX-License-Identifier: AGPL-3.0-only

package releaseworkflow

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

func repoRoot(t *testing.T) string {
	t.Helper()
	_, self, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate the test source")
	}
	repo := filepath.Join(filepath.Dir(self), "..", "..", "..", "..")
	if _, err := os.Stat(filepath.Join(repo, ".github")); os.IsNotExist(err) {
		t.Skip("no .github directory: staged release source tree")
	}
	return repo
}

// The weekly cron must re-sign every time, so the timestamp expiry moves
// every week. The decision is executed from the workflow's own text.
func TestKnowledgePublishCronNeverSkips(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available")
	}
	wf, _ := loadPublishWorkflow(t)
	var run string
	for _, st := range wf.Jobs["sign"].Steps {
		if st.Name == "Build, sign and verify" {
			run = st.Run
			if st.Env["EVENT_NAME"] != "${{ github.event_name }}" {
				t.Errorf("sign step env EVENT_NAME = %q", st.Env["EVENT_NAME"])
			}
		}
	}
	start := strings.Index(run, "\nskip=false\n")
	if start < 0 {
		t.Fatal("skip decision block not found in the sign step")
	}
	end := strings.Index(run[start:], "\nfi\n")
	if end < 0 {
		t.Fatal("skip decision block has no end")
	}
	block := run[start : start+end+len("\nfi\n")]
	for _, c := range []struct {
		event string
		want  string
	}{{"schedule", "false"}, {"push", "true"}, {"workflow_dispatch", "true"}} {
		script := "now=1000000; PREV_CREATED=999900; MODE=state; rules=r; PREV_RULES=r; EVENT_NAME=" + c.event + "\n" + block + "\necho \"${skip}\"\n"
		out, err := exec.Command("bash", "-c", script).CombinedOutput()
		if err != nil {
			t.Fatalf("%s: %v: %s", c.event, err, out)
		}
		if got := strings.TrimSpace(string(out)); got != c.want {
			t.Errorf("event %s: skip = %s, want %s (unchanged bundle, previous publish 100s old)", c.event, got, c.want)
		}
	}
}

type verifyWorkflow struct {
	On          map[string]any `yaml:"on"`
	Permissions map[string]string
	Jobs        map[string]publishJob `yaml:"jobs"`
}

// The self-check workflow holds no secret and writes nothing but the one
// tracking issue.
func TestPublishVerifyWorkflowIsHardened(t *testing.T) {
	repo := repoRoot(t)
	raw, err := os.ReadFile(filepath.Join(repo, ".github", "workflows", "knowledge-publish-verify.yml"))
	if err != nil {
		t.Fatal(err)
	}
	var wf verifyWorkflow
	if err := yaml.Unmarshal(raw, &wf); err != nil {
		t.Fatal(err)
	}
	if wf.Permissions == nil || len(wf.Permissions) != 0 {
		t.Errorf("top-level permissions = %v, want {}", wf.Permissions)
	}
	if len(wf.On) != 2 || wf.On["schedule"] == nil {
		t.Errorf("triggers = %v, want schedule and workflow_dispatch only", wf.On)
	}
	if _, ok := wf.On["workflow_dispatch"]; !ok {
		t.Error("missing workflow_dispatch")
	}
	if len(wf.Jobs) != 1 {
		t.Fatalf("jobs = %d, want 1", len(wf.Jobs))
	}
	job := wf.Jobs["verify"]
	if !samePermissions(job.Permissions, map[string]string{"contents": "read", "issues": "write"}) {
		t.Errorf("permissions = %v", job.Permissions)
	}
	if job.Environment != nil {
		t.Error("must not use an environment")
	}
	for _, want := range []string{"refs/heads/main", "KNOWLEDGE_RELEASE_ENABLED"} {
		if !strings.Contains(job.If, want) {
			t.Errorf("if %q lacks %s", job.If, want)
		}
	}
	if strings.Contains(string(raw), "secrets.") {
		t.Error("must not reference secrets.*")
	}
	pinned := regexp.MustCompile(`^[A-Za-z0-9._-]+/[A-Za-z0-9._/-]+@[0-9a-f]{40}$`)
	for _, st := range job.Steps {
		if st.Uses != "" && !pinned.MatchString(st.Uses) {
			t.Errorf("action %q is not pinned by a 40-hex commit SHA", st.Uses)
		}
		if strings.HasPrefix(st.Uses, "actions/checkout@") {
			if v, ok := st.With["persist-credentials"].(bool); !ok || v {
				t.Error("checkout must set persist-credentials: false")
			}
		}
		if strings.HasPrefix(st.Uses, "actions/setup-go@") {
			if v, ok := st.With["cache"].(bool); !ok || v {
				t.Error("setup-go must set cache: false")
			}
		}
		if strings.Contains(st.Run, "${{") {
			t.Errorf("step %q: run must not interpolate expressions (use env)", st.Name)
		}
	}
}

// Behaviour of scripts/publish-verify.sh with a stubbed network and client.
func TestPublishVerifyScript(t *testing.T) {
	repo := repoRoot(t)
	for _, tool := range []string{"bash", "jq", "curl"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skip(tool + " not available")
		}
	}
	if out, err := exec.Command("date", "-u", "-d", "@0", "+%s").CombinedOutput(); err != nil || strings.TrimSpace(string(out)) != "0" {
		t.Skip("GNU date required")
	}
	script := filepath.Join(repo, "scripts", "publish-verify.sh")

	now := time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)
	ts := func(d time.Time) string { return d.Format("2006-01-02T15:04:05Z") }
	day := 24 * time.Hour

	type scenario struct {
		name       string
		signed     time.Time // feed signing time; expires = signed + 14d
		evidence   time.Time // zero: signed + 60d
		runStarted time.Time
		noRun      bool
		merge      time.Time
		noMerge    bool
		lastMod    time.Time
		verifyFail bool
		feedFail   bool
		wantExit   int
		wantIn     string
	}
	good := scenario{signed: now.Add(-1 * day), runStarted: now.Add(-1 * day), merge: now.Add(-3 * day), wantExit: 0, wantIn: "publish-verify: OK revision 7"}
	with := func(name string, f func(*scenario), exit int, in string) scenario {
		s := good
		s.name = name
		f(&s)
		s.wantExit, s.wantIn = exit, in
		return s
	}
	scenarios := []scenario{
		with("healthy", func(*scenario) {}, 0, "publish-verify: OK revision 7"),
		with("feed older than 8 days", func(s *scenario) { s.signed = now.Add(-9 * day); s.runStarted = now.Add(-1 * day) }, 1, "feed age 9 days"),
		with("expiry under 5 days", func(s *scenario) { s.signed = now.Add(-10 * day) }, 1, "timestamp expires in 4 days"),
		with("last run older than 8 days", func(s *scenario) { s.runStarted = now.Add(-9 * day) }, 1, "last successful Knowledge publish run on main is 9 days old"),
		with("no successful run", func(s *scenario) { s.noRun = true }, 1, "no successful Knowledge publish run on main"),
		with("feed not newer than merge", func(s *scenario) {
			s.signed = now.Add(-3 * day)
			s.merge = now.Add(-1 * day)
			s.runStarted = now.Add(-4 * day)
		}, 1, "feed not newer than the newest knowledge merge"),
		with("merge inside grace", func(s *scenario) { s.merge = now.Add(-30 * time.Minute); s.runStarted = now.Add(-1 * day) }, 0, "publish-verify: OK"),
		with("later skipped run accounts for the merge", func(s *scenario) {
			s.signed = now.Add(-3 * day)
			s.merge = now.Add(-2 * day)
			s.runStarted = now.Add(-1 * day)
		}, 0, "publish-verify: OK"),
		with("no knowledge merge at all", func(s *scenario) { s.noMerge = true }, 0, "publish-verify: OK"),
		with("feed does not verify", func(s *scenario) { s.verifyFail = true }, 1, "feed does not verify against the pinned root"),
		with("feed unreachable", func(s *scenario) { s.feedFail = true }, 1, "feed unreachable"),
		with("evidence-capped expiry uses Last-Modified", func(s *scenario) {
			s.evidence = s.signed.Add(5 * day) // expires == evidence expiry: cap not binding
			s.lastMod = now.Add(-10 * day)
		}, 1, "feed age 10 days"),
		with("two reasons on one line", func(s *scenario) { s.signed = now.Add(-12 * day); s.runStarted = now.Add(-9 * day) }, 1, "; "),
	}

	for _, sc := range scenarios {
		t.Run(sc.name, func(t *testing.T) {
			dir := t.TempDir()
			bin := filepath.Join(dir, "bin")
			if err := os.Mkdir(bin, 0o755); err != nil {
				t.Fatal(err)
			}
			expires := sc.signed.Add(14 * day)
			evidence := sc.evidence
			if evidence.IsZero() {
				evidence = sc.signed.Add(60 * day)
			} else {
				expires = evidence
			}
			lastMod := sc.lastMod
			if lastMod.IsZero() {
				lastMod = sc.signed
			}
			write := func(name, content string) {
				if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			write("receipt.json", fmt.Sprintf(`{"status":"VERIFIED","knowledgeRevision":7,"timestamp":{"version":7,"expires":%q},"evidenceExpiresAt":%q}`, ts(expires), ts(evidence)))
			write("headers", "HTTP/2 200\r\nlast-modified: "+lastMod.Format("Mon, 02 Jan 2006 15:04:05")+" GMT\r\n\r\n")
			runs := `{"workflow_runs":[]}`
			if !sc.noRun {
				runs = fmt.Sprintf(`{"workflow_runs":[{"run_started_at":%q}]}`, ts(sc.runStarted))
			}
			write("runs.json", runs)
			commits := `[]`
			if !sc.noMerge {
				commits = fmt.Sprintf(`[{"commit":{"committer":{"date":%q}}}]`, ts(sc.merge))
			}
			write("commits.json", commits)
			write("root.json", "{}")
			if sc.feedFail {
				write("feed_fail", "1")
			}
			if sc.verifyFail {
				write("verify_fail", "1")
			}
			stubCurl := `#!/usr/bin/env bash
d="$(dirname "$0")/.."
out="" hdr="" url=""
while [ $# -gt 0 ]; do
  case "$1" in
    -o) out="$2"; shift 2 ;;
    -D) hdr="$2"; shift 2 ;;
    --) url="$2"; shift 2 ;;
    *) shift ;;
  esac
done
case "${url}" in
  *knowledge-publish.yml/runs*) cat "$d/runs.json" ;;
  */commits*) cat "$d/commits.json" ;;
  *)
    [ ! -e "$d/feed_fail" ] || exit 22
    cp "$d/headers" "${hdr}"; echo tar > "${out}" ;;
esac
`
			stubPrufyx := `#!/usr/bin/env bash
d="$(dirname "$0")/.."
[ ! -e "$d/verify_fail" ] || exit 3
cat "$d/receipt.json"
`
			for name, body := range map[string]string{"curl": stubCurl, "prufyx": stubPrufyx} {
				if err := os.WriteFile(filepath.Join(bin, name), []byte(body), 0o755); err != nil {
					t.Fatal(err)
				}
			}
			cmd := exec.Command("bash", script, "--bin", filepath.Join(bin, "prufyx"), "--root", filepath.Join(dir, "root.json"),
				"--root-digest", "sha256:"+strings.Repeat("0", 64), "--repo", "prufyx/prufyx")
			cmd.Env = append(os.Environ(), "PATH="+bin+":"+os.Getenv("PATH"), fmt.Sprintf("PUBLISH_VERIFY_NOW=%d", now.Unix()))
			out, err := cmd.Output()
			code := 0
			if ee, ok := err.(*exec.ExitError); ok {
				code = ee.ExitCode()
			} else if err != nil {
				t.Fatal(err)
			}
			line := strings.TrimRight(string(out), "\n")
			if code != sc.wantExit || !strings.Contains(line, sc.wantIn) || strings.Contains(line, "\n") {
				t.Errorf("exit %d (want %d), line %q, want it to contain %q on one line", code, sc.wantExit, line, sc.wantIn)
			}
		})
	}
}
