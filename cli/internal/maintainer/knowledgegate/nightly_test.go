// SPDX-License-Identifier: AGPL-3.0-only

package knowledgegate

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const nPRHead = "5555555555555555555555555555555555555555"

func nRun(id int64, at, conclusion string) CIRun {
	return CIRun{ID: id, Status: "completed", Conclusion: conclusion, Event: "schedule", HeadBranch: "main", Path: ciWorkflowPath, CreatedAt: at}
}

func nOwn(id int64, at, conclusion string) CIRun {
	return CIRun{ID: id, Status: "completed", Conclusion: conclusion, Event: "pull_request", HeadBranch: "fix", HeadSHA: nPRHead, Path: ciWorkflowPath, CreatedAt: at}
}

func TestNightlyVerdictRefuses(t *testing.T) {
	t.Parallel()
	red := []CIRun{nRun(1, "2026-11-17T02:17:00Z", "success"), nRun(2, "2026-11-18T02:17:00Z", "failure")}
	redJobs := []CIJob{{RunID: 2, Name: "race", Conclusion: "failure"}, {RunID: 2, Name: "lint-build", Conclusion: "success"}}
	greenOwn := []CIJob{{RunID: 9, Name: "race", Conclusion: "success"}, {RunID: 9, Name: "lint-build", Conclusion: "success"}}
	fixIn := func() NightlyInput {
		return NightlyInput{
			Runs: red, Fix: true, PRHead: nPRHead,
			NightlyJobs: redJobs, NightlyJobsTotal: 2,
			PRRuns: []CIRun{nOwn(9, "2026-11-18T09:00:00Z", "success")}, PRJobs: greenOwn, PRJobsTotal: 2,
		}
	}
	cases := map[string]NightlyInput{
		"no runs":                     {},
		"red, no label":               {Runs: red},
		"cancelled":                   {Runs: []CIRun{nRun(3, "2026-11-18T02:17:00Z", "cancelled")}},
		"empty conclusion":            {Runs: []CIRun{nRun(3, "2026-11-18T02:17:00Z", "")}},
		"only an in-progress run":     {Runs: []CIRun{{ID: 4, Status: "in_progress", Event: "schedule", HeadBranch: "main", Path: ciWorkflowPath, CreatedAt: "2026-11-18T02:17:00Z"}}},
		"only a push run":             {Runs: []CIRun{{ID: 5, Status: "completed", Conclusion: "success", Event: "push", HeadBranch: "main", Path: ciWorkflowPath, CreatedAt: "2026-11-18T02:17:00Z"}}},
		"another workflow":            {Runs: []CIRun{{ID: 5, Status: "completed", Conclusion: "success", Event: "schedule", HeadBranch: "main", Path: ".github/workflows/x.yml", CreatedAt: "2026-11-18T02:17:00Z"}}},
		"bad time":                    {Runs: []CIRun{nRun(3, "yesterday", "success")}},
		"newer red hides older green": {Runs: []CIRun{nRun(2, "2026-11-18T02:17:00Z", "failure"), nRun(1, "2026-11-17T02:17:00Z", "success")}},
	}
	for name, in := range cases {
		if _, err := NightlyVerdict(in); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	mods := map[string]func(in *NightlyInput){
		"label but no own run": func(in *NightlyInput) { in.PRRuns = nil },
		"own run red":          func(in *NightlyInput) { in.PRRuns = []CIRun{nOwn(9, "2026-11-18T09:00:00Z", "failure")} },
		"own latest red, older green": func(in *NightlyInput) {
			in.PRRuns = []CIRun{nOwn(8, "2026-11-18T08:00:00Z", "success"), nOwn(9, "2026-11-18T09:00:00Z", "failure")}
		},
		"own run for another head": func(in *NightlyInput) {
			r := nOwn(9, "2026-11-18T09:00:00Z", "success")
			r.HeadSHA = strings.Repeat("6", 40)
			in.PRRuns = []CIRun{r}
		},
		"own run still running": func(in *NightlyInput) {
			r := nOwn(9, "2026-11-18T09:00:00Z", "")
			r.Status = "in_progress"
			in.PRRuns = []CIRun{r}
		},
		"red job skipped in own run": func(in *NightlyInput) {
			in.PRJobs = []CIJob{{RunID: 9, Name: "race", Conclusion: "skipped"}, {RunID: 9, Name: "lint-build", Conclusion: "success"}}
		},
		"red job missing in own run": func(in *NightlyInput) {
			in.PRJobs = []CIJob{{RunID: 9, Name: "lint-build", Conclusion: "success"}}
			in.PRJobsTotal = 1
		},
		"another job red in own run": func(in *NightlyInput) {
			in.PRJobs = append(append([]CIJob{}, greenOwn...), CIJob{RunID: 9, Name: "x", Conclusion: "failure"})
			in.PRJobsTotal = 3
		},
		"another job skipped in own run": func(in *NightlyInput) {
			in.PRJobs = append(append([]CIJob{}, greenOwn...), CIJob{RunID: 9, Name: "x", Conclusion: "skipped"})
			in.PRJobsTotal = 3
		},
		"own jobs belong to another run": func(in *NightlyInput) {
			in.PRJobs = []CIJob{{RunID: 1, Name: "race", Conclusion: "success"}, {RunID: 1, Name: "lint-build", Conclusion: "success"}}
		},
		"own jobs list truncated": func(in *NightlyInput) { in.PRJobsTotal = 101 },
		"own jobs empty":          func(in *NightlyInput) { in.PRJobs = nil; in.PRJobsTotal = 0 },
		"nightly jobs truncated":  func(in *NightlyInput) { in.NightlyJobsTotal = 150 },
		"nightly jobs of another run": func(in *NightlyInput) {
			in.NightlyJobs = []CIJob{{RunID: 1, Name: "race", Conclusion: "failure"}}
			in.NightlyJobsTotal = 1
		},
		"red nightly names no red job": func(in *NightlyInput) {
			in.NightlyJobs = []CIJob{{RunID: 2, Name: "lint-build", Conclusion: "success"}}
			in.NightlyJobsTotal = 1
		},
		"bad pr head": func(in *NightlyInput) { in.PRHead = "main" },
	}
	for name, mod := range mods {
		in := fixIn()
		mod(&in)
		if _, err := NightlyVerdict(in); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestNightlyVerdictAccepts(t *testing.T) {
	t.Parallel()
	green := []CIRun{nRun(1, "2026-11-17T02:17:00Z", "failure"), nRun(2, "2026-11-18T02:17:00Z", "success")}
	if msg, err := NightlyVerdict(NightlyInput{Runs: green}); err != nil || !strings.Contains(msg, "green") {
		t.Fatalf("%q %v", msg, err)
	}
	// An older red run does not matter when the newest is green (page order is not trusted).
	if _, err := NightlyVerdict(NightlyInput{Runs: []CIRun{green[1], green[0]}}); err != nil {
		t.Fatal(err)
	}
	// Red with the label and a fully green run of the fix on its exact head.
	in := NightlyInput{
		Runs: []CIRun{nRun(2, "2026-11-18T02:17:00Z", "failure")}, Fix: true, PRHead: nPRHead,
		NightlyJobs:      []CIJob{{RunID: 2, Name: "race", Conclusion: "failure"}, {RunID: 2, Name: "slow", Conclusion: "cancelled"}, {RunID: 2, Name: "ok", Conclusion: "success"}},
		NightlyJobsTotal: 3,
		PRRuns:           []CIRun{nOwn(8, "2026-11-18T08:00:00Z", "failure"), nOwn(9, "2026-11-18T09:00:00Z", "success")},
		PRJobs:           []CIJob{{RunID: 9, Name: "race", Conclusion: "success"}, {RunID: 9, Name: "slow", Conclusion: "success"}, {RunID: 9, Name: "ok", Conclusion: "success"}},
		PRJobsTotal:      3,
	}
	msg, err := NightlyVerdict(in)
	if err != nil || !strings.Contains(msg, "nightly-fix") {
		t.Fatalf("%q %v", msg, err)
	}
}

func TestNightlyCommand(t *testing.T) {
	t.Parallel()
	write := func(v any) string {
		b, _ := json.Marshal(v)
		p := filepath.Join(t.TempDir(), "x.json")
		if err := os.WriteFile(p, b, 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	run := func(args ...string) (int, string) {
		var so, se bytes.Buffer
		c := Main(append([]string{"nightly"}, args...), func(string) string { return "" }, &so, &se)
		return c, so.String()
	}
	if c, _ := run("--runs", filepath.Join(t.TempDir(), "missing.json")); c == 0 {
		t.Fatal("unreadable runs accepted")
	}
	if c, _ := run("--runs", write(map[string]any{"workflow_runs": []CIRun{}})); c == 0 {
		t.Fatal("no runs accepted")
	}
	if c, _ := run("--runs", write(map[string]any{"message": "Server Error"})); c == 0 {
		t.Fatal("error body accepted")
	}
	redRuns := write(map[string]any{"workflow_runs": []CIRun{nRun(2, "2026-11-18T02:17:00Z", "failure")}})
	if c, _ := run("--runs", redRuns); c == 0 {
		t.Fatal("red accepted")
	}
	if c, _ := run("--runs", redRuns, "--fix", "--pr-head", nPRHead); c == 0 {
		t.Fatal("--fix without the job payloads accepted")
	}
	if c, _ := run("--runs", write(map[string]any{"workflow_runs": []CIRun{nRun(2, "2026-11-18T02:17:00Z", "success")}})); c != 0 {
		t.Fatal("green refused")
	}
	pr := write(map[string]any{"workflow_runs": []CIRun{nOwn(9, "2026-11-18T09:00:00Z", "success")}})
	c, out := run("--runs", redRuns, "--select", "--pr-runs", pr, "--pr-head", nPRHead)
	if c != 0 || out != "nightly=2\npr=9\n" {
		t.Fatalf("select: %d %q", c, out)
	}
	nj := write(map[string]any{"total_count": 1, "jobs": []CIJob{{RunID: 2, Name: "race", Conclusion: "failure"}}})
	pj := write(map[string]any{"total_count": 1, "jobs": []CIJob{{RunID: 9, Name: "race", Conclusion: "success"}}})
	if c, _ := run("--runs", redRuns, "--fix", "--pr-head", nPRHead, "--nightly-jobs", nj, "--pr-runs", pr, "--pr-jobs", pj); c != 0 {
		t.Fatal("proven fix refused")
	}
	pjBad := write(map[string]any{"total_count": 1, "jobs": []CIJob{{RunID: 9, Name: "race", Conclusion: "failure"}}})
	if c, _ := run("--runs", redRuns, "--fix", "--pr-head", nPRHead, "--nightly-jobs", nj, "--pr-runs", pr, "--pr-jobs", pjBad); c == 0 {
		t.Fatal("red fix run accepted")
	}
}
