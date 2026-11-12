// SPDX-License-Identifier: AGPL-3.0-only

package knowledgegate

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

const alarmTailEnd = `exit "${status}"`

// alarmTail returns the part of the verify step that turns the alarm record into the
// alarm_count output, up to and including the final exit.
func alarmTail(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile(workflowPath)
	if err != nil {
		t.Fatal(err)
	}
	var wf workflow
	if err := yaml.Unmarshal(raw, &wf); err != nil {
		t.Fatal(err)
	}
	for _, s := range wf.Jobs["gate"].Steps {
		if s.ID != "verify" {
			continue
		}
		i := strings.Index(s.Run, `if [ ! -f "${RUNNER_TEMP}/gate-alarms.json" ]; then`)
		j := strings.LastIndex(s.Run, alarmTailEnd)
		if i < 0 || j < i {
			t.Fatal("the verify step no longer checks the alarm record before counting")
		}
		return s.Run[i : j+len(alarmTailEnd)]
	}
	t.Fatal("no verify step")
	return ""
}

func strPtr(s string) *string { return &s }

// The gate exits 0 (status=0) in every case below; only the alarm extraction decides the step.
func TestAlarmCountFailsClosed(t *testing.T) {
	tail := alarmTail(t)
	cases := []struct {
		name    string
		record  *string // nil: no file
		fakeJq  string  // body of a fake jq placed first on PATH; empty: the real jq
		wantOut string  // "" means no alarm_count line may be written
		wantOK  bool
	}{
		{"zero alarms", strPtr(`{"alarms":[]}`), "", "alarm_count=0\n", true},
		{"two alarms", strPtr(`{"alarms":["a","b"]}`), "", "alarm_count=2\n", true},
		{"missing record", nil, "", "", false},
		{"unparseable record", strPtr(`not json`), "", "", false},
		{"alarms is not a list", strPtr(`{"alarms":null}`), "", "", false},
		{"jq fails and prints nothing", strPtr(`{"alarms":[]}`), "exit 3", "", false},
		{"jq prints an empty line and succeeds", strPtr(`{"alarms":[]}`), "echo", "", false},
		{"jq prints text", strPtr(`{"alarms":[]}`), "echo many", "", false},
		{"jq prints a negative number", strPtr(`{"alarms":[]}`), "echo -1", "", false},
		{"jq prints two lines", strPtr(`{"alarms":[]}`), "printf '0\\n0\\n'", "", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			temp, bin := filepath.Join(dir, "tmp"), filepath.Join(dir, "bin")
			for _, d := range []string{temp, bin} {
				if err := os.Mkdir(d, 0o755); err != nil {
					t.Fatal(err)
				}
			}
			if c.record != nil {
				if err := os.WriteFile(filepath.Join(temp, "gate-alarms.json"), []byte(*c.record), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			path := os.Getenv("PATH")
			if c.fakeJq != "" {
				if err := os.WriteFile(filepath.Join(bin, "jq"), []byte("#!/bin/sh\n"+c.fakeJq+"\n"), 0o755); err != nil {
					t.Fatal(err)
				}
				path = bin + ":" + path
			}
			out := filepath.Join(dir, "output")
			cmd := exec.Command("bash", "-c", "set -euo pipefail\nstatus=0\n"+tail)
			cmd.Env = []string{"PATH=" + path, "RUNNER_TEMP=" + temp, "GITHUB_OUTPUT=" + out}
			err := cmd.Run()
			got, _ := os.ReadFile(out)
			if (err == nil) != c.wantOK {
				t.Fatalf("step succeeded=%v, want %v (output %q)", err == nil, c.wantOK, got)
			}
			if string(got) != c.wantOut {
				t.Fatalf("GITHUB_OUTPUT = %q, want %q", got, c.wantOut)
			}
		})
	}
}
