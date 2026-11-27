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

// renewalSignScript returns the shell text of one step of the sign job, as the
// workflow file holds it.
func renewalSignScript(t *testing.T, name string) string {
	t.Helper()
	raw, err := os.ReadFile(renewalWorkflowPath)
	if err != nil {
		t.Fatal(err)
	}
	var wf renewalWorkflow
	if err := yaml.Unmarshal(raw, &wf); err != nil {
		t.Fatal(err)
	}
	for _, s := range wf.Jobs["sign"].Steps {
		if s.Name == name && s.Run != "" {
			return s.Run
		}
	}
	t.Fatalf("sign step %q not found", name)
	return ""
}

func writeRenewalFile(t *testing.T, path, content string, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
}

// runRenewalStep runs a step script the way the runner does, with a stand-in
// for the built CLI that records its arguments (and a stand-in for jq). It
// returns the recorded arguments, empty when the CLI was never run.
func runRenewalStep(t *testing.T, script, temp, pmBody string) (args, outputs, log string, err error) {
	t.Helper()
	work, bin := t.TempDir(), t.TempDir()
	record := filepath.Join(temp, "pm.args")
	writeRenewalFile(t, filepath.Join(temp, "prufyx-maintainer"), "#!/bin/sh\nprintf '%s\\n' \"$@\" > \""+record+"\"\n"+pmBody, 0o700)
	writeRenewalFile(t, filepath.Join(bin, "jq"), "#!/bin/sh\necho 0001\n", 0o700)
	file := filepath.Join(bin, "step.sh")
	writeRenewalFile(t, file, script, 0o600)
	outputPath := filepath.Join(bin, "github-output")
	writeRenewalFile(t, outputPath, "", 0o600)
	cmd := exec.Command("bash", "--noprofile", "--norc", "-e", file)
	cmd.Dir = work
	cmd.Env = []string{
		"PATH=" + bin + string(os.PathListSeparator) + os.Getenv("PATH"),
		"RUNNER_TEMP=" + temp, "GITHUB_OUTPUT=" + outputPath, "PACK=cncf",
		"REATTEST_TRUST_ROOT_DIGEST=sha256:test",
	}
	combined, err := cmd.CombinedOutput()
	got, readErr := os.ReadFile(record)
	if readErr != nil && !os.IsNotExist(readErr) {
		t.Fatal(readErr)
	}
	out, readErr := os.ReadFile(outputPath)
	if readErr != nil {
		t.Fatal(readErr)
	}
	return string(got), string(out), string(combined), err
}

func TestRenewalSignVerifyNeedsItsOwnWorklist(t *testing.T) {
	t.Parallel()
	script := renewalSignScript(t, renewalVerifyStep)
	const prepared = `{"generatedAt":"2026-01-01T00:00:00Z"}`
	const independent = `{"generatedAt":"2026-01-01T00:05:00Z"}`
	must := func(t *testing.T, err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	cases := []struct {
		name  string
		setup func(t *testing.T, preparedPath, rerunPath string)
		ok    bool
	}{
		{"independent worklist", func(t *testing.T, _, r string) { writeRenewalFile(t, r, independent, 0o600) }, true},
		{"missing", func(*testing.T, string, string) {}, false},
		{"empty", func(t *testing.T, _, r string) { writeRenewalFile(t, r, "", 0o600) }, false},
		{"directory", func(t *testing.T, _, r string) { must(t, os.Mkdir(r, 0o700)) }, false},
		{"copy of the prepared worklist", func(t *testing.T, _, r string) { writeRenewalFile(t, r, prepared, 0o600) }, false},
		{"symlink to the prepared worklist", func(t *testing.T, p, r string) { must(t, os.Symlink(p, r)) }, false},
		{"symlink to another file", func(t *testing.T, p, r string) {
			writeRenewalFile(t, p+".other", independent, 0o600)
			must(t, os.Symlink(p+".other", r))
		}, false},
		{"hard link to the prepared worklist", func(t *testing.T, p, r string) { must(t, os.Link(p, r)) }, false},
		{"comparison cannot run", func(t *testing.T, p, r string) {
			writeRenewalFile(t, r, independent, 0o600)
			must(t, os.Remove(p))
		}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			temp := t.TempDir()
			preparedPath := filepath.Join(temp, "prepared", "worklist.json")
			rerunPath := filepath.Join(temp, "rerun-worklist.json")
			writeRenewalFile(t, preparedPath, prepared, 0o600)
			writeRenewalFile(t, filepath.Join(temp, "prepared", "statement.json"), "{}", 0o600)
			writeRenewalFile(t, filepath.Join(temp, "signed", "statement.sig.json"), "{}", 0o600)
			tc.setup(t, preparedPath, rerunPath)
			args, outputs, log, err := runRenewalStep(t, script, temp, "exit 0\n")
			if tc.ok {
				if err != nil {
					t.Fatalf("refused: %v\n%s", err, log)
				}
				for _, want := range []string{"--worklist\n" + preparedPath + "\n", "--rerun-worklist\n" + rerunPath + "\n"} {
					if !strings.Contains(args, want) {
						t.Fatalf("arguments lack %q:\n%s", want, args)
					}
				}
				if !strings.Contains(outputs, "signed=true") {
					t.Fatalf("no signed output: %q", outputs)
				}
				return
			}
			if err == nil || args != "" || strings.Contains(outputs, "signed=true") {
				t.Fatalf("not refused before verify: err=%v args=%q outputs=%q\n%s", err, args, outputs, log)
			}
		})
	}
	t.Run("verify failure", func(t *testing.T) {
		t.Parallel()
		temp := t.TempDir()
		writeRenewalFile(t, filepath.Join(temp, "prepared", "worklist.json"), prepared, 0o600)
		writeRenewalFile(t, filepath.Join(temp, "prepared", "statement.json"), "{}", 0o600)
		writeRenewalFile(t, filepath.Join(temp, "signed", "statement.sig.json"), "{}", 0o600)
		writeRenewalFile(t, filepath.Join(temp, "rerun-worklist.json"), independent, 0o600)
		args, outputs, log, err := runRenewalStep(t, script, temp, "exit 1\n")
		if err == nil || args == "" || strings.Contains(outputs, "signed=true") {
			t.Fatalf("a failed verify passed: err=%v outputs=%q\n%s", err, outputs, log)
		}
	})
}

func TestRenewalSignRepinFailsClosed(t *testing.T) {
	t.Parallel()
	script := renewalSignScript(t, renewalRepinStep)
	// The stand-in writes to the value of --output, the last argument.
	const target = "for a in \"$@\"; do out=\"$a\"; done\n"
	for name, tc := range map[string]struct {
		body string
		ok   bool
	}{
		"writes a worklist":    {target + "echo fresh > \"$out\"\n", true},
		"fails":                {"exit 1\n", false},
		"fails after writing":  {target + "echo partial > \"$out\"\nexit 1\n", false},
		"writes nothing":       {"exit 0\n", false},
		"writes an empty file": {target + ": > \"$out\"\n", false},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			temp := t.TempDir()
			rerunPath := filepath.Join(temp, "rerun-worklist.json")
			// A file left at the path must never satisfy the step.
			writeRenewalFile(t, rerunPath, "stale", 0o600)
			args, _, log, err := runRenewalStep(t, script, temp, tc.body)
			if (err == nil) != tc.ok {
				t.Fatalf("ok=%v, err=%v\n%s", tc.ok, err, log)
			}
			if !strings.HasPrefix(args, "evidence\nrepin\n") || !strings.HasSuffix(args, "--output\n"+rerunPath+"\n") {
				t.Fatalf("unexpected arguments:\n%s", args)
			}
		})
	}
}
