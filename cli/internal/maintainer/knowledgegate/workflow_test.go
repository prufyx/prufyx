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

var workflowPath = filepath.Join(repoRoot, ".github", "workflows", "knowledge-gate.yml")

type workflow struct {
	On          map[string]any    `yaml:"on"`
	Permissions map[string]string `yaml:"permissions"`
	Jobs        map[string]struct {
		Permissions map[string]string `yaml:"permissions"`
		Steps       []struct {
			Name             string            `yaml:"name"`
			Uses             string            `yaml:"uses"`
			Run              string            `yaml:"run"`
			With             map[string]any    `yaml:"with"`
			Env              map[string]string `yaml:"env"`
			WorkingDirectory string            `yaml:"working-directory"`
		} `yaml:"steps"`
	} `yaml:"jobs"`
}

// TestWorkflowShape pins the properties the gate's safety rests on: the
// gate is built from the base checkout only, the proposed change is
// checked out without credentials and never built or run, the token is
// read-only, every action is pinned by commit, and nothing merges.
func TestWorkflowShape(t *testing.T) {
	raw, err := os.ReadFile(workflowPath)
	if err != nil {
		t.Fatal(err)
	}
	var wf workflow
	if err := yaml.Unmarshal(raw, &wf); err != nil {
		t.Fatal(err)
	}
	if _, ok := wf.On["pull_request_target"]; !ok {
		t.Fatal("the gate must run its base-branch definition (pull_request_target)")
	}
	if _, ok := wf.On["pull_request"]; ok {
		t.Fatal("pull_request would run the change's own workflow definition")
	}
	if len(wf.Permissions) != 1 || wf.Permissions["contents"] != "read" {
		t.Fatalf("permissions %v, want contents: read only", wf.Permissions)
	}
	if strings.Contains(string(raw), "secrets.") {
		t.Fatal("the gate must not use secrets")
	}
	for _, forbidden := range []string{"gh pr merge", "--auto", "pulls/merge", "enable-auto-merge"} {
		if strings.Contains(string(raw), forbidden) {
			t.Fatalf("the workflow must not merge (%q)", forbidden)
		}
	}
	job, ok := wf.Jobs["gate"]
	if !ok {
		t.Fatal("no gate job")
	}
	if len(job.Permissions) != 0 {
		t.Fatal("the job must not widen permissions")
	}
	sawBuild := false
	for _, s := range job.Steps {
		if s.Uses != "" {
			at := strings.Index(s.Uses, "@")
			if at < 0 || len(s.Uses[at+1:]) < 40 {
				t.Fatalf("%s: action not pinned by commit", s.Name)
			}
		}
		if strings.HasPrefix(s.Uses, "actions/checkout@") {
			if s.With["persist-credentials"] != false {
				t.Fatalf("%s: checkout must not persist credentials", s.Name)
			}
		}
		if strings.HasPrefix(s.Uses, "actions/setup-go@") && s.With["cache"] != false {
			t.Fatal("setup-go caching must be off (a change could poison it)")
		}
		if strings.Contains(s.Run, "go build") || strings.Contains(s.Run, "go run") || strings.Contains(s.Run, "go test") {
			if s.WorkingDirectory != "base/cli" {
				t.Fatalf("%s: builds outside the base checkout", s.Name)
			}
			sawBuild = true
		}
		if strings.Contains(s.WorkingDirectory, "head") || strings.Contains(s.Run, "head/cli/") || strings.Contains(s.Run, "./head") {
			t.Fatalf("%s: executes or builds from the proposed change", s.Name)
		}
		if strings.Contains(s.Run, "${{") {
			t.Fatalf("%s: expressions must reach scripts through env, never inline", s.Name)
		}
	}
	if !sawBuild {
		t.Fatal("the workflow never builds the gate")
	}
}

// TestWorkflowLint runs actionlint when it is installed.
func TestWorkflowLint(t *testing.T) {
	bin, err := exec.LookPath("actionlint")
	if err != nil {
		t.Skip("actionlint is not installed")
	}
	out, err := exec.Command(bin, workflowPath).CombinedOutput()
	if err != nil {
		t.Fatalf("actionlint: %v\n%s", err, out)
	}
}
