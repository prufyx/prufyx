// SPDX-License-Identifier: AGPL-3.0-only

package releaseworkflow

import (
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

type publishJob struct {
	If          string            `yaml:"if"`
	Environment any               `yaml:"environment"`
	Permissions map[string]string `yaml:"permissions"`
	Steps       []workflowStep    `yaml:"steps"`
}

type publishWorkflow struct {
	On          map[string]any        `yaml:"on"`
	Permissions map[string]string     `yaml:"permissions"`
	Jobs        map[string]publishJob `yaml:"jobs"`
}

func loadPublishWorkflow(t *testing.T) (publishWorkflow, string) {
	t.Helper()
	_, self, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate the test source")
	}
	repo := filepath.Join(filepath.Dir(self), "..", "..", "..", "..")
	if _, err := os.Stat(filepath.Join(repo, ".github")); os.IsNotExist(err) {
		t.Skip("no .github directory: staged release source tree")
	}
	raw, err := os.ReadFile(filepath.Join(repo, ".github", "workflows", "knowledge-publish.yml"))
	if err != nil {
		t.Fatal(err)
	}
	var wf publishWorkflow
	if err := yaml.Unmarshal(raw, &wf); err != nil {
		t.Fatal(err)
	}
	return wf, string(raw)
}

func samePermissions(got, want map[string]string) bool {
	if len(got) != len(want) {
		return false
	}
	for k, v := range want {
		if got[k] != v {
			return false
		}
	}
	return true
}

// The publish workflow holds the online TUF keys in one job and the Pages
// deploy token in another; these properties keep the two apart.
func TestKnowledgePublishWorkflowIsHardened(t *testing.T) {
	wf, raw := loadPublishWorkflow(t)
	if wf.Permissions == nil || len(wf.Permissions) != 0 {
		t.Errorf("top-level permissions = %v, want {}", wf.Permissions)
	}
	if _, ok := wf.On["pull_request"]; ok {
		t.Error("must not trigger on pull_request")
	}
	if _, ok := wf.On["pull_request_target"]; ok {
		t.Error("must not trigger on pull_request_target")
	}
	sign, deploy := wf.Jobs["sign"], wf.Jobs["deploy"]
	if len(wf.Jobs) != 2 {
		t.Errorf("jobs = %d, want sign and deploy", len(wf.Jobs))
	}
	if env, _ := sign.Environment.(string); env != "knowledge-release" {
		t.Errorf("sign environment = %v, want knowledge-release", sign.Environment)
	}
	for _, want := range []string{"refs/heads/main", "KNOWLEDGE_RELEASE_ENABLED"} {
		if !strings.Contains(sign.If, want) {
			t.Errorf("sign if %q lacks %s", sign.If, want)
		}
	}
	if !samePermissions(sign.Permissions, map[string]string{"contents": "read", "actions": "read"}) {
		t.Errorf("sign permissions = %v", sign.Permissions)
	}
	if !samePermissions(deploy.Permissions, map[string]string{"pages": "write", "id-token": "write", "actions": "read", "contents": "read"}) {
		t.Errorf("deploy permissions = %v", deploy.Permissions)
	}
	for name, job := range wf.Jobs {
		for _, step := range job.Steps {
			switch {
			case strings.HasPrefix(step.Uses, "actions/setup-go@"):
				if v, ok := step.With["cache"].(bool); !ok || v {
					t.Errorf("%s: setup-go must set cache: false", name)
				}
			case strings.HasPrefix(step.Uses, "actions/checkout@"):
				if v, ok := step.With["persist-credentials"].(bool); !ok || v {
					t.Errorf("%s: checkout must set persist-credentials: false", name)
				}
			case strings.HasPrefix(step.Uses, "actions/cache"):
				t.Errorf("%s: must not use actions/cache", name)
			}
		}
	}
	pinned := regexp.MustCompile(`^[A-Za-z0-9._-]+/[A-Za-z0-9._/-]+@[0-9a-f]{40}$`)
	for name, job := range wf.Jobs {
		for _, step := range job.Steps {
			if step.Uses != "" && !pinned.MatchString(step.Uses) {
				t.Errorf("%s: action %q is not pinned by a 40-hex commit SHA", name, step.Uses)
			}
			if name == "deploy" {
				for _, v := range step.Env {
					if strings.Contains(v, "secrets.") {
						t.Error("deploy must not reference secrets")
					}
				}
				for _, v := range step.With {
					if s, ok := v.(string); ok && strings.Contains(s, "secrets.") {
						t.Error("deploy must not reference secrets")
					}
				}
			}
		}
	}
	// The previous-state digest is passed to `db verify` with its prefix.
	if !strings.Contains(raw, `expected_digest="sha256:${aname##*-}"`) {
		t.Error("the artifact-name digest must be passed to db verify as sha256:<hex>")
	}
}
