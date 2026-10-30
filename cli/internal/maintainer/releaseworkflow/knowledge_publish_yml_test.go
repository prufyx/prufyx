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

func stepIndex(steps []workflowStep, name string) int {
	for i, s := range steps {
		if s.Name == name {
			return i
		}
	}
	return -1
}

// The oldest-supported-client gate runs after the keys are gone, before the
// upload, holds no secret, and builds a commit-pinned client.
func TestKnowledgePublishOldestClientGate(t *testing.T) {
	wf, _ := loadPublishWorkflow(t)
	steps := wf.Jobs["sign"].Steps
	signed := stepIndex(steps, "Build, sign and verify")
	read := stepIndex(steps, "Read the oldest supported client pin")
	checkout := stepIndex(steps, "Check out the oldest supported client")
	gate := stepIndex(steps, "Verify with the oldest supported client")
	upload := stepIndex(steps, "Upload the signed package")
	if signed < 0 || read < 0 || checkout < 0 || gate < 0 || upload < 0 {
		t.Fatalf("missing step: sign=%d read=%d checkout=%d gate=%d upload=%d", signed, read, checkout, gate, upload)
	}
	if !(signed < read && read < checkout && checkout < gate && gate < upload) {
		t.Errorf("step order wrong: sign=%d read=%d checkout=%d gate=%d upload=%d", signed, read, checkout, gate, upload)
	}
	for _, i := range []int{read, checkout, gate} {
		st := steps[i]
		if !strings.Contains(st.If, "steps.sign.outputs.skip == 'false'") {
			t.Errorf("%q: if %q must be limited to runs that produce a package", st.Name, st.If)
		}
		for k, v := range st.Env {
			if strings.Contains(v, "secrets.") {
				t.Errorf("%q: env %s references secrets", st.Name, k)
			}
		}
		for k, v := range st.With {
			if s, ok := v.(string); ok && strings.Contains(s, "secrets.") {
				t.Errorf("%q: with %s references secrets", st.Name, k)
			}
		}
		if strings.Contains(st.Run, "secrets.") || strings.Contains(st.Run, "github.token") || strings.Contains(st.Run, "GH_TOKEN") {
			t.Errorf("%q: run block touches a token or secret", st.Name)
		}
	}
	if steps[signed].ID != "sign" {
		t.Errorf("signing step id = %q", steps[signed].ID)
	}
	co := steps[checkout]
	if !regexp.MustCompile(`^actions/checkout@[0-9a-f]{40}$`).MatchString(co.Uses) {
		t.Errorf("oldest checkout %q is not pinned by a 40-hex SHA", co.Uses)
	}
	if v, ok := co.With["persist-credentials"].(bool); !ok || v {
		t.Error("oldest checkout must set persist-credentials: false")
	}
	if co.With["path"] != "oldest" {
		t.Errorf("oldest checkout path = %v, want oldest", co.With["path"])
	}
	if ref, _ := co.With["ref"].(string); !strings.Contains(ref, "steps.oldest.outputs.ref") {
		t.Errorf("oldest checkout ref = %q, must come from the pin file", ref)
	}
	run := steps[gate].Run
	for _, want := range []string{
		"buildidentity.Version=${OLDEST_VERSION}",
		"GOTOOLCHAIN=local",
		"db verify",
		"--expected-package-digest",
		"--expected-revision",
		"--bootstrap-root",
		"the oldest supported client (",
		"the feed keeps the last package",
	} {
		if !strings.Contains(run, want) {
			t.Errorf("gate run block lacks %q", want)
		}
	}
	if strings.Contains(run, "|| true") {
		t.Error("gate must not swallow a failure")
	}
}

var (
	oldestRefLine     = regexp.MustCompile(`^ref=([0-9a-f]{40}|v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z]+\.[0-9]+)?)$`)
	oldestVersionLine = regexp.MustCompile(`^version=v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z]+\.[0-9]+)?$`)
)

func TestOldestSupportedClientPin(t *testing.T) {
	_, self, _, _ := runtime.Caller(0)
	repo := filepath.Join(filepath.Dir(self), "..", "..", "..", "..")
	if _, err := os.Stat(filepath.Join(repo, ".github")); os.IsNotExist(err) {
		t.Skip("no .github directory: staged release source tree")
	}
	raw, err := os.ReadFile(filepath.Join(repo, "cli", "knowledge", "oldest-supported-client.txt"))
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n")
	if len(lines) != 2 || !strings.HasSuffix(string(raw), "\n") {
		t.Fatalf("pin file must hold exactly two newline-terminated lines, got %q", raw)
	}
	if !oldestRefLine.MatchString(lines[0]) {
		t.Errorf("ref line %q is not a 40-hex commit or a vX.Y.Z[-pre.N] tag", lines[0])
	}
	if !oldestVersionLine.MatchString(lines[1]) {
		t.Errorf("version line %q is not vMAJOR.MINOR.PATCH[-pre.N]", lines[1])
	}
	for _, bad := range []string{"version=0.1.0", "version=v0.1", "version=v01.1.0", "version=v0.1.0-beta", "version=v0.1.0 ", "ref=abc"} {
		if oldestVersionLine.MatchString(bad) || oldestRefLine.MatchString(bad) {
			t.Errorf("%q must not match", bad)
		}
	}
}
