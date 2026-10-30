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

// The dry-run workflow (.github/workflows/release-dry-run.yml) runs the step
// bodies of release.yml on pull requests. It is public and runs on code from
// pull requests, so these tests pin that it can reach nothing a release can:
// no tag trigger, a read-only token, no secrets, no upload or attestation.

type dryRunWorkflow struct {
	On          map[string]any    `yaml:"on"`
	Permissions map[string]string `yaml:"permissions"`
	Jobs        map[string]struct {
		Environment any               `yaml:"environment"`
		Permissions map[string]string `yaml:"permissions"`
		Steps       []workflowStep    `yaml:"steps"`
	} `yaml:"jobs"`
}

func repoRootForTest(t *testing.T) string {
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

func loadDryRun(t *testing.T) (dryRunWorkflow, string, string) {
	t.Helper()
	repo := repoRootForTest(t)
	raw, err := os.ReadFile(filepath.Join(repo, ".github", "workflows", "release-dry-run.yml"))
	if err != nil {
		t.Fatal(err)
	}
	var wf dryRunWorkflow
	if err := yaml.Unmarshal(raw, &wf); err != nil {
		t.Fatal(err)
	}
	return wf, string(raw), repo
}

func TestReleaseDryRunWorkflowIsLeastPrivilege(t *testing.T) {
	wf, raw, _ := loadDryRun(t)

	if len(wf.On) != 2 {
		t.Errorf("triggers = %v, want pull_request and workflow_dispatch only", wf.On)
	}
	pr, ok := wf.On["pull_request"].(map[string]any)
	if !ok {
		t.Fatal("must trigger on pull_request")
	}
	if _, ok := wf.On["workflow_dispatch"]; !ok {
		t.Error("must trigger on workflow_dispatch")
	}
	for _, bad := range []string{"push", "pull_request_target", "schedule", "release", "create", "workflow_run"} {
		if _, ok := wf.On[bad]; ok {
			t.Errorf("must not trigger on %s", bad)
		}
	}
	paths := map[string]bool{}
	list, _ := pr["paths"].([]any)
	for _, p := range list {
		s, _ := p.(string)
		paths[s] = true
	}
	for _, want := range []string{
		".github/workflows/release.yml",
		".github/workflows/release-dry-run.yml",
		"cli/docs/releasing.md",
		"scripts/release-dry-run.sh",
	} {
		if !paths[want] {
			t.Errorf("pull_request paths lack %s", want)
		}
	}

	read := map[string]string{"contents": "read"}
	if !samePermissions(wf.Permissions, read) {
		t.Errorf("top-level permissions = %v, want contents: read only", wf.Permissions)
	}
	if len(wf.Jobs) == 0 {
		t.Fatal("no jobs")
	}
	pinned := regexp.MustCompile(`^[A-Za-z0-9._-]+/[A-Za-z0-9._/-]+@[0-9a-f]{40}$`)
	goVersion := ""
	for name, job := range wf.Jobs {
		if !samePermissions(job.Permissions, read) {
			t.Errorf("%s: permissions = %v, want contents: read only", name, job.Permissions)
		}
		if job.Environment != nil {
			t.Errorf("%s: must not use an environment", name)
		}
		for _, step := range job.Steps {
			if step.Uses != "" && !pinned.MatchString(step.Uses) {
				t.Errorf("%s: action %q is not pinned by a 40-hex commit SHA", name, step.Uses)
			}
			switch {
			case strings.HasPrefix(step.Uses, "actions/setup-go@"):
				if v, ok := step.With["cache"].(bool); !ok || v {
					t.Errorf("%s: setup-go must set cache: false", name)
				}
				goVersion, _ = step.With["go-version"].(string)
			case strings.HasPrefix(step.Uses, "actions/checkout@"):
				if v, ok := step.With["persist-credentials"].(bool); !ok || v {
					t.Errorf("%s: checkout must set persist-credentials: false", name)
				}
			case step.Uses != "":
				t.Errorf("%s: unexpected action %q (only checkout and setup-go)", name, step.Uses)
			}
		}
	}
	if secretsRef.MatchString(raw) {
		t.Error("must not reference secrets")
	}
	for _, bad := range []string{"id-token", "attestations", "contents: write", "gh release", "gh attestation", "upload-artifact", "attest-build-provenance", "refs/tags", "GITHUB_TOKEN", "github.token"} {
		if strings.Contains(raw, bad) {
			t.Errorf("must not contain %q", bad)
		}
	}

	// The dry run uses the Go release the release workflow pins.
	var rel struct {
		Jobs map[string]struct {
			Steps []workflowStep `yaml:"steps"`
		} `yaml:"jobs"`
	}
	relRaw, err := os.ReadFile(filepath.Join(repoRootForTest(t), ".github", "workflows", "release.yml"))
	if err != nil {
		t.Fatal(err)
	}
	if err := yaml.Unmarshal(relRaw, &rel); err != nil {
		t.Fatal(err)
	}
	want := ""
	for _, s := range rel.Jobs["build"].Steps {
		if strings.HasPrefix(s.Uses, "actions/setup-go@") {
			want, _ = s.With["go-version"].(string)
		}
	}
	if want == "" || goVersion != want {
		t.Errorf("dry run go-version = %q, release.yml pins %q", goVersion, want)
	}
}

// The script is what runs on the pull request. It must run the dry-run
// script, never a copy of the release steps, and every step it extracts must
// exist in release.yml.
func TestReleaseDryRunScriptExtractsExistingReleaseSteps(t *testing.T) {
	wf, _, repo := loadDryRun(t)
	ran := false
	for _, job := range wf.Jobs {
		for _, step := range job.Steps {
			if strings.Contains(step.Run, "scripts/release-dry-run.sh") {
				ran = true
			}
		}
	}
	if !ran {
		t.Error("no step runs scripts/release-dry-run.sh")
	}

	scriptRaw, err := os.ReadFile(filepath.Join(repo, "scripts", "release-dry-run.sh"))
	if err != nil {
		t.Fatal(err)
	}
	script := string(scriptRaw)
	var code []string
	for _, line := range strings.Split(script, "\n") {
		if !strings.HasPrefix(strings.TrimSpace(line), "#") {
			code = append(code, line)
		}
	}
	for _, bad := range []*regexp.Regexp{
		regexp.MustCompile(`git (push|tag)\b`),
		regexp.MustCompile(`(^|[\s;|&(])gh\s`),
		regexp.MustCompile(`attest|upload|secrets|id-token|GITHUB_TOKEN`),
	} {
		if bad.MatchString(strings.Join(code, "\n")) {
			t.Errorf("dry-run script code must not match %s", bad)
		}
	}
	var rel workflowFile
	relRaw, err := os.ReadFile(filepath.Join(repo, ".github", "workflows", "release.yml"))
	if err != nil {
		t.Fatal(err)
	}
	if err := yaml.Unmarshal(relRaw, &rel); err != nil {
		t.Fatal(err)
	}
	calls := regexp.MustCompile(`step_script (\w+) "([^"]+)"`).FindAllStringSubmatch(script, -1)
	if len(calls) < 5 {
		t.Fatalf("script extracts %d release steps, want the tag, pin, freshness, build, packages and checksum steps", len(calls))
	}
	need := map[string]bool{
		"build/Check the tag":                         false,
		"build/Check the knowledge root pin":          false,
		"build/Check the embedded knowledge is fresh": false,
		"build/Build binaries":                        false,
		"packages/Build packages":                     false,
		"provenance/Generate SHA256SUMS":              false,
	}
	for _, c := range calls {
		found := false
		for _, s := range rel.Jobs[c[1]].Steps {
			if s.Name == c[2] && s.Run != "" {
				found = true
			}
		}
		if !found {
			t.Errorf("release.yml has no run step %q in job %s", c[2], c[1])
		}
		need[c[1]+"/"+c[2]] = true
	}
	for k, seen := range need {
		if !seen {
			t.Errorf("the dry run does not execute release step %s", k)
		}
	}
}

// The freshness row is a warning on pull requests (the merge commit is dated
// now, so expiring evidence would fail every unrelated pull request) and a
// failure on workflow_dispatch, the pre-tag check. A WARN must not fail the run.
func TestReleaseDryRunFreshnessSplitsOnTrigger(t *testing.T) {
	_, _, repo := loadDryRun(t)
	raw, err := os.ReadFile(filepath.Join(repo, "scripts", "release-dry-run.sh"))
	if err != nil {
		t.Fatal(err)
	}
	script := string(raw)
	split := regexp.MustCompile(`(?s)if \[ "\$\{GITHUB_EVENT_NAME:-\}" = pull_request \]; then\s+record "freshness gate[^\n]*" WARN [^\n]*\n\s+echo "::warning[^\n]*\n\s+else\s+record "freshness gate[^\n]*" FAIL`)
	if !split.MatchString(script) {
		t.Error("the freshness row must be WARN on pull_request and FAIL otherwise")
	}
	if !strings.Contains(script, `[ "$2" = PASS ] || [ "$2" = WARN ] || failed=1`) {
		t.Error("only FAIL may fail the run; WARN must not")
	}
}
