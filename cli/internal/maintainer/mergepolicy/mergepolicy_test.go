// SPDX-License-Identifier: AGPL-3.0-only

package mergepolicy

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

const repoRoot = "../../../.."

func read(t *testing.T, rel string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(repoRoot, rel))
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

type wf struct {
	On   map[string]any `yaml:"on"`
	Jobs map[string]struct {
		Steps []struct {
			Name string            `yaml:"name"`
			If   string            `yaml:"if"`
			Run  string            `yaml:"run"`
			Env  map[string]string `yaml:"env"`
		} `yaml:"steps"`
	} `yaml:"jobs"`
}

func TestWorkflowShape(t *testing.T) {
	for _, f := range []string{".github/workflows/ci.yml", ".github/workflows/merge-policy.yml"} {
		var w wf
		if err := yaml.Unmarshal(read(t, f), &w); err != nil {
			t.Fatal(err)
		}
		mg, ok := w.On["merge_group"].(map[string]any)
		if !ok {
			t.Fatalf("%s: merge_group trigger missing", f)
		}
		if fmt.Sprint(mg["types"]) != "[checks_requested]" {
			t.Fatalf("%s: merge_group types = %v", f, mg["types"])
		}
		inj := regexp.MustCompile(`\$\{\{`)
		for name, job := range w.Jobs {
			for _, s := range job.Steps {
				if inj.MatchString(s.Run) {
					t.Fatalf("%s: job %s step %q interpolates an expression into run", f, name, s.Name)
				}
			}
		}
	}
	var w wf
	if err := yaml.Unmarshal(read(t, ".github/workflows/merge-policy.yml"), &w); err != nil {
		t.Fatal(err)
	}
	steps := w.Jobs["merge-policy"].Steps
	if len(steps) == 0 {
		t.Fatal("no steps")
	}
	last := steps[len(steps)-1]
	want := "github.event_name != 'pull_request' && github.event_name != 'push' && github.event_name != 'merge_group'"
	if last.If != want || !strings.Contains(last.Run, "exit 1") {
		t.Fatalf("final step must fail closed on unknown events, got if=%q", last.If)
	}
	found := false
	for _, s := range steps {
		if s.If == "github.event_name == 'merge_group'" && strings.Contains(s.Run, "scripts/merge-policy-queue.sh") {
			found = true
		}
		if s.If == "" {
			t.Fatalf("step %q has no condition", s.Name)
		}
	}
	if !found {
		t.Fatal("merge_group policy step missing")
	}
}

func git(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@example.invalid",
		"GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@example.invalid", "GIT_CONFIG_GLOBAL=/dev/null")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

type scenario struct {
	dir, bin                     string
	base, x, queue, ref, mainTip string
	json                         string
	env                          map[string]string
}

func commit(t *testing.T, dir, name string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(name), 0o644); err != nil {
		t.Fatal(err)
	}
	git(t, dir, "add", name)
	git(t, dir, "commit", "-qm", name)
}

// newScenario builds origin (main) and a work clone holding a queue commit:
// a merge of a two-commit topic branch onto the main tip.
func newScenario(t *testing.T) *scenario {
	t.Helper()
	root := t.TempDir()
	origin := filepath.Join(root, "origin.git")
	git(t, root, "init", "-q", "--bare", "-b", "main", origin)
	work := filepath.Join(root, "work")
	git(t, root, "clone", "-q", origin, work)
	git(t, work, "checkout", "-q", "-b", "main")
	commit(t, work, "a")
	commit(t, work, "b")
	git(t, work, "push", "-q", "origin", "main")
	base := git(t, work, "rev-parse", "HEAD")
	git(t, work, "checkout", "-q", "-b", "topic")
	commit(t, work, "c")
	commit(t, work, "d")
	x := git(t, work, "rev-parse", "HEAD")
	git(t, work, "checkout", "-q", "--detach", base)
	git(t, work, "merge", "-q", "--no-ff", "-m", "queue", x)
	queue := git(t, work, "rev-parse", "HEAD")
	ref := "refs/heads/gh-readonly-queue/main/pr-7-" + queue
	bin := filepath.Join(root, "bin")
	if err := os.Mkdir(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	stub := "#!/bin/sh\nif [ -n \"$GH_FAIL\" ]; then exit 1; fi\nprintf '%s' \"$GH_JSON\"\n"
	if err := os.WriteFile(filepath.Join(bin, "gh"), []byte(stub), 0o755); err != nil {
		t.Fatal(err)
	}
	s := &scenario{dir: work, bin: bin, base: base, x: x, queue: queue, ref: ref, mainTip: base}
	s.json = fmt.Sprintf(`{"state":"open","base":{"ref":"main"},"head":{"ref":"topic","sha":"%s"},"commits":2}`, x)
	s.env = map[string]string{
		"QUEUE_REF": ref, "QUEUE_SHA": queue, "MQ_BASE_REF": "refs/heads/main",
		"MQ_BASE_SHA": base, "MQ_HEAD_REF": ref, "MQ_HEAD_SHA": queue, "REPO": "o/r",
	}
	return s
}

func (s *scenario) run(t *testing.T) (string, error) {
	t.Helper()
	script, err := filepath.Abs(filepath.Join(repoRoot, "scripts", "merge-policy-queue.sh"))
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("bash", script)
	cmd.Dir = s.dir
	cmd.Env = []string{"PATH=" + s.bin + ":" + os.Getenv("PATH"), "HOME=" + s.dir, "GIT_CONFIG_GLOBAL=/dev/null", "GH_JSON=" + s.json}
	for k, v := range s.env {
		cmd.Env = append(cmd.Env, k+"="+v)
	}
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func TestQueuePositive(t *testing.T) {
	s := newScenario(t)
	git(t, s.dir, "checkout", "-q", "--detach", s.queue)
	if out, err := s.run(t); err != nil {
		t.Fatalf("positive case failed: %v\n%s", err, out)
	}
}

var wantMsg = map[string]string{
	"wrong ref shape":     "queue ref shape",
	"sha differs":         "not the merge_group head",
	"base ref not main":   "base_ref",
	"missing input":       "missing input",
	"one parent":          "exactly 2 parents",
	"parent1 not base":    "first parent",
	"head not X":          "second parent",
	"pr closed":           "not open",
	"pr base not main":    "not main",
	"head ref is main":    "topic branch",
	"commit count":        "by the API",
	"unresolved pr":       "cannot read pull request",
	"empty api payload":   "missing",
	"merge inside pr":     "merge commits",
	"base lacks main tip": "main tip",
}

func TestQueueNegative(t *testing.T) {
	cases := map[string]func(t *testing.T, s *scenario){
		"wrong ref shape": func(t *testing.T, s *scenario) {
			s.env["QUEUE_REF"] = "refs/heads/feature"
			s.env["MQ_HEAD_REF"] = "refs/heads/feature"
		},
		"sha differs":       func(t *testing.T, s *scenario) { s.env["QUEUE_SHA"] = s.base },
		"base ref not main": func(t *testing.T, s *scenario) { s.env["MQ_BASE_REF"] = "refs/heads/dev" },
		"missing input":     func(t *testing.T, s *scenario) { delete(s.env, "REPO") },
		"one parent": func(t *testing.T, s *scenario) {
			git(t, s.dir, "checkout", "-q", "--detach", s.x)
			s.env["QUEUE_SHA"], s.env["MQ_HEAD_SHA"] = s.x, s.x
		},
		"parent1 not base": func(t *testing.T, s *scenario) {
			s.env["MQ_BASE_SHA"] = git(t, s.dir, "rev-parse", s.base+"~1")
		},
		"head not X": func(t *testing.T, s *scenario) { s.json = strings.Replace(s.json, s.x, strings.Repeat("0", 40), 1) },
		"pr closed":  func(t *testing.T, s *scenario) { s.json = strings.Replace(s.json, `"open"`, `"closed"`, 1) },
		"pr base not main": func(t *testing.T, s *scenario) {
			s.json = strings.Replace(s.json, `"base":{"ref":"main"}`, `"base":{"ref":"dev"}`, 1)
		},
		"head ref is main":  func(t *testing.T, s *scenario) { s.json = strings.Replace(s.json, `"ref":"topic"`, `"ref":"main"`, 1) },
		"commit count":      func(t *testing.T, s *scenario) { s.json = strings.Replace(s.json, `"commits":2`, `"commits":3`, 1) },
		"unresolved pr":     func(t *testing.T, s *scenario) { s.env["GH_FAIL"] = "1" },
		"empty api payload": func(t *testing.T, s *scenario) { s.json = "" },
		"merge inside pr": func(t *testing.T, s *scenario) {
			// topic gets a merge commit of a side branch.
			git(t, s.dir, "checkout", "-q", "-b", "side", s.base)
			commit(t, s.dir, "e")
			git(t, s.dir, "checkout", "-q", "topic")
			git(t, s.dir, "merge", "-q", "--no-ff", "-m", "m", "side")
			x := git(t, s.dir, "rev-parse", "HEAD")
			git(t, s.dir, "checkout", "-q", "--detach", s.base)
			git(t, s.dir, "merge", "-q", "--no-ff", "-m", "queue2", x)
			q := git(t, s.dir, "rev-parse", "HEAD")
			s.env["QUEUE_SHA"], s.env["MQ_HEAD_SHA"] = q, q
			ref := "refs/heads/gh-readonly-queue/main/pr-7-" + q
			s.env["QUEUE_REF"], s.env["MQ_HEAD_REF"] = ref, ref
			s.json = fmt.Sprintf(`{"state":"open","base":{"ref":"main"},"head":{"ref":"topic","sha":"%s"},"commits":4}`, x)
		},
		"base lacks main tip": func(t *testing.T, s *scenario) {
			// main advances after the queue chain was built.
			git(t, s.dir, "checkout", "-q", "main")
			commit(t, s.dir, "newer")
			git(t, s.dir, "push", "-q", "origin", "main")
			git(t, s.dir, "checkout", "-q", "--detach", s.queue)
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			s := newScenario(t)
			git(t, s.dir, "checkout", "-q", "--detach", s.queue)
			mutate(t, s)
			out, err := s.run(t)
			if err == nil {
				t.Fatalf("expected failure, got success:\n%s", out)
			}
			if !strings.Contains(out, wantMsg[name]) {
				t.Fatalf("failed for another reason (want %q):\n%s", wantMsg[name], out)
			}
		})
	}
}
