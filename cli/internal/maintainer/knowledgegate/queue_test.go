// SPDX-License-Identifier: AGPL-3.0-only

package knowledgegate

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const (
	qBase = "1111111111111111111111111111111111111111"
	qPR   = "2222222222222222222222222222222222222222"
	qHead = "3333333333333333333333333333333333333333"
)

func qRef(n string) string { return "refs/heads/gh-readonly-queue/main/pr-" + n + "-" + qHead }

func qPRJSON(mod func(m map[string]any)) []byte {
	m := map[string]any{
		"number": 42, "state": "open",
		"user":   map[string]any{"login": "alice"},
		"labels": []any{map[string]any{"name": "shadow"}},
		"head":   map[string]any{"sha": qPR, "repo": map[string]any{"full_name": "prufyx/prufyx"}},
		"base":   map[string]any{"ref": "main", "repo": map[string]any{"full_name": "prufyx/prufyx"}},
	}
	if mod != nil {
		mod(m)
	}
	b, _ := json.Marshal(m)
	return b
}

func qInput() QueueInput {
	return QueueInput{
		Repo: "prufyx/prufyx", Ref: qRef("42"), RunSHA: qHead, HeadRef: qRef("42"), HeadSHA: qHead,
		BaseRef: "refs/heads/main", BaseSHA: qBase, Parents: []string{qBase, qPR},
		PRJSON: qPRJSON(nil), Changed: []string{"cli/knowledge/x.json"},
	}
}

func TestParseQueueRefRejects(t *testing.T) {
	t.Parallel()
	for _, ref := range []string{
		"", "refs/heads/main", "refs/heads/gh-readonly-queue/main/pr-42",
		"refs/heads/gh-readonly-queue/main/pr-42-abc",
		"refs/heads/gh-readonly-queue/main/pr-42-" + strings.Repeat("A", 40),
		"refs/heads/gh-readonly-queue/main/pr-042-" + qHead,
		"refs/heads/gh-readonly-queue/main/pr-0-" + qHead,
		"refs/heads/gh-readonly-queue/main/pr-4294967296000-" + qHead,
		"refs/heads/gh-readonly-queue/other/pr-42-" + qHead,
		"refs/heads/gh-readonly-queue/main/pr-42-" + qHead + "\n",
		"refs/heads/gh-readonly-queue/main/pr-42-" + qHead + "/x",
		"refs/heads/gh-readonly-queue/main/pr-1-pr-2-" + qHead,
		"gh-readonly-queue/main/pr-42-" + qHead,
	} {
		if _, _, err := ParseQueueRef(ref); err == nil {
			t.Errorf("accepted %q", ref)
		}
	}
	pr, sha, err := ParseQueueRef(qRef("42"))
	if err != nil || pr != 42 || sha != qHead {
		t.Fatalf("got %d %s %v", pr, sha, err)
	}
}

func TestVerifyQueueFailsClosed(t *testing.T) {
	t.Parallel()
	third := "4444444444444444444444444444444444444444"
	cases := map[string]func(in *QueueInput){
		"two pull requests (first parent is not the base)": func(in *QueueInput) { in.Parents = []string{third, qPR} },
		"three parents":                    func(in *QueueInput) { in.Parents = []string{qBase, qPR, third} },
		"one parent":                       func(in *QueueInput) { in.Parents = []string{qBase} },
		"no parents":                       func(in *QueueInput) { in.Parents = nil },
		"malformed ref":                    func(in *QueueInput) { in.Ref = "refs/heads/gh-readonly-queue/main/pr-x"; in.HeadRef = in.Ref },
		"head_ref differs from ref":        func(in *QueueInput) { in.HeadRef = qRef("43") },
		"ref names another commit":         func(in *QueueInput) { in.HeadSHA = third; in.RunSHA = third },
		"run sha is not the head":          func(in *QueueInput) { in.RunSHA = third },
		"base ref is not main":             func(in *QueueInput) { in.BaseRef = "refs/heads/dev" },
		"short base":                       func(in *QueueInput) { in.BaseSHA = "abc" },
		"missing repo":                     func(in *QueueInput) { in.Repo = "" },
		"api error: empty payload":         func(in *QueueInput) { in.PRJSON = nil },
		"api error: error object":          func(in *QueueInput) { in.PRJSON = []byte(`{"message":"Server Error"}`) },
		"api payload not json":             func(in *QueueInput) { in.PRJSON = []byte("<html>500</html>") },
		"payload for another pull request": func(in *QueueInput) { in.PRJSON = qPRJSON(func(m map[string]any) { m["number"] = 43 }) },
		"pull request closed":              func(in *QueueInput) { in.PRJSON = qPRJSON(func(m map[string]any) { m["state"] = "closed" }) },
		"head mismatch": func(in *QueueInput) {
			in.PRJSON = qPRJSON(func(m map[string]any) {
				m["head"] = map[string]any{"sha": third, "repo": map[string]any{"full_name": "prufyx/prufyx"}}
			})
		},
		"fork head repo": func(in *QueueInput) {
			in.PRJSON = qPRJSON(func(m map[string]any) {
				m["head"] = map[string]any{"sha": qPR, "repo": map[string]any{"full_name": "mallory/prufyx"}}
			})
		},
		"head repo missing (deleted fork)": func(in *QueueInput) {
			in.PRJSON = qPRJSON(func(m map[string]any) { m["head"] = map[string]any{"sha": qPR, "repo": nil} })
		},
		"head repo field absent": func(in *QueueInput) {
			in.PRJSON = qPRJSON(func(m map[string]any) { m["head"] = map[string]any{"sha": qPR} })
		},
		"head missing": func(in *QueueInput) { in.PRJSON = qPRJSON(func(m map[string]any) { delete(m, "head") }) },
		"base ref not main": func(in *QueueInput) {
			in.PRJSON = qPRJSON(func(m map[string]any) {
				m["base"] = map[string]any{"ref": "dev", "repo": map[string]any{"full_name": "prufyx/prufyx"}}
			})
		},
		"base repo differs": func(in *QueueInput) {
			in.PRJSON = qPRJSON(func(m map[string]any) {
				m["base"] = map[string]any{"ref": "main", "repo": map[string]any{"full_name": "x/y"}}
			})
		},
		"author missing": func(in *QueueInput) { in.PRJSON = qPRJSON(func(m map[string]any) { delete(m, "user") }) },
		"author with newline": func(in *QueueInput) {
			in.PRJSON = qPRJSON(func(m map[string]any) { m["user"] = map[string]any{"login": "a\nB=1"} })
		},
		"labels missing": func(in *QueueInput) { in.PRJSON = qPRJSON(func(m map[string]any) { delete(m, "labels") }) },
		"label name malformed": func(in *QueueInput) {
			in.PRJSON = qPRJSON(func(m map[string]any) { m["labels"] = []any{map[string]any{"name": "a\nb"}} })
		},
		"group changes the knowledge gate":   func(in *QueueInput) { in.Changed = []string{".github/workflows/knowledge-gate.yml"} },
		"group changes the nightly check":    func(in *QueueInput) { in.Changed = []string{".github/workflows/nightly-main.yml"} },
		"group changes the merge policy":     func(in *QueueInput) { in.Changed = []string{"scripts/merge-policy-queue.sh"} },
		"group changes gate code":            func(in *QueueInput) { in.Changed = []string{"cli/internal/maintainer/knowledgegate/gate.go"} },
		"group changes CODEOWNERS":           func(in *QueueInput) { in.Changed = []string{".github/CODEOWNERS"} },
		"gate path hidden among other files": func(in *QueueInput) { in.Changed = []string{"a.txt", ".github/workflows/ci.yml", "b.txt"} },
	}
	for name, mod := range cases {
		in := qInput()
		mod(&in)
		if ctx, err := VerifyQueue(in); err == nil {
			t.Errorf("%s: accepted (%+v)", name, ctx)
		}
	}
}

func TestVerifyQueueAccepts(t *testing.T) {
	t.Parallel()
	ctx, err := VerifyQueue(qInput())
	if err != nil {
		t.Fatal(err)
	}
	if ctx.PR != 42 || ctx.CandidateID != "pr-42" || ctx.Author != "alice" || !ctx.Shadow || ctx.NightlyFix || ctx.PRHead != qPR || ctx.BaseSHA != qBase {
		t.Fatalf("%+v", ctx)
	}
	in := qInput()
	in.PRJSON = qPRJSON(func(m map[string]any) {
		m["user"] = map[string]any{"login": "prufyx-factory[bot]"}
		m["labels"] = []any{map[string]any{"name": "nightly-fix"}}
	})
	ctx, err = VerifyQueue(in)
	if err != nil || ctx.Shadow || !ctx.NightlyFix || ctx.Author != "prufyx-factory[bot]" {
		t.Fatalf("%+v %v", ctx, err)
	}
	in.PRJSON = qPRJSON(func(m map[string]any) { m["labels"] = []any{} })
	if _, err := VerifyQueue(in); err != nil {
		t.Fatal(err)
	}
}

func TestProtectedGatePathsAreExact(t *testing.T) {
	t.Parallel()
	for _, p := range []string{"cli/knowledge/a.json", "docs/knowledge-gate.yml", ".github/workflows/knowledge-gate.yml.bak", "scripts/merge-policy.sh", ".github/workflows/onboard-bundles.yml"} {
		if got := ProtectedGatePaths([]string{p}); len(got) != 0 {
			t.Errorf("%s is not a gate path", p)
		}
	}
	for _, p := range []string{".github/workflows/knowledge-gate.yml", ".github/workflows/merge-policy.yml", ".github/workflows/ci.yml", ".github/workflows/verify-pr.yml", ".github/workflows/nightly-main.yml", ".github/CODEOWNERS", "scripts/merge-policy-pr.sh", "cli/cmd/prufyx-maintainer/gate.go", "cli/internal/maintainer/mergepolicy/x.go"} {
		if got := ProtectedGatePaths([]string{p}); len(got) != 1 {
			t.Errorf("%s must be a gate path", p)
		}
	}
}

// qRepo builds a real queue commit: base, a topic commit, and their merge.
func qRepo(t *testing.T, extraFile string) (dir, base, pr, head string) {
	t.Helper()
	dir = t.TempDir()
	run := func(args ...string) string {
		cmd := exec.Command("git", append([]string{"-C", dir, "-c", "user.name=t", "-c", "user.email=t@example.invalid", "-c", "commit.gpgsign=false"}, args...)...)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
		return strings.TrimSpace(string(out))
	}
	run("init", "-q", "-b", "main")
	write := func(name string) {
		p := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(name), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("README")
	run("add", "-A")
	run("commit", "-q", "-m", "base")
	base = run("rev-parse", "HEAD")
	run("checkout", "-q", "-b", "topic")
	write(extraFile)
	run("add", "-A")
	run("commit", "-q", "-m", "change")
	pr = run("rev-parse", "HEAD")
	run("checkout", "-q", "main")
	run("merge", "-q", "--no-ff", "-m", "queue", "topic")
	head = run("rev-parse", "HEAD")
	return
}

func TestQueueContextCommand(t *testing.T) {
	t.Parallel()
	dir, base, pr, head := qRepo(t, "cli/knowledge/x.json")
	ref := "refs/heads/gh-readonly-queue/main/pr-7-" + head
	payload := func(mod func(m map[string]any)) string {
		m := map[string]any{
			"number": 7, "state": "open", "user": map[string]any{"login": "alice"},
			"labels": []any{}, "head": map[string]any{"sha": pr, "repo": map[string]any{"full_name": "prufyx/prufyx"}},
			"base": map[string]any{"ref": "main", "repo": map[string]any{"full_name": "prufyx/prufyx"}},
		}
		if mod != nil {
			mod(m)
		}
		b, _ := json.Marshal(m)
		p := filepath.Join(t.TempDir(), "pr.json")
		if err := os.WriteFile(p, b, 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	run := func(prFile string, over map[string]string) (int, string, string) {
		out := filepath.Join(t.TempDir(), "ctx.json")
		args := map[string]string{
			"repo": "prufyx/prufyx", "ref": ref, "run-sha": head, "head-ref": ref, "head-sha": head,
			"base-ref": "refs/heads/main", "base-sha": base, "git-dir": dir, "pr-json": prFile, "out": out,
		}
		for k, v := range over {
			args[k] = v
		}
		var argv []string
		for k, v := range args {
			argv = append(argv, "--"+k, v)
		}
		var so, se bytes.Buffer
		code := Main(append([]string{"queue-context"}, argv...), func(string) string { return "" }, &so, &se)
		return code, out, se.String()
	}
	// Negative first.
	if code, out, _ := run(payload(func(m map[string]any) {
		m["head"] = map[string]any{"sha": base, "repo": map[string]any{"full_name": "prufyx/prufyx"}}
	}), nil); code == 0 || fileExists(out) {
		t.Fatalf("head mismatch: code %d", code)
	}
	if code, out, _ := run(filepath.Join(t.TempDir(), "missing.json"), nil); code == 0 || fileExists(out) {
		t.Fatalf("missing payload: code %d", code)
	}
	if code, _, _ := run(payload(nil), map[string]string{"base-sha": pr}); code == 0 {
		t.Fatal("a base that is not the first parent was accepted")
	}
	if code, _, _ := run(payload(nil), map[string]string{"head-sha": strings.Repeat("a", 40), "run-sha": strings.Repeat("a", 40)}); code == 0 {
		t.Fatal("a commit that is not in the store was accepted")
	}
	// A group of two: head's first parent is not the group base.
	if code, _, _ := run(payload(nil), map[string]string{"base-sha": pr}); code == 0 {
		t.Fatal("grouped entry accepted")
	}
	code, out, errOut := run(payload(nil), nil)
	if code != 0 {
		t.Fatalf("code %d: %s", code, errOut)
	}
	var qc QueueContext
	raw, _ := os.ReadFile(out)
	if err := json.Unmarshal(raw, &qc); err != nil || qc.PR != 7 || qc.PRHead != pr {
		t.Fatalf("%s %v", raw, err)
	}
	// The same entry touching a gate file is refused.
	dir2, base2, pr2, head2 := qRepo(t, ".github/workflows/knowledge-gate.yml")
	ref2 := "refs/heads/gh-readonly-queue/main/pr-7-" + head2
	var so, se bytes.Buffer
	b, _ := json.Marshal(map[string]any{
		"number": 7, "state": "open", "user": map[string]any{"login": "alice"}, "labels": []any{},
		"head": map[string]any{"sha": pr2, "repo": map[string]any{"full_name": "prufyx/prufyx"}}, "base": map[string]any{"ref": "main", "repo": map[string]any{"full_name": "prufyx/prufyx"}},
	})
	pf := filepath.Join(t.TempDir(), "pr.json")
	_ = os.WriteFile(pf, b, 0o600)
	o2 := filepath.Join(t.TempDir(), "c.json")
	code = Main([]string{"queue-context", "--repo", "prufyx/prufyx", "--ref", ref2, "--run-sha", head2, "--head-ref", ref2, "--head-sha", head2,
		"--base-ref", "refs/heads/main", "--base-sha", base2, "--git-dir", dir2, "--pr-json", pf, "--out", o2}, func(string) string { return "" }, &so, &se)
	if code == 0 || fileExists(o2) {
		t.Fatalf("gate file change accepted: %s", se.String())
	}
}

func fileExists(p string) bool { _, err := os.Stat(p); return err == nil }
