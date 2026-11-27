// SPDX-License-Identifier: AGPL-3.0-only

package rangepropose

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const (
	testComponent = "pkg:github/acme/demo"
	testFact      = "component.demo.flag_present"
	oldCode       = "package demo\n\nfunc flags() {\n\tregister(\"--legacy\")\n}\n"
	newCode       = "package demo\n\nfunc flags() {\n\treject(\"--legacy\")\n}\n"
)

// files is a whole tree: path to content. A content starting with "->" is a
// symbolic link.
type files map[string]string

type release struct {
	tag  string
	tree files
}

type fixture struct {
	t       *testing.T
	work    string
	commits map[string]string // tag to commit
	trees   map[string]files
}

func git(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + dir, "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null",
		"GIT_AUTHOR_NAME=Fixture", "GIT_AUTHOR_EMAIL=fixture@example.invalid", "GIT_COMMITTER_NAME=Fixture",
		"GIT_COMMITTER_EMAIL=fixture@example.invalid", "GIT_AUTHOR_DATE=2026-01-01T00:00:00Z", "GIT_COMMITTER_DATE=2026-01-01T00:00:00Z"}
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

func write(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if target, link := strings.CutPrefix(content, "->"); link {
		if err := os.Symlink(target, path); err != nil {
			t.Fatal(err)
		}
		return
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// commit replaces the whole tree and commits it.
func (f *fixture) commit(message string, tree files) string {
	f.t.Helper()
	git(f.t, f.work, "rm", "-r", "-q", "--ignore-unmatch", ".")
	// The message file keeps two commits with equal trees apart.
	write(f.t, filepath.Join(f.work, ".message"), message+"\n")
	for path, content := range tree {
		write(f.t, filepath.Join(f.work, path), content)
	}
	git(f.t, f.work, "add", "-A")
	git(f.t, f.work, "commit", "-q", "-m", message)
	return git(f.t, f.work, "rev-parse", "HEAD")
}

func newFixture(t *testing.T, releases []release) *fixture {
	t.Helper()
	f := &fixture{t: t, work: t.TempDir(), commits: map[string]string{}, trees: map[string]files{}}
	git(t, f.work, "init", "-q", "-b", "main")
	for _, r := range releases {
		f.commits[r.tag] = f.commit(r.tag, r.tree)
		f.trees[r.tag] = r.tree
		git(t, f.work, "tag", r.tag)
	}
	return f
}

func (f *fixture) bare() string {
	f.t.Helper()
	dir := filepath.Join(f.t.TempDir(), "demo.git")
	git(f.t, f.work, "clone", "-q", "--bare", f.work, dir)
	return dir
}

// standard is two adjacent lines whose cited files never change inside a
// line.
func standard() []release {
	from := files{"flags.go": oldCode, "CHANGELOG.md": "- a\n"}
	to := files{"flags.go": newCode, "CHANGELOG.md": "- b\n"}
	return []release{{"v1.4.0", from}, {"v1.4.1", from}, {"v1.4.2", from}, {"v1.5.0", to}, {"v1.5.1", to}}
}

// with returns the releases with one path of one tag replaced; an empty
// content removes the path.
func with(releases []release, tag, path, content string) []release {
	out := append([]release(nil), releases...)
	for i, r := range out {
		if r.tag != tag {
			continue
		}
		tree := files{}
		for k, v := range r.tree {
			tree[k] = v
		}
		if content == "" {
			delete(tree, path)
		} else {
			tree[path] = content
		}
		out[i].tree = tree
	}
	return out
}

type src = map[string]any

// source cites lines of the file as it is at tag.
func (f *fixture) source(id, tag, path string, start, end int) src {
	return sourceAt(id, "acme/demo", f.commits[tag], path, f.trees[tag][path], start, end)
}

func sourceAt(id, repo, commit, path, content string, start, end int) src {
	return src{"id": id, "url": "https://github.com/" + repo + "/blob/" + commit + "/" + path, "revision": commit,
		"contentDigest": digest([]byte(content)), "startLine": start, "endLine": end}
}

// both is one stable source per side.
func (f *fixture) both() []src {
	return []src{f.source("old-flags", "v1.4.1", "flags.go", 3, 5), f.source("new-flags", "v1.5.0", "flags.go", 3, 5)}
}

func rule(id, from, to string, sources []src) map[string]any {
	return map[string]any{
		"id": id, "operator": "forbid_predicate_value",
		"subject":     map[string]any{"component": testComponent, "from": from, "to": to},
		"condition":   map[string]any{"side": "proposed", "component": testComponent, "factId": testFact, "boolValue": true},
		"appliesWhen": []any{},
		"evidence": map[string]any{"state": "active", "reviewedAt": "2026-01-01T00:00:00Z",
			"validUntil": "2027-01-01T00:00:00Z", "sources": sources},
		"reasonCode": "FEATURE_REMOVED", "nextAction": "remove the flag before the upgrade",
	}
}

func marshal(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func packJSON(t *testing.T, rules ...map[string]any) string {
	t.Helper()
	entries := []any{}
	for _, r := range rules {
		entries = append(entries, map[string]any{"project": "demo", "rule": r})
	}
	return marshal(t, map[string]any{"schema": "test", "entries": entries})
}

func rulesRepo(t *testing.T, pack string) (string, string) {
	t.Helper()
	dir := t.TempDir()
	git(t, dir, "init", "-q", "-b", "main")
	write(t, filepath.Join(dir, RulesPath), pack)
	git(t, dir, "add", "-A")
	git(t, dir, "commit", "-q", "-m", "rules")
	return dir, git(t, dir, "rev-parse", "HEAD")
}

func config(path string) Config {
	return Config{Projects: map[string]Project{"demo": {Repo: "acme/demo", Path: path, TagPrefix: "v"}}}
}

func options(t *testing.T, clone string, rules ...map[string]any) Options {
	t.Helper()
	repo, commit := rulesRepo(t, packJSON(t, rules...))
	return Options{RulesRepo: repo, RulesCommit: commit, Config: config(clone), ToolRevision: "test"}
}

func run(t *testing.T, o Options) Report {
	t.Helper()
	report, err := Run(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	return report
}

func wantProposal(t *testing.T, r Report) Proposal {
	t.Helper()
	if len(r.Proposals) != 1 || len(r.NeedsReview) != 0 || len(r.Refused) != 0 {
		t.Fatalf("want one proposal, got %s", marshal(t, r))
	}
	return r.Proposals[0]
}

func wantReview(t *testing.T, r Report, code string) Review {
	t.Helper()
	if len(r.Proposals) != 0 || len(r.NeedsReview) != 1 || len(r.Refused) != 0 {
		t.Fatalf("want one review %s, got %s", code, marshal(t, r))
	}
	for _, reason := range r.NeedsReview[0].Reasons {
		if reason.Code == code {
			return r.NeedsReview[0]
		}
	}
	t.Fatalf("want reason %s, got %s", code, marshal(t, r.NeedsReview[0].Reasons))
	return Review{}
}

func wantRefused(t *testing.T, r Report, code string) Refused {
	t.Helper()
	if len(r.Proposals) != 0 || len(r.NeedsReview) != 0 || len(r.Refused) != 1 || r.Refused[0].Code != code {
		t.Fatalf("want one refusal %s, got %s", code, marshal(t, r))
	}
	return r.Refused[0]
}
