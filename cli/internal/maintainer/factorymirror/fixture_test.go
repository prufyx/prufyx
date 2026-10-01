// SPDX-License-Identifier: AGPL-3.0-only

package factorymirror

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// upstream is a local bare repository that stands in for a hosted one.
type upstream struct {
	t    *testing.T
	bare string
	work string
}

func gitEnv() []string {
	return append(os.Environ(),
		"GIT_CONFIG_GLOBAL="+os.DevNull, "GIT_CONFIG_NOSYSTEM=1", "GIT_TERMINAL_PROMPT=0",
		"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@example.invalid", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@example.invalid",
		"GIT_AUTHOR_DATE=2020-01-01T00:00:00Z", "GIT_COMMITTER_DATE=2020-01-01T00:00:00Z")
}

func runGit(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = gitEnv()
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return strings.TrimSpace(string(out))
}

func requireGit(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
}

// newUpstream creates root/<host>/<owner>/<name>.git served over file://.
func newUpstream(t *testing.T, root, key string) *upstream {
	t.Helper()
	requireGit(t)
	bare := filepath.Join(root, filepath.FromSlash(key)+".git")
	if err := os.MkdirAll(bare, 0o755); err != nil {
		t.Fatal(err)
	}
	runGit(t, bare, "init", "-q", "--bare", "-b", "main")
	runGit(t, bare, "config", "uploadpack.allowFilter", "true")
	runGit(t, bare, "config", "uploadpack.allowAnySHA1InWant", "true")
	work := filepath.Join(t.TempDir(), "work")
	runGit(t, filepath.Dir(bare), "clone", "-q", bare, work)
	runGit(t, work, "checkout", "-q", "-b", "main")
	return &upstream{t: t, bare: bare, work: work}
}

// commit writes files, commits, pushes main and returns the commit SHA.
func (u *upstream) commit(msg string, files map[string]string) string {
	u.t.Helper()
	for name, content := range files {
		p := filepath.Join(u.work, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			u.t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			u.t.Fatal(err)
		}
	}
	runGit(u.t, u.work, "add", "-A")
	runGit(u.t, u.work, "commit", "-q", "-m", msg)
	runGit(u.t, u.work, "push", "-q", "-f", "origin", "main")
	return runGit(u.t, u.work, "rev-parse", "HEAD")
}

var tagSeq int

func (u *upstream) tag(name string, annotated bool) {
	u.t.Helper()
	if annotated {
		tagSeq++
		runGit(u.t, u.work, "tag", "-f", "-a", "-m", name+" "+strings.Repeat("x", tagSeq), name)
	} else {
		runGit(u.t, u.work, "tag", "-f", name)
	}
	runGit(u.t, u.work, "push", "-q", "-f", "origin", "refs/tags/"+name)
}

func (u *upstream) deleteTag(name string) {
	u.t.Helper()
	runGit(u.t, u.work, "tag", "-d", name)
	runGit(u.t, u.work, "push", "-q", "origin", ":refs/tags/"+name)
}

func (u *upstream) resetTo(commit string) {
	u.t.Helper()
	runGit(u.t, u.work, "reset", "-q", "--hard", commit)
}

// countingGit records every git subcommand it runs.
type countingGit struct {
	inner GitRunner
	mu    sync.Mutex
	calls map[string]int
	// failFirst makes the first matching command fail once.
	failFirst func(args []string) bool
	failed    bool
	cur, max  int
	delay     time.Duration
}

func newCountingGit() *countingGit {
	return &countingGit{inner: ExecGit{AllowProtocols: "file"}, calls: map[string]int{}}
}

func (c *countingGit) count(name string) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.calls[name]
}

func (c *countingGit) reset() {
	c.mu.Lock()
	c.calls = map[string]int{}
	c.mu.Unlock()
}

func (c *countingGit) enter(args []string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.calls[args[0]]++
	c.cur++
	if c.cur > c.max {
		c.max = c.cur
	}
	if c.failFirst != nil && !c.failed && c.failFirst(args) {
		c.failed = true
		return &GitError{Args: args, Err: os.ErrDeadlineExceeded}
	}
	return nil
}

func (c *countingGit) leave() {
	c.mu.Lock()
	c.cur--
	c.mu.Unlock()
}

func (c *countingGit) Run(ctx context.Context, dir string, args ...string) ([]byte, error) {
	return c.RunStdin(ctx, dir, nil, args...)
}

func (c *countingGit) RunStdin(ctx context.Context, dir string, stdin []byte, args ...string) ([]byte, error) {
	err := c.enter(args)
	defer c.leave()
	if err != nil {
		return nil, err
	}
	if c.delay > 0 && args[0] == "ls-remote" {
		time.Sleep(c.delay)
	}
	return c.inner.RunStdin(ctx, dir, stdin, args...)
}

func fileBase(root string) string { return "file://" + root + "/" }

func mustRepo(t *testing.T, s string) Repo {
	t.Helper()
	r, err := ParseRepo(s)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func fixedNow() func() time.Time {
	t := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
	return func() time.Time { return t }
}
