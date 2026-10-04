// SPDX-License-Identifier: AGPL-3.0-only

package consensus

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/prufyx/prufyx/cli/internal/extract"
	"github.com/prufyx/prufyx/cli/internal/maintainer/factorymirror"
	"github.com/prufyx/prufyx/cli/internal/strictjson"
)

// DefaultHistoryLimit bounds the commit walk of one release range. A
// Kubernetes minor release range holds well under this many commits; a
// range with more is not walked and its claims stay leads.
const DefaultHistoryLimit = 50000

// History errors.
var (
	// ErrHistoryUnbounded: the range holds more commits than the walk limit.
	ErrHistoryUnbounded = errors.New("the release range holds more commits than the walk limit")
	// ErrHistoryUnavailable: this source has no commit history.
	ErrHistoryUnavailable = errors.New("no commit history is available from this source")
	// ErrHistoryIncomplete: a commit of the range is not held locally.
	ErrHistoryIncomplete = errors.New("the commit history of the release range is not complete")
)

// CommitSubject is one commit of a release range and its subject line.
type CommitSubject struct {
	Commit  string
	Subject string
}

// History answers questions about a repository's commit graph.
type History interface {
	// RangeSubjects lists every commit reachable from to and not from
	// from, with its subject. It returns ErrHistoryUnbounded when there
	// are more than limit commits.
	RangeSubjects(repo extract.RepoRef, from, to string, limit int) ([]CommitSubject, error)
	// OnBranch reports whether commit is base or descends from it, and
	// is reachable from the head of branch. A branch that is not recorded
	// answers false.
	OnBranch(repo extract.RepoRef, base, commit, branch string) (bool, error)
}

// MirrorHistory reads commit objects from the offline factory mirror. A
// mirror cloned without file contents still holds every commit object, so
// nothing needs the network. Git runs with the repository named explicitly,
// no system or global configuration, every transport, lazy fetching and
// replace objects disabled, hooks and the file system monitor off,
// signatures never checked, and repository discovery bounded.
type MirrorHistory struct {
	State string
}

const maxGitOutput = 64 << 20

type gitExit struct {
	code   int
	stderr string
}

func (e *gitExit) Error() string { return fmt.Sprintf("git exited %d: %s", e.code, e.stderr) }

func (m MirrorHistory) dir(repo extract.RepoRef) (string, error) {
	parsed, err := factorymirror.ParseRepo(repo.Key)
	if err != nil {
		return "", err
	}
	dir, err := filepath.Abs(filepath.Join(m.State, parsed.RelPath()))
	if err != nil {
		return "", err
	}
	if st, err := os.Stat(dir); err != nil || !st.IsDir() {
		return "", fmt.Errorf("%w: %s is not mirrored", ErrHistoryIncomplete, repo.Key)
	}
	return dir, nil
}

// git runs one read-only git command against the mirror repository dir.
func (m MirrorHistory) git(ctx context.Context, dir string, args ...string) ([]byte, error) {
	full := append([]string{"-c", "protocol.allow=never", "--git-dir=" + dir}, args...)
	cmd := exec.CommandContext(ctx, "git", full...)
	cmd.Dir = dir
	config := [][2]string{
		{"core.hooksPath", os.DevNull}, {"core.fsmonitor", "false"}, {"safe.directory", dir},
		{"log.showSignature", "false"}, {"core.pager", "cat"},
	}
	cmd.Env = []string{
		"PATH=" + os.Getenv("PATH"), "HOME=" + os.TempDir(), "LC_ALL=C",
		"GIT_TERMINAL_PROMPT=0", "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=" + os.DevNull, "GIT_PAGER=cat",
		"GIT_ALLOW_PROTOCOL=none", "GIT_NO_LAZY_FETCH=1", "GIT_NO_REPLACE_OBJECTS=1",
		"GIT_CEILING_DIRECTORIES=" + filepath.Dir(dir), "GIT_DIR=" + dir,
		"GIT_CONFIG_COUNT=" + strconv.Itoa(len(config)),
	}
	for i, kv := range config {
		cmd.Env = append(cmd.Env, fmt.Sprintf("GIT_CONFIG_KEY_%d=%s", i, kv[0]), fmt.Sprintf("GIT_CONFIG_VALUE_%d=%s", i, kv[1]))
	}
	var out, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &stderr
	err := cmd.Run()
	if out.Len() > maxGitOutput {
		return nil, errors.New("git output too large")
	}
	if err != nil {
		var exit *exec.ExitError
		msg := strings.TrimSpace(stderr.String())
		if len(msg) > 300 {
			msg = msg[:300]
		}
		if errors.As(err, &exit) {
			return nil, &gitExit{code: exit.ExitCode(), stderr: msg}
		}
		return nil, err
	}
	return out.Bytes(), nil
}

func (m MirrorHistory) hasCommit(ctx context.Context, dir, c string) bool {
	_, err := m.git(ctx, dir, "cat-file", "-e", c+"^{commit}")
	return err == nil
}

// RangeSubjects implements History.
func (m MirrorHistory) RangeSubjects(repo extract.RepoRef, from, to string, limit int) ([]CommitSubject, error) {
	if !extract.IsCommitSHA(from) || !extract.IsCommitSHA(to) || limit < 1 {
		return nil, errors.New("range ends must be full commit SHAs")
	}
	dir, err := m.dir(repo)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	for _, c := range []string{from, to} {
		if !m.hasCommit(ctx, dir, c) {
			return nil, fmt.Errorf("%w: commit %s is not in the mirror", ErrHistoryIncomplete, c)
		}
	}
	out, err := m.git(ctx, dir, "log", "-z", "--no-color", "--no-decorate", "--no-show-signature", "--no-mailmap",
		"--format=%H %s", "--max-count="+strconv.Itoa(limit+1), from+".."+to, "--")
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrHistoryIncomplete, err)
	}
	var subjects []CommitSubject
	for _, rec := range bytes.Split(out, []byte{0}) {
		if len(rec) == 0 {
			continue
		}
		sha, subject, _ := strings.Cut(string(rec), " ")
		if !extract.IsCommitSHA(sha) {
			return nil, fmt.Errorf("%w: unexpected git output", ErrHistoryIncomplete)
		}
		subjects = append(subjects, CommitSubject{Commit: sha, Subject: subject})
	}
	if len(subjects) > limit {
		return nil, ErrHistoryUnbounded
	}
	return subjects, nil
}

// OnBranch implements History with "git merge-base --is-ancestor".
func (m MirrorHistory) OnBranch(repo extract.RepoRef, base, commit, branch string) (bool, error) {
	if !extract.IsCommitSHA(base) || !extract.IsCommitSHA(commit) || !branchRE.MatchString(branch) {
		return false, errors.New("bad commit or branch")
	}
	dir, err := m.dir(repo)
	if err != nil {
		return false, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	for _, c := range []string{base, commit} {
		if !m.hasCommit(ctx, dir, c) {
			return false, fmt.Errorf("%w: commit %s is not in the mirror", ErrHistoryIncomplete, c)
		}
	}
	out, err := m.git(ctx, dir, "rev-parse", "--verify", "--quiet", "refs/heads/"+branch+"^{commit}")
	if err != nil {
		return false, nil
	}
	head := strings.TrimSpace(string(out))
	if !extract.IsCommitSHA(head) {
		return false, nil
	}
	for _, pair := range [][2]string{{base, commit}, {commit, head}} {
		_, err := m.git(ctx, dir, "merge-base", "--is-ancestor", pair[0], pair[1])
		var exit *gitExit
		switch {
		case err == nil:
		case errors.As(err, &exit) && exit.code == 1:
			return false, nil
		default:
			return false, fmt.Errorf("%w: %v", ErrHistoryIncomplete, err)
		}
	}
	return true, nil
}

var branchRE = regexp.MustCompile(`^release-1\.(0|[1-9][0-9]{0,2})$`)

// FixtureHistory reads the commit graph of a fixture tree:
//
//	<root>/<host>/<owner>/<name>/history.json
//	{"commits": [{"commit": "<sha>", "parents": ["<sha>", ...], "subject": "..."}, ...],
//	 "branches": {"release-1.41": "<sha>", ...}}
//
// A repository without the file has no history.
type FixtureHistory struct {
	Root string
}

type fixtureCommit struct {
	Commit  string   `json:"commit"`
	Parents []string `json:"parents"`
	Subject string   `json:"subject"`
}

type fixtureGraph struct {
	commits  map[string]fixtureCommit
	branches map[string]string
}

func (f FixtureHistory) load(repo extract.RepoRef) (*fixtureGraph, error) {
	raw, err := os.ReadFile(filepath.Join(f.Root, filepath.FromSlash(repo.Key), "history.json"))
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrHistoryUnavailable
	}
	if err != nil {
		return nil, err
	}
	var doc struct {
		Commits  []fixtureCommit   `json:"commits"`
		Branches map[string]string `json:"branches"`
	}
	if err := strictjson.Decode(raw, &doc); err != nil {
		return nil, fmt.Errorf("fixture history: %w", err)
	}
	g := &fixtureGraph{commits: map[string]fixtureCommit{}, branches: doc.Branches}
	for _, c := range doc.Commits {
		if !extract.IsCommitSHA(c.Commit) {
			return nil, fmt.Errorf("fixture history: bad commit %q", c.Commit)
		}
		if _, dup := g.commits[c.Commit]; dup {
			return nil, fmt.Errorf("fixture history: commit %s appears twice", c.Commit)
		}
		g.commits[c.Commit] = c
	}
	return g, nil
}

// reach walks the parents of start, not entering stop, in breadth-first
// order. max > 0 bounds the walk.
func (g *fixtureGraph) reach(start string, stop map[string]bool, max int) ([]string, error) {
	seen := map[string]bool{}
	queue := []string{start}
	var order []string
	for len(queue) > 0 {
		c := queue[0]
		queue = queue[1:]
		if seen[c] || stop[c] {
			continue
		}
		node, ok := g.commits[c]
		if !ok {
			return nil, fmt.Errorf("%w: commit %s is not in the fixture history", ErrHistoryIncomplete, c)
		}
		seen[c] = true
		order = append(order, c)
		if max > 0 && len(order) > max {
			return nil, ErrHistoryUnbounded
		}
		queue = append(queue, node.Parents...)
	}
	return order, nil
}

// RangeSubjects implements History.
func (f FixtureHistory) RangeSubjects(repo extract.RepoRef, from, to string, limit int) ([]CommitSubject, error) {
	g, err := f.load(repo)
	if err != nil {
		return nil, err
	}
	ancestors, err := g.reach(from, nil, 0)
	if err != nil {
		return nil, err
	}
	stop := map[string]bool{}
	for _, c := range ancestors {
		stop[c] = true
	}
	inRange, err := g.reach(to, stop, limit)
	if err != nil {
		return nil, err
	}
	out := make([]CommitSubject, 0, len(inRange))
	for _, c := range inRange {
		out = append(out, CommitSubject{Commit: c, Subject: g.commits[c].Subject})
	}
	return out, nil
}

// OnBranch implements History.
func (f FixtureHistory) OnBranch(repo extract.RepoRef, base, commit, branch string) (bool, error) {
	g, err := f.load(repo)
	if err != nil {
		return false, err
	}
	head, ok := g.branches[branch]
	if !ok {
		return false, nil
	}
	if _, ok := g.commits[commit]; !ok {
		return false, nil
	}
	fromHead, err := g.reach(head, nil, 0)
	if err != nil {
		return false, err
	}
	fromCommit, err := g.reach(commit, nil, 0)
	if err != nil {
		return false, err
	}
	return containsString(fromHead, commit) && containsString(fromCommit, base), nil
}

func containsString(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}
