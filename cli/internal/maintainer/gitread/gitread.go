// SPDX-License-Identifier: AGPL-3.0-only

// Package gitread reads public GitHub repositories over anonymous git, for
// organisations whose IP allow list refuses the REST API to the runner. It
// serves commit lookups, tree listings, object kinds and history checks from
// a partial clone kept in a per-run directory. A git failure is always an
// error: nothing here turns "could not ask" into "not found".
package gitread

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Limits on the git work of one run.
const (
	DefaultMaxCommands = 400
	maxParallel        = 2
	maxOutputBytes     = 64 << 20
	maxTagDepth        = 10
)

// ErrCap marks a git command refused because the cap of this run is used up.
var ErrCap = errors.New("git command cap for this run is used up")

var namePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)
var shaPattern = regexp.MustCompile(`^[0-9a-f]{40}$`)

// Entry is one tree entry, with the fields of the git trees REST API.
type Entry struct{ Path, Mode, Type, SHA string }

// Stats counts the git work done.
type Stats struct {
	// Fetches are network operations (fetch, ls-remote); Reads are local
	// object reads (cat-file, ls-tree, rev-parse).
	Fetches, Reads int64
	// Owners are the organisations learned to be IP allow-listed.
	Owners []string
}

// Remote reads repositories anonymously over git. The zero value works.
type Remote struct {
	// Base defaults to https://github.com; tests point it at file:// paths.
	Base string
	// Dir is the parent of the per-repository clones; empty means a
	// temporary directory created on first use and removed by Close.
	Dir string
	// MaxCommands caps the git commands of the run; 0 means DefaultMaxCommands.
	MaxCommands int64
	// Timeout bounds one command; 0 means 3 minutes.
	Timeout time.Duration

	mu      sync.Mutex
	tmp     string
	listed  map[string]bool
	repoMu  map[string]*sync.Mutex
	fetched map[string]bool
	sem     chan struct{}

	nFetch, nRead, nCmd atomic.Int64
}

// MarkListed remembers that owner's IP allow list refuses token requests.
func (r *Remote) MarkListed(owner string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.listed == nil {
		r.listed = map[string]bool{}
	}
	r.listed[owner] = true
}

// Listed reports whether MarkListed was called for owner.
func (r *Remote) Listed(owner string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.listed[owner]
}

// Stats returns the counters of this run.
func (r *Remote) Stats() Stats {
	r.mu.Lock()
	var owners []string
	for o := range r.listed {
		owners = append(owners, o)
	}
	r.mu.Unlock()
	sort.Strings(owners)
	return Stats{Fetches: r.nFetch.Load(), Reads: r.nRead.Load(), Owners: owners}
}

// Close removes the temporary directory, if one was created.
func (r *Remote) Close() error {
	r.mu.Lock()
	tmp := r.tmp
	r.tmp = ""
	r.mu.Unlock()
	if tmp == "" {
		return nil
	}
	return os.RemoveAll(tmp)
}

func (r *Remote) base() string {
	if r.Base == "" {
		return "https://github.com"
	}
	return strings.TrimSuffix(r.Base, "/")
}

func (r *Remote) url(owner, repo string) (string, error) {
	if !namePattern.MatchString(owner) || !namePattern.MatchString(repo) || strings.Contains(repo, "..") || strings.Contains(owner, "..") {
		return "", fmt.Errorf("invalid repository %q/%q", owner, repo)
	}
	return r.base() + "/" + owner + "/" + repo, nil
}

// repoDir returns the bare repository directory of one clone kind ("obj"
// for shallow object fetches, "hist" for the commit-only history), created
// on first use, and the lock that serialises git commands on it.
func (r *Remote) repoDir(ctx context.Context, owner, repo, kind string) (string, *sync.Mutex, error) {
	r.mu.Lock()
	if r.sem == nil {
		r.sem = make(chan struct{}, maxParallel)
		r.repoMu = map[string]*sync.Mutex{}
		r.fetched = map[string]bool{}
	}
	root := r.Dir
	if root == "" {
		if r.tmp == "" {
			d, err := os.MkdirTemp("", "prufyx-gitread-")
			if err != nil {
				r.mu.Unlock()
				return "", nil, err
			}
			r.tmp = d
		}
		root = r.tmp
	}
	key := owner + "/" + repo + "/" + kind
	lock := r.repoMu[key]
	if lock == nil {
		lock = &sync.Mutex{}
		r.repoMu[key] = lock
	}
	r.mu.Unlock()
	dir := filepath.Join(root, owner+"__"+repo+"."+kind+".git")
	lock.Lock()
	if _, err := os.Stat(filepath.Join(dir, "HEAD")); err != nil {
		if err := os.MkdirAll(root, 0o755); err != nil {
			lock.Unlock()
			return "", nil, err
		}
		if _, err := r.run(ctx, root, false, "init", "--bare", "--quiet", "--", dir); err != nil {
			lock.Unlock()
			return "", nil, err
		}
	}
	return dir, lock, nil
}

// run executes one git command. Anonymous by construction: no token is ever
// passed, credential helpers are off and prompts are disabled.
func (r *Remote) run(ctx context.Context, dir string, network bool, args ...string) ([]byte, error) {
	max := r.MaxCommands
	if max <= 0 {
		max = DefaultMaxCommands
	}
	if r.nCmd.Add(1) > max {
		r.nCmd.Add(-1)
		return nil, fmt.Errorf("%w (%d)", ErrCap, max)
	}
	if network {
		r.nFetch.Add(1)
	} else {
		r.nRead.Add(1)
	}
	r.mu.Lock()
	if r.sem == nil {
		r.sem = make(chan struct{}, maxParallel)
		r.repoMu = map[string]*sync.Mutex{}
		r.fetched = map[string]bool{}
	}
	sem := r.sem
	r.mu.Unlock()
	select {
	case sem <- struct{}{}:
		defer func() { <-sem }()
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	timeout := r.Timeout
	if timeout <= 0 {
		timeout = 3 * time.Minute
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	argv, env := gitCommand(dir, os.Environ(), args)
	cmd := exec.CommandContext(ctx, "git", argv...)
	cmd.Env = env
	var out, errOut bytes.Buffer
	cmd.Stdout, cmd.Stderr = &limitWriter{w: &out}, &errOut
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("git %s: %w: %s", args[0], err, oneLine(errOut.String()))
	}
	if out.Len() > maxOutputBytes {
		return nil, fmt.Errorf("git %s: output too large", args[0])
	}
	return out.Bytes(), nil
}

// gitCommand builds the argument vector and environment of one git command.
// git never runs in the process working directory (always -C dir), and no
// ambient configuration applies: the global and system config files are off,
// every inherited GIT_* variable is dropped, and no extra HTTP header or
// credential helper (as a CI checkout installs) can reach the request.
func gitCommand(dir string, environ, args []string) (argv, env []string) {
	argv = []string{"-c", "credential.helper=", "-c", "core.askPass=", "-c", "http.extraheader=",
		"-c", "gc.auto=0", "-c", "fetch.writeCommitGraph=false", "-C", dir}
	argv = append(argv, args...)
	for _, e := range environ {
		if !strings.HasPrefix(e, "GIT_") {
			env = append(env, e)
		}
	}
	env = append(env, "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null", "GIT_CONFIG_NOSYSTEM=1",
		"GIT_TERMINAL_PROMPT=0", "GIT_NO_LAZY_FETCH=1", "LC_ALL=C")
	return argv, env
}

type limitWriter struct {
	w *bytes.Buffer
}

func (l *limitWriter) Write(p []byte) (int, error) {
	if l.w.Len() > maxOutputBytes {
		return len(p), nil
	}
	return l.w.Write(p)
}

func oneLine(s string) string {
	s = strings.Join(strings.Fields(strings.ToValidUTF8(s, "?")), " ")
	if len(s) > 300 {
		s = s[:300] + "..."
	}
	return s
}

// fetch makes the object sha (and, shallowly, its trees) present locally.
func (r *Remote) fetch(ctx context.Context, owner, repo, sha string) (string, error) {
	if !shaPattern.MatchString(sha) {
		return "", fmt.Errorf("%q is not a full 40-character lowercase SHA", sha)
	}
	u, err := r.url(owner, repo)
	if err != nil {
		return "", err
	}
	dir, lock, err := r.repoDir(ctx, owner, repo, "obj")
	if err != nil {
		return "", err
	}
	defer lock.Unlock()
	key := owner + "/" + repo + "/" + sha
	r.mu.Lock()
	done := r.fetched[key]
	r.mu.Unlock()
	if done {
		return dir, nil
	}
	if _, err := r.run(ctx, dir, true, "fetch", "--quiet", "--no-tags", "--depth=1", "--filter=blob:none", "--", u, sha); err != nil {
		return "", fmt.Errorf("fetch %s of %s/%s: %w", sha, owner, repo, err)
	}
	r.mu.Lock()
	r.fetched[key] = true
	r.mu.Unlock()
	return dir, nil
}

// Commit fetches commit sha and returns the id of its root tree. A sha that
// is not a commit is an error.
func (r *Remote) Commit(ctx context.Context, owner, repo, sha string) (string, error) {
	dir, err := r.fetch(ctx, owner, repo, sha)
	if err != nil {
		return "", err
	}
	kind, err := r.run(ctx, dir, false, "cat-file", "-t", sha)
	if err != nil {
		return "", fmt.Errorf("commit %s of %s/%s: %w", sha, owner, repo, err)
	}
	if k := strings.TrimSpace(string(kind)); k != "commit" {
		return "", fmt.Errorf("commit %s of %s/%s: the object is a %s, not a commit", sha, owner, repo, k)
	}
	out, err := r.run(ctx, dir, false, "cat-file", "commit", sha)
	if err != nil {
		return "", fmt.Errorf("commit %s of %s/%s: %w", sha, owner, repo, err)
	}
	line, _, _ := strings.Cut(string(out), "\n")
	tree, ok := strings.CutPrefix(line, "tree ")
	if !ok || !shaPattern.MatchString(tree) {
		return "", fmt.Errorf("commit %s of %s/%s: unexpected commit object", sha, owner, repo)
	}
	return tree, nil
}

// Tree lists a tree object that a Commit call made present. recursive also
// lists every subtree, with the tree entries themselves, as the REST API does.
func (r *Remote) Tree(ctx context.Context, owner, repo, id string, recursive bool) ([]Entry, error) {
	if !shaPattern.MatchString(id) {
		return nil, fmt.Errorf("%q is not a full 40-character lowercase SHA", id)
	}
	dir, lock, err := r.repoDir(ctx, owner, repo, "obj")
	if err != nil {
		return nil, err
	}
	defer lock.Unlock()
	args := []string{"ls-tree", "-z"}
	if recursive {
		args = append(args, "-r", "-t")
	}
	out, err := r.run(ctx, dir, false, append(args, id)...)
	if err != nil {
		return nil, fmt.Errorf("tree %s of %s/%s: %w", id, owner, repo, err)
	}
	var entries []Entry
	for _, rec := range strings.Split(string(out), "\x00") {
		if rec == "" {
			continue
		}
		meta, p, ok := strings.Cut(rec, "\t")
		f := strings.Fields(meta)
		if !ok || len(f) != 3 || p == "" || !shaPattern.MatchString(f[2]) {
			return nil, fmt.Errorf("tree %s of %s/%s: unexpected ls-tree record %q", id, owner, repo, rec)
		}
		entries = append(entries, Entry{Path: p, Mode: f[0], Type: f[1], SHA: f[2]})
	}
	return entries, nil
}

// Kind fetches sha and reports whether it is a commit or, if it is a tag
// object, the commit it peels to. Anything else is an error.
func (r *Remote) Kind(ctx context.Context, owner, repo, sha string) (commit bool, peeled string, err error) {
	dir, err := r.fetch(ctx, owner, repo, sha)
	if err != nil {
		return false, "", err
	}
	cur := sha
	for depth := 0; depth < maxTagDepth; depth++ {
		t, err := r.run(ctx, dir, false, "cat-file", "-t", cur)
		if err != nil {
			return false, "", fmt.Errorf("object %s of %s/%s: %w", cur, owner, repo, err)
		}
		switch strings.TrimSpace(string(t)) {
		case "commit":
			if depth == 0 {
				return true, "", nil
			}
			return false, cur, nil
		case "tag":
			body, err := r.run(ctx, dir, false, "cat-file", "tag", cur)
			if err != nil {
				return false, "", fmt.Errorf("tag %s of %s/%s: %w", cur, owner, repo, err)
			}
			first, _, _ := strings.Cut(string(body), "\n")
			next, ok := strings.CutPrefix(first, "object ")
			if !ok || !shaPattern.MatchString(next) {
				return false, "", fmt.Errorf("tag %s of %s/%s: unexpected tag object", cur, owner, repo)
			}
			cur = next
		default:
			return false, "", fmt.Errorf("revision %s is neither a commit nor a tag object in %s/%s", cur, owner, repo)
		}
	}
	return false, "", errors.New("tag object chain is too deep to peel")
}

// Reachable reports whether sha is the commit of a tag of the repository or
// is in the history of its default branch (the tip included). The tags come
// from "git ls-remote --tags", the history from one commit-only fetch of HEAD
// that is kept for the run; any failure is an error.
func (r *Remote) Reachable(ctx context.Context, owner, repo, sha string) (bool, error) {
	if !shaPattern.MatchString(sha) {
		return false, fmt.Errorf("revision %q is not a full 40-character lowercase SHA", sha)
	}
	u, err := r.url(owner, repo)
	if err != nil {
		return false, err
	}
	dir, lock, err := r.repoDir(ctx, owner, repo, "hist")
	if err != nil {
		return false, err
	}
	defer lock.Unlock()
	out, err := r.run(ctx, dir, true, "ls-remote", "--tags", "--", u)
	if err != nil {
		return false, fmt.Errorf("list tags of %s/%s: %w", owner, repo, err)
	}
	direct, peeled := map[string]string{}, map[string]string{}
	for _, line := range strings.Split(string(out), "\n") {
		if line == "" {
			continue
		}
		id, ref, ok := strings.Cut(line, "\t")
		if !ok || !shaPattern.MatchString(id) || !strings.HasPrefix(ref, "refs/tags/") {
			return false, fmt.Errorf("list tags of %s/%s: unexpected line %q", owner, repo, oneLine(line))
		}
		if name, isPeeled := strings.CutSuffix(ref, "^{}"); isPeeled {
			peeled[name] = id
		} else {
			direct[ref] = id
		}
	}
	for ref, id := range direct {
		if p, ok := peeled[ref]; ok {
			id = p
		}
		if id == sha {
			return true, nil
		}
	}
	key := owner + "/" + repo + "/HEAD"
	r.mu.Lock()
	done := r.fetched[key]
	r.mu.Unlock()
	if !done {
		if _, err := r.run(ctx, dir, true, "fetch", "--quiet", "--no-tags", "--filter=tree:0", "--", u, "HEAD"); err != nil {
			return false, fmt.Errorf("fetch history of %s/%s: %w", owner, repo, err)
		}
		r.mu.Lock()
		r.fetched[key] = true
		r.mu.Unlock()
	}
	// Only the default branch history was fetched, so a commit object that
	// is present is the tip or an ancestor of it.
	// rev-parse --quiet exits 1 for an object that is absent; any other
	// failure is an error, not a "no".
	if _, err := r.run(ctx, dir, false, "rev-parse", "--verify", "--quiet", sha+"^{commit}"); err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) && ee.ExitCode() == 1 {
			return false, nil
		}
		return false, fmt.Errorf("history check of %s in %s/%s: %w", sha, owner, repo, err)
	}
	return true, nil
}

// IsIPAllowListRefusal reports whether the body of a 403 is GitHub's IP allow
// list refusal ("... the `x` organization has an IP allow list enabled ...").
func IsIPAllowListRefusal(body []byte) bool {
	var doc struct {
		Message string `json:"message"`
	}
	msg := string(body)
	if json.Unmarshal(body, &doc) == nil && doc.Message != "" {
		msg = doc.Message
	}
	return strings.Contains(strings.ToLower(msg), "ip allow list")
}
