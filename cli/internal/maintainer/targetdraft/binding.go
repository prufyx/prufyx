// SPDX-License-Identifier: AGPL-3.0-only

package targetdraft

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Upstream binding (B1). The consistency check proves a fact bundle is
// internally sound; it cannot prove the bundle comes from the real repository.
// This file closes that gap for the tag window only: one `git ls-remote
// --tags` of the recipe's repository, and every window tag must resolve (peeled
// to a commit) to the commit the recipe and the bundle both name. Every error,
// empty answer, missing tag, redirect, malformed line or moved tag is a typed
// failure; there is no skip, no warning and no cached result.
//
// The only network code in this package is the exec of git below, behind the
// LsRemoteRunner interface. Tests inject a fake runner and never touch the
// network.

const (
	// bindingHost is the one host the binding talks to. It is a constant: it
	// is never read from the recipe.
	bindingHost = "github.com"

	bindingMaxAttempts = 3
	bindingTimeout     = 60 * time.Second
	bindingMaxOutput   = 64 << 10
	bindingMaxStderr   = 16 << 10
	// bindingPath is the fixed PATH of the cleared environment.
	bindingPath = "/usr/bin:/bin"
)

var (
	// bindingTagRE is stricter than tagNameRE: no glob character, no leading
	// '-', no '^', at most 100 bytes. ls-remote patterns are globs, so a tag
	// with a glob character would widen what the pattern matches.
	bindingTagRE   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]{0,99}$`)
	bindingLineRE  = regexp.MustCompile(`^([0-9a-f]{40}|[0-9a-f]{64})\t(refs/tags/[A-Za-z0-9][A-Za-z0-9._+-]{0,99}(\^\{\})?)$`)
	bindingGitDirs = []string{"/usr/bin/git", "/usr/local/bin/git", "/bin/git"}
)

// bindingBackoff is the wait before attempt 2 and attempt 3.
var bindingBackoff = [...]time.Duration{5 * time.Second, 15 * time.Second}

// ExecSpec is one command: a fixed argv (argv[0] is "git"), the exact
// environment, and nothing else. Env does not hold HOME: the real runner adds
// HOME and the working directory, both an empty temporary directory outside
// any repository.
type ExecSpec struct {
	Argv []string
	Env  []string
}

// ExecResult is what one run produced. Err is set when the command could not
// run at all (binary missing); a non-zero exit is not an Err.
type ExecResult struct {
	Stdout   []byte
	Stderr   []byte
	Exit     int
	TimedOut bool
	Err      error
}

// LsRemoteRunner runs one command. It is the only seam to the network.
type LsRemoteRunner interface {
	Run(ctx context.Context, spec ExecSpec) ExecResult
}

// BindingTag is one verified window tag.
type BindingTag struct {
	Tag       string `json:"tag"`
	Commit    string `json:"commit"`
	Annotated bool   `json:"annotated"`
}

// BindingResult is the machine-readable result of a verified binding. It is
// bound to the head commit it was produced for.
type BindingResult struct {
	Repo        string       `json:"repo"`
	HeadSHA     string       `json:"headSha"`
	Tags        []BindingTag `json:"tags"`
	Annotated   int          `json:"annotated"`
	Lightweight int          `json:"lightweight"`
	Digest      string       `json:"bindingDigest"`
}

// Binder runs the binding. Sleep is injectable so tests do not wait.
type Binder struct {
	Runner LsRemoteRunner
	Sleep  func(time.Duration)
	// Ctx is the caller's context; cancelling it stops the binding at once
	// (no further attempt, never a pass). nil means context.Background().
	Ctx context.Context
}

func bindFail(code, format string, a ...any) *VerifyFailure { return fail(code, format, a...) }
func bindHarness(code, format string, a ...any) *VerifyFailure {
	return harness(code, format, a...)
}

// bindingEnv is the exact environment of the git process (without HOME).
func bindingEnv() []string {
	return []string{
		"PATH=" + bindingPath,
		"LC_ALL=C",
		"GIT_TERMINAL_PROMPT=0",
		"GIT_ALLOW_PROTOCOL=https",
		"GIT_CONFIG_GLOBAL=/dev/null",
		"GIT_CONFIG_SYSTEM=/dev/null",
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_ASKPASS=/bin/false",
	}
}

// bindingRepoPath returns owner/name for a validated recipe repo.
func bindingRepoPath(repo string) (string, *VerifyFailure) {
	if !repoRE.MatchString(repo) {
		return "", bindFail("binding-input", "repo %q is not %s/<owner>/<name>", repo, bindingHost)
	}
	p := strings.TrimPrefix(repo, bindingHost+"/")
	if strings.Contains(p, "..") || strings.HasSuffix(p, ".git") || strings.HasSuffix(p, ".") {
		return "", bindFail("binding-input", "repo %q has a refused name shape", repo)
	}
	return p, nil
}

// bindingArgv builds the fixed argument vector. The URL is assembled from the
// constant host; patterns are exact full ref names.
func bindingArgv(repoPath string, tags []string) []string {
	argv := []string{"git",
		"-c", "protocol.version=2",
		"-c", "http.followRedirects=false",
		"-c", "credential.helper=",
		"-c", "http.lowSpeedLimit=1000",
		"-c", "http.lowSpeedTime=20",
		"-c", "core.askPass=",
		"ls-remote", "--tags", "--",
		"https://" + bindingHost + "/" + repoPath + ".git"}
	for _, t := range tags {
		argv = append(argv, "refs/tags/"+t, "refs/tags/"+t+"^{}")
	}
	return argv
}

// Bind verifies the recipe's window against the upstream refs. commits maps
// every window tag to the commit the recipe names; bundleCommit gives the
// commit the verified bundle names. All three must agree.
func (b Binder) Bind(rc *Recipe, bundleCommit func(tag string) (string, bool), headSHA string) (*BindingResult, *VerifyFailure) {
	if b.Runner == nil {
		return nil, bindHarness("binding-unavailable", "no runner")
	}
	if !sha1HexRE.MatchString(headSHA) {
		return nil, bindFail("binding-input", "head sha is not 40 lowercase hex")
	}
	repoPath, f := bindingRepoPath(rc.Repo)
	if f != nil {
		return nil, f
	}
	if len(rc.Commits) == 0 || len(rc.Commits) > MaxBundleTags {
		return nil, bindFail("binding-input", "window has %d tags", len(rc.Commits))
	}
	want := map[string]string{}
	var tags []string
	for _, c := range rc.Commits {
		if !bindingTagRE.MatchString(c.Tag) || strings.Contains(c.Tag, "..") || !sha1HexRE.MatchString(c.Commit) {
			return nil, bindFail("binding-input", "tag %q or its commit is malformed", c.Tag)
		}
		if _, dup := want[c.Tag]; dup {
			return nil, bindFail("binding-input", "tag %q listed twice", c.Tag)
		}
		bc, ok := bundleCommit(c.Tag)
		if !ok || bc != c.Commit {
			return nil, bindFail("binding-input", "tag %s: recipe and bundle commits differ", c.Tag)
		}
		want[c.Tag] = c.Commit
		tags = append(tags, c.Tag)
	}
	sort.Strings(tags)
	spec := ExecSpec{Argv: bindingArgv(repoPath, tags), Env: bindingEnv()}

	parent := b.Ctx
	if parent == nil {
		parent = context.Background()
	}
	var out []byte
	for attempt := 1; ; attempt++ {
		if parent.Err() != nil {
			return nil, bindHarness("binding-unavailable", "cancelled by the caller")
		}
		ctx, cancel := context.WithTimeout(parent, bindingTimeout)
		res := b.Runner.Run(ctx, spec)
		cancel()
		if parent.Err() != nil {
			return nil, bindHarness("binding-unavailable", "cancelled by the caller")
		}
		stdout, retry, f := classifyRun(res)
		if f == nil {
			out = stdout
			break
		}
		if !retry || attempt >= bindingMaxAttempts {
			return nil, f
		}
		if b.Sleep != nil {
			b.Sleep(bindingBackoff[attempt-1])
		}
	}
	return parseBinding(out, tags, want, "https://"+bindingHost+"/"+repoPath, headSHA, rc.Repo)
}

// classifyRun maps one run to stdout or a typed failure. retry is true only
// for the transient classes. A non-zero exit never yields stdout.
func classifyRun(r ExecResult) (stdout []byte, retry bool, f *VerifyFailure) {
	if r.Err != nil {
		return nil, false, bindHarness("binding-unavailable", "git could not run: %v", r.Err)
	}
	if r.TimedOut {
		return nil, true, bindHarness("binding-unavailable", "git ls-remote timed out")
	}
	if r.Exit == 0 {
		return r.Stdout, false, nil
	}
	s := strings.ToLower(string(r.Stderr))
	has := func(subs ...string) bool {
		for _, x := range subs {
			if strings.Contains(s, x) {
				return true
			}
		}
		return false
	}
	switch {
	case has("redirect", "returned error: 30", "moved permanently"):
		return nil, false, bindFail("binding-redirect", "the repository URL redirects (renamed or moved)")
	case has("ssl", "tls", "certificate"):
		return nil, false, bindHarness("binding-unavailable", "TLS failure (not retried)")
	case has("returned error: 401", "returned error: 403", "returned error: 404", "repository not found", "authentication failed", "could not read username", "terminal prompts disabled"):
		return nil, false, bindFail("binding-unavailable", "the repository is not readable without credentials, or does not exist")
	case has("returned error: 429", "returned error: 5", "timed out", "timeout", "connection reset", "could not resolve", "connection refused", "early eof", "rpc failed", "remote end hung up", "unable to access"):
		return nil, true, bindHarness("binding-unavailable", "transient network failure (exit %d)", r.Exit)
	}
	return nil, false, bindHarness("binding-unavailable", "git ls-remote exited %d", r.Exit)
}

// parseBinding checks the output strictly and compares every tag.
func parseBinding(out []byte, tags []string, want map[string]string, urlBase, headSHA, repo string) (*BindingResult, *VerifyFailure) {
	if len(out) == 0 {
		return nil, bindFail("binding-malformed", "empty answer (never read as no tags)")
	}
	if len(out) > bindingMaxOutput {
		return nil, bindFail("binding-malformed", "answer over %d bytes", bindingMaxOutput)
	}
	if out[len(out)-1] != '\n' {
		return nil, bindFail("binding-malformed", "answer is truncated (no final newline)")
	}
	expected := map[string]bool{}
	for _, t := range tags {
		expected["refs/tags/"+t] = true
		expected["refs/tags/"+t+"^{}"] = true
	}
	got := map[string]string{}
	lines := strings.Split(strings.TrimSuffix(string(out), "\n"), "\n")
	if len(lines) > 2*len(tags) {
		return nil, bindFail("binding-malformed", "%d lines for %d tags", len(lines), len(tags))
	}
	for _, ln := range lines {
		m := bindingLineRE.FindStringSubmatch(ln)
		if m == nil {
			return nil, bindFail("binding-malformed", "unexpected line %q", ln)
		}
		if len(m[1]) == 64 {
			return nil, bindFail("binding-hashalgo", "the repository uses a 64-hex object format")
		}
		if !expected[m[2]] {
			return nil, bindFail("binding-malformed", "unexpected ref %q", m[2])
		}
		if _, dup := got[m[2]]; dup {
			return nil, bindFail("binding-malformed", "ref %q listed twice", m[2])
		}
		got[m[2]] = m[1]
	}
	res := &BindingResult{Repo: repo, HeadSHA: headSHA}
	for _, t := range tags {
		ref, hasRef := got["refs/tags/"+t]
		peeled, hasPeeled := got["refs/tags/"+t+"^{}"]
		if !hasRef {
			if hasPeeled {
				return nil, bindFail("binding-malformed", "tag %s: peeled line without the tag line", t)
			}
			return nil, bindFail("binding-missing", "tag %s is not in the upstream repository", t)
		}
		commit, annotated := ref, false
		if hasPeeled {
			commit, annotated = peeled, true
		}
		if commit != want[t] {
			return nil, bindFail("binding-mismatch", "tag %s: upstream has %s, recipe and bundle have %s", t, commit, want[t])
		}
		res.Tags = append(res.Tags, BindingTag{Tag: t, Commit: commit, Annotated: annotated})
		if annotated {
			res.Annotated++
		} else {
			res.Lightweight++
		}
	}
	res.Digest = bindingDigest(repo, res.Tags)
	return res, nil
}

// bindingDigest is sha256 over the repo and the sorted tag -> commit list.
func bindingDigest(repo string, tags []BindingTag) string {
	ts := append([]BindingTag(nil), tags...)
	sort.Slice(ts, func(i, j int) bool { return ts[i].Tag < ts[j].Tag })
	var b bytes.Buffer
	b.WriteString("prufyx.io/upstream-binding/v1\n")
	b.WriteString(repo + "\n")
	for _, t := range ts {
		b.WriteString(t.Tag + "\t" + t.Commit + "\n")
	}
	s := sha256.Sum256(b.Bytes())
	return hex.EncodeToString(s[:])
}

// bindingLine is the human line printed when the binding verified.
func bindingLine(r *BindingResult) string {
	return fmt.Sprintf("upstream binding: verified %s %d tags, annotated %d, lightweight %d, head %s, digest %s",
		r.Repo, len(r.Tags), r.Annotated, r.Lightweight, r.HeadSHA, r.Digest)
}

// execRunner is the real runner: git with the exact argv and environment, run
// from an empty temporary directory that is also HOME.
type execRunner struct{}

type cappedBuffer struct {
	buf   bytes.Buffer
	limit int
	over  bool
}

func (c *cappedBuffer) Write(p []byte) (int, error) {
	if room := c.limit + 1 - c.buf.Len(); room > 0 {
		if len(p) > room {
			c.buf.Write(p[:room])
		} else {
			c.buf.Write(p)
		}
	}
	if c.buf.Len() > c.limit {
		c.over = true
	}
	return len(p), nil
}

// runnerEnv is the spec environment plus HOME.
func runnerEnv(spec ExecSpec, home string) []string {
	return append(append([]string(nil), spec.Env...), "HOME="+home)
}

func (execRunner) Run(ctx context.Context, spec ExecSpec) ExecResult {
	if len(spec.Argv) < 2 || spec.Argv[0] != "git" {
		return ExecResult{Err: errors.New("refused argv")}
	}
	gitBin := ""
	for _, c := range bindingGitDirs {
		if st, err := os.Stat(c); err == nil && st.Mode().IsRegular() && st.Mode()&0o111 != 0 {
			gitBin = c
			break
		}
	}
	if gitBin == "" {
		return ExecResult{Err: errors.New("git binary not found")}
	}
	home, err := os.MkdirTemp("", "prufyx-binding-")
	if err != nil {
		return ExecResult{Err: err}
	}
	defer os.RemoveAll(home)
	cmd := exec.CommandContext(ctx, gitBin, spec.Argv[1:]...)
	so, se := prepareCmd(cmd, runnerEnv(spec, home), home)
	return finishCmd(ctx, cmd, so, se)
}

// bindingWaitDelay bounds how long Wait lingers on the output pipes after the
// process was killed, so a stuck child cannot hold the run past its deadline.
const bindingWaitDelay = 2 * time.Second

// prepareCmd sets the exact environment and directory, capped output buffers,
// a kill of the whole process group on cancel, and a wait delay.
func prepareCmd(cmd *exec.Cmd, env []string, dir string) (so, se *cappedBuffer) {
	cmd.Env = env
	cmd.Dir = dir
	so, se = &cappedBuffer{limit: bindingMaxOutput}, &cappedBuffer{limit: bindingMaxStderr}
	cmd.Stdout, cmd.Stderr = so, se
	cmd.WaitDelay = bindingWaitDelay
	killGroupOnCancel(cmd)
	return so, se
}

// finishCmd runs the prepared command and maps the outcome.
func finishCmd(ctx context.Context, cmd *exec.Cmd, so, se *cappedBuffer) ExecResult {
	runErr := cmd.Run()
	res := ExecResult{Stdout: so.buf.Bytes(), Stderr: se.buf.Bytes()}
	// A capped buffer that overflowed holds limit+1 bytes and so stays over
	// the parse limit; it is never read as a short, valid answer.
	if ctx.Err() != nil {
		res.TimedOut = true
		return res
	}
	var ee *exec.ExitError
	switch {
	case runErr == nil:
	case errors.As(runErr, &ee):
		res.Exit = ee.ExitCode()
		if res.Exit == 0 {
			res.Exit = -1
		}
	default:
		res.Err = runErr
	}
	return res
}
