// SPDX-License-Identifier: AGPL-3.0-only

package factorymirror

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strings"
)

const maxGitOutput = 64 << 20

// GitRunner runs one git command. dir may be empty. It exists so tests can
// observe which network commands the mirror issues.
type GitRunner interface {
	Run(ctx context.Context, dir string, args ...string) ([]byte, error)
	// RunStdin is Run with data on standard input.
	RunStdin(ctx context.Context, dir string, stdin []byte, args ...string) ([]byte, error)
}

// ExecGit runs the git binary found in PATH with a scrubbed environment:
// no prompts, no system or user configuration, no pager.
type ExecGit struct {
	// AllowProtocols is the value of GIT_ALLOW_PROTOCOL ("https" by default).
	AllowProtocols string
	// Offline disables every transport and lazy object fetching.
	Offline bool
}

type limitBuffer struct {
	buf   bytes.Buffer
	limit int
	over  bool
}

func (l *limitBuffer) Write(p []byte) (int, error) {
	if l.buf.Len()+len(p) > l.limit {
		l.over = true
		return len(p), nil
	}
	return l.buf.Write(p)
}

func (g ExecGit) env() []string {
	allow := g.AllowProtocols
	if allow == "" {
		allow = "https"
	}
	env := []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + os.TempDir(),
		"LC_ALL=C",
		"GIT_TERMINAL_PROMPT=0",
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_CONFIG_GLOBAL=" + os.DevNull,
		"GIT_PAGER=cat",
		"GIT_ALLOW_PROTOCOL=" + allow,
		// The state directory is operator-owned; it may belong to another
		// uid than the process (bind mounts), which git would refuse.
		"GIT_CONFIG_COUNT=1", "GIT_CONFIG_KEY_0=safe.directory", "GIT_CONFIG_VALUE_0=*",
	}
	if g.Offline {
		env = append(env, "GIT_NO_LAZY_FETCH=1", "GIT_ALLOW_PROTOCOL=none")
	}
	return env
}

// Run implements GitRunner.
func (g ExecGit) Run(ctx context.Context, dir string, args ...string) ([]byte, error) {
	return g.RunStdin(ctx, dir, nil, args...)
}

// RunStdin implements GitRunner.
func (g ExecGit) RunStdin(ctx context.Context, dir string, stdin []byte, args ...string) ([]byte, error) {
	full := args
	if g.Offline {
		full = append([]string{"-c", "protocol.allow=never"}, args...)
	}
	cmd := exec.CommandContext(ctx, "git", full...)
	cmd.Dir = dir
	cmd.Env = g.env()
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	out := &limitBuffer{limit: maxGitOutput}
	var stderr limitBuffer
	stderr.limit = 1 << 16
	cmd.Stdout = out
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.buf.String())
		if len(msg) > 500 {
			msg = msg[:500]
		}
		return nil, &GitError{Args: args, Err: err, Stderr: msg}
	}
	if out.over {
		return nil, &GitError{Args: args, Err: errors.New("output too large")}
	}
	return out.buf.Bytes(), nil
}

// GitError carries a failed git invocation.
type GitError struct {
	Args   []string
	Err    error
	Stderr string
}

func (e *GitError) Error() string {
	name := "git"
	if len(e.Args) > 0 {
		name += " " + e.Args[0]
		if e.Args[0] == "-c" && len(e.Args) > 2 {
			name = "git " + e.Args[2]
		}
	}
	if e.Stderr != "" {
		return fmt.Sprintf("%s: %v: %s", name, e.Err, e.Stderr)
	}
	return fmt.Sprintf("%s: %v", name, e.Err)
}
func (e *GitError) Unwrap() error { return e.Err }

// TagInfo is one tag as recorded by the mirror. Commit is the fully peeled
// commit; Object is the tag object for annotated tags and empty otherwise.
type TagInfo struct {
	Commit string `json:"commit"`
	Object string `json:"object,omitempty"`
}

// Snapshot is the remote ref state seen by one "git ls-remote".
type Snapshot struct {
	Heads map[string]string  // branch -> commit
	Tags  map[string]TagInfo // tag -> commit
}

// Fingerprint is a stable digest of the snapshot.
func (s Snapshot) Fingerprint() string {
	var lines []string
	for n, c := range s.Heads {
		lines = append(lines, "h "+n+" "+c)
	}
	for n, t := range s.Tags {
		lines = append(lines, "t "+n+" "+t.Commit+" "+t.Object)
	}
	sort.Strings(lines)
	sum := sha256.Sum256([]byte(strings.Join(lines, "\n")))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func isSHA(s string) bool {
	if len(s) != 40 {
		return false
	}
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// ParseLsRemote parses "git ls-remote --tags --heads" output. Peeled
// entries (refs/tags/x^{}) provide the commit of an annotated tag.
func ParseLsRemote(out []byte) (Snapshot, error) {
	snap := Snapshot{Heads: map[string]string{}, Tags: map[string]TagInfo{}}
	direct := map[string]string{}
	peeled := map[string]string{}
	for _, line := range strings.Split(string(out), "\n") {
		if line == "" {
			continue
		}
		fields := strings.Split(line, "\t")
		if len(fields) != 2 || !isSHA(fields[0]) {
			return Snapshot{}, fmt.Errorf("%w: unexpected ls-remote line", ErrInvalid)
		}
		sha, ref := fields[0], fields[1]
		switch {
		case strings.HasPrefix(ref, "refs/heads/"):
			snap.Heads[strings.TrimPrefix(ref, "refs/heads/")] = sha
		case strings.HasPrefix(ref, "refs/tags/") && strings.HasSuffix(ref, "^{}"):
			peeled[strings.TrimSuffix(strings.TrimPrefix(ref, "refs/tags/"), "^{}")] = sha
		case strings.HasPrefix(ref, "refs/tags/"):
			direct[strings.TrimPrefix(ref, "refs/tags/")] = sha
		}
	}
	for name, sha := range direct {
		if p, ok := peeled[name]; ok {
			snap.Tags[name] = TagInfo{Commit: p, Object: sha}
		} else {
			snap.Tags[name] = TagInfo{Commit: sha}
		}
	}
	return snap, nil
}
