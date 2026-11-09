// SPDX-License-Identifier: AGPL-3.0-only

package knowledgepacket

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

// repo runs read-only git commands against one local repository.
type repo struct{ dir string }

func (r repo) git(ctx context.Context, args ...string) ([]byte, error) {
	full := append([]string{"-C", r.dir, "-c", "core.quotepath=off", "-c", "log.showSignature=false"}, args...)
	cmd := exec.CommandContext(ctx, "git", full...)
	cmd.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1", "GIT_TERMINAL_PROMPT=0", "GIT_OPTIONAL_LOCKS=0", "LC_ALL=C")
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("git %s: %w: %s", args[0], err, strings.TrimSpace(errb.String()))
	}
	return out.Bytes(), nil
}

func (r repo) resolve(ctx context.Context, rev string) (string, error) {
	if rev == "" || strings.HasPrefix(rev, "-") {
		return "", fmt.Errorf("revision %q is not acceptable", rev)
	}
	out, err := r.git(ctx, "rev-parse", "--verify", "--end-of-options", rev+"^{commit}")
	if err != nil {
		return "", err
	}
	sha := strings.TrimSpace(string(out))
	if !sha40.MatchString(sha) {
		return "", fmt.Errorf("revision %q did not resolve to a 40-hex commit", rev)
	}
	return sha, nil
}

func (r repo) isAncestor(ctx context.Context, anc, desc string) (bool, error) {
	cmd := exec.CommandContext(ctx, "git", "-C", r.dir, "merge-base", "--is-ancestor", anc, desc)
	cmd.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1", "GIT_TERMINAL_PROMPT=0", "LC_ALL=C")
	err := cmd.Run()
	if err == nil {
		return true, nil
	}
	if ee, ok := err.(*exec.ExitError); ok && ee.ExitCode() == 1 {
		return false, nil
	}
	return false, fmt.Errorf("git merge-base: %w", err)
}

func (r repo) revList(ctx context.Context, base, head string, merges bool) ([]string, error) {
	flag := "--no-merges"
	if merges {
		flag = "--merges"
	}
	out, err := r.git(ctx, "rev-list", "--first-parent", flag, "--reverse", base+".."+head)
	if err != nil {
		return nil, err
	}
	return strings.Fields(string(out)), nil
}

func (r repo) parents(ctx context.Context, c string) ([]string, error) {
	out, err := r.git(ctx, "rev-list", "--parents", "-n", "1", c)
	if err != nil {
		return nil, err
	}
	f := strings.Fields(string(out))
	if len(f) == 0 || f[0] != c {
		return nil, fmt.Errorf("cannot read parents of %s", c)
	}
	return f[1:], nil
}

func (r repo) subject(ctx context.Context, c string) (string, error) {
	out, err := r.git(ctx, "show", "-s", "--format=%s", c)
	return strings.TrimSpace(string(out)), err
}

func (r repo) committerDate(ctx context.Context, c string) (time.Time, error) {
	out, err := r.git(ctx, "show", "-s", "--format=%cI", c)
	if err != nil {
		return time.Time{}, err
	}
	return time.Parse(time.RFC3339, strings.TrimSpace(string(out)))
}

// changedFiles lists the paths a merge changed against its first parent.
func (r repo) changedFiles(ctx context.Context, a, b string) ([]string, error) {
	out, err := r.git(ctx, "diff", "--name-only", "--no-renames", "-z", a, b, "--")
	if err != nil {
		return nil, err
	}
	var files []string
	for _, f := range strings.Split(string(out), "\x00") {
		if f != "" {
			files = append(files, f)
		}
	}
	return files, nil
}

func (r repo) nameStatus(ctx context.Context, a, b string, paths ...string) ([]PathChange, error) {
	args := append([]string{"diff", "--name-status", "--no-renames", "-z", a, b, "--"}, paths...)
	out, err := r.git(ctx, args...)
	if err != nil {
		return nil, err
	}
	parts := strings.Split(strings.TrimRight(string(out), "\x00"), "\x00")
	var res []PathChange
	if len(parts) == 1 && parts[0] == "" {
		return res, nil
	}
	if len(parts)%2 != 0 {
		return nil, fmt.Errorf("unparsable git name-status output")
	}
	for i := 0; i < len(parts); i += 2 {
		res = append(res, PathChange{Status: parts[i], Path: parts[i+1]})
	}
	return res, nil
}

func (r repo) show(ctx context.Context, rev, path string) ([]byte, error) {
	return r.git(ctx, "show", rev+":"+path)
}
