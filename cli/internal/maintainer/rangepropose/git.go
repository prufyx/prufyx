// SPDX-License-Identifier: AGPL-3.0-only

package rangepropose

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

const (
	// maxFileBytes bounds one file read from a tree.
	maxFileBytes = 8 << 20
	maxGitOutput = 32 << 20
	gitTimeout   = 2 * time.Minute
)

// errOutputTooLarge reports a git answer over maxGitOutput.
var errOutputTooLarge = errors.New("git output too large")

// gitBinaries are the only places git is taken from; the caller's PATH is
// never searched.
var gitBinaries = []string{"/usr/bin/git", "/usr/local/bin/git", "/bin/git"}

func findGit(candidates []string) (string, error) {
	for _, c := range candidates {
		if st, err := os.Stat(c); err == nil && st.Mode().IsRegular() && st.Mode()&0o111 != 0 {
			return c, nil
		}
	}
	return "", errors.New("git binary not found")
}

// gitEnv is the fixed environment of every git command. Nothing of the
// caller's environment reaches git: no ambient configuration, no network
// protocol, no lazy fetch of a missing object, no replace objects.
func gitEnv() []string {
	return []string{
		"PATH=/usr/bin:/bin:/usr/local/bin", "HOME=/nonexistent", "XDG_CONFIG_HOME=/nonexistent", "LC_ALL=C",
		"GIT_TERMINAL_PROMPT=0", "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_SYSTEM=/dev/null", "GIT_CONFIG_GLOBAL=/dev/null",
		"GIT_NO_REPLACE_OBJECTS=1", "GIT_NO_LAZY_FETCH=1", "GIT_ALLOW_PROTOCOL=none",
	}
}

// runGit runs one read-only git command on local objects of exactly the
// given git directory; git never discovers a repository by itself.
func runGit(ctx context.Context, gitDir string, args ...string) ([]byte, error) {
	return execGit(ctx, gitDir, io.Discard, args...)
}

// runGitSilent is runGit for a command whose warnings mean an incomplete
// answer: any output on standard error is a failure.
func runGitSilent(ctx context.Context, gitDir string, args ...string) ([]byte, error) {
	warnings := &boundedBuffer{}
	out, err := execGit(ctx, gitDir, warnings, args...)
	if err == nil && (warnings.over || warnings.buf.Len() != 0) {
		return nil, fmt.Errorf("git %s: warnings", args[0])
	}
	return out, err
}

// gitArgv pins the git directory and switches off hooks, the file system
// monitor, every protocol and automatic maintenance.
func gitArgv(gitDir string, args ...string) []string {
	argv := []string{"-c", "core.hooksPath=/dev/null", "-c", "core.fsmonitor=false", "-c", "protocol.allow=never", "-c", "gc.auto=0", "--git-dir=" + gitDir}
	return append(argv, args...)
}

func execGit(ctx context.Context, gitDir string, stderr io.Writer, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, gitTimeout)
	defer cancel()
	bin, err := findGit(gitBinaries)
	if err != nil {
		return nil, err
	}
	cmd := exec.CommandContext(ctx, bin, gitArgv(gitDir, args...)...)
	cmd.Env = gitEnv()
	out := &boundedBuffer{}
	cmd.Stdout, cmd.Stderr = out, stderr
	if err := cmd.Run(); err != nil {
		if out.over {
			return nil, errOutputTooLarge
		}
		return nil, fmt.Errorf("git %s: %w", args[0], err)
	}
	return out.buf.Bytes(), nil
}

type boundedBuffer struct {
	buf  bytes.Buffer
	over bool
}

func (b *boundedBuffer) Write(p []byte) (int, error) {
	if b.buf.Len()+len(p) > maxGitOutput {
		b.over = true
		return 0, errOutputTooLarge
	}
	return b.buf.Write(p)
}

// Reasons a path of a readable tree cannot be compared.
const (
	fileNotRegular = "not-regular"
	fileTooLarge   = "too-large"
	fileBinary     = "binary"
	filePointer    = "lfs-pointer"
)

// treeFile is one path at one commit. A nil *treeFile means a successful
// tree listing did not hold the path. problem names why the content cannot
// be compared; data is set only when problem is empty.
type treeFile struct {
	problem string
	data    []byte
}

// readTreeFile resolves path by exact lookup in a tree listing of commit. A
// missing object is an error, never an absent path.
func readTreeFile(ctx context.Context, gitDir, commit, path string) (*treeFile, error) {
	out, err := runGit(ctx, gitDir, "ls-tree", "-z", "--full-tree", commit, "--", path)
	if err != nil {
		return nil, refuse(CodeObjectMissing, "the tree of commit "+commit+" cannot be read")
	}
	if len(out) == 0 {
		return nil, nil
	}
	head, name, found := strings.Cut(strings.TrimSuffix(string(out), "\x00"), "\t")
	fields := strings.Fields(head)
	if !found || name != path || len(fields) != 3 || !commitRE.MatchString(fields[2]) {
		return nil, refuse(CodeGit, "unexpected tree answer at commit "+commit)
	}
	if fields[1] != "blob" || fields[0] != "100644" && fields[0] != "100755" {
		return &treeFile{problem: fileNotRegular}, nil
	}
	missing := refuse(CodeObjectMissing, "a file object of commit "+commit+" is not in the clone")
	size, err := runGit(ctx, gitDir, "cat-file", "-s", fields[2])
	if err != nil {
		return nil, missing
	}
	n, err := strconv.ParseInt(strings.TrimSpace(string(size)), 10, 64)
	if err != nil || n < 0 {
		return nil, refuse(CodeGit, "unexpected object size at commit "+commit)
	}
	if n > maxFileBytes {
		return &treeFile{problem: fileTooLarge}, nil
	}
	data, err := runGit(ctx, gitDir, "cat-file", "blob", fields[2])
	if err != nil {
		return nil, missing
	}
	switch {
	case bytes.IndexByte(data, 0) >= 0:
		return &treeFile{problem: fileBinary}, nil
	case bytes.HasPrefix(data, []byte("version https://git-lfs.github.com/spec/")):
		return &treeFile{problem: filePointer}, nil
	}
	return &treeFile{data: data}, nil
}
