// SPDX-License-Identifier: AGPL-3.0-only

package releasenotes

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"
)

// The generated part of a CHANGELOG entry or release notes file sits between these two lines.
const (
	MarkerBegin = "<!-- release-notes:begin -->"
	MarkerEnd   = "<!-- release-notes:end -->"
)

// ReplaceBlock replaces the text between the marker lines of doc with
// block. Each marker must appear exactly once, alone on its line, begin first.
func ReplaceBlock(doc, block string) (string, error) {
	lines := strings.Split(doc, "\n")
	begin, end := -1, -1
	for i, l := range lines {
		switch strings.TrimRight(l, " \r") {
		case MarkerBegin:
			if begin >= 0 {
				return "", fmt.Errorf("the file has two %s lines", MarkerBegin)
			}
			begin = i
		case MarkerEnd:
			if end >= 0 {
				return "", fmt.Errorf("the file has two %s lines", MarkerEnd)
			}
			end = i
		}
	}
	if begin < 0 || end < 0 || end < begin {
		return "", fmt.Errorf("the file needs one %s line followed by one %s line", MarkerBegin, MarkerEnd)
	}
	out := append([]string{}, lines[:begin+1]...)
	out = append(out, "", strings.TrimRight(block, "\n"), "")
	out = append(out, lines[end:]...)
	return strings.Join(out, "\n"), nil
}

// Commit resolves a revision to a short commit hash.
func Commit(repo, rev string) (string, error) {
	if rev == "" || strings.HasPrefix(rev, "-") {
		return "", fmt.Errorf("invalid revision %q", rev)
	}
	cmd := exec.CommandContext(context.Background(), "git", "-C", repo, "rev-parse", "--short=12", "--verify", "--end-of-options", rev+"^{commit}")
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("git rev-parse %s: %w: %s", rev, err, strings.TrimSpace(errb.String()))
	}
	return strings.TrimSpace(out.String()), nil
}
