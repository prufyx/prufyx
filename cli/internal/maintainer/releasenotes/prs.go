// SPDX-License-Identifier: AGPL-3.0-only

package releasenotes

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
)

// PR is one pull request merged between two revisions.
type PR struct {
	Number int // 0 when the merge commit is not a GitHub pull-request merge
	Title  string
}

var mergeSubject = regexp.MustCompile(`^Merge pull request #(\d+) from `)

// MergedPRs lists the merge commits on the first-parent line of from..to,
// oldest first. The title of a pull request is the first line of the merge
// commit body, which GitHub fills from the pull request title.
func MergedPRs(repo, from, to string) ([]PR, error) {
	for _, r := range []string{from, to} {
		if r == "" || strings.HasPrefix(r, "-") {
			return nil, fmt.Errorf("invalid revision %q", r)
		}
	}
	cmd := exec.CommandContext(context.Background(), "git", "-C", repo, "log", "--first-parent", "--merges", "--reverse",
		"--format=%s%x1f%b%x1e", from+".."+to)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("git log %s..%s: %w: %s", from, to, err, strings.TrimSpace(errb.String()))
	}
	return parsePRs(out.String()), nil
}

func parsePRs(log string) []PR {
	var prs []PR
	for _, rec := range strings.Split(log, "\x1e") {
		rec = strings.TrimLeft(rec, "\n")
		if strings.TrimSpace(rec) == "" {
			continue
		}
		subject, body, _ := strings.Cut(rec, "\x1f")
		subject = clean(subject)
		pr := PR{Title: subject}
		if m := mergeSubject.FindStringSubmatch(subject); m != nil {
			pr.Number, _ = strconv.Atoi(m[1])
			pr.Title = ""
			for _, l := range strings.Split(body, "\n") {
				if l = clean(l); l != "" {
					pr.Title = l
					break
				}
			}
			if pr.Title == "" {
				pr.Title = subject
			}
		}
		prs = append(prs, pr)
	}
	return prs
}

// clean makes a git-supplied string one printable line.
func clean(s string) string {
	return strings.TrimSpace(strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, s))
}
