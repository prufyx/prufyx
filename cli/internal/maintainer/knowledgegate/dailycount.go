// SPDX-License-Identifier: AGPL-3.0-only

package knowledgegate

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/prufyx/prufyx/cli/internal/strictjson"
)

// Bounds of the daily count.
const (
	// MaxDailyCommits bounds the commits of one day the count reads; more
	// make the count unavailable (and so the change ineligible for
	// automatic merging) rather than partial.
	MaxDailyCommits     = 300
	maxDailyCommitsFile = 4 << 20
)

// DailyCommit is one commit of the main branch's last day: the commit, its
// first parent, and its author's login (nil when GitHub knows none).
type DailyCommit struct {
	SHA    string  `json:"sha"`
	Parent *string `json:"parent"`
	Author *string `json:"author"`
}

// ParseDailyCommits parses the commit list the workflow reduces from the
// GitHub API.
func ParseDailyCommits(raw []byte) ([]DailyCommit, error) {
	if len(raw) > maxDailyCommitsFile {
		return nil, errors.New("commit list too large")
	}
	if err := strictjson.Check(raw); err != nil {
		return nil, fmt.Errorf("commit list: %w", err)
	}
	var out []DailyCommit
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("commit list: %w", err)
	}
	if len(out) > MaxDailyCommits {
		return nil, fmt.Errorf("commit list holds more than %d commits", MaxDailyCommits)
	}
	for _, c := range out {
		if !shaRE.MatchString(c.SHA) {
			return nil, errors.New("commit list: a commit id is not a full commit id")
		}
	}
	return out, nil
}

// exportedPaths are the repository paths Classify reads.
func (l Layout) exportedPaths() []string {
	out := []string{l.PausePath}
	for _, spec := range l.Packs {
		out = append(out, spec.Path, l.ReattestDir+"/"+spec.Name+"/chain/")
	}
	return out
}

// DailyCount counts the loosening changes the automation merged: for every
// listed commit not authored by someone else (an unknown author counts),
// the commit is classified against its first parent with the same code as
// a pull request, and the loosening changes are added up. The objects of
// every commit and parent must already be in gitDir; nothing is fetched. A
// commit that cannot be classified fails the count: a partial count would
// read as a smaller one.
func DailyCount(ctx context.Context, layout Layout, gitDir string, commits []DailyCommit, bot string) (int, error) {
	if bot == "" {
		bot = DefaultBotLogin
	}
	scratch, err := os.MkdirTemp("", "gate-daily-")
	if err != nil {
		return 0, err
	}
	defer os.RemoveAll(scratch)
	total := 0
	for i, c := range commits {
		if c.Author != nil && *c.Author != bot {
			continue
		}
		if c.Parent == nil || !shaRE.MatchString(*c.Parent) {
			return 0, fmt.Errorf("commit %s has no first parent to compare against", logSafe(c.SHA))
		}
		dir := filepath.Join(scratch, fmt.Sprint(i))
		trees := [2]Tree{{Root: filepath.Join(dir, "base")}, {Root: filepath.Join(dir, "head")}}
		for j, sha := range []string{*c.Parent, c.SHA} {
			if err := os.MkdirAll(dir, 0o755); err != nil {
				return 0, err
			}
			if err := Export(ctx, ExportOptions{GitDir: gitDir, Commit: sha, Out: trees[j].Root, Only: layout.exportedPaths()}); err != nil {
				return 0, fmt.Errorf("commit %s: %w", logSafe(c.SHA), err)
			}
		}
		cls, err := Classify(layout, trees[0], trees[1])
		if err != nil {
			return 0, fmt.Errorf("commit %s: %w", logSafe(c.SHA), err)
		}
		_, loose := cls.Counts()
		total += loose
		if err := os.RemoveAll(dir); err != nil {
			return 0, err
		}
	}
	return total, nil
}
