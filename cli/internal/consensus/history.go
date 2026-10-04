// SPDX-License-Identifier: AGPL-3.0-only

package consensus

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
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
	// ErrHistoryUnbounded: the range holds more commits than the limit.
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

// History lists the commits of a release range: every commit reachable
// from to and not from from. It returns ErrHistoryUnbounded when there are
// more than limit commits.
type History interface {
	RangeSubjects(repo extract.RepoRef, from, to string, limit int) ([]CommitSubject, error)
}

// MirrorHistory reads commit objects from the offline factory mirror. A
// mirror cloned without file contents still holds every commit object, so
// the walk never needs the network; git runs with every transport and
// lazy fetching disabled.
type MirrorHistory struct {
	State string
}

// RangeSubjects implements History.
func (m MirrorHistory) RangeSubjects(repo extract.RepoRef, from, to string, limit int) ([]CommitSubject, error) {
	if !extract.IsCommitSHA(from) || !extract.IsCommitSHA(to) || limit < 1 {
		return nil, errors.New("range ends must be full commit SHAs")
	}
	parsed, err := factorymirror.ParseRepo(repo.Key)
	if err != nil {
		return nil, err
	}
	dir := filepath.Join(m.State, parsed.RelPath())
	if st, err := os.Stat(dir); err != nil || !st.IsDir() {
		return nil, fmt.Errorf("%w: %s is not mirrored", ErrHistoryIncomplete, repo.Key)
	}
	g := factorymirror.ExecGit{Offline: true, StateDir: m.State}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	for _, c := range []string{from, to} {
		if _, err := g.Run(ctx, dir, "cat-file", "-e", c+"^{commit}"); err != nil {
			return nil, fmt.Errorf("%w: commit %s is not in the mirror", ErrHistoryIncomplete, c)
		}
	}
	out, err := g.Run(ctx, dir, "log", "-z", "--no-color", "--no-decorate", "--no-show-signature",
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

// FixtureHistory reads the commit graph of a fixture tree:
//
//	<root>/<host>/<owner>/<name>/history.json
//	{"commits": [{"commit": "<sha>", "parents": ["<sha>", ...], "subject": "..."}, ...]}
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

// RangeSubjects implements History.
func (f FixtureHistory) RangeSubjects(repo extract.RepoRef, from, to string, limit int) ([]CommitSubject, error) {
	raw, err := os.ReadFile(filepath.Join(f.Root, filepath.FromSlash(repo.Key), "history.json"))
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrHistoryUnavailable
	}
	if err != nil {
		return nil, err
	}
	var doc struct {
		Commits []fixtureCommit `json:"commits"`
	}
	if err := strictjson.Decode(raw, &doc); err != nil {
		return nil, fmt.Errorf("fixture history: %w", err)
	}
	graph := map[string]fixtureCommit{}
	for _, c := range doc.Commits {
		if !extract.IsCommitSHA(c.Commit) {
			return nil, fmt.Errorf("fixture history: bad commit %q", c.Commit)
		}
		if _, dup := graph[c.Commit]; dup {
			return nil, fmt.Errorf("fixture history: commit %s appears twice", c.Commit)
		}
		graph[c.Commit] = c
	}
	reach := func(start string, stop map[string]bool, max int) ([]string, error) {
		seen := map[string]bool{}
		queue := []string{start}
		var order []string
		for len(queue) > 0 {
			c := queue[0]
			queue = queue[1:]
			if seen[c] || stop[c] {
				continue
			}
			node, ok := graph[c]
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
	ancestors, err := reach(from, nil, 0)
	if err != nil {
		return nil, err
	}
	stop := map[string]bool{}
	for _, c := range ancestors {
		stop[c] = true
	}
	inRange, err := reach(to, stop, limit)
	if err != nil {
		return nil, err
	}
	out := make([]CommitSubject, 0, len(inRange))
	for _, c := range inRange {
		out = append(out, CommitSubject{Commit: c, Subject: graph[c].Subject})
	}
	return out, nil
}
