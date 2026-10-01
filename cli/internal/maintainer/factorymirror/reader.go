// SPDX-License-Identifier: AGPL-3.0-only

package factorymirror

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Reader errors. A caller must treat every one of them as "no evidence".
var (
	ErrRepoNotMirrored = errors.New("factory mirror: repository is not mirrored")
	ErrCommitUnknown   = errors.New("factory mirror: commit is not in the mirror")
	ErrPathNotFound    = errors.New("factory mirror: path does not exist at that commit")
	ErrNotAFile        = errors.New("factory mirror: path is not a regular file")
	// ErrBlobNotLocal means the commit and path exist but the file contents
	// were never fetched. The Reader does not fetch them (it has no network
	// access); the mirror command does, via Options.Wants.
	ErrBlobNotLocal = errors.New("factory mirror: file contents are not materialized in the mirror")
	ErrTooLarge     = errors.New("factory mirror: file too large")
)

// MaxFileBytes bounds a single Read.
const MaxFileBytes = 32 << 20

// Reader reads pinned bytes from the mirror strictly offline: every git
// process it starts has network transports disabled and lazy object
// fetching switched off, so reading can never download anything. Contents
// that are not already local are reported as ErrBlobNotLocal. Only the
// mirror command (Run with Options.Wants) may fetch them.
//
// A Reader sees the index as it was when it was opened.
type Reader struct {
	state string
	idx   *Index
	git   GitRunner
	ctx   context.Context
}

// OpenReader opens the mirror in stateDir.
func OpenReader(stateDir string) (*Reader, error) {
	idx, err := LoadIndex(stateDir)
	if err != nil {
		return nil, err
	}
	return &Reader{state: stateDir, idx: idx, git: ExecGit{Offline: true, StateDir: stateDir}, ctx: context.Background()}, nil
}

func (r *Reader) dir(repo string) (Repo, string, error) {
	parsed, err := ParseRepo(repo)
	if err != nil {
		return Repo{}, "", err
	}
	dir := filepath.Join(r.state, parsed.RelPath())
	if st, err := os.Stat(dir); err != nil || !st.IsDir() {
		return parsed, "", ErrRepoNotMirrored
	}
	return parsed, dir, nil
}

func (r *Reader) run(dir string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(r.ctx, 2*time.Minute)
	defer cancel()
	return r.git.Run(ctx, dir, args...)
}

func (r *Reader) commitDir(repo, commit string) (string, error) {
	if !isSHA(commit) {
		return "", fmt.Errorf("%w: commit must be a full 40-character SHA", ErrInvalid)
	}
	_, dir, err := r.dir(repo)
	if err != nil {
		return "", err
	}
	if _, err := r.run(dir, "cat-file", "-e", commit+"^{commit}"); err != nil {
		return "", ErrCommitUnknown
	}
	return dir, nil
}

// HasCommit reports whether the commit object is present locally.
func (r *Reader) HasCommit(repo, commit string) bool {
	_, err := r.commitDir(repo, commit)
	return err == nil
}

// Read returns the contents of a regular file at a full commit SHA.
func (r *Reader) Read(repo, commit, path string) ([]byte, error) {
	clean, err := cleanRepoPath(path)
	if err != nil {
		return nil, err
	}
	dir, err := r.commitDir(repo, commit)
	if err != nil {
		return nil, err
	}
	entries, err := lsTree(r.ctx, r.git, dir, commit, clean, false)
	if err != nil {
		return nil, err
	}
	if len(entries) == 0 {
		return nil, ErrPathNotFound
	}
	e := entries[0]
	if len(entries) != 1 || e.Path != clean || e.Type != "blob" || e.Mode == "120000" {
		return nil, ErrNotAFile
	}
	sizeOut, err := r.run(dir, "cat-file", "-s", e.SHA)
	if err != nil {
		return nil, ErrBlobNotLocal
	}
	size, err := strconv.ParseInt(strings.TrimSpace(string(sizeOut)), 10, 64)
	if err != nil {
		return nil, ErrBlobNotLocal
	}
	if size > MaxFileBytes {
		return nil, ErrTooLarge
	}
	data, err := r.run(dir, "cat-file", "blob", e.SHA)
	if err != nil {
		return nil, ErrBlobNotLocal
	}
	return data, nil
}

// List returns the entries directly inside a directory at a commit ("" is
// the repository root). Listing needs only trees, which the mirror always
// holds for fetched commits.
func (r *Reader) List(repo, commit, dir string) ([]TreeEntry, error) {
	clean := ""
	if dir != "" {
		var err error
		if clean, err = cleanRepoPath(dir); err != nil {
			return nil, err
		}
	}
	gitDir, err := r.commitDir(repo, commit)
	if err != nil {
		return nil, err
	}
	entries, err := lsTree(r.ctx, r.git, gitDir, commit, clean, clean != "")
	if err != nil {
		return nil, err
	}
	if len(entries) == 0 && clean != "" {
		return nil, ErrPathNotFound
	}
	return entries, nil
}

func (r *Reader) info(repo string) (*RepoInfo, error) {
	parsed, err := ParseRepo(repo)
	if err != nil {
		return nil, err
	}
	info := r.idx.Repos[parsed.Key()]
	if info == nil {
		return nil, ErrRepoNotMirrored
	}
	return info, nil
}

// ResolveTag returns the commit a tag pointed at when the mirror last
// looked.
func (r *Reader) ResolveTag(repo, tag string) (string, error) {
	info, err := r.info(repo)
	if err != nil {
		return "", err
	}
	t, ok := info.Tags[tag]
	if !ok {
		return "", fmt.Errorf("%w: unknown tag", ErrInvalid)
	}
	return t.Commit, nil
}

// Tags returns a copy of the recorded tag -> commit map.
func (r *Reader) Tags(repo string) (map[string]TagInfo, error) {
	info, err := r.info(repo)
	if err != nil {
		return nil, err
	}
	out := make(map[string]TagInfo, len(info.Tags))
	for k, v := range info.Tags {
		out[k] = v
	}
	return out, nil
}

// Releases returns the cached release metadata; Status is "unknown" when no
// authenticated metadata exists.
func (r *Reader) Releases(repo string) (Releases, error) {
	info, err := r.info(repo)
	if err != nil {
		return Releases{}, err
	}
	return info.Releases, nil
}

// Frozen reports whether the repository has an unacknowledged alarm.
// Callers that would loosen results from this repository must refuse.
func (r *Reader) Frozen(repo string) (bool, error) {
	info, err := r.info(repo)
	if err != nil {
		return false, err
	}
	for _, a := range r.idx.Alarms {
		if a.Repo == info.Host+"/"+info.Owner+"/"+info.Name && !a.Acknowledged {
			return true, nil
		}
	}
	return false, nil
}

// OpenAlarms lists the unacknowledged alarms.
func (r *Reader) OpenAlarms() []Alarm { return r.idx.OpenAlarms() }
