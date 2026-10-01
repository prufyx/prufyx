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
	// ErrRepoFrozen means the repository has an unacknowledged alarm: its
	// tags are not trustworthy until a person has reviewed the alarm.
	ErrRepoFrozen = errors.New("factory mirror: repository is frozen by an unacknowledged alarm")
	// ErrReleasesIncomplete means release metadata is missing, stale, or
	// truncated and must not be used to derive anything.
	ErrReleasesIncomplete = errors.New("factory mirror: release metadata is not complete")
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

// frozen reports whether the repository has an unacknowledged alarm.
func (r *Reader) frozen(info *RepoInfo) bool {
	key := info.Host + "/" + info.Owner + "/" + info.Name
	for _, a := range r.idx.Alarms {
		if a.Repo == key && !a.Acknowledged {
			return true
		}
	}
	return false
}

// ResolveTag returns the commit a tag pointed at when the mirror last
// looked. While the repository is frozen it returns ErrRepoFrozen: the
// recorded tags may include one that upstream moved.
func (r *Reader) ResolveTag(repo, tag string) (string, error) {
	info, err := r.info(repo)
	if err != nil {
		return "", err
	}
	if r.frozen(info) {
		return "", ErrRepoFrozen
	}
	t, ok := info.Tags[tag]
	if !ok {
		return "", fmt.Errorf("%w: unknown tag", ErrInvalid)
	}
	return t.Commit, nil
}

// Tags returns a copy of the recorded tag -> commit map, or ErrRepoFrozen
// while the repository has an unacknowledged alarm.
func (r *Reader) Tags(repo string) (map[string]TagInfo, error) {
	info, err := r.info(repo)
	if err != nil {
		return nil, err
	}
	if r.frozen(info) {
		return nil, ErrRepoFrozen
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
	return r.frozen(info), nil
}

// UsableReleases returns the release metadata only when it is known and
// fresh; a list the mirror itself cut short (Truncated) is still returned,
// because its newest entries are present. Otherwise it returns
// ErrReleasesIncomplete. Anything that needs the NEWEST release may use
// it; anything that needs every release must use CompleteReleases.
func (r *Reader) UsableReleases(repo string) (Releases, error) {
	rel, err := r.Releases(repo)
	if err != nil {
		return Releases{}, err
	}
	if rel.Status != ReleasesKnown {
		return Releases{}, fmt.Errorf("%w: status %q, reason %q", ErrReleasesIncomplete, rel.Status, rel.Reason)
	}
	if t, err := time.Parse(time.RFC3339, rel.FetchedAt); err != nil || time.Since(t) > DefaultReleasesTTL {
		return Releases{}, fmt.Errorf("%w: last revalidated %q", ErrReleasesIncomplete, rel.FetchedAt)
	}
	return rel, nil
}

// CompleteReleases returns the release metadata only when it is known,
// fresh and not truncated; otherwise it returns ErrReleasesIncomplete.
// Anything that derives a release line from the list must use this.
func (r *Reader) CompleteReleases(repo string) (Releases, error) {
	rel, err := r.UsableReleases(repo)
	if err != nil {
		return Releases{}, err
	}
	if rel.Truncated {
		return Releases{}, fmt.Errorf("%w: the list is truncated", ErrReleasesIncomplete)
	}
	return rel, nil
}

// RepoStatus is the mirror's own record of when it last looked at one
// repository.
type RepoStatus struct {
	// Status is "ok" after a successful check, "error" after a failed one.
	Status string
	// LastCheckedAt is the last check attempt (successful only when Status
	// is "ok"); LastFetchedAt is when refs last changed and were fetched.
	LastCheckedAt string
	LastFetchedAt string
	// ReleasesFetchedAt is the last successful revalidation of the release
	// metadata.
	ReleasesFetchedAt string
}

// RepoStatus reports when the mirror last looked at a repository.
func (r *Reader) RepoStatus(repo string) (RepoStatus, error) {
	info, err := r.info(repo)
	if err != nil {
		return RepoStatus{}, err
	}
	return RepoStatus{Status: info.Status, LastCheckedAt: info.LastCheckedAt, LastFetchedAt: info.LastFetchedAt, ReleasesFetchedAt: info.Releases.FetchedAt}, nil
}

// IndexInfo identifies the index snapshot this Reader sees: when the mirror
// last wrote it and a digest of its bytes.
func (r *Reader) IndexInfo() (updatedAt, digest string) { return r.idx.UpdatedAt, r.idx.Digest() }

// OpenAlarms lists the unacknowledged alarms.
func (r *Reader) OpenAlarms() []Alarm { return r.idx.OpenAlarms() }
