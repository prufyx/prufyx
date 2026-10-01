// SPDX-License-Identifier: AGPL-3.0-only

package factorymirror

import (
	"context"
	"fmt"
	"path"
	"path/filepath"
	"strings"
	"time"
)

const blobBatch = 500

// cleanRepoPath validates a repository-relative file path.
func cleanRepoPath(p string) (string, error) {
	if p == "" || strings.ContainsRune(p, 0) || strings.HasPrefix(p, "/") || strings.Contains(p, "\n") {
		return "", fmt.Errorf("%w: path %q", ErrInvalid, p)
	}
	c := path.Clean(p)
	if c == "." || c == ".." || strings.HasPrefix(c, "../") || c != p {
		return "", fmt.Errorf("%w: path %q", ErrInvalid, p)
	}
	return c, nil
}

// materialize makes the wanted files readable offline. It is part of the
// mirror command: it may use the network (to fetch an unreachable pinned
// commit, and to fetch blobs lazily in batches) so that the Reader never has
// to.
func (r *run) materialize(ctx context.Context, wants []Want) []WantResult {
	var out []WantResult
	for _, w := range wants {
		out = append(out, r.materializeOne(ctx, w))
	}
	return out
}

func (r *run) materializeOne(ctx context.Context, w Want) WantResult {
	res := WantResult{Repo: w.Repo, Commit: w.Commit}
	fail := func(format string, a ...any) WantResult {
		res.Error = fmt.Sprintf(format, a...)
		return res
	}
	repo, err := ParseRepo(w.Repo)
	if err != nil || !isSHA(w.Commit) {
		return fail("invalid want")
	}
	r.mu.Lock()
	info := r.idx.Repos[repo.Key()]
	ok := info != nil && info.Status == "ok"
	r.mu.Unlock()
	dest := filepath.Join(r.opts.StateDir, repo.RelPath())
	if !ok {
		return fail("repository is not mirrored")
	}
	have := func(spec string) bool {
		_, err := r.offline().Run(ctx, dest, "cat-file", "-e", spec)
		return err == nil
	}
	if !have(w.Commit + "^{commit}") {
		if _, err := r.git(ctx, r.opts.GitTimeout, dest, "fetch", "-q", "--no-tags", "--no-write-fetch-head", "origin", w.Commit); err != nil || !have(w.Commit+"^{commit}") {
			return fail("commit is not available upstream")
		}
		// Keep it reachable.
		_, _ = r.git(ctx, time.Minute, dest, "update-ref", "refs/prufyx/preserved/"+w.Commit, w.Commit)
	}
	var missingOIDs []string
	for _, p := range w.Paths {
		clean, err := cleanRepoPath(p)
		if err != nil {
			return fail("invalid path")
		}
		entries, err := lsTree(ctx, r.offline(), dest, w.Commit, clean, false)
		if err != nil {
			return fail("ls-tree failed")
		}
		if len(entries) != 1 || entries[0].Type != "blob" || entries[0].Path != clean {
			res.Missing = append(res.Missing, clean)
			continue
		}
		if !have(entries[0].SHA) {
			missingOIDs = append(missingOIDs, entries[0].SHA)
		}
	}
	for start := 0; start < len(missingOIDs); start += blobBatch {
		end := min(start+blobBatch, len(missingOIDs))
		input := strings.Join(missingOIDs[start:end], "\n") + "\n"
		c, cancel := context.WithTimeout(ctx, r.opts.GitTimeout)
		// A normal (non-offline) runner: git fetches the missing blobs
		// from the promisor remote in one request.
		_, err := r.opts.Git.RunStdin(c, dest, []byte(input), "cat-file", "--batch-check")
		cancel()
		if err != nil {
			return fail("blob fetch failed")
		}
	}
	for _, oid := range missingOIDs {
		if have(oid) {
			res.Fetched++
		}
	}
	res.Complete = len(res.Missing) == 0 && res.Fetched == len(missingOIDs)
	return res
}

// offline returns a runner that cannot touch the network or lazily fetch.
func (r *run) offline() GitRunner {
	if r.opts.OfflineGit != nil {
		return r.opts.OfflineGit
	}
	return ExecGit{Offline: true}
}

// TreeEntry is one entry of a git tree.
type TreeEntry struct {
	Mode string `json:"mode"`
	Type string `json:"type"`
	SHA  string `json:"sha"`
	Path string `json:"path"`
}

// lsTree lists path (a file, or with dir=true the contents of a directory)
// at commit.
func lsTree(ctx context.Context, g GitRunner, dir, commit, p string, listDir bool) ([]TreeEntry, error) {
	args := []string{"ls-tree", "-z", commit}
	if p != "" {
		if listDir {
			p += "/"
		}
		args = append(args, "--", p)
	}
	raw, err := g.Run(ctx, dir, args...)
	if err != nil {
		return nil, err
	}
	var out []TreeEntry
	for _, rec := range strings.Split(string(raw), "\x00") {
		if rec == "" {
			continue
		}
		tab := strings.IndexByte(rec, '\t')
		if tab < 0 {
			return nil, fmt.Errorf("%w: ls-tree record", ErrInvalid)
		}
		meta := strings.Fields(rec[:tab])
		if len(meta) != 3 {
			return nil, fmt.Errorf("%w: ls-tree record", ErrInvalid)
		}
		out = append(out, TreeEntry{Mode: meta[0], Type: meta[1], SHA: meta[2], Path: rec[tab+1:]})
	}
	return out, nil
}
