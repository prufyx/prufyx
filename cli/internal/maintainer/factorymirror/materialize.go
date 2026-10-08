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

const (
	blobBatch = 500
	pathBatch = 256
)

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
//
// Blobs are fetched in batches: every blob the wants of one repository still
// lack is requested with a single "git fetch --stdin" per batch (see
// fetchBlobs), not one object at a time.
func (r *run) materialize(ctx context.Context, wants []Want) []WantResult {
	out := make([]WantResult, len(wants))
	pending := make([]*pendingWant, len(wants))
	for i, w := range wants {
		out[i], pending[i] = r.prepareWant(ctx, w)
	}
	// One fetch per repository for the union of what its wants lack.
	union := map[string][]string{}
	inUnion := map[string]bool{}
	var order []string
	for _, p := range pending {
		if p == nil {
			continue
		}
		if _, ok := union[p.dest]; !ok {
			order = append(order, p.dest)
			union[p.dest] = nil
		}
		for _, oid := range p.missing {
			if k := p.dest + "\x00" + oid; !inUnion[k] {
				inUnion[k] = true
				union[p.dest] = append(union[p.dest], oid)
			}
		}
	}
	for _, dest := range order {
		r.fetchBlobs(ctx, dest, union[dest])
	}
	counted := map[string]bool{}
	for i, p := range pending {
		if p == nil {
			continue
		}
		still, err := r.absent(ctx, p.dest, p.missing)
		if err != nil {
			out[i].Error = "blob check failed"
			continue
		}
		lacking := map[string]bool{}
		for _, oid := range still {
			lacking[oid] = true
		}
		for _, oid := range p.missing {
			if k := p.dest + "\x00" + oid; !lacking[oid] && !counted[k] {
				counted[k] = true
				out[i].Fetched++
			}
		}
		out[i].Complete = len(out[i].Missing) == 0 && len(still) == 0
	}
	return out
}

// pendingWant is a want whose blobs are still to be fetched.
type pendingWant struct {
	dest    string
	missing []string
}

// prepareWant resolves a want against the local object store. It returns a
// non-nil pendingWant only when the want is otherwise valid and some of its
// blobs are not present.
func (r *run) prepareWant(ctx context.Context, w Want) (WantResult, *pendingWant) {
	res := WantResult{Repo: w.Repo, Commit: w.Commit}
	fail := func(format string, a ...any) (WantResult, *pendingWant) {
		res.Error = fmt.Sprintf(format, a...)
		return res, nil
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
	clean := make([]string, 0, len(w.Paths))
	for _, p := range w.Paths {
		c, err := cleanRepoPath(p)
		if err != nil {
			return fail("invalid path")
		}
		clean = append(clean, c)
	}
	// One ls-tree per chunk of paths instead of one per path.
	blobOf := map[string]string{}
	for start := 0; start < len(clean); start += pathBatch {
		chunk := clean[start:min(start+pathBatch, len(clean))]
		entries, err := lsTreePaths(ctx, r.offline(), dest, w.Commit, chunk)
		if err != nil {
			return fail("ls-tree failed")
		}
		for _, e := range entries {
			if e.Type == "blob" {
				blobOf[e.Path] = e.SHA
			}
		}
	}
	var oids []string
	seen := map[string]bool{}
	for _, c := range clean {
		oid, ok := blobOf[c]
		if !ok {
			res.Missing = append(res.Missing, c)
			continue
		}
		if !seen[oid] {
			seen[oid] = true
			oids = append(oids, oid)
		}
	}
	missingOIDs, err := r.absent(ctx, dest, oids)
	if err != nil {
		return fail("blob check failed")
	}
	res.Complete = len(res.Missing) == 0 && len(missingOIDs) == 0
	if len(missingOIDs) == 0 {
		return res, nil
	}
	return res, &pendingWant{dest: dest, missing: missingOIDs}
}

// fetchBlobs makes the blobs with the given ids present in dest. They are
// requested explicitly (not lazily, one object per round trip as a blob read
// would) with "git fetch --stdin": one request per batch. The ids come from
// the pinned commit's tree and git stores a received object under the hash of
// its bytes, so an object that arrives under a wanted id has exactly the
// bytes the tree records. When the batched fetch fails (a server that will
// not serve a blob by id), the blobs are read through the lazy path instead.
// The caller re-checks what is present; this reports nothing.
func (r *run) fetchBlobs(ctx context.Context, dest string, oids []string) {
	for start := 0; start < len(oids); start += blobBatch {
		batch := oids[start:min(start+blobBatch, len(oids))]
		input := []byte(strings.Join(batch, "\n") + "\n")
		c, cancel := context.WithTimeout(ctx, r.opts.GitTimeout)
		_, err := r.opts.Git.RunStdin(c, dest, input, "-c", "fetch.negotiationAlgorithm=noop", "fetch", "-q", "--no-tags", "--no-write-fetch-head", "--no-auto-gc", "--recurse-submodules=no", "--filter=blob:none", "origin", "--stdin")
		cancel()
		if err == nil {
			continue
		}
		c, cancel = context.WithTimeout(ctx, r.opts.GitTimeout)
		_, _ = r.opts.Git.RunStdin(c, dest, input, "cat-file", "--batch-check")
		cancel()
	}
}

// absent returns, in order, the ids that are not present in dest. It never
// touches the network.
func (r *run) absent(ctx context.Context, dest string, oids []string) ([]string, error) {
	if len(oids) == 0 {
		return nil, nil
	}
	out, err := r.offline().RunStdin(ctx, dest, []byte(strings.Join(oids, "\n")+"\n"), "cat-file", "--batch-check")
	if err != nil {
		return nil, err
	}
	lines := strings.Split(strings.TrimRight(string(out), "\n"), "\n")
	if len(lines) != len(oids) {
		return nil, fmt.Errorf("%w: cat-file answer", ErrInvalid)
	}
	var missing []string
	for i, l := range lines {
		if strings.HasSuffix(l, " missing") {
			missing = append(missing, oids[i])
		} else if !strings.HasPrefix(l, oids[i]+" blob ") {
			return nil, fmt.Errorf("%w: cat-file answer", ErrInvalid)
		}
	}
	return missing, nil
}

// offline returns a runner that cannot touch the network or lazily fetch.
func (r *run) offline() GitRunner {
	if r.opts.OfflineGit != nil {
		return r.opts.OfflineGit
	}
	return ExecGit{Offline: true, StateDir: r.opts.StateDir}
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
	return parseLsTree(raw)
}

func parseLsTree(raw []byte) ([]TreeEntry, error) {
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

// lsTreePaths lists the entries at the given paths (files or directories)
// of a commit with one git process. A path that does not exist yields no
// entry.
func lsTreePaths(ctx context.Context, g GitRunner, dir, commit string, paths []string) ([]TreeEntry, error) {
	args := append([]string{"ls-tree", "-z", commit, "--"}, paths...)
	raw, err := g.Run(ctx, dir, args...)
	if err != nil {
		return nil, err
	}
	return parseLsTree(raw)
}
