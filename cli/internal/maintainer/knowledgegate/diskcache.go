// SPDX-License-Identifier: AGPL-3.0-only

package knowledgegate

import (
	"crypto/sha1" //nolint:gosec // git object ids are SHA-1 by definition
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/prufyx/prufyx/cli/internal/extract"
)

// The on-disk cache holds git trees and small blobs under their object ids.
// Git object ids are content hashes, so an entry is trusted only after it
// hashes to its own name: a tampered, truncated or foreign file is a miss,
// never a wrong answer. (Commits are not cached: the commit-to-tree link is
// not recoverable from the API response alone, so it cannot be verified.)
// Every failure to read or write the cache is silent; the cache only ever
// saves requests.

const maxDiskTreeBytes = 8 << 20

func (g *GitHubSource) diskPath(kind, id string) string {
	if g.CacheDir == "" || !extract.IsCommitSHA(id) {
		return ""
	}
	return filepath.Join(g.CacheDir, kind, id[:2], id)
}

// canonicalModes are the mode strings the git trees API reports, with the
// entry type each one implies. "40000" is the form inside a raw tree object;
// the API pads it to six digits. Anything else (a leading zero on a file mode,
// an unknown mode) is not canonical and is refused.
var canonicalModes = map[string]string{
	"40000": "tree", "040000": "tree",
	"100644": "blob", "100755": "blob", "120000": "blob",
	"160000": "commit",
}

// treeObjectID rebuilds the raw git tree object of entries and returns its id.
func treeObjectID(entries []extract.TreeEntry) (string, bool) {
	var body []byte
	for _, e := range entries {
		raw, err := hex.DecodeString(e.SHA)
		if err != nil || len(raw) != sha1.Size || e.Path == "" || strings.ContainsAny(e.Path, "/\x00") {
			return "", false
		}
		// The stored Mode and Type are covered too: only a canonical mode
		// string is accepted and the type must be the one the mode implies,
		// so neither can be altered while the entry still hashes to its id.
		typ, ok := canonicalModes[e.Mode]
		if !ok || e.Type != typ {
			return "", false
		}
		mode := strings.TrimLeft(e.Mode, "0")
		body = append(body, mode...)
		body = append(body, ' ')
		body = append(body, e.Path...)
		body = append(body, 0)
		body = append(body, raw...)
	}
	h := sha1.New() //nolint:gosec // git object ids are SHA-1 by definition
	fmt.Fprintf(h, "tree %d\x00", len(body))
	h.Write(body)
	return hex.EncodeToString(h.Sum(nil)), true
}

func (g *GitHubSource) diskLoadTree(id string) ([]extract.TreeEntry, bool) {
	p := g.diskPath("tree", id)
	if p == "" {
		return nil, false
	}
	raw, err := readCapped(p, maxDiskTreeBytes)
	if err != nil {
		return nil, false
	}
	var entries []extract.TreeEntry
	if json.Unmarshal(raw, &entries) != nil {
		return nil, false
	}
	if got, ok := treeObjectID(entries); !ok || got != id {
		return nil, false
	}
	return entries, true
}

func (g *GitHubSource) diskStoreTree(id string, entries []extract.TreeEntry) {
	p := g.diskPath("tree", id)
	if p == "" {
		return
	}
	if got, ok := treeObjectID(entries); !ok || got != id {
		return // never write what would not verify
	}
	raw, err := json.Marshal(entries)
	if err != nil {
		return
	}
	writeAtomic(g.CacheDir, p, raw)
}

func (g *GitHubSource) diskLoadBlob(id string) ([]byte, bool) {
	p := g.diskPath("blob", id)
	if p == "" {
		return nil, false
	}
	b, err := readCapped(p, maxCachedBlobBytes)
	if err != nil || gitBlobID(b) != id {
		return nil, false
	}
	return b, true
}

func (g *GitHubSource) diskStoreBlob(id string, b []byte) {
	if p := g.diskPath("blob", id); p != "" && len(b) <= maxCachedBlobBytes {
		writeAtomic(g.CacheDir, p, b)
	}
}

// readCapped opens p without following a symlink, then checks the open file
// (not the path, which could be swapped in between): it must be a regular
// file within the limit. The content is verified by the caller anyway.
func readCapped(p string, limit int64) ([]byte, error) {
	f, err := openNoFollow(p)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() || fi.Size() > limit {
		return nil, fmt.Errorf("not a cache file")
	}
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil || int64(len(b)) > limit {
		return nil, fmt.Errorf("not a cache file")
	}
	return b, nil
}

// ensureDir creates dir (inside root) one component at a time and refuses to
// go through a symlink or a non-directory below root. root itself is the
// caller's own choice and may be a link.
func ensureDir(root, dir string) error {
	rel, err := filepath.Rel(root, dir)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return fmt.Errorf("outside the cache")
	}
	if err := os.MkdirAll(root, 0o755); err != nil {
		return err
	}
	cur := root
	for _, part := range strings.Split(rel, string(filepath.Separator)) {
		if part == "." || part == "" {
			continue
		}
		cur = filepath.Join(cur, part)
		fi, err := os.Lstat(cur)
		if os.IsNotExist(err) {
			if err = os.Mkdir(cur, 0o755); err != nil {
				return err
			}
			continue
		}
		if err != nil {
			return err
		}
		if !fi.IsDir() {
			return fmt.Errorf("%s is not a plain directory", cur)
		}
	}
	return nil
}

// writeAtomic writes p (inside root) through a temporary file in the same
// directory. It never writes through a symlinked directory.
func writeAtomic(root, p string, data []byte) {
	if ensureDir(root, filepath.Dir(p)) != nil {
		return
	}
	f, err := os.CreateTemp(filepath.Dir(p), ".tmp-*")
	if err != nil {
		return
	}
	_, werr := f.Write(data)
	cerr := f.Close()
	if werr != nil || cerr != nil || os.Rename(f.Name(), p) != nil {
		_ = os.Remove(f.Name())
	}
}
