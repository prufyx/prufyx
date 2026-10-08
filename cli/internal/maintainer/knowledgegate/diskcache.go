// SPDX-License-Identifier: AGPL-3.0-only

package knowledgegate

import (
	"crypto/sha1" //nolint:gosec // git object ids are SHA-1 by definition
	"encoding/hex"
	"encoding/json"
	"fmt"
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

// treeObject rebuilds the raw git tree object of entries and returns its id.
func treeObjectID(entries []extract.TreeEntry) (string, bool) {
	var body []byte
	for _, e := range entries {
		raw, err := hex.DecodeString(e.SHA)
		if err != nil || len(raw) != sha1.Size || e.Path == "" || strings.ContainsAny(e.Path, "/\x00") {
			return "", false
		}
		mode := strings.TrimLeft(e.Mode, "0")
		if mode == "" {
			return "", false
		}
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
	writeAtomic(p, raw)
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
		writeAtomic(p, b)
	}
}

func readCapped(p string, limit int64) ([]byte, error) {
	fi, err := os.Lstat(p)
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() || fi.Size() > limit {
		return nil, fmt.Errorf("not a cache file")
	}
	return os.ReadFile(p)
}

// writeAtomic writes p through a temporary file in the same directory.
func writeAtomic(p string, data []byte) {
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
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
