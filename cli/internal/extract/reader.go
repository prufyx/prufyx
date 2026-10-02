// SPDX-License-Identifier: AGPL-3.0-only

package extract

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"path"
	"sort"
	"strings"
	"sync"

	"github.com/prufyx/prufyx/cli/internal/maintainer/factorymirror"
)

// TreeEntry is one entry of a git tree: Path is the full repository path,
// SHA the git object id, Type "blob", "tree" or "commit".
type TreeEntry struct {
	Mode string
	Type string
	SHA  string
	Path string
}

// PinnedReader is the only way an extractor reads upstream bytes. Commits
// are full 40-character SHAs; paths are repository-relative.
type PinnedReader interface {
	// Read returns the contents of a regular file at commit.
	Read(repo RepoRef, commit, path string) ([]byte, error)
	// List returns the entries directly inside dir at commit ("" is the
	// repository root).
	List(repo RepoRef, commit, dir string) ([]TreeEntry, error)
}

// TagSource yields the recorded tags of a repository.
type TagSource interface {
	Tags(repo RepoRef) ([]Tag, error)
}

// ErrNotFound reports a path that does not exist at the commit.
var ErrNotFound = errors.New("path does not exist at that commit")

var shaRE = func(s string) bool {
	if len(s) != 40 {
		return false
	}
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// IsCommitSHA reports whether s is a full lowercase 40-character SHA.
func IsCommitSHA(s string) bool { return shaRE(s) }

// MirrorReader reads through the factory mirror's offline Reader.
type MirrorReader struct {
	R *factorymirror.Reader
}

// Read implements PinnedReader.
func (m MirrorReader) Read(repo RepoRef, commit, p string) ([]byte, error) {
	data, err := m.R.Read(repo.Key, commit, p)
	if errors.Is(err, factorymirror.ErrPathNotFound) {
		return nil, fmt.Errorf("%w: %s", ErrNotFound, p)
	}
	return data, err
}

// List implements PinnedReader.
func (m MirrorReader) List(repo RepoRef, commit, dir string) ([]TreeEntry, error) {
	entries, err := m.R.List(repo.Key, commit, dir)
	if errors.Is(err, factorymirror.ErrPathNotFound) {
		return nil, fmt.Errorf("%w: %s", ErrNotFound, dir)
	}
	if err != nil {
		return nil, err
	}
	out := make([]TreeEntry, 0, len(entries))
	for _, e := range entries {
		out = append(out, TreeEntry{Mode: e.Mode, Type: e.Type, SHA: e.SHA, Path: e.Path})
	}
	return out, nil
}

// Tags implements TagSource. A frozen repository (one with an
// unacknowledged tag alarm) yields an error: its tags are not trusted.
func (m MirrorReader) Tags(repo RepoRef) ([]Tag, error) {
	tags, err := m.R.Tags(repo.Key)
	if err != nil {
		return nil, err
	}
	out := make([]Tag, 0, len(tags))
	for name, info := range tags {
		out = append(out, Tag{Name: name, Commit: info.Commit})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// ReadRecord is one logged read.
type ReadRecord struct {
	Repo   string
	Commit string
	Path   string
	SHA256 string // hex
	Size   int
	Lines  int
}

// Recorder wraps a PinnedReader and logs every read. It also lets an
// extractor reuse work across commits for content it already read: a git
// tree or blob id names its bytes, so a directory listing is served from an
// earlier listing of the same tree id, and Reuse logs a read of a file
// whose blob id was read before without reading it again. Either way the
// read is logged against the commit that asked for it.
type Recorder struct {
	inner PinnedReader

	mu      sync.Mutex
	reads   map[string]ReadRecord // repo NUL commit NUL path
	lists   map[string]int        // repo NUL commit -> listings served
	pathOID map[string]TreeEntry  // repo NUL commit NUL path -> entry seen in a listing
	blobs   map[string]ReadRecord // repo NUL blob id -> digest of its bytes
	trees   map[string][]TreeEntry
}

// NewRecorder wraps inner.
func NewRecorder(inner PinnedReader) *Recorder {
	return &Recorder{inner: inner, reads: map[string]ReadRecord{}, lists: map[string]int{}, pathOID: map[string]TreeEntry{}, blobs: map[string]ReadRecord{}, trees: map[string][]TreeEntry{}}
}

func key3(a, b, c string) string { return a + "\x00" + b + "\x00" + c }

// CountLines returns the number of lines in data (a final line without a
// newline counts).
func CountLines(data []byte) int {
	n := 0
	for _, b := range data {
		if b == '\n' {
			n++
		}
	}
	if len(data) > 0 && data[len(data)-1] != '\n' {
		n++
	}
	return n
}

// Read implements PinnedReader and logs the read.
func (r *Recorder) Read(repo RepoRef, commit, p string) ([]byte, error) {
	data, err := r.inner.Read(repo, commit, p)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(data)
	rec := ReadRecord{Repo: repo.Key, Commit: commit, Path: p, SHA256: hex.EncodeToString(sum[:]), Size: len(data), Lines: CountLines(data)}
	r.mu.Lock()
	defer r.mu.Unlock()
	if old, ok := r.reads[key3(repo.Key, commit, p)]; ok && old.SHA256 != rec.SHA256 {
		return nil, fmt.Errorf("pinned file %s@%s:%s changed between reads", repo.Key, commit, p)
	}
	r.reads[key3(repo.Key, commit, p)] = rec
	if e, ok := r.pathOID[key3(repo.Key, commit, p)]; ok && e.Type == "blob" {
		r.blobs[repo.Key+"\x00"+e.SHA] = rec
	}
	return data, nil
}

// List implements PinnedReader and logs the listing.
func (r *Recorder) List(repo RepoRef, commit, dir string) ([]TreeEntry, error) {
	r.mu.Lock()
	self, known := r.pathOID[key3(repo.Key, commit, dir)]
	if known && self.Type == "tree" {
		if cached, ok := r.trees[repo.Key+"\x00"+self.SHA]; ok {
			out := make([]TreeEntry, len(cached))
			for i, e := range cached {
				e.Path = path.Join(dir, e.Path)
				out[i] = e
				r.pathOID[key3(repo.Key, commit, e.Path)] = e
			}
			r.lists[repo.Key+"\x00"+commit]++
			r.mu.Unlock()
			return out, nil
		}
	}
	r.mu.Unlock()
	entries, err := r.inner.List(repo, commit, dir)
	if err != nil {
		return nil, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	rel := make([]TreeEntry, 0, len(entries))
	for _, e := range entries {
		if parent := path.Dir(e.Path); (dir == "" && parent != ".") || (dir != "" && parent != dir) {
			return nil, fmt.Errorf("listing of %q returned %q outside it", dir, e.Path)
		}
		r.pathOID[key3(repo.Key, commit, e.Path)] = e
		short := e
		short.Path = path.Base(e.Path)
		rel = append(rel, short)
	}
	if known && self.Type == "tree" {
		r.trees[repo.Key+"\x00"+self.SHA] = rel
	}
	r.lists[repo.Key+"\x00"+commit]++
	return entries, nil
}

// Reuse logs a read of path at commit without reading it, when the path was
// seen in a listing at that commit with blob id oid and a file with the same
// blob id was read before. It returns the digest record, or ok=false when
// the caller must Read.
func Reuse(r PinnedReader, repo RepoRef, commit, p, oid string) (ReadRecord, bool) {
	rec, ok := r.(*Recorder)
	if !ok {
		return ReadRecord{}, false
	}
	rec.mu.Lock()
	defer rec.mu.Unlock()
	e, seen := rec.pathOID[key3(repo.Key, commit, p)]
	if !seen || e.Type != "blob" || e.SHA != oid {
		return ReadRecord{}, false
	}
	blob, ok := rec.blobs[repo.Key+"\x00"+oid]
	if !ok {
		return ReadRecord{}, false
	}
	blob.Commit, blob.Path = commit, p
	rec.reads[key3(repo.Key, commit, p)] = blob
	return blob, true
}

// Lookup returns the logged read of path at commit.
func (r *Recorder) Lookup(repo RepoRef, commit, p string) (ReadRecord, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	rec, ok := r.reads[key3(repo.Key, commit, p)]
	return rec, ok
}

// CommitReads returns every read logged at one commit, sorted by path.
func (r *Recorder) CommitReads(repo RepoRef, commit string) []ReadRecord {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []ReadRecord
	prefix := repo.Key + "\x00" + commit + "\x00"
	for k, rec := range r.reads {
		if strings.HasPrefix(k, prefix) {
			out = append(out, rec)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out
}

// Commits returns every commit with at least one logged read or listing,
// sorted.
func (r *Recorder) Commits(repo RepoRef) []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	set := map[string]bool{}
	for k := range r.reads {
		parts := strings.SplitN(k, "\x00", 3)
		if parts[0] == repo.Key {
			set[parts[1]] = true
		}
	}
	for k := range r.lists {
		parts := strings.SplitN(k, "\x00", 2)
		if parts[0] == repo.Key {
			set[parts[1]] = true
		}
	}
	out := make([]string, 0, len(set))
	for c := range set {
		out = append(out, c)
	}
	sort.Strings(out)
	return out
}

// Listings returns how many directory listings were served at a commit.
func (r *Recorder) Listings(repo RepoRef, commit string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.lists[repo.Key+"\x00"+commit]
}
