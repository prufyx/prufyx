// SPDX-License-Identifier: AGPL-3.0-only

package extractcli

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path"
	"path/filepath"
	"sort"
	"sync"

	"github.com/prufyx/prufyx/cli/internal/extract"
	"github.com/prufyx/prufyx/cli/internal/maintainer/factorymirror"
)

type wantKey struct{ repo, commit, path string }

// wantsReader records the files an extractor reads that the mirror does not
// hold locally. It answers such a read with empty bytes so the run goes on
// and finds the other files it needs; a run that recorded anything derives
// nothing that is kept, so the stand-in bytes never reach an output.
type wantsReader struct {
	inner   extract.PinnedReader
	mu      sync.Mutex
	missing map[wantKey]bool
	// absent are commits (repo@commit) the mirror does not hold at all.
	absent map[string]bool
	// listed are the blobs the extractor saw in directory listings, by
	// repo@commit. A listing is answered offline (trees are always local),
	// so it is complete from the first round.
	listed map[string][]string
}

func (w *wantsReader) Read(repo extract.RepoRef, commit, path string) ([]byte, error) {
	data, err := w.inner.Read(repo, commit, path)
	if errors.Is(err, factorymirror.ErrBlobNotLocal) {
		w.mu.Lock()
		w.missing[wantKey{repo.Key, commit, path}] = true
		w.mu.Unlock()
		return []byte{}, nil
	}
	w.noteAbsent(repo, commit, err)
	return data, err
}

func (w *wantsReader) List(repo extract.RepoRef, commit, dir string) ([]extract.TreeEntry, error) {
	entries, err := w.inner.List(repo, commit, dir)
	w.noteAbsent(repo, commit, err)
	if err == nil {
		w.mu.Lock()
		k := repo.Key + "@" + commit
		for _, e := range entries {
			if e.Type == "blob" {
				w.listed[k] = append(w.listed[k], e.Path)
			}
		}
		w.mu.Unlock()
	}
	return entries, err
}

func (w *wantsReader) noteAbsent(repo extract.RepoRef, commit string, err error) {
	if errors.Is(err, factorymirror.ErrCommitUnknown) || errors.Is(err, factorymirror.ErrRepoNotMirrored) {
		w.mu.Lock()
		w.absent[repo.Key+"@"+commit] = true
		w.mu.Unlock()
	}
}

func (w *wantsReader) absentList() []string {
	out := make([]string, 0, len(w.absent))
	for k := range w.absent {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// write renders the wants as the document "factory mirror --wants" reads,
// grouped by repository and commit, sorted, and writes it atomically. It
// returns the number of files.
func (w *wantsReader) write(file string) (int, error) {
	type group struct{ repo, commit string }
	byGroup := map[group][]string{}
	for _, k := range w.expanded() {
		g := group{k.repo, k.commit}
		byGroup[g] = append(byGroup[g], k.path)
	}
	groups := make([]group, 0, len(byGroup))
	for g := range byGroup {
		groups = append(groups, g)
	}
	sort.Slice(groups, func(i, j int) bool {
		if groups[i].repo != groups[j].repo {
			return groups[i].repo < groups[j].repo
		}
		return groups[i].commit < groups[j].commit
	})
	wants := make([]factorymirror.Want, 0, len(groups))
	n := 0
	for _, g := range groups {
		paths := byGroup[g]
		sort.Strings(paths)
		n += len(paths)
		wants = append(wants, factorymirror.Want{Repo: g.repo, Commit: g.commit, Paths: paths})
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(map[string]any{"wants": wants}); err != nil {
		return 0, err
	}
	tmp, err := os.CreateTemp(filepath.Dir(file), ".wants-*")
	if err != nil {
		return 0, err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(buf.Bytes()); err != nil {
		tmp.Close()
		return 0, err
	}
	if err := tmp.Chmod(0o644); err != nil {
		tmp.Close()
		return 0, err
	}
	if err := tmp.Close(); err != nil {
		return 0, err
	}
	return n, os.Rename(tmp.Name(), file)
}

// expanded returns the missing files plus, for each, the blobs of the same
// name that the extractor saw listed at the same commit. An extractor that
// walks a tree reads one file after another and (given empty stand-in bytes)
// stops at the first it cannot understand, so on its own each round would
// reveal one file per commit: k8s.served-api-removal over upstream
// kubernetes needs two files per API version directory and would take
// about 120 rounds. The listing is complete from the first round, so asking
// for every same-named file costs a few extra small blobs and cuts the
// rounds to the number of distinct file kinds. The files are only fetched,
// never read on the extractor's behalf, so the derivation is unchanged.
func (w *wantsReader) expanded() []wantKey {
	seen := map[wantKey]bool{}
	var out []wantKey
	add := func(k wantKey) {
		if !seen[k] {
			seen[k] = true
			out = append(out, k)
		}
	}
	for k := range w.missing {
		add(k)
		for _, p := range w.listed[k.repo+"@"+k.commit] {
			if path.Base(p) == path.Base(k.path) {
				add(wantKey{k.repo, k.commit, p})
			}
		}
	}
	return out
}
