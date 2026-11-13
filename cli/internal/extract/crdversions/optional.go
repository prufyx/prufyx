// SPDX-License-Identifier: AGPL-3.0-only

package crdversions

import (
	"path"
	"strings"

	"github.com/prufyx/prufyx/cli/internal/extract"
)

// An optional path is absent only when a complete pinned parent listing
// omits it or one of its ancestors. A failed read is never absence proof.
func optionalPathMissing(r extract.PinnedReader, repo extract.RepoRef, commit string, spec PathSpec) (bool, error) {
	if spec.Path == "" || spec.Path == "." || spec.Path == ".." || path.Clean(spec.Path) != spec.Path || strings.HasPrefix(spec.Path, "../") || strings.HasPrefix(spec.Path, "/") || strings.Contains(spec.Path, "\x00") {
		return false, problemf("optional path %q is not canonical", spec.Path)
	}
	dir := ""
	parts := strings.Split(spec.Path, "/")
	for i, name := range parts {
		entries, err := r.List(repo, commit, dir)
		if err != nil {
			return false, problemf("cannot prove optional path %s absent: listing %q failed: %v", spec.Path, dir, err)
		}
		want := path.Join(dir, name)
		seen := map[string]bool{}
		var found *extract.TreeEntry
		for j := range entries {
			e := &entries[j]
			parent := path.Dir(e.Path)
			if parent == "." {
				parent = ""
			}
			validMode := e.Type == "tree" && e.Mode == "040000" ||
				e.Type == "blob" && (e.Mode == "100644" || e.Mode == "100755" || e.Mode == "120000") ||
				e.Type == "commit" && e.Mode == "160000"
			if e.Path == "" || e.Path == "." || e.Path == ".." || path.Clean(e.Path) != e.Path || parent != dir || strings.Contains(e.Path, "\x00") || seen[e.Path] || !extract.IsCommitSHA(e.SHA) || !validMode {
				return false, problemf("cannot prove optional path %s absent: malformed or repeated entry %q in %q", spec.Path, e.Path, dir)
			}
			seen[e.Path] = true
			if e.Path == want {
				found = e
			}
		}
		if found == nil {
			return true, nil
		}
		if i == len(parts)-1 {
			if spec.Dir && found.Type == "tree" || !spec.Dir && found.Type == "blob" && (found.Mode == "100644" || found.Mode == "100755") {
				return false, nil
			}
			return false, problemf("optional path %s exists with an unsupported type or mode", spec.Path)
		}
		if found.Type != "tree" || found.Mode != "040000" {
			return false, problemf("optional path %s has an opaque ancestor %s", spec.Path, found.Path)
		}
		dir = want
	}
	return false, problemf("cannot prove optional path %s absent", spec.Path)
}
