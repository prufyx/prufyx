// SPDX-License-Identifier: AGPL-3.0-only

package targetdraft

import (
	"path"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// Literal same-tag tree references.
//
// A reference is a statement INSIDE one tree that names another path of the
// SAME tree literally: a kustomization's resources and bases entries, and the
// crds directory a chart declares by its Chart.yaml. The reader is a pure
// function of a file list and a bounded read function. It evaluates no
// template, follows no link, resolves no remote reference and never leaves
// the tree: an entry with a scheme, a variable, a template, a glob, a drive or
// home prefix, an absolute path, or a normalised path that escapes the tree
// root is dropped (never guessed). A reference from a documentation, test,
// example, vendor, template, bundle or similar directory is dropped too.
//
// It is designed to be shared: the target generator uses it as the second
// evidence of an install directory; any other reader of install surface
// facts must call this function instead of parsing the files a second time.

// Reference kinds.
const (
	// RefKustomizeResource is an entry of a kustomization's resources list.
	RefKustomizeResource = "kustomize-resources"
	// RefKustomizeBase is an entry of a kustomization's bases list.
	RefKustomizeBase = "kustomize-bases"
	// RefChartCRDs is the crds directory next to a Chart.yaml: the chart
	// format itself installs every file of that directory.
	RefChartCRDs = "chart-crds-dir"
)

// TreeRef is one literal reference. To is a normalised tree path; a directory
// ends in "/".
type TreeRef struct {
	From string `json:"from"`
	To   string `json:"to"`
	Kind string `json:"kind"`
}

// maxRefsPerFile bounds the entries read from one file.
const maxRefsPerFile = 4096

// refTarget normalises one literal entry relative to the directory of its
// file. ok is false for anything that is not a plain in-tree relative path.
func refTarget(dir, entry string) (string, bool) {
	if entry == "" || !cleanText(entry) {
		return "", false
	}
	if strings.ContainsAny(entry, ":$%{}\\*?[]~|<>\"'`!;& ") || strings.HasPrefix(entry, "/") {
		return "", false
	}
	q := path.Join(dir, entry)
	if q == "." || q == "" || q == ".." || strings.HasPrefix(q, "../") || strings.HasPrefix(q, "/") {
		return "", false
	}
	return q, true
}

// kustomizeEntries decodes the resources and bases lists of a kustomization.
// Any entry that is not a string makes the whole file unreadable here (the
// file then contributes no reference).
func kustomizeEntries(data []byte) (resources, bases []string, ok bool) {
	var doc map[string]any
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, nil, false
	}
	list := func(key string) ([]string, bool) {
		v, present := doc[key]
		if !present || v == nil {
			return nil, true
		}
		items, isList := v.([]any)
		if !isList || len(items) > maxRefsPerFile {
			return nil, false
		}
		out := make([]string, 0, len(items))
		for _, it := range items {
			s, isStr := it.(string)
			if !isStr {
				return nil, false
			}
			out = append(out, s)
		}
		return out, true
	}
	var ok1, ok2 bool
	resources, ok1 = list("resources")
	bases, ok2 = list("bases")
	return resources, bases, ok1 && ok2
}

// ReadTreeRefs returns the literal references of a tree, sorted and without
// duplicates. entries is the tree listing; read returns the bytes of one
// regular file (an error means the file contributes nothing).
func ReadTreeRefs(entries []Entry, read func(p string) ([]byte, error)) []TreeRef {
	files := map[string]bool{}
	links := map[string]bool{}
	dirs := map[string]bool{}
	for _, e := range entries {
		if e.IsLink {
			links[e.Path] = true
		} else {
			files[e.Path] = true
		}
		for d := path.Dir(e.Path); d != "." && d != "/" && d != ""; d = path.Dir(d) {
			dirs[d] = true
		}
	}
	seen := map[TreeRef]bool{}
	var out []TreeRef
	add := func(r TreeRef) {
		if !seen[r] {
			seen[r] = true
			out = append(out, r)
		}
	}
	for _, e := range entries {
		if e.IsLink || inferSkippedPath(e.Path) {
			continue
		}
		base := path.Base(e.Path)
		switch {
		case isKustomizationName(base):
			data, err := read(e.Path)
			if err != nil {
				continue
			}
			res, bas, ok := kustomizeEntries(data)
			if !ok {
				continue
			}
			dir := path.Dir(e.Path)
			for _, set := range []struct {
				kind    string
				entries []string
			}{{RefKustomizeResource, res}, {RefKustomizeBase, bas}} {
				for _, s := range set.entries {
					q, ok := refTarget(dir, s)
					if !ok || links[q] {
						continue
					}
					switch {
					case files[q]:
						add(TreeRef{From: e.Path, To: q, Kind: set.kind})
					case dirs[q]:
						add(TreeRef{From: e.Path, To: q + "/", Kind: set.kind})
					}
				}
			}
		case base == "Chart.yaml":
			crds := path.Join(path.Dir(e.Path), "crds")
			if dirs[crds] && !links[crds] {
				add(TreeRef{From: e.Path, To: crds + "/", Kind: RefChartCRDs})
			}
		}
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.From != b.From {
			return a.From < b.From
		}
		if a.To != b.To {
			return a.To < b.To
		}
		return a.Kind < b.Kind
	})
	return out
}

// CoveredFiles lists the regular files the references install, as a set. A
// file reference covers that file. A chart crds directory covers every file
// directly in it. A kustomize reference to a directory covers nothing by
// itself: the files that directory's own kustomization names are covered by
// that kustomization's references. A file reached through a link is never
// covered. A directory counts only through its files: a definition file in a
// directory is covered only when it is covered itself.
func CoveredFiles(entries []Entry, refs []TreeRef) map[string]bool {
	cov := map[string]bool{}
	byDir := map[string][]string{}
	isFile := map[string]bool{}
	for _, e := range entries {
		if e.IsLink {
			continue
		}
		isFile[e.Path] = true
		d := path.Dir(e.Path) + "/"
		byDir[d] = append(byDir[d], e.Path)
	}
	for _, r := range refs {
		switch {
		case !strings.HasSuffix(r.To, "/"):
			if isFile[r.To] {
				cov[r.To] = true
			}
		case r.Kind == RefChartCRDs:
			for _, f := range byDir[r.To] {
				cov[f] = true
			}
		}
	}
	return cov
}
