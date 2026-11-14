// SPDX-License-Identifier: AGPL-3.0-only

package targetdraft

import (
	"fmt"
	"path"
	"regexp"
	"sort"
	"strings"
)

// The one match and guard pair the generator ever emits for a directory entry.
// They are literals, copied by hand to equal the loader's accepted form: no
// pattern is ever derived from repository content. A directory that needs any
// other pattern is a typed stop, never a widened or invented regular
// expression.
const (
	// DefaultDirMatch selects the files of a directory entry: a visible
	// .yaml or .yml file name.
	DefaultDirMatch = `^[^.][^/]*\.ya?ml$`
	// DefaultDirGuard names the files that look like a CRD manifest; a file
	// the guard matches but the match does not makes the loader's inventory
	// incomplete.
	DefaultDirGuard = `(?i)crd`
)

var (
	dirMatchRE = regexp.MustCompile(DefaultDirMatch)
	dirGuardRE = regexp.MustCompile(DefaultDirGuard)
)

// collapseTag is what the collapse decision reads of one window tag: every
// file and link of the tree, every definition-bearing file the scan found, and
// the install files the classification included.
type collapseTag struct {
	Tag      string
	Entries  []Entry
	Defs     []defFile
	Included []includedFile
}

// defFile is a definition-bearing file of a tree.
type defFile struct {
	Path       string
	Unreadable bool
}

// includedFile is an install file of a tag.
type includedFile struct {
	Path string
	Link bool // included through a symbolic link into a test-like directory
}

// collapsedDir is one directory entry the target will carry, with the file
// names it reads (identical at every window tag).
type collapsedDir struct {
	Dir   string
	Files []string
}

// collapseDirs decides whether the install files can be written as directory
// entries. It is a pure function of the window's trees: no IO, no map-order
// dependence.
//
// A directory D qualifies only when, at EVERY window tag, all of these hold:
//   - every file directly in D that the default match selects is an included,
//     readable, regular definition file (nothing else would be read);
//   - no definition file directly in D lies outside the default match
//     (it would need another pattern);
//   - no file directly in D matches the guard without the match, and no
//     matching name is a symbolic link (the loader reports an incomplete
//     inventory);
//   - no definition file lies in a subdirectory of D (no recursion);
//   - the matched set equals the set of included files below D, and equals the
//     set at the newest tag.
//
// Every install file must belong to such a directory; a file that cannot be
// (repository root, link, test-like path) is a stop too. The result is a
// representation of the exact-file set, never a different surface: the
// matched set of each directory is proved equal to the included files at
// every tag. On any stop the directory list is nil.
func collapseDirs(tags []collapseTag) ([]collapsedDir, []Stop) {
	if len(tags) == 0 {
		return nil, []Stop{stop(StopDirUnsupported, "", "no window tags")}
	}
	newest := tags[len(tags)-1]
	var stops []Stop
	dirSet := map[string]bool{}
	for _, f := range newest.Included {
		d := path.Dir(f.Path)
		switch {
		case f.Link:
			stops = append(stops, stop(StopDirUnsupported, f.Path, "installed through a symbolic link; it stays an exact file"))
		case d == "." || !cleanRepoDir(d):
			stops = append(stops, stop(StopDirUnsupported, f.Path, "not inside a directory that can be a directory entry"))
		case testLike(f.Path) || defaultExcludedPath(f.Path):
			stops = append(stops, stop(StopDirUnsupported, f.Path, "inside a test-like or default-excluded directory"))
		default:
			dirSet[d] = true
		}
	}
	if len(stops) > 0 {
		return nil, sortStops(stops)
	}
	dirs := make([]string, 0, len(dirSet))
	for d := range dirSet {
		dirs = append(dirs, d)
	}
	sort.Strings(dirs)

	var out []collapsedDir
	for _, d := range dirs {
		perTag := make([][]string, len(tags))
		bad := false
		for k, t := range tags {
			files, ds := dirFilesAt(t, d)
			perTag[k] = files
			if len(ds) > 0 {
				stops = append(stops, ds...)
				bad = true
			}
		}
		if bad {
			continue
		}
		ref := perTag[len(tags)-1]
		for k, t := range tags {
			if !equalStrings(perTag[k], ref) {
				stops = append(stops, stop(StopDirSetDiffers, d, fmt.Sprintf("%s reads [%s], %s reads [%s]", t.Tag, strings.Join(perTag[k], ","), newest.Tag, strings.Join(ref, ","))))
			}
		}
		out = append(out, collapsedDir{Dir: d, Files: ref})
	}
	// Every tag must include exactly the files of the directories, nothing
	// elsewhere.
	for _, t := range tags {
		want := map[string]bool{}
		for _, d := range out {
			for _, n := range d.Files {
				want[path.Join(d.Dir, n)] = true
			}
		}
		got := map[string]bool{}
		for _, f := range t.Included {
			got[f.Path] = true
		}
		var extra, missing []string
		for p := range got {
			if !want[p] {
				extra = append(extra, p)
			}
		}
		for p := range want {
			if !got[p] {
				missing = append(missing, p)
			}
		}
		sort.Strings(extra)
		sort.Strings(missing)
		if len(extra)+len(missing) > 0 {
			stops = append(stops, stop(StopDirSetDiffers, t.Tag, fmt.Sprintf("the directories would read %v and miss %v of the install files", missing, extra)))
		}
	}
	if len(stops) > 0 {
		return nil, sortStops(dedupStops(stops))
	}
	return out, nil
}

// dirFilesAt evaluates directory d at one tag: the sorted names the default
// match would read, or the stops that forbid a directory entry.
func dirFilesAt(t collapseTag, d string) ([]string, []Stop) {
	var stops []Stop
	included := map[string]bool{}
	for _, f := range t.Included {
		if !f.Link {
			included[f.Path] = true
		}
	}
	defs := map[string]defFile{}
	for _, f := range t.Defs {
		defs[f.Path] = f
	}
	prefix := d + "/"
	var files []string
	for _, e := range t.Entries {
		if !strings.HasPrefix(e.Path, prefix) {
			continue
		}
		if path.Dir(e.Path) != d {
			continue // below a subdirectory: judged through the definitions
		}
		name := path.Base(e.Path)
		matched, guarded := dirMatchRE.MatchString(name), dirGuardRE.MatchString(name)
		switch {
		case e.IsLink && (matched || guarded):
			stops = append(stops, stop(StopDirIncomplete, e.Path, t.Tag+": a symbolic link the directory read would refuse"))
		case matched:
			df, isDef := defs[e.Path]
			switch {
			case !isDef:
				stops = append(stops, stop(StopDirMixed, e.Path, t.Tag+": matched by the default match but defines no CRD"))
			case df.Unreadable || !included[e.Path]:
				stops = append(stops, stop(StopDirMixed, e.Path, t.Tag+": a definition file the target does not install (excluded, filtered or unreadable)"))
			default:
				files = append(files, name)
			}
		case guarded:
			stops = append(stops, stop(StopDirIncomplete, e.Path, t.Tag+": matches the guard but not the match; the loader's inventory would be incomplete"))
		}
	}
	for _, f := range t.Defs {
		if !strings.HasPrefix(f.Path, prefix) {
			continue
		}
		if path.Dir(f.Path) != d {
			stops = append(stops, stop(StopDirSubdir, f.Path, t.Tag+": a definition file in a subdirectory of "+d+"; recursion is not emitted"))
			continue
		}
		if !dirMatchRE.MatchString(path.Base(f.Path)) {
			stops = append(stops, stop(StopDirMatchNondefault, f.Path, t.Tag+": a definition file the default match does not select; another pattern would be needed"))
		}
	}
	sort.Strings(files)
	if len(files) == 0 && len(stops) == 0 {
		stops = append(stops, stop(StopDirMixed, d, t.Tag+": the directory holds no file the default match reads"))
	}
	return files, stops
}

func cleanRepoDir(d string) bool {
	return d != "" && !strings.HasPrefix(d, "/") && path.Clean(d) == d && d != "." && d != ".." && !strings.HasPrefix(d, "../") && !strings.ContainsAny(d, "\x00\n\\")
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func dedupStops(in []Stop) []Stop {
	seen := map[Stop]bool{}
	var out []Stop
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}
