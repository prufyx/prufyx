// SPDX-License-Identifier: AGPL-3.0-only

package targetdraft

import (
	"fmt"
	"path"
	"sort"
	"strings"
)

// Window grow-only (opt-in, --window-grow-only, only with collapseDirectories).
//
// Without the option the window is the longest run of newest tags that read
// the exact same install files. With it, an older tag may also stay in the
// window when it reads FEWER files than the next newer tag of the window, and
// only when every difference is a pure growth:
//   - every file the older tag installs is installed by the newer tag, with
//     the same CRD identities (group, kind, plural, scope, version list);
//   - the files only the newer tag installs are not links, lie in a
//     directory the older tag also installs files in, and carry only CRDs
//     the older tag does not define at all (no identity is moved, renamed or
//     removed);
//   - the older tag has no stop other than the install-path-matches-nothing
//     of an exact installPaths file that is one of those missing files.
//
// The check is made between every tag and its next newer neighbour, so the
// install set is monotone toward the newest tag. Anything else is the
// existing withhold, with its reason.

// crdFacts are the per-CRD facts compared across tags (the file name is not).
type crdFacts struct {
	Group, Kind, Plural, Scope, Versions string
}

func factsOf(c crd) crdFacts {
	return crdFacts{Group: c.Group, Kind: c.Kind, Plural: c.Plural, Scope: c.Scope, Versions: strings.Join(c.Versions, ",")}
}

// fileFacts is the sorted fact list of the CRDs of one included file.
func fileFacts(i *inclusion) []crdFacts {
	out := make([]crdFacts, 0, len(i.CRDs))
	for _, c := range i.CRDs {
		out = append(out, factsOf(c))
	}
	sort.Slice(out, func(a, b int) bool { return fmt.Sprint(out[a]) < fmt.Sprint(out[b]) })
	return out
}

func equalFacts(a, b []crdFacts) bool {
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

// growStep judges whether r (an older tag) may share the window with next,
// the next newer tag of the window. It returns "" when r reads the same files
// as next or a pure growth of them, with the files only next reads in added.
// A non-empty why is the reason the tag is withheld; stopped is true when the
// reason is the tag's own stops (reported by the existing reasonFor).
func growStep(r, next, newest *tagResult, rules *Rules) (why string, stopped bool, added []string) {
	// Stops: only the install-path-matches-nothing of an exact file entry
	// that next reads and r does not may be set aside; all others stay.
	for _, s := range r.stops {
		if s.Code != StopInstallPathNothing || !growableMissing(s.Subject, r, next, rules) {
			return "stop", true, nil
		}
	}
	for _, p := range sortedPaths(next.included) {
		ni := next.included[p]
		if _, ok := r.included[p]; ok {
			continue
		}
		if r.optAbsent[p] {
			continue
		}
		if ni.LinkKind {
			return "grow-only: " + p + " is read through a symbolic link at the newer tag", false, nil
		}
		added = append(added, p)
	}
	sort.Strings(added)
	for _, p := range sortedPaths(r.included) {
		if _, ok := next.included[p]; !ok {
			return "grow-only: " + p + " is read at the older tag and not at the next newer tag (set shrinks)", false, nil
		}
	}
	// Carried identities, against the whole path from the newest tag down to
	// r (not only the next tag): a CRD r defines ANYWHERE in its tree,
	// installed or not, must not be "new" in a file the newest tag reads and r
	// does not, or r would silently lose it. An unreadable definition file of
	// r outside the install set may hide such an identity: no growth then.
	have := map[string]bool{}
	for _, f := range r.defs {
		for _, c := range f.CRDs {
			for _, k := range identityKeys(c) {
				have[k] = true
			}
		}
	}
	unreadableOutside := ""
	for _, f := range r.defs {
		if _, in := r.included[f.Path]; !in && f.Unreadable != "" && (unreadableOutside == "" || f.Path < unreadableOutside) {
			unreadableOutside = f.Path
		}
	}
	var newestOnly []string
	for _, p := range sortedPaths(newest.included) {
		if _, ok := r.included[p]; !ok && !r.optAbsent[p] {
			newestOnly = append(newestOnly, p)
		}
	}
	sort.Strings(newestOnly)
	for _, p := range newestOnly {
		for _, c := range newest.included[p].CRDs {
			if k := firstCarried(have, c); k != "" {
				return "grow-only: " + p + " defines " + k + ", which the older tag already defines in another file (moved or not installed)", false, nil
			}
		}
	}
	if len(newestOnly) > 0 && unreadableOutside != "" {
		return "grow-only: " + unreadableOutside + " is an unreadable definition file outside the install set of the older tag; it may hide a CRD the newer tags install", false, nil
	}
	// Same file set: exactly the behaviour without the option (no facts are
	// compared; only a real growth is judged by identity facts).
	if len(added) == 0 {
		return "", false, nil
	}
	for _, p := range sortedPaths(r.included) {
		ri, ni := r.included[p], next.included[p]
		switch {
		case ri.LinkKind || ni.LinkKind:
			return "grow-only: " + p + " is read through a symbolic link", false, nil
		case !equalFacts(fileFacts(ri), fileFacts(ni)):
			return "grow-only: " + p + " defines other CRD identity facts (group, kind, plural, scope or versions) than at the next newer tag", false, nil
		}
	}
	// A real growth needs complete, comparable facts on every file the older
	// tag installs; anything incomplete is the withhold (fail closed).
	for _, p := range sortedPaths(r.included) {
		for _, c := range r.included[p].CRDs {
			if c.Group == "" || c.Kind == "" || c.Plural == "" || c.Scope == "" || len(c.Versions) == 0 {
				return "grow-only: " + p + " has CRD facts that cannot be compared (plural, scope or versions missing)", false, nil
			}
		}
	}
	// Directories of the newer tag; the older tag must read in each of them.
	rdirs := map[string]bool{}
	for p := range r.included {
		rdirs[path.Dir(p)] = true
	}
	for _, p := range sortedPaths(next.included) {
		if !rdirs[path.Dir(p)] {
			return "grow-only: directory " + path.Dir(p) + " has no install file at the older tag", false, nil
		}
	}
	return "", false, added
}

// growableMissing reports whether an install-path-matches-nothing stop on
// subject is the exact installPaths file entry of a file the older tag
// lacks and the newer tag reads.
func growableMissing(subject string, r, next *tagResult, rules *Rules) bool {
	if subject == "" || strings.HasSuffix(subject, "/") {
		return false
	}
	if _, in := r.included[subject]; in {
		return false
	}
	if i, ok := next.included[subject]; !ok || i.LinkKind {
		return false
	}
	for _, ip := range rules.InstallPaths {
		if ip.Path == subject {
			return !ip.Optional && ip.Role == "" && ip.FromTag == "" && ip.ToTag == "" && len(ip.AbsentTags) == 0
		}
	}
	return false
}

// growReason is the typed reason reported for a tag that stays in the window
// only because the install set grows toward the newest tag.
func growReason(added []string) string {
	return "install files added by a later release: " + strings.Join(added, ",")
}

// collapseDirsGrow is collapseDirsDropping for a window whose older tags may
// read a subset of the newest tag's files in each directory. Same checks, but
// the per-tag file set of a directory must be a non-empty subset of the
// newest tag's, and every tag must include exactly the files its own
// directories read. The emitted entry is the same directory entry.
func collapseDirsGrow(tags []collapseTag, dropped []string) ([]collapsedDir, []Stop) {
	return collapseDirsWith(tags, dropped, true)
}

func subsetStrings(a, b []string) bool {
	in := map[string]bool{}
	for _, x := range b {
		in[x] = true
	}
	for _, x := range a {
		if !in[x] {
			return false
		}
	}
	return true
}

// sortedPaths lists the keys of an inclusion map in order, so every judgement
// and every reason text is independent of map iteration order.
func sortedPaths(m map[string]*inclusion) []string {
	out := make([]string, 0, len(m))
	for p := range m {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

// identityKeys are the keys under which a CRD counts as carried: group/kind
// and the lower-cased group/plural (the API resource name).
func identityKeys(c crd) []string {
	k := []string{c.Group + "/" + c.Kind}
	if c.Plural != "" {
		k = append(k, "plural:"+strings.ToLower(c.Group)+"/"+strings.ToLower(c.Plural))
	}
	return k
}

func firstCarried(have map[string]bool, c crd) string {
	for _, k := range identityKeys(c) {
		if have[k] {
			return k
		}
	}
	return ""
}
