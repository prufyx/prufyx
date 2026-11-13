// SPDX-License-Identifier: AGPL-3.0-only

package targetdraft

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// Optional installPaths entries.
//
// An installPaths entry may carry optional:true. Such an entry names one
// exact file that a project added at some release line, so older tags of the
// window do not carry it. At a tag the rules list in absentTags the entry is
// tolerated only on verified true tree absence: the path is absent from the
// full Git tree of the tag, read from local Git with lazy fetching disabled.
// Everything else that is not a plain regular file is a typed stop; the
// newest tag must read the file. Without an optional entry none of this code
// runs and the generator behaves as before.

// Stop codes of optional entries.
const (
	// StopOptionalUnverifiable: absence or presence could not be proven
	// (read error, tree reader without a prober, opaque tree entry, a
	// directory at the path, a regular file as a parent directory, a
	// definition file that cannot be read, a local-only environment missing).
	StopOptionalUnverifiable = "optional-path-unverifiable"
	// StopOptionalLink: a symbolic link or a submodule entry sits at the
	// path or at one of its parent directories.
	StopOptionalLink = "optional-path-link"
	// StopOptionalPresentListed: the file exists at a tag the rules list as
	// proven absent; the pinned evidence is wrong.
	StopOptionalPresentListed = "optional-path-present-at-absent-tag"
	// StopOptionalAbsentNewest: the newest tag must read the file.
	StopOptionalAbsentNewest = "optional-absent-at-newest"
)

func init() {
	nextAction[StopOptionalUnverifiable] = "repair the local checkout or the entry; an optional path is tolerated only on verified true tree absence from local git"
	nextAction[StopOptionalLink] = "a symbolic link or submodule at an optional path is never followed; review the tree or drop the optional entry"
	nextAction[StopOptionalPresentListed] = "the file exists at a tag listed in absentTags; correct absentTags with pinned evidence"
	nextAction[StopOptionalAbsentNewest] = "the newest tag must carry the file; correct the entry or the tag set"
}

// PathKind is what a tree holds at one exact path.
type PathKind string

// Kinds a PathProber reports. PathAbsent means verified: no entry at the
// path, or a parent directory is itself absent. The Parent kinds say that a
// component above the path is a regular file, a symbolic link or a submodule
// entry.
const (
	PathAbsent        PathKind = "absent"
	PathFile          PathKind = "file"
	PathSymlink       PathKind = "symlink"
	PathGitlink       PathKind = "gitlink"
	PathDirectory     PathKind = "directory"
	PathParentFile    PathKind = "parent-file"
	PathParentSymlink PathKind = "parent-symlink"
	PathParentGitlink PathKind = "parent-gitlink"
)

// PathProber is implemented by a Tree that can say what sits at one exact
// path of the full tree. An error means "not proven"; a Tree without it can
// never support an optional entry.
type PathProber interface {
	Probe(path string) (PathKind, error)
}

var (
	lsRecRE  = regexp.MustCompile(`^([0-7]{6}) (blob|tree|commit) ([0-9a-f]{40}|[0-9a-f]{64})$`)
	treeShaR = regexp.MustCompile(`^([0-9a-f]{40}|[0-9a-f]{64})$`)
)

type lsRec struct {
	kind PathKind
	sha  string
	name string
}

// requireLocalOnly refuses to probe unless the command environment disables
// lazy fetching and network protocols.
func (g GitSource) requireLocalOnly() error {
	have := map[string]bool{}
	for _, e := range g.environ() {
		have[e] = true
	}
	for _, want := range []string{"GIT_NO_LAZY_FETCH=1", "GIT_ALLOW_PROTOCOL=none", "GIT_TERMINAL_PROMPT=0"} {
		if !have[want] {
			return fmt.Errorf("local-only git environment is missing %s", want)
		}
	}
	return nil
}

// lsTreeDir lists one tree object (not recursive). Every record must be a
// known entry kind; an unknown or malformed record fails the whole listing.
func (g GitSource) lsTreeDir(treeish string) ([]lsRec, error) {
	raw, err := g.git("ls-tree", "-z", "--end-of-options", treeish)
	if err != nil {
		return nil, err
	}
	var out []lsRec
	for _, rec := range bytes.Split(raw, []byte{0}) {
		if len(rec) == 0 {
			continue
		}
		tab := bytes.IndexByte(rec, '\t')
		if tab < 0 {
			return nil, errors.New("opaque tree record (no name separator)")
		}
		m := lsRecRE.FindStringSubmatch(string(rec[:tab]))
		if m == nil {
			return nil, errors.New("opaque tree record (unparseable header)")
		}
		name := string(rec[tab+1:])
		if name == "" || strings.Contains(name, "/") {
			return nil, errors.New("opaque tree record (bad name)")
		}
		var k PathKind
		switch {
		case m[1] == "040000" && m[2] == "tree":
			k = PathDirectory
		case (m[1] == "100644" || m[1] == "100755") && m[2] == "blob":
			k = PathFile
		case m[1] == "120000" && m[2] == "blob":
			k = PathSymlink
		case m[1] == "160000" && m[2] == "commit":
			k = PathGitlink
		default:
			return nil, fmt.Errorf("opaque tree record (mode %s with type %s)", m[1], m[2])
		}
		out = append(out, lsRec{kind: k, sha: m[3], name: name})
	}
	return out, nil
}

// Probe implements PathProber by walking the tree one component at a time
// from the commit's root tree. It never uses the recursive listing of Open,
// which silently skips entries it does not understand.
func (t *gitTree) Probe(p string) (PathKind, error) {
	if err := t.g.requireLocalOnly(); err != nil {
		return "", err
	}
	if p == "" || strings.HasPrefix(p, "/") || strings.HasSuffix(p, "/") {
		return "", fmt.Errorf("%q is not an exact file path", p)
	}
	segs := strings.Split(p, "/")
	treeish := t.commit + "^{tree}"
	for i, seg := range segs {
		if seg == "" || seg == "." || seg == ".." {
			return "", fmt.Errorf("%q is not a clean path", p)
		}
		recs, err := t.g.lsTreeDir(treeish)
		if err != nil {
			return "", err
		}
		var found *lsRec
		for k := range recs {
			if recs[k].name == seg {
				if found != nil {
					return "", fmt.Errorf("tree lists %q twice", seg)
				}
				found = &recs[k]
			}
		}
		if found == nil {
			return PathAbsent, nil
		}
		last := i == len(segs)-1
		switch found.kind {
		case PathDirectory:
			if last {
				return PathDirectory, nil
			}
			if !treeShaR.MatchString(found.sha) {
				return "", errors.New("opaque tree id")
			}
			treeish = found.sha
		case PathFile:
			if last {
				return PathFile, nil
			}
			return PathParentFile, nil
		case PathSymlink:
			if last {
				return PathSymlink, nil
			}
			return PathParentSymlink, nil
		default: // gitlink
			if last {
				return PathGitlink, nil
			}
			return PathParentGitlink, nil
		}
	}
	return "", errors.New("unreachable")
}

// optionalEntries returns the optional installPaths entries in rule order.
func optionalEntries(rules *Rules) []InstallPathRule {
	var out []InstallPathRule
	if rules == nil {
		return nil
	}
	for _, ip := range rules.InstallPaths {
		if ip.Optional {
			out = append(out, ip)
		}
	}
	return out
}

// validateOptionalEntry checks the rule-file shape of one entry.
func validateOptionalEntry(ip InstallPathRule) error {
	if !ip.Optional {
		if len(ip.AbsentTags) > 0 {
			return fmt.Errorf("rules: install path %q lists absentTags without optional:true", ip.Path)
		}
		return nil
	}
	if strings.HasSuffix(ip.Path, "/") || !candidateExt(ip.Path) {
		return fmt.Errorf("rules: optional install path %q must be one exact definition file (.yaml, .yml or .json), never a directory", ip.Path)
	}
	if len(ip.AbsentTags) == 0 {
		return fmt.Errorf("rules: optional install path %q needs absentTags naming the tags where its absence is proven", ip.Path)
	}
	seen := map[string]bool{}
	for _, t := range ip.AbsentTags {
		if !tagNameRE.MatchString(t) || seen[t] {
			return fmt.Errorf("rules: optional install path %q: absent tag %q is not a plain tag name or is listed twice", ip.Path, t)
		}
		seen[t] = true
	}
	return nil
}

// checkOptionalTags requires every absent tag to be a tag of the run.
func checkOptionalTags(rules *Rules, tags []parsedTag) []Stop {
	have := map[string]bool{}
	for _, t := range tags {
		have[t.Tag] = true
	}
	var out []Stop
	for _, ip := range optionalEntries(rules) {
		for _, t := range ip.AbsentTags {
			if !have[t] {
				out = append(out, stop(StopBadInput, ip.Path, "absent tag "+t+" is not a tag of the window"))
			}
		}
	}
	return out
}

func listedIn(tags []string, tag string) bool {
	for _, t := range tags {
		if t == tag {
			return true
		}
	}
	return false
}

// applyOptional settles the optional entries of one tag after classify. It
// removes the install-path-matches-nothing stop of an entry whose absence is
// verified and listed, records what each entry did, and returns the stops
// that must end the run whatever the tag (integrity of the reading, not
// content of the window).
func applyOptional(r *tagResult, tree Tree, rules *Rules, tag string, isNewest bool) []Stop {
	opts := optionalEntries(rules)
	if len(opts) == 0 {
		return nil
	}
	r.optStatus = map[string]string{}
	r.optAbsent = map[string]bool{}
	var fatal []Stop
	drop := map[string]bool{} // "<code>\x00<subject>" removed from r.stops
	for _, ip := range opts {
		unverifiable := func(why string) {
			fatal = append(fatal, stop(StopOptionalUnverifiable, ip.Path, tag+": "+why))
		}
		prober, ok := tree.(PathProber)
		if !ok {
			unverifiable("the tree reader cannot verify a path")
			continue
		}
		kind, err := prober.Probe(ip.Path)
		if err != nil {
			unverifiable(err.Error())
			continue
		}
		listed := listedIn(ip.AbsentTags, tag)
		switch kind {
		case PathFile:
			if listed {
				fatal = append(fatal, stop(StopOptionalPresentListed, ip.Path, tag+": the file exists but the tag is listed in absentTags"))
				continue
			}
			r.optStatus[ip.Path] = "read"
			// A present file that cannot be read as definitions is not
			// absent: refuse the run instead of shrinking the window.
			for _, s := range r.stops {
				if s.Code == StopUnreadableShape && s.Subject == ip.Path {
					unverifiable("present but unreadable: " + s.Detail)
					drop[s.Code+"\x00"+s.Subject] = true
				}
			}
		case PathAbsent:
			drop[StopInstallPathNothing+"\x00"+ip.Path] = true
			switch {
			case isNewest:
				r.stops = append(r.stops, stop(StopOptionalAbsentNewest, ip.Path, tag+": the newest tag must read the file"))
			case listed:
				r.optStatus[ip.Path] = "verified-absent"
				r.optAbsent[ip.Path] = true
			default:
				// Absent at a tag the rules do not list: the existing stop.
				delete(drop, StopInstallPathNothing+"\x00"+ip.Path)
			}
		case PathSymlink, PathGitlink, PathParentSymlink, PathParentGitlink:
			fatal = append(fatal, stop(StopOptionalLink, ip.Path, tag+": "+string(kind)))
		default: // directory, parent-file, anything unknown
			unverifiable("path state is " + string(kind))
		}
	}
	if len(drop) > 0 {
		kept := r.stops[:0:0]
		for _, s := range r.stops {
			if !drop[s.Code+"\x00"+s.Subject] {
				kept = append(kept, s)
			}
		}
		r.stops = kept
	}
	return fatal
}

// OptionalFact is what one optional entry did at one window tag.
type OptionalFact struct {
	Tag    string `json:"tag"`
	Path   string `json:"path"`
	Status string `json:"status"` // read | verified-absent
}

// annotateOptional adds the per-tag optional facts to the report and folds
// them into the facts digest. Without optional entries it does nothing, so
// every other digest is unchanged.
func annotateOptional(res *Result, rules *Rules, window []*tagResult) {
	opts := optionalEntries(rules)
	if len(opts) == 0 {
		return
	}
	paths := make([]string, 0, len(opts))
	for _, ip := range opts {
		paths = append(paths, ip.Path)
	}
	sort.Strings(paths)
	var lines []string
	for _, r := range window {
		for _, p := range paths {
			st := r.optStatus[p]
			res.Report.OptionalPaths = append(res.Report.OptionalPaths, OptionalFact{Tag: r.tag, Path: p, Status: st})
			lines = append(lines, r.tag+"\toptional\t"+p+"\t"+st)
		}
	}
	h := sha256.New()
	h.Write([]byte(res.Report.FactsDigest + "\n"))
	for _, l := range lines {
		h.Write([]byte(l + "\n"))
	}
	res.Report.FactsDigest = "sha256:" + hex.EncodeToString(h.Sum(nil))
}
