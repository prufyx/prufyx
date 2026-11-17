// SPDX-License-Identifier: AGPL-3.0-only

package targetdraft

import (
	"fmt"
	"path"
	"sort"
	"strconv"
	"strings"
)

// Install-path inference (opt-in, Input.InferInstallPaths) and the outside-copy
// checks (opt-in, Input.CheckInstallPathCopies, implied by inference).
//
// Inference reads only the decoded definition files of the tags of the run. It
// derives ONE directory by a fixed literal rule (R2) and uses it as
// installPaths only when that directory is the unambiguous winner at EVERY tag
// of the run; anything else is the typed stop install-path-ambiguous and
// nothing is written. It never creates an exclusion, a filter, an optional or a
// ranged entry and never widens a match or guard. The module is pure: no IO.
//
// Rule R2 (per tag):
//   - a candidate is a readable file that defines at least one definition and
//     whose directory path has no skipped segment (see inferSkipSegment);
//   - rank 1: a config/crd or config/crds directory outside a chart; rank 2:
//     another crd or crds directory outside a chart; rank 3: a crd or crds
//     directory below a chart; every other directory has no rank and is never
//     picked;
//   - when any rank 1 or 2 candidate exists only ranks 1 and 2 count,
//     otherwise only rank 3 counts;
//   - each definition (group and kind) picks the directories of its files of
//     the best rank; the union of the picked directories must be ONE directory.

// Fixed texts of the inferred entry; never read from repository content.
const (
	inferRule     = "R2"
	inferReason   = "inferred: rule R2 install directory"
	inferEvidence = "inferred: rule R2 chose this directory at every tag of the run"
)

// inferSkipExact are directory segments that are never an install location.
var inferSkipExact = map[string]bool{
	"vendor": true, "node_modules": true, "third_party": true, "testdata": true,
	"test": true, "tests": true, "e2e": true, "docs": true, "doc": true,
	"hack": true, "example": true, "examples": true, "sample": true,
	"samples": true, "fixtures": true, "fixture": true, "output": true,
	"dist": true, "templates": true, "olm": true, "olm-catalog": true,
}

// inferSkipSegment says that a directory segment disqualifies a file: the
// literal list above, any segment starting with "bundle", and the extractor's
// default-excluded segments (through testLike on the whole path, see
// inferRank).
func inferSkipSegment(seg string) bool {
	s := strings.ToLower(seg)
	return inferSkipExact[s] || strings.HasPrefix(s, "bundle")
}

// inferSkippedPath says that a file sits below a skipped directory (the same
// segments that disqualify a ranking candidate, plus the default-excluded and
// documentation segments).
func inferSkippedPath(p string) bool {
	if testLike(p) {
		return true
	}
	segs := strings.Split(p, "/")
	for _, s := range segs[:len(segs)-1] {
		if inferSkipSegment(s) {
			return true
		}
	}
	return false
}

// inferMayStayUnread says that an unreadable file may stay unread: its
// resolved path is skipped AND every symbolic link that reaches it is below a
// skipped directory too. A file reached through a link from an install-like
// location is never skipped.
func inferMayStayUnread(f *finding) bool {
	if !inferSkippedPath(f.Path) {
		return false
	}
	for _, l := range f.Reached {
		if !inferSkippedPath(l) {
			return false
		}
	}
	return true
}

// inferRank returns the rank of a definition file (1 best, 3 worst) or 0 when
// the file is never a candidate.
func inferRank(p string) int {
	if testLike(p) {
		return 0
	}
	segs := strings.Split(p, "/")
	dirs := segs[:len(segs)-1]
	if len(dirs) == 0 {
		return 0
	}
	chart, crdDir, cfgCRD := false, false, false
	for i, s := range dirs {
		l := strings.ToLower(s)
		if inferSkipSegment(l) {
			return 0
		}
		switch l {
		case "charts", "chart", "helm":
			chart = true
		case "crd", "crds":
			crdDir = true
			if i > 0 && strings.ToLower(dirs[i-1]) == "config" {
				cfgCRD = true
			}
		}
	}
	switch {
	case cfgCRD && !chart:
		return 1
	case crdDir && !chart:
		return 2
	case crdDir && chart:
		return 3
	}
	return 0
}

// InferCandidate is one directory that holds ranked definition files at a tag.
type InferCandidate struct {
	Dir  string `json:"dir"`
	Rank int    `json:"rank"`
	Keys int    `json:"keys"`
}

// InferTagFact is the ranking evidence of one tag.
type InferTagFact struct {
	Tag        string           `json:"tag"`
	Candidates []InferCandidate `json:"candidates"`
}

// InferredInstallPaths is the report block of an inferred run. It exists only
// when inference ran and is part of the facts digest then.
type InferredInstallPaths struct {
	Rule  string         `json:"rule"`
	Paths []string       `json:"paths"`
	Rank  int            `json:"rank"`
	Tags  []InferTagFact `json:"tags"`
}

func ambiguous(subject, detail string) []Stop {
	return []Stop{stop(StopInstallPathAmbiguous, subject, detail)}
}

// inferOne applies rule R2 to one tag. It returns the chosen directory (with a
// trailing slash), its rank and the evidence, or a stop.
func inferOne(tag string, fs []*finding) (string, int, InferTagFact, []Stop) {
	fact := InferTagFact{Tag: tag, Candidates: []InferCandidate{}}
	type cand struct {
		f    *finding
		rank int
		dir  string
	}
	var cs []cand
	var unreadable []cand
	for _, f := range fs {
		rk := inferRank(f.Path)
		if rk == 0 {
			continue
		}
		c := cand{f: f, rank: rk, dir: path.Dir(f.Path) + "/"}
		if f.Unreadable != "" {
			unreadable = append(unreadable, c)
			continue
		}
		if len(f.CRDs) > 0 {
			cs = append(cs, c)
		}
	}
	// Evidence: every ranked directory with its definition keys.
	type dk struct {
		dir  string
		rank int
	}
	keysOf := map[dk]map[string]bool{}
	for _, c := range cs {
		k := dk{c.dir, c.rank}
		if keysOf[k] == nil {
			keysOf[k] = map[string]bool{}
		}
		for _, d := range c.f.CRDs {
			keysOf[k][crdKey(d)] = true
		}
	}
	for k, ks := range keysOf {
		fact.Candidates = append(fact.Candidates, InferCandidate{Dir: k.dir, Rank: k.rank, Keys: len(ks)})
	}
	sort.Slice(fact.Candidates, func(i, j int) bool {
		a, b := fact.Candidates[i], fact.Candidates[j]
		if a.Rank != b.Rank {
			return a.Rank < b.Rank
		}
		return a.Dir < b.Dir
	})
	if len(cs) == 0 {
		return "", 0, fact, ambiguous(tag, "no ranked definition directory (rule R2)")
	}
	// Tier: ranks 1 and 2 when any exists, otherwise rank 3.
	tierMax := 3
	for _, c := range cs {
		if c.rank <= 2 {
			tierMax = 2
			break
		}
	}
	inTier := func(rk int) bool {
		if tierMax == 2 {
			return rk <= 2
		}
		return rk == 3
	}
	best := map[string]int{} // key -> best rank
	for _, c := range cs {
		if !inTier(c.rank) {
			continue
		}
		for _, d := range c.f.CRDs {
			k := crdKey(d)
			if r, ok := best[k]; !ok || c.rank < r {
				best[k] = c.rank
			}
		}
	}
	dirs := map[string]bool{}
	rank := 0
	for _, c := range cs {
		if !inTier(c.rank) {
			continue
		}
		for _, d := range c.f.CRDs {
			if best[crdKey(d)] == c.rank {
				dirs[c.dir] = true
				if rank == 0 || c.rank < rank {
					rank = c.rank
				}
			}
		}
	}
	if len(dirs) != 1 {
		var ds []string
		for d := range dirs {
			ds = append(ds, d)
		}
		sort.Strings(ds)
		return "", 0, fact, ambiguous(tag, "the best-ranked definitions sit in "+strconv.Itoa(len(ds))+" directories: "+strings.Join(ds, ", "))
	}
	var dir string
	for d := range dirs {
		dir = d
	}
	// The directory entry reads everything below it: every definition-bearing
	// file below it must itself be a ranked candidate of exactly that
	// directory (no deeper directory, no skipped segment).
	for _, f := range fs {
		if !strings.HasPrefix(f.Path, dir) {
			continue
		}
		if path.Dir(f.Path)+"/" != dir || inferRank(f.Path) == 0 {
			return "", 0, fact, ambiguous(f.Path, "the directory "+dir+" would also read this file, which rule R2 does not rank")
		}
	}
	// An unreadable definition file that ranks as well as the choice and sits
	// elsewhere could hide a definition; it is never guessed around.
	for _, u := range unreadable {
		if u.dir != dir && u.rank <= rank {
			return "", 0, fact, ambiguous(u.f.Path, "unreadable file of rank "+strconv.Itoa(u.rank)+" outside the chosen directory "+dir)
		}
	}
	return dir, rank, fact, nil
}

// inferInstallPaths applies rule R2 to every tag (oldest first as given) and
// requires the same directory and rank at every one. Result: the entry and the
// report block, or the stops.
func inferInstallPaths(tags []parsedTag, scans [][]*finding) (*InstallPathRule, *InferredInstallPaths, []Stop) {
	if len(tags) == 0 || len(tags) != len(scans) {
		return nil, nil, ambiguous("", "no tags to infer from")
	}
	var dir string
	rank := 0
	var facts []InferTagFact
	for i, t := range tags {
		d, rk, fact, stops := inferOne(t.Tag, scans[i])
		if len(stops) > 0 {
			return nil, nil, stops
		}
		facts = append(facts, fact)
		if i == 0 {
			dir, rank = d, rk
			continue
		}
		if d != dir || rk != rank {
			return nil, nil, ambiguous(t.Tag, fmt.Sprintf("rule R2 chooses %s (rank %d) here and %s (rank %d) at %s", d, rk, dir, rank, tags[0].Tag))
		}
	}
	sort.Slice(facts, func(i, j int) bool { return facts[i].Tag < facts[j].Tag })
	return &InstallPathRule{Path: dir, Reason: inferReason, Evidence: inferEvidence},
		&InferredInstallPaths{Rule: inferRule, Paths: []string{dir}, Rank: rank, Tags: facts}, nil
}

// annotateInferred adds the inferred set and its rank evidence to the report,
// the facts digest and the changelog. Only runs that inferred call it, so every
// other digest is unchanged.
func annotateInferred(res *Result, inf *InferredInstallPaths) {
	var lines []string
	lines = append(lines, "inferred-install-paths\t"+safeField(inf.Rule)+"\t"+safeField(strings.Join(inf.Paths, ","))+"\t"+strconv.Itoa(inf.Rank))
	for _, t := range inf.Tags {
		for _, c := range t.Candidates {
			lines = append(lines, fmt.Sprintf("%s\tinfer-candidate\t%s\t%d\t%d", safeField(t.Tag), safeField(c.Dir), c.Rank, c.Keys))
		}
	}
	res.Report.InferredInstallPaths = inf
	res.Report.FactsDigest = sumHex([]byte(res.Report.FactsDigest + "\n" + strings.Join(lines, "\n") + "\n"))
	txt := "\nInstall paths were inferred, not reviewed by hand: rule " + inf.Rule + " chose " + strings.Join(inf.Paths, ", ") + " (rank " + strconv.Itoa(inf.Rank) + ") at every tag of the run. Every readable definition file outside it was compared with the installed definitions and none differs or hides a definition; an unreadable file outside it is a stop unless it sits below a skipped directory (documentation, test, vendor, templates, bundle, olm), where it stays unread and is reported as a non-install copy."
	res.Changelog = append(res.Changelog, []byte(txt+"\n")...)
}

// outsideChecks proves, for one tag, that the files outside the install set
// neither hide a definition nor repeat one with a different spec. Files with
// a reviewed exclusion rule are not passed in; unreadable files define no
// comparable definition: such a file is a stop unless it sits below a skipped
// directory. It is the single place of both checks.
func outsideChecks(inside []*inclusion, outside []*finding) []Stop {
	held := map[string][]crd{}
	for _, i := range inside {
		for _, c := range i.CRDs {
			held[crdKey(c)] = append(held[crdKey(c)], c)
		}
	}
	var stops []Stop
	for _, f := range outside {
		if f.Unreadable != "" {
			// An unreadable file may define anything; only a skipped
			// directory (docs, test, vendor, templates, bundle, olm, ...) may
			// stay unread. Everywhere else it is a stop.
			if !inferMayStayUnread(f) {
				stops = append(stops, stop(StopInstallPathHidesCRD, f.Path, "unreadable file outside the install paths may define a definition no install path defines: "+f.Unreadable))
			}
			continue
		}
		for _, c := range f.CRDs {
			k := crdKey(c)
			hs := held[k]
			if len(hs) == 0 {
				stops = append(stops, stop(StopInstallPathHidesCRD, k, f.Path+" defines it and no install path does"))
				continue
			}
			for _, h := range hs {
				if !crdsEqual(h, c) {
					stops = append(stops, stop(StopInstallPathCopyDiffers, k, fmt.Sprintf("%s differs from the installed definition in %s", f.Path, firstDifference(h, c))))
					break
				}
			}
		}
	}
	return stops
}
