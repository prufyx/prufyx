// SPDX-License-Identifier: AGPL-3.0-only

package targetdraft

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Version-ranged installPaths entries.
//
// An installPaths entry may carry a role and a tag range (fromTag, toTag,
// both inclusive, tags of the run). Entries that share a role describe the
// same logical source moving over time: their ranges must be disjoint and
// contiguous and together cover the run exactly. Inside its range an entry is
// mandatory; outside its range its path must be absent from the full Git tree.
// Range membership is a generator-side selection and check only: the emitted
// target lists the union of the paths used and its format is unchanged.
// Without a ranged entry none of this code runs.

// Stop codes of ranged entries.
const (
	StopRangeGap             = "range-gap"
	StopRangeOverlap         = "range-overlap"
	StopRangeNotCovering     = "range-not-covering-window"
	StopRangeAbsentInRange   = "range-path-absent-in-range"
	StopRangePresentOutRange = "range-path-present-out-of-range"
	StopRangeUnverifiable    = "range-path-unverifiable"

	rangeWithOptionalParseTag = "range-with-optional"
)

func init() {
	nextAction[StopRangeGap] = "tags between two ranges of one role belong to no entry; extend a range so the ranges of the role are contiguous, never leave a tag uncovered"
	nextAction[StopRangeOverlap] = "two entries of one role cover the same tag; make the ranges disjoint"
	nextAction[StopRangeNotCovering] = "the ranges of a role must cover the whole tag window exactly; add or extend an entry so the oldest and the newest tag are covered"
	nextAction[StopRangeAbsentInRange] = "an entry is mandatory inside its range and its path is absent (or holds no definition file) at this tag; correct the range boundary or the path with pinned evidence"
	nextAction[StopRangePresentOutRange] = "the path exists at a tag outside the entry's range, so the pinned move evidence is wrong; correct the range boundary"
	nextAction[StopRangeUnverifiable] = "the path state at this tag could not be proven from the local full tree (read error, link, submodule, wrong entry type or no probing reader); repair the checkout or the entry"
}

var roleRE = regexp.MustCompile(`^[a-z][a-z0-9-]{0,62}$`)

// validateRangeEntry checks the rule-file shape of the range members of one
// entry. Tag-dependent checks are typed stops in planRanges.
func validateRangeEntry(ip InstallPathRule) error {
	hasRange := ip.FromTag != "" || ip.ToTag != ""
	if ip.Role == "" {
		if hasRange {
			return fmt.Errorf("rules: install path %q: fromTag/toTag need a role", ip.Path)
		}
		return nil
	}
	if ip.Optional || len(ip.AbsentTags) > 0 {
		return fmt.Errorf("rules: %s: install path %q combines role/range with optional or absentTags; a range replaces optional for a moved path", rangeWithOptionalParseTag, ip.Path)
	}
	if !roleRE.MatchString(ip.Role) {
		return fmt.Errorf("rules: install path %q: role %q is not a lower-case name", ip.Path, ip.Role)
	}
	if !hasRange {
		return fmt.Errorf("rules: install path %q: a role needs fromTag and/or toTag (an omitted bound means the window edge)", ip.Path)
	}
	for _, t := range []string{ip.FromTag, ip.ToTag} {
		if t != "" && !tagNameRE.MatchString(t) {
			return fmt.Errorf("rules: install path %q: range tag %q is not a plain tag name", ip.Path, t)
		}
	}
	return nil
}

// validateRoleShapes requires the entries of one role to share a match shape.
func validateRoleShapes(r *Rules) error {
	seen := map[string]bool{}
	for _, ip := range r.InstallPaths {
		if ip.Role == "" {
			continue
		}
		d := strings.HasSuffix(ip.Path, "/")
		if prev, ok := seen[ip.Role]; ok && prev != d {
			return fmt.Errorf("rules: role %q mixes directory and exact-file entries", ip.Role)
		}
		seen[ip.Role] = d
	}
	return nil
}

func usesRanges(r *Rules) bool {
	if r == nil {
		return false
	}
	for _, ip := range r.InstallPaths {
		if ip.Role != "" {
			return true
		}
	}
	return false
}

// rangeEntry is one ranged entry with its resolved inclusive line indexes.
type rangeEntry struct {
	ip          *InstallPathRule
	first, last int
}

// rangeCtx says which ranged entries apply at the tag being classified.
type rangeCtx struct {
	entries map[string]rangeEntry
	idx     int
}

func (c *rangeCtx) active(ip *InstallPathRule) bool {
	if c == nil || ip.Role == "" {
		return true
	}
	e, ok := c.entries[ip.Path]
	if !ok {
		return false
	}
	return e.first <= c.idx && c.idx <= e.last
}

// planRanges resolves every ranged entry against the run's tags and checks
// that the ranges of each role are disjoint, contiguous and cover the run.
func planRanges(rules *Rules, tags []parsedTag) (map[string]rangeEntry, []Stop) {
	if !usesRanges(rules) {
		return nil, nil
	}
	at := map[string]int{}
	for i, t := range tags {
		at[t.Tag] = i
	}
	n := len(tags)
	var stops []Stop
	byRole := map[string][]rangeEntry{}
	plan := map[string]rangeEntry{}
	for k := range rules.InstallPaths {
		ip := &rules.InstallPaths[k]
		if ip.Role == "" {
			continue
		}
		e := rangeEntry{ip: ip, first: 0, last: n - 1}
		ok := true
		if ip.FromTag != "" {
			i, found := at[ip.FromTag]
			if !found {
				stops = append(stops, stop(StopBadInput, ip.Path, "fromTag "+ip.FromTag+" is not a tag of the window"))
				ok = false
			}
			e.first = i
		}
		if ip.ToTag != "" {
			i, found := at[ip.ToTag]
			if !found {
				stops = append(stops, stop(StopBadInput, ip.Path, "toTag "+ip.ToTag+" is not a tag of the window"))
				ok = false
			}
			e.last = i
		}
		if ok && e.first > e.last {
			stops = append(stops, stop(StopBadInput, ip.Path, "fromTag "+ip.FromTag+" is after toTag "+ip.ToTag))
			ok = false
		}
		if !ok {
			continue
		}
		byRole[ip.Role] = append(byRole[ip.Role], e)
		plan[ip.Path] = e
	}
	if len(stops) > 0 {
		return nil, sortStops(stops)
	}
	span := func(a, b int) string {
		if a == b {
			return tags[a].Tag
		}
		return tags[a].Tag + ".." + tags[b].Tag
	}
	for role, es := range byRole {
		sort.Slice(es, func(i, j int) bool {
			if es[i].first != es[j].first {
				return es[i].first < es[j].first
			}
			return es[i].ip.Path < es[j].ip.Path
		})
		if es[0].first != 0 {
			stops = append(stops, stop(StopRangeNotCovering, role, "oldest tags "+span(0, es[0].first-1)+" are covered by no entry"))
		}
		maxTo := es[0].last
		for i := 1; i < len(es); i++ {
			prev, cur := es[i-1], es[i]
			switch {
			case cur.first <= prev.last:
				hi := prev.last
				if cur.last < hi {
					hi = cur.last
				}
				stops = append(stops, stop(StopRangeOverlap, role, fmt.Sprintf("%s and %s both cover %s", prev.ip.Path, cur.ip.Path, span(cur.first, hi))))
			case cur.first > prev.last+1:
				stops = append(stops, stop(StopRangeGap, role, fmt.Sprintf("tags %s are covered by no entry (between %s and %s)", span(prev.last+1, cur.first-1), prev.ip.Path, cur.ip.Path)))
			}
			if cur.last > maxTo {
				maxTo = cur.last
			}
		}
		if maxTo != n-1 {
			stops = append(stops, stop(StopRangeNotCovering, role, "newest tags "+span(maxTo+1, n-1)+" are covered by no entry"))
		}
	}
	if len(stops) > 0 {
		return nil, sortStops(stops)
	}
	return plan, nil
}

// probeRanged checks one ranged entry against one tree. active says the tag
// lies inside the entry's range. detail names the tag.
func probeRanged(tree Tree, e rangeEntry, active bool, detail string) []Stop {
	prober, ok := tree.(PathProber)
	if !ok {
		return []Stop{stop(StopRangeUnverifiable, e.ip.Path, detail+": the tree reader cannot verify a path")}
	}
	kind, err := prober.Probe(strings.TrimSuffix(e.ip.Path, "/"))
	if err != nil {
		return []Stop{stop(StopRangeUnverifiable, e.ip.Path, detail+": "+err.Error())}
	}
	dir := strings.HasSuffix(e.ip.Path, "/")
	switch kind {
	case PathAbsent:
		if active {
			return []Stop{stop(StopRangeAbsentInRange, e.ip.Path, detail+": the path is absent inside its range ("+rangeText(e)+")")}
		}
		return nil
	case PathSymlink, PathGitlink, PathParentFile, PathParentSymlink, PathParentGitlink:
		return []Stop{stop(StopRangeUnverifiable, e.ip.Path, detail+": path state is "+string(kind))}
	}
	if !active {
		return []Stop{stop(StopRangePresentOutRange, e.ip.Path, detail+": the path is present outside its range ("+rangeText(e)+")")}
	}
	if (dir && kind != PathDirectory) || (!dir && kind != PathFile) {
		return []Stop{stop(StopRangeUnverifiable, e.ip.Path, detail+": path state is "+string(kind))}
	}
	return nil
}

func rangeText(e rangeEntry) string {
	f, t := e.ip.FromTag, e.ip.ToTag
	if f == "" {
		f = "oldest"
	}
	if t == "" {
		t = "newest"
	}
	return f + ".." + t
}

// RangedFact is the ranged entry selected at one window tag.
type RangedFact struct {
	Tag  string `json:"tag"`
	Role string `json:"role"`
	Path string `json:"path"`
}

func sortedPlanPaths(plan map[string]rangeEntry) []string {
	paths := make([]string, 0, len(plan))
	for p := range plan {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	return paths
}

// applyRanges settles the ranged entries of one run tag after classify and
// returns the stops that end the run. A ranged entry's stop is never turned
// into a shorter window.
func applyRanges(r *tagResult, tree Tree, plan map[string]rangeEntry, idx int, tag string) []Stop {
	var fatal []Stop
	for _, p := range sortedPlanPaths(plan) {
		e := plan[p]
		active := e.first <= idx && idx <= e.last
		st := probeRanged(tree, e, active, tag)
		if active {
			if len(st) == 0 && !r.usedIP[p] {
				st = []Stop{stop(StopRangeAbsentInRange, p, tag+": the path holds no definition file inside its range")}
			}
			if len(st) == 0 {
				r.ranged = append(r.ranged, RangedFact{Tag: tag, Role: e.ip.Role, Path: p})
			}
			dropStop(r, StopInstallPathNothing, p)
		}
		fatal = append(fatal, st...)
	}
	return fatal
}

func dropStop(r *tagResult, code, subject string) {
	kept := r.stops[:0:0]
	for _, s := range r.stops {
		if s.Code != code || s.Subject != subject {
			kept = append(kept, s)
		}
	}
	r.stops = kept
}

// checkRangeTags reads ALL given tags of each line (not only the run tag of
// the line) to prove each ranged entry present inside and absent outside its
// range. It never classifies. Local git only: the probe refuses to run
// without the local-only environment.
func checkRangeTags(in Input, tags []parsedTag, plan map[string]rangeEntry) ([]string, []Stop) {
	if len(in.RangeCheckTags) == 0 {
		return nil, nil
	}
	if len(plan) == 0 {
		return nil, []Stop{stop(StopBadInput, "", "range check tags need ranged installPaths entries")}
	}
	line := map[[2]int]int{}
	runTag := map[string]bool{}
	for i, t := range tags {
		line[[2]int{t.Major, t.Minor}] = i
		runTag[t.Tag] = true
	}
	paths := sortedPlanPaths(plan)
	seen := map[string]bool{}
	var checked []string
	var stops []Stop
	list := append([]string(nil), in.RangeCheckTags...)
	sort.Strings(list)
	for _, t := range list {
		if seen[t] {
			stops = append(stops, stop(StopBadInput, t, "range check tag listed twice"))
			continue
		}
		seen[t] = true
		m := tagRE.FindStringSubmatch(t)
		if m == nil || m[1] != tags[0].Prefix {
			stops = append(stops, stop(StopBadInput, t, "range check tag is not <prefix>X.Y.Z of the run's prefix"))
			continue
		}
		maj, _ := strconv.Atoi(m[2])
		min, _ := strconv.Atoi(m[3])
		idx, ok := line[[2]int{maj, min}]
		if !ok {
			stops = append(stops, stop(StopBadInput, t, "range check tag belongs to no line of the run"))
			continue
		}
		if runTag[t] {
			// Already read by the run itself.
			checked = append(checked, t)
			continue
		}
		tree, _, err := in.Source.Open(t)
		if err != nil {
			stops = append(stops, stop(StopTagUnreadable, t, err.Error()))
			continue
		}
		checked = append(checked, t)
		for _, p := range paths {
			e := plan[p]
			active := e.first <= idx && idx <= e.last
			stops = append(stops, probeRanged(tree, e, active, t+" (range check, line of "+tags[idx].Tag+")")...)
		}
	}
	return checked, stops
}

// keySet is the logical file set of a tag: a file under a ranged entry is
// keyed by role and the path relative to the entry, so the same logical file
// before and after a move is the same key.
func (r *tagResult) keySet() map[string]bool {
	out := make(map[string]bool, len(r.included))
	for p := range r.included {
		if k, ok := r.logical[p]; ok {
			out[k] = true
		} else {
			out[p] = true
		}
	}
	return out
}

func displayKey(k string) string { return strings.Replace(k, "\x00", ":", 1) }

// logicalKeys maps each included file under a ranged entry to its key.
func logicalKeys(rules *Rules, r *tagResult) {
	for p := range r.included {
		ip := installPathFor(rules, p, nil)
		if ip == nil || ip.Role == "" {
			continue
		}
		if r.logical == nil {
			r.logical = map[string]string{}
		}
		r.logical[p] = "role " + ip.Role + "\x00" + strings.TrimPrefix(p, ip.Path)
	}
}

// filterApplies says whether a pathFilter entry can match at the tag: a filter
// that lies only under ranged entries applies only where one of them is
// active. expectFiles is therefore the exact count where the entry applies.
func filterApplies(rules *Rules, glob string, rg *rangeCtx) bool {
	if rg == nil {
		return true
	}
	gs := strings.Split(glob, "/")
	covered, applies := false, false
	for k := range rules.InstallPaths {
		e := &rules.InstallPaths[k]
		cov := false
		if strings.HasSuffix(e.Path, "/") {
			es := strings.Split(strings.TrimSuffix(e.Path, "/"), "/")
			if len(gs) > len(es) {
				cov = true
				for i := range es {
					if ok, err := path.Match(gs[i], es[i]); err != nil || !ok {
						cov = false
						break
					}
				}
			}
		} else {
			cov = globMatch(glob, e.Path)
		}
		if !cov {
			continue
		}
		covered = true
		if e.Role == "" || rg.active(e) {
			applies = true
		}
	}
	return !covered || applies
}

// annotateRanges adds the per-tag ranged selection to the report and folds it
// into the facts digest. Without ranged entries it does nothing, so every
// other digest is unchanged.
func annotateRanges(res *Result, rules *Rules, window []*tagResult, checked []string) {
	if !usesRanges(rules) {
		return
	}
	var lines []string
	for _, r := range window {
		facts := append([]RangedFact(nil), r.ranged...)
		sort.Slice(facts, func(i, j int) bool {
			if facts[i].Role != facts[j].Role {
				return facts[i].Role < facts[j].Role
			}
			return facts[i].Path < facts[j].Path
		})
		for _, f := range facts {
			res.Report.RangedPaths = append(res.Report.RangedPaths, f)
			lines = append(lines, f.Tag+"\trange\t"+safeField(f.Role)+"\t"+safeField(f.Path))
		}
	}
	if len(checked) > 0 {
		res.Report.RangeCheckedTags = append([]string(nil), checked...)
		sort.Strings(res.Report.RangeCheckedTags)
		for _, t := range res.Report.RangeCheckedTags {
			lines = append(lines, t+"\trange-check")
		}
	}
	h := sha256.New()
	h.Write([]byte(res.Report.FactsDigest + "\n"))
	for _, l := range lines {
		h.Write([]byte(l + "\n"))
	}
	res.Report.FactsDigest = "sha256:" + hex.EncodeToString(h.Sum(nil))
}

// unionIncluded is every file read at any window tag (the newest tag's entry
// wins), the paths of the emitted target when ranges are used.
func unionIncluded(window []*tagResult) map[string]*inclusion {
	out := map[string]*inclusion{}
	for _, r := range window {
		for p, i := range r.included {
			out[p] = i
		}
	}
	return out
}
