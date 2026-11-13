// SPDX-License-Identifier: AGPL-3.0-only

// Package targetdraft derives a CRD version target draft from a source tree.
// It is read-only: it reads the tags of a local checkout through a Source,
// reads no network and writes nothing but its returned values. The output is
// two halves of one target (A: onboarding target without attestation or
// exclusions; B: the same target with attestation and the pinned
// exclusions), a table row, a changelog text and a report naming the rule
// behind every decision. A judgment the pinned rules do not cover ends in a
// typed Stop, never in a guess.
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

	"github.com/prufyx/prufyx/cli/internal/customresources"
	"github.com/prufyx/prufyx/cli/internal/extract/crdversions"
)

// Input is everything one run needs.
type Input struct {
	Slug        string
	Name        string
	Repo        string // github.com/<owner>/<name>
	Component   string // default pkg:github/<owner>/<name>
	FactProject string // default: Slug with dashes as underscores
	Catalog     string // "cncf" (default) or "community"
	Tags        []string
	Source      Source
	Rules       *Rules
	// StrictWindow turns a shrunk window (older tags withheld) into the
	// typed stop window-shortened.
	StrictWindow bool
	// RangeCheckTags are ALL tags of the lines of the run (not only the one
	// tag per line the run reads). They are used only to prove each ranged
	// installPaths entry present inside and absent outside its range; they
	// are never classified. Needs ranged entries.
	RangeCheckTags []string
}

// Result is the successful output of a run.
type Result struct {
	A         []byte // half A target file
	B         []byte // half B target file
	TableRow  []byte
	Changelog []byte
	Report    Report
}

var (
	slugRE = regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*$`)
	repoRE = regexp.MustCompile(`^github\.com/[A-Za-z0-9][A-Za-z0-9._-]*/[A-Za-z0-9][A-Za-z0-9._-]*$`)
	tagRE  = regexp.MustCompile(`^([^0-9]*)(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$`)
)

type parsedTag struct {
	Tag          string
	Prefix       string
	Major, Minor int
}

// Generate runs the generator. On a judgment it cannot make it returns a
// *StopError and no files.
func Generate(in Input) (*Result, error) {
	if !slugRE.MatchString(in.Slug) || in.Name == "" || !repoRE.MatchString(in.Repo) || in.Source == nil {
		return nil, &StopError{Stops: []Stop{stop(StopBadInput, "", "slug, name, repo and a source are required and must be well formed")}}
	}
	catalog := in.Catalog
	if catalog == "" {
		catalog = crdversions.CatalogCNCF
	}
	if catalog != crdversions.CatalogCNCF && catalog != crdversions.CatalogCommunity {
		return nil, &StopError{Stops: []Stop{stop(StopBadInput, catalog, "catalog must be cncf or community")}}
	}
	ownerRepo := strings.TrimPrefix(in.Repo, "github.com/")
	component := in.Component
	if component == "" {
		component = "pkg:github/" + ownerRepo
	}
	fact := in.FactProject
	if fact == "" {
		fact = strings.ReplaceAll(in.Slug, "-", "_")
	}
	rules := in.Rules
	if rules == nil {
		rules = &Rules{Schema: RulesSchema}
	}
	if catalog == crdversions.CatalogCommunity {
		u := rules.Upstream
		if u == nil || u.Name == "" || u.Repository == "" || u.License == "" || u.LicenseSource == "" {
			return nil, &StopError{Stops: []Stop{stop(StopCommunityUpstream, in.Slug, "")}}
		}
	}

	tags, prefix, stops := parseTags(in.Tags)
	if len(stops) > 0 {
		return nil, &StopError{Stops: stops}
	}

	if stops := checkOptionalTags(rules, tags); len(stops) > 0 {
		return nil, &StopError{Stops: sortStops(stops)}
	}
	plan, rstops := planRanges(rules, tags)
	if len(rstops) > 0 {
		return nil, &StopError{Stops: sortStops(rstops)}
	}
	index := customresources.DefaultIndex()
	var optFatal []Stop
	results := make([]*tagResult, len(tags))
	for i, t := range tags {
		tree, commit, err := in.Source.Open(t.Tag)
		if err != nil {
			return nil, &StopError{Stops: []Stop{stop(StopTagUnreadable, t.Tag, err.Error())}}
		}
		fs, scanStops := scanTree(tree)
		var rg *rangeCtx
		if plan != nil {
			rg = &rangeCtx{entries: plan, idx: i}
		}
		r := classify(t.Tag, commit, fs, rules, in.Slug, index, rg)
		r.stops = append(scanStops, r.stops...)
		optFatal = append(optFatal, applyOptional(r, tree, rules, t.Tag, i == len(tags)-1)...)
		if plan != nil {
			optFatal = append(optFatal, applyRanges(r, tree, plan, i, t.Tag)...)
			logicalKeys(rules, r)
		}
		results[i] = r
	}
	checked, cstops := checkRangeTags(in, tags, plan)
	optFatal = append(optFatal, cstops...)
	if len(optFatal) > 0 {
		return nil, &StopError{Stops: sortStops(optFatal)}
	}

	newest := results[len(results)-1]
	if len(newest.stops) > 0 {
		return nil, &StopError{Stops: sortStops(newest.stops)}
	}
	// The window is the longest run of newest tags that read the same
	// included files with no stop; older tags are withheld and reported.
	first := len(results) - 1
	var dropped []DroppedTag
	for i := len(results) - 2; i >= 0; i-- {
		why := differs(results[i], newest)
		if why != "" {
			for j := i; j >= 0; j-- {
				dropped = append(dropped, DroppedTag{Tag: results[j].tag, Reason: reasonFor(results[j], newest, j == i)})
			}
			break
		}
		first = i
	}
	sort.Slice(dropped, func(i, j int) bool { return dropped[i].Tag < dropped[j].Tag })
	window := results[first:]
	if len(window) < 2 {
		d := "only the newest tag reads"
		if len(dropped) > 0 {
			d += "; " + dropped[len(dropped)-1].Tag + " withheld: " + dropped[len(dropped)-1].Reason
		}
		return nil, &StopError{Stops: []Stop{stop(StopWindowTooShort, window[0].tag, d)}}
	}
	// Every pinned rule must have been used in the window.
	usedExcl := map[string]bool{}
	usedSurf := map[string]bool{}
	for _, r := range window {
		for p := range r.usedExcl {
			usedExcl[p] = true
		}
		for p := range r.usedSurf {
			usedSurf[p] = true
		}
	}
	var ruleStops []Stop
	for _, e := range rules.Exclusions {
		if !usedExcl[e.Path] {
			ruleStops = append(ruleStops, stop(StopRuleMatchesNothing, e.Path, "exclusion"))
		}
	}
	for _, s := range rules.InstallSurface {
		if !usedSurf[s.Path] {
			ruleStops = append(ruleStops, stop(StopRuleMatchesNothing, s.Path, "install surface"))
		}
	}
	if len(ruleStops) > 0 {
		return nil, &StopError{Stops: sortStops(ruleStops)}
	}

	if in.StrictWindow && len(dropped) > 0 {
		return nil, &StopError{Stops: []Stop{stop(StopWindowShortened, dropped[len(dropped)-1].Tag, fmt.Sprintf("%d older tag(s) withheld; last: %s", len(dropped), dropped[len(dropped)-1].Reason))}}
	}
	minFrom := fmt.Sprintf("%d.%d", tags[first].Major, tags[first].Minor)
	var union map[string]*inclusion
	if plan != nil {
		union = unionIncluded(window)
	}
	res, err := build(in, catalog, component, fact, ownerRepo, prefix, minFrom, rules, window, dropped, newest, union)
	if err != nil {
		return nil, err
	}
	annotateOptional(res, rules, window)
	annotateRanges(res, rules, window, checked)
	return res, nil
}

func parseTags(in []string) ([]parsedTag, string, []Stop) {
	if len(in) == 0 {
		return nil, "", []Stop{stop(StopBadInput, "", "no tags given")}
	}
	var out []parsedTag
	seen := map[string]bool{}
	lines := map[[2]int]string{}
	var stops []Stop
	for _, t := range in {
		m := tagRE.FindStringSubmatch(t)
		if m == nil {
			stops = append(stops, stop(StopTagGrammar, t, "tag is not <prefix>X.Y.Z"))
			continue
		}
		if seen[t] {
			stops = append(stops, stop(StopTagGrammar, t, "tag listed twice"))
			continue
		}
		seen[t] = true
		maj, _ := strconv.Atoi(m[2])
		min, _ := strconv.Atoi(m[3])
		if other, ok := lines[[2]int{maj, min}]; ok {
			stops = append(stops, stop(StopTagLineDuplicate, t, "same line as "+other+"; pin one final tag per line"))
			continue
		}
		lines[[2]int{maj, min}] = t
		out = append(out, parsedTag{Tag: t, Prefix: m[1], Major: maj, Minor: min})
	}
	if len(stops) > 0 {
		return nil, "", sortStops(stops)
	}
	prefix := out[0].Prefix
	for _, p := range out {
		if p.Prefix != prefix {
			return nil, "", []Stop{stop(StopTagPrefixMixed, p.Tag, "tags use prefixes "+strconv.Quote(prefix)+" and "+strconv.Quote(p.Prefix))}
		}
	}
	if !crdversions.ValidTagPrefix(prefix) {
		return nil, "", []Stop{stop(StopTagPrefixUnsupported, prefix, "")}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Major != out[j].Major {
			return out[i].Major < out[j].Major
		}
		return out[i].Minor < out[j].Minor
	})
	return out, prefix, nil
}

// inclusion is one file the target reads.
type inclusion struct {
	Path     string
	Rule     string
	CRDs     []crd
	Reach    string // best reaching link, for symbolic-link inclusions
	Depth    int
	LinkKind bool
}

// tagResult is the classification of one tag.
type tagResult struct {
	tag, commit string
	included    map[string]*inclusion
	decisions   []Decision
	stops       []Stop
	usedExcl    map[string]bool
	usedSurf    map[string]bool
	usedExclCls map[string]string
	usedIP      map[string]bool
	optStatus   map[string]string // optional entry -> read | verified-absent
	optAbsent   map[string]bool   // optional entries verified absent at this tag
	usedPF      map[string]bool
	countPF     map[string]int
	ranged      []RangedFact      // ranged entries selected at this tag
	logical     map[string]string // included path -> role key, ranged entries only
	copies      []NonInstallCopy
	filtered    []FilteredCopy
}

// pathFilterFor returns the pathFilter entry that matches the file.
func pathFilterFor(rules *Rules, p string) *PathFilterRule {
	for k := range rules.PathFilter {
		if globMatch(rules.PathFilter[k].Glob, p) {
			return &rules.PathFilter[k]
		}
	}
	return nil
}

// installPathFor returns the installPaths entry that names the file.
func installPathFor(rules *Rules, p string, rg *rangeCtx) *InstallPathRule {
	for k := range rules.InstallPaths {
		e := &rules.InstallPaths[k]
		if !rg.active(e) {
			continue
		}
		if e.Path == p || (strings.HasSuffix(e.Path, "/") && strings.HasPrefix(p, e.Path)) {
			return e
		}
	}
	return nil
}

func exclusionFor(rules *Rules, p string) *ExclusionRule {
	for k := range rules.Exclusions {
		e := &rules.Exclusions[k]
		if (e.Class == ClassExactFile && p == e.Path) || (e.Class == ClassFixtureDir && strings.HasPrefix(p, e.Path)) {
			return e
		}
	}
	return nil
}

func classify(tag, commit string, fs []*finding, rules *Rules, slug string, index customresources.Index, rg *rangeCtx) *tagResult {
	r := &tagResult{tag: tag, commit: commit, included: map[string]*inclusion{}, usedExcl: map[string]bool{}, usedSurf: map[string]bool{}, usedIP: map[string]bool{}, usedPF: map[string]bool{}, countPF: map[string]int{}}
	surface := map[string]bool{}
	for _, s := range rules.InstallSurface {
		surface[s.Path] = true
	}
	stopAt := func(code, subject, detail string) { r.stops = append(r.stops, stop(code, subject, detail)) }
	var rest []*finding
	var filteredFiles []*finding
	var filteredBy []*PathFilterRule

	// Phase 1: the files the target reads.
	for _, f := range fs {
		var rule string
		var reach string
		depth := 0
		via := ""
		switch {
		case len(rules.InstallPaths) > 0:
			// Positive source list: only the declared paths are read.
			if ip := installPathFor(rules, f.Path, rg); ip != nil {
				r.usedIP[ip.Path] = true
				if pf := pathFilterFor(rules, f.Path); pf != nil {
					// A filter never hides an unreadable file.
					r.usedPF[pf.Glob] = true
					r.countPF[pf.Glob]++
					if f.Unreadable != "" {
						stopAt(StopUnreadableShape, f.Path, f.Unreadable)
					} else {
						filteredFiles = append(filteredFiles, f)
						filteredBy = append(filteredBy, pf)
					}
					continue
				}
				rule = RuleIncludeInstallPath
				via = "declared by installPaths entry " + ip.Path
			} else if exclusionFor(rules, f.Path) == nil {
				c := NonInstallCopy{Path: f.Path, Groups: groupSet(f.CRDs), Unreadable: f.Unreadable}
				r.copies = append(r.copies, c)
				d := "groups " + strings.Join(c.Groups, ",")
				if c.Unreadable != "" {
					d += "; unreadable: " + c.Unreadable
				}
				r.decisions = append(r.decisions, Decision{Rule: RuleNonInstallCopy, Subject: f.Path, Detail: d})
				continue
			}
		case !testLike(f.Path):
			rule = RuleIncludeInstallDir
		default:
			for _, l := range f.Reached {
				if testLike(l) {
					continue
				}
				d := strings.Count(l, "/")
				if reach == "" || d > depth || (d == depth && l < reach) {
					reach, depth = l, d
				}
			}
			switch {
			case reach != "":
				rule = RuleIncludeSymlinkResolved
			case surface[f.Path]:
				rule = RuleIncludePinnedSurface
				r.usedSurf[f.Path] = true
			}
		}
		if rule == "" {
			rest = append(rest, f)
			continue
		}
		if f.Unreadable != "" {
			stopAt(StopUnreadableShape, f.Path, f.Unreadable)
			continue
		}
		r.included[f.Path] = &inclusion{Path: f.Path, Rule: rule, CRDs: f.CRDs, Reach: reach, Depth: depth, LinkKind: rule == RuleIncludeSymlinkResolved}
		detail := via
		if reach != "" {
			detail = "reached by link " + reach
		}
		r.decisions = append(r.decisions, Decision{Rule: rule, Subject: f.Path, Detail: detail})
	}

	owned := map[string]bool{}
	ownedCRD := map[string]bool{}
	seenCRD := map[string]string{}
	var inc []*inclusion
	for _, i := range r.included {
		inc = append(inc, i)
	}
	sort.Slice(inc, func(i, j int) bool { return inc[i].Path < inc[j].Path })
	for _, i := range inc {
		for _, c := range i.CRDs {
			owned[c.Group] = true
			key := c.Group + "/" + c.Kind
			ownedCRD[key] = true
			if prev, dup := seenCRD[key]; dup {
				stopAt(StopDuplicateCRD, key, prev+" and "+i.Path+" define it; pin one source")
			}
			seenCRD[key] = i.Path
			if customresources.ReservedNamespace(c.Group) || customresources.KubernetesGroup(c.Group) {
				stopAt(StopReservedGroup, c.Group, i.Path)
			} else if o, a := index.Owner(c.Group); a != customresources.Unknown && o != slug {
				stopAt(StopGroupOwnedElsewhere, c.Group, "listed by "+o+" ("+i.Path+")")
			}
		}
	}
	// Fail closed: a filtered file is allowed only when every group it
	// defines is a reserved/Kubernetes group (the copy case) or has a known
	// OTHER owner in the index. A group of the target (read, or listed for
	// this slug) or of an unknown or ambiguous owner stops.
	for k, f := range filteredFiles {
		fc := FilteredCopy{Path: f.Path, Glob: filteredBy[k].Glob, Groups: groupSet(f.CRDs)}
		bad := false
		for _, c := range f.CRDs {
			key := c.Group + "/" + c.Kind
			if owned[c.Group] {
				stopAt(StopFilterHidesOwned, f.Path, "defines "+key+" of a group the target reads; filter "+fc.Glob)
				bad = true
				continue
			}
			if customresources.ReservedNamespace(c.Group) || customresources.KubernetesGroup(c.Group) {
				continue
			}
			o, a := index.OwnerOf(c.Group, c.Kind)
			switch {
			case a == customresources.Owned && o == slug:
				stopAt(StopFilterHidesOwned, f.Path, "defines "+key+", which the ownership index lists for "+slug+"; filter "+fc.Glob)
				bad = true
			case a == customresources.Owned:
				// A known other owner: a legitimate copy.
			default:
				stopAt(StopFilterHidesUnowned, f.Path, "defines "+key+", whose group has no single known owner in the index; filter "+fc.Glob)
				bad = true
			}
		}
		if bad {
			continue
		}
		r.filtered = append(r.filtered, fc)
		r.decisions = append(r.decisions, Decision{Rule: RuleFilteredCopy, Subject: f.Path, Detail: "groups " + strings.Join(fc.Groups, ",") + "; pathFilter " + fc.Glob})
	}
	for _, pf := range rules.PathFilter {
		if !filterApplies(rules, pf.Glob, rg) {
			continue
		}
		switch n := r.countPF[pf.Glob]; {
		case n == 0:
			stopAt(StopPathFilterNothing, pf.Glob, "no file under installPaths matches this filter")
		case n != pf.ExpectFiles:
			stopAt(StopPathFilterCount, pf.Glob, fmt.Sprintf("matches %d file(s) under installPaths, the entry pins expectFiles %d", n, pf.ExpectFiles))
		}
	}
	for k := range rules.InstallPaths {
		ip := rules.InstallPaths[k]
		if !rg.active(&rules.InstallPaths[k]) {
			continue
		}
		if !r.usedIP[ip.Path] {
			stopAt(StopInstallPathNothing, ip.Path, "no definition file under this entry")
		}
	}
	if len(inc) == 0 && len(r.stops) == 0 {
		stopAt(StopNoCRDSource, "", "")
	}

	// Phase 2: every other finding needs a pinned rule or a stop.
	for _, f := range rest {
		var matched *ExclusionRule
		for k := range rules.Exclusions {
			e := &rules.Exclusions[k]
			if (e.Class == ClassExactFile && f.Path == e.Path) || (e.Class == ClassFixtureDir && strings.HasPrefix(f.Path, e.Path)) {
				matched = e
				break
			}
		}
		if matched != nil {
			r.usedExcl[matched.Path] = true
			if matched.Class == ClassExactFile {
				if f.Unreadable != "" {
					stopAt(StopUnreadableShape, f.Path, f.Unreadable)
					continue
				}
				bad := false
				for _, c := range f.CRDs {
					if owned[c.Group] {
						stopAt(StopExclusionOwnedGroup, f.Path, "defines "+c.Group+"/"+c.Kind+" of an owned group")
						bad = true
						break
					}
				}
				if !bad {
					r.decisions = append(r.decisions, Decision{Rule: RuleExcludePinnedFile, Subject: f.Path, Detail: "groups " + groupList(f.CRDs)})
				}
				continue
			}
			// fixture directory
			if f.Unreadable != "" {
				r.decisions = append(r.decisions, Decision{Rule: RuleExcludePinnedFixtures, Subject: f.Path, Detail: "excluded-unread: " + f.Unreadable})
				continue
			}
			hidden := ""
			for _, c := range f.CRDs {
				if owned[c.Group] && !ownedCRD[c.Group+"/"+c.Kind] {
					hidden = c.Group + "/" + c.Kind
					break
				}
			}
			if hidden != "" {
				stopAt(StopFixtureHiddenOwnedCRD, f.Path, hidden+" is not read by the target")
				continue
			}
			r.decisions = append(r.decisions, Decision{Rule: RuleExcludePinnedFixtures, Subject: f.Path, Detail: "groups " + groupList(f.CRDs)})
			for _, c := range f.CRDs {
				if !owned[c.Group] {
					r.decisions = append(r.decisions, Decision{Rule: RuleFixtureDrop, Subject: c.Group, Detail: "group of fixture " + f.Path + " is not part of the table row"})
				}
			}
			continue
		}
		if f.Unreadable != "" {
			stopAt(StopUnreadableShape, f.Path, f.Unreadable)
			continue
		}
		// A foreign group in a file the extractor skips by default is a
		// third-party copy; anywhere else (documentation, fixtures) the
		// file needs a pinned rule, the generator will not guess.
		allForeign := defaultExcludedPath(f.Path)
		for _, c := range f.CRDs {
			o, a := index.Owner(c.Group)
			if owned[c.Group] || a == customresources.Unknown || o == slug {
				allForeign = false
				break
			}
		}
		if allForeign {
			r.decisions = append(r.decisions, Decision{Rule: RuleForeignCopy, Subject: f.Path, Detail: "groups " + groupList(f.CRDs) + " are listed by other projects"})
			continue
		}
		if hasDocsSegment(f.Path) {
			stopAt(StopDocsOnlyCRDSource, f.Path, "groups "+groupList(f.CRDs))
		} else if !defaultExcludedPath(f.Path) && foreignOnly(f.CRDs, slug, owned, index) {
			stopAt(StopForeignCopyUnpinned, f.Path, "groups "+groupList(f.CRDs)+" are listed by other projects but the file is not under a default-excluded directory")
		} else {
			stopAt(StopUnpinnedExclusion, f.Path, "groups "+groupList(f.CRDs))
		}
	}
	return r
}

func groupSet(cs []crd) []string {
	set := map[string]bool{}
	for _, c := range cs {
		set[c.Group] = true
	}
	g := []string{}
	for k := range set {
		g = append(g, k)
	}
	sort.Strings(g)
	return g
}

func groupList(cs []crd) string {
	set := map[string]bool{}
	for _, c := range cs {
		set[c.Group] = true
	}
	var g []string
	for k := range set {
		g = append(g, k)
	}
	sort.Strings(g)
	return strings.Join(g, ",")
}

// differs says why an older tag cannot share the window with the newest.
func differs(r, newest *tagResult) string {
	if len(r.stops) > 0 {
		return "stop"
	}
	// A verified-absent optional entry is not a difference; every other
	// missing or extra file is.
	rk, nk := r.keySet(), newest.keySet()
	for p := range nk {
		if !rk[p] && !r.optAbsent[p] {
			return "set"
		}
	}
	for p := range rk {
		if !nk[p] {
			return "set"
		}
	}
	return ""
}

func reasonFor(r, newest *tagResult, boundary bool) string {
	if len(r.stops) > 0 {
		cs := make([]string, 0, len(r.stops))
		for _, s := range sortStops(r.stops) {
			cs = append(cs, s.Code+":"+s.Subject)
		}
		return strings.Join(cs, ", ")
	}
	var miss, extra []string
	rk, nk := r.keySet(), newest.keySet()
	for p := range nk {
		if !rk[p] && !r.optAbsent[p] {
			miss = append(miss, displayKey(p))
		}
	}
	for p := range rk {
		if !nk[p] {
			extra = append(extra, displayKey(p))
		}
	}
	sort.Strings(miss)
	sort.Strings(extra)
	s := ""
	if len(miss) > 0 {
		s += "missing " + strings.Join(miss, ",")
	}
	if len(extra) > 0 {
		if s != "" {
			s += "; "
		}
		s += "extra " + strings.Join(extra, ",")
	}
	if s == "" {
		s = "older than a withheld tag"
	}
	if !boundary {
		s = "older than the first withheld tag"
	}
	return s
}

// orderPaths is the deterministic order of the target's paths: regular
// install files by path, then symbolic-link-resolved files by the depth of
// the best reaching link (deepest first), the link path, the file path.
func orderPaths(inc map[string]*inclusion) []*inclusion {
	var out []*inclusion
	for _, i := range inc {
		out = append(out, i)
	}
	sort.Slice(out, func(a, b int) bool {
		x, y := out[a], out[b]
		if x.LinkKind != y.LinkKind {
			return !x.LinkKind
		}
		if x.LinkKind {
			if x.Depth != y.Depth {
				return x.Depth > y.Depth
			}
			if x.Reach != y.Reach {
				return x.Reach < y.Reach
			}
		}
		return x.Path < y.Path
	})
	return out
}

// safeField returns s unchanged when it is valid UTF-8 without control
// characters, otherwise its ASCII-quoted form, so no value can inject a tab or
// newline into a tab/newline-separated digest line.
func safeField(s string) string {
	if cleanText(s) {
		return s
	}
	return strconv.QuoteToASCII(s)
}

func digestFacts(window []*tagResult) string {
	h := sha256.New()
	for _, r := range window {
		var lines []string
		for _, i := range r.included {
			for _, c := range i.CRDs {
				lines = append(lines, fmt.Sprintf("%s\t%s\t%s\t%s\t%s", safeField(r.tag), safeField(i.Path), safeField(c.Group), safeField(c.Kind), safeField(strings.Join(c.Versions, ","))))
			}
		}
		// Non-install copies are facts of the run: a changed list must change
		// the digest so --compare-report flags it. Such lines exist only when
		// installPaths is used, so every other digest is unchanged.
		for _, c := range r.copies {
			lines = append(lines, fmt.Sprintf("%s\tnon-install-copy\t%s\t%s\t%s", safeField(r.tag), safeField(c.Path), safeField(strings.Join(c.Groups, ",")), safeField(c.Unreadable)))
		}
		// Filtered copies are facts of the run too; lines exist only with
		// pathFilter, so digests without it are unchanged.
		for _, c := range r.filtered {
			lines = append(lines, fmt.Sprintf("%s\tfiltered-copy\t%s\t%s", safeField(r.tag), safeField(c.Path), safeField(strings.Join(c.Groups, ","))))
		}
		sort.Strings(lines)
		for _, l := range lines {
			h.Write([]byte(l + "\n"))
		}
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil))
}

func blobURL(ownerRepo, commit, p string) string {
	return "https://github.com/" + ownerRepo + "/blob/" + commit + "/" + path.Clean(p)
}

// defaultExcludedPath mirrors the extractor's rule for a file under a
// default-excluded directory: some directory segment of the path is one of
// crdversions.DefaultExcludedSegments (the file name itself does not count).
func defaultExcludedPath(p string) bool {
	segs := strings.Split(p, "/")
	for _, s := range segs[:len(segs)-1] {
		for _, d := range crdversions.DefaultExcludedSegments {
			if s == d {
				return true
			}
		}
	}
	return false
}

// foreignOnly reports that every group of the file is listed by another
// project and none is owned by the target.
func foreignOnly(cs []crd, slug string, owned map[string]bool, index customresources.Index) bool {
	if len(cs) == 0 {
		return false
	}
	for _, c := range cs {
		o, a := index.Owner(c.Group)
		if owned[c.Group] || a == customresources.Unknown || o == slug {
			return false
		}
	}
	return true
}
