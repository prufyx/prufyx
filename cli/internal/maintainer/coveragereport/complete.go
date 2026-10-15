// SPDX-License-Identifier: AGPL-3.0-only

package coveragereport

import (
	"encoding/json"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/prufyx/prufyx/cli/internal/constraintengine"
	"github.com/prufyx/prufyx/cli/internal/lineattest"
)

// MaxAllLines bounds the lines of one project in the ALL window.
const MaxAllLines = 1024

// Reasons a project is not complete: a closed vocabulary, reported so that a
// refusal can be told from a gap.
const (
	whySnapshotUndated   = "snapshot-undated"
	whySnapshotStale     = "snapshot-stale"
	whySnapshotFuture    = "snapshot-future"
	whySnapshotTruncated = "snapshot-truncated"
	whySnapshotHole      = "snapshot-hole"
	whyNoFamily          = "no-registered-family"
	whyChartLines        = "chart-lines-unmapped"
	whyTooFewLines       = "too-few-lines"
	whyInvalidDecl       = "invalid-declaration"
	whyUndeclared        = "undeclared-pairs"
	whyCountMismatch     = "count-mismatch"
)

// Counts is how many of a window's lines and pairs the pack decides. A window
// of N lines has N-1 pairs; every pair is decided, declared unknown or
// undeclared.
type Counts struct {
	LinesTotal      int `json:"linesTotal"`
	Decided         int `json:"decided"`
	DeclaredUnknown int `json:"declaredUnknown"`
	Undeclared      int `json:"undeclared"`
}

// FamilyCounts are the counts of one family of one project.
type FamilyCounts struct {
	Family string `json:"family"`
	Counts
}

// Completion is a project's result of the complete predicate. It is present
// in the ALL window only.
type Completion struct {
	Counts
	// Complete is true only when every clause of the predicate holds; see
	// docs/coverage-report.md. It is a statement about the shipped pack and
	// the lines snapshot, never a compatibility claim.
	Complete            bool           `json:"complete"`
	InvalidDeclarations int            `json:"invalidDeclarations"`
	Reasons             []string       `json:"incompleteReasons,omitempty"`
	FamilyCounts        []FamilyCounts `json:"familyCounts"`
}

// SnapshotInfo describes the lines snapshot complete is relative to.
type SnapshotInfo struct {
	Digest     string `json:"digest"`
	CapturedOn string `json:"capturedOn,omitempty"`
	AgeDays    *int   `json:"ageDays,omitempty"`
}

// DeclaredInfo describes the declared-unknown file that was read.
type DeclaredInfo struct {
	Digest  string `json:"digest"`
	Records int    `json:"records"`
}

const (
	stateUndeclared = iota
	stateDeclared
	stateDecided
)

var (
	commit40RE = regexp.MustCompile(`^[0-9a-f]{40}$`)
)

type completer struct {
	now             time.Time
	atts            []lineattest.LineAttestation
	byID            map[string]*ruleRec
	decls           map[declKey]Declaration
	declsByProject  map[string][]Declaration
	snapshotReasons []string
}

func newCompleter(now time.Time, atts []lineattest.LineAttestation, byID map[string]*ruleRec, decls []Declaration, capturedOn string) *completer {
	c := &completer{now: now, atts: atts, byID: byID, decls: map[declKey]Declaration{}, declsByProject: map[string][]Declaration{}}
	for _, d := range decls {
		c.decls[d.key()] = d
		c.declsByProject[d.Project] = append(c.declsByProject[d.Project], d)
	}
	switch {
	case capturedOn == "":
		c.snapshotReasons = append(c.snapshotReasons, whySnapshotUndated)
	default:
		captured, err := time.Parse("2006-01-02", capturedOn)
		switch {
		case err != nil:
			c.snapshotReasons = append(c.snapshotReasons, whySnapshotUndated)
		case captured.After(now):
			c.snapshotReasons = append(c.snapshotReasons, whySnapshotFuture)
		case now.Sub(captured) > ExpiryHorizon:
			c.snapshotReasons = append(c.snapshotReasons, whySnapshotStale)
		}
	}
	return c
}

// snapshotInfo reports the snapshot's date and age at now.
func snapshotInfo(digest, capturedOn string, now time.Time) *SnapshotInfo {
	info := &SnapshotInfo{Digest: digest, CapturedOn: capturedOn}
	if captured, err := time.Parse("2006-01-02", capturedOn); err == nil {
		age := int(now.Sub(captured) / (24 * time.Hour))
		info.AgeDays = &age
	}
	return info
}

func lineParts(line string) (int, int, bool) {
	major, minor, ok := strings.Cut(line, ".")
	if !ok {
		return 0, 0, false
	}
	a, err1 := strconv.Atoi(major)
	b, err2 := strconv.Atoi(minor)
	return a, b, err1 == nil && err2 == nil
}

func lineAtLeast(line string, min [2]int) bool {
	a, b, ok := lineParts(line)
	return ok && (a > min[0] || (a == min[0] && b >= min[1]))
}

// windowStart is the lines of a project in the ALL window: from the lowest
// minFrom of its project-line families, or every line when it has none.
func allWindow(lines []string, regs []registration) []string {
	var min *[2]int
	for _, r := range regs {
		if r.space != projectLines {
			continue
		}
		m := r.minFrom
		if min == nil || m[0] < min[0] || (m[0] == min[0] && m[1] < min[1]) {
			min = &m
		}
	}
	if min == nil {
		return lines
	}
	for i, l := range lines {
		if lineAtLeast(l, *min) {
			return lines[i:]
		}
	}
	return nil
}

// evaluate applies the complete predicate to one project. pl are the
// project's snapshot lines and window its ALL window.
func (c *completer) evaluate(slug string, pl ProjectLines, window []string) *Completion {
	regs := registrations(slug)
	why := map[string]bool{}
	for _, r := range c.snapshotReasons {
		why[r] = true
	}
	if len(regs) == 0 {
		why[whyNoFamily] = true
	}
	if len(window) < 2 {
		why[whyTooFewLines] = true
	}
	// (a): the snapshot reaches back to every minFrom and holds no hole.
	for _, r := range regs {
		if r.space == chartLines {
			why[whyChartLines] = true
			continue
		}
		if len(pl.Lines) == 0 || lineAtLeast(pl.Lines[0], [2]int{r.minFrom[0], r.minFrom[1] + 1}) {
			why[whySnapshotTruncated] = true
		}
	}
	for i := 0; i+1 < len(window); i++ {
		a1, a2, ok1 := lineParts(window[i])
		b1, b2, ok2 := lineParts(window[i+1])
		if !ok1 || !ok2 || (a1 == b1 && b2 != a2+1) {
			why[whySnapshotHole] = true
		}
	}

	out := &Completion{FamilyCounts: []FamilyCounts{}}
	out.LinesTotal = len(window)
	for _, r := range regs {
		fw := window
		if r.space == projectLines {
			fw = nil
			for _, l := range window {
				if lineAtLeast(l, r.minFrom) {
					fw = append(fw, l)
				}
			}
		}
		fc := FamilyCounts{Family: r.family}
		fc.LinesTotal = len(fw)
		for i := 0; i+1 < len(fw); i++ {
			switch c.pairState(slug, r, pl, fw[i], fw[i+1]) {
			case stateDecided:
				fc.Decided++
			case stateDeclared:
				fc.DeclaredUnknown++
			}
		}
		fc.Undeclared = max(fc.LinesTotal-1-fc.Decided-fc.DeclaredUnknown, 0)
		if fc.LinesTotal < 2 || fc.Decided+fc.DeclaredUnknown != fc.LinesTotal-1 || fc.Undeclared != 0 {
			why[whyCountMismatch] = true
		}
		out.FamilyCounts = append(out.FamilyCounts, fc)
	}
	// A project pair is decided only when every registered family decides it,
	// and declared unknown only when each family that does not decide it
	// declares it.
	for i := 0; i+1 < len(window); i++ {
		state := stateDecided
		for _, r := range regs {
			if s := c.pairState(slug, r, pl, window[i], window[i+1]); s < state {
				state = s
			}
		}
		if len(regs) == 0 {
			state = stateUndeclared
		}
		switch state {
		case stateDecided:
			out.Decided++
		case stateDeclared:
			out.DeclaredUnknown++
		}
	}
	if len(window) > 0 {
		out.Undeclared = len(window) - 1 - out.Decided - out.DeclaredUnknown
	}
	if out.Undeclared != 0 {
		why[whyUndeclared] = true
	}
	if out.LinesTotal < 2 || out.Decided+out.DeclaredUnknown != out.LinesTotal-1 {
		why[whyCountMismatch] = true
	}
	out.InvalidDeclarations = c.invalidDeclarations(slug, pl, regs)
	if out.InvalidDeclarations > 0 {
		why[whyInvalidDecl] = true
	}
	for r := range why {
		out.Reasons = append(out.Reasons, r)
	}
	sort.Strings(out.Reasons)
	out.Complete = len(out.Reasons) == 0
	return out
}

// invalidDeclarations counts the project's declarations that name a family it
// is not registered in (or a chart-line family), or a pair that is not two
// consecutive lines of the snapshot. Such a declaration is ignored and makes
// the project incomplete.
func (c *completer) invalidDeclarations(slug string, pl ProjectLines, regs []registration) int {
	n := 0
	for _, d := range c.declsByProject[slug] {
		ok := false
		for _, r := range regs {
			if r.family == d.Family && r.space == projectLines {
				ok = true
			}
		}
		if ok {
			ok = false
			for i := 0; i+1 < len(pl.Lines); i++ {
				if pl.Lines[i] == d.From && pl.Lines[i+1] == d.To {
					ok = true
				}
			}
		}
		if !ok {
			n++
		}
	}
	return n
}

// pairState decides one pair of one family: decided by a qualifying
// attestation, declared unknown, or undeclared. A declaration never replaces
// an attestation; it only fills a pair that has none.
func (c *completer) pairState(slug string, r registration, pl ProjectLines, from, to string) int {
	if r.space != projectLines {
		return stateUndeclared
	}
	if c.attested(r, pl, from, to) {
		return stateDecided
	}
	if d, ok := c.decls[declKey{slug, r.family, from}]; ok && d.To == to && d.currentAt(c.now) {
		return stateDeclared
	}
	return stateUndeclared
}

// attested reports whether a current attestation decides the pair, by every
// clause: the hop, the releases read, cited sources, the shipped extractor
// and the expiry horizon, for the attestation and for each rule it lists.
func (c *completer) attested(r registration, pl ProjectLines, from, to string) bool {
	family, ok := lineattest.LookupFamily(r.family)
	if !ok {
		return false
	}
	if previous, ok := previousLine(to); !ok || previous != from {
		return false
	}
	for _, a := range c.atts {
		if a.Component != r.component || a.FactFamily != r.family || a.Line != to || a.Completeness != lineattest.Completeness {
			continue
		}
		if a.Freshness(c.now) != lineattest.FreshnessCurrent || !c.evidenceOK(r, a.Evidence.Basis, a.Evidence.Extractor, a.Evidence.Sources, a.Evidence.ValidUntil) {
			return false
		}
		if family.ReleaseScoped() && !releasesMatch(a.Releases, pl.Releases[from], pl.Releases[to]) {
			return false
		}
		for _, id := range a.RuleIDs {
			rule := c.byID[id]
			if rule == nil || !rule.valid || !family.CoversLine(rule.tr, to) {
				return false
			}
			var shape struct {
				Evidence struct {
					Basis      string                            `json:"basis"`
					Extractor  *constraintengine.Extractor       `json:"extractor"`
					ValidUntil string                            `json:"validUntil"`
					Sources    []constraintengine.SourceEvidence `json:"sources"`
				} `json:"evidence"`
			}
			if json.Unmarshal(rule.raw, &shape) != nil {
				return false
			}
			ev := shape.Evidence
			if !c.evidenceOK(r, ev.Basis, ev.Extractor, ev.Sources, ev.ValidUntil) {
				return false
			}
		}
		return true
	}
	return false
}

// evidenceOK checks clauses (c) and (d) for one record: mechanical basis from
// the shipped extractor (id, version and code digest), every source pinned to
// a 40-hex commit and a path, and validUntil strictly beyond the expiry
// horizon.
func (c *completer) evidenceOK(r registration, basis string, ex *constraintengine.Extractor, sources []constraintengine.SourceEvidence, validUntil string) bool {
	if basis != constraintengine.BasisMechanical || ex == nil {
		return false
	}
	shipped, err := r.digest()
	if err != nil || shipped == "" || ex.ID != r.extractorID || ex.Version != r.version || ex.CodeDigest != shipped {
		return false
	}
	if !sourcesCited(sources) {
		return false
	}
	until, err := constraintengine.ParseUTC(validUntil)
	return err == nil && until.Sub(c.now) > ExpiryHorizon
}

// sourcesCited reports whether there is at least one source and each pins a
// 40-hex commit and names a path inside it.
func sourcesCited(sources []constraintengine.SourceEvidence) bool {
	if len(sources) == 0 {
		return false
	}
	for _, s := range sources {
		if !commit40RE.MatchString(s.Revision) {
			return false
		}
		_, path, ok := strings.Cut(s.URL, "/"+s.Revision+"/")
		if !ok || path == "" {
			return false
		}
	}
	return true
}

// releasesMatch reports whether the releases an attestation names on each
// side are exactly the snapshot's final releases of those lines, each pinned
// to a 40-hex commit. The attestation's own list is never trusted.
func releasesMatch(att *lineattest.Releases, from, to []string) bool {
	if att == nil || len(from) == 0 || len(to) == 0 {
		return false
	}
	same := func(have []lineattest.Release, want []string) bool {
		if len(have) != len(want) {
			return false
		}
		set := map[string]bool{}
		for _, v := range want {
			set[v] = true
		}
		for _, rel := range have {
			if !set[rel.Version] || !commit40RE.MatchString(rel.Commit) {
				return false
			}
			delete(set, rel.Version)
		}
		return len(set) == 0
	}
	return same(att.From, from) && same(att.To, to)
}
