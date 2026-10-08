// SPDX-License-Identifier: AGPL-3.0-only

package coveragereport

import (
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/prufyx/prufyx/cli/internal/constraintengine"
	"github.com/prufyx/prufyx/cli/internal/lineattest"
)

// Schema identifies the report document.
const Schema = "prufyx.io/coverage-report/v1"

// DefaultWindow is the number of lines in a project's window. N lines make
// N-1 consecutive pairs.
const DefaultWindow = 6

// ExpiryHorizon is how far ahead an entry counts as expiring.
const ExpiryHorizon = 14 * 24 * time.Hour

// Pair statuses.
const (
	StatusA = "A" // attested: a current line attestation, every listed rule line-wide
	StatusB = "B" // bounded: a line-wide range, or a crossing rule, decides the whole pair
	StatusS = "S" // spot: only an exact-pair rule
	StatusG = "G" // gap: nothing
)

// Input is everything a report depends on.
type Input struct {
	Pack   []byte
	Lines  []byte
	Now    time.Time
	Window int
}

// Pair is one consecutive pair of lines and its status.
type Pair struct {
	From   string `json:"from"`
	To     string `json:"to"`
	Status string `json:"status"`
	// Families names the fact families of the attestations (A) or rules
	// (B) that decide the pair.
	Families []string `json:"families,omitempty"`
}

// Project is one project's row.
type Project struct {
	Project  string   `json:"project"`
	Priority bool     `json:"priority"`
	Window   []string `json:"window"`
	Pairs    []Pair   `json:"pairs"`
	A        int      `json:"a"`
	B        int      `json:"b"`
	S        int      `json:"s"`
	G        int      `json:"g"`
	// VC is (A+B)/pairs and VCA is A/pairs; both are 0 without pairs.
	VC  float64 `json:"vc"`
	VCA float64 `json:"vcA"`
	// Covered is C1: at least one valid rule or attestation.
	Covered bool `json:"covered"`
	// ValidRules is the number of valid rules of the project.
	ValidRules int `json:"validRules"`
	// RulesInWindow counts valid rules whose anchor versions both lie in
	// the window.
	RulesInWindow int `json:"rulesInWindow"`
	// Expiring counts valid rules and attestations whose validUntil falls
	// within 14 days.
	Expiring int `json:"expiring14d"`
}

// Totals aggregates a set of projects.
type Totals struct {
	Projects int `json:"projects"`
	Pairs    int `json:"pairs"`
	A        int `json:"a"`
	B        int `json:"b"`
	S        int `json:"s"`
	G        int `json:"g"`
	// C1 counts covered projects among those with lines.
	C1 int `json:"c1"`
	// C3 counts projects with VC >= 0.6, C5 projects with VC_A = 1.
	C3 int `json:"c3"`
	C5 int `json:"c5"`
	// VCPairs is (A+B)/pairs over all pairs; VCMean is the mean of the
	// per-project VC over projects with at least one pair.
	VCPairs float64 `json:"vcPairs"`
	VCMean  float64 `json:"vcMean"`
	// SPairs is S/pairs, shown but not part of VC.
	SPairs float64 `json:"sPairs"`
	// RulesInWindow counts valid rules touching a window.
	RulesInWindow int `json:"rulesInWindow"`
}

// Family counts the pairs a fact family decides.
type Family struct {
	Family string `json:"family"`
	A      int    `json:"a"`
	B      int    `json:"b"`
}

// Report is the whole result. It carries no wall-clock time: the same
// inputs give the same bytes.
type Report struct {
	Schema string `json:"schema"`
	Now    string `json:"now"`
	Window int    `json:"window"`
	Pack   struct {
		Revision string `json:"revision"`
		Schema   string `json:"schema"`
		Digest   string `json:"digest"`
	} `json:"pack"`
	Lines struct {
		CapturedOn string `json:"capturedOn,omitempty"`
		Digest     string `json:"digest"`
	} `json:"lines"`
	// PackProjects is the number of projects with a valid rule or
	// attestation in the pack, whether or not lines are known for them.
	PackProjects int       `json:"packProjectsCovered"`
	Fleet        Totals    `json:"fleet"`
	Priority     Totals    `json:"priorityProjects"`
	Families     []Family  `json:"families"`
	Projects     []Project `json:"projects"`
	// WithoutLines lists projects with a valid rule or attestation but no
	// lines in the snapshot. Their pairs are unknown, never counted as
	// covered.
	WithoutLines []string `json:"projectsWithoutLines"`
	// ExpiringProjects lists projects with an entry expiring within 14 days.
	ExpiringProjects []string `json:"expiringProjects"`
}

type packEntry struct {
	Project string          `json:"project"`
	Rule    json.RawMessage `json:"rule"`
}

type packDoc struct {
	Schema   string      `json:"schema"`
	Revision string      `json:"revision"`
	Entries  []packEntry `json:"entries"`
}

type ruleRec struct {
	id        string
	project   string
	tr        constraintengine.RuleTransition
	families  []string
	valid     bool
	expiring  bool
	validTill time.Time
}

type evidenceShape struct {
	State      string `json:"state"`
	ReviewedAt string `json:"reviewedAt"`
	ValidUntil string `json:"validUntil"`
}

// valid reports whether the evidence is active and current at now.
func validAt(e evidenceShape, now time.Time) (ok bool, until time.Time) {
	if e.State != "active" {
		return false, time.Time{}
	}
	reviewed, err1 := constraintengine.ParseUTC(e.ReviewedAt)
	until, err2 := constraintengine.ParseUTC(e.ValidUntil)
	if err1 != nil || err2 != nil {
		return false, time.Time{}
	}
	return !now.Before(reviewed) && now.Before(until), until
}

// lineMapped reports whether line arithmetic on engine versions is the
// project's line scheme. Projects whose release lines are not the engine's
// major.minor of the version are measured on exact pairs only: their ranges,
// crossings and attestations are never read as line-wide.
func lineMapped(project string) bool { return project != "cloud-custodian" }

// versionLine maps a rule version to its line.
func versionLine(project, version string) (string, bool) {
	if project == "cloud-custodian" {
		parts := strings.Split(version, ".")
		if len(parts) == 3 && parts[0] == "0" && parts[1] == "9" {
			line := "9." + parts[2]
			return line, lineattest.ValidLine(line)
		}
		return "", false
	}
	return lineattest.LineOf(version)
}

// nextLineStart returns M.(m+1).0 of a valid line.
func nextLineStart(line string) (string, bool) {
	major, minor, ok := strings.Cut(line, ".")
	if !ok {
		return "", false
	}
	m, err := strconv.ParseUint(minor, 10, 32)
	if err != nil {
		return "", false
	}
	return major + "." + strconv.FormatUint(m+1, 10) + ".0", true
}

// previousLine returns M.(m-1) when line is M.m with m > 0.
func previousLine(line string) (string, bool) {
	major, minor, ok := strings.Cut(line, ".")
	if !ok {
		return "", false
	}
	m, err := strconv.ParseUint(minor, 10, 32)
	if err != nil || m == 0 {
		return "", false
	}
	return major + "." + strconv.FormatUint(m-1, 10), true
}

func ratio(n, d int) float64 {
	if d == 0 {
		return 0
	}
	return math.Round(float64(n)/float64(d)*10000) / 10000
}

// Compute builds the report. It uses the engine's own matching helpers
// (VersionBound.CoversLine, RuleTransition.CrossingBounds, the line
// attestation families) and never evaluates a rule.
func Compute(in Input) (Report, error) {
	window := in.Window
	if window == 0 {
		window = DefaultWindow
	}
	if window < 2 || window > 64 {
		return Report{}, fmt.Errorf("%w: window must be between 2 and 64", ErrInvalid)
	}
	if in.Now.IsZero() {
		return Report{}, fmt.Errorf("%w: now is required", ErrInvalid)
	}
	now := in.Now.UTC()
	linesFile, err := ParseLines(in.Lines)
	if err != nil {
		return Report{}, err
	}
	var pack packDoc
	if err := json.Unmarshal(in.Pack, &pack); err != nil {
		return Report{}, fmt.Errorf("%w: pack: %v", ErrInvalid, err)
	}
	section, present, err := lineattest.PackSection(in.Pack)
	if err != nil {
		return Report{}, fmt.Errorf("%w: pack: %v", ErrInvalid, err)
	}
	var atts []lineattest.LineAttestation
	if present {
		if atts, err = lineattest.Parse(section); err != nil {
			return Report{}, fmt.Errorf("%w: pack attestations: %v", ErrInvalid, err)
		}
	}

	byID := map[string]*ruleRec{}
	byProject := map[string][]*ruleRec{}
	components := map[string]map[string]bool{} // project -> components of its rules
	for _, entry := range pack.Entries {
		var shape struct {
			Evidence evidenceShape `json:"evidence"`
		}
		if json.Unmarshal(entry.Rule, &shape) != nil || entry.Project == "" {
			return Report{}, fmt.Errorf("%w: pack: malformed entry", ErrInvalid)
		}
		scope, err := lineattest.ScopeOf(entry.Rule)
		if err != nil {
			return Report{}, fmt.Errorf("%w: pack: %v", ErrInvalid, err)
		}
		if _, dup := byID[scope.ID]; dup {
			return Report{}, fmt.Errorf("%w: pack: duplicate rule id", ErrInvalid)
		}
		neutral, err := constraintengine.RawRuleVerdictNeutral(entry.Rule)
		if err != nil {
			return Report{}, fmt.Errorf("%w: pack: %v", ErrInvalid, err)
		}
		ok, until := validAt(shape.Evidence, now)
		rec := &ruleRec{id: scope.ID, project: entry.Project, tr: scope.Transition, families: scope.Families, valid: ok && !neutral, validTill: until}
		rec.expiring = rec.valid && until.Sub(now) <= ExpiryHorizon
		byID[rec.id] = rec
		byProject[entry.Project] = append(byProject[entry.Project], rec)
		if components[entry.Project] == nil {
			components[entry.Project] = map[string]bool{}
		}
		components[entry.Project][scope.Component] = true
	}

	// Attestations belong to the project that owns their component.
	componentProject := map[string]string{}
	for slug, p := range linesFile.Projects {
		if p.Component != "" {
			componentProject[p.Component] = slug
		}
	}
	for project, set := range components {
		for c := range set {
			componentProject[c] = project
		}
	}
	attsByProject := map[string][]lineattest.LineAttestation{}
	expiringAtt := map[string]int{}
	validAtt := map[string]int{}
	for _, a := range atts {
		project, ok := componentProject[a.Component]
		if !ok {
			continue
		}
		if a.Freshness(now) != lineattest.FreshnessCurrent {
			continue
		}
		attsByProject[project] = append(attsByProject[project], a)
		validAtt[project]++
		if until, err := constraintengine.ParseUTC(a.Evidence.ValidUntil); err == nil && until.Sub(now) <= ExpiryHorizon {
			expiringAtt[project]++
		}
	}

	var report Report
	report.Schema = Schema
	report.Now = now.Format(time.RFC3339)
	report.Window = window
	report.Pack.Revision = pack.Revision
	report.Pack.Schema = pack.Schema
	report.Pack.Digest = digestOf(in.Pack)
	report.Lines.CapturedOn = linesFile.CapturedOn
	report.Lines.Digest = digestOf(in.Lines)

	covered := map[string]bool{}
	for project, recs := range byProject {
		for _, r := range recs {
			if r.valid {
				covered[project] = true
			}
		}
	}
	for project, n := range validAtt {
		if n > 0 {
			covered[project] = true
		}
	}
	report.PackProjects = len(covered)

	slugs := make([]string, 0, len(linesFile.Projects))
	for slug := range linesFile.Projects {
		slugs = append(slugs, slug)
	}
	sort.Strings(slugs)

	familyA := map[string]int{}
	familyB := map[string]int{}
	for _, slug := range slugs {
		pl := linesFile.Projects[slug]
		lines := pl.Lines
		if len(lines) > window {
			lines = lines[len(lines)-window:]
		}
		row := Project{Project: slug, Priority: pl.Priority, Window: append([]string{}, lines...), Pairs: []Pair{}, Covered: covered[slug]}
		inWindow := map[string]bool{}
		for _, l := range lines {
			inWindow[l] = true
		}
		for _, r := range byProject[slug] {
			if !r.valid {
				continue
			}
			row.ValidRules++
			if r.expiring {
				row.Expiring++
			}
			from, ok1 := versionLine(slug, r.tr.From)
			to, ok2 := versionLine(slug, r.tr.To)
			if ok1 && ok2 && inWindow[from] && inWindow[to] {
				row.RulesInWindow++
			}
		}
		row.Expiring += expiringAtt[slug]
		for i := 0; i+1 < len(lines); i++ {
			pair := classify(slug, lines[i], lines[i+1], byProject[slug], attsByProject[slug], byID)
			row.Pairs = append(row.Pairs, pair)
			switch pair.Status {
			case StatusA:
				row.A++
				for _, f := range pair.Families {
					familyA[f]++
				}
			case StatusB:
				row.B++
				for _, f := range pair.Families {
					familyB[f]++
				}
			case StatusS:
				row.S++
			default:
				row.G++
			}
		}
		row.VC = ratio(row.A+row.B, len(row.Pairs))
		row.VCA = ratio(row.A, len(row.Pairs))
		report.Projects = append(report.Projects, row)
	}
	for _, p := range report.Projects {
		add := func(t *Totals) {
			t.Projects++
			t.Pairs += len(p.Pairs)
			t.A += p.A
			t.B += p.B
			t.S += p.S
			t.G += p.G
			t.RulesInWindow += p.RulesInWindow
			if p.Covered {
				t.C1++
			}
			if len(p.Pairs) > 0 {
				t.VCMean += p.VC // summed, divided below
				if p.VC >= 0.6 {
					t.C3++
				}
				if p.VCA == 1 {
					t.C5++
				}
			}
		}
		add(&report.Fleet)
		if p.Priority {
			add(&report.Priority)
		}
	}
	for _, t := range []*Totals{&report.Fleet, &report.Priority} {
		withPairs := 0
		for _, p := range report.Projects {
			if len(p.Pairs) > 0 && (t == &report.Fleet || p.Priority) {
				withPairs++
			}
		}
		if withPairs > 0 {
			t.VCMean = math.Round(t.VCMean/float64(withPairs)*10000) / 10000
		}
		t.VCPairs = ratio(t.A+t.B, t.Pairs)
		t.SPairs = ratio(t.S, t.Pairs)
	}

	names := map[string]bool{}
	for f := range familyA {
		names[f] = true
	}
	for f := range familyB {
		names[f] = true
	}
	report.Families = []Family{}
	for f := range names {
		report.Families = append(report.Families, Family{Family: f, A: familyA[f], B: familyB[f]})
	}
	sort.Slice(report.Families, func(i, j int) bool { return report.Families[i].Family < report.Families[j].Family })

	withLines := map[string]bool{}
	for _, slug := range slugs {
		withLines[slug] = true
	}
	report.WithoutLines = []string{}
	for project := range covered {
		if !withLines[project] {
			report.WithoutLines = append(report.WithoutLines, project)
		}
	}
	sort.Strings(report.WithoutLines)
	report.ExpiringProjects = []string{}
	for _, p := range report.Projects {
		if p.Expiring > 0 {
			report.ExpiringProjects = append(report.ExpiringProjects, p.Project)
		}
	}
	return report, nil
}

// classify decides one pair, strongest status first: A, B, S, G.
func classify(project, from, to string, rules []*ruleRec, atts []lineattest.LineAttestation, byID map[string]*ruleRec) Pair {
	pair := Pair{From: from, To: to, Status: StatusG}
	if lineMapped(project) {
		if fams := attestedFamilies(from, to, atts, byID); len(fams) > 0 {
			pair.Status, pair.Families = StatusA, fams
			return pair
		}
		if fams, ok := boundedFamilies(from, to, rules); ok {
			pair.Status, pair.Families = StatusB, fams
			return pair
		}
	}
	for _, r := range rules {
		if !r.valid {
			continue
		}
		rf, ok1 := versionLine(project, r.tr.From)
		rt, ok2 := versionLine(project, r.tr.To)
		if ok1 && ok2 && rf == from && rt == to {
			pair.Status = StatusS
			return pair
		}
	}
	return pair
}

// attestedFamilies returns the families with a current attestation for the
// target line whose hop is exactly from->to and whose listed rules are all
// valid and line-wide for that line.
func attestedFamilies(from, to string, atts []lineattest.LineAttestation, byID map[string]*ruleRec) []string {
	previous, ok := previousLine(to)
	if !ok || previous != from {
		return nil
	}
	set := map[string]bool{}
	for _, a := range atts {
		if a.Line != to || a.Completeness != lineattest.Completeness {
			continue
		}
		family, ok := lineattest.LookupFamily(a.FactFamily)
		if !ok {
			continue
		}
		wide := true
		for _, id := range a.RuleIDs {
			r := byID[id]
			if r == nil || !r.valid || !family.CoversLine(r.tr, to) {
				wide = false
				break
			}
		}
		if wide {
			set[a.FactFamily] = true
		}
	}
	return sortedKeys(set)
}

// boundedFamilies reports whether a valid rule decides the whole pair: its
// range covers the whole from line and the whole to line, or its crossing
// removal release lies inside the to line and its crossing region covers the
// whole from line. The returned families name the rules' fact families, or
// "other" for a rule outside every attestable family.
func boundedFamilies(from, to string, rules []*ruleRec) ([]string, bool) {
	toNext, ok := nextLineStart(to)
	if !ok {
		return nil, false
	}
	toBound := constraintengine.VersionBound{Gte: to + ".0", Lt: toNext}
	set := map[string]bool{}
	for _, r := range rules {
		if !r.valid {
			continue
		}
		hit := false
		if r.tr.Range != nil && r.tr.Range.From.CoversLine(from) && r.tr.Range.To.CoversLine(to) {
			hit = true
		}
		if cf, ct, ok := r.tr.CrossingBounds(); ok && cf.CoversLine(from) && toBound.Contains(ct.Gte) && constraintengine.VersionLess(ct.Gte, ct.Lt) {
			hit = true
		}
		if !hit {
			continue
		}
		if len(r.families) == 0 {
			set["other"] = true
		}
		for _, f := range r.families {
			set[f] = true
		}
	}
	if len(set) == 0 {
		return nil, false
	}
	return sortedKeys(set), true
}

func sortedKeys(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
