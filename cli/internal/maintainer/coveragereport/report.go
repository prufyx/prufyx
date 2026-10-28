// SPDX-License-Identifier: AGPL-3.0-only

package coveragereport

import (
	"encoding/json"
	"fmt"
	"math"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/prufyx/prufyx/cli/internal/constraintengine"
	"github.com/prufyx/prufyx/cli/internal/customresources"
	"github.com/prufyx/prufyx/cli/internal/lineattest"
)

// CatalogCommunity marks the row of a project of the community catalog: a
// project outside the embedded CNCF landscape catalog (no CNCF status is
// asserted). Its pairs are counted apart: the fleet and priority totals, the
// families and the pack-project count are the CNCF catalog's.
const CatalogCommunity = "community"

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
	// All selects the ALL window: every line from the project's minFrom. It
	// adds the completeness members and ignores Window, which must be 0.
	All bool
	// Declared is the declared-unknown file; nil means the embedded one.
	Declared []byte
	// CRDVersionProjects is copied into the report when set (see
	// CRDProjectCount); zero leaves the member out.
	CRDVersionProjects int
	// CRDTargetComponents maps the projects with a reviewed target to the
	// component of the target (see CRDProjectComponents); when set, the
	// report counts those that also have a published rule or line
	// attestation of the CRD version family.
	CRDTargetComponents map[string]string
	// CommunityPack is the community rule pack, or nil. Only the count of
	// published CRD projects reads it: a valid crd.custom_resource_versions
	// rule or a current line attestation in it counts a target project
	// once, together with the main pack.
	CommunityPack []byte
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
	Project string `json:"project"`
	// Catalog is "community" for a community-catalog project and absent for
	// a CNCF one.
	Catalog  string   `json:"catalog,omitempty"`
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
	// Completion is present in the ALL window only.
	*Completion
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
	// Counts sum the family's counts over the CNCF projects; ALL window only.
	*Counts
}

// Report is the whole result. It carries no wall-clock time: the same
// inputs give the same bytes.
type Report struct {
	Schema string `json:"schema"`
	Now    string `json:"now"`
	Window int    `json:"window,omitempty"`
	// WindowAll marks the ALL window (every line from minFrom); it replaces
	// Window.
	WindowAll bool `json:"windowAll,omitempty"`
	Pack      struct {
		Revision string `json:"revision"`
		Schema   string `json:"schema"`
		Digest   string `json:"digest"`
	} `json:"pack"`
	Lines struct {
		CapturedOn string `json:"capturedOn,omitempty"`
		Digest     string `json:"digest"`
	} `json:"lines"`
	// LinesSnapshot and Declared are present in the ALL window only: the
	// complete predicate is relative to this snapshot and this declared file.
	LinesSnapshot *SnapshotInfo `json:"linesSnapshot,omitempty"`
	Declared      *DeclaredInfo `json:"declared,omitempty"`
	// PackProjects is the number of projects with a valid rule or
	// attestation in the pack, whether or not lines are known for them. A
	// community project counts only through a current attestation.
	PackProjects int `json:"packProjectsCovered"`
	// CRDVersionProjects is the number of distinct projects with a reviewed
	// crd.custom_resource_versions target: the projects whose CRD version
	// knowledge exists, whether or not lines are known for them.
	CRDVersionProjects int `json:"crdVersionProjects,omitempty"`
	// CRDPublishedProjects is the number of those target projects that
	// also have a valid rule or a current line attestation of the
	// crd.custom_resource_versions family in the pack. A target alone
	// answers nothing: community projects without data are refused.
	CRDPublishedProjects int    `json:"crdPublishedProjects,omitempty"`
	Fleet                Totals `json:"fleet"`
	Priority             Totals `json:"priorityProjects"`
	// CommunityCatalog totals the community-catalog projects apart from
	// the fleet; it is absent when the lines snapshot lists none.
	CommunityCatalog *Totals   `json:"communityCatalog,omitempty"`
	Families         []Family  `json:"families"`
	Projects         []Project `json:"projects"`
	// WithoutLines lists projects with a valid rule or attestation but no
	// lines in the snapshot (a community project: a current attestation).
	// Their pairs are unknown, never counted as covered.
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
	raw       json.RawMessage
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

// crdPublished names the projects and components that a pack publishes for
// the crd.custom_resource_versions family.
type crdPublished struct{ project, component map[string]bool }

// communityCRDPublished reads the community pack (nil: nothing published):
// a valid, verdict-bearing rule of the CRD version family publishes its
// project; a current line attestation of the family publishes its component.
func communityCRDPublished(raw []byte, now time.Time) (crdPublished, error) {
	out := crdPublished{project: map[string]bool{}, component: map[string]bool{}}
	if len(raw) == 0 {
		return out, nil
	}
	var pack packDoc
	if err := json.Unmarshal(raw, &pack); err != nil {
		return out, fmt.Errorf("%w: community pack: %v", ErrInvalid, err)
	}
	for _, entry := range pack.Entries {
		var shape struct {
			Evidence evidenceShape `json:"evidence"`
		}
		if json.Unmarshal(entry.Rule, &shape) != nil || entry.Project == "" {
			return out, fmt.Errorf("%w: community pack: malformed entry", ErrInvalid)
		}
		scope, err := lineattest.ScopeOf(entry.Rule)
		if err != nil {
			return out, fmt.Errorf("%w: community pack: %v", ErrInvalid, err)
		}
		neutral, err := constraintengine.RawRuleVerdictNeutral(entry.Rule)
		if err != nil {
			return out, fmt.Errorf("%w: community pack: %v", ErrInvalid, err)
		}
		if ok, _ := validAt(shape.Evidence, now); ok && !neutral && slices.Contains(scope.Families, lineattest.FamilyCustomResourceVersions) {
			out.project[entry.Project] = true
		}
	}
	section, present, err := lineattest.PackSection(raw)
	if err != nil {
		return out, fmt.Errorf("%w: community pack: %v", ErrInvalid, err)
	}
	if !present {
		return out, nil
	}
	atts, err := lineattest.Parse(section)
	if err != nil {
		return out, fmt.Errorf("%w: community pack attestations: %v", ErrInvalid, err)
	}
	for _, a := range atts {
		if a.FactFamily == lineattest.FamilyCustomResourceVersions && a.Freshness(now) == lineattest.FreshnessCurrent {
			out.component[a.Component] = true
		}
	}
	return out, nil
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
	if in.All {
		if window != 0 {
			return Report{}, fmt.Errorf("%w: the ALL window takes no window size", ErrInvalid)
		}
	} else {
		if window == 0 {
			window = DefaultWindow
		}
		if window < 2 || window > 64 {
			return Report{}, fmt.Errorf("%w: window must be between 2 and 64", ErrInvalid)
		}
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
		rec := &ruleRec{id: scope.ID, project: entry.Project, tr: scope.Transition, families: scope.Families, valid: ok && !neutral, validTill: until, raw: entry.Rule}
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
	// A project that owns no component through the snapshot or its rules
	// takes the component of its reviewed CRD target. Fail closed: a project
	// that already owns a component, a component that another project owns
	// or that two targets claim, or an empty component attributes nothing.
	targetClaims := map[string]int{}
	for _, c := range in.CRDTargetComponents {
		targetClaims[c]++
	}
	for project, c := range in.CRDTargetComponents {
		if c == "" || targetClaims[c] != 1 || len(components[project]) > 0 || linesFile.Projects[project].Component != "" {
			continue
		}
		if _, inSnapshot := linesFile.Projects[project]; !inSnapshot {
			continue
		}
		if _, owned := componentProject[c]; owned {
			continue
		}
		componentProject[c] = project
	}
	attsByProject := map[string][]lineattest.LineAttestation{}
	expiringAtt := map[string]int{}
	validAtt := map[string]int{}
	crdAttComponent := map[string]bool{}
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
	report.CRDVersionProjects = in.CRDVersionProjects
	report.Schema = Schema
	report.Now = now.Format(time.RFC3339)
	report.Window = window
	report.WindowAll = in.All
	report.Pack.Revision = pack.Revision
	report.Pack.Schema = pack.Schema
	report.Pack.Digest = digestOf(in.Pack)
	report.Lines.CapturedOn = linesFile.CapturedOn
	report.Lines.Digest = digestOf(in.Lines)

	var comp *completer
	famCounts := map[string]*Counts{}
	if in.All {
		declaredRaw := in.Declared
		if declaredRaw == nil {
			declaredRaw = embeddedDeclared
		}
		declared, err := ParseDeclared(declaredRaw)
		if err != nil {
			return Report{}, err
		}
		report.LinesSnapshot = snapshotInfo(report.Lines.Digest, linesFile.CapturedOn, now)
		report.Declared = &DeclaredInfo{Digest: digestOf(declaredRaw), Records: len(declared.Declarations)}
		comp = newCompleter(now, atts, byID, declared.Declarations, linesFile.CapturedOn)
	}

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
	for project := range covered {
		if customresources.IsCommunity(project) && validAtt[project] == 0 {
			continue
		}
		report.PackProjects++
	}

	for _, a := range atts {
		if a.FactFamily == lineattest.FamilyCustomResourceVersions && a.Freshness(now) == lineattest.FreshnessCurrent {
			crdAttComponent[a.Component] = true
		}
	}
	communityCRD, err := communityCRDPublished(in.CommunityPack, now)
	if err != nil {
		return Report{}, err
	}
	for project, component := range in.CRDTargetComponents {
		published := crdAttComponent[component]
		for _, r := range byProject[project] {
			if r.valid && slices.Contains(r.families, lineattest.FamilyCustomResourceVersions) {
				published = true
			}
		}
		if published || communityCRD.project[project] || communityCRD.component[component] {
			report.CRDPublishedProjects++
		}
	}

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
		if in.All {
			if len(lines) > MaxAllLines {
				return Report{}, fmt.Errorf("%w: lines: %s: more than %d lines", ErrInvalid, slug, MaxAllLines)
			}
			lines = allWindow(lines, registrations(slug))
		} else if len(lines) > window {
			lines = lines[len(lines)-window:]
		}
		row := Project{Project: slug, Priority: pl.Priority, Window: append([]string{}, lines...), Pairs: []Pair{}, Covered: covered[slug]}
		community := customresources.IsCommunity(slug)
		if community {
			row.Catalog = CatalogCommunity
		}
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
					if !community {
						familyA[f]++
					}
				}
			case StatusB:
				row.B++
				for _, f := range pair.Families {
					if !community {
						familyB[f]++
					}
				}
			case StatusS:
				row.S++
			default:
				row.G++
			}
		}
		if in.All {
			row.Completion = comp.evaluate(slug, pl, lines)
			if !community {
				for _, fc := range row.Completion.FamilyCounts {
					sum := famCounts[fc.Family]
					if sum == nil {
						sum = &Counts{}
						famCounts[fc.Family] = sum
					}
					sum.LinesTotal += fc.LinesTotal
					sum.Decided += fc.Decided
					sum.DeclaredUnknown += fc.DeclaredUnknown
					sum.Undeclared += fc.Undeclared
				}
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
		if p.Catalog == CatalogCommunity {
			if report.CommunityCatalog == nil {
				report.CommunityCatalog = &Totals{}
			}
			add(report.CommunityCatalog)
			continue
		}
		add(&report.Fleet)
		if p.Priority {
			add(&report.Priority)
		}
	}
	totals := []*Totals{&report.Fleet, &report.Priority}
	if report.CommunityCatalog != nil {
		totals = append(totals, report.CommunityCatalog)
	}
	for _, t := range totals {
		withPairs := 0
		for _, p := range report.Projects {
			if len(p.Pairs) == 0 {
				continue
			}
			switch {
			case t == report.CommunityCatalog:
				if p.Catalog == CatalogCommunity {
					withPairs++
				}
			case p.Catalog == CatalogCommunity:
			case t == &report.Fleet || p.Priority:
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
	if in.All {
		for _, f := range registeredFamilies() {
			names[f] = true
			if famCounts[f] == nil {
				famCounts[f] = &Counts{}
			}
		}
	}
	report.Families = []Family{}
	for f := range names {
		report.Families = append(report.Families, Family{Family: f, A: familyA[f], B: familyB[f], Counts: famCounts[f]})
	}
	sort.Slice(report.Families, func(i, j int) bool { return report.Families[i].Family < report.Families[j].Family })

	withLines := map[string]bool{}
	for _, slug := range slugs {
		withLines[slug] = true
	}
	report.WithoutLines = []string{}
	for project := range covered {
		if !withLines[project] && (!customresources.IsCommunity(project) || validAtt[project] > 0) {
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
func classify(project, fromLine, toLine string, rules []*ruleRec, atts []lineattest.LineAttestation, byID map[string]*ruleRec) Pair {
	pair := Pair{From: fromLine, To: toLine, Status: StatusG}
	if lineMapped(project) {
		if fams := attestedFamilies(fromLine, toLine, atts, byID); len(fams) > 0 {
			pair.Status, pair.Families = StatusA, fams
			return pair
		}
		if fams, ok := boundedFamilies(fromLine, toLine, rules); ok {
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
		if ok1 && ok2 && rf == fromLine && rt == toLine {
			pair.Status = StatusS
			return pair
		}
	}
	return pair
}

// attestedFamilies returns the families with a current attestation for the
// target line whose hop is exactly fromLine->toLine and whose listed rules are all
// valid and line-wide for that line.
func attestedFamilies(fromLine, toLine string, atts []lineattest.LineAttestation, byID map[string]*ruleRec) []string {
	set := map[string]bool{}
	for _, a := range atts {
		if a.Line != toLine || a.Completeness != lineattest.Completeness {
			continue
		}
		if previous, ok := lineattest.PreviousLine(a.Component, toLine); !ok || previous != fromLine {
			continue
		}
		family, ok := lineattest.LookupFamily(a.FactFamily)
		if !ok {
			continue
		}
		wide := true
		for _, id := range a.RuleIDs {
			r := byID[id]
			if r == nil || !r.valid || !family.CoversLine(a.Component, r.tr, toLine) {
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
func boundedFamilies(fromLine, toLine string, rules []*ruleRec) ([]string, bool) {
	toNext, ok := nextLineStart(toLine)
	if !ok {
		return nil, false
	}
	toBound := constraintengine.VersionBound{Gte: toLine + ".0", Lt: toNext}
	set := map[string]bool{}
	for _, r := range rules {
		if !r.valid {
			continue
		}
		hit := false
		if r.tr.Range != nil && r.tr.Range.From.CoversLine(fromLine) && r.tr.Range.To.CoversLine(toLine) {
			hit = true
		}
		if cf, ct, ok := r.tr.CrossingBounds(); ok && cf.CoversLine(fromLine) && toBound.Contains(ct.Gte) && constraintengine.VersionLess(ct.Gte, ct.Lt) {
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
