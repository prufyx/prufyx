// SPDX-License-Identifier: AGPL-3.0-only

// Package providerfacts evaluates what a provider announces (support dates)
// for a provider version the caller declared. It is pure: it reads a
// distribution record through the Records interface and the clock it is
// given, and it returns advisory findings.
//
// The findings are advisory only. They never state SAFE, never clear a
// finding or a gap, and nothing that reads them may change a verdict,
// ApplicabilityFor, or an exit code because of them. Every row of the
// fail-closed matrix (design section 3) that applies here yields a typed
// UNKNOWN finding with a next action; there is no rule that blocks.
//
// Not evaluated yet (stated, not guessed): provider upgrade-path rules,
// provider deprecations, release channels, component pins and the source
// drift alarm (no record state carries it). The deadline is the standard
// support end unless the caller declared extended support; extended support
// is paid and is never recommended as a path.
package providerfacts

import (
	"fmt"
	"strings"
	"time"

	"github.com/prufyx/prufyx/cli/internal/constraintengine"
	"github.com/prufyx/prufyx/cli/internal/distribution"
	"github.com/prufyx/prufyx/cli/internal/k8sversion"
)

// Severities of an advisory finding. None of them blocks.
const (
	SeverityInfo    = "INFO"
	SeverityWarn    = "WARN"
	SeverityUnknown = "UNKNOWN"
)

// Rule ids.
const (
	RuleUnrecognized        = "provider_unrecognized"
	RuleRecordAbsent        = "provider_record_absent"
	RuleSourceUnavailable   = "provider_source_unavailable"
	RuleVersionUnknown      = "provider_version_unknown"
	RuleVersionPrerelease   = "provider_version_prerelease"
	RuleLifecycleStale      = "provider_lifecycle_stale"
	RuleMappingConflict     = "provider_mapping_conflict"
	RuleDateImprecise       = "provider_date_imprecise"
	RuleSupportEnded        = "provider_support_ended"
	RuleSupportEnding       = "provider_support_ending"
	RuleSupportCurrent      = "provider_support_current"
	RuleForcedUpgrade       = "provider_forced_upgrade"
	RuleForcedUpgradeUnknow = "provider_forced_upgrade_unknown"
)

// Roles of a line in a section.
const (
	RoleDeclared     = "declared"
	RoleCurrent      = "current"
	RoleTarget       = "target"
	RoleCurrentLine  = "current_target"
	RoleIntermediate = "intermediate"
)

// EndingDays is how far ahead of a deadline a support end is reported as
// ending.
const EndingDays = 90

// maxSpan bounds the lines evaluated between the endpoints.
const maxSpan = distribution.MaxLifecycle

// Notes are the standing statements every section carries.
var Notes = []string{
	"Provider facts are advisory: they never make a scan SAFE and never change a verdict.",
	"Dates are what the provider announces globally; availability in your region or channel is UNKNOWN (check the provider console).",
	"Extended support is paid and provider-specific; Prufyx does not recommend it as a path.",
}

// Records is the lookup the evaluation needs. distribution.Index implements
// it.
type Records interface {
	Record(distribution string, now time.Time) (record distribution.Record, freshness string, found bool)
}

// Endpoint is one end of the declared upgrade. Version is the provider
// version as the caller declared it (a bare 1.N.P, or a self-identifying
// string such as v1.29.3-eks-adc7111). Upstream, when set, is the upstream
// Kubernetes version the caller declared for the same end; a disagreement
// with what Version identifies is a conflict.
type Endpoint struct {
	Version  string
	Upstream string
}

// Input is one evaluation.
type Input struct {
	Provider string
	Current  Endpoint
	Target   Endpoint
	Now      time.Time
	Records  Records
	// ExtendedOptIn is true only when the caller declared extended support
	// or channel enrolment for the provider. No CLI flag sets it yet.
	ExtendedOptIn     bool
	KnowledgeRevision string
}

// Finding is one advisory result.
type Finding struct {
	Rule     string `json:"rule"`
	Severity string `json:"severity"`
	Provider string `json:"provider"`
	// Line is the provider line the finding is about; empty when the
	// declaration itself could not be read.
	Line string `json:"line,omitempty"`
	Text string `json:"text"`
	// Next is the bounded next action; empty for an informational finding.
	Next              string                            `json:"next,omitempty"`
	KnowledgeRevision string                            `json:"knowledgeRevision"`
	Basis             string                            `json:"basis,omitempty"`
	ReviewedAt        string                            `json:"reviewedAt,omitempty"`
	ValidUntil        string                            `json:"validUntil,omitempty"`
	Sources           []constraintengine.SourceEvidence `json:"sources"`
}

// LineFacts holds the findings of one line.
type LineFacts struct {
	Line     string    `json:"line,omitempty"`
	Role     string    `json:"role"`
	Findings []Finding `json:"findings"`
}

// Section is the evaluation of one declared provider.
type Section struct {
	Provider          string      `json:"provider"`
	Now               string      `json:"now"`
	KnowledgeRevision string      `json:"knowledgeRevision"`
	Lines             []LineFacts `json:"lines"`
	Notes             []string    `json:"notes"`
}

// Evaluable reports whether provider is a distribution whose line is the
// upstream minor of its version, which this evaluation reads.
func Evaluable(provider string) bool {
	switch provider {
	case string(k8sversion.EKS), string(k8sversion.GKE), string(k8sversion.AKS), string(k8sversion.K3s), string(k8sversion.RKE2):
		return true
	}
	return false
}

// Evaluate evaluates the declared provider. ok is false when there is
// nothing to say: an empty provider, or upstream Kubernetes itself, which is
// not a provider. Any other token yields a section, never silence.
func Evaluate(in Input) (Section, bool) {
	if in.Provider == "" || distribution.UpstreamEquivalent(in.Provider) {
		return Section{}, false
	}
	s := Section{Provider: in.Provider, Now: in.Now.UTC().Format(time.RFC3339), KnowledgeRevision: in.KnowledgeRevision, Lines: []LineFacts{}, Notes: append([]string(nil), Notes...)}
	e := &evaluator{in: in}
	if !k8sversion.Known(in.Provider) {
		s.Lines = append(s.Lines, LineFacts{Role: RoleDeclared, Findings: []Finding{e.unknown(RuleUnrecognized, "",
			fmt.Sprintf("%q is not a distribution Prufyx recognises, so no provider fact is evaluated", in.Provider),
			"declare --distribution from the documented list, or custom_build", distribution.Evidence{})}})
		return s, true
	}
	if !Evaluable(in.Provider) {
		s.Lines = append(s.Lines, LineFacts{Role: RoleDeclared, Findings: []Finding{e.unknown(RuleVersionUnknown, "",
			fmt.Sprintf("%s lines do not equal an upstream minor; mapping its version to a provider line is not evaluated", e.name()),
			"check the provider's own support page by hand", distribution.Evidence{})}})
		return s, true
	}
	cur, curProblem := e.read(in.Current)
	tgt, tgtProblem := e.read(in.Target)
	if curProblem != nil {
		s.Lines = append(s.Lines, LineFacts{Role: RoleCurrent, Findings: []Finding{*curProblem}})
	}
	if tgtProblem != nil {
		s.Lines = append(s.Lines, LineFacts{Role: RoleTarget, Findings: []Finding{*tgtProblem}})
	}
	var ends []lineRole
	switch {
	case curProblem == nil && tgtProblem == nil:
		ends = span(cur, tgt)
	case curProblem == nil:
		ends = []lineRole{{cur, RoleCurrent}}
	case tgtProblem == nil:
		ends = []lineRole{{tgt, RoleTarget}}
	}
	lines := make([]LineFacts, 0, len(ends))
	for _, lr := range ends {
		lines = append(lines, LineFacts{Line: lr.line.String(), Role: lr.role, Findings: e.line(lr.line, lr.role)})
	}
	s.Lines = append(lines, s.Lines...)
	return s, true
}

type line struct{ major, minor int }

func (l line) String() string { return fmt.Sprintf("%d.%d", l.major, l.minor) }

type lineRole struct {
	line line
	role string
}

func span(cur, tgt line) []lineRole {
	switch {
	case cur == tgt:
		return []lineRole{{cur, RoleCurrentLine}}
	case cur.major != tgt.major || tgt.minor < cur.minor || tgt.minor-cur.minor > maxSpan:
		return []lineRole{{cur, RoleCurrent}, {tgt, RoleTarget}}
	}
	out := []lineRole{{cur, RoleCurrent}}
	for m := cur.minor + 1; m < tgt.minor; m++ {
		out = append(out, lineRole{line{cur.major, m}, RoleIntermediate})
	}
	return append(out, lineRole{tgt, RoleTarget})
}

type evaluator struct{ in Input }

func (e *evaluator) name() string {
	switch e.in.Provider {
	case "eks", "gke", "aks":
		return strings.ToUpper(e.in.Provider)
	case "rke2":
		return "RKE2"
	}
	return e.in.Provider
}

func (e *evaluator) finding(rule, severity, ln, text, next string, ev distribution.Evidence) Finding {
	f := Finding{Rule: rule, Severity: severity, Provider: e.in.Provider, Line: ln, Text: text, Next: next, KnowledgeRevision: e.in.KnowledgeRevision, Sources: []constraintengine.SourceEvidence{}}
	if len(ev.Sources) > 0 {
		f.Basis, f.ReviewedAt, f.ValidUntil = constraintengine.EffectiveBasis(ev.Basis), ev.ReviewedAt, ev.ValidUntil
		f.Sources = append(f.Sources, ev.Sources...)
	}
	return f
}

func (e *evaluator) unknown(rule, ln, text, next string, ev distribution.Evidence) Finding {
	return e.finding(rule, SeverityUnknown, ln, text, next, ev)
}

// read turns a declared endpoint into a provider line, or a typed finding.
func (e *evaluator) read(p Endpoint) (line, *Finding) {
	problem := func(rule, text, next string) (line, *Finding) {
		f := e.unknown(rule, "", text, next, distribution.Evidence{})
		return line{}, &f
	}
	if p.Version == "" {
		return problem(RuleVersionUnknown, "no version is declared for "+e.name(), "declare the version with --from / --to")
	}
	v, err := k8sversion.Parse(p.Version, e.in.Provider)
	if err != nil {
		// A bare version is how --from/--to declare it with --distribution.
		v, err = k8sversion.Parse(p.Version, "")
		if err != nil {
			return problem(RuleVersionUnknown, fmt.Sprintf("version %q is not in an accepted %s format", p.Version, e.name()), "report the version in an accepted format (see kubernetes-distribution-versions.md)")
		}
		if v.Distribution != k8sversion.OfficialUpstream {
			return problem(RuleMappingConflict, fmt.Sprintf("version %q identifies itself as %s but %s was declared", p.Version, v.Distribution, e.in.Provider), "declare the distribution the version belongs to; human review of the conflict")
		}
	}
	if v.Upstream.PreRelease() {
		return problem(RuleVersionPrerelease, fmt.Sprintf("version %q is a pre-release, not a release; no provider fact applies to it", p.Version), "use a GA version")
	}
	if p.Upstream != "" {
		u, err := k8sversion.Parse(p.Upstream, "")
		if err != nil || u.Distribution != k8sversion.OfficialUpstream {
			return problem(RuleVersionUnknown, fmt.Sprintf("upstream version %q is not a plain Kubernetes version", p.Upstream), "declare a plain upstream version")
		}
		if u.Upstream.Line() != v.Upstream.Line() {
			return problem(RuleMappingConflict, fmt.Sprintf("%s version %q maps to Kubernetes %s but Kubernetes %s was declared for it", e.name(), p.Version, v.Upstream.Line(), u.Upstream.Line()), "none automatic; human review of the conflict row")
		}
	}
	return line{v.Upstream.Major, v.Upstream.Minor}, nil
}

// line evaluates one provider line. The first return of a record problem is
// the only finding of the line.
func (e *evaluator) line(l line, role string) []Finding {
	ln := l.String()
	rec, fresh, found := e.in.Records.Record(e.in.Provider, e.in.Now)
	if !found {
		return []Finding{e.unknown(RuleRecordAbsent, ln, fmt.Sprintf("there is no %s provider record in the knowledge pack (provider data is not published yet)", e.name()), "refresh the knowledge bundle; none automatic if no provider data exists", distribution.Evidence{})}
	}
	ev := rec.Evidence
	if fresh == distribution.FreshnessCurrent && ev.DerivedAt != "" {
		if d, err := constraintengine.ParseUTC(ev.DerivedAt); err != nil || e.in.Now.Before(d) {
			fresh = distribution.FreshnessClockBeforeReview
		}
	}
	switch fresh {
	case distribution.FreshnessCurrent:
	case distribution.FreshnessStale:
		return []Finding{e.unknown(RuleLifecycleStale, ln, fmt.Sprintf("the %s record's evidence ended %s; its dates are not used at this time", e.name(), ev.ValidUntil), "refresh the knowledge bundle; date facts need a new fetch", ev)}
	case distribution.FreshnessClockBeforeReview:
		return []Finding{e.unknown(RuleRecordAbsent, ln, fmt.Sprintf("the %s record is dated after --now (clock_before_review); it is treated as absent", e.name()), "use a current --now or drop it", ev)}
	default:
		return []Finding{e.unknown(RuleRecordAbsent, ln, fmt.Sprintf("the %s record is %s; it is treated as absent", e.name(), fresh), "refresh the knowledge bundle", ev)}
	}
	if len(rec.Lifecycle) == 0 {
		return []Finding{e.unknown(RuleSourceUnavailable, ln, fmt.Sprintf("the %s record holds no lifecycle rows: no official source for support dates is recorded", e.name()), "none automatic; a maintainer adds an official source", ev)}
	}
	var row *distribution.Lifecycle
	for i := range rec.Lifecycle {
		if rec.Lifecycle[i].Line == ln {
			row = &rec.Lifecycle[i]
			break
		}
	}
	if row == nil {
		return []Finding{e.unknown(RuleVersionUnknown, ln, fmt.Sprintf("%s %s is not in the attested lifecycle rows, so its end-of-support dates are unknown", e.name(), ln), "refresh the knowledge bundle, or confirm the dates with the provider", ev)}
	}
	out := e.dates(ln, row, ev)
	out = append(out, e.forced(ln, role, row, ev)...)
	return out
}

func parseDay(s string) (time.Time, bool) {
	t, err := time.Parse("2006-01-02", s)
	return t, err == nil
}

func (e *evaluator) dates(ln string, row *distribution.Lifecycle, ev distribution.Evidence) []Finding {
	name := e.name()
	deadline, label := row.StandardEnd, "standard"
	if e.in.ExtendedOptIn && row.ExtendedEnd != "" {
		deadline, label = row.ExtendedEnd, "extended (paid), as you declared"
	}
	extended := ""
	if row.ExtendedEnd != "" {
		extended = "; extended (paid) ends " + row.ExtendedEnd
		switch {
		case row.ExtendedRequiresOptIn != nil && *row.ExtendedRequiresOptIn:
			extended += ", requires opt-in"
		case row.ExtendedRequiresOptIn != nil:
			extended += ", automatic per the provider"
		default:
			extended += ", opt-in not recorded"
		}
		if !e.in.ExtendedOptIn {
			extended += "; extended support is not assumed, no opt-in was declared"
		}
	}
	if row.Precision != distribution.PrecisionDay || deadline == "" {
		why := "no date is recorded"
		if deadline != "" {
			why = fmt.Sprintf("the date %s is announced to the %s only", deadline, row.Precision)
		} else if row.Precision != distribution.PrecisionDay {
			why = fmt.Sprintf("the row's date precision is %s", row.Precision)
		}
		return []Finding{e.unknown(RuleDateImprecise, ln, fmt.Sprintf("%s says %s %s support end: %s; no day-level deadline check is made%s", name, ln, label, why, extended), "state: date not announced to the day; check the provider's page", ev)}
	}
	end, ok := parseDay(deadline)
	if !ok {
		return []Finding{e.unknown(RuleDateImprecise, ln, fmt.Sprintf("%s says %s %s support end %q, which is not a day date", name, ln, label, deadline), "refresh the knowledge bundle", ev)}
	}
	over := end.AddDate(0, 0, 1) // the announced day is the last day
	switch {
	case !e.in.Now.Before(over):
		return []Finding{e.finding(RuleSupportEnded, SeverityWarn, ln, fmt.Sprintf("%s says %s %s support ended %s (announced globally)%s", name, ln, label, deadline, extended), "plan the upgrade to a line whose support end is later; check the provider console for your region", ev)}
	case !e.in.Now.Add(EndingDays * 24 * time.Hour).Before(over):
		return []Finding{e.finding(RuleSupportEnding, SeverityWarn, ln, fmt.Sprintf("%s says %s %s support ends %s, within %d days (announced globally)%s", name, ln, label, deadline, EndingDays, extended), "plan the upgrade before that date; check the provider console for your region", ev)}
	}
	return []Finding{e.finding(RuleSupportCurrent, SeverityInfo, ln, fmt.Sprintf("%s says %s %s support runs until %s (announced globally; availability in your region or channel is UNKNOWN)%s", name, ln, label, deadline, extended), "", ev)}
}

func (e *evaluator) forced(ln, role string, row *distribution.Lifecycle, ev distribution.Evidence) []Finding {
	name := e.name()
	if row.ForcedUpgrade == nil {
		if role != RoleTarget && role != RoleCurrentLine {
			return nil
		}
		return []Finding{e.finding(RuleForcedUpgradeUnknow, SeverityInfo, ln, fmt.Sprintf("%s %s forced upgrade date: UNKNOWN (no official sentence is recorded)", name, ln), "", ev)}
	}
	date := row.ForcedUpgrade.Date
	d, ok := parseDay(date)
	if row.Precision != distribution.PrecisionDay || !ok {
		return []Finding{e.unknown(RuleDateImprecise, ln, fmt.Sprintf("%s says a forced upgrade of %s on %s, which is not announced to the day", name, ln, date), "state: date not announced to the day; check the provider's page", ev)}
	}
	over := d.AddDate(0, 0, 1)
	text := fmt.Sprintf("%s says it upgrades clusters still on %s on %s (sentence %s)", name, ln, date, row.ForcedUpgrade.SentenceID)
	switch {
	case !e.in.Now.Before(over):
		return []Finding{e.finding(RuleForcedUpgrade, SeverityWarn, ln, text+"; that date has passed", "upgrade before the provider does", ev)}
	case !e.in.Now.Add(EndingDays * 24 * time.Hour).Before(over):
		return []Finding{e.finding(RuleForcedUpgrade, SeverityWarn, ln, text+fmt.Sprintf("; that is within %d days", EndingDays), "upgrade before that date", ev)}
	}
	return []Finding{e.finding(RuleForcedUpgrade, SeverityInfo, ln, text, "", ev)}
}
