// SPDX-License-Identifier: AGPL-3.0-only

package upstream

import (
	"fmt"
	"regexp"
	"sort"

	"github.com/prufyx/prufyx/cli/internal/distribution"
	"github.com/prufyx/prufyx/cli/internal/maintainer/providerderive/shared"
	"github.com/prufyx/prufyx/cli/internal/maintainer/providerexcerpt"
)

// Provider id and anchors of the upstream excerpts.
const (
	Provider       = "upstream"
	AnchorSchedule = "schedule-yaml"
	AnchorEOL      = "eol-yaml"
)

// Input is one committed excerpt: its manifest entry and file bytes.
type Input struct {
	Entry providerexcerpt.Entry
	Data  []byte
}

// Status of a minor on the reference day.
const (
	StatusSupported   = "supported"
	StatusMaintenance = "maintenance"
	StatusEOL         = "eol"
)

// Line is one upstream minor with its status on the reference day. Presence
// in schedule.yaml does not mean supported: Status is by date.
type Line struct {
	Minor
	LatestPatch string // stable marker patch for the stable line, else NextPatch
	Status      string
}

// Result is the deterministic derivation.
type Result struct {
	// Lifecycle rows, ascending by line, of the distribution record shape:
	// ga = releaseDate, maintenanceStart, standardEnd = endOfLifeDate, day
	// precision, no extended end. Advisory, never a SAFE signal.
	Lifecycle []distribution.Lifecycle
	Lines     []Line
	AsOf      string // YYYY-MM-DD, the later fetch day of the two excerpts
	Warnings  []string
}

var sourceRE = regexp.MustCompile(`^https://(?:raw\.githubusercontent\.com/kubernetes/website/(main|[0-9a-f]{40})|github\.com/kubernetes/website/blob/(main|[0-9a-f]{40}))/data/releases/(schedule|eol)\.yaml$`)

func checkInput(in Input, anchor, file string) (string, error) {
	e := in.Entry
	m := sourceRE.FindStringSubmatch(e.SourceURL)
	if e.Provider != Provider || e.Anchor != anchor || m == nil || m[3] != file ||
		e.Licence != providerexcerpt.LicencePermissive || e.Form != providerexcerpt.FormVerbatim {
		return "", shared.Drift(shared.KindExcerpt, "entry %s is not the %s excerpt of the upstream release data", e.ID, anchor)
	}
	return shared.Body(e, in.Data)
}

// Derive turns the schedule and eol excerpts (and optionally the stable
// marker bytes, which have no excerpt host yet) into lifecycle rows. A line
// present in both files, a stable line absent from the schedule, or any
// parse error is a drift error with no partial output.
func Derive(schedule, eol Input, stable []byte) (Result, error) {
	sb, err := checkInput(schedule, AnchorSchedule, "schedule")
	if err != nil {
		return Result{}, err
	}
	eb, err := checkInput(eol, AnchorEOL, "eol")
	if err != nil {
		return Result{}, err
	}
	s, err := ParseSchedule(sb)
	if err != nil {
		return Result{}, err
	}
	e, err := ParseEOL(eb)
	if err != nil {
		return Result{}, err
	}
	d1, err := shared.FetchedDate(schedule.Entry)
	if err != nil {
		return Result{}, err
	}
	d2, err := shared.FetchedDate(eol.Entry)
	if err != nil {
		return Result{}, err
	}
	asOf := d1
	if d2 > asOf {
		asOf = d2
	}
	res := Result{AsOf: asOf}
	byLine := map[string]*Line{}
	var order []string
	for _, m := range s.Minors {
		l := &Line{Minor: m, LatestPatch: m.NextPatch}
		switch {
		case asOf >= m.EndOfLife:
			l.Status = StatusEOL
		case asOf >= m.MaintenanceStart:
			l.Status = StatusMaintenance
		default:
			l.Status = StatusSupported
		}
		if l.Status == StatusEOL {
			res.Warnings = append(res.Warnings, fmt.Sprintf("%s is listed in the schedule but its end of life %s is past", m.Line, m.EndOfLife))
		}
		byLine[m.Line] = l
		order = append(order, m.Line)
	}
	for _, m := range e.Minors {
		if _, dup := byLine[m.Line]; dup {
			return Result{}, shared.Drift(shared.KindConflict, "line %s is in both the schedule and the end-of-life list", m.Line)
		}
		byLine[m.Line] = &Line{Minor: m, LatestPatch: m.FinalPatch, Status: StatusEOL}
		order = append(order, m.Line)
	}
	if stable != nil {
		line, patch, err := ParseStable(string(stable))
		if err != nil {
			return Result{}, err
		}
		l, ok := byLine[line]
		if !ok {
			return Result{}, shared.Drift(shared.KindConflict, "stable marker line %s is not a scheduled line", line)
		}
		if l.NextPatch != "" && l.NextPatch != patch {
			res.Warnings = append(res.Warnings, fmt.Sprintf("schedule next patch %s differs from stable marker %s; the marker is used", l.NextPatch, patch))
		}
		l.LatestPatch = patch
	}
	sort.Slice(order, func(i, j int) bool { return lineNum(order[i]) < lineNum(order[j]) })
	for _, k := range order {
		l := byLine[k]
		res.Lines = append(res.Lines, *l)
		res.Lifecycle = append(res.Lifecycle, distribution.Lifecycle{
			Line: l.Line, GA: l.ReleaseDate, MaintenanceStart: l.MaintenanceStart,
			StandardEnd: l.EndOfLife, Precision: distribution.PrecisionDay,
		})
	}
	sort.Strings(res.Warnings)
	return res, nil
}
