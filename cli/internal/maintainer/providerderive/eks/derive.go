// SPDX-License-Identifier: AGPL-3.0-only

package eks

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/prufyx/prufyx/cli/internal/distribution"
	"github.com/prufyx/prufyx/cli/internal/maintainer/providerderive/shared"
	"github.com/prufyx/prufyx/cli/internal/maintainer/providerexcerpt"
)

// Provider id and anchor of the EKS excerpt.
const (
	Provider = "eks"
	Anchor   = "release-calendar"
)

// Input is the committed excerpt: manifest entry and file bytes.
type Input struct {
	Entry providerexcerpt.Entry
	Data  []byte
}

// Result is the deterministic derivation.
type Result struct {
	// Lifecycle rows ascending by line: ga = EKS release, standardEnd,
	// extendedEnd with extendedRequiresOptIn=false (extended is automatic).
	Lifecycle []distribution.Lifecycle
	// NotYetReleased lists lines whose upstream or EKS release is after the
	// excerpt's fetch day: no support claim is made for them.
	NotYetReleased []string
	// Warnings flag rows that break the page's own 14+12 month rule.
	Warnings []string
}

var (
	sourceRE = regexp.MustCompile(`^https://docs\.aws\.amazon\.com/eks/latest/userguide/kubernetes-versions\.(md|html)$`)
	dateTok  = `(\d{4}-\d{2}-\d{2}|\d{4}-\d{2}|\d{4}-Q[1-4]|tbd)`
	lineRE   = regexp.MustCompile(`^eks (1\.(?:0|[1-9][0-9]{0,5})) upstream ` + dateTok + ` release ` + dateTok + ` standard-end ` + dateTok + ` extended-end ` + dateTok + `$`)
)

// extendedRequiresOptIn is the single source of the opt-in flag written to
// every row. EXTENDED SUPPORT AUTOMATIC ON EKS: confirm from an official
// source sentence before shipping in a pack. A change is one reviewed edit.
const extendedRequiresOptIn = false

func tokCell(t string) (shared.Cell, error) {
	if t == "tbd" {
		return shared.ParseCell("TBD", false)
	}
	return shared.ParseCell(t, false)
}

// Derive reads the paraphrase excerpt body (see Canonical) and derives the
// lifecycle rows. Every line must match the grammar and pass the row checks;
// a bad line rejects the whole excerpt.
func Derive(in Input) (Result, error) {
	e := in.Entry
	if e.Provider != Provider || e.Anchor != Anchor || !sourceRE.MatchString(e.SourceURL) ||
		e.Licence != providerexcerpt.LicenceUnknown || e.Form != providerexcerpt.FormParaphrase {
		return Result{}, shared.Drift(shared.KindExcerpt, "entry %s is not the EKS release calendar excerpt", e.ID)
	}
	body, err := shared.Body(e, in.Data)
	if err != nil {
		return Result{}, err
	}
	day, err := shared.FetchedDate(e)
	if err != nil {
		return Result{}, err
	}
	var rows []Row
	for i, l := range strings.Split(strings.TrimSuffix(body, "\n"), "\n") {
		m := lineRE.FindStringSubmatch(l)
		if m == nil {
			return Result{}, shared.Drift(shared.KindUnparsable, "excerpt line %d is outside the grammar", i+1)
		}
		r := Row{Line: m[1]}
		for j, dst := range []*shared.Cell{&r.Upstream, &r.Release, &r.StandardEnd, &r.ExtendedEnd} {
			if *dst, err = tokCell(m[j+2]); err != nil {
				return Result{}, fmt.Errorf("excerpt line %d: %w", i+1, err)
			}
		}
		if err := checkRow(r); err != nil {
			return Result{}, fmt.Errorf("excerpt line %d (%s): %w", i+1, r.Line, err)
		}
		if len(rows) > 0 && lineNum(r.Line) >= lineNum(rows[len(rows)-1].Line) {
			return Result{}, shared.Drift(shared.KindUnparsable, "excerpt line %d (%s): versions must be strictly descending", i+1, r.Line)
		}
		rows = append(rows, r)
	}
	return FromRows(rows, day)
}

// afterDay reports whether a dated cell lies after the fetch day (YYYY-MM-DD)
// at the cell's own precision: day, month (YYYY-MM) and quarter (YYYY-Qn). A
// month or quarter that contains the fetch day is not after it.
func afterDay(c shared.Cell, day string) bool {
	switch c.Precision {
	case distribution.PrecisionDay:
		return c.Value > day
	case distribution.PrecisionMonth:
		return c.Value > day[:7]
	case distribution.PrecisionQuarter:
		mo := int(day[5]-'0')*10 + int(day[6]-'0')
		return c.Value > fmt.Sprintf("%s-Q%d", day[:4], (mo-1)/3+1)
	}
	return false
}

// FromRows derives lifecycle rows from a parsed table as of a fetch day
// (YYYY-MM-DD).
func FromRows(rows []Row, day string) (Result, error) {
	var res Result
	for _, r := range rows {
		if afterDay(r.Upstream, day) || afterDay(r.Release, day) {
			res.NotYetReleased = append(res.NotYetReleased, r.Line)
			continue
		}
		l := distribution.Lifecycle{Line: r.Line, Precision: r.Release.Precision}
		if r.Release.Precision != distribution.PrecisionTBD {
			opt := extendedRequiresOptIn
			l.GA, l.StandardEnd, l.ExtendedEnd = r.Release.Value, r.StandardEnd.Value, r.ExtendedEnd.Value
			l.ExtendedRequiresOptIn = &opt
		}
		if r.Release.Precision == distribution.PrecisionDay {
			if w := ruleWarning(r); w != "" {
				res.Warnings = append(res.Warnings, w)
			}
		}
		res.Lifecycle = append(res.Lifecycle, l)
	}
	sort.Slice(res.Lifecycle, func(i, j int) bool { return lineNum(res.Lifecycle[i].Line) < lineNum(res.Lifecycle[j].Line) })
	sort.Strings(res.NotYetReleased)
	sort.Strings(res.Warnings)
	return res, nil
}

// ruleWarning checks the page's own rule (standard = release + 14 months,
// extended = standard + 12 months). A deviation is flagged, never normalised.
func ruleWarning(r Row) string {
	rel, e1 := time.Parse("2006-01-02", r.Release.Value)
	std, e2 := time.Parse("2006-01-02", r.StandardEnd.Value)
	ext, e3 := time.Parse("2006-01-02", r.ExtendedEnd.Value)
	if e1 != nil || e2 != nil || e3 != nil {
		return ""
	}
	if !rel.AddDate(0, 14, 0).Equal(std) {
		return fmt.Sprintf("%s: standard end %s is not 14 months after release %s", r.Line, r.StandardEnd.Value, r.Release.Value)
	}
	if !std.AddDate(0, 12, 0).Equal(ext) {
		return fmt.Sprintf("%s: extended end %s is not 12 months after standard end %s", r.Line, r.ExtendedEnd.Value, r.StandardEnd.Value)
	}
	return ""
}
