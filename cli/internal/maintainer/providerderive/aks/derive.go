// SPDX-License-Identifier: AGPL-3.0-only

package aks

import (
	"strings"

	"github.com/prufyx/prufyx/cli/internal/distribution"
	pd "github.com/prufyx/prufyx/cli/internal/maintainer/providerderive"
)

// Facts is what the support excerpts state.
type Facts struct {
	Lifecycle []distribution.Lifecycle
	// Prerelease lists lines with no GA date or no upstream release date yet
	// (preview or unannounced), never given a lifecycle row.
	Prerelease []string
	// PlatformUpgrade is the platform-initiated upgrade column per line. It
	// is not a forcedUpgrade fact: that needs a source sentence.
	PlatformUpgrade map[string]pd.Date
}

func tokCell(tok string) (Cell, bool) {
	switch {
	case tok == "tbd":
		return Cell{Kind: KindTBD, Date: pd.Date{Precision: distribution.PrecisionTBD}}, true
	case strings.HasPrefix(tok, "until:"):
		l := strings.TrimPrefix(tok, "until:")
		return Cell{Kind: KindUntil, UntilLine: l, Date: pd.Date{Precision: distribution.PrecisionTBD}}, pd.ParseLine(l)
	}
	d, ok := pd.ParseISO(tok)
	if !ok || d.Precision == distribution.PrecisionQuarter {
		return Cell{}, false
	}
	return Cell{Kind: KindDate, Date: d}, true
}

// DeriveSupport reads support excerpts (rows ascending within each table
// across the slice) and returns lifecycle rows. GA is the AKS GA column,
// standardEnd the End of life column, extendedEnd the LTS End of life column
// (always extendedRequiresOptIn true: LTS is opt-in). A cell that is TBD or
// "Until 1.N GA" carries no date and is left out; a row left with no date has
// precision tbd. Dates of one row are coarsened to the row's coarsest
// precision.
func DeriveSupport(xs []pd.Excerpt) (Facts, error) {
	if len(xs) == 0 {
		return Facts{}, pd.Drift(srcSupport, pd.KindEmpty, "no excerpts")
	}
	var s Support
	last := map[string]int{"std": -1, "lts": -1}
	for _, x := range xs {
		if x.Entry.Provider != Distribution || x.Entry.SourceURL != "https://"+SupportHost+SupportPath {
			return Facts{}, pd.Drift(srcSupport, pd.KindExcerpt, "excerpt %s cites a source outside the anchored one", x.Entry.ID)
		}
		body, err := pd.Body(srcSupport, x)
		if err != nil {
			return Facts{}, err
		}
		if len(body) < 2 || body[0] != SupportFormat {
			return Facts{}, pd.Drift(srcSupport, pd.KindExcerpt, "%s: not a support body", x.Entry.ID)
		}
		for _, ln := range body[1:] {
			f := strings.Split(ln, " ")
			if len(f) != 8 || (f[0] != "std" && f[0] != "lts") || !pd.ParseLine(f[1]) {
				return Facts{}, pd.Drift(srcSupport, pd.KindExcerpt, "%s: bad row", x.Entry.ID)
			}
			r := Row{Line: f[1]}
			dst := []*Cell{&r.Upstream, &r.Preview, &r.GA, &r.EOL, &r.Platform, &r.PlatformUpgrade}
			if f[0] == "lts" {
				dst[4] = &r.LTSEnd
			}
			for k, d := range dst {
				c, ok := tokCell(f[k+2])
				if !ok {
					return Facts{}, pd.Drift(srcSupport, pd.KindExcerpt, "%s: bad token in %s", x.Entry.ID, f[1])
				}
				*d = c
			}
			if n := lineN(r.Line); n <= last[f[0]] {
				return Facts{}, pd.Drift(srcSupport, pd.KindExcerpt, "%s: lines not strictly ascending at %s", x.Entry.ID, r.Line)
			} else {
				last[f[0]] = n
			}
			if f[0] == "std" {
				s.Standard = append(s.Standard, r)
			} else {
				s.LTS = append(s.LTS, r)
			}
		}
	}
	return s.facts()
}

func (s Support) facts() (Facts, error) {
	lines, err := s.Merge()
	if err != nil {
		return Facts{}, err
	}
	f := Facts{PlatformUpgrade: map[string]pd.Date{}}
	for _, l := range lines {
		if l.Prerelease {
			f.Prerelease = append(f.Prerelease, l.Line)
			continue
		}
		r := l.Row
		ext := Cell{Kind: KindTBD, Date: pd.Date{Precision: distribution.PrecisionTBD}}
		if l.InLTS {
			ext = r.LTSEnd
		}
		p, v := pd.Unify(r.GA.Date, r.EOL.Date, ext.Date)
		lc := distribution.Lifecycle{Line: l.Line, GA: v[0], StandardEnd: v[1], ExtendedEnd: v[2], Precision: p}
		prev := ""
		for _, d := range []string{lc.GA, lc.StandardEnd, lc.ExtendedEnd} {
			if d == "" {
				continue
			}
			if d < prev {
				return Facts{}, pd.Drift(srcSupport, pd.KindRow, "%s: dates out of order (GA <= end of life <= LTS end of life)", l.Line)
			}
			prev = d
		}
		if lc.ExtendedEnd != "" {
			yes := true
			lc.ExtendedRequiresOptIn = &yes
		}
		f.Lifecycle = append(f.Lifecycle, lc)
		if r.PlatformUpgrade.Kind == KindDate {
			f.PlatformUpgrade[l.Line] = r.PlatformUpgrade.Date
		}
	}
	return f, nil
}
