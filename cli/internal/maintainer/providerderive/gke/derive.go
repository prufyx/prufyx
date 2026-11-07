// SPDX-License-Identifier: AGPL-3.0-only

package gke

import (
	"sort"
	"strings"

	"github.com/prufyx/prufyx/cli/internal/distribution"
	pd "github.com/prufyx/prufyx/cli/internal/maintainer/providerderive"
)

// Facts is what the schedule excerpts state, as distribution record members.
type Facts struct {
	Lifecycle []distribution.Lifecycle
	Channels  []distribution.Channel
}

func parseToken(tok string) (Cell, bool) {
	est := strings.HasSuffix(tok, "~")
	tok = strings.TrimSuffix(tok, "~")
	if tok == "tbd" {
		return Cell{Precision: distribution.PrecisionTBD, Estimate: est}, true
	}
	d, ok := pd.ParseISO(tok)
	d.Estimate = est
	return d, ok
}

// checkSource refuses an excerpt that does not cite the anchored GKE source.
func checkSource(x pd.Excerpt, src, path string) error {
	if x.Entry.Provider != Distribution {
		return pd.Drift(src, pd.KindExcerpt, "excerpt %s is not a gke excerpt", x.Entry.ID)
	}
	u := strings.TrimPrefix(x.Entry.SourceURL, "https://")
	host, p, _ := strings.Cut(u, "/")
	if !SourceHosts[host] || "/"+p != path {
		return pd.Drift(src, pd.KindExcerpt, "excerpt %s cites a source outside the anchored one", x.Entry.ID)
	}
	return nil
}

// SchedulePath is the page path an excerpt of the schedule must cite.
const SchedulePath = "/kubernetes-engine/docs/release-schedule"

// DeriveSchedule reads the schedule excerpts, in ascending line order across
// the slice, and returns lifecycle and channel rows. Standard end and the
// extended end come from the row; the schedule has no GA column, so GA stays
// empty (channel availability is in the channel rows). The extended end
// always carries extendedRequiresOptIn true (channel enrolment). No excerpts
// is an error.
func DeriveSchedule(xs []pd.Excerpt) (Facts, error) {
	if len(xs) == 0 {
		return Facts{}, pd.Drift(srcSchedule, pd.KindEmpty, "no excerpts")
	}
	var rows []Row
	prev := -1
	for _, x := range xs {
		if err := checkSource(x, srcSchedule, SchedulePath); err != nil {
			return Facts{}, err
		}
		body, err := pd.Body(srcSchedule, x)
		if err != nil {
			return Facts{}, err
		}
		if len(body) < 2 || body[0] != ScheduleFormat {
			return Facts{}, pd.Drift(srcSchedule, pd.KindExcerpt, "%s: not a schedule body", x.Entry.ID)
		}
		for _, ln := range body[1:] {
			f := strings.Split(ln, " ")
			if len(f) != 11 || !pd.ParseLine(f[0]) {
				return Facts{}, pd.Drift(srcSchedule, pd.KindExcerpt, "%s: row is not 11 fields", x.Entry.ID)
			}
			r := Row{Line: f[0]}
			for i, tok := range f[1:] {
				d, ok := parseToken(tok)
				if !ok {
					return Facts{}, pd.Drift(srcSchedule, pd.KindExcerpt, "%s: bad token in %s", x.Entry.ID, f[0])
				}
				r.Dates[i] = d
			}
			n := lineN(r.Line)
			if n <= prev {
				return Facts{}, pd.Drift(srcSchedule, pd.KindExcerpt, "%s: lines not strictly ascending at %s", x.Entry.ID, r.Line)
			}
			prev = n
			rows = append(rows, r)
		}
	}
	if err := (Schedule{Rows: rows}).check(); err != nil {
		return Facts{}, err
	}
	var f Facts
	yes := true
	for _, r := range rows {
		p, v := pd.Unify(r.Dates[8], r.Dates[9])
		l := distribution.Lifecycle{Line: r.Line, StandardEnd: v[0], ExtendedEnd: v[1], Precision: p}
		// The distribution record refuses extendedRequiresOptIn without an
		// extendedEnd, so a TBD extended end leaves the flag unset.
		if l.ExtendedEnd != "" {
			b := yes
			l.ExtendedRequiresOptIn = &b
		}
		f.Lifecycle = append(f.Lifecycle, l)
		for i, ch := range headerChannels {
			p, v := pd.Unify(r.Dates[2*i], r.Dates[2*i+1])
			f.Channels = append(f.Channels, distribution.Channel{Line: r.Line, Channel: ch, Available: v[0], AutoUpgrade: v[1], Precision: p})
		}
	}
	// Record order: ascending (line, channel name).
	sort.SliceStable(f.Channels, func(i, j int) bool {
		a, b := f.Channels[i], f.Channels[j]
		if a.Line != b.Line {
			return lineN(a.Line) < lineN(b.Line)
		}
		return a.Channel < b.Channel
	})
	return f, nil
}
