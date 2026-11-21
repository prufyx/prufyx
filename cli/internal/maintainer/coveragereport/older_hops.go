// SPDX-License-Identifier: AGPL-3.0-only

package coveragereport

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/prufyx/prufyx/cli/internal/hopstop"
	"github.com/prufyx/prufyx/cli/internal/lineattest"
)

// OlderHopsTitle is the heading of the block. The wording is "older hops
// derived", never "coverage": the block is not part of the cohort number.
const OlderHopsTitle = "Older hops (not part of the cohort number)"

// MaxOlderDepth is the hard bound of OlderHopsInput.DepthBound.
const MaxOlderDepth = 24

// OlderHop is one hop (consecutive release lines From to To) whose from line
// lies before the cohort window start. Attested: an admitted attestation
// covers it. Blocked: a citation-backed B rule exists for it. Stop: a final
// hop-stop code or "". A hop with none of the three is not derived.
type OlderHop struct {
	From, To string
	Attested bool
	Blocked  bool
	Stop     string
}

// OlderHopsProject is one project's older hops, ascending, unique,
// consecutive.
type OlderHopsProject struct {
	Project string
	Hops    []OlderHop
}

// OlderHopsInput is what the block is computed from. DepthBound (1..24)
// caps how many of the hops nearest to the window start are counted per
// project; the bound is part of the block and printed with it.
type OlderHopsInput struct {
	DepthBound int
	Projects   []OlderHopsProject
}

// OlderHopsCounts are the counts of one project or of the whole block.
// Pairs is the denominator (the hops counted, after the depth cap). Derived
// is Attested plus the hops with a stop or a B rule only, so Derived plus
// NotDerived equals Pairs. BlockedKnown counts hops with a B rule whether or
// not they are attested.
type OlderHopsCounts struct {
	Pairs        int            `json:"pairs"`
	Derived      int            `json:"derived"`
	Attested     int            `json:"attested"`
	BlockedKnown int            `json:"blockedKnown"`
	Stops        map[string]int `json:"stops"`
	NotDerived   int            `json:"notDerived"`
}

// OlderHopsRow is one project's counts.
type OlderHopsRow struct {
	Project string `json:"project"`
	OlderHopsCounts
}

// OlderHops is the report member. Total adds the older hops of the rows
// together and nothing else: it is never added to a cohort figure, and no
// cohort total reads it.
type OlderHops struct {
	Title      string          `json:"title"`
	DepthBound int             `json:"depthBound"`
	Total      OlderHopsCounts `json:"total"`
	Projects   []OlderHopsRow  `json:"projects"`
}

func newCounts() OlderHopsCounts { return OlderHopsCounts{Stops: map[string]int{}} }

func (c *OlderHopsCounts) add(o OlderHopsCounts) {
	c.Pairs += o.Pairs
	c.Derived += o.Derived
	c.Attested += o.Attested
	c.BlockedKnown += o.BlockedKnown
	c.NotDerived += o.NotDerived
	for k, v := range o.Stops {
		c.Stops[k] += v
	}
}

// ErrOlderHops marks an input the block is not computed from.
var ErrOlderHops = errors.New("older hops refused")

// ComputeOlderHops counts the older hops. It is fail closed: a stop code
// outside the closed set (or a transient one), a hop both attested and
// stopped, hops that are unsorted, repeated or not consecutive, an invalid
// line, a repeated project or a depth bound outside 1..24 refuses the whole
// block.
func ComputeOlderHops(in OlderHopsInput) (*OlderHops, error) {
	bad := func(format string, args ...any) (*OlderHops, error) {
		return nil, fmt.Errorf("%w: %s", ErrOlderHops, fmt.Sprintf(format, args...))
	}
	if in.DepthBound < 1 || in.DepthBound > MaxOlderDepth {
		return bad("depth bound %d is outside 1..%d", in.DepthBound, MaxOlderDepth)
	}
	out := &OlderHops{Title: OlderHopsTitle, DepthBound: in.DepthBound, Total: newCounts(), Projects: []OlderHopsRow{}}
	seen := map[string]bool{}
	for _, p := range in.Projects {
		if p.Project == "" || seen[p.Project] {
			return bad("project %q is empty or repeated", p.Project)
		}
		seen[p.Project] = true
		for i, h := range p.Hops {
			prevEnd, start := "", h.From
			if i > 0 {
				prevEnd = p.Hops[i-1].To
			}
			continues := i > 0 && prevEnd == start
			switch {
			case !lineattest.ValidLine(h.From) || !lineattest.ValidLine(h.To) || !lineattest.LineLess(h.From, h.To):
				return bad("%s: hop %d has invalid or unordered lines", p.Project, i)
			case i > 0 && !continues:
				return bad("%s: hop %d does not continue hop %d", p.Project, i, i-1)
			case h.Attested && h.Stop != "":
				return bad("%s: hop %d is both attested and stopped", p.Project, i)
			case h.Stop != "" && !hopstop.Final(h.Stop):
				return bad("%s: hop %d has a stop code outside the closed final set", p.Project, i)
			}
		}
		hops := p.Hops
		if len(hops) > in.DepthBound {
			hops = hops[len(hops)-in.DepthBound:] // nearest to the window start
		}
		row := OlderHopsRow{Project: p.Project, OlderHopsCounts: newCounts()}
		for _, h := range hops {
			row.Pairs++
			switch {
			case h.Attested:
				row.Attested++
			case h.Stop != "":
				row.Stops[h.Stop]++
			}
			if h.Blocked {
				row.BlockedKnown++
			}
			if h.Attested || h.Stop != "" || h.Blocked {
				row.Derived++
			} else {
				row.NotDerived++
			}
		}
		out.Total.add(row.OlderHopsCounts)
		out.Projects = append(out.Projects, row)
	}
	sort.Slice(out.Projects, func(i, j int) bool { return out.Projects[i].Project < out.Projects[j].Project })
	return out, nil
}

// WithOlderHops returns a copy of the report that carries the block. Every
// other member is untouched: the cohort totals, the window and the README
// block are those of the report without it.
func (r Report) WithOlderHops(o *OlderHops) Report {
	r.OlderHops = o
	return r
}

// Line is the one-line statement of the block for prose: the counts of
// older hops derived, with the depth bound, never called coverage.
func (o *OlderHops) Line() string {
	return fmt.Sprintf("%s: %d older hops derived of %d counted (depth bound %d), %d attested, %d with a known blocker, %d not derived.",
		OlderHopsTitle, o.Total.Derived, o.Total.Pairs, o.DepthBound, o.Total.Attested, o.Total.BlockedKnown, o.Total.NotDerived)
}

// Markdown is the block for the Markdown report.
func (o *OlderHops) Markdown() string {
	var b strings.Builder
	fmt.Fprintf(&b, "## %s\n\n%s\n\n", o.Title, o.Line())
	b.WriteString("| Project | Hops | Derived | Attested | Blocked known | Stops | Not derived |\n|---|---|---|---|---|---|---|\n")
	for _, p := range o.Projects {
		codes := make([]string, 0, len(p.Stops))
		for c := range p.Stops {
			codes = append(codes, c)
		}
		sort.Strings(codes)
		parts := make([]string, 0, len(codes))
		for _, c := range codes {
			parts = append(parts, fmt.Sprintf("%s %d", c, p.Stops[c]))
		}
		stops := "-"
		if len(parts) > 0 {
			stops = strings.Join(parts, ", ")
		}
		fmt.Fprintf(&b, "| %s | %d | %d | %d | %d | %s | %d |\n", p.Project, p.Pairs, p.Derived, p.Attested, p.BlockedKnown, stops, p.NotDerived)
	}
	return b.String()
}
