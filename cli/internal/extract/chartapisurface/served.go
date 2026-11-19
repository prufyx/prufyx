// SPDX-License-Identifier: AGPL-3.0-only

package chartapisurface

import (
	"sort"
	"strings"

	"github.com/prufyx/prufyx/cli/internal/servedapis"
)

func groupOf(apiVersion string) string {
	if i := strings.Index(apiVersion, "/"); i >= 0 {
		return apiVersion[:i]
	}
	return ""
}

// CheckServed adds one served-API check per requested line. It is a
// measurement: would-block, would-pass or withheld, never a rule.
//
// records are the Kubernetes served lists (servedapis.Parse output). Lines
// that have no record are withheld. Freshness of a record is not judged
// here: nothing leaves the ledger as a claim.
func (l *Ledger) CheckServed(records []servedapis.Record, lines []string) {
	byLine := map[string]servedapis.Record{}
	groups := map[string]bool{}
	for _, r := range records {
		byLine[r.Line] = r
		for _, p := range r.APIs {
			v, _, _ := strings.Cut(p, " ")
			groups[groupOf(v)] = true
		}
	}
	lines = append([]string(nil), lines...)
	sort.Strings(lines)
	for _, line := range lines {
		c := ServedCheck{Line: line, Blockers: []Blocker{}, Notices: []Blocker{}, NotBuiltin: []Pair{}, Unknown: []Pair{}, Reasons: []string{}}
		rec, ok := byLine[line]
		if !ok {
			c.Result = ResultWithheld
			c.Reasons = append(c.Reasons, "no_served_list_for_line")
			l.ServedChecks = append(l.ServedChecks, c)
			continue
		}
		served := map[string]bool{}
		for _, p := range rec.APIs {
			served[p] = true
		}
		complete := rec.Completeness == servedapis.Completeness
		// first occurrence of each pair, unconditional occurrences first
		type occ struct {
			e    Entry
			uncd bool
		}
		first := map[Pair]*occ{}
		for _, e := range l.APIs {
			k := Pair{e.APIVersion, e.Kind}
			o := first[k]
			if o == nil {
				first[k] = &occ{e: e, uncd: !e.Conditional}
				continue
			}
			if !e.Conditional && !o.uncd {
				o.e, o.uncd = e, true
			}
		}
		for _, k := range l.Pairs() {
			o := first[k]
			switch {
			case !groups[groupOf(k.APIVersion)]:
				c.NotBuiltin = append(c.NotBuiltin, k)
			case served[k.APIVersion+" "+k.Kind]:
			case !complete:
				c.Unknown = append(c.Unknown, k)
			default:
				b := Blocker{APIVersion: k.APIVersion, Kind: k.Kind, File: o.e.File, Line: o.e.Line}
				if o.uncd {
					c.Blockers = append(c.Blockers, b)
				} else {
					c.Notices = append(c.Notices, b)
				}
			}
		}
		switch {
		case len(c.Blockers) > 0:
			c.Result = ResultWouldBlock
		case l.Status != StatusComplete:
			c.Result = ResultWithheld
			c.Reasons = append(c.Reasons, "chart_withheld")
		case len(c.Unknown) > 0:
			c.Result = ResultWithheld
			c.Reasons = append(c.Reasons, "partial_served_list")
		default:
			c.Result = ResultWouldPass
		}
		l.ServedChecks = append(l.ServedChecks, c)
	}
}
