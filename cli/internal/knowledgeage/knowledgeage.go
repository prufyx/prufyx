// SPDX-License-Identifier: AGPL-3.0-only

// Package knowledgeage decides whether the knowledge a command used is close
// to the end of its review window, and words the one-line note that tells the
// operator so. It reads no file and no clock: callers pass the rules' end
// dates and the instant the command evaluated at, so the same inputs give
// the same line.
package knowledgeage

import (
	"fmt"
	"sort"
	"time"
)

// Window is how long before a rule's end date the note starts.
const Window = 30 * 24 * time.Hour

// Source is the active rules of one body of knowledge (the embedded pack, or
// one target of a knowledge database): ID names the body so a body used
// several times is counted once, Expiries are the end dates of its active
// rules.
type Source struct {
	ID       string
	Expiries []time.Time
}

// Summary counts the active rules that end within the window or have ended.
type Summary struct {
	// Expired rules have an end date at or before the evaluation instant,
	// the instant from which the engine treats their evidence as stale.
	Expired int
	// Expiring rules end after the instant and no later than Window after it.
	Expiring int
	// First is the earliest end date among the counted rules.
	First time.Time
}

// Summarize counts the rules of the distinct sources. A source ID that
// appears more than once is counted once.
func Summarize(sources []Source, now time.Time) Summary {
	var summary Summary
	seen := map[string]bool{}
	limit := now.Add(Window)
	for _, source := range sources {
		if seen[source.ID] {
			continue
		}
		seen[source.ID] = true
		for _, end := range source.Expiries {
			switch {
			case !end.After(now):
				summary.Expired++
			case !end.After(limit):
				summary.Expiring++
			default:
				continue
			}
			if summary.First.IsZero() || end.Before(summary.First) {
				summary.First = end
			}
		}
	}
	return summary
}

// Merge returns the sources of both lists, in a stable order.
func Merge(lists ...[]Source) []Source {
	var out []Source
	for _, list := range lists {
		out = append(out, list...)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// Line is the note for the summary, without the "prufyx: " prefix and the
// line end, or "" when no rule is expired or about to be. embedded says the
// knowledge was the one built into the binary, which can also be replaced by
// a knowledge database. The line names no path and no input.
func Line(summary Summary, now time.Time, embedded bool) string {
	if summary.Expired == 0 && summary.Expiring == 0 {
		return ""
	}
	date := summary.First.UTC().Format("2006-01-02")
	var text string
	if summary.Expired > 0 {
		text = fmt.Sprintf("note: %d knowledge %s expired, the earliest on %s (%s)", summary.Expired, rules(summary.Expired, "rule has", "rules have"), date, ago(now.Sub(summary.First)))
	} else {
		text = fmt.Sprintf("note: %d knowledge %s within 30 days, the earliest on %s (%s)", summary.Expiring, rules(summary.Expiring, "rule expires", "rules expire"), date, in(summary.First.Sub(now)))
	}
	text += "; update with `prufyx db update`"
	if embedded {
		text += " and use --knowledge-db"
	}
	return text
}

func rules(count int, one, many string) string {
	if count == 1 {
		return one
	}
	return many
}

func days(d time.Duration) int { return int(d / (24 * time.Hour)) }

func in(d time.Duration) string {
	switch n := days(d); n {
	case 0:
		return "in less than a day"
	case 1:
		return "in 1 day"
	default:
		return fmt.Sprintf("in %d days", n)
	}
}

func ago(d time.Duration) string {
	switch n := days(d); n {
	case 0:
		return "less than a day ago"
	case 1:
		return "1 day ago"
	default:
		return fmt.Sprintf("%d days ago", n)
	}
}
