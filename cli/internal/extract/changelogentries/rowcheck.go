// SPDX-License-Identifier: AGPL-3.0-only

package changelogentries

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/prufyx/prufyx/cli/internal/extract"
)

// Row check statuses.
const (
	RowPass = "PASS"
	RowFail = "FAIL"
	// RowSkip is a row whose form is never read (release body, post-tag,
	// docs page, monorepo): it has nothing to prove here and claims nothing.
	RowSkip = "SKIP"
)

// RowResult is the outcome of checking one row against the recorded tags of
// its repository.
type RowResult struct {
	Component string
	Form      string
	Status    string
	// Tags is the number of final release tags checked; NotFinal the number of
	// recorded tags skipped because they are not final releases.
	Tags     int
	NotFinal int
	// Located is the number of tags whose entry was read in full.
	Located int
	// Withheld counts the typed reasons of the tags without an entry.
	Withheld map[Code]int
	// Window is the number of newest final versions looked at; WindowLocated
	// how many of them were located. Bar is how many had to be (the row's
	// minLocatedNewest, or the explicit override), at most Window.
	Window        int
	WindowLocated int
	Bar           int
	// Unlocated lists the tags of the window versions that were not located,
	// newest first; the receipt names them even when the row passes.
	Unlocated []string
	// MinLocatedNewest is the row's coverage bar as configured (the default
	// when the row has none) or the explicit override; it is what the
	// receipt prints.
	MinLocatedNewest int
	// Reasons says why the row failed; empty for PASS and SKIP.
	Reasons []string
}

// DefaultMinLocatedNewest is the number of newest final tags that must each
// have a located entry for a row to PASS (fewer when fewer tags exist).
const DefaultMinLocatedNewest = 8

// WithheldTotal is the number of tags withheld with a typed reason.
func (r RowResult) WithheldTotal() int {
	n := 0
	for _, c := range r.Withheld {
		n += c
	}
	return n
}

// CheckRow runs the one reader over every final release tag the source
// records for the row's repository. It is read-only and deterministic. Per
// tag the result must be an entry or a typed reason. The row fails when:
//   - a tag gives an error that is not a typed reason (a read failure, a
//     tag the source cannot serve);
//   - a tag name is recorded twice;
//   - a tag is withheld for a reason that is the row's own defect, not a fact
//     about the source (NO_CHANGELOG_TARGET, SHAPE_NOT_PER_TAG,
//     SOURCE_NOT_PINNED_GIT);
//   - the source records no final tag;
//   - no tag at all has an entry (the path or template never resolves, or
//     the headings never read);
//   - fewer than the row's bar (minLocatedNewest, 5 to 8, default 8) of the
//     newest 8 final versions (all of them when fewer exist) are located; a
//     version counts only when every one of its tags has an entry, and a
//     typed withheld reason does not count as located.
//
// A row of a form that is not read is SKIP.
func CheckRow(src interface {
	extract.PinnedReader
	extract.TagSource
}, t Target, codeDigest string) RowResult {
	return checkRow(src, t, codeDigest, t.bar(), false)
}

// bar is the row's coverage bar: its minLocatedNewest, or the default.
func (t Target) bar() int {
	if t.MinLocatedNewest == 0 {
		return DefaultMinLocatedNewest
	}
	return t.MinLocatedNewest
}

// CheckRowMin is CheckRow with an explicit newest-tag coverage bar that
// replaces the row's own: the newest min final versions (all of them when
// fewer) must each be located, so the override is never looser in shape than
// the row bar; min < 1 fails the row.
func CheckRowMin(src interface {
	extract.PinnedReader
	extract.TagSource
}, t Target, codeDigest string, min int) RowResult {
	return checkRow(src, t, codeDigest, min, true)
}

// checkRow is the one row check. With prefix false the window is the newest
// DefaultMinLocatedNewest versions and at least bar of them (all when fewer
// exist) must be located; the row bar is 5 to 8, set in reviewed data. With
// prefix true the window is the newest bar versions and all must be located.
// Either way a version is located only when every one of its tags is.
func checkRow(src interface {
	extract.PinnedReader
	extract.TagSource
}, t Target, codeDigest string, min int, prefix bool) RowResult {
	res := RowResult{Component: t.Component, Form: t.Form, Withheld: map[Code]int{}, MinLocatedNewest: min}
	switch t.Form {
	case FormFile, FormPerLineFile, FormPerVersionFile:
	default:
		res.Status = RowSkip
		res.MinLocatedNewest = 0
		return res
	}
	fail := func(format string, a ...any) { res.Reasons = append(res.Reasons, fmt.Sprintf(format, a...)) }
	tags, err := src.Tags(t.Repo)
	if err != nil {
		fail("tags of %s cannot be read: %v", t.Repo.Key, err)
		res.Status = RowFail
		return res
	}
	if min < 1 {
		fail("min located newest %d: must be at least 1", min)
	}
	seen := map[string]bool{}
	located := map[string]bool{}
	var finals []string
	for _, tag := range tags {
		if seen[tag.Name] {
			fail("tag %q is recorded twice", tag.Name)
			continue
		}
		seen[tag.Name] = true
		if _, ok := tagVersion(tag.Name); !ok {
			res.NotFinal++
			continue
		}
		res.Tags++
		finals = append(finals, tag.Name)
		m, err := BuildManifest(src, t, tag, codeDigest)
		if err != nil {
			fail("tag %s: %v", tag.Name, err)
			continue
		}
		if m.Entry != nil {
			res.Located++
			located[tag.Name] = true
			continue
		}
		switch m.Withheld.Code {
		case NoChangelogTarget, ShapeNotPerTag, SourceNotPinnedGit:
			fail("tag %s: %s: %s", tag.Name, m.Withheld.Code, m.Withheld.Detail)
		}
		res.Withheld[m.Withheld.Code]++
	}
	if res.Tags == 0 {
		fail("no final release tag is recorded for %s", t.Repo.Key)
	} else if res.Located == 0 {
		fail("no tag of %d has an entry: the path or the headings never resolve", res.Tags)
	}
	if res.Tags > 0 && min >= 1 {
		size := min
		if !prefix {
			size = DefaultMinLocatedNewest
		}
		groups := newestVersions(finals, size)
		res.Window = len(groups)
		res.Bar = min
		if res.Bar > res.Window {
			res.Bar = res.Window
		}
		var missing []string
		for _, g := range groups {
			all := true
			for _, n := range g {
				if !located[n] {
					all = false
					missing = append(missing, n)
				}
			}
			if all {
				res.WindowLocated++
			}
		}
		res.Unlocated = missing
		if res.WindowLocated < res.Bar {
			fail("only %d of the newest %d final versions have an entry, %d are required (no entry at %s)", res.WindowLocated, res.Window, res.Bar, strings.Join(missing, ", "))
		}
	}
	res.Status = RowPass
	if len(res.Reasons) > 0 {
		res.Status = RowFail
	}
	return res
}

// SortedCodes lists the withheld codes of a result in code order.
func (r RowResult) SortedCodes() []Code {
	out := make([]Code, 0, len(r.Withheld))
	for c := range r.Withheld {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

var errNoRows = errors.New("no row to check")

// CheckRows checks every row of the table, or the one row of component when
// it is not empty (a component without a row is an error, not a result).
func CheckRows(src interface {
	extract.PinnedReader
	extract.TagSource
}, table []Target, component, codeDigest string) ([]RowResult, error) {
	return checkRows(src, table, component, codeDigest, nil)
}

// CheckRowsMin is CheckRows with an explicit newest-tag coverage bar for every
// row (see CheckRowMin); it replaces the rows' own bars.
func CheckRowsMin(src interface {
	extract.PinnedReader
	extract.TagSource
}, table []Target, component, codeDigest string, min int) ([]RowResult, error) {
	return checkRows(src, table, component, codeDigest, &min)
}

func checkRows(src interface {
	extract.PinnedReader
	extract.TagSource
}, table []Target, component, codeDigest string, override *int) ([]RowResult, error) {
	rows := table
	if component != "" {
		t, err := Lookup(table, component)
		if err != nil {
			return nil, err
		}
		rows = []Target{t}
	}
	if len(rows) == 0 {
		return nil, errNoRows
	}
	out := make([]RowResult, 0, len(rows))
	for _, t := range rows {
		var r RowResult
		if override != nil {
			r = CheckRowMin(src, t, codeDigest, *override)
		} else {
			r = CheckRow(src, t, codeDigest)
		}
		if component != "" && r.Status == RowSkip {
			r.Status = RowFail
			r.Reasons = append(r.Reasons, fmt.Sprintf("form %q is not read, nothing to check", t.Form))
		}
		out = append(out, r)
	}
	return out, nil
}
