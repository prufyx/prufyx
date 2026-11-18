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
	// Window is the number of newest final tags that had to be located
	// (min(MinLocatedNewest, Tags)); WindowLocated how many of them were.
	Window        int
	WindowLocated int
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
//   - one of the newest min final tags (all of them when fewer) has no
//     located entry; a typed withheld reason does not count as located.
//
// A row of a form that is not read is SKIP.
func CheckRow(src interface {
	extract.PinnedReader
	extract.TagSource
}, t Target, codeDigest string) RowResult {
	return CheckRowMin(src, t, codeDigest, DefaultMinLocatedNewest)
}

// CheckRowMin is CheckRow with an explicit newest-tag coverage bar; min < 1
// fails the row.
func CheckRowMin(src interface {
	extract.PinnedReader
	extract.TagSource
}, t Target, codeDigest string, min int) RowResult {
	res := RowResult{Component: t.Component, Form: t.Form, Withheld: map[Code]int{}}
	switch t.Form {
	case FormFile, FormPerLineFile, FormPerVersionFile:
	default:
		res.Status = RowSkip
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
		sortNewestFirst(finals)
		res.Window = min
		if res.Window > len(finals) {
			res.Window = len(finals)
		}
		var missing []string
		for _, n := range finals[:res.Window] {
			if located[n] {
				res.WindowLocated++
			} else {
				missing = append(missing, n)
			}
		}
		if len(missing) > 0 {
			fail("only %d of the newest %d final tags have an entry (no entry at %s)", res.WindowLocated, res.Window, strings.Join(missing, ", "))
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
	return CheckRowsMin(src, table, component, codeDigest, DefaultMinLocatedNewest)
}

// CheckRowsMin is CheckRows with an explicit newest-tag coverage bar.
func CheckRowsMin(src interface {
	extract.PinnedReader
	extract.TagSource
}, table []Target, component, codeDigest string, min int) ([]RowResult, error) {
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
		r := CheckRowMin(src, t, codeDigest, min)
		if component != "" && r.Status == RowSkip {
			r.Status = RowFail
			r.Reasons = append(r.Reasons, fmt.Sprintf("form %q is not read, nothing to check", t.Form))
		}
		out = append(out, r)
	}
	return out, nil
}
