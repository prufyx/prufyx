// SPDX-License-Identifier: AGPL-3.0-only

package changelogattest

import (
	"reflect"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/extract"
	ce "github.com/prufyx/prufyx/cli/internal/extract/changelogentries"
)

// rowAlterations changes each field of a row on its own. Every field of
// ce.Target needs an entry.
var rowAlterations = map[string][]func(*ce.Target){
	"Component":        {func(t *ce.Target) { t.Component += "x" }},
	"Repo":             {func(t *ce.Target) { t.Repo = extract.RepoRef{Key: "github.com/example/other"} }},
	"Form":             {func(t *ce.Target) { t.Form = ce.FormPerLineFile }},
	"Path":             {func(t *ce.Target) { t.Path = "docs/CHANGELOG.md" }},
	"HeadingPattern":   {func(t *ce.Target) { t.HeadingPattern += "x" }},
	"BoundaryPatterns": {func(t *ce.Target) { t.BoundaryPatterns = append(append([]string{}, t.BoundaryPatterns...), `^.*$`) }},
	"InnerPatterns": {
		func(t *ce.Target) { t.InnerPatterns = []ce.InnerPattern{{Pattern: `^Note$`, FirstOnly: true}} },
		func(t *ce.Target) { t.InnerPatterns = []ce.InnerPattern{{Pattern: `^.*$`}} },
	},
	"MaxBytes": {func(t *ce.Target) { t.MaxBytes++ }},
	"MinLocatedNewest": {
		func(t *ce.Target) { t.MinLocatedNewest = 5 },
		func(t *ce.Target) { t.MinLocatedNewest = ce.DefaultMinLocatedNewest },
	},
	"Floor": {func(t *ce.Target) { t.Floor = "1.0" }},
}

// A row that differs from the reviewed one in any field attests nothing.
func TestListedRefusesAnyAlteredField(t *testing.T) {
	typ := reflect.TypeOf(ce.Target{})
	for i := range typ.NumField() {
		name := typ.Field(i).Name
		alts := rowAlterations[name]
		if len(alts) == 0 {
			t.Errorf("field %s has no alteration: compare it in sameTarget and add one", name)
		}
		for n, alter := range alts {
			row := reviewed(t)
			alter(&row)
			if sameTarget(reviewed(t), row) || sameTarget(row, reviewed(t)) {
				t.Errorf("%s #%d: the altered row compares equal", name, n)
			}
			if reviewedRow(row) {
				t.Errorf("%s #%d: the altered row is taken as reviewed", name, n)
			}
			if _, err := NewListed(row); err == nil {
				t.Errorf("%s #%d: an extractor was made for an altered row", name, n)
			}
			if res, err := AttestListed(newListing(nil), row, tags(), pair); res != nil || err == nil {
				t.Errorf("%s #%d: an altered row was attested", name, n)
			}
		}
	}
}

// Inner patterns differ also in FirstOnly and in order; nil and empty do not.
func TestSameTargetInnerPatterns(t *testing.T) {
	a, b := reviewed(t), reviewed(t)
	x, y := ce.InnerPattern{Pattern: `^Note$`, FirstOnly: true}, ce.InnerPattern{Pattern: `^Fixed$`}
	a.InnerPatterns, b.InnerPatterns = []ce.InnerPattern{x, y}, []ce.InnerPattern{x, y}
	if !sameTarget(a, b) {
		t.Fatal("equal rows differ")
	}
	b.InnerPatterns = []ce.InnerPattern{y, x}
	if sameTarget(a, b) {
		t.Error("reordered inner patterns compare equal")
	}
	b.InnerPatterns = []ce.InnerPattern{{Pattern: x.Pattern}, y}
	if sameTarget(a, b) {
		t.Error("a changed FirstOnly compares equal")
	}
	a.InnerPatterns, b.InnerPatterns = nil, []ce.InnerPattern{}
	a.BoundaryPatterns, b.BoundaryPatterns = nil, []string{}
	if !sameTarget(a, b) {
		t.Error("nil and empty lists differ")
	}
}
