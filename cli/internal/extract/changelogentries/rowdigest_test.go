// SPDX-License-Identifier: AGPL-3.0-only

package changelogentries

import (
	"crypto/sha256"
	"encoding/hex"
	"maps"
	"reflect"
	"slices"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/extract"
)

func TestRowDigestGoldenAndSensitive(t *testing.T) {
	base := Target{Component: "notes", Repo: extract.RepoRef{Key: "github.com/example/notes"}, Form: FormFile, Path: "CHANGELOG.md",
		HeadingPattern: `^(?P<version>[0-9]+\.[0-9]+\.[0-9]+)$`, BoundaryPatterns: []string{`^Unreleased$`}}
	const want = "902db864d45b131f13ef3d2724d823476e3f37cabb63bceb53986ab7a4e5a398"
	got := base.RowDigest()
	if got != want {
		t.Fatalf("RowDigest = %s", got)
	}
	for name, mut := range map[string]func(*Target){
		"path":     func(x *Target) { x.Path = "docs/CHANGELOG.md" },
		"heading":  func(x *Target) { x.HeadingPattern = `^v(?P<version>[0-9]+\.[0-9]+\.[0-9]+)$` },
		"boundary": func(x *Target) { x.BoundaryPatterns = []string{`^\[Unreleased\]$`} },
		"repo":     func(x *Target) { x.Repo = extract.RepoRef{Key: "github.com/example/other"} },
		"maxBytes": func(x *Target) { x.MaxBytes = 5 },
	} {
		m := base
		mut(&m)
		if m.RowDigest() == got {
			t.Errorf("%s change did not alter the digest", name)
		}
	}
	a, b := base, base
	a.BoundaryPatterns, b.BoundaryPatterns = nil, []string{}
	if a.RowDigest() != b.RowDigest() {
		t.Error("nil and empty boundary differ")
	}
	a, b = base, base
	a.InnerPatterns, b.InnerPatterns = nil, []InnerPattern{}
	if a.RowDigest() != b.RowDigest() {
		t.Error("nil and empty inner patterns differ")
	}
}

// Every field of a row is part of its digest: each change, from an unset and
// from a set value, gives a digest no other variant has.
func TestRowDigestBindsEveryField(t *testing.T) {
	base := Target{Component: "notes", Repo: extract.RepoRef{Key: "github.com/example/notes"}, Form: FormFile, Path: "CHANGELOG.md",
		HeadingPattern: `^(?P<version>[0-9]+\.[0-9]+\.[0-9]+)$`, BoundaryPatterns: []string{`^Unreleased$`}}
	note := InnerPattern{Pattern: `^Note$`, FirstOnly: true}
	fixed := InnerPattern{Pattern: `^Fixed$`}
	inner := func(p ...InnerPattern) func(*Target) { return func(x *Target) { x.InnerPatterns = p } }
	bar := func(n int) func(*Target) { return func(x *Target) { x.MinLocatedNewest = n } }
	floor := func(f string) func(*Target) { return func(x *Target) { x.Floor = f } }
	variants := map[string]map[string]func(*Target){
		"Component":        {"component": func(x *Target) { x.Component = "other" }},
		"Repo":             {"repo": func(x *Target) { x.Repo = extract.RepoRef{Key: "github.com/example/other"} }},
		"Form":             {"form": func(x *Target) { x.Form = FormPerLineFile }},
		"Path":             {"path": func(x *Target) { x.Path = "docs/CHANGELOG.md" }},
		"HeadingPattern":   {"heading": func(x *Target) { x.HeadingPattern = `^x$` }},
		"BoundaryPatterns": {"boundary": func(x *Target) { x.BoundaryPatterns = []string{`^x$`} }},
		"InnerPatterns": {
			"inner note":           inner(note),
			"inner note not first": inner(InnerPattern{Pattern: note.Pattern}),
			"inner fixed":          inner(fixed),
			"inner both":           inner(note, fixed),
			"inner reordered":      inner(fixed, note),
		},
		"MaxBytes":         {"maxBytes": func(x *Target) { x.MaxBytes = 5 }},
		"MinLocatedNewest": {"bar 5": bar(5), "bar 6": bar(6), "bar 8": bar(8)},
		"Floor":            {"floor 1.0": floor("1.0"), "floor 1.1": floor("1.1")},
	}
	typ := reflect.TypeOf(Target{})
	for i := range typ.NumField() {
		if len(variants[typ.Field(i).Name]) == 0 {
			t.Errorf("field %s has no variant: add it to RowDigest and here", typ.Field(i).Name)
		}
	}
	if n := reflect.TypeOf(InnerPattern{}).NumField(); n != 2 {
		t.Errorf("InnerPattern has %d fields: add the new one to RowDigest and here", n)
	}
	seen := map[string]string{base.RowDigest(): "base"}
	for _, group := range variants {
		for name, mut := range group {
			m := base
			mut(&m)
			d := m.RowDigest()
			if other, dup := seen[d]; dup {
				t.Errorf("%q and %q share a digest", name, other)
			}
			seen[d] = name
		}
	}
}

// The serialized form of a row that sets the optional fields is pinned; the
// golden digest above pins the form without them.
func TestRowDigestOptionalFieldsForm(t *testing.T) {
	row := Target{Component: "notes", Repo: extract.RepoRef{Key: "github.com/example/notes"}, Form: FormFile, Path: "CHANGELOG.md",
		HeadingPattern: `^h$`, BoundaryPatterns: []string{`^b$`},
		InnerPatterns: []InnerPattern{{Pattern: `^Note$`, FirstOnly: true}}, MinLocatedNewest: 6, Floor: "1.2"}
	const form = `{"component":"notes","repo":"github.com/example/notes","form":"changelog-file","path":"CHANGELOG.md",` +
		`"heading":"^h$","boundary":["^b$"],"maxBytes":0,"inner":[{"pattern":"^Note$","firstOnly":true}],"minLocatedNewest":6,"floor":"1.2"}`
	sum := sha256.Sum256([]byte(form))
	if got := row.RowDigest(); got != hex.EncodeToString(sum[:]) {
		t.Fatalf("RowDigest = %s", got)
	}
}

// A re-checked record does not carry over to a row whose inner patterns, bar or
// floor changed, even with the fixture's own row digest left as it was.
func TestRecheckedRecordDoesNotCoverChangedOptionalFields(t *testing.T) {
	rows, digests, fixtures := shipped(t)
	if err := CheckRowsOffline(rows, digests, fixtures, rowsRechecked); err != nil {
		t.Fatal(err)
	}
	for name, mut := range map[string]func(*Target){
		"inner": func(x *Target) { x.InnerPatterns = []InnerPattern{{Pattern: `^Note$`, FirstOnly: true}} },
		"bar":   func(x *Target) { x.MinLocatedNewest = 5 },
		"floor": func(x *Target) { x.Floor = "0.1" },
	} {
		changed := append([]Target(nil), rows...)
		i := slices.IndexFunc(changed, func(r Target) bool { return r.Component == "prometheus" })
		if i < 0 {
			t.Fatal("no prometheus row")
		}
		mut(&changed[i])
		d := maps.Clone(digests)
		d["prometheus"] = changed[i].RowDigest()
		// The old fixture no longer matches the row.
		if err := CheckRowsOffline(changed, d, fixtures, rowsRechecked); err == nil {
			t.Errorf("%s: the old fixture passed for the changed row", name)
		}
		// Nor does the old record cover a fixture edited to the new digest.
		fx := *fixtures["prometheus"]
		fx.RowDigest = d["prometheus"]
		edited := maps.Clone(fixtures)
		edited["prometheus"] = &fx
		if err := CheckRowsOffline(changed, d, edited, rowsRechecked); err == nil {
			t.Errorf("%s: the old re-checked record covered the changed row", name)
		}
	}
}
