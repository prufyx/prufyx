// SPDX-License-Identifier: AGPL-3.0-only

package changelogentries

import (
	"path/filepath"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/extract"
)

// The fixture holds real excerpts (preamble and first four sections, cut at a
// section boundary) of each upstream CHANGELOG.md read at the tag's commit;
// see testdata/fixture-single-file/PROVENANCE.json. Every tag of the review
// window was also read in full through the reader and located with no
// residue and no withheld code; the item counts below are those of the full
// files.
func sfRoot() extract.FixtureReader {
	return extract.FixtureReader{Root: filepath.Join("testdata", "fixture-single-file")}
}

var singleFileRows = []struct {
	component, repo string
	tags            map[string]int // tag -> items
}{
	{"prometheus", "github.com/prometheus/prometheus", map[string]int{
		"v3.13.5": 5, "v3.15.0": 80, "v3.16.0": 85,
	}},
	{"alertmanager", "github.com/prometheus/alertmanager", map[string]int{
		"v0.30.0": 42, "v0.32.0": 35, "v0.34.0": 17, "v0.34.2": 2, "v0.35.0": 56,
	}},
}

func TestSingleFileRowsArePinned(t *testing.T) {
	for _, w := range singleFileRows {
		n := 0
		for _, x := range Reviewed {
			if x.Component == w.component {
				n++
			}
		}
		if n != 1 {
			t.Fatalf("%s: %d rows", w.component, n)
		}
		row, err := Lookup(Reviewed, w.component)
		if err != nil {
			t.Fatal(err)
		}
		if row.Repo.Key != w.repo || row.Form != FormFile || row.Path != "CHANGELOG.md" {
			t.Fatalf("%s: row %+v", w.component, row)
		}
		if _, err := row.compile(); err != nil {
			t.Fatal(err)
		}
	}
	// Projects whose window has a tag that does not locate carry no row.
	for _, c := range []string{"thanos", "cortex"} {
		if _, err := Lookup(Reviewed, c); err == nil {
			t.Fatalf("%s must have no reviewed row", c)
		}
	}
}

// Each row is re-derived against the pinned bytes: the entry is the tag's own,
// the tiling has no residue and the manifest carries an entry, not a reason.
func TestSingleFileRowsRederive(t *testing.T) {
	r := sfRoot()
	for _, w := range singleFileRows {
		row, err := Lookup(Reviewed, w.component)
		if err != nil {
			t.Fatal(err)
		}
		for name, items := range w.tags {
			tag := fixtureTag(t, r, row, name)
			e, err := Locate(r, row, tag)
			if err != nil {
				t.Errorf("%s %s: %v", w.component, name, err)
				continue
			}
			if e.Version != name[1:] || len(e.Items) != items {
				t.Fatalf("%s %s: version %q, %d items, want %d", w.component, name, e.Version, len(e.Items), items)
			}
			if e.ResidueLines != 0 {
				t.Fatalf("%s %s: residue %d", w.component, name, e.ResidueLines)
			}
			m, err := BuildManifest(r, row, tag, "sha256:test")
			if err != nil || m.Entry == nil || m.Withheld != nil || m.Entry.Tag != name {
				t.Fatalf("%s %s: manifest %+v, %v", w.component, name, m, err)
			}
		}
	}
}

// The independent CommonMark parser reads these files differently from the
// scanner somewhere in the whole file. The disagreement lies below the heading
// that follows the entry, outside the checked prefix: the entry is read and
// its manifest records the scoped length, which is shorter than the blob.
func TestSingleFileRowScopedPastCommonMarkDisagreement(t *testing.T) {
	r := sfRoot()
	row, err := Lookup(Reviewed, "prometheus")
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"v3.11.0", "v3.11.1"} {
		tag := fixtureTag(t, r, row, name)
		raw, err := r.Read(row.Repo, tag.Commit, row.Path)
		if err != nil {
			t.Fatal(err)
		}
		lines, err := splitLines(raw)
		if err != nil {
			t.Fatal(err)
		}
		if cmDisagreement(lines, scan(lines), 0, 0) == "" {
			t.Fatalf("%s: the whole file no longer disagrees: the test shape is void", name)
		}
		m, err := BuildManifest(r, row, tag, "sha256:test")
		if err != nil || m.Entry == nil || m.Withheld != nil {
			t.Fatalf("%s: %+v, %v", name, m, err)
		}
		if cb := m.Entry.Source.CheckedBytes; cb <= 0 || cb >= len(raw) {
			t.Fatalf("%s: checkedBytes %d of %d", name, cb, len(raw))
		}
	}
}

// The unreleased heading is a boundary and never names an entry; a heading
// that is neither final nor a listed boundary leaves the end unproven; a
// release candidate or dateless heading is no final heading.
func TestSingleFileRowsRefuse(t *testing.T) {
	pr, err := Lookup(Reviewed, "prometheus")
	if err != nil {
		t.Fatal(err)
	}
	am, err := Lookup(Reviewed, "alertmanager")
	if err != nil {
		t.Fatal(err)
	}
	pre := "# Changelog\n\n"
	unreleased := "## main / unreleased\n\n* [CHANGE] x\n\n"
	final := "## 3.16.0 / 2026-11-04\n\n* [CHANGE] y\n\n"

	// Ask for the unreleased section's name and for a version only listed
	// as unreleased.
	_, err = locateMem(pr, "main", pre+unreleased+final)
	wantCode(t, err, EntryNotFinal)
	_, err = locateMem(pr, "v3.17.0", pre+unreleased+final)
	wantCode(t, err, EntryMissing)

	// Dateless, rc and wrong-separator headings are not final headings.
	for _, h := range []string{"## 3.17.0 / TBD\n", "## 3.17.0-rc.0 / 2026-12-01\n", "## 3.17.0 - 2026-12-01\n", "## 3.17.0 / 2026-12-01 (draft)\n"} {
		_, err = locateMem(pr, "v3.17.0", pre+h+"\n* [CHANGE] z\n\n"+final)
		if c, ok := CodeOf(err); !ok || (c != EntryMissing && c != EntryNotFinal) {
			t.Fatalf("%q: %v", h, err)
		}
	}

	// A heading between sections that is not final and not a boundary
	// leaves the end of the section before it unproven.
	_, err = locateMem(pr, "v3.16.0", pre+final+"## 3.15.0-rc.0 / 2026-09-01\n\n* [CHANGE] q\n\n## 3.15.0 / 2026-09-24\n\n* [CHANGE] w\n")
	wantCode(t, err, EntryBoundaryUnproven)
	_, err = locateMem(am, "v0.36.0", pre+"## 0.36.0 / 2026-12-01\n\n* [CHANGE] a\n\n## 0.37.0-beta.0 / 2026-11-20\n\n* [CHANGE] b\n")
	wantCode(t, err, EntryBoundaryUnproven)
	// The same version under another wording is a duplicate, never a pass.
	_, err = locateMem(am, "v0.36.0", pre+"## 0.36.0 / 2026-12-01\n\n* [CHANGE] a\n\n## 0.36.0-beta.0 / 2026-11-20\n\n* [CHANGE] b\n")
	wantCode(t, err, EntryDuplicate)

	// The alertmanager unreleased spelling is not the prometheus one.
	_, err = locateMem(am, "v0.36.0", pre+"## main / (unreleased)\n\n* [CHANGE] a\n\n## 0.35.0 / 2026-11-09\n\n* [CHANGE] b\n")
	wantCode(t, err, EntryMissing)
}
