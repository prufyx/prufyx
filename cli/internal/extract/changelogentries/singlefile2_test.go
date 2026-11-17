// SPDX-License-Identifier: AGPL-3.0-only

package changelogentries

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/extract"
)

// The fixture holds real excerpts of each upstream CHANGELOG.md read at the
// tag's commit (the preamble, the sections above the tag's entry, the entry
// and the one release section after it; see
// testdata/fixture-single-file-2/PROVENANCE.json). Every final tag of the last
// six minor lines of each repository was also read in full through the reader
// and located with no residue and no withheld code; the item counts below are
// those of the full files.
func sf2Root() extract.FixtureReader {
	return extract.FixtureReader{Root: filepath.Join("testdata", "fixture-single-file-2")}
}

var singleFile2Rows = []struct {
	component, repo string
	tags            map[string]int // tag -> items
}{
	{"blackbox_exporter", "github.com/prometheus/blackbox_exporter", map[string]int{
		"v0.24.0": 3, "v0.26.0": 11, "v0.28.0": 14, "v0.29.0": 11, "v0.29.1": 5,
	}},
	{"openfga", "github.com/openfga/openfga", map[string]int{
		"v1.17.0": 2, "v1.18.3": 1, "v1.20.0": 4, "v1.22.0": 4, "v1.22.1": 4,
	}},
	{"in-toto", "github.com/in-toto/in-toto", map[string]int{
		"v2.0.0": 13, "v2.1.1": 2, "v2.2.0": 18, "v3.0.0": 3, "v3.1.0": 6,
	}},
	{"fluentd", "github.com/fluent/fluentd", map[string]int{
		"v1.15.0": 15, "v1.16.0": 20, "v1.16.9": 2, "v1.19.0": 42, "v1.20.1": 1,
	}},
	// jaeger: the fixture is structure-preserving, not byte-verbatim (see
	// PROVENANCE.json and TestJaegerFixtureIsStructural); the item counts are
	// those of the real upstream files, read through the reader at each tag.
	{"jaeger", "github.com/jaegertracing/jaeger", map[string]int{
		"v2.18.0": 96, "v2.20.0": 123, "v2.22.0": 105, "v2.23.0": 132,
	}},
}

func TestBatch2RowsArePinned(t *testing.T) {
	for _, w := range singleFile2Rows {
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
	// No component has two rows, whichever batch they come from.
	seen := map[string]bool{}
	for _, x := range Reviewed {
		if seen[x.Component] {
			t.Fatalf("component %s has more than one row", x.Component)
		}
		seen[x.Component] = true
	}
	// Projects whose window has a tag that does not locate, or whose file
	// does not hold the tag's own entry, carry no row.
	for _, c := range []string{
		"spire", "loki", "cubefs", "dragonfly", "postgres_exporter", "kube-state-metrics",
		"oauth2-proxy", "aws-ebs-csi-driver", "harbor", "hami", "nfs-subdir-external-provisioner",
	} {
		if _, err := Lookup(Reviewed, c); err == nil {
			t.Fatalf("%s must have no reviewed row", c)
		}
	}
}

// Each row is re-derived against the pinned bytes: the entry is the tag's own,
// the tiling has no residue and the manifest carries an entry, not a reason.
func TestBatch2RowsRederive(t *testing.T) {
	r := sf2Root()
	for _, w := range singleFile2Rows {
		row, err := Lookup(Reviewed, w.component)
		if err != nil {
			t.Fatal(err)
		}
		for name, items := range w.tags {
			tag := fixtureTag(t, r, row, name)
			e, err := Locate(r, row, tag)
			if err != nil {
				t.Fatalf("%s %s: %v", w.component, name, err)
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

// A tag the file does not name, a release heading in another wording and an
// unlisted heading between sections are all refused, never passed.
func TestBatch2RowsRefuse(t *testing.T) {
	look := func(c string) Target {
		row, err := Lookup(Reviewed, c)
		if err != nil {
			t.Fatal(err)
		}
		return row
	}
	bb, of, it, fl, jg := look("blackbox_exporter"), look("openfga"), look("in-toto"), look("fluentd"), look("jaeger")
	pre := "# Changelog\n\n"

	// blackbox_exporter: the unreleased heading is a boundary, never an entry;
	// the spelling of another project is no boundary.
	bbFinal := "## 0.29.0 / 2026-10-07\n\n* [CHANGE] y\n\n"
	_, err := locateMem(bb, "main", pre+"## master / unreleased\n\n* [CHANGE] x\n\n"+bbFinal)
	wantCode(t, err, EntryNotFinal)
	_, err = locateMem(bb, "v0.30.0", pre+"## master / unreleased\n\n* [CHANGE] x\n\n"+bbFinal)
	wantCode(t, err, EntryMissing)
	_, err = locateMem(bb, "v0.29.0", pre+bbFinal+"## main / (unreleased)\n\n* [CHANGE] x\n\n## 0.28.0 / 2025-12-04\n\n* [CHANGE] w\n")
	wantCode(t, err, EntryBoundaryUnproven)
	_, err = locateMem(bb, "v0.29.0", pre+bbFinal+"## 0.29.0-rc.0 / 2026-09-01\n\n* [CHANGE] q\n\n## 0.28.0 / 2025-12-04\n\n* [CHANGE] w\n")
	wantCode(t, err, EntryDuplicate) // an rc of the same version is another wording, never a pass

	// openfga: a dateless or rc heading is no final heading; an unlisted
	// heading after the entry leaves its end unproven.
	ofFinal := "## [1.22.1] - 2026-10-27\n### Changed\n- a\n\n"
	_, err = locateMem(of, "v1.23.0", pre+"## [Unreleased]\n\n"+ofFinal)
	wantCode(t, err, EntryMissing)
	_, err = locateMem(of, "v1.22.1", pre+ofFinal+"## [1.22.0-rc.1] - 2026-10-01\n### Added\n- b\n\n## [1.22.0] - 2026-10-06\n### Added\n- c\n")
	wantCode(t, err, EntryBoundaryUnproven)
	_, err = locateMem(of, "v1.22.1", pre+"## [1.22.1] - TBD\n- a\n\n## [1.22.0] - 2026-10-06\n- c\n")
	wantCode(t, err, EntryNotFinal)

	// in-toto: the same version under another wording is a duplicate.
	_, err = locateMem(it, "v3.1.0", pre+"## v3.1.0\n\n### Changed\n\n- a\n\n## v3.1.0-rc1\n\n- b\n")
	wantCode(t, err, EntryDuplicate)
	_, err = locateMem(it, "v3.2.0", pre+"## v3.1.0\n\n### Changed\n\n- a\n")
	wantCode(t, err, EntryMissing)

	// fluentd: a release heading without a date is no final heading, and an
	// unlisted group heading leaves the end unproven.
	flRel := "## Release v1.20.1 - 2026/10/26\n\n### Bug Fix\n\n* a\n\n"
	_, err = locateMem(fl, "v1.20.1", pre+"# v1.20\n\n"+"## Release v1.20.1\n\n### Bug Fix\n\n* a\n\n")
	wantCode(t, err, EntryNotFinal)
	_, err = locateMem(fl, "v1.20.1", pre+"# v1.20\n\n"+flRel+"# Notes\n\n## Release v1.20.0 - 2026/10/23\n\n* b\n")
	wantCode(t, err, EntryBoundaryUnproven)

	// jaeger: a version heading without a date is no final heading, the
	// unreleased template is no entry, and an rc of the same version is
	// another wording, never a pass.
	jgFinal := "v2.23.0 (2026-11-04)\n-------------------------------\n\n### Backend Changes\n\n* a\n\n"
	_, err = locateMem(jg, "v2.23.0", pre+"v2.23.0\n-------------------------------\n\n* a\n\nv2.22.0 (2026-10-05)\n-------------------------------\n\n* c\n")
	wantCode(t, err, EntryNotFinal)
	_, err = locateMem(jg, "v2.24.0", pre+jgFinal)
	wantCode(t, err, EntryMissing)
	_, err = locateMem(jg, "v2.23.0", pre+jgFinal+"v2.23.0-rc1 (2026-10-30)\n-------------------------------\n\n* b\n\nv2.22.0 (2026-10-05)\n-------------------------------\n\n* c\n")
	wantCode(t, err, EntryDuplicate)
}

// The jaeger fixture files must say they are structure-preserving, carry an
// upstream commit per tag that matches tags.json, and hold no upstream item
// text: every item line is the placeholder.
func TestJaegerFixtureIsStructural(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "fixture-single-file-2", "PROVENANCE.json"))
	if err != nil {
		t.Fatal(err)
	}
	var prov struct {
		Files []struct {
			Repo, Tag, Commit, Fidelity, ExcerptSha256 string
		}
	}
	if err := json.Unmarshal(raw, &prov); err != nil {
		t.Fatal(err)
	}
	r := sf2Root()
	row, err := Lookup(Reviewed, "jaeger")
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, f := range prov.Files {
		if f.Repo != row.Repo.Key {
			if f.Fidelity != "" {
				t.Fatalf("%s %s: unexpected fidelity %q", f.Repo, f.Tag, f.Fidelity)
			}
			continue
		}
		n++
		if f.Fidelity != "structure-preserving" {
			t.Fatalf("%s: fidelity %q", f.Tag, f.Fidelity)
		}
		if tag := fixtureTag(t, r, row, f.Tag); tag.Commit != f.Commit {
			t.Fatalf("%s: commit %s, tags.json %s", f.Tag, f.Commit, tag.Commit)
		}
		b, err := os.ReadFile(filepath.Join("testdata", "fixture-single-file-2", filepath.FromSlash(row.Repo.Key), "commits", f.Commit, "CHANGELOG.md"))
		if err != nil {
			t.Fatal(err)
		}
		if got := fmt.Sprintf("%x", sha256.Sum256(b)); got != f.ExcerptSha256 {
			t.Fatalf("%s: sha256 %s, provenance %s", f.Tag, got, f.ExcerptSha256)
		}
		for i, l := range strings.Split(string(b), "\n") {
			if m := itemLineRE.FindStringSubmatch(l); m != nil && !strings.HasPrefix(m[3], "placeholder item ") {
				t.Fatalf("%s line %d: item text is not a placeholder: %q", f.Tag, i+1, l)
			}
		}
	}
	if n != 4 {
		t.Fatalf("%d jaeger provenance entries, want 4", n)
	}
}

var itemLineRE = regexp.MustCompile(`^(\s*)([*+-]|[0-9]{1,9}[.)])[ \t]+(.*)$`)
