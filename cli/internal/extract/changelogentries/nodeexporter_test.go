// SPDX-License-Identifier: AGPL-3.0-only

package changelogentries

import (
	"path/filepath"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/extract"
)

// The fixture holds real excerpts (preamble and first four sections, cut at a
// section boundary) of the upstream CHANGELOG.md read at each tag's commit.
func neRoot() extract.FixtureReader {
	return extract.FixtureReader{Root: filepath.Join("testdata", "fixture-node-exporter")}
}

func neRow(t *testing.T) Target {
	t.Helper()
	row, err := Lookup(Reviewed, "node_exporter")
	if err != nil {
		t.Fatal(err)
	}
	return row
}

func TestNodeExporterRowIsPinned(t *testing.T) {
	row := neRow(t)
	if row.Repo.Key != "github.com/prometheus/node_exporter" || row.Form != FormFile || row.Path != "CHANGELOG.md" {
		t.Fatalf("row %+v", row)
	}
	if _, err := row.compile(); err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, x := range Reviewed {
		if x.Component == "node_exporter" {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("%d rows", n)
	}
}

func TestNodeExporterRealTags(t *testing.T) {
	row, r := neRow(t), neRoot()
	for _, name := range []string{"v1.0.0", "v1.5.0", "v1.8.2", "v1.12.1"} {
		tag := fixtureTag(t, r, row, name)
		e, err := Locate(r, row, tag)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if e.Version != name[1:] || len(e.Items) == 0 {
			t.Fatalf("%s: version %q, %d items", name, e.Version, len(e.Items))
		}
		m, err := BuildManifest(r, row, tag, "sha256:test")
		if err != nil || m.Entry == nil || m.Withheld != nil || m.Entry.Tag != name {
			t.Fatalf("%s: manifest %+v, %v", name, m, err)
		}
	}
}

// The release candidate heading and the unreleased heading are boundaries:
// neither names an entry, whatever tag is asked for.
func TestNodeExporterRcAndUnreleasedNameNoEntry(t *testing.T) {
	row, r := neRow(t), neRoot()
	rc := fixtureTag(t, r, row, "v1.0.0-rc.0")
	_, err := Locate(r, row, rc)
	wantCode(t, err, EntryNotFinal)
	// The rc file holds "1.0.0-rc.0 / ..." and "master / unreleased" only; the
	// final tag's name must not resolve to either (the reader withholds it).
	_, err = Locate(r, row, extract.Tag{Name: "v1.0.0", Commit: rc.Commit})
	wantCode(t, err, EntryNotFinal)
	_, err = Locate(r, row, extract.Tag{Name: "master", Commit: rc.Commit})
	wantCode(t, err, EntryNotFinal)
	m, err := BuildManifest(r, row, rc, "sha256:test")
	if err != nil || m.Entry != nil || m.Withheld == nil || m.Withheld.Code != EntryNotFinal {
		t.Fatalf("manifest %+v, %v", m, err)
	}
}
