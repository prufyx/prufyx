// SPDX-License-Identifier: AGPL-3.0-only

package changelogentries

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/extract"
)

var snapshotterTarget = Target{
	Component: "external-snapshotter", Repo: extract.RepoRef{Key: "github.com/kubernetes-csi/external-snapshotter"},
	Form: FormPerLineFile, Path: "CHANGELOG/CHANGELOG-{line}.md",
	HeadingPattern:   `^v(?P<version>[0-9]+\.[0-9]+\.[0-9]+)$`,
	BoundaryPatterns: []string{`^v[0-9]+\.[0-9]+\.[0-9]+-(rc|alpha|beta)\.[0-9]+$`},
}

var perVersionTarget = Target{
	Component: "notes", Repo: extract.RepoRef{Key: "github.com/example/notes"},
	Form: FormPerVersionFile, Path: "docs/release-notes/{version}.md",
}

const perLineFile = "# v3.5.1\n\n## Changes\n\n- fix a\n- fix b\n\n# v3.5.0\n\n## Changes\n\n- first\n"

func locateAt(t Target, tag, resolved string, file []byte) (*Entry, error) {
	r := &memReader{files: map[string][]byte{t.Repo.Key + "@" + testCommit + ":" + resolved: file}}
	return Locate(r, t, extract.Tag{Name: tag, Commit: testCommit})
}

func TestPerLineFile(t *testing.T) {
	e, err := locateAt(snapshotterTarget, "v3.5.1", "CHANGELOG/CHANGELOG-3.5.md", []byte(perLineFile))
	if err != nil {
		t.Fatal(err)
	}
	if e.Source.Path != "CHANGELOG/CHANGELOG-3.5.md" || e.Source.Form != FormPerLineFile || e.Version != "3.5.1" || len(e.Items) != 2 {
		t.Fatalf("unexpected entry %+v", e)
	}
	// Same bytes through the single-file form give the same proof but for the form.
	single := snapshotterTarget
	single.Form, single.Path = FormFile, "CHANGELOG/CHANGELOG-3.5.md"
	e2, err := locateAt(single, "v3.5.1", single.Path, []byte(perLineFile))
	if err != nil {
		t.Fatal(err)
	}
	e2.Source.Form = FormPerLineFile
	a, _ := e.Canonical()
	b, _ := e2.Canonical()
	if !bytes.Equal(a, b) {
		t.Fatal("per-line entry differs from the single-file entry")
	}
	e3, _ := locateAt(snapshotterTarget, "v3.5.1", "CHANGELOG/CHANGELOG-3.5.md", []byte(perLineFile))
	c, _ := e3.Canonical()
	if !bytes.Equal(a, c) {
		t.Fatal("not deterministic")
	}
}

func TestPerLineFileNegatives(t *testing.T) {
	good := []byte(perLineFile)
	// wrong line file: the tag's line file only holds another line
	_, err := locateAt(snapshotterTarget, "v3.5.1", "CHANGELOG/CHANGELOG-3.4.md", good)
	wantCode(t, err, PathMissingAtTag)
	// right file name, but the version is not in it
	_, err = locateAt(snapshotterTarget, "v3.5.9", "CHANGELOG/CHANGELOG-3.5.md", good)
	wantCode(t, err, EntryMissing)
	// release candidate tag
	_, err = locateAt(snapshotterTarget, "v3.5.1-rc.1", "CHANGELOG/CHANGELOG-3.5.md", good)
	wantCode(t, err, EntryNotFinal)
	// 3.50 is not 3.5
	_, err = locateAt(snapshotterTarget, "v3.50.0", "CHANGELOG/CHANGELOG-3.5.md", good)
	wantCode(t, err, PathMissingAtTag)
	// CRLF throughout is read as LF; mixed is refused
	crlf := []byte(strings.ReplaceAll(perLineFile, "\n", "\r\n"))
	if _, err = locateAt(snapshotterTarget, "v3.5.1", "CHANGELOG/CHANGELOG-3.5.md", crlf); err != nil {
		t.Fatal(err)
	}
	mixed := []byte("# v3.5.1\r\n\n- a\n")
	_, err = locateAt(snapshotterTarget, "v3.5.1", "CHANGELOG/CHANGELOG-3.5.md", mixed)
	wantCode(t, err, EntryParseResidue)
	// residue
	_, err = locateAt(snapshotterTarget, "v3.5.1", "CHANGELOG/CHANGELOG-3.5.md", []byte("# v3.5.1\n\n---\n\n- a\n"))
	wantCode(t, err, EntryParseResidue)
	// empty file, empty entry
	_, err = locateAt(snapshotterTarget, "v3.5.1", "CHANGELOG/CHANGELOG-3.5.md", nil)
	wantCode(t, err, EntryMissing)
	_, err = locateAt(snapshotterTarget, "v3.5.1", "CHANGELOG/CHANGELOG-3.5.md", []byte("# v3.5.1\n"))
	wantCode(t, err, EntryEmpty)
	// referral only
	_, err = locateAt(snapshotterTarget, "v3.5.1", "CHANGELOG/CHANGELOG-3.5.md", []byte("# v3.5.1\n\n- See https://example.com/notes\n"))
	wantCode(t, err, EntryRefersElsewhere)
	// over bound
	small := snapshotterTarget
	small.MaxBytes = 10
	_, err = locateAt(small, "v3.5.1", "CHANGELOG/CHANGELOG-3.5.md", good)
	wantCode(t, err, EntryOverBound)
	// missing file reader error is not a reason
	r := &memReader{err: errors.New("boom")}
	_, err = Locate(r, snapshotterTarget, extract.Tag{Name: "v3.5.1", Commit: testCommit})
	if _, ok := CodeOf(err); ok || err == nil {
		t.Fatalf("read error must stay untyped, got %v", err)
	}
}

func TestPerVersionFile(t *testing.T) {
	file := "## Highlights\n\n- one\n- two\n\n## Fixes\n\n- three\n\n"
	e, err := locateAt(perVersionTarget, "v2.5.0", "docs/release-notes/2.5.0.md", []byte(file))
	if err != nil {
		t.Fatal(err)
	}
	if e.Source.Path != "docs/release-notes/2.5.0.md" || e.Source.Form != FormPerVersionFile || len(e.Items) != 3 ||
		e.Section.StartLine != 1 || e.Section.EndLine != 8 || e.ResidueLines != 0 {
		t.Fatalf("unexpected entry %+v", e)
	}
	if got := e.Tiling.Headings + e.Tiling.Blanks + e.Tiling.LinkDefs + e.Tiling.ItemLines; got != e.Tiling.Lines || e.Tiling.Lines != 8 {
		t.Fatalf("tiling does not add up: %+v", e.Tiling)
	}
	if e.Items[2].HeadingPath[0] != "Fixes" {
		t.Fatalf("heading path %v", e.Items[2].HeadingPath)
	}
	// determinism, and CRLF equals LF content
	a, _ := e.Canonical()
	e2, _ := locateAt(perVersionTarget, "v2.5.0", "docs/release-notes/2.5.0.md", []byte(file))
	b, _ := e2.Canonical()
	if !bytes.Equal(a, b) {
		t.Fatal("not deterministic")
	}
	if _, err = locateAt(perVersionTarget, "2.5.0", "docs/release-notes/2.5.0.md", []byte(strings.ReplaceAll(file, "\n", "\r\n"))); err != nil {
		t.Fatal(err)
	}
	// a manifest round trip
	m, err := BuildManifest(&memReader{files: map[string][]byte{perVersionTarget.Repo.Key + "@" + testCommit + ":docs/release-notes/2.5.0.md": []byte(file)}},
		perVersionTarget, extract.Tag{Name: "v2.5.0", Commit: testCommit}, "d")
	if err != nil || m.Entry == nil {
		t.Fatalf("manifest: %v", err)
	}
}

func TestPerVersionFileNegatives(t *testing.T) {
	good := []byte("- one\n")
	const f25 = "docs/release-notes/2.5.0.md"
	// 2.5.0 is not 2.50.0 in either direction
	_, err := locateAt(perVersionTarget, "v2.50.0", f25, good)
	wantCode(t, err, PathMissingAtTag)
	_, err = locateAt(perVersionTarget, "v2.5.0", "docs/release-notes/2.50.0.md", good)
	wantCode(t, err, PathMissingAtTag)
	// release candidate
	_, err = locateAt(perVersionTarget, "v2.5.0-rc.1", f25, good)
	wantCode(t, err, EntryNotFinal)
	_, err = locateAt(perVersionTarget, "v2.5", f25, good)
	wantCode(t, err, EntryNotFinal)
	// missing at the tag
	_, err = locateAt(perVersionTarget, "v2.5.0", "elsewhere.md", good)
	wantCode(t, err, PathMissingAtTag)
	// empty, blank-only
	for _, b := range [][]byte{nil, []byte("\n\n  \n")} {
		_, err = locateAt(perVersionTarget, "v2.5.0", f25, b)
		wantCode(t, err, EntryEmpty)
	}
	// headings only: no item
	_, err = locateAt(perVersionTarget, "v2.5.0", f25, []byte("## Fixes\n"))
	wantCode(t, err, EntryEmpty)
	// referral only
	_, err = locateAt(perVersionTarget, "v2.5.0", f25, []byte("See the website.\n"))
	wantCode(t, err, EntryRefersElsewhere)
	_, err = locateAt(perVersionTarget, "v2.5.0", f25, []byte("- [notes](https://example.com/a)\n"))
	wantCode(t, err, EntryRefersElsewhere)
	// residue: thematic break, unowned indented line, open fence, mixed newlines, BOM
	for _, s := range []string{"- a\n\n---\n", "    stray\n\n- a\n", "- a\n\n```\nnever closed\n", "- a\r\n- b\n", "\xef\xbb\xbf- a\n", "- a\x00\n"} {
		_, err = locateAt(perVersionTarget, "v2.5.0", f25, []byte(s))
		wantCode(t, err, EntryParseResidue)
	}
	// over bound: bytes and lines
	small := perVersionTarget
	small.MaxBytes = 4
	_, err = locateAt(small, "v2.5.0", f25, good)
	wantCode(t, err, EntryOverBound)
	_, err = locateAt(perVersionTarget, "v2.5.0", f25, []byte(strings.Repeat("- x\n", MaxSectionLines+1)))
	wantCode(t, err, EntryOverBound)
	if _, err = locateAt(perVersionTarget, "v2.5.0", f25, []byte(strings.Repeat("- x\n", MaxSectionLines))); err != nil {
		t.Fatal(err)
	}
	// bad commit
	_, err = Locate(&memReader{}, perVersionTarget, extract.Tag{Name: "v2.5.0", Commit: "abc"})
	wantCode(t, err, SourceNotPinnedGit)
	// patterns have no place on a per-version row
	p := perVersionTarget
	p.HeadingPattern = `^(?P<version>x)$`
	_, err = locateAt(p, "v2.5.0", f25, good)
	wantCode(t, err, NoChangelogTarget)
	// no read happens on a refused template
	r := &memReader{}
	bad := perVersionTarget
	bad.Path = "../{version}.md"
	_, err = Locate(r, bad, extract.Tag{Name: "v2.5.0", Commit: testCommit})
	wantCode(t, err, NoChangelogTarget)
	if r.reads != 0 {
		t.Fatal("a refused template must not read")
	}
}

func TestShapeTemplatesRefused(t *testing.T) {
	cases := []struct {
		form, path string
	}{
		{FormPerLineFile, "CHANGELOG/CHANGELOG-{version}.md"}, // wrong placeholder for the form
		{FormPerVersionFile, "notes/{line}.md"},
		{FormPerLineFile, "CHANGELOG/CHANGELOG-{toLine}.md"}, // unknown placeholder
		{FormPerVersionFile, "notes/{version}-{other}.md"},
		{FormPerVersionFile, "notes/{major}.md"},
		{FormPerLineFile, "CHANGELOG/CHANGELOG.md"}, // no placeholder
		{FormPerVersionFile, "notes/{version}-{version}.md"},
		{FormPerLineFile, "../CHANGELOG-{line}.md"},
		{FormPerLineFile, "a/../CHANGELOG-{line}.md"},
		{FormPerVersionFile, "notes/{version}/../x.md"},
		{FormPerVersionFile, "notes/..{version}.md"},
		{FormPerVersionFile, "/etc/{version}.md"},
		{FormPerVersionFile, "{version}/notes.md"[:0] + "notes//{version}.md"},
		{FormPerVersionFile, "notes/{version}/"},
		{FormPerVersionFile, "notes//{version}.md"},
		{FormPerVersionFile, ""},
		{FormPerVersionFile, "notes/./{version}.md"},
		{FormPerVersionFile, "{version}"},            // placeholder alone in its element
		{FormPerVersionFile, "notes/{version}/x.md"}, // alone in a directory element
		{FormPerVersionFile, "notes\\{version}.md"},
		{FormPerVersionFile, "notes/{version.md"},
		{FormPerVersionFile, "notes/version}.md"},
		{FormPerVersionFile, "notes/\x00{version}.md"},
		{FormPerVersionFile, "notes/${version}.md"},
	}
	for _, c := range cases {
		tg := perVersionTarget
		tg.Form, tg.Path = c.form, c.path
		tg.HeadingPattern, tg.BoundaryPatterns = "", nil
		if c.form == FormPerLineFile {
			tg.HeadingPattern = snapshotterTarget.HeadingPattern
		}
		r := &memReader{}
		_, err := Locate(r, tg, extract.Tag{Name: "v3.5.1", Commit: testCommit})
		if got, ok := CodeOf(err); !ok || got != NoChangelogTarget {
			t.Errorf("%s %q: want NO_CHANGELOG_TARGET, got %v", c.form, c.path, err)
		}
		if r.reads != 0 {
			t.Errorf("%s %q: read before refusing", c.form, c.path)
		}
	}
}

func TestShapeTemplatesAccepted(t *testing.T) {
	for _, c := range []struct{ form, tpl, ph string }{
		{FormPerLineFile, "CHANGELOG/CHANGELOG-{line}.md", placeholderLine},
		{FormPerVersionFile, "docs/release-notes/{version}.md", placeholderVersion},
		{FormPerVersionFile, "docs/v{version}/notes.md", placeholderVersion},
	} {
		if err := checkTemplate(c.tpl, c.ph); err != nil {
			t.Errorf("%q: %v", c.tpl, err)
		}
	}
}

func TestExistingFormsStillRefuseNewFormsByDefault(t *testing.T) {
	_, err := locateBytes(Target{Component: "x", Repo: extract.RepoRef{Key: "github.com/a/b"}, Form: "changelog-per-whatever", Path: "x"}, "v1.0.0", []byte("- a\n"))
	wantCode(t, err, ShapeNotPerTag)
}
