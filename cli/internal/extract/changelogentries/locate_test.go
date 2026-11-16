// SPDX-License-Identifier: AGPL-3.0-only

package changelogentries

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/extract"
)

const promFile = "# Changelog\n\n## main / unreleased\n\n## 3.5.0 / 2025-07-14\n\n" +
	"* [FEATURE] A: add `a`. #1\n* [CHANGE] B: remove flag `--b`. #2\n  continued line\n" +
	"* [BUGFIX] C. #3\n\n## 3.4.0 / 2025-05-17\n\n* [FEATURE] D. #4\n"

func TestLocateBasic(t *testing.T) {
	e := mustLocate(t, promTarget, "v3.5.0", promFile)
	if e.Version != "3.5.0" || e.Section.HeadingLine != 5 || e.Section.EndLine != 10 {
		t.Fatalf("bounds: %+v", e.Section)
	}
	if len(e.Items) != 3 || e.Items[1].Marker != "CHANGE" || e.Items[1].StartLine != 8 || e.Items[1].EndLine != 9 {
		t.Fatalf("items: %+v", e.Items)
	}
	if e.ResidueLines != 0 || e.Tiling.Lines != 6 || e.Tiling.Headings != 1 || e.Tiling.Blanks != 1 || e.Tiling.ItemLines != 4 {
		t.Fatalf("tiling: %+v", e.Tiling)
	}
	if e.Source.Commit != testCommit || e.TagCommit != testCommit || e.Source.Form != FormFile {
		t.Fatalf("source: %+v", e.Source)
	}
	// The last entry of a file ends at end of file.
	last := mustLocate(t, promTarget, "3.4.0", promFile)
	if last.Section.EndLine != 14 || len(last.Items) != 1 {
		t.Fatalf("last: %+v", last.Section)
	}
	// No final newline is the same entry.
	again := mustLocate(t, promTarget, "3.4.0", strings.TrimSuffix(promFile, "\n"))
	if again.Section.Digest != last.Section.Digest || again.Items[0].Digest != last.Items[0].Digest {
		t.Fatal("a missing final newline changed the digests")
	}
}

func TestItemDigestBindsHeadingPath(t *testing.T) {
	a := mustLocate(t, thanosTarget, "v0.38.0", thanosFile("### Fixed", "### Added", "- [#1](u) same text"))
	b := mustLocate(t, thanosTarget, "v0.38.0", thanosFile("### Added", "### Fixed", "- [#1](u) same text"))
	if a.Items[1].Digest == b.Items[1].Digest {
		t.Fatal("moving an item under another heading kept its digest")
	}
	if got := strings.Join(a.Items[1].HeadingPath, "|"); got != "Added" {
		t.Fatalf("heading path %q", got)
	}
}

// thanosFile has two sub-headings; the item sits under the second one.
func thanosFile(h1, h2, item string) string {
	return "# Changelog\n\n## Unreleased\n\n## [v0.38.0](https://x/tree/release-0.38) - 03.04.2025\n\n" +
		h1 + "\n\n- [#9](u) other\n\n" + h2 + "\n\n" + item + "\n\n## [v0.37.2](https://x/tree/release-0.37) - 11.12.2024\n\n### Fixed\n\n- [#2](u) y\n"
}

func TestDuplicateHeading(t *testing.T) {
	f := promFile + "\n## 3.5.0 / 2025-08-01\n\n* [BUGFIX] again. #9\n"
	_, err := locateMem(promTarget, "v3.5.0", f)
	wantCode(t, err, EntryDuplicate)
	// A heading in fenced code is not a heading.
	g := strings.Replace(promFile, "* [BUGFIX] C. #3\n", "* [BUGFIX] C. #3\n  ```\n  ## 3.5.0 / 2025-08-01\n  ```\n", 1)
	if _, err := locateMem(promTarget, "v3.5.0", g); err != nil {
		t.Fatal(err)
	}
}

func TestPaddedVersionsAreDistinct(t *testing.T) {
	f := "## 2.50.0 / 2024-01-01\n\n* [FEATURE] fifty. #1\n\n## 2.4.0 / 2023-01-01\n\n* [FEATURE] four. #2\n"
	_, err := locateMem(promTarget, "v2.5.0", f)
	wantCode(t, err, EntryMissing)
	// Both present: each tag reads only its own entry.
	both := "## 2.50.0 / 2024-01-01\n\n* [FEATURE] fifty. #1\n\n## 2.5.0 / 2023-06-01\n\n* [FEATURE] five. #3\n"
	e := mustLocate(t, promTarget, "v2.5.0", both)
	if len(e.Items) != 1 || e.Section.HeadingLine != 5 {
		t.Fatalf("2.5.0 read the wrong entry: %+v", e.Section)
	}
	e = mustLocate(t, promTarget, "v2.50.0", both)
	if e.Section.HeadingLine != 1 || e.Section.EndLine != 3 {
		t.Fatalf("2.50.0: %+v", e.Section)
	}
	// A leading zero is not a version.
	_, err = locateMem(promTarget, "v2.5.0", "## 02.5.0 / 2023-06-01\n\n* [FEATURE] x. #1\n")
	wantCode(t, err, EntryMissing)
	// x.y is not x.y.0.
	_, err = locateMem(promTarget, "v2.5.0", "## 2.5 / 2023-06-01\n\n* [FEATURE] x. #1\n")
	wantCode(t, err, EntryMissing)
}

func TestReleaseCandidate(t *testing.T) {
	rc := "## 3.5.0-rc.0 / 2025-06-01\n\n* [FEATURE] x. #1\n"
	// The only heading is a release candidate: not the final entry.
	_, err := locateMem(promTarget, "v3.5.0", rc)
	wantCode(t, err, EntryNotFinal)
	// A release candidate tag is not a window tag.
	_, err = locateMem(promTarget, "v3.5.0-rc.0", rc)
	wantCode(t, err, EntryNotFinal)
	// A release candidate heading after the final one ends its section.
	f := "## 3.5.0 / 2025-07-14\n\n* [FEATURE] x. #1\n\n## 3.5.0-rc.0 / 2025-06-01\n\n* [FEATURE] y. #2\n"
	e := mustLocate(t, promTarget, "v3.5.0", f)
	if e.Section.EndLine != 3 || len(e.Items) != 1 {
		t.Fatalf("rc heading did not end the entry: %+v", e.Section)
	}
	// Unreleased wording on the version heading itself.
	_, err = locateMem(cortexTarget, "v1.19.0", "## 1.19.0 in progress\n\n* [CHANGE] x. #1\n")
	wantCode(t, err, EntryNotFinal)
	for _, tag := range []string{"v3.5.0+build", "3.5", "v3.5.0.1", "release-3.5.0", "v03.5.0", "latest"} {
		_, err = locateMem(promTarget, tag, promFile)
		wantCode(t, err, EntryNotFinal)
	}
}

func TestSetextAndATXMix(t *testing.T) {
	// A setext version heading with ATX siblings.
	f := "Changelog\n=========\n\n3.5.0 / 2025-07-14\n------------------\n\n* [FEATURE] x. #1\n\n## 3.4.0 / 2025-05-17\n\n* [FEATURE] y. #2\n"
	e := mustLocate(t, promTarget, "v3.5.0", f)
	if e.Section.HeadingLine != 4 || e.Section.EndLine != 7 || e.Structure[0].EndLine != 5 || e.Structure[0].Level != 2 {
		t.Fatalf("setext heading: %+v %+v", e.Section, e.Structure[0])
	}
	if e.Tiling.Headings != 2 || e.Tiling.Lines != 4 {
		t.Fatalf("tiling: %+v", e.Tiling)
	}
	// An ATX version section ended by a setext heading that names no release.
	g := "## 3.5.0 / 2025-07-14\n\n* [FEATURE] x. #1\n\nNotes\n-----\n\ntext\n"
	_, err := locateMem(promTarget, "v3.5.0", g)
	wantCode(t, err, EntryBoundaryUnproven)
	// A setext level-1 heading ends a level-2 entry the same way.
	h := "## 3.5.0 / 2025-07-14\n\n* [FEATURE] x. #1\n\nOld releases\n============\n\n* z\n"
	_, err = locateMem(promTarget, "v3.5.0", h)
	wantCode(t, err, EntryBoundaryUnproven)
	// A setext release heading after an ATX one is a proven boundary.
	k := "## 3.5.0 / 2025-07-14\n\n* [FEATURE] x. #1\n\n3.4.0 / 2025-05-17\n------------------\n\n* [FEATURE] y. #2\n"
	e = mustLocate(t, promTarget, "v3.5.0", k)
	if e.Section.EndLine != 3 {
		t.Fatalf("setext boundary: %+v", e.Section)
	}
	// A setext underline after an item line is a thematic break, not a heading.
	m := "## 3.5.0 / 2025-07-14\n\n* [FEATURE] x. #1\n---\n"
	_, err = locateMem(promTarget, "v3.5.0", m)
	wantCode(t, err, EntryParseResidue)
}

func TestFencedHashIsNotAHeading(t *testing.T) {
	f := "## 3.5.0 / 2025-07-14\n\n* [CHANGE] Rename:\n\n  ```sh\n  # a comment\n  ## 3.4.0 / 2025-05-17\n  prometheus --x\n  ```\n\n* [BUGFIX] after. #2\n\n~~~\n# top-level fence\n## 9.9.9 / 2030-01-01\n~~~\n\n## 3.4.0 / 2025-05-17\n\n* [FEATURE] y. #2\n"
	e := mustLocate(t, promTarget, "v3.5.0", f)
	if len(e.Structure) != 1 || len(e.Items) != 3 {
		t.Fatalf("structure %+v items %+v", e.Structure, e.Items)
	}
	if e.Items[0].EndLine != 9 || e.Items[2].Kind != "block" {
		t.Fatalf("fence handling: %+v", e.Items)
	}
	// An unterminated fence swallows the rest of the file: withheld.
	g := "## 3.5.0 / 2025-07-14\n\n* [CHANGE] x.\n\n  ```\n  code\n\n## 3.4.0 / 2025-05-17\n\n* [FEATURE] y. #2\n"
	_, err := locateMem(promTarget, "v3.5.0", g)
	wantCode(t, err, EntryParseResidue)
	// A fence opened before the heading hides it: the entry is missing.
	h := "```\n## 3.5.0 / 2025-07-14\n\n* x\n"
	_, err = locateMem(promTarget, "v3.5.0", h)
	wantCode(t, err, EntryMissing)
}

func TestCRLF(t *testing.T) {
	lf := mustLocate(t, promTarget, "v3.5.0", promFile)
	crlf := strings.ReplaceAll(promFile, "\n", "\r\n")
	e := mustLocate(t, promTarget, "v3.5.0", crlf)
	if e.Section.Digest != lf.Section.Digest || len(e.Items) != len(lf.Items) {
		t.Fatal("CRLF changed the section")
	}
	for i := range e.Items {
		if e.Items[i].Digest != lf.Items[i].Digest {
			t.Fatalf("CRLF changed item %d digest", i)
		}
	}
	if e.Source.FileDigest == lf.Source.FileDigest {
		t.Fatal("the file digest must cover the bytes as stored")
	}
	// Mixed line breaks and a bare carriage return are withheld.
	mixed := strings.Replace(crlf, "\r\n", "\n", 1)
	_, err := locateMem(promTarget, "v3.5.0", mixed)
	wantCode(t, err, EntryParseResidue)
	_, err = locateMem(promTarget, "v3.5.0", strings.Replace(promFile, "C. #3", "C.\r#3", 1))
	wantCode(t, err, EntryParseResidue)
}

func TestFileEncodingRefused(t *testing.T) {
	_, err := locateBytes(promTarget, "v3.5.0", append([]byte("\xef\xbb\xbf"), promFile...))
	wantCode(t, err, EntryParseResidue)
	_, err = locateBytes(promTarget, "v3.5.0", append([]byte(promFile), 0))
	wantCode(t, err, EntryParseResidue)
	_, err = locateBytes(promTarget, "v3.5.0", append([]byte(promFile), 0xff, 0xfe))
	wantCode(t, err, EntryParseResidue)
}

func TestResidueLines(t *testing.T) {
	for name, body := range map[string]string{
		"thematic break":          "* [FEATURE] x. #1\n\n---\n\n* [FEATURE] y. #2\n",
		"indented code":           "    indented at the start\n\n* [FEATURE] y. #2\n",
		"indented after heading":  "\tlead\n* [FEATURE] y. #2\n",
		"star thematic break":     "* [FEATURE] y. #2\n\n* * *\n",
		"underscore break inline": "* [FEATURE] y. #2\n___\n",
	} {
		f := "## 3.5.0 / 2025-07-14\n\n" + body + "\n## 3.4.0 / 2025-05-17\n\n* [FEATURE] z. #3\n"
		_, err := locateMem(promTarget, "v3.5.0", f)
		if c, _ := CodeOf(err); c != EntryParseResidue {
			t.Errorf("%s: %v", name, err)
		}
	}
	// A residue line outside the entry does not matter.
	f := "---\n\n## 3.5.0 / 2025-07-14\n\n* [FEATURE] y. #2\n\n## 3.4.0 / 2025-05-17\n\n    junk\n"
	if _, err := locateMem(promTarget, "v3.5.0", f); err != nil {
		t.Fatal(err)
	}
	// A repeated identical item (cortex 1.18.0 has one upstream) keeps one
	// digest and is told apart by its occurrence; nothing is dropped.
	e := mustLocate(t, promTarget, "v3.5.0", "## 3.5.0 / 2025-07-14\n\n* [FEATURE] y. #2\n* [FEATURE] y. #2\n")
	if len(e.Items) != 2 || e.Items[0].Digest != e.Items[1].Digest || e.Items[0].Occurrence != 1 || e.Items[1].Occurrence != 2 {
		t.Fatalf("%+v", e.Items)
	}
}

func TestLinkDefinitionsAndBlocks(t *testing.T) {
	f := "## 3.5.0 / 2025-07-14\n\nA paragraph\nover two lines.\n\n* [FEATURE] x. [ref]\n\n[ref]: https://example.test/x\n"
	e := mustLocate(t, promTarget, "v3.5.0", f)
	if len(e.Items) != 2 || e.Items[0].Kind != "block" || e.Items[0].EndLine != 4 || e.Tiling.LinkDefs != 1 {
		t.Fatalf("%+v %+v", e.Items, e.Tiling)
	}
	// A reference-looking line glued to an item is a continuation.
	g := "## 3.5.0 / 2025-07-14\n\n* [FEATURE] x\n[ref]: https://example.test/x\n"
	e = mustLocate(t, promTarget, "v3.5.0", g)
	if e.Tiling.LinkDefs != 0 || len(e.Items) != 1 || e.Items[0].EndLine != 4 {
		t.Fatalf("%+v %+v", e.Items, e.Tiling)
	}
}

func TestOverBound(t *testing.T) {
	tg := promTarget
	tg.MaxBytes = 40
	_, err := locateMem(tg, "v3.5.0", promFile)
	wantCode(t, err, EntryOverBound)
	var b strings.Builder
	b.WriteString("## 3.5.0 / 2025-07-14\n\n")
	for i := 0; i <= MaxSectionLines; i++ {
		fmt.Fprintf(&b, "* [FEATURE] item %d\n", i)
	}
	_, err = locateMem(promTarget, "v3.5.0", b.String())
	wantCode(t, err, EntryOverBound)
	tg.MaxBytes = MaxFileBytes + 1
	_, err = locateMem(tg, "v3.5.0", promFile)
	wantCode(t, err, NoChangelogTarget)
	// The bound applies to the file, not only to the section.
	big := promFile + strings.Repeat("x", 100)
	tg.MaxBytes = len(promFile)
	_, err = locateMem(tg, "v3.5.0", big)
	wantCode(t, err, EntryOverBound)
	if _, err = locateMem(tg, "v3.5.0", promFile); err != nil {
		t.Fatal(err)
	}
}

func TestEmpty(t *testing.T) {
	for name, f := range map[string]string{
		"heading at end":       "## 3.5.0 / 2025-07-14\n",
		"heading then blanks":  "## 3.5.0 / 2025-07-14\n\n\n## 3.4.0 / 2025-05-17\n\n* x\n",
		"only a sub-heading":   "## 3.5.0 / 2025-07-14\n\n### Added\n\n## 3.4.0 / 2025-05-17\n\n* x\n",
		"only a link def":      "## 3.5.0 / 2025-07-14\n\n[a]: https://x.test\n\n## 3.4.0 / 2025-05-17\n\n* x\n",
		"heading with no body": "## 3.5.0 / 2025-07-14\n## 3.4.0 / 2025-05-17\n\n* x\n",
	} {
		_, err := locateMem(promTarget, "v3.5.0", f)
		if c, _ := CodeOf(err); c != EntryEmpty {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestRefersElsewhere(t *testing.T) {
	for name, body := range map[string]string{
		"see":         "See https://github.com/x/y/releases/tag/v3.5.0 for details.\n",
		"see item":    "* See the release notes.\n",
		"refer":       "Please refer to the documentation.\n",
		"link only":   "* [v3.5.0 notes](https://x.test/notes)\n",
		"bare url":    "https://x.test/notes\n",
		"two links":   "* [a](https://x.test/a)\n* <https://x.test/b>\n",
		"changes are": "The changes are documented in the wiki.\n",
	} {
		f := "## 3.5.0 / 2025-07-14\n\n" + body + "\n## 3.4.0 / 2025-05-17\n\n* [FEATURE] x\n"
		_, err := locateMem(promTarget, "v3.5.0", f)
		if c, _ := CodeOf(err); c != EntryRefersElsewhere {
			t.Errorf("%s: %v", name, err)
		}
	}
	// One real item beside a pointer is read; the pointer is just an item.
	f := "## 3.5.0 / 2025-07-14\n\n* See the docs.\n* [CHANGE] Remove `--x`.\n"
	e := mustLocate(t, promTarget, "v3.5.0", f)
	if len(e.Items) != 2 {
		t.Fatal("items dropped")
	}
	// A neighbour is never read instead of a missing entry.
	g := "## 3.4.0 / 2025-05-17\n\n* [FEATURE] x\n"
	_, err := locateMem(promTarget, "v3.5.0", g)
	wantCode(t, err, EntryMissing)
}

func TestBoundary(t *testing.T) {
	// A non-version sibling heading of the same level.
	f := "## 3.5.0 / 2025-07-14\n\n* [FEATURE] x. #1\n\n## Notes\n\n* y\n\n## 3.4.0 / 2025-05-17\n\n* z\n"
	_, err := locateMem(promTarget, "v3.5.0", f)
	wantCode(t, err, EntryBoundaryUnproven)
	// A higher-level heading that names no release.
	g := "## 3.5.0 / 2025-07-14\n\n* [FEATURE] x. #1\n\n# Archive\n\n* y\n"
	_, err = locateMem(promTarget, "v3.5.0", g)
	wantCode(t, err, EntryBoundaryUnproven)
	// A lower-level heading is part of the entry and is recorded.
	h := "## 3.5.0 / 2025-07-14\n\n### Notes\n\n* [FEATURE] x. #1\n\n## 3.4.0 / 2025-05-17\n\n* z\n"
	e := mustLocate(t, promTarget, "v3.5.0", h)
	if len(e.Structure) != 2 || e.Structure[1].Kind != "sub" || e.Structure[1].Text != "Notes" {
		t.Fatalf("%+v", e.Structure)
	}
	// A release heading nested below the version heading is an unproven end.
	n := "## 3.5.0 / 2025-07-14\n\n* [FEATURE] x. #1\n\n### 3.4.0 / 2025-05-17\n\n* z\n"
	_, err = locateMem(promTarget, "v3.5.0", n)
	wantCode(t, err, EntryBoundaryUnproven)
	n2 := "## 3.5.0 / 2025-07-14\n\n* [FEATURE] x. #1\n\n### main / unreleased\n\n* z\n"
	_, err = locateMem(promTarget, "v3.5.0", n2)
	wantCode(t, err, EntryBoundaryUnproven)
	// The unreleased heading above and the unreleased heading as the end are fine.
	u := "## main / unreleased\n\n* [FEATURE] new\n\n## 3.5.0 / 2025-07-14\n\n* [FEATURE] x. #1\n"
	if _, err := locateMem(promTarget, "v3.5.0", u); err != nil {
		t.Fatal(err)
	}
	// A heading that closes with hashes is read without them.
	c := "## 3.5.0 / 2025-07-14 ##\n\n* [FEATURE] x. #1\n"
	if _, err := locateMem(promTarget, "v3.5.0", c); err != nil {
		t.Fatal(err)
	}
}

func TestFormsAndSources(t *testing.T) {
	cases := map[string]Code{
		"":                  NoChangelogTarget,
		FormGithubRelease:   SourceNotPinnedGit,
		FormPostTag:         EntryNotAtTag,
		FormDocsPage:        ShapeNotPerTag,
		FormMonorepo:        MonorepoEntryAmbiguous,
		"per-version-file":  ShapeNotPerTag,
		"anything-else-new": ShapeNotPerTag,
	}
	for form, want := range cases {
		tg := promTarget
		tg.Form = form
		r := &memReader{files: map[string][]byte{}}
		_, err := Locate(r, tg, extract.Tag{Name: "v3.5.0", Commit: testCommit})
		wantCode(t, err, want)
		if r.reads != 0 {
			t.Errorf("form %q: the source was read", form)
		}
	}
	// A missing path is typed; any other read error is not a reason.
	r := &memReader{files: map[string][]byte{}}
	_, err := Locate(r, promTarget, extract.Tag{Name: "v3.5.0", Commit: testCommit})
	wantCode(t, err, PathMissingAtTag)
	boom := errors.New("mirror unavailable")
	r = &memReader{err: boom}
	_, err = Locate(r, promTarget, extract.Tag{Name: "v3.5.0", Commit: testCommit})
	if _, ok := CodeOf(err); ok || !errors.Is(err, boom) {
		t.Fatalf("a read error became a reason: %v", err)
	}
	// An unpinned commit is never read.
	for _, c := range []string{"", "main", "0123456789ABCDEF0123456789abcdef01234567", testCommit[:39]} {
		r = &memReader{files: map[string][]byte{}}
		_, err = Locate(r, promTarget, extract.Tag{Name: "v3.5.0", Commit: c})
		wantCode(t, err, SourceNotPinnedGit)
		if r.reads != 0 {
			t.Errorf("commit %q was read", c)
		}
	}
}

func TestTargetValidation(t *testing.T) {
	bad := map[string]func(*Target){
		"unanchored":        func(x *Target) { x.HeadingPattern = `(?P<version>[0-9.]+)` },
		"no start anchor":   func(x *Target) { x.HeadingPattern = `(?P<version>[0-9.]+)$` },
		"escaped dollar":    func(x *Target) { x.HeadingPattern = `^(?P<version>[0-9.]+)\$` },
		"unnamed capture":   func(x *Target) { x.HeadingPattern = `^([0-9.]+)$` },
		"two captures":      func(x *Target) { x.HeadingPattern = `^(?P<version>[0-9.]+) (?P<x>.*)$` },
		"wrong name":        func(x *Target) { x.HeadingPattern = `^(?P<v>[0-9.]+)$` },
		"no capture":        func(x *Target) { x.HeadingPattern = `^[0-9.]+$` },
		"bad regexp":        func(x *Target) { x.HeadingPattern = `^(?P<version>[0-9.]+$` },
		"unanchored bound":  func(x *Target) { x.BoundaryPatterns = []string{`unreleased`} },
		"absolute path":     func(x *Target) { x.Path = "/CHANGELOG.md" },
		"dotdot path":       func(x *Target) { x.Path = "../CHANGELOG.md" },
		"unclean path":      func(x *Target) { x.Path = "a//CHANGELOG.md" },
		"empty path":        func(x *Target) { x.Path = "" },
		"empty component":   func(x *Target) { x.Component = "" },
		"non-canonical key": func(x *Target) { x.Repo = extract.RepoRef{Key: "github.com/Prometheus/prometheus"} },
		"not github":        func(x *Target) { x.Repo = extract.RepoRef{Key: "gitlab.com/a/b"} },
	}
	for name, mut := range bad {
		tg := promTarget
		mut(&tg)
		_, err := locateMem(tg, "v3.5.0", promFile)
		if c, _ := CodeOf(err); c != NoChangelogTarget {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestEditingAnotherEntryKeepsThisOne(t *testing.T) {
	a := mustLocate(t, promTarget, "v3.5.0", promFile)
	edited := strings.Replace(promFile, "* [FEATURE] D. #4", "* [FEATURE] D changed. #4", 1)
	b := mustLocate(t, promTarget, "v3.5.0", edited)
	if a.Section.Digest != b.Section.Digest || a.Items[0].Digest != b.Items[0].Digest {
		t.Fatal("an edit in another entry moved this entry's digests")
	}
	if a.Source.FileDigest == b.Source.FileDigest {
		t.Fatal("file digest must change")
	}
	// An edit in this entry moves its digests.
	c := mustLocate(t, promTarget, "v3.5.0", strings.Replace(promFile, "remove flag `--b`", "remove flag `--c`", 1))
	if c.Section.Digest == a.Section.Digest || c.Items[1].Digest == a.Items[1].Digest || c.Items[0].Digest != a.Items[0].Digest {
		t.Fatal("edit not reflected exactly in the changed item")
	}
	// Trailing blank lines are not part of the section.
	d := mustLocate(t, promTarget, "v3.4.0", promFile+"\n\n\n")
	e := mustLocate(t, promTarget, "v3.4.0", promFile)
	if d.Section.Digest != e.Section.Digest || d.Section.EndLine != e.Section.EndLine {
		t.Fatal("trailing blanks moved the section")
	}
}

func TestCodesClosedList(t *testing.T) {
	seen := map[Code]bool{}
	for _, c := range Codes() {
		if seen[c] || c == "" || strings.ToUpper(string(c)) != string(c) {
			t.Fatalf("bad code %q", c)
		}
		seen[c] = true
	}
	if len(seen) != 21 {
		t.Fatalf("design lists 21 codes, have %d", len(seen))
	}
	if _, ok := CodeOf(errors.New("x")); ok {
		t.Fatal("plain error has a code")
	}
}

func TestDeterministic(t *testing.T) {
	var first []byte
	for i := 0; i < 5; i++ {
		e := mustLocate(t, promTarget, "v3.5.0", promFile)
		b, err := e.Canonical()
		if err != nil {
			t.Fatal(err)
		}
		if first == nil {
			first = b
		} else if string(first) != string(b) {
			t.Fatal("output differs between runs")
		}
	}
	// The entry never reports a nil list or map-ordered field.
	if strings.Contains(string(first), "null") {
		t.Fatalf("null in output: %s", first)
	}
	_ = extract.Tag{}
}
