// SPDX-License-Identifier: AGPL-3.0-only

package changelogentries

import (
	"strings"
	"testing"
)

// rowOf builds a file row from reviewed-data fields.
func rowOf(t *testing.T, r rowData) Target {
	t.Helper()
	r.Component, r.Form, r.Path = "notes", FormFile, "CHANGELOG.md"
	if r.Repo == "" {
		r.Repo = rcRepo
	}
	tg, err := r.target()
	if err != nil {
		t.Fatal(err)
	}
	return tg
}

func bar(n int) *int { return &n }

// ---- same-level inner headings ------------------------------------------

// Verbatim shape of kube-state-metrics: a "## Note" at the level of the
// release heading, right under it.
const ksmFile = "## v2.16.0 / 2025-06-23\n\n## Note\n\n* This release builds with Golang `v1.24.4`\n* This release builds with `k8s.io/client-go`: `v0.32.6`\n\n" +
	"* [FEATURE] Add a `reclaim_policy` label by @SuperQ in <https://github.com/kubernetes/kube-state-metrics/pull/2597>\n\n" +
	"## v2.15.0 / 2025-02-03\n\n## Note\n\n* This release builds with Golang `v1.23.5`\n\n* [BUGFIX] Fix CR cache by @chelseychen in <https://github.com/kubernetes/kube-state-metrics/pull/2593>\n\n" +
	"## v2.14.0 / 2024-11-08\n\n### Note\n\n* This release builds with Golang `v1.23.3`\n\n* [BUGFIX] Use --track-unscheduled-pods by @CatherineF-dev in <https://github.com/kubernetes/kube-state-metrics/pull/2468>\n"

func ksmRow(t *testing.T, inner ...string) Target {
	return rowOf(t, rowData{HeadingStyle: "version-v-slash-date", BoundaryStyles: []string{"unreleased"}, InnerHeadingStyles: inner})
}

func TestInnerNoteStaysInsideTheEntry(t *testing.T) {
	tg := ksmRow(t, "note-first")
	for _, tag := range []string{"v2.16.0", "v2.15.0", "v2.14.0"} {
		e := mustLocate(t, tg, tag, ksmFile)
		if len(e.Items) == 0 {
			t.Fatalf("%s: no items", tag)
		}
		for _, it := range e.Items {
			if len(it.HeadingPath) != 1 || it.HeadingPath[0] != "Note" {
				t.Fatalf("%s: heading path %v", tag, it.HeadingPath)
			}
		}
	}
	e := mustLocate(t, tg, "v2.16.0", ksmFile)
	if e.Section.EndLine != strings.Count(ksmFile[:strings.Index(ksmFile, "## v2.15.0")], "\n")-1 {
		t.Fatalf("section ends at %d", e.Section.EndLine)
	}
	// the entry holds nothing of the next release
	for _, it := range e.Items {
		if it.EndLine > e.Section.EndLine {
			t.Fatalf("item past the section: %+v", it)
		}
	}
}

func TestInnerNoteNegatives(t *testing.T) {
	// Without the style the same file stays unproven (the old behaviour).
	_, err := locateMem(ksmRow(t), "v2.16.0", ksmFile)
	wantCode(t, err, EntryBoundaryUnproven)
	tg := ksmRow(t, "note-first")
	head := "## v2.16.0 / 2025-06-23\n\n"
	next := "\n## v2.15.0 / 2025-02-03\n\n- a\n"
	cases := map[string]string{
		// a Note after content is a trailer of the file, not part of the entry
		"note after items":      head + "- a\n\n## Note\n\n- n\n" + next,
		"note after text":       head + "text\n\n## Note\n\n- n\n" + next,
		"second note":           head + "## Note\n\n- n\n\n## Note\n\n- m\n" + next,
		"note after other head": head + "## Other\n\n- n\n" + next,
		"note one level higher": head + "# Note\n\n- n\n" + next,
		"different word":        head + "## Notes\n\n- n\n" + next,
		"lower case":            head + "## note\n\n- n\n" + next,
		"note with suffix":      head + "## Note: x\n\n- n\n" + next,
		"unlisted section":      head + "## Fixed\n\n- n\n" + next,
	}
	for name, f := range cases {
		e, err := locateMem(tg, "v2.16.0", f)
		if err == nil {
			t.Errorf("%s: located %+v", name, e.Section)
			continue
		}
		wantCode(t, err, EntryBoundaryUnproven)
	}
	// The entry still ends at the next release heading.
	e := mustLocate(t, tg, "v2.16.0", head+"## Note\n\n- n\n"+next)
	if e.Section.EndLine != 5 {
		t.Fatalf("end %d", e.Section.EndLine)
	}
}

// Verbatim shape of thanos: release headings at level 3, the sections
// ("Fixed", "Added") at the same level, then a level-2 heading with a typo.
const thanosV3File = "# Changelog\n\nAll notable changes to this project will be documented in this file.\n\n" +
	"### [v0.39.2](https://github.com/thanos-io/thanos/tree/release-0.39) - 2025 07 17\n\n### Fixed\n\n- [#8374](https://github.com/thanos-io/thanos/pull/8374) Query: fix panic\n\n" +
	"### [v0.39.1](https://github.com/thanos-io/thanos/tree/release-0.39) - 2025 07 01\n\nFixes a memory leak issue on query-frontend.\n\n### Fixed\n\n- [#8349](https://github.com/thanos-io/thanos/pull/8349) Query-Frontend: clean up\n\n" +
	"### [v0.39.0](https://github.com/thanos-io/thanos/tree/release-0.39) - 2025 06 25\n\n### Added\n\n- [#8308](https://github.com/thanos-io/thanos/pull/8308) Receive: counters\n\n### Fixed\n\n- [#8300](https://github.com/thanos-io/thanos/pull/8300) x\n\n" +
	"## [v0.38.0] https://github.com/thanos-io/thanos/tree/release-0.38) - 03.04.2025\n\n### Fixed\n\n- [#8000](https://github.com/thanos-io/thanos/pull/8000) y\n"

func thanosRow(t *testing.T, bounds []string, inner ...string) Target {
	return rowOf(t, rowData{Repo: "github.com/thanos-io/thanos", HeadingStyle: "version-linked-spaced-date", BoundaryStyles: bounds, InnerHeadingStyles: inner})
}

func TestInnerSectionsAndLooseBoundaryThanos(t *testing.T) {
	tg := thanosRow(t, []string{"unreleased", "version-linked-loose-date"}, "change-sections")
	for tag, paths := range map[string][]string{"v0.39.2": {"Fixed"}, "v0.39.1": {"Fixed"}, "v0.39.0": {"Added", "Fixed"}} {
		e := mustLocate(t, tg, tag, thanosV3File)
		seen := map[string]bool{}
		for _, it := range e.Items {
			if len(it.HeadingPath) == 1 {
				seen[it.HeadingPath[0]] = true
			}
		}
		for _, p := range paths {
			if !seen[p] {
				t.Fatalf("%s: no item under %s: %v", tag, p, seen)
			}
		}
	}
	// the last entry before the typo heading ends at it, not at the file end
	e := mustLocate(t, tg, "v0.39.0", thanosV3File)
	if want := strings.Count(thanosV3File[:strings.Index(thanosV3File, "## [v0.38.0]")], "\n") - 1; e.Section.EndLine != want {
		t.Fatalf("section %+v, want end %d", e.Section, want)
	}
	// the typo heading is no entry, not even its own
	_, err := locateMem(tg, "v0.38.0", thanosV3File)
	wantCode(t, err, EntryNotFinal)
}

func TestThanosNegatives(t *testing.T) {
	full := []string{"unreleased", "version-linked-loose-date"}
	// no inner style: the sections end the entry unproven
	_, err := locateMem(thanosRow(t, full), "v0.39.2", thanosV3File)
	wantCode(t, err, EntryBoundaryUnproven)
	// no loose boundary: the typo heading ends the entry unproven
	_, err = locateMem(thanosRow(t, []string{"unreleased"}, "change-sections"), "v0.39.0", thanosV3File)
	wantCode(t, err, EntryBoundaryUnproven)
	tg := thanosRow(t, full, "change-sections")
	h := func(s string) string { return "# Changelog\n\n" + s + "\n\n- a\n\n## Unreleased\n" }
	good := "## [v0.42.5](https://github.com/thanos-io/thanos/tree/release-0.42) - 2026 07 30"
	mustLocate(t, tg, "v0.42.5", h(good))
	bad := map[string]string{
		"ref of another line":   "## [v0.42.5](https://github.com/thanos-io/thanos/tree/release-0.41) - 2026 07 30",
		"ref is the tag":        "## [v0.42.5](https://github.com/thanos-io/thanos/tree/v0.42.5) - 2026 07 30",
		"typo in the ref":       "## [v0.42.5](https://github.com/thanos-io/thanos/tree/release-42.0) - 2026 07 30",
		"other repository":      "## [v0.42.5](https://github.com/other/thanos/tree/release-0.42) - 2026 07 30",
		"other host":            "## [v0.42.5](https://example.com/thanos-io/thanos/tree/release-0.42) - 2026 07 30",
		"dashed date":           "## [v0.42.5](https://github.com/thanos-io/thanos/tree/release-0.42) - 2026-07-30",
		"dotted date":           "## [v0.42.5](https://github.com/thanos-io/thanos/tree/release-0.42) - 30.07.2026",
		"no date":               "## [v0.42.5](https://github.com/thanos-io/thanos/tree/release-0.42)",
		"text after date":       "## [v0.42.5](https://github.com/thanos-io/thanos/tree/release-0.42) - 2026 07 30 rc",
		"release-0.42.1":        "## [v0.42.5](https://github.com/thanos-io/thanos/tree/release-0.42.1) - 2026 07 30",
		"link to a path":        "## [v0.42.5](https://github.com/thanos-io/thanos/tree/release-0.42/x) - 2026 07 30",
		"no v":                  "## [0.42.5](https://github.com/thanos-io/thanos/tree/release-0.42) - 2026 07 30",
		"prerelease version":    "## [v0.42.5-rc.1](https://github.com/thanos-io/thanos/tree/release-0.42) - 2026 07 30",
		"nested in a link text": "## [see [v0.42.5]](https://github.com/thanos-io/thanos/tree/release-0.42) - 2026 07 30",
	}
	for name, hd := range bad {
		e, err := locateMem(tg, "v0.42.5", h(hd))
		if err == nil {
			t.Errorf("%s: located %+v", name, e.Section)
		}
	}
	// A loose boundary heading never names an entry, and a second heading
	// for the entry's own version, in a loose spelling, is a duplicate.
	loose := "## [v0.42.5] https://github.com/thanos-io/thanos/tree/release-0.42) - 03.04.2025"
	_, err = locateMem(tg, "v0.42.5", h(loose))
	wantCode(t, err, EntryNotFinal)
	_, err = locateMem(tg, "v0.42.5", "# Changelog\n\n"+good+"\n\n- a\n\n"+loose+"\n\n- b\n")
	wantCode(t, err, EntryDuplicate)
	_, err = locateMem(tg, "v0.42.5", "# Changelog\n\n"+loose+"\n\n- b\n\n"+good+"\n\n- a\n")
	wantCode(t, err, EntryDuplicate)
	// the loose style of another version is a plain end of section
	mustLocate(t, tg, "v0.42.5", "# Changelog\n\n"+good+"\n\n- a\n\n## [v0.41.0](https://github.com/thanos-io/thanos/tree/release-41.0) - 2026 02 12\n\n- b\n")
}

// ---- boundary "in progress" ---------------------------------------------

func TestInProgressBoundary(t *testing.T) {
	file := "## master / unreleased\n\n## 1.20.0 2025-11-10\n\n* [CHANGE] a\n\n## 1.19.0 in progress\n\n* [CHANGE] b\n\n## 1.18.1 2024-10-14\n\n* [CHANGE] c\n"
	with := rowOf(t, rowData{HeadingStyle: "version-space-date", BoundaryStyles: []string{"master-unreleased", "version-in-progress"}})
	without := rowOf(t, rowData{HeadingStyle: "version-space-date", BoundaryStyles: []string{"master-unreleased"}})
	e := mustLocate(t, with, "v1.20.0", file)
	if e.Section.EndLine != 5 {
		t.Fatalf("end %d", e.Section.EndLine)
	}
	_, err := locateMem(without, "v1.20.0", file)
	wantCode(t, err, EntryBoundaryUnproven)
	// the in-progress release itself has no entry, with or without the style
	_, err = locateMem(with, "v1.19.0", file)
	wantCode(t, err, EntryNotFinal)
	_, err = locateMem(without, "v1.19.0", file)
	wantCode(t, err, EntryNotFinal)
	// a second heading for the entry's own version, "in progress", is refused
	dup := "## 1.20.0 2025-11-10\n\n* [CHANGE] a\n\n## 1.20.0 in progress\n\n* [CHANGE] b\n"
	_, err = locateMem(with, "v1.20.0", dup)
	wantCode(t, err, EntryDuplicate)
	// only the exact shape is a boundary
	for name, hd := range map[string]string{
		"two part":   "## 1.19 in progress",
		"suffix":     "## 1.19.0 in progress now",
		"prefix":     "## v1.19.0 in progress",
		"upper case": "## 1.19.0 In Progress",
		"prerelease": "## 1.19.0-rc.1 in progress",
	} {
		f := "## 1.20.0 2025-11-10\n\n* [CHANGE] a\n\n" + hd + "\n\n* [CHANGE] b\n"
		if _, err := locateMem(with, "v1.20.0", f); err == nil {
			t.Errorf("%s: located", name)
		}
	}
}

// ---- heading styles -----------------------------------------------------

func TestVocabV3Styles(t *testing.T) {
	cases := []struct {
		name    string
		row     Target
		file    string
		located []string
		refused map[string]Code
	}{
		{
			name:    "grafana level-1 parenthesised date",
			row:     rowOf(t, rowData{HeadingStyle: "version-paren-date", BoundaryStyles: []string{"unreleased"}}),
			file:    "<!-- 13.3.1 START -->\n\n# 13.3.1 (2026-11-10)\n\n### Security\n\n- Security: Fix CVE-2026-1\n\n### Features and enhancements\n\n- **DateTime:** Update [#136951](https://github.com/grafana/grafana/pull/136951), [@joshhunt](https://github.com/joshhunt)\n\n<!-- 13.3.1 END -->\n<!-- 13.3.0 START -->\n\n# 13.3.0 (2026-10-27)\n\n### Security\n\n- Security: Fix CVE-2026-2\n\n<!-- 13.3.0 END -->\n",
			located: []string{"v13.3.1", "v13.3.0"},
			refused: map[string]Code{"v13.2.0": EntryMissing},
		},
		{
			name:    "emissary day first and month first",
			row:     rowOf(t, rowData{HeadingStyle: "version-bracketed-long-date", BoundaryStyles: []string{"unreleased"}}),
			file:    "# CHANGELOG\n\n## [4.2.0] TBD\n\n- Feature: x\n\n## [4.1.0] 1 May 2026\n\n- Feature: a\n\n## [3.9.0] November 13, 2023\n[3.9.0]: https://github.com/emissary-ingress/emissary/compare/v3.8.0...v3.9.0\n\n- Feature: b\n\n## [3.8.0] October 3, 2023\n\n- Feature: c\n",
			located: []string{"v4.1.0", "v3.9.0", "v3.8.0"},
			refused: map[string]Code{"v4.2.0": EntryNotFinal},
		},
	}
	for _, c := range cases {
		for _, tag := range c.located {
			if _, err := locateMem(c.row, tag, c.file); err != nil {
				t.Errorf("%s: %s: %v", c.name, tag, err)
			}
		}
		for tag, code := range c.refused {
			_, err := locateMem(c.row, tag, c.file)
			if got, ok := CodeOf(err); !ok || got != code {
				t.Errorf("%s: %s: want %s, got %v", c.name, tag, code, err)
			}
		}
	}
}

func TestVocabV3StyleNegatives(t *testing.T) {
	long := rowOf(t, rowData{HeadingStyle: "version-bracketed-long-date", BoundaryStyles: []string{"unreleased"}})
	for name, hd := range map[string]string{
		"month typo":        "## [4.1.0] 1 Mayy 2026",
		"month lower case":  "## [4.1.0] 1 may 2026",
		"no year":           "## [4.1.0] 1 May",
		"three digit day":   "## [4.1.0] 101 May 2026",
		"year of 2 digits":  "## [4.1.0] 1 May 26",
		"month day no come": "## [4.1.0] May 1 2026",
		"tbd":               "## [4.1.0] TBD",
		"dev":               "## [4.1.0-dev] 1 May 2026",
		"no bracket":        "## 4.1.0 1 May 2026",
		"trailing text":     "## [4.1.0] 1 May 2026 (patch)",
		"iso date":          "## [4.1.0] 2026-05-01",
	} {
		if e, err := locateMem(long, "v4.1.0", hd+"\n\n- a\n"); err == nil {
			t.Errorf("long date %s: located %+v", name, e.Section)
		}
	}
	paren := rowOf(t, rowData{HeadingStyle: "version-paren-date", BoundaryStyles: []string{"unreleased"}})
	for name, hd := range map[string]string{
		"security suffix": "# 13.3.1+security-01 (2026-03-25)",
		"v prefix":        "# v13.3.1 (2026-11-10)",
		"text after":      "# 13.3.1 (2026-11-10) beta",
		"slash date":      "# 13.3.1 (2026/11/10)",
		"no parens":       "# 13.3.1 2026-11-10",
		"two part":        "# 13.3 (2026-11-10)",
	} {
		if e, err := locateMem(paren, "v13.3.1", hd+"\n\n- a\n"); err == nil {
			t.Errorf("paren date %s: located %+v", name, e.Section)
		}
	}
}

// ---- scanner rules, checked by the CommonMark oracle ---------------------

func commentRow(t *testing.T) Target {
	return rowOf(t, rowData{HeadingStyle: "version-v-prefixed", BoundaryStyles: []string{"unreleased"}})
}

func TestCommentRunsBetweenEntries(t *testing.T) {
	tg := commentRow(t)
	two := "<!-- 1.1.0 START -->\n\n## v1.1.0\n\n- a\n\n<!-- 1.1.0 END -->\n<!-- 1.0.0 START -->\n\n## v1.0.0\n\n- b\n\n<!-- 1.0.0 END -->\n"
	e := mustLocate(t, tg, "v1.1.0", two)
	if e.Tiling.Comments != 2 {
		t.Fatalf("%+v", e.Tiling)
	}
	if t2 := e.Tiling; t2.Headings+t2.Blanks+t2.LinkDefs+t2.ItemLines+t2.Comments != t2.Lines {
		t.Fatalf("tiling does not add up: %+v", t2)
	}
	mustLocate(t, tg, "v1.0.0", two)
	three := "## v1.1.0\n\n- a\n\n<!-- one -->\n<!-- two -->\n<!-- three -->\n\n## v1.0.0\n\n- b\n"
	if e := mustLocate(t, tg, "v1.1.0", three); e.Tiling.Comments != 3 {
		t.Fatalf("%+v", e.Tiling)
	}
	head := "## v1.1.0\n\n- a\n\n"
	tail := "\n## v1.0.0\n\n- b\n"
	cases := map[string]string{
		"run glued to the item above": "## v1.1.0\n\n- a\n<!-- one -->\n<!-- two -->\n" + tail,
		"run glued to text below":     head + "<!-- one -->\n<!-- two -->\ntext\n" + tail,
		"run glued to an item below":  head + "<!-- one -->\n<!-- two -->\n- c\n" + tail,
		"second comment spans lines":  head + "<!-- one -->\n<!--\ntwo\n-->\n" + tail,
		"text between comments":       head + "<!-- one -->\ntext\n<!-- two -->\n" + tail,
		"second comment indented":     head + "<!-- one -->\n  <!-- two -->\n" + tail,
		"second comment unbalanced":   head + "<!-- one -->\n<!-- two\n" + tail,
		"second comment has markup":   head + "<!-- one -->\n<!-- <b> -->\n" + tail,
		"second is another block":     head + "<!-- one -->\n<div>\n" + tail,
		"second hides a heading":      head + "<!-- one -->\n<!--\n## v1.0.5\n-->\n" + tail,
	}
	for name, f := range cases {
		if e, err := locateMem(tg, "v1.1.0", f); err == nil {
			t.Errorf("%s: located %+v", name, e.Tiling)
		} else {
			wantCode(t, err, EntryParseResidue)
		}
	}
}

// Verbatim shape of the traefik entry that failed: a paragraph, a blank line,
// text indented by two spaces, then list items.
const traefikShape = "## [v3.6.10](https://github.com/traefik/traefik/tree/v3.6.10) (2026-03-06)\n[All Commits](https://github.com/traefik/traefik/compare/v3.6.9...v3.6.10)\n\n  **Bug fixes:**\n- **[docker]** Bump Docker ([#12761](https://github.com/traefik/traefik/pull/12761) by [mmatur](https://github.com/mmatur))\n- **[otel]** Bump otel ([#12754](https://github.com/traefik/traefik/pull/12754) by [rtribotte](https://github.com/rtribotte))\n\n" +
	"## [v2.11.40](https://github.com/traefik/traefik/tree/v2.11.40) (2026-03-06)\n\n- **[a]** b\n"

func TestIndentedTextAfterParagraph(t *testing.T) {
	tg := rowOf(t, rowData{Repo: "github.com/traefik/traefik", HeadingStyle: "version-linked-paren-date", BoundaryStyles: []string{"prerelease-linked-paren-date"}})
	e := mustLocate(t, tg, "v3.6.10", traefikShape)
	if len(e.Items) != 4 {
		t.Fatalf("items %d", len(e.Items))
	}
	// the same text with four spaces is an indented code block: refused
	four := strings.Replace(traefikShape, "\n  **Bug fixes:**", "\n    **Bug fixes:**", 1)
	if _, err := locateMem(tg, "v3.6.10", four); err == nil {
		t.Fatal("indented code block located")
	}
	// a tab is not read
	tab := strings.Replace(traefikShape, "\n  **Bug fixes:**", "\n\t**Bug fixes:**", 1)
	if _, err := locateMem(tg, "v3.6.10", tab); err == nil {
		t.Fatal("tab-indented text located")
	}
	// without the blank line the indented text is the paragraph's own line
	lazy := strings.Replace(traefikShape, "v3.6.9...v3.6.10)\n\n  **Bug", "v3.6.9...v3.6.10)\n  **Bug", 1)
	if e := mustLocate(t, tg, "v3.6.10", lazy); len(e.Items) != 3 {
		t.Fatalf("lazy: items %d", len(e.Items))
	}
}

// Verbatim shape of the coredns v1.11.4 note: a paragraph and, with no blank
// line, bullets indented by two spaces.
const corednsShape = "This release adds some new features and fixes some bugs.  New features of note:\n  * forward plugin: new option `next`, to try alternate upstreams\n  * dnssec plugin: new option to load keys\n  * rewrite plugin: new option to revert EDNS0 option rewrites\n\n## Brought to You By\n\nAdamKorcz,\nAnifalak\n"

func TestIndentedBulletsInterruptAParagraph(t *testing.T) {
	r := rcFixture(t, map[string]byte{"v1.11.4": 'a'}, map[string]string{"a|docs/releases/v1.11.4.md": corednsShape})
	tags, err := r.Tags(pvRow.Repo)
	if err != nil || len(tags) != 1 {
		t.Fatal(tags, err)
	}
	if _, err := Locate(r, pvRow, tags[0]); err != nil {
		t.Fatalf("coredns shape: %v", err)
	}
	row := rowOf(t, rowData{HeadingStyle: "version-v-prefixed", BoundaryStyles: []string{"unreleased"}})
	head := "## v1.0.0\n\nIntro line:\n"
	tail := "\n## v0.9.0\n\n- z\n"
	ok := map[string]string{
		"two spaces":          head + "  * a\n  * b\n" + tail,
		"one space":           head + " - a\n - b\n" + tail,
		"three spaces":        head + "   + a\n   + b\n" + tail,
		"after a blank":       head + "\n  * a\n  * b\n" + tail,
		"ordered from one":    head + "  1. a\n  1. b\n" + tail,
		"list after a header": "## v1.0.0\n\n - a\n - b\n" + tail,
		// not a list start: stays text the paragraph holds, and the oracle agrees
		"tab continues the text": head + "\t* a\n" + tail,
		"ordered not from one":   head + "  2. a\n" + tail,
		"empty bullet":           head + "  *\n" + tail,
	}
	for name, f := range ok {
		if _, err := locateMem(row, "v1.0.0", f); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	// What the scanner does not read stays refused, whatever the oracle says.
	refused := map[string]string{
		"siblings at other columns": head + "  * a\n * b\n" + tail,
		"four spaces is code":       head + "\n    * a\n" + tail,
		"nested deeper then back":   head + "  * a\n     * b\n  * c\n   * d\n" + tail,
		"fence in an indented item": head + "  * a\n  ```\n  x\n  ```\n" + tail,
	}
	for name, f := range refused {
		if e, err := locateMem(row, "v1.0.0", f); err == nil {
			t.Errorf("%s: located %+v", name, e.Tiling)
		}
	}
	// the items are the real ones: three bullets, three items
	e := mustLocate(t, row, "v1.0.0", head+"  * a\n  * b\n  * c\n"+tail)
	if len(e.Items) != 4 {
		t.Fatalf("items %d, want the paragraph and three bullets", len(e.Items))
	}
}

// ---- loader -------------------------------------------------------------

func TestLoaderV3Fields(t *testing.T) {
	row := func(extra string) string {
		return `{"schema":"prufyx.io/changelog-targets/v1","rows":[{"component":"a","repo":"github.com/o/a","form":"changelog-file","path":"CHANGELOG.md","headingStyle":"version-v-prefixed","boundaryStyles":["unreleased"]` + extra + `}]}`
	}
	good := []string{``, `,"minLocatedNewest":5`, `,"minLocatedNewest":8`, `,"innerHeadingStyles":["note-first"]`, `,"innerHeadingStyles":["note-first","change-sections"],"minLocatedNewest":7`}
	for _, e := range good {
		if _, err := parseTargets([]byte(row(e))); err != nil {
			t.Errorf("%q: %v", e, err)
		}
	}
	bad := map[string]string{
		"bar 0":              `,"minLocatedNewest":0`,
		"bar 4":              `,"minLocatedNewest":4`,
		"bar 9":              `,"minLocatedNewest":9`,
		"bar negative":       `,"minLocatedNewest":-5`,
		"bar string":         `,"minLocatedNewest":"7"`,
		"bar float":          `,"minLocatedNewest":7.5`,
		"bar twice":          `,"minLocatedNewest":7,"minLocatedNewest":7`,
		"inner unknown":      `,"innerHeadingStyles":["note"]`,
		"inner twice":        `,"innerHeadingStyles":["note-first","note-first"]`,
		"inner empty":        `,"innerHeadingStyles":[]`,
		"inner a pattern":    `,"innerHeadingStyles":["^Note$"]`,
		"unknown field":      `,"minLocated":7`,
		"inner case":         `,"innerHeadingStyles":["Note-First"]`,
		"inner is a string":  `,"innerHeadingStyles":"note-first"`,
		"inner null element": `,"innerHeadingStyles":[null]`,
	}
	for name, e := range bad {
		if rows, err := parseTargets([]byte(row(e))); err == nil {
			t.Errorf("%s accepted: %v", name, rows)
		}
	}
	// the fields belong to rows that are read, and inner styles to rows with headings
	for name, doc := range map[string]string{
		"bar on post-tag":       `{"schema":"prufyx.io/changelog-targets/v1","rows":[{"component":"a","repo":"github.com/o/a","form":"post-tag","minLocatedNewest":7}]}`,
		"bar on github-release": `{"schema":"prufyx.io/changelog-targets/v1","rows":[{"component":"a","repo":"github.com/o/a","form":"github-release","minLocatedNewest":5}]}`,
		"inner on post-tag":     `{"schema":"prufyx.io/changelog-targets/v1","rows":[{"component":"a","repo":"github.com/o/a","form":"post-tag","innerHeadingStyles":["note-first"]}]}`,
		"inner on per-version":  `{"schema":"prufyx.io/changelog-targets/v1","rows":[{"component":"a","repo":"github.com/o/a","form":"changelog-per-version-file","path":"n/{version}.md","innerHeadingStyles":["note-first"]}]}`,
	} {
		if rows, err := parseTargets([]byte(doc)); err == nil {
			t.Errorf("%s accepted: %v", name, rows)
		}
	}
	// a per-version row may carry a bar, a per-line row both
	for name, doc := range map[string]string{
		"bar on per-version": `{"schema":"prufyx.io/changelog-targets/v1","rows":[{"component":"a","repo":"github.com/o/a","form":"changelog-per-version-file","path":"n/{version}.md","minLocatedNewest":6}]}`,
		"both on per-line":   `{"schema":"prufyx.io/changelog-targets/v1","rows":[{"component":"a","repo":"github.com/o/a","form":"changelog-per-line-file","path":"n/{line}.md","headingStyle":"version-v-prefixed","boundaryStyles":["unreleased"],"innerHeadingStyles":["change-sections"],"minLocatedNewest":6}]}`,
	} {
		if _, err := parseTargets([]byte(doc)); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	// the in-code table refuses what the data loader refuses
	low := cortexTarget
	low.MinLocatedNewest = 4
	if _, err := low.compile(); err == nil {
		t.Error("compile accepted a bar of 4")
	}
}
