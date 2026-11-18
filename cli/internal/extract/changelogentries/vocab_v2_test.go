// SPDX-License-Identifier: AGPL-3.0-only

package changelogentries

import (
	"strings"
	"testing"
)

// styleRow builds a changelog-file target from closed style names.
func styleRow(t *testing.T, heading string, boundaries ...string) Target {
	t.Helper()
	tg, err := rowData{
		Component: "notes", Repo: rcRepo, Form: FormFile, Path: "CHANGELOG.md",
		HeadingStyle: heading, BoundaryStyles: boundaries,
	}.target()
	if err != nil {
		t.Fatal(err)
	}
	return tg
}

const (
	badFence = "- x\n  ```\n  code\n```\n" // an indented fence closed at another indentation
	badHTML  = "<!--\nx\n-->\n"            // a multi-line HTML block
)

func TestVocabV2Styles(t *testing.T) {
	cases := []struct {
		name     string
		tg       func(*testing.T) Target
		file     string
		located  []string
		refused  map[string]Code
		tagsOnly bool
	}{
		{
			name:    "fluentd release-v-slash-date + line-heading-v",
			tg:      func(t *testing.T) Target { return styleRow(t, "release-v-slash-date", "line-heading-v") },
			file:    "# v1.20\n\n## Release v1.20.1 - 2026/10/26\n\n### Bug fix\n\n* a\n\n## Release v1.20.0 - 2026/10/01\n\n* b\n\n# v1.19\n\n## Release v1.19.3 - 2026/06/25\n\n* c\n",
			located: []string{"v1.20.1", "v1.20.0", "v1.19.3"},
			refused: map[string]Code{"v1.20.5": EntryMissing},
		},
		{
			name:    "cortex version-space-date + master-unreleased",
			tg:      func(t *testing.T) Target { return styleRow(t, "version-space-date", "master-unreleased") },
			file:    "# Changelog\n\n## master / unreleased\n\n* [CHANGE] x\n\n## 1.21.1 2026-06-04\n\n* [BUGFIX] y\n\n## 1.21.0 2026-05-01\n\n* [FEATURE] z\n\n## 1.19.0 in progress\n\n* [FEATURE] w\n",
			located: []string{"v1.21.1"},
			// the in-progress heading is not a final heading and names the tag
			refused: map[string]Code{"v1.19.0": EntryNotFinal, "v1.21.2": EntryMissing},
		},
		{
			name:    "kube-state-metrics version-v-slash-date",
			tg:      func(t *testing.T) Target { return styleRow(t, "version-v-slash-date", "unreleased") },
			file:    "# Changelog\n\n## v2.17.0 / 2025-09-01\n\n* [BUGFIX] a\n\n## v2.16.0 / 2025-06-23\n\n* [FEATURE] b\n\n## Note\n\ntext\n",
			located: []string{"v2.17.0"},
			// `## Note` after v2.16.0 ends it without naming a release: not read
			refused: map[string]Code{"v2.16.0": EntryBoundaryUnproven, "v2.15.0": EntryMissing},
		},
		{
			name: "traefik version-linked-paren-date + prerelease-linked-paren-date",
			tg: func(t *testing.T) Target {
				return styleRow(t, "version-linked-paren-date", "prerelease-linked-paren-date")
			},
			file:    "## [v3.2.0](https://github.com/traefik/traefik/tree/v3.2.0) (2024-10-20)\n\n* a\n\n## [v3.2.0-rc2](https://github.com/traefik/traefik/tree/v3.2.0-rc2) (2024-10-09)\n\n* rc\n\n## [v3.1.0](https://github.com/traefik/traefik/tree/v3.1.0) (2024-08-01)\n\n* b\n\n## [v3.0.0-ea.1](https://github.com/traefik/traefik/tree/v3.0.0-ea.1) (2024-01-01)\n\n* ea\n",
			located: []string{"v3.2.0", "v3.1.0"},
			refused: map[string]Code{"v3.2.1": EntryMissing, "v3.0.0": EntryNotFinal},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			tg := c.tg(t)
			for _, tag := range c.located {
				if _, err := locateMem(tg, tag, c.file); err != nil {
					t.Fatalf("%s: %v", tag, err)
				}
			}
			for tag, code := range c.refused {
				_, err := locateMem(tg, tag, c.file)
				wantCode(t, err, code)
			}
		})
	}
}

func TestVocabV2StyleNearMisses(t *testing.T) {
	notFinal := func(tg Target, file, tag string) {
		t.Helper()
		_, err := locateMem(tg, tag, file)
		wantCode(t, err, EntryNotFinal)
	}
	// pre-release suffix, wrong separator and a looser date never match.
	s5 := styleRow(t, "release-v-slash-date", "line-heading-v")
	for _, h := range []string{"## Release v1.2.3-rc1 - 2026/10/26", "## Release v1.2.3 - 2026-10-26", "## Release 1.2.3 - 2026/10/26", "## release v1.2.3 - 2026/10/26"} {
		_, err := locateMem(s5, "v1.2.3", h+"\n\n* a\n")
		if err == nil {
			t.Fatalf("%q located", h)
		}
	}
	notFinal(s5, "## Release v1.2.3 - 2026/10\n\n* a\n", "v1.2.3")
	s1 := styleRow(t, "version-space-date", "master-unreleased")
	for _, h := range []string{"## 1.2.3 unreleased", "## 1.2.3-rc.1 2026-10-26", "## 1.2.3  2026-10-26", "## v1.2.3 2026-10-26", "## 1.2.3 2026-10-26 extra"} {
		if _, err := locateMem(s1, "v1.2.3", h+"\n\n* a\n"); err == nil {
			t.Fatalf("%q located", h)
		}
	}
	s2 := styleRow(t, "version-v-slash-date", "unreleased")
	for _, h := range []string{"## 1.2.3 / 2026-10-26", "## v1.2.3 / unreleased", "## v1.2.3-rc.1 / 2026-10-26"} {
		if _, err := locateMem(s2, "v1.2.3", h+"\n\n* a\n"); err == nil {
			t.Fatalf("%q located", h)
		}
	}
	s3 := styleRow(t, "version-linked-paren-date", "prerelease-linked-paren-date")
	for _, h := range []string{
		"## [v1.2.3-rc1](https://github.com/o/r/tree/v1.2.3-rc1) (2026-10-26)",
		"## [v1.2.3](https://example.com/o/r/tree/v1.2.3) (2026-10-26)",
		"## [v1.2.3](https://github.com/o/r/tree/v1.2.3) (2026/10/26)",
		"## [1.2.3](https://github.com/o/r/tree/v1.2.3) (2026-10-26)",
		"## [v1.2.3](https://github.com/o/r/tree/v1.2.3) - 2026-10-26",
	} {
		if _, err := locateMem(s3, "v1.2.3", h+"\n\n* a\n"); err == nil {
			t.Fatalf("%q located", h)
		}
	}
	// A linked pre-release heading naming the tag's version (no boundary
	// style) is not read as the release; with the boundary style it is a
	// boundary only.
	pre := "## [v1.2.3-rc1](https://github.com/o/r/tree/v1.2.3-rc1) (2026-10-26)\n\n* rc\n"
	rel := "## [v1.2.3](https://github.com/o/r/tree/v1.2.3) (2026-10-27)\n\n* a\n\n"
	if _, err := locateMem(s3, "v1.2.3", rel+pre); err != nil {
		t.Fatal(err)
	}
	s3NoB := styleRow(t, "version-linked-paren-date", "unreleased")
	_, err := locateMem(s3NoB, "v1.2.3", rel+pre)
	wantCode(t, err, EntryDuplicate)
	// S3 duplicates are refused, also across a differing link target.
	dup := rel + "## [v1.2.3](https://github.com/o/r/tree/other) (2026-10-28)\n\n* b\n"
	_, err = locateMem(s3, "v1.2.3", dup)
	wantCode(t, err, EntryDuplicate)
	// S5 / S1 / S2 duplicates as well.
	_, err = locateMem(s5, "v1.2.3", "## Release v1.2.3 - 2026/10/26\n\n* a\n\n## Release v1.2.3 - 2026/10/27\n\n* b\n")
	wantCode(t, err, EntryDuplicate)
	_, err = locateMem(s1, "v1.2.3", "## 1.2.3 2026-10-26\n\n* a\n\n## 1.2.3 2026-10-27\n\n* b\n")
	wantCode(t, err, EntryDuplicate)
	_, err = locateMem(s2, "v1.2.3", "## v1.2.3 / 2026-10-26\n\n* a\n\n## v1.2.3 / 2026-10-27\n\n* b\n")
	wantCode(t, err, EntryDuplicate)
	// B2 cannot name an entry: a line heading with a patch version is no boundary.
	s5b := styleRow(t, "release-v-slash-date", "line-heading-v")
	_, err = locateMem(s5b, "v1.2.3", "## Release v1.2.3 - 2026/10/26\n\n* a\n\n# v1.2\n\n* b\n")
	if err != nil {
		t.Fatal(err)
	}
	_, err = locateMem(s5b, "v1.2.3", "## Release v1.2.3 - 2026/10/26\n\n* a\n\n# v1.2.2\n\n* b\n")
	wantCode(t, err, EntryBoundaryUnproven)
}

func TestVocabV2StylesLoadThroughTheStrictLoader(t *testing.T) {
	for _, h := range []string{"version-space-date", "version-v-slash-date", "version-linked-paren-date", "release-v-slash-date"} {
		if _, ok := headingStyles[h]; !ok {
			t.Fatalf("missing heading style %s", h)
		}
	}
	for _, b := range []string{"master-unreleased", "line-heading-v", "prerelease-linked-paren-date"} {
		if _, ok := boundaryStyles[b]; !ok {
			t.Fatalf("missing boundary style %s", b)
		}
	}
	// A style name outside the closed tables is refused.
	if _, err := (rowData{Component: "notes", Repo: rcRepo, Form: FormFile, Path: "CHANGELOG.md",
		HeadingStyle: "release-v-slash-datex", BoundaryStyles: []string{"line-heading-v"}}).target(); err == nil {
		t.Fatal("unknown style accepted")
	}
}

// C1: the file-wide checks cover the prefix up to the heading that follows the entry.

const c1Head = "# Changelog\n\n"

func c1Row(t *testing.T) Target { return styleRow(t, "version-bracketed-date", "unreleased-bracketed") }

func TestScopedChecksFenceInsideEntryStillRefuses(t *testing.T) {
	f := c1Head + "## [1.1.0] - 2026-01-02\n\n" + badFence + "\n## [1.0.0] - 2026-01-01\n\n- a\n"
	_, err := locateMem(c1Row(t), "v1.1.0", f)
	wantCode(t, err, EntryParseResidue)
}

func TestScopedChecksFenceInPrefixAboveEntryStillRefuses(t *testing.T) {
	for _, bad := range []string{badFence, badHTML} {
		f := c1Head + "## [1.1.0] - 2026-01-02\n\n- n\n\n## [1.0.0] - 2026-01-01\n\n- a\n\n## [0.9.0] - 2025-12-01\n\n" + bad
		// the entry is v1.0.0; the construct sits BELOW the next heading and is not checked
		_, err := locateMem(c1Row(t), "v1.0.0", f)
		if err != nil {
			t.Fatalf("below the entry: %v", err)
		}
		// the entry is v1.0.0 and the construct is ABOVE it: still refused
		g := c1Head + bad + "\n## [1.1.0] - 2026-01-02\n\n- n\n\n## [1.0.0] - 2026-01-01\n\n- a\n"
		_, err = locateMem(c1Row(t), "v1.0.0", g)
		wantCode(t, err, EntryParseResidue)
		// the construct sits between the entry above and the entry itself
		h := c1Head + "## [1.1.0] - 2026-01-02\n\n- n\n\n" + bad + "\n## [1.0.0] - 2026-01-01\n\n- a\n"
		_, err = locateMem(c1Row(t), "v1.0.0", h)
		wantCode(t, err, EntryParseResidue)
	}
}

func TestScopedChecksBelowNextHeadingNoLongerRefuse(t *testing.T) {
	for _, bad := range []string{badFence, badHTML} {
		f := c1Head + "## [1.1.0] - 2026-01-02\n\n- n\n\n## [1.0.0] - 2026-01-01\n\n- a\n\n## [0.9.0] - 2025-12-01\n\n" + bad
		e, err := locateMem(c1Row(t), "v1.1.0", f)
		if err != nil {
			t.Fatalf("construct below the next heading refused the read: %v", err)
		}
		if e.Section.EndLine != 5 {
			t.Fatalf("section %+v", e.Section)
		}
		// the construct inside the following entry itself is that entry's own refusal
		_, err = locateMem(c1Row(t), "v0.9.0", f)
		wantCode(t, err, EntryParseResidue)
	}
	// no entry located: the whole file is still checked and refuses first
	f := c1Head + "## [1.1.0] - 2026-01-02\n\n- n\n\n" + badHTML
	_, err := locateMem(c1Row(t), "v7.7.7", f)
	wantCode(t, err, EntryParseResidue)
	// a mistaken whole-file refusal must not appear as a missing entry either
	_, err = locateMem(c1Row(t), "v1.1.0", f)
	wantCode(t, err, EntryParseResidue)
}

func TestScopedChecksManifestRecordsTheCut(t *testing.T) {
	head := c1Head + "## [1.1.0] - 2026-01-02\n\n- n\n\n"
	one := head + "## [1.0.0] - 2026-01-01\n\n- a\n\n## [0.9.0] - 2025-12-01\n\n- z\n"
	two := head + "- m\n\n## [1.0.0] - 2026-01-01\n\n- a\n\n## [0.9.0] - 2025-12-01\n\n- z\n"
	e1 := mustLocate(t, c1Row(t), "v1.1.0", one)
	// the cut covers the entry and the next heading line, nothing below it
	want := len(head + "## [1.0.0] - 2026-01-01\n")
	if e1.Source.CheckedBytes != want || e1.Source.CheckedBytes >= len(one) {
		t.Fatalf("checkedBytes %d, want %d of %d", e1.Source.CheckedBytes, want, len(one))
	}
	if e1.Source.CheckedDigest != hexSum([]byte(one)[:want]) || e1.Source.FileDigest != hexSum([]byte(one)) {
		t.Fatal("digests do not match the scoped and whole bytes")
	}
	e2 := mustLocate(t, c1Row(t), "v1.1.0", two)
	if e2.Source.CheckedBytes == e1.Source.CheckedBytes || e2.Source.CheckedDigest == e1.Source.CheckedDigest {
		t.Fatal("a moved cut point left the scoped length unchanged")
	}
	// the last entry has no following heading: the whole file is covered
	e3 := mustLocate(t, c1Row(t), "v0.9.0", one)
	if e3.Source.CheckedBytes != len(one) || e3.Source.CheckedDigest != e3.Source.FileDigest {
		t.Fatalf("%+v", e3.Source)
	}
	// editing below the cut changes the file digest and not the scoped one
	three := strings.Replace(one, "- z", "- zz", 1)
	e4 := mustLocate(t, c1Row(t), "v1.1.0", three)
	if e4.Source.CheckedDigest != e1.Source.CheckedDigest || e4.Source.FileDigest == e1.Source.FileDigest {
		t.Fatal("scoped digest must ignore the part below the cut")
	}
	// CRLF counts original bytes
	crlf := strings.ReplaceAll(one, "\n", "\r\n")
	e5 := mustLocate(t, c1Row(t), "v1.1.0", crlf)
	if e5.Source.CheckedBytes != want+strings.Count(head+"## [1.0.0] - 2026-01-01\n", "\n") {
		t.Fatalf("crlf checkedBytes %d", e5.Source.CheckedBytes)
	}
}

func TestScopedChecksDuplicateBelowStillRefuses(t *testing.T) {
	f := c1Head + "## [1.1.0] - 2026-01-02\n\n- n\n\n## [1.0.0] - 2026-01-01\n\n- a\n\n## [1.1.0] - 2026-01-03\n\n- m\n"
	_, err := locateMem(c1Row(t), "v1.1.0", f)
	wantCode(t, err, EntryDuplicate)
}

func TestScopedChecksSetextFollowingHeading(t *testing.T) {
	f := c1Head + "## [1.1.0] - 2026-01-02\n\n- n\n\n[1.0.0] - 2026-01-01\n-----------\n\n- a\n\n" + badHTML
	tg := styleRow(t, "version-bracketed-date", "unreleased-bracketed")
	e := mustLocate(t, tg, "v1.1.0", f)
	if e.Source.CheckedBytes != len(c1Head+"## [1.1.0] - 2026-01-02\n\n- n\n\n[1.0.0] - 2026-01-01\n-----------\n") {
		t.Fatalf("%d", e.Source.CheckedBytes)
	}
}

func TestProposePicksNotesPerVersionPath(t *testing.T) {
	body := "+++\ntitle = \"CoreDNS-1.15.0 Release\"\n+++\n\n## Brought to You By\n\nA B C.\n\n## Noteworthy Changes\n\n* plugin/x: a change\n* plugin/y: another change\n"
	tags := map[string]byte{"v1.15.0": 'a', "v1.14.1": 'a'}
	src := rcFixture(t, tags, map[string]string{
		"a|notes/coredns-1.15.0.md": body, "a|notes/coredns-1.14.1.md": body,
	})
	p, err := propose(t, src)
	if err != nil {
		t.Fatal(err)
	}
	if p.Row.Form != FormPerVersionFile || p.Row.Path != "notes/coredns-{version}.md" || p.Located != 2 {
		t.Fatalf("%+v", p)
	}
	// a file of another name is not tried
	src = rcFixture(t, tags, map[string]string{"a|notes/other-1.15.0.md": body, "a|notes/other-1.14.1.md": body})
	_, err = propose(t, src)
	wantNoRow(t, err, NoRowNoCandidate)
}
