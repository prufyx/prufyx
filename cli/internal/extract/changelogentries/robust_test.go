// SPDX-License-Identifier: AGPL-3.0-only

package changelogentries

import (
	"crypto/sha256"
	"encoding/hex"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func entryWith(body string) string {
	return "## 3.5.0 / 2025-07-14\n\n" + body + "\n## 3.4.0 / 2025-05-17\n\n* [FEATURE] z. #3\n"
}

func TestLinkDefinitionShape(t *testing.T) {
	prose := "[BREAKING]: the flag --foo was removed, use --bar"
	// Prose that looks like "[label]: text" is an item wherever it sits.
	for name, body := range map[string]string{
		"after blank":   "* [FEATURE] x. #1\n\n" + prose + "\n",
		"after heading": "### Notes\n" + prose + "\n* [FEATURE] x. #1\n",
		"first line":    prose + "\n",
		"two in a row":  "* [FEATURE] x. #1\n\n" + prose + "\n[CHANGE]: removed flag --x\n",
		"one word":      "* [FEATURE] x. #1\n\n[BREAKING]: removed\n",
		"two words":     "* [FEATURE] x. #1\n\n[BREAKING]: removed flag\n",
		"url then text": "* [FEATURE] x. #1\n\n[ref]: https://x.test/a and the flag --x is removed\n",
	} {
		e := locateOrDisagree(t, promTarget, "v3.5.0", entryWith(body))
		if e == nil {
			continue
		}
		if e.Tiling.LinkDefs != 0 {
			t.Errorf("%s: prose counted as a link definition: %+v", name, e.Tiling)
		}
		found := false
		for _, it := range e.Items {
			if it.Kind == "block" && it.StartLine > 2 {
				found = true
			}
		}
		if !found {
			t.Errorf("%s: no block item for the prose line: %+v", name, e.Items)
		}
		raw := []byte(entryWith(body))
		oracleAccount(t, raw, e)
	}
	// Real definitions still count, with or without a title.
	for _, def := range []string{
		"[a]: https://x.test/a", "[a]: <https://x.test/a>", `[a]: https://x.test/a "Title"`,
		"[a]: https://x.test/a 'Title'", "[a]: https://x.test/a (Title)", "[a]: /docs/a", "[a]: #frag",
	} {
		e := mustLocate(t, promTarget, "v3.5.0", entryWith("* [FEATURE] x. #1\n\n"+def+"\n"))
		if e.Tiling.LinkDefs != 1 || len(e.Items) != 1 {
			t.Errorf("%q: %+v %+v", def, e.Tiling, e.Items)
		}
		if !oracleIsLinkDef(def) {
			t.Errorf("oracle disagrees on %q", def)
		}
	}
	for _, not := range []string{prose, "[a]: removed", "[a]: https://x.test/a b c", `[a]: https://x.test/a "T" x`, "[a]:", "[]: https://x.test"} {
		if oracleIsLinkDef(not) {
			t.Errorf("oracle accepts %q", not)
		}
	}
}

func TestIndentedFenceWithoutOwner(t *testing.T) {
	for name, body := range map[string]string{
		"after heading":  "### Notes\n  ```\n  # fake\n  ```\n* [FEATURE] x. #1\n",
		"after break":    "---\n  ```\n  code\n  ```\n* [FEATURE] x. #1\n",
		"after linkdef":  "[a]: https://x.test\n  ```\n  code\n  ```\n* [FEATURE] x. #1\n",
		"unterminated":   "* [FEATURE] x. #1\n\n### Notes\n  ```\n  code\n",
		"tab indent":     "### Notes\n\t```\n\tcode\n\t```\n* [FEATURE] x. #1\n",
		"at file start":  "  ```\n",
		"fence then end": "### Notes\n  ```",
	} {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("%s: panic %v", name, r)
				}
			}()
			_, err := locateMem(promTarget, "v3.5.0", entryWith(body))
			if name == "at file start" {
				_, err = locateMem(promTarget, "v3.5.0", body)
				wantCode(t, err, EntryMissing)
				return
			}
			if c, _ := CodeOf(err); c != EntryParseResidue && c != EntryBoundaryUnproven {
				t.Errorf("%s: %v", name, err)
			}
		}()
	}
	// An indented fence after an item and a blank line is that item's continuation,
	// and what it holds is never read as a heading.
	c := mustLocate(t, promTarget, "v3.5.0", entryWith("* [FEATURE] x. #1\n\n  ~~~\n  ## 3.4.0 / 2025-05-17\n\n  ~~~\n"))
	if len(c.Items) != 1 || len(c.Structure) != 1 {
		t.Fatalf("%+v", c.Items)
	}
	oracleAccount(t, []byte(entryWith("* [FEATURE] x. #1\n\n  ~~~\n  ## 3.4.0 / 2025-05-17\n\n  ~~~\n")), c)
	// The same fence in ANOTHER entry does not disturb the located one.
	f := "## 3.5.0 / 2025-07-14\n\n* [FEATURE] x. #1\n\n## 3.4.0 / 2025-05-17\n\n### Notes\n  ```\n  # fake\n  ## 3.5.0 / 2025-07-14\n  ```\n* [FEATURE] y. #2\n"
	e := mustLocate(t, promTarget, "v3.5.0", f)
	if len(e.Items) != 1 || e.Section.EndLine != 3 {
		t.Fatalf("%+v", e.Section)
	}
	// Its contents are not read as headings: a hidden heading cannot end or duplicate an entry.
	g := "## 3.5.0 / 2025-07-14\n\n### Notes\n  ```\n  ## 3.4.0 / 2025-05-17\n  ```\n"
	_, err := locateMem(promTarget, "v3.5.0", g)
	wantCode(t, err, EntryParseResidue)
}

var mixLines = []string{
	"", "", "* [CHANGE] x", "* [FEATURE] y", "  continued", "\tnested", "- a", "1. b", "```", "  ```", "~~~", "  ~~~",
	"---", "===", "--", "=", "-", "# T", "## 3.5.0 / 2025-01-01", "## 3.4.0 / 2024-01-01", "### Added", "### Fixed", "Text", "Title",
	"[a]: https://x", "[BREAKING]: gone", "[a]: <https://x> 'T'", "<details>", "</details>", "* ", "> quote", "| a | b |", "    code", "* * *",
	"## 3.5.0-rc.0 / 2024-12-01", "## main / unreleased", "* [CHANGE] x",
}

func checkNoPanic(t *testing.T, data []byte) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("panic %v on %q", r, data)
		}
	}()
	for _, tg := range []string{"v3.5.0", "v3.4.0"} {
		e, err := locateBytes(promTarget, tg, data)
		if err != nil {
			if _, ok := CodeOf(err); !ok {
				t.Fatalf("untyped error %v on %q", err, data)
			}
			continue
		}
		oracleAccount(t, data, e)
		if lines, lerr := splitLines(data); lerr == nil {
			if d := cmDisagreement(lines, scan(lines), e.Section.StartLine, e.Section.EndLine); d != "" {
				t.Fatalf("entry returned although the CommonMark oracle disagrees (%s) on %q", d, data)
			}
		}
		if b, err := e.Canonical(); err != nil || len(b) == 0 {
			t.Fatal("canonical failed")
		}
	}
}

func TestRandomLineMixesNeverPanic(t *testing.T) {
	rng := rand.New(rand.NewSource(614))
	for i := 0; i < 4000; i++ {
		n := 2 + rng.Intn(24)
		var b strings.Builder
		for j := 0; j < n; j++ {
			b.WriteString(mixLines[rng.Intn(len(mixLines))])
			b.WriteByte('\n')
		}
		checkNoPanic(t, []byte(b.String()))
	}
}

func FuzzLocate(f *testing.F) {
	files, _ := filepath.Glob(filepath.Join("testdata", "fixture", "github.com", "*", "*", "commits", "*", "CHANGELOG.md"))
	for _, p := range files {
		if b, err := os.ReadFile(p); err == nil {
			f.Add(b)
		}
	}
	f.Add([]byte(promFile))
	f.Add([]byte(shapeBlankLabel))
	f.Add([]byte(shapeFootnote))
	f.Add([]byte(shapeDeepClose))
	for _, s := range []string{shapeHTMLInItem, shapeHTMLDivItem, shapeHTMLBlankEnd, shapeHTMLPreTab, shapeHTMLPreOpen, shapeTabStop, shapeTabOpener, shapeHTMLComment, shapeHTMLPre, shapeHTMLBeforeEntry, shapeHTMLInEntry, shapeHTMLOneLine, shapeItemFenceNoCloser, shapeOpenerLeftOfItem, shapeOpenerFourPast, shapeListFence, shapeListFenceNested, shapeQuoteFence, shapeNBSPClose, shapeBareAngle} {
		f.Add([]byte(s))
	}
	f.Add([]byte("## 3.5.0 / 2025-07-14\n\n### Notes\n  ```\n  code\n"))
	f.Fuzz(func(t *testing.T, data []byte) { checkNoPanic(t, data) })
}

func TestSecondWordingIsAmbiguous(t *testing.T) {
	for _, extra := range []string{"## Upgrade notes for 3.5.0\n\n* x\n", "### Migrating to v3.5.0\n"} {
		f := promFile + "\n" + extra
		_, err := locateMem(promTarget, "v3.5.0", f)
		wantCode(t, err, EntryDuplicate)
	}
	// A release candidate heading of the same version is a boundary, not a second wording.
	f := "## 3.5.0 / 2025-07-14\n\n* [FEATURE] x. #1\n\n## 3.5.0-rc.0 / 2025-06-01\n\n* y\n"
	if _, err := locateMem(promTarget, "v3.5.0", f); err != nil {
		t.Fatal(err)
	}
	// The thanos heading with unreleased wording is not final.
	_, err := locateMem(thanosTarget, "v0.38.0", "## [v0.38.0](https://x/tree/release-0.38) - in progress\n\n### Added\n\n- [#1](u) x\n")
	wantCode(t, err, EntryNotFinal)
}

func TestDigestFormulaAndControlBytes(t *testing.T) {
	e := mustLocate(t, thanosTarget, "v0.38.0", thanosFile("### Fixed", "### Added", "- [#1](u) same text"))
	it := e.Items[1]
	h := sha256.New()
	h.Write([]byte("thanos\x00" + "0.38.0\x00" + "Added\x00" + "" + "\x00" + "- [#1](u) same text"))
	if it.Digest != hex.EncodeToString(h.Sum(nil)) {
		t.Fatal("digest does not follow the documented formula")
	}
	// Two levels must not alias one level whose text holds the separator.
	for _, c := range []byte{0x1f, 0x0c, 0x01, 0x7f - 0x60} {
		f := strings.Replace(promFile, "### ", "### ", 1)
		f = strings.Replace(f, "* [BUGFIX] C. #3", "* [BUGFIX] C"+string([]byte{c})+". #3", 1)
		_, err := locateMem(promTarget, "v3.5.0", f)
		wantCode(t, err, EntryParseResidue)
	}
}

func TestAnchoringIsStructural(t *testing.T) {
	for _, p := range []string{`^a|b$`, `^(?P<version>[0-9.]+)$|^x$`, `(?m)^(?P<version>[0-9.]+)$`, `^(?P<version>[0-9.]+)\$`, `^(?P<version>[0-9.]+)`, `(?P<version>[0-9.]+)$`} {
		tg := promTarget
		tg.HeadingPattern = p
		_, err := locateMem(tg, "v3.5.0", promFile)
		if c, _ := CodeOf(err); c != NoChangelogTarget {
			t.Errorf("%q accepted: %v", p, err)
		}
	}
	tg := promTarget
	tg.BoundaryPatterns = []string{`^a$|b`}
	_, err := locateMem(tg, "v3.5.0", promFile)
	wantCode(t, err, NoChangelogTarget)
	tg.BoundaryPatterns = []string{`^(?:main|master) / unreleased$`}
	if _, err := locateMem(tg, "v3.5.0", promFile); err != nil {
		t.Fatal(err)
	}
}

// A lone "=" or "-" under a text line is a setext underline in Markdown. The
// scanner does not take it for one, so the CommonMark oracle disagrees and the
// file is withheld.
func TestOneCharUnderlineIsOverInclusive(t *testing.T) {
	f := "## 3.5.0 / 2025-07-14\n\n* [FEATURE] x. #1\n\nTitle\n=\n\n## 3.4.0 / 2025-05-17\n\n* z\n"
	// CommonMark reads it as a heading and the scanner does not: withheld.
	if e := locateOrDisagree(t, promTarget, "v3.5.0", f); e != nil {
		t.Fatalf("located %+v", e.Section)
	}
}

const (
	shapeBlankLabel        = "## 3.5.0 / 2025-07-14\n\n* [FEATURE] x. #1\n\n[ ]: https://x.test \"the flag --foo was removed\"\n"
	shapeFootnote          = "## 3.5.0 / 2025-07-14\n\n* [FEATURE] x. #1\n\n[^1]: #1234 \"the flag --foo was removed\"\n"
	shapeListFence         = "## 3.5.0 / 2025-07-14\n\n* ~~~\n  ## 3.4.0 / 2025-05-17\n  * [CHANGE] flag --x removed\n  ~~~\n\n* [BUGFIX] tail. #9\n"
	shapeListFenceNested   = "## 3.5.0 / 2025-07-14\n\n1. [FEATURE] x\n  - ```\n  ## 3.4.0 / 2025-05-17\n  ```\n* [BUGFIX] tail. #9\n"
	shapeQuoteFence        = "## 3.5.0 / 2025-07-14\n\n> ~~~\n  ## 3.4.0 / 2025-05-17\n> ~~~\n* [BUGFIX] tail. #9\n"
	shapeNBSPClose         = "## 3.5.0 / 2025-07-14\n\n* [FEATURE] x\n\n  ~~~\n  code\n  ~~~\u00a0\n## 3.4.0 / 2025-05-17\n  * [CHANGE] flag --x removed\n  ~~~\n\n* [BUGFIX] tail. #9\n"
	shapeBareAngle         = "## 3.5.0 / 2025-07-14\n\n* [FEATURE] x. #1\n\n[r]: https://x/<bad> \"removed --foo\"\n"
	shapeItemFenceNoCloser = "## 3.5.0 / 2025-07-14\n* [ENHANCEMENT] Example config:\n  ~~~\n  key: value\nThanks to all contributors.\n~~~\n## 3.4.0 / 2025-05-17\n~~~\n* [CHANGE] The flag --foo was removed.\n\n## 3.4.0 / 2025-05-17\n* [BUGFIX] x\n"
	shapeOpenerLeftOfItem  = "## 3.5.0 / 2025-07-14\n\n* [FEATURE] x\n\n * [BUGFIX] y\n ```\n  ```\n## 3.4.0 / 2025-05-17\n```\n* [CHANGE] z\n"
	shapeOpenerFourPast    = "## 3.5.0 / 2025-07-14\n\n* [FEATURE] x\n\n      ~~~\n~~~\n## 3.4.0 / 2025-05-17\n~~~\n* [CHANGE] z\n"
	shapeTabStop           = "## 3.5.0 / 2025-07-14\n- outer\n  1. inner\n     ~~~\n     code\n   \t- sibling\n     ~~~\n## 3.4.0 / 2025-05-17\n  ~~~\n- [CHANGE] The flag --foo was removed.\n"
	shapeTabOpener         = "## 3.5.0 / 2025-07-14\n* [FEATURE] x\n\t~~~\n\tcode\n\t~~~\n* [BUGFIX] y\n"
	shapeHTMLComment       = "## 3.5.0 / 2025-07-14\n* [FEATURE] x\n<!--\n## 3.4.0 / 2025-05-17\n-->\n* [CHANGE] The flag --foo was removed.\n\n## 3.4.0 / 2025-05-17\n* [BUGFIX] y\n"
	shapeHTMLPre           = "## 3.5.0 / 2025-07-14\n* [FEATURE] x\n\n<pre>\n~~~\n</pre>\n\n~~~\n## 3.4.0 / 2025-05-17\n~~~\n* [CHANGE] The flag --foo was removed.\n"
	shapeHTMLBeforeEntry   = "# Changelog\n<!--\n## 3.5.0 / 2025-07-14\n-->\n\n## 3.5.0 / 2025-07-14\n* [FEATURE] x\n\n## 3.4.0 / 2025-05-17\n* [BUGFIX] y\n"
	shapeHTMLInEntry       = "## 3.5.0 / 2025-07-14\n* [FEATURE] x\n\n<details>\n\n* [CHANGE] The flag --foo was removed.\n\n## 3.4.0 / 2025-05-17\n* [BUGFIX] y\n"
	shapeHTMLOneLine       = "## 3.5.0 / 2025-07-14\n* [FEATURE] x\n\n## 3.4.0 / 2025-05-17\n<!-- a note -->\n* [BUGFIX] y\n"
	shapeHTMLInItem        = "## 3.5.0 / 2025-07-14\n- [FEATURE] x\n- <!--\n  ## 3.4.0 / 2025-05-17\n  -->\n- [CHANGE] The flag --foo was removed.\n"
	shapeHTMLDivItem       = "## 3.5.0 / 2025-07-14\n- [FEATURE] x\n- <div>\n  ## 3.4.0 / 2025-05-17\n  </div>\n- [CHANGE] The flag --foo was removed.\n"
	shapeHTMLBlankEnd      = "# Changelog\n\n<div>\n~~~\n</div>\n\n## 3.5.0 / 2025-07-14\n- [CHANGE] The flag --foo was removed.\n\n~~~\n## 3.4.0 / 2025-05-17\n~~~\n"
	shapeHTMLPreTab        = "# Changelog\n\n<pre\tx>\n~~~\n</pre>\n\n## 3.5.0 / 2025-07-14\n- [CHANGE] The flag --foo was removed.\n\n~~~\n## 3.4.0 / 2025-05-17\n~~~\n"
	shapeHTMLPreOpen       = "# Changelog\n\n<pre>\n~~~\n</pre\n\n## 3.5.0 / 2025-07-14\n- [CHANGE] The flag --foo was removed.\n\n~~~\n## 3.4.0 / 2025-05-17\n~~~\n"
	shapeDeepClose         = "## 3.5.0 / 2025-07-14\n\n* [FEATURE] x. #1\n\n```\n    ```\n## 3.4.0 / 2025-05-17\n* [CHANGE] flag --x removed\n```\n\n* [BUGFIX] tail. #9\n"
)

// A label of spaces only, a footnote label and a destination with an
// unbalanced parenthesis are not link definitions: each line is a block item
// with its own digest, never a silently counted definition.
func TestLinkLikeLinesAreItems(t *testing.T) {
	for name, line := range map[string]string{
		"blank label":      `[ ]: https://x.test "the flag --foo was removed"`,
		"tab label":        "[\t]: https://x.test \"the flag --foo was removed\"",
		"footnote":         `[^1]: #1234 "the flag --foo was removed"`,
		"footnote no text": `[^note]: https://x.test/a`,
		"open paren":       `[a]: https://x.test/a(b "the flag --foo was removed"`,
		"paren in url":     `[a]: https://x.test/(b) "the flag --foo was removed"`,
		"title only":       `[a]: "the flag --foo was removed"`,
	} {
		for ctx, body := range map[string]string{
			"after blank":   "* [FEATURE] x. #1\n\n" + line + "\n",
			"after heading": "### Notes\n" + line + "\n* [FEATURE] x. #1\n",
		} {
			f := entryWith(body)
			e := locateOrDisagree(t, promTarget, "v3.5.0", f)
			if e == nil {
				continue
			}
			if e.Tiling.LinkDefs != 0 {
				t.Errorf("%s/%s: counted as a definition", name, ctx)
			}
			found := false
			for _, it := range e.Items {
				if it.Kind == "block" && strings.Contains(strings.Join(strings.Split(f, "\n")[it.StartLine-1:it.EndLine], "\n"), "the flag --foo") || it.Kind == "block" && name == "footnote no text" {
					found = true
				}
			}
			if !found {
				t.Errorf("%s/%s: no block item: %+v", name, ctx, e.Items)
			}
			oracleAccount(t, []byte(f), e)
		}
		if oracleIsLinkDef(line) {
			t.Errorf("oracle accepts %q", line)
		}
	}
	// One link-like token plus a quoted title is still a definition.
	for _, def := range []string{`[a]: https://x.test/a "t"`, `[a b]: https://x.test/a`} {
		e := mustLocate(t, promTarget, "v3.5.0", entryWith("* [FEATURE] x. #1\n\n"+def+"\n"))
		if e.Tiling.LinkDefs != 1 || !oracleIsLinkDef(def) {
			t.Errorf("%q: %+v", def, e.Tiling)
		}
	}
}

// A line of fence characters indented four columns or more is code inside the
// fence, not its closing line: what follows must not be read as structure.
func TestDeeplyIndentedFenceLineDoesNotClose(t *testing.T) {
	f := shapeDeepClose + "\n## 3.4.0 / 2025-05-17\n\n* [FEATURE] z. #3\n"
	e := mustLocate(t, promTarget, "v3.5.0", f)
	if len(e.Structure) != 1 || len(e.Items) != 3 || e.Section.EndLine != 11 {
		t.Fatalf("entry truncated or split: %+v %+v", e.Section, e.Items)
	}
	if e.Items[2].Marker != "BUGFIX" {
		t.Fatalf("tail item lost: %+v", e.Items)
	}
	oracleAccount(t, []byte(f), e)
	// A tab-indented fence line is also code.
	g := strings.Replace(f, "    ```\n", "\t```\n", 1)
	if e2 := mustLocate(t, promTarget, "v3.5.0", g); len(e2.Items) != 3 {
		t.Fatalf("tab: %+v", e2.Items)
	}
	// A closing fence indented up to three columns past its opener still closes.
	h := "## 3.5.0 / 2025-07-14\n\n* [FEATURE] x\n\n  ```\n  code\n     ```\n\n* [BUGFIX] after. #9\n"
	// An indented opener is read without its container: a closer indented
	// differently from the opener is a file-wide stop, not a close.
	_, err0 := locateMem(promTarget, "v3.5.0", h)
	wantCode(t, err0, EntryParseResidue)
	// Four columns past the opener does not close it: the fence runs to the end, unterminated.
	k := "## 3.5.0 / 2025-07-14\n\n* [FEATURE] x\n\n  ```\n  code\n      ```\n\n* [BUGFIX] after. #9\n"
	_, err := locateMem(promTarget, "v3.5.0", k)
	wantCode(t, err, EntryParseResidue)
}

func TestNewShapesNeverPanic(t *testing.T) {
	for _, s := range []string{shapeHTMLInItem, shapeHTMLDivItem, shapeHTMLBlankEnd, shapeHTMLPreTab, shapeHTMLPreOpen, shapeTabStop, shapeTabOpener, shapeHTMLComment, shapeHTMLPre, shapeHTMLBeforeEntry, shapeHTMLInEntry, shapeHTMLOneLine, shapeItemFenceNoCloser, shapeOpenerLeftOfItem, shapeOpenerFourPast, shapeBlankLabel, shapeFootnote, shapeDeepClose, shapeListFence, shapeListFenceNested, shapeQuoteFence, shapeNBSPClose, shapeBareAngle} {
		checkNoPanic(t, []byte(s))
	}
}

// A fence opened inside a list item or block quote is not tracked, so a
// release-looking line inside it must never truncate an entry: the file is
// refused with a typed stop, never located.
func TestContainerFenceIsRefused(t *testing.T) {
	for name, s := range map[string]string{
		"list": shapeListFence, "nested list": shapeListFenceNested, "quote": shapeQuoteFence,
		"ordered":   "## 3.5.0 / 2025-07-14\n\n1) ~~~\n  ## 3.4.0 / 2025-05-17\n  ~~~\n* [BUGFIX] t\n",
		"backticks": "## 3.5.0 / 2025-07-14\n\n- ```go\n  ## 3.4.0 / 2025-05-17\n  ```\n* [BUGFIX] t\n",
		"indented":  "## 3.5.0 / 2025-07-14\n\n* [FEATURE] x\n  * ~~~\n  ## 3.4.0 / 2025-05-17\n  ~~~\n* [BUGFIX] t\n",
	} {
		for _, tg := range []string{"v3.5.0", "v3.4.0"} {
			e, err := locateMem(promTarget, tg, s)
			if err == nil {
				t.Errorf("%s %s: located %+v", name, tg, e.Section)
				continue
			}
			wantCode(t, err, EntryParseResidue)
		}
	}
	// Inline code that merely contains backticks is not a fence.
	mustLocate(t, promTarget, "v3.5.0", "## 3.5.0 / 2025-07-14\n\n* [FEATURE] ```x``` y\n* [BUGFIX] t\n")
}

// Only an ASCII space or tab may follow or precede a closing fence: a
// no-break space makes the line code inside the fence, and the fence then
// runs unterminated, so the heading inside it can never truncate the entry.
func TestUnicodeWhitespaceDoesNotCloseFence(t *testing.T) {
	for _, ws := range []string{"\u00a0", "\u2003", "\u3000", "\u200b"} {
		for _, f := range []string{
			strings.Replace(shapeNBSPClose, "\u00a0", ws, 1),
			strings.Replace(shapeNBSPClose, "  ~~~\u00a0", "  "+ws+"~~~", 1),
		} {
			// The fence stays open to its real closing line, so the entry is
			// either refused or complete: it must reach the last line and the
			// heading inside the fence must not be one.
			total := strings.Count(f, "\n")
			e, err := locateMem(promTarget, "v3.5.0", f)
			if err != nil {
				wantCode(t, err, EntryParseResidue)
				continue
			}
			if e.Section.EndLine != total || len(e.Structure) != 1 || len(e.Items) != 2 {
				t.Errorf("%q: truncated or split entry %+v %+v", ws, e.Section, e.Items)
			}
		}
	}
	// A control: with a real ASCII closing the entry ends at the next release heading.
	ctl := "## 3.5.0 / 2025-07-14\n\n* [FEATURE] x\n\n  ~~~\n  code\n  ~~~\n## 3.4.0 / 2025-05-17\n* [BUGFIX] y\n"
	if e := mustLocate(t, promTarget, "v3.5.0", ctl); e.Section.EndLine != 7 {
		t.Fatalf("control did not end at the release heading: %+v", e.Section)
	}
	// ASCII space and tab still close.
	f := "## 3.5.0 / 2025-07-14\n\n* [FEATURE] x\n\n  ~~~\n  code\n  ~~~ \t\n\n* [BUGFIX] tail. #9\n"
	if e := mustLocate(t, promTarget, "v3.5.0", f); len(e.Items) != 2 {
		t.Fatalf("%+v", e.Items)
	}
	// A line of only no-break spaces is text, not a blank.
	g := "## 3.5.0 / 2025-07-14\n\n* [FEATURE] x\n\u00a0\n* [BUGFIX] tail. #9\n"
	e := mustLocate(t, promTarget, "v3.5.0", g)
	if e.Tiling.Blanks != 1 {
		t.Fatalf("no-break space line counted as blank: %+v", e.Tiling)
	}
}

// A bare destination holds no angle bracket: such a line is an item with its
// own digest, never a silently excluded link definition.
func TestBareDestinationAngleBracketIsItem(t *testing.T) {
	for _, def := range []string{`[r]: https://x/<bad> "removed --foo"`, `[r]: https://x/bad> "removed --foo"`, `[r]: https://x/<bad`} {
		e := locateOrDisagree(t, promTarget, "v3.5.0", entryWith("* [FEATURE] x. #1\n\n"+def+"\n"))
		if e == nil {
			continue
		}
		if e.Tiling.LinkDefs != 0 || oracleIsLinkDef(def) || len(e.Items) != 2 {
			t.Errorf("%q: %+v items %d", def, e.Tiling, len(e.Items))
		}
	}
	for _, s := range []string{shapeBareAngle} {
		checkNoPanic(t, []byte(s))
	}
}

// A fence opened on an indented line is read without its container, so an
// inner line or closer indented differently from the opener stops the whole
// file, for every tag, instead of inverting the fence state.
func TestIndentedOpenerFenceStop(t *testing.T) {
	g := strings.Replace(shapeItemFenceNoCloser, "~~~\n## 3.4.0 / 2025-05-17\n~~~", "~~~\n\n## 3.4.0 / 2025-05-17\n~~~", 1)
	for name, s := range map[string]string{
		"item fence no closer": shapeItemFenceNoCloser, "opener left of item": shapeOpenerLeftOfItem,
		"opener four past": shapeOpenerFourPast, "with blank": g,
	} {
		for _, tg := range []string{"v3.5.0", "v3.4.0"} {
			e, err := locateMem(promTarget, tg, s)
			if err == nil {
				t.Errorf("%s %s: located %+v", name, tg, e.Section)
				continue
			}
			wantCode(t, err, EntryParseResidue)
		}
	}
	// Control: an indented fence closed at exactly its opener's indentation is read.
	ok := "## 3.5.0 / 2025-07-14\n\n* [FEATURE] x\n  ~~~\n  code\n  ~~~\n* [BUGFIX] y\n"
	if e := mustLocate(t, promTarget, "v3.5.0", ok); len(e.Items) != 2 {
		t.Fatalf("%+v", e.Items)
	}
}

// A tab in the white space of a fence opened on an indented line, and a line
// that does not carry the opener's own white space as a prefix, stop the file;
// so does any HTML block that can hide a heading or a fence, and any HTML
// block inside the entry itself.
func TestTabAndHTMLBlockStops(t *testing.T) {
	for name, s := range map[string]string{
		"tab stop sibling": shapeTabStop, "tab opener": shapeTabOpener, "comment hides heading": shapeHTMLComment,
		"pre hides fence": shapeHTMLPre, "comment before entry": shapeHTMLBeforeEntry, "html in entry": shapeHTMLInEntry,
		"script":                  "## 3.5.0 / 2025-07-14\n* [FEATURE] x\n\n<script>\n## 3.4.0 / 2025-05-17\n</script>\n",
		"style":                   "## 3.5.0 / 2025-07-14\n* [FEATURE] x\n\n<STYLE>\n# a\n</style>\n",
		"textarea":                "## 3.5.0 / 2025-07-14\n* [FEATURE] x\n\n<textarea>\n~~~\n</textarea>\n",
		"pi":                      "## 3.5.0 / 2025-07-14\n* [FEATURE] x\n\n<?x\n## 3.4.0 / 2025-05-17\n?>\n",
		"cdata":                   "## 3.5.0 / 2025-07-14\n* [FEATURE] x\n\n<![CDATA[\n## 3.4.0 / 2025-05-17\n]]>\n",
		"declaration":             "## 3.5.0 / 2025-07-14\n* [FEATURE] x\n\n<!DOCTYPE\n## 3.4.0 / 2025-05-17\n>\n",
		"inside comment in entry": "## 3.5.0 / 2025-07-14\n* [FEATURE] x\n\n<!-- one line -->\n",
		"closing tag in entry":    "## 3.5.0 / 2025-07-14\n* [FEATURE] x\n\n</div>\n",
	} {
		e, err := locateMem(promTarget, "v3.5.0", s)
		if err == nil {
			t.Errorf("%s: located %+v", name, e.Section)
			continue
		}
		wantCode(t, err, EntryParseResidue)
	}
	// The tab-stop and the multi-line shapes stop the file for the other tag too.
	for _, s := range []string{shapeTabStop, shapeHTMLComment, shapeHTMLPre} {
		_, err := locateMem(promTarget, "v3.4.0", s)
		wantCode(t, err, EntryParseResidue)
	}
	// A one-line comment outside the entry is fine.
	mustLocate(t, promTarget, "v3.5.0", shapeHTMLOneLine)
}

// locateOrDisagree locates the file, or returns nil when the CommonMark oracle
// disagrees with the scanner and the file is withheld (the safe outcome for a
// shape the scanner reads more strictly than CommonMark).
func locateOrDisagree(t *testing.T, tg Target, tagName, file string) *Entry {
	t.Helper()
	e, err := locateMem(tg, tagName, file)
	if err != nil {
		wantCode(t, err, EntryParseResidue)
		if !strings.Contains(err.Error(), "commonmark-disagreement") {
			t.Fatalf("unexpected refusal: %v", err)
		}
		return nil
	}
	return e
}

// Container-started HTML, HTML ended by a blank line, a tab after a raw tag
// name and an end tag without ">" are all stopped by a hand rule or by the
// CommonMark oracle, for both tags: no entry is returned.
func TestHTMLClassNegatives(t *testing.T) {
	for name, s := range map[string]string{
		"comment in item": shapeHTMLInItem, "div in item": shapeHTMLDivItem, "blank-terminated div": shapeHTMLBlankEnd,
		"pre tab": shapeHTMLPreTab, "pre without end bracket": shapeHTMLPreOpen,
		"details":    "# Changelog\n\n<details>\n~~~\n</details>\n\n## 3.5.0 / 2025-07-14\n- [CHANGE] x\n\n~~~\n## 3.4.0 / 2025-05-17\n~~~\n",
		"table":      "# Changelog\n\n<table>\n~~~\n</table>\n\n## 3.5.0 / 2025-07-14\n- [CHANGE] x\n\n~~~\n## 3.4.0 / 2025-05-17\n~~~\n",
		"quote html": "## 3.5.0 / 2025-07-14\n- [FEATURE] x\n\n> <!--\n> ## 3.4.0 / 2025-05-17\n> -->\n- [CHANGE] y\n",
	} {
		for _, tg := range []string{"v3.5.0", "v3.4.0"} {
			if e, err := locateMem(promTarget, tg, s); err == nil {
				t.Errorf("%s %s: located %+v", name, tg, e.Section)
			} else {
				wantCode(t, err, EntryParseResidue)
			}
		}
	}
}

// Every returned entry is one the CommonMark oracle agrees with.
func TestOracleAgreesWithEveryFixtureEntry(t *testing.T) {
	files, _ := filepath.Glob(filepath.Join("testdata", "fixture", "github.com", "*", "*", "commits", "*", "CHANGELOG.md"))
	if len(files) == 0 {
		t.Fatal("no fixtures")
	}
	for _, p := range files {
		b, _ := os.ReadFile(p)
		lines, err := splitLines(b)
		if err != nil {
			t.Fatal(err)
		}
		if d := cmDisagreement(lines, scan(lines), 0, 0); d != "" {
			t.Errorf("%s: %s", p, d)
		}
	}
}

// A release heading nested in a list item or a quote, and a block that crosses
// a section boundary, withhold the whole file for every tag.
func TestContainerHeadingsAndCrossingBlocksWithholdFile(t *testing.T) {
	for name, s := range map[string]string{
		"heading in list item": "## 3.6.0 / 2025-09-01\n\n* outer\n  ## 3.5.0 / 2025-07-14\n* [FEATURE] x\n\n## 3.4.0 / 2025-05-17\n\n* [FEATURE] z. #3\n",
		"heading in quote":     "## 3.6.0 / 2025-09-01\n\n> outer\n> ## 3.5.0 / 2025-07-14\n* [FEATURE] x\n\n## 3.4.0 / 2025-05-17\n\n* [FEATURE] z. #3\n",
		"heading in nested":    "## 3.6.0 / 2025-09-01\n\n* outer\n  > ## 3.5.0 / 2025-07-14\n* [FEATURE] x\n\n## 3.4.0 / 2025-05-17\n\n* [FEATURE] z. #3\n",
	} {
		for _, tg := range []string{"v3.6.0", "v3.5.0", "v3.4.0"} {
			e, err := locateMem(promTarget, tg, s)
			if err == nil {
				t.Errorf("%s %s: located %+v", name, tg, e.Section)
				continue
			}
			wantCode(t, err, EntryParseResidue)
		}
	}
	// The section-boundary check itself: a unit that starts before the section
	// and reaches into it, or starts inside it and ends after it.
	v := &cmView{units: []cmUnit{{lo: 3, hi: 6}}}
	if cmSectionDisagreement(v, 5, 9) == "" || cmSectionDisagreement(v, 1, 4) == "" {
		t.Error("a crossing unit passed")
	}
	if cmSectionDisagreement(v, 7, 9) != "" || cmSectionDisagreement(v, 1, 6) != "" {
		t.Error("a contained or disjoint unit refused")
	}
}

// An item disagreement anywhere in the file withholds every tag, including a
// tag whose own section is clean.
func TestItemDisagreementElsewhereWithholdsEveryTag(t *testing.T) {
	f := "## 3.5.0 / 2025-07-14\n\n* [FEATURE] x. #1\n\n## 3.4.0 / 2025-05-17\n\n[^1]: #1234 \"the flag --foo was removed\"\n* [FEATURE] z. #3\n"
	lines, err := splitLines([]byte(f))
	if err != nil {
		t.Fatal(err)
	}
	if lines2 := scan(lines); cmDisagreement(lines, lines2, 0, 0) == "" {
		t.Skip("the oracle and the scanner agree on this shape")
	}
	for _, tg := range []string{"v3.5.0", "v3.4.0"} {
		_, err := locateMem(promTarget, tg, f)
		wantCode(t, err, EntryParseResidue)
	}
}
