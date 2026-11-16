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

	"github.com/prufyx/prufyx/cli/internal/extract"
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
		e := mustLocate(t, promTarget, "v3.5.0", entryWith(body))
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
// reader does not take it for one: the pair becomes a block item (and the
// entry runs on into the next heading's section). That is over-inclusive
// (never a dropped line) and is pinned here so a change is deliberate.
func TestOneCharUnderlineIsOverInclusive(t *testing.T) {
	f := "## 3.5.0 / 2025-07-14\n\n* [FEATURE] x. #1\n\nTitle\n=\n\n## 3.4.0 / 2025-05-17\n\n* z\n"
	e := mustLocate(t, promTarget, "v3.5.0", f)
	if len(e.Items) != 2 || e.Items[1].Kind != "block" || e.Items[1].StartLine != 5 || e.Items[1].EndLine != 6 || e.Section.EndLine != 6 {
		t.Fatalf("%+v %+v", e.Items, e.Section)
	}
	oracleAccount(t, []byte(f), e)
	g := "## 3.5.0 / 2025-07-14\n\n* [FEATURE] x. #1\n\nTitle\n-\n\n## 3.4.0 / 2025-05-17\n\n* z\n"
	e = mustLocate(t, promTarget, "v3.5.0", g)
	oracleAccount(t, []byte(g), e)
	_ = extract.Tag{}
}

const (
	shapeBlankLabel = "## 3.5.0 / 2025-07-14\n\n* [FEATURE] x. #1\n\n[ ]: https://x.test \"the flag --foo was removed\"\n"
	shapeFootnote   = "## 3.5.0 / 2025-07-14\n\n* [FEATURE] x. #1\n\n[^1]: #1234 \"the flag --foo was removed\"\n"
	shapeDeepClose  = "## 3.5.0 / 2025-07-14\n\n* [FEATURE] x. #1\n\n```\n    ```\n## 3.4.0 / 2025-05-17\n* [CHANGE] flag --x removed\n```\n\n* [BUGFIX] tail. #9\n"
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
			e := mustLocate(t, promTarget, "v3.5.0", f)
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
	e = mustLocate(t, promTarget, "v3.5.0", h)
	if len(e.Items) != 2 {
		t.Fatalf("close at +3: %+v", e.Items)
	}
	// Four columns past the opener does not close it: the fence runs to the end, unterminated.
	k := "## 3.5.0 / 2025-07-14\n\n* [FEATURE] x\n\n  ```\n  code\n      ```\n\n* [BUGFIX] after. #9\n"
	_, err := locateMem(promTarget, "v3.5.0", k)
	wantCode(t, err, EntryParseResidue)
}

func TestNewShapesNeverPanic(t *testing.T) {
	for _, s := range []string{shapeBlankLabel, shapeFootnote, shapeDeepClose} {
		checkNoPanic(t, []byte(s))
	}
}
