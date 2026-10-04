// SPDX-License-Identifier: AGPL-3.0-only

package consensus

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Regression cases for hidden-content attacks. Each replaces one visible
// removal item of the C01 control with a variant that a reader of the
// rendered page would not see, or would not read as a cited removal, and
// must not verify.

const atkPR = "([#140005](https://github.com/kubernetes/kubernetes/pull/140005), [@dev-h](https://github.com/dev-h)) [SIG Node]"
const atkItem = "- Removed the SilentDial feature gate. " + atkPR

const retired = "- Removed the `RetiredKnob` feature gate, which was locked to its default since v1.38. ([#140001](https://github.com/kubernetes/kubernetes/pull/140001), [@dev-c](https://github.com/dev-c)) [SIG Node]"

type attack struct {
	id, desc string
	// inject replaces the RetiredKnob item of C01; whole, when set,
	// rewrites the whole file instead.
	inject string
	whole  func(string) string
	names  []string
}

// mayVerify are the variants that verify by design: X00 is the plain
// visible item; X27 cites a visible item before a real level-1 heading
// (the contradicting item belongs to another section); X28 is the plain
// item in a file with CRLF line endings; X14 cites a merged pull request
// of the range that is unrelated to the removal, which no offline check
// can tell (a documented limit; the absence check in the later release
// still holds).
var mayVerify = map[string]bool{"X00": true, "X14": true, "X27": true, "X28": true}

func TestHiddenContentAttacksDoNotVerify(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(corpusDir, "controls", "C01-gate-link-squash", "CHANGELOG-1.41.md"))
	if err != nil {
		t.Fatal(err)
	}
	base := string(raw)
	if !strings.Contains(base, retired) {
		t.Fatal("template line not found")
	}
	itemB := "- Restored the SilentDial feature gate after a regression; its removal is reverted. ([#140006](https://github.com/kubernetes/kubernetes/pull/140006), [@dev-h](https://github.com/dev-h)) [SIG Node]"
	attacks := []attack{
		{id: "X00", desc: "control: plain visible item", inject: atkItem},
		{id: "X01", desc: "indented code block (4 spaces after blank line)", inject: "    " + atkItem},
		{id: "X02", desc: "multi-line <img alt=\"...\"> attribute hides the item", inject: "<img alt=\"\n" + atkItem + "\n\" src=\"x.png\">"},
		{id: "X03", desc: "multi-line <a title=\"...\"> attribute hides the item", inject: "<a href=\"https://example.invalid\" title=\"\n" + atkItem + "\n\">docs</a>"},
		{id: "X04", desc: "<style> block hides the item", inject: "<style>\n" + atkItem + "\n</style>"},
		{id: "X05", desc: "<details> collapsed block", inject: "<details>\n<summary>More</summary>\n\n" + atkItem + "\n\n</details>"},
		{id: "X06", desc: "shortcut reference image: name and cue only in alt text", inject: "- See ![Removed the SilentDial feature gate] for details. " + atkPR + "\n\n[Removed the SilentDial feature gate]: https://example.invalid/x.png"},
		{id: "X07", desc: "image alt with nested brackets escapes image stripping", inject: "- See ![Removed the SilentDial [x] feature gate](https://example.invalid/x.png) for details. " + atkPR},
		{id: "X08", desc: "PR number only in a link title (tooltip)", inject: "- Removed the SilentDial feature gate. ([details](https://example.invalid/notes \"#140005\"))"},
		{id: "X09", desc: "HTML entity inside the name (renders SilentDial)", inject: "- Removed the Silent&#68;ial feature gate. " + atkPR},
		{id: "X10", desc: "fullwidth name", inject: "- Removed the ＳｉｌｅｎｔＤｉａｌ feature gate. " + atkPR},
		{id: "X11", desc: "NFD: combining acute after the name", inject: "- Removed the SilentDiaĺ feature gate. " + atkPR},
		{id: "X12", desc: "Cyrillic e in the cue word", inject: "- Rеmoved the SilentDial feature gate. " + atkPR},
		{id: "X13", desc: "negated cue (semantics: gate NOT removed)", inject: "- The SilentDial feature gate is not removed in this release and stays. " + atkPR},
		{id: "X14", desc: "PR in range but unrelated (#140003 is an API change)", inject: "- Removed the SilentDial feature gate. ([#140003](https://github.com/kubernetes/kubernetes/pull/140003))"},
		{id: "X15a", desc: "baseline: contradicting second item -> ambiguous", inject: atkItem + "\n" + itemB},
		{id: "X15b", desc: "code span `<!--` ... `-->` hides the contradicting item from the verifier only", inject: atkItem + "\n- Documented the `<!--` marker.\n" + itemB + "\n- Documented the `-->` marker."},
		{id: "X15c", desc: "fenced code holding <!-- hides the contradicting item from the verifier only", inject: atkItem + "\n\n```\n<!--\n```\n\n" + itemB + "\n\n```\n-->\n```"},
		{id: "X15d", desc: "inline unterminated <!-- (literal in CommonMark) truncates the rest; contradicting item after it", inject: atkItem + "\n- The literal text <!-- is not a comment in a paragraph.\n" + itemB},
		{id: "X16", desc: "lone CR splits marker line (renderer: two lines)", inject: "Note\r" + atkItem},
		{id: "X17", desc: "marker after 60000 spaces (indented code, near line bound)", inject: strings.Repeat(" ", 60000) + atkItem},
		{id: "X18", desc: "table row", inject: "| change |\n| --- |\n| " + atkItem + " |"},
		{id: "X19", desc: "blockquote", inject: "> " + atkItem},
		{id: "X20", desc: "raw <div> HTML block (renders as literal text, not a list)", inject: "<div>\n" + atkItem + "\n</div>"},
		{id: "X21", desc: "multi-line processing instruction <? ... ?>", inject: "<?\n" + atkItem + "\n?>"},
		{id: "X22", desc: "multi-line CDATA", inject: "<![CDATA[\n" + atkItem + "\n]]>"},
		{id: "X23", desc: "link reference definition with multi-line title", inject: "[x]: https://example.invalid \"\n" + atkItem + "\n\""},
		{id: "X24", desc: "PR URL embedded in another host's URL", inject: "- Removed the SilentDial feature gate. (https://evil.example/https://github.com/kubernetes/kubernetes/pull/140005)"},
		{id: "X25", desc: "footnote definition carries name+cue", inject: "- Cleanup.[^1] " + atkPR + "\n\n[^1]: Removed the SilentDial feature gate."},
		{id: "X26", desc: "next heading with one leading space does not end the section; item placed in rc section", whole: func(s string) string {
			s = strings.Replace(s, retired, "- Updated docs. "+atkPR, 1)
			s = strings.Replace(s, "# v1.41.0-rc.1", " # v1.41.0-rc.1", 1)
			return s + "\n" + atkItem + "\n"
		}},
		{id: "X27", desc: "fake heading `# v1.42.0` inside section before the contradicting item (section truncated)", inject: atkItem + "\n\n# v1.42.0-fake\n\n" + itemB},
		{id: "X28", desc: "HTML comment opener in inline code `<!--` across fence (fail-open?) baseline with mixed CRLF", whole: func(s string) string {
			s = strings.Replace(s, retired, atkItem, 1)
			return strings.ReplaceAll(s, "\n", "\r\n")
		}},
		{id: "X29", desc: "4-space indented item after a paragraph (lazy continuation, not code)", inject: "Some paragraph.\n    " + atkItem},
		{id: "X30", desc: "HTML block <textarea> hides nothing but raw", inject: "<textarea>\n" + atkItem + "\n</textarea>"},
		{id: "X31", desc: "<noscript>/<template> block", inject: "<template>\n" + atkItem + "\n</template>"},
		{id: "X32", desc: "<!--> empty comment (CommonMark complete) eats until next -->", inject: atkItem + "\n- Empty comment <!--> here.\n" + itemB + "\n- end -->"},
	}
	ids := map[string]bool{}
	for _, a := range attacks {
		ids[a.id] = true
		text := base
		if a.whole != nil {
			text = a.whole(base)
		} else {
			text = strings.Replace(base, retired, a.inject, 1)
		}
		root := fixtureWith(t, []byte(text))
		names := a.names
		if names == nil {
			names = []string{"SilentDial"}
		}
		rep := verifyFixture(t, root, honestBundle(t, root, []Claim{{ID: "c1", Kind: "removed_feature_gate", Names: names}}))
		c := rep.Claims[0]
		switch {
		case mayVerify[a.id] && c.Verdict != VerdictVerified:
			t.Errorf("%s (%s): %s:%s (%s), want verified", a.id, a.desc, c.Verdict, c.Reason, c.Detail)
		case !mayVerify[a.id] && c.Verdict == VerdictVerified:
			t.Errorf("%s (%s): verified", a.id, a.desc)
		}
	}
	for i := 1; i <= 32; i++ {
		id := "X" + strings.TrimPrefix(string(rune('0'+i/10))+string(rune('0'+i%10)), "")
		if !ids[id] && !ids[id+"a"] {
			t.Errorf("attack %s is missing", id)
		}
	}
}

const pr5 = "([#140005](https://github.com/kubernetes/kubernetes/pull/140005))"
const pr6 = "([#140006](https://github.com/kubernetes/kubernetes/pull/140006))"

// yMayVerify are the second-series variants that verify by design: Y00 is
// the plain control; Y12 contradicts the item under "## Known Issues",
// which is outside the subsections read (a documented limit); Y16 and Y19
// keep the cited text visible and correct (an escaped "&lt;!--", a pull
// request link inside emphasis); Y15 has a table in a later sibling
// section, which cannot hide the item before it.
var yMayVerify = map[string]bool{"Y00": true, "Y12": true, "Y15": true, "Y16": true, "Y19": true}

func TestHiddenContentAttacksSecondSeries(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(corpusDir, "controls", "C01-gate-link-squash", "CHANGELOG-1.41.md"))
	if err != nil {
		t.Fatal(err)
	}
	base := string(raw)
	sub := func(inject string) func(string) string {
		return func(s string) string { return strings.Replace(s, retired, inject, 1) }
	}
	cases := []struct {
		id, desc string
		f        func(string) string
	}{
		{"Y00", "control", sub(atkItem)},
		{"Y01", "escaped backtick: grammar sees a code span, CommonMark sees <span title=\"...\"> spanning lines", sub("- See \\`<span title=\"\\`\n  Removed the SilentDial feature gate. " + pr5 + "\n  \"> for details.")},
		{"Y02", "multi-line code span pairs differently: <span title= hidden on line 2", sub("- Note `x\n  y` <span title=\"`z\n  Removed the SilentDial feature gate. " + pr5 + "\n  \"> done.")},
		{"Y03", "name only as a contributor login [@SilentDial](https://github.com/SilentDial)", sub("- Removed stale docs. ([#140005](https://github.com/kubernetes/kubernetes/pull/140005), [@SilentDial](https://github.com/SilentDial)) [SIG Node]")},
		{"Y04", "entity in PR link text [&#35;140005]", sub("- Removed the SilentDial feature gate. ([&#35;140005](https://github.com/kubernetes/kubernetes/pull/140005))")},
		{"Y05a", "baseline: contradicting item with cue", sub(atkItem + "\n- The removal of the SilentDial feature gate was undone. " + pr6)},
		{"Y05b", "entity in the contradicting item's name hides it from the ambiguity check", sub(atkItem + "\n- The removal of the Silent&#68;ial feature gate was undone. " + pr6)},
		{"Y05c", "zero-width char in the contradicting item's name", sub(atkItem + "\n- The removal of the Silent\u200bDial feature gate was undone. " + pr6)},
		{"Y05d", "contradicting item without a cue word", sub(atkItem + "\n- The SilentDial feature gate is back after a regression. " + pr6)},
		{"Y06", "nested item jumps 0->6 after a blank line (CommonMark: indented code in the parent)", sub("- Parent item. " + pr6 + "\n\n      " + atkItem)},
		{"Y07", "nested item jumps 0->6 without blank (CommonMark: lazy paragraph text)", sub("- Parent item. " + pr6 + "\n      " + atkItem)},
		{"Y08", "marker followed by 5 spaces (CommonMark: indented code inside the item)", sub("-     Removed the SilentDial feature gate. " + pr5)},
		{"Y09", "continuation at marker+5 after blank in a nested item", sub("- Parent. " + pr6 + "\n  - Child. " + pr6 + "\n\n       Removed the SilentDial feature gate. " + pr5)},
		{"Y10", "release heading hidden in a comment (content renders under v1.41.1)", func(s string) string {
			s = strings.Replace(s, retired, atkItem, 1)
			return strings.Replace(s, "# v1.41.0\n", "<!--\n# v1.41.0\n-->\n", 1)
		}},
		{"Y11", "<details> opened in 'Changelog since' with no blank before Urgent heading", func(s string) string {
			s = strings.Replace(s, retired, atkItem, 1)
			return strings.Replace(s, "## Changelog since v1.40.0\n\n", "## Changelog since v1.40.0\n\n<details>\n", 1)
		}},
		{"Y12", "contradicting item in a non-citable subsection (## Known Issues)", func(s string) string {
			s = strings.Replace(s, retired, atkItem, 1)
			return strings.Replace(s, "# v1.41.0-rc.1", "## Known Issues\n\n- The removal of the SilentDial feature gate was reverted. "+pr6+"\n\n# v1.41.0-rc.1", 1)
		}},
		{"Y13", "fake '## Changes by Kind' heading twice", func(s string) string {
			s = strings.Replace(s, retired, atkItem, 1)
			return strings.Replace(s, "### Feature", "## Changes by Kind\n\n### Feature", 1)
		}},
		{"Y14", "'##  Changes by Kind' (two spaces) ends the real subsection; item under it uncitable", func(s string) string {
			return strings.Replace(s, retired, "- Updated docs. "+pr6+"\n\n##  Changes by Kind\n\n"+atkItem, 1)
		}},
		{"Y15", "item in Urgent Upgrade Notes h3 whose sibling h3 has a problem", func(s string) string {
			s = strings.Replace(s, retired, "- Updated docs. "+pr6, 1)
			return strings.Replace(s, "### (Read this before you upgrade)\n", "### (Read this before you upgrade)\n\n"+atkItem+"\n\n### Other\n\n| table |\n", 1)
		}},
		{"Y16", "HTML entity &lt;!-- is literal text (no hiding)", sub(atkItem + "\n- Documented &lt;!-- markers. " + pr6)},
		{"Y17", "docs link whose text carries the name and cue", sub("- See [Removed the SilentDial feature gate](https://kubernetes.io/docs/x). " + pr5)},
		{"Y18", "angle autolink to PR", sub("- Removed the SilentDial feature gate. (<https://github.com/kubernetes/kubernetes/pull/140005>)")},
		{"Y19", "PR link inside emphasis *[#140005](...)*", sub("- Removed the SilentDial feature gate. (*[#140005](https://github.com/kubernetes/kubernetes/pull/140005)*)")},
		{"Y20", "backslash-escaped link opener: \\[#140005](...) renders literal text", sub("- Removed the SilentDial feature gate. (\\[#140005](https://github.com/kubernetes/kubernetes/pull/140005))")},
		{"Y21", "link inside code span is literal text", sub("- Removed the SilentDial feature gate. (`[#140005](https://github.com/kubernetes/kubernetes/pull/140005)`)")},
		{"Y22", "nested brackets: [[#140005](...)](https://evil)", sub("- Removed the SilentDial feature gate. ([[#140005](https://github.com/kubernetes/kubernetes/pull/140005)](https://evil.example))")},
		{"Y11b", "<details> plus blank line in 'Changelog since' (outside citable subsections): element stays open in the browser", func(s string) string {
			s = strings.Replace(s, retired, atkItem, 1)
			return strings.Replace(s, "## Changelog since v1.40.0\n\n", "## Changelog since v1.40.0\n\n<details>\n\n", 1)
		}},
		{"Y11c", "<details> in the Urgent notes h3 (that section unparsed); Deprecation h3 later in the file collapsed", func(s string) string {
			s = strings.Replace(s, retired, atkItem, 1)
			return strings.Replace(s, "### (Read this before you upgrade)\n\n", "### (Read this before you upgrade)\n\n<details>\n\n", 1)
		}},
		{"Y24", "marker + 4 spaces (content at 5), blank, 4-space line: document-level indented code", sub("-    Parent item. " + pr6 + "\n\n    Removed the SilentDial feature gate. " + pr5)},
		{"Y25", "level-1 heading inside an item ends the section early, hiding a contradicting item after it", sub(atkItem + "\n  # Notes\n- The removal of the SilentDial feature gate was undone. " + pr6)},
		{"Y23", "hard line break + heading-looking line in continuation", sub("- Removed the SilentDial feature gate. " + pr5 + "\\\n  # not a heading")},
	}
	for _, c := range cases {
		root := fixtureWith(t, []byte(c.f(base)))
		rep := verifyFixture(t, root, honestBundle(t, root, []Claim{{ID: "c1", Kind: "removed_feature_gate", Names: []string{"SilentDial"}}}))
		cl := rep.Claims[0]
		switch {
		case yMayVerify[c.id] && cl.Verdict != VerdictVerified:
			t.Errorf("%s (%s): %s:%s (%s), want verified", c.id, c.desc, cl.Verdict, cl.Reason, cl.Detail)
		case !yMayVerify[c.id] && cl.Verdict == VerdictVerified:
			t.Errorf("%s (%s): verified", c.id, c.desc)
		}
	}
}
