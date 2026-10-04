// SPDX-License-Identifier: AGPL-3.0-only

package consensus

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Attacks found in an independent review, kept as regression tests. Each
// replaces one visible removal item of the C01 control with a variant that
// a reader of the rendered page would not see, or would not read as a
// cited removal, and must not verify.

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

func TestReviewAttacksDoNotVerify(t *testing.T) {
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
