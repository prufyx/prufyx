// SPDX-License-Identifier: AGPL-3.0-only

package htmltable

import "testing"

func TestScriptWithNonASCIIDoesNotShiftSkip(t *testing.T) {
	// U+0130 and U+212A change byte length under Unicode lowercasing.
	page := "<script>var a='İİK';</SCRIPT><table><tr><td>1.30</td></tr></table>" +
		"<style>/* İK */</Style><table><tr><td>1.31</td></tr></table>"
	ts, err := Parse([]byte(page))
	if err != nil {
		t.Fatal(err)
	}
	if len(ts) != 2 || ts[0].Rows[0][0].Text != "1.30" || ts[1].Rows[0][0].Text != "1.31" {
		t.Fatalf("tables %+v", ts)
	}
	if _, err := Parse([]byte("<script>İ no end")); err == nil {
		t.Fatal("unterminated script accepted")
	}
}

func TestPartlyItalicCellIsItalic(t *testing.T) {
	ts, err := Parse([]byte("<table><tr><td><i>2026-11</i>-11</td><td><i>2026-11-11</i></td><td>2026-11-11</td></tr></table>"))
	if err != nil {
		t.Fatal(err)
	}
	c := ts[0].Rows[0]
	if !c[0].Italic || !c[1].Italic || c[2].Italic {
		t.Fatalf("italic flags %v %v %v", c[0].Italic, c[1].Italic, c[2].Italic)
	}
}
