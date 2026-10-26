// SPDX-License-Identifier: AGPL-3.0-only

package coveragereport

import "testing"

func TestSpliceBlock(t *testing.T) {
	t.Parallel()
	const b, e = READMEBegin, READMEEnd
	doc := "# Title\n\n" + b + "\nold\nlines\n" + e + "\n\nTail.\n"
	got, err := SpliceBlock([]byte(doc), b, e, "new\n")
	if err != nil {
		t.Fatal(err)
	}
	if want := "# Title\n\n" + b + "\nnew\n" + e + "\n\nTail.\n"; string(got) != want {
		t.Fatalf("got %q want %q", got, want)
	}
	// The same block is a fixed point; an empty block is allowed; the end
	// marker may be the last line without a newline.
	again, err := SpliceBlock(got, b, e, "new\n")
	if err != nil || string(again) != string(got) {
		t.Fatalf("not a fixed point: %v", err)
	}
	if out, err := SpliceBlock([]byte(b+"\nx\n"+e), b, e, ""); err != nil || string(out) != b+"\n"+e {
		t.Fatalf("%q %v", out, err)
	}
	refused := map[string]string{
		"begin twice":     b + "\n" + b + "\n" + e + "\n",
		"end twice":       b + "\n" + e + "\n" + e + "\n",
		"begin missing":   "x\n" + e + "\n",
		"end missing":     b + "\nx\n",
		"end before":      e + "\nx\n" + b + "\n",
		"inline begin":    "text " + b + "\n" + e + "\n",
		"begin suffixed":  b + " \n" + e + "\n",
		"end suffixed":    b + "\n" + e + " \n",
		"crlf":            b + "\r\n" + e + "\n",
		"begin at eof":    e + "\n" + b,
		"marker in prose": "see " + e + " here\n" + b + "\n" + e + "\n",
	}
	for name, d := range refused {
		if _, err := SpliceBlock([]byte(d), b, e, "new\n"); err == nil {
			t.Errorf("%s: spliced", name)
		}
	}
	if _, err := SpliceBlock([]byte(doc), b, e, "no newline"); err == nil {
		t.Error("a block without a final newline was accepted")
	}
	if _, err := SpliceBlock([]byte(doc), b, e, "x "+e+"\n"); err == nil {
		t.Error("a block holding a marker was accepted")
	}
}

func TestReadmePct(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		a, b int
		want string
	}{{34, 390, "8.7%"}, {40, 390, "10.2%"}, {316, 390, "81%"}, {0, 0, "0%"}, {1, 3, "33.3%"}, {2, 2, "100%"}} {
		if got := readmePct(c.a, c.b); got != c.want {
			t.Errorf("%d/%d: %s want %s", c.a, c.b, got, c.want)
		}
	}
}
