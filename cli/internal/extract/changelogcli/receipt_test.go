// SPDX-License-Identifier: AGPL-3.0-only

package changelogcli

import (
	"bytes"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/extract"
	"github.com/prufyx/prufyx/cli/internal/extract/changelogentries"
)

const secretText = "ZEBRA-QUOKKA-CHANGELOG-SENTENCE"

func receiptLines(out string) []string {
	var r []string
	for _, l := range strings.Split(out, "\n") {
		if strings.HasPrefix(l, ReceiptTag+" ") {
			r = append(r, l)
		}
	}
	return r
}

func proposeOut(t *testing.T, fx string) string {
	t.Helper()
	var o, e bytes.Buffer
	code := run([]string{"propose-rows", "--fixture", fx, "--component", "notes", "--repo", "github.com/example/notes"}, nil, &o, &e)
	if code != 0 {
		t.Fatalf("%d %s %s", code, o.String(), e.String())
	}
	return o.String()
}

func checkOut(t *testing.T, fx string) string {
	t.Helper()
	tbl := []changelogentries.Target{{Component: "notes", Repo: extract.RepoRef{Key: "github.com/example/notes"},
		Form: changelogentries.FormPerVersionFile, Path: "docs/releases/v{version}.md"}}
	var o, e bytes.Buffer
	if code := run([]string{"rows-check", "--fixture", fx}, tbl, &o, &e); code != 0 {
		t.Fatalf("%d %s %s", code, o.String(), e.String())
	}
	return o.String()
}

func TestReceiptHasNoChangelogText(t *testing.T) {
	fx := rowsFixture(t, map[string]string{"docs/releases/v1.0.0.md": "## Changes\n\n- " + secretText + "\n"})
	for name, out := range map[string]string{"propose": proposeOut(t, fx), "check": checkOut(t, fx)} {
		if strings.Contains(out, secretText) {
			t.Fatalf("%s output carries changelog text:\n%s", name, out)
		}
		ls := receiptLines(out)
		if len(ls) != 1 {
			t.Fatalf("%s: want one receipt line, got %v", name, ls)
		}
		if _, err := ParseReceipt(ls[0]); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
	}
}

func TestReceiptGoldenFormat(t *testing.T) {
	d := strings.Repeat("ab", 32)
	got := Receipt{Step: "check", Component: "notes", RowDigest: d, TagsDigest: d, MirrorDigest: "none", CodeDigest: d}.Line()
	want := "receipt/v1 step=check component=notes rowDigest=" + d + " tagsDigest=" + d + " mirrorDigest=none codeDigest=" + d
	if got != want {
		t.Fatalf("got  %s\nwant %s", got, want)
	}
	r, err := ParseReceipt(want)
	if err != nil || r.Line() != want {
		t.Fatalf("%v %+v", err, r)
	}
	// A mirror index digest (16 hex) is accepted.
	if _, err := ParseReceipt(strings.Replace(want, "mirrorDigest=none", "mirrorDigest=0123456789abcdef", 1)); err != nil {
		t.Fatal(err)
	}
}

func TestReceiptDeterministicAndMatchesAcrossSteps(t *testing.T) {
	fx := rowsFixture(t, map[string]string{"docs/releases/v1.0.0.md": "## Changes\n\n- a\n"})
	a, b := receiptLines(proposeOut(t, fx)), receiptLines(proposeOut(t, fx))
	if len(a) != 1 || len(b) != 1 || a[0] != b[0] {
		t.Fatalf("not deterministic: %v %v", a, b)
	}
	c := receiptLines(checkOut(t, fx))
	pr, _ := ParseReceipt(a[0])
	cr, _ := ParseReceipt(c[0])
	pr.Step, cr.Step = "", ""
	if pr != cr {
		t.Fatalf("propose and check receipts differ:\n%+v\n%+v", pr, cr)
	}
	if pr.MirrorDigest != "none" {
		t.Fatalf("fixture mirrorDigest = %q, want none", pr.MirrorDigest)
	}
}

func TestReceiptMissingMirrorIsExplicitNone(t *testing.T) {
	fx := rowsFixture(t, map[string]string{"docs/releases/v1.0.0.md": "## Changes\n\n- a\n"})
	for _, out := range []string{proposeOut(t, fx), checkOut(t, fx)} {
		if !strings.Contains(receiptLines(out)[0], " mirrorDigest=none ") {
			t.Fatalf("no explicit none:\n%s", out)
		}
	}
	if !strings.Contains(checkOut(t, fx), " mirrorDigest=none\n") {
		t.Fatal("summary line omits mirrorDigest=none")
	}
}

func TestParseReceiptRejects(t *testing.T) {
	d := strings.Repeat("a", 64)
	ok := "receipt/v1 step=check component=notes rowDigest=" + d + " tagsDigest=" + d + " mirrorDigest=none codeDigest=" + d
	if _, err := ParseReceipt(ok); err != nil {
		t.Fatal(err)
	}
	swap := "receipt/v1 step=check component=notes tagsDigest=" + d + " rowDigest=" + d + " mirrorDigest=none codeDigest=" + d
	for name, l := range map[string]string{
		"empty":          "",
		"order":          swap,
		"no mirror":      strings.Replace(ok, " mirrorDigest=none", "", 1),
		"empty mirror":   strings.Replace(ok, "mirrorDigest=none", "mirrorDigest=", 1),
		"extra field":    ok + " note=x",
		"extra space":    strings.Replace(ok, " tagsDigest", "  tagsDigest", 1),
		"trailing space": ok + " ",
		"bad version":    strings.Replace(ok, "receipt/v1", "receipt/v2", 1),
		"bad step":       strings.Replace(ok, "step=check", "step=other", 1),
		"bad component":  strings.Replace(ok, "component=notes", "component=No_Tes", 1),
		"short row":      strings.Replace(ok, "rowDigest="+d, "rowDigest=abc", 1),
		"upper code":     strings.Replace(ok, "codeDigest="+d, "codeDigest="+strings.ToUpper(d), 1),
		"bad mirror":     strings.Replace(ok, "mirrorDigest=none", "mirrorDigest=zz", 1),
		"text":           ok + " " + secretText,
	} {
		if _, err := ParseReceipt(l); err == nil {
			t.Errorf("%s accepted: %q", name, l)
		}
	}
}
