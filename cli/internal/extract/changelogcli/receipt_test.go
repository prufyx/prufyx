// SPDX-License-Identifier: AGPL-3.0-only

package changelogcli

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
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
	got := Receipt{Step: "check", Component: "notes", RowDigest: d, TagsDigest: d, MirrorDigest: "none", CodeDigest: "sha256:" + d}.Line()
	want := "receipt/v1 step=check component=notes rowDigest=" + d + " tagsDigest=" + d + " mirrorDigest=none codeDigest=sha256:" + d
	if got != want {
		t.Fatalf("got  %s\nwant %s", got, want)
	}
	r, err := ParseReceipt(want)
	if err != nil || r.Line() != want {
		t.Fatalf("%v %+v", err, r)
	}
	// A full 64-hex mirror digest is accepted.
	if _, err := ParseReceipt(strings.Replace(want, "mirrorDigest=none", "mirrorDigest="+d, 1)); err != nil {
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
	if !strings.Contains(checkOut(t, fx), " mirrorDigest=none targets=embedded\n") {
		t.Fatal("summary line omits mirrorDigest=none")
	}
}

func TestParseReceiptRejects(t *testing.T) {
	d := strings.Repeat("a", 64)
	ok := "receipt/v1 step=check component=notes rowDigest=" + d + " tagsDigest=" + d + " mirrorDigest=none codeDigest=sha256:" + d
	if _, err := ParseReceipt(ok); err != nil {
		t.Fatal(err)
	}
	swap := "receipt/v1 step=check component=notes tagsDigest=" + d + " rowDigest=" + d + " mirrorDigest=none codeDigest=sha256:" + d
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
		"upper code":     strings.Replace(ok, "codeDigest=sha256:"+d, "codeDigest=sha256:"+strings.ToUpper(d), 1),
		"bad mirror":     strings.Replace(ok, "mirrorDigest=none", "mirrorDigest=zz", 1),
		"bare code":      strings.Replace(ok, "codeDigest=sha256:", "codeDigest=", 1),
		"text":           ok + " " + secretText,
		"repeated field": ok + " codeDigest=sha256:" + d,
		"repeated mid":   strings.Replace(ok, " tagsDigest="+d, " rowDigest="+d+" tagsDigest="+d, 1),
		"mirror 15 hex":  strings.Replace(ok, "mirrorDigest=none", "mirrorDigest="+strings.Repeat("a", 15), 1),
		"mirror 16 hex":  strings.Replace(ok, "mirrorDigest=none", "mirrorDigest="+strings.Repeat("a", 16), 1),
		"mirror 65 hex":  strings.Replace(ok, "mirrorDigest=none", "mirrorDigest="+strings.Repeat("a", 65), 1),
		"upper row":      strings.Replace(ok, "rowDigest="+d, "rowDigest="+strings.ToUpper(d), 1),
		"trailing nl":    ok + "\n",
	} {
		if _, err := ParseReceipt(l); err == nil {
			t.Errorf("%s accepted: %q", name, l)
		}
	}
}

func TestReceiptStrictRefusals(t *testing.T) {
	d := strings.Repeat("a", 64)
	mk := func(tags, mirror string) string {
		return "receipt/v1 step=check component=notes rowDigest=" + d + " tagsDigest=" + tags + " mirrorDigest=" + mirror + " codeDigest=sha256:" + d
	}
	cases := []struct {
		name          string
		line          string
		fixture, want bool
	}{
		{"production full", mk(d, d), false, true},
		{"fixture none", mk(d, "none"), true, true},
		{"production none", mk(d, "none"), false, false},
		{"unreadable production", mk("unreadable", d), false, false},
		{"unreadable fixture", mk("unreadable", "none"), true, false},
	}
	for _, c := range cases {
		_, err := ParseReceiptStrict(c.line, c.fixture)
		if (err == nil) != c.want {
			t.Errorf("%s: err=%v want ok=%v", c.name, err, c.want)
		}
	}
	// Admissible on a hand-built receipt with a short mirror digest.
	if err := (Receipt{TagsDigest: d, MirrorDigest: strings.Repeat("a", 16)}).Admissible(false); err == nil {
		t.Error("short mirror digest admitted")
	}
	if err := (Receipt{TagsDigest: d, MirrorDigest: strings.Repeat("a", 16)}).Admissible(true); err == nil {
		t.Error("short mirror digest admitted in fixture run")
	}
}

func TestUnreadableTagsExitNonZeroNoReceipt(t *testing.T) {
	fx := rowsFixture(t, map[string]string{"docs/releases/v1.0.0.md": "## Changes\n\n- a\n"})
	tbl := []changelogentries.Target{{Component: "gone", Repo: extract.RepoRef{Key: "github.com/example/gone"},
		Form: changelogentries.FormPerVersionFile, Path: "docs/releases/v{version}.md"}}
	var o, e bytes.Buffer
	code := run([]string{"rows-check", "--fixture", fx}, tbl, &o, &e)
	if code != 2 || len(receiptLines(o.String())) != 0 || strings.Contains(o.String(), "unreadable") {
		t.Fatalf("code %d out %q err %q", code, o.String(), e.String())
	}
	o.Reset()
	if code := run([]string{"propose-rows", "--fixture", fx, "--component", "gone", "--repo", "github.com/example/gone"}, nil, &o, &e); code != 2 || len(receiptLines(o.String())) != 0 {
		t.Fatalf("propose: %d %q", code, o.String())
	}
}

func TestRepoTagsDigestUnreadableIsError(t *testing.T) {
	fx := rowsFixture(t, nil)
	src, _ := openSource("", fx)
	if d, err := repoTagsDigest(src, extract.RepoRef{Key: "github.com/example/gone"}); err == nil || d != "" {
		t.Fatalf("%q %v", d, err)
	}
}

func TestTagsDigestBindsCommit(t *testing.T) {
	digest := func(commit string) string {
		fx := rowsFixture(t, nil)
		tags := filepath.Join(fx, "github.com", "example", "notes", "tags.json")
		if err := os.WriteFile(tags, []byte(`{"v1.0.0":"`+commit+`"}`), 0o644); err != nil {
			t.Fatal(err)
		}
		src, err := openSource("", fx)
		if err != nil {
			t.Fatal(err)
		}
		d, err := repoTagsDigest(src, extract.RepoRef{Key: "github.com/example/notes"})
		if err != nil {
			t.Fatal(err)
		}
		return d
	}
	a, b := digest(strings.Repeat("a", 40)), digest(strings.Repeat("b", 40))
	if a == b || a != digest(strings.Repeat("a", 40)) {
		t.Fatalf("retag not bound or not deterministic: %s %s", a, b)
	}
}

func TestMirrorDigestFull(t *testing.T) {
	dir := t.TempDir()
	raw := []byte(`{"schema":"x"}`)
	if err := os.WriteFile(filepath.Join(dir, "mirror-index.json"), raw, 0o644); err != nil {
		t.Fatal(err)
	}
	// A stub source whose reader digest is the short prefix.
	sum := sha256.Sum256(raw)
	full := hex.EncodeToString(sum[:])
	if got, err := fullFromShort(dir, full[:16]); err != nil || got != full || len(got) != 64 {
		t.Fatalf("%q %v", got, err)
	}
	if _, err := fullFromShort(dir, strings.Repeat("0", 16)); err == nil {
		t.Fatal("mismatching short digest accepted")
	}
	if _, err := fullFromShort(t.TempDir(), full[:16]); err == nil {
		t.Fatal("missing index accepted")
	}
}

func TestReceiptNoTextForFileAndPerLineForms(t *testing.T) {
	file := "## 1.0.0\n\n- " + secretText + "\n\n## Unreleased\n"
	fx := rowsFixture(t, map[string]string{"CHANGELOG.md": file})
	var o, e bytes.Buffer
	if code := run([]string{"propose-rows", "--fixture", fx, "--component", "notes", "--repo", "github.com/example/notes"}, nil, &o, &e); code != 0 {
		t.Fatalf("propose file: %d %s %s", code, o.String(), e.String())
	}
	check := func(out string) {
		if strings.Contains(out, secretText) {
			t.Fatalf("text in output:\n%s", out)
		}
		for _, l := range receiptLines(out) {
			if _, err := ParseReceipt(l); err != nil {
				t.Fatal(err)
			}
		}
	}
	check(o.String())
	for name, tbl := range map[string][]changelogentries.Target{
		"file": {{Component: "notes", Repo: extract.RepoRef{Key: "github.com/example/notes"}, Form: changelogentries.FormFile, Path: "CHANGELOG.md",
			HeadingPattern: `^(?P<version>[0-9]+\.[0-9]+\.[0-9]+)$`, BoundaryPatterns: []string{`^Unreleased$`}}},
		"per-line": {{Component: "notes", Repo: extract.RepoRef{Key: "github.com/example/notes"}, Form: changelogentries.FormPerLineFile, Path: "CHANGELOG/CHANGELOG-{line}.md",
			HeadingPattern: `^(?P<version>[0-9]+\.[0-9]+\.[0-9]+)$`, BoundaryPatterns: []string{`^Unreleased$`}}},
	} {
		o.Reset()
		run([]string{"rows-check", "--fixture", fx}, tbl, &o, &e)
		if len(receiptLines(o.String())) != 1 {
			t.Fatalf("%s: %s", name, o.String())
		}
		check(o.String())
	}
}
