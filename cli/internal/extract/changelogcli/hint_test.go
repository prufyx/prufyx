// SPDX-License-Identifier: AGPL-3.0-only

package changelogcli

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/extract"
	"github.com/prufyx/prufyx/cli/internal/extract/changelogentries"
)

func hintArgs(fx, hintPath string) []string {
	return []string{"propose-rows", "--fixture", fx, "--component", "notes", "--repo", "github.com/example/notes", "--hint-file", hintPath}
}

func writeHint(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "hint.json")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

const goodHint = `{"source":"path","path":"docs/CHANGELOG.md","style":"version-v-prefixed"}` + "\n"

func hintFixture(t *testing.T) string {
	return rowsFixture(t, map[string]string{"docs/CHANGELOG.md": "# v1.0.0\n\n- a\n", "CHANGELOG.md": "# unrelated\n\n- x\n"})
}

func TestProposeWithHintEqualsWithout(t *testing.T) {
	fx := hintFixture(t)
	var plain, hinted, e bytes.Buffer
	if code := run([]string{"propose-rows", "--fixture", fx, "--component", "notes", "--repo", "github.com/example/notes"}, nil, &plain, &e); code != 0 {
		t.Fatalf("%d %s", code, e.String())
	}
	if code := run(hintArgs(fx, writeHint(t, goodHint)), nil, &hinted, &e); code != 0 {
		t.Fatalf("%d %s %s", code, hinted.String(), e.String())
	}
	// Everything but the receipt line is byte-identical; the receipt differs only by its hintDigest field.
	pl, hl := receiptLines(plain.String()), receiptLines(hinted.String())
	if len(pl) != 1 || len(hl) != 1 {
		t.Fatalf("%v %v", pl, hl)
	}
	if strings.Replace(plain.String(), pl[0], "", 1) != strings.Replace(hinted.String(), hl[0], "", 1) {
		t.Fatalf("rows differ:\n%s\n%s", plain.String(), hinted.String())
	}
	sum := sha256.Sum256([]byte(goodHint))
	if hl[0] != pl[0]+" hintDigest="+hex.EncodeToString(sum[:]) {
		t.Fatalf("receipt does not carry the hint digest:\n%s\n%s", pl[0], hl[0])
	}
	r, err := ParseReceipt(hl[0])
	if err != nil || r.HintDigest != hex.EncodeToString(sum[:]) || r.Line() != hl[0] {
		t.Fatalf("%v %+v", err, r)
	}
	if strings.Contains(pl[0], "hintDigest") {
		t.Fatal("an unhinted receipt carries a hint digest")
	}
}

func TestProposeHintRefusals(t *testing.T) {
	fx := hintFixture(t)
	cases := map[string]string{
		"unknown field": `{"source":"path","path":"docs/CHANGELOG.md","style":"version-v-prefixed","x":1}`,
		"traversal":     `{"source":"path","path":"../docs/CHANGELOG.md","style":"version-v-prefixed"}`,
		"unknown style": `{"source":"path","path":"docs/CHANGELOG.md","style":"nonsense"}`,
		"missing file":  `{"source":"path","path":"docs/NOPE.md","style":"version-v-prefixed"}`,
		"oversized":     `{"source":"path","path":"` + strings.Repeat("a", 4096) + `.md","style":"version-v-prefixed"}`,
	}
	for name, body := range cases {
		var o, e bytes.Buffer
		if code := run(hintArgs(fx, writeHint(t, body)), nil, &o, &e); code != 2 || o.Len() != 0 || !strings.Contains(e.String(), "HINT_") {
			t.Fatalf("%s: %d out=%q err=%q", name, code, o.String(), e.String())
		}
	}
	for name, args := range map[string][]string{
		"no such hint file": hintArgs(fx, filepath.Join(t.TempDir(), "absent.json")),
		"directory":         hintArgs(fx, t.TempDir()),
		"empty path":        hintArgs(fx, ""),
		"repeated":          append(hintArgs(fx, writeHint(t, goodHint)), "--hint-file", writeHint(t, goodHint)),
	} {
		var o, e bytes.Buffer
		if code := run(args, nil, &o, &e); code != 2 || o.Len() != 0 {
			t.Fatalf("%s: %d %q", name, code, o.String())
		}
	}
}

func TestProposeMisleadingHintGivesNoRow(t *testing.T) {
	fx := hintFixture(t)
	var o, e bytes.Buffer
	body := `{"source":"path","path":"CHANGELOG.md","style":"version-v-prefixed"}`
	if code := run(hintArgs(fx, writeHint(t, body)), nil, &o, &e); code != 1 || !strings.HasPrefix(o.String(), "NO-ROW ") || len(receiptLines(o.String())) != 0 {
		t.Fatalf("%d out=%q err=%q", code, o.String(), e.String())
	}
}

// A hinted propose receipt is no input of rows-check: a failing row stays FAIL.
func TestHintedReceiptCannotPassAFailingCheck(t *testing.T) {
	fx := hintFixture(t)
	var po, e bytes.Buffer
	if code := run(hintArgs(fx, writeHint(t, goodHint)), nil, &po, &e); code != 0 {
		t.Fatalf("%d %s", code, e.String())
	}
	prop := receiptLines(po.String())[0]
	tbl := []changelogentries.Target{{Component: "notes", Repo: extract.RepoRef{Key: "github.com/example/notes"},
		Form: changelogentries.FormPerVersionFile, Path: "nowhere/v{version}.md"}}
	var co bytes.Buffer
	if code := run([]string{"rows-check", "--fixture", fx}, tbl, &co, &e); code != 1 || !strings.Contains(co.String(), "FAIL notes") {
		t.Fatalf("%d %s", code, co.String())
	}
	cr, err := ParseReceipt(receiptLines(co.String())[0])
	pr, err2 := ParseReceipt(prop)
	if err != nil || err2 != nil || cr.HintDigest != "" || cr.RowDigest == pr.RowDigest {
		t.Fatalf("%v %v %+v %+v", err, err2, cr, pr)
	}
}

func TestUsageNamesHintFile(t *testing.T) {
	if !strings.Contains(usage, "propose-rows (--mirror-state DIR | --fixture DIR) --component NAME --repo github.com/OWNER/NAME [--tags TAG,TAG | --upstream-tags FILE] [--hint-file FILE]") {
		t.Fatal(usage)
	}
}

func TestReceiptHintDigestNegative(t *testing.T) {
	d := strings.Repeat("ab", 32)
	base := "receipt/v1 step=propose component=notes rowDigest=" + d + " tagsDigest=" + d + " mirrorDigest=" + d + " codeDigest=sha256:" + d
	if _, err := ParseReceipt(base + " hintDigest=" + d); err != nil {
		t.Fatal(err)
	}
	for name, l := range map[string]string{
		"short digest":    base + " hintDigest=abc",
		"wrong key":       base + " hint=" + d,
		"two extras":      base + " hintDigest=" + d + " hintDigest=" + d,
		"on a check line": strings.Replace(base, "step=propose", "step=check", 1) + " hintDigest=" + d,
		"empty":           base + " hintDigest=",
		"trailing space":  base + " hintDigest=" + d + " ",
	} {
		if _, err := ParseReceipt(l); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
}

// The output of an unhinted propose-rows is the output of the build before
// --hint-file existed, byte for byte (golden captured from that build; the code
// digest is the digest of the changed source and is normalised).
const goldenUnhinted = `{
  "row": {
    "component": "notes",
    "repo": "github.com/example/notes",
    "form": "changelog-per-version-file",
    "path": "docs/releases/v{version}.md"
  },
  "located": 1,
  "tags": 1,
  "versionsLocated": 1,
  "versions": 1,
  "hits": [
    {
      "tag": "v1.0.0",
      "located": true
    }
  ]
}
receipt/v1 step=propose component=notes rowDigest=0f53cbb32ee9bdca53384d43b08d0d8c6f8ddd6a6792febe1f3974058931c57c tagsDigest=746c276701b23f42fca5ec4f3282fdad103a84f590af8a39c4928ab78a6941e4 mirrorDigest=none codeDigest=<code>
`

func TestUnhintedOutputIsGolden(t *testing.T) {
	fx := rowsFixture(t, map[string]string{"docs/releases/v1.0.0.md": "## Changes\n\n- fix a\n"})
	got := regexp.MustCompile(`codeDigest=sha256:[0-9a-f]{64}`).ReplaceAllString(proposeOut(t, fx), "codeDigest=<code>")
	if got != goldenUnhinted {
		t.Fatalf("unhinted output changed:\n%s", got)
	}
}
