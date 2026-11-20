// SPDX-License-Identifier: AGPL-3.0-only

package changelogcli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/extract"
	"github.com/prufyx/prufyx/cli/internal/extract/changelogentries"
)

const upRepo = "github.com/example/notes"

func upFile(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "up.tsv")
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func floorTable(floor string) []changelogentries.Target {
	return []changelogentries.Target{{Component: "notes", Repo: extract.RepoRef{Key: upRepo},
		Form: changelogentries.FormPerVersionFile, Path: "docs/v{version}.md", Floor: floor}}
}

// Golden: a row without a floor prints the receipt it always printed.
func TestRowsCheckAbsentFloorReceiptUnchanged(t *testing.T) {
	fx := rowsFixture(t, map[string]string{"docs/v1.0.0.md": "## Changes\n\n- a\n"})
	var out, errb bytes.Buffer
	code := run([]string{"rows-check", "--fixture", fx}, floorTable(""), &out, &errb)
	want := "PASS notes form=changelog-per-version-file tags=1 located=1 withheld=0 notFinal=0 newest=1/1 minLocatedNewest=8\n" +
		"rows=1 failed=0 minLocatedNewest=rows tagsDigest=746c276701b23f42fca5ec4f3282fdad103a84f590af8a39c4928ab78a6941e4 mirrorDigest=none\n" +
		"receipt/v1 step=check component=notes rowDigest=e0861bdeaa3b0c492047fc31e426ff0178f3b7cbfc6517faaa3a5ad4f89398f1 tagsDigest=746c276701b23f42fca5ec4f3282fdad103a84f590af8a39c4928ab78a6941e4 mirrorDigest=none codeDigest=sha256:\n"
	// The code digest moves with every extractor change; the rest is pinned.
	trim := func(s string) string {
		if i := strings.Index(s, "codeDigest=sha256:"); i >= 0 {
			return s[:i+len("codeDigest=sha256:")] + "\n"
		}
		return s
	}
	if code != 0 || trim(out.String()) != want {
		t.Fatalf("%d\n%s", code, out.String())
	}
	// An upstream list given for a row without a floor changes nothing.
	up := upFile(t, upRepo+"\t"+strings.Repeat("a", 40)+"\tv1.0.0\n")
	out.Reset()
	code = run([]string{"rows-check", "--fixture", fx, "--upstream-tags", up}, floorTable(""), &out, &errb)
	if code != 0 || trim(out.String()) != want {
		t.Fatalf("%d\n%s", code, out.String())
	}
}

func TestRowsCheckFloorRowFailsClosed(t *testing.T) {
	fx := rowsFixture(t, map[string]string{"docs/v1.0.0.md": "## Changes\n\n- a\n"})
	// Without an upstream list a floor row fails; it is never read as newest 5.
	var out, errb bytes.Buffer
	code := run([]string{"rows-check", "--fixture", fx}, floorTable("0.5"), &out, &errb)
	if code != 1 || !strings.HasPrefix(out.String(), "FAIL notes") || !strings.Contains(out.String(), "upstream") || !strings.Contains(out.String(), "floor=0.5") {
		t.Fatalf("%d\n%s", code, out.String())
	}
	// With a list the cap is the measured constant; the floor 0.5 is not a
	// line of the one-tag list, so the row fails on that, closed.
	up := upFile(t, upRepo+"\t"+strings.Repeat("a", 40)+"\tv1.0.0\n")
	out.Reset()
	code = run([]string{"rows-check", "--fixture", fx, "--upstream-tags", up}, floorTable("0.5"), &out, &errb)
	if code != 1 || !strings.Contains(out.String(), "not a release line") {
		t.Fatalf("%d\n%s", code, out.String())
	}
}

func TestUpstreamTagsFlagRefusals(t *testing.T) {
	fx := rowsFixture(t, map[string]string{"docs/v1.0.0.md": "## Changes\n\n- a\n"})
	cases := map[string][]string{
		"missing file":      {"rows-check", "--fixture", fx, "--upstream-tags", filepath.Join(t.TempDir(), "none")},
		"unparsable file":   {"rows-check", "--fixture", fx, "--upstream-tags", upFile(t, "garbage\n")},
		"given twice":       {"rows-check", "--fixture", fx, "--upstream-tags", "a", "--upstream-tags", "b"},
		"propose with tags": {"propose-rows", "--fixture", fx, "--component", "notes", "--repo", upRepo, "--tags", "v1.0.0", "--upstream-tags", upFile(t, upRepo+"\t"+strings.Repeat("a", 40)+"\tv1.0.0\n")},
		"propose bad list":  {"propose-rows", "--fixture", fx, "--component", "notes", "--repo", upRepo, "--upstream-tags", upFile(t, "x\n")},
	}
	for name, args := range cases {
		var o, e bytes.Buffer
		if code := run(args, floorTable(""), &o, &e); code != 2 || o.Len() != 0 {
			t.Errorf("%s: %d %s", name, code, o.String())
		}
	}
}

func TestProposeRowsWithoutUpstreamPrintsNoFloor(t *testing.T) {
	fx := rowsFixture(t, map[string]string{"docs/releases/v1.0.0.md": "## Changes\n\n- a\n"})
	var o, e bytes.Buffer
	code := run([]string{"propose-rows", "--fixture", fx, "--component", "notes", "--repo", upRepo}, floorTable(""), &o, &e)
	if code != 0 || strings.Contains(o.String(), "floor") || strings.Contains(o.String(), "windowTagsDigest") {
		t.Fatalf("%d %s %s", code, o.String(), e.String())
	}
}
