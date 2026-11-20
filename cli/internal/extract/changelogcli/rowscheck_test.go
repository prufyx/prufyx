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

func rowsFixture(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	base := filepath.Join(root, "github.com", "example", "notes")
	c := strings.Repeat("a", 40)
	if err := os.MkdirAll(filepath.Join(base, "commits", c), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(base, "tags.json"), []byte(`{"v1.0.0":"`+c+`"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	for p, v := range files {
		full := filepath.Join(base, "commits", c, filepath.FromSlash(p))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(v), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func TestRowsCheckExitCodes(t *testing.T) {
	row := func(path string) []changelogentries.Target {
		return []changelogentries.Target{{
			Component: "notes", Repo: extract.RepoRef{Key: "github.com/example/notes"},
			Form: changelogentries.FormPerVersionFile, Path: path,
		}}
	}
	fx := rowsFixture(t, map[string]string{"docs/v1.0.0.md": "## Changes\n\n- fix a\n"})
	cases := []struct {
		name string
		tbl  []changelogentries.Target
		args []string
		code int
		want string
	}{
		{"pass", row("docs/v{version}.md"), []string{"rows-check", "--fixture", fx}, 0, "PASS notes form=changelog-per-version-file tags=1 located=1"},
		{"pass one component", row("docs/v{version}.md"), []string{"rows-check", "--fixture", fx, "--component", "notes"}, 0, "failed=0"},
		{"path never resolves", row("nowhere/v{version}.md"), []string{"rows-check", "--fixture", fx}, 1, "FAIL notes"},
		{"unknown component", row("docs/v{version}.md"), []string{"rows-check", "--fixture", fx, "--component", "x"}, 2, ""},
		{"no source", row("docs/v{version}.md"), []string{"rows-check"}, 2, ""},
		{"both sources", row("docs/v{version}.md"), []string{"rows-check", "--fixture", fx, "--mirror-state", fx}, 2, ""},
		{"extra arg", row("docs/v{version}.md"), []string{"rows-check", "--fixture", fx, "x"}, 2, ""},
		{"unknown flag", row("docs/v{version}.md"), []string{"rows-check", "--fixture", fx, "--tag", "v1.0.0"}, 2, ""},
		{"repeated flag", row("docs/v{version}.md"), []string{"rows-check", "--fixture", fx, "--fixture", fx}, 2, ""},
		{"empty table", nil, []string{"rows-check", "--fixture", fx}, 2, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var out, errb bytes.Buffer
			code := run(c.args, c.tbl, &out, &errb)
			if code != c.code || !strings.Contains(out.String(), c.want) {
				t.Fatalf("code %d (want %d)\nout: %s\nerr: %s", code, c.code, out.String(), errb.String())
			}
			if code == 2 && out.Len() != 0 {
				t.Fatalf("stdout on refusal: %s", out.String())
			}
		})
	}
}

func TestProposeRowsCLI(t *testing.T) {
	fx := rowsFixture(t, map[string]string{"docs/releases/v1.0.0.md": "## Changes\n\n- fix a\n"})
	a := func(extra ...string) []string {
		return append([]string{"propose-rows", "--fixture", fx, "--component", "notes", "--repo", "github.com/example/notes"}, extra...)
	}
	var out, errb bytes.Buffer
	if code := run(a(), nil, &out, &errb); code != 0 || !strings.Contains(out.String(), `"path": "docs/releases/v{version}.md"`) {
		t.Fatalf("%d %s %s", code, out.String(), errb.String())
	}
	out.Reset()
	toml := rowsFixture(t, map[string]string{"releases/v1.0.0.toml": "- a\n- b\n"})
	if code := run([]string{"propose-rows", "--fixture", toml, "--component", "notes", "--repo", "github.com/example/notes"}, nil, &out, &errb); code != 1 || !strings.Contains(out.String(), "NO-ROW NON_MARKDOWN_SOURCE") {
		t.Fatalf("%d %s", code, out.String())
	}
	for name, args := range map[string][]string{
		"no component": {"propose-rows", "--fixture", fx, "--repo", "github.com/example/notes"},
		"no source":    {"propose-rows", "--component", "notes", "--repo", "github.com/example/notes"},
		"bad tag":      a("--tags", "v9.9.9"),
		"repeated":     a("--repo", "github.com/example/notes"),
		"extra":        a("x"),
	} {
		var o, e bytes.Buffer
		if code := run(args, nil, &o, &e); code != 2 || o.Len() != 0 {
			t.Fatalf("%s: %d %s", name, code, o.String())
		}
	}
}

func TestUsageExitLine(t *testing.T) {
	if strings.Contains(usage, "1 a row FAIL or NO-ROW, 1 a row FAIL") || !strings.Contains(usage, "1 a row FAIL or NO-ROW, 2 input rejected") || !strings.Contains(usage, "--min-located-newest N") {
		t.Fatal(usage)
	}
}

func TestRowsCheckReceiptBindsTagSetAndMin(t *testing.T) {
	tbl := []changelogentries.Target{{Component: "notes", Repo: extract.RepoRef{Key: "github.com/example/notes"},
		Form: changelogentries.FormPerVersionFile, Path: "docs/v{version}.md"}}
	line := func(fx string, extra ...string) (int, string) {
		var out, errb bytes.Buffer
		code := run(append([]string{"rows-check", "--fixture", fx}, extra...), tbl, &out, &errb)
		return code, out.String()
	}
	one := rowsFixture(t, map[string]string{"docs/v1.0.0.md": "## Changes\n\n- a\n"})
	c1, o1 := line(one)
	if c1 != 0 || !strings.Contains(o1, "tagsDigest=") || !strings.Contains(o1, "minLocatedNewest=8") {
		t.Fatalf("%d %s", c1, o1)
	}
	// Same table, a second tag: the digest differs.
	two := rowsFixture(t, map[string]string{"docs/v1.0.0.md": "## Changes\n\n- a\n"})
	c := strings.Repeat("a", 40)
	os.WriteFile(filepath.Join(two, "github.com", "example", "notes", "tags.json"), []byte(`{"v1.0.0":"`+c+`","v1.0.1":"`+c+`"}`), 0o644)
	_, o2 := line(two, "--min-located-newest", "1")
	d := func(o string) string { return o[strings.Index(o, "tagsDigest="):] }
	if d(o1) == d(o2) {
		t.Fatalf("digest equal:\n%s%s", o1, o2)
	}
	// Two tags, one located: default bar fails.
	if code, _ := line(two); code != 1 {
		t.Fatalf("partial passed: %d", code)
	}
	for _, bad := range []string{"0", "x", "-1"} {
		if code, _ := line(one, "--min-located-newest", bad); code != 2 {
			t.Fatalf("%q: %d", bad, code)
		}
	}
}

func TestRowsCheckReceiptPrintsEachRowBar(t *testing.T) {
	mk := func(min int) []changelogentries.Target {
		return []changelogentries.Target{{
			Component: "notes", Repo: extract.RepoRef{Key: "github.com/example/notes"},
			Form: changelogentries.FormPerVersionFile, Path: "docs/v{version}.md", MinLocatedNewest: min,
		}, {
			Component: "other", Repo: extract.RepoRef{Key: "github.com/example/other"},
			Form: changelogentries.FormPostTag,
		}}
	}
	fx := rowsFixture(t, map[string]string{"docs/v1.0.0.md": "## Changes\n\n- a\n"})
	// the skipped row still gets a receipt line, which binds its tag list
	other := filepath.Join(fx, "github.com", "example", "other")
	if err := os.MkdirAll(other, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(other, "tags.json"), []byte(`{}`), 0o644); err != nil {
		t.Fatal(err)
	}
	run1 := func(tbl []changelogentries.Target, extra ...string) (int, string) {
		var out, errb bytes.Buffer
		code := run(append([]string{"rows-check", "--fixture", fx}, extra...), tbl, &out, &errb)
		return code, out.String()
	}
	code, o := run1(mk(7))
	if code != 0 || !strings.Contains(o, "PASS notes form=changelog-per-version-file tags=1 located=1 withheld=0 notFinal=0 newest=1/1 minLocatedNewest=7\n") ||
		!strings.Contains(o, "minLocatedNewest=rows ") {
		t.Fatalf("%d %s", code, o)
	}
	// the default is printed as 8, and a row that is not read prints no bar
	_, o = run1(mk(0))
	if !strings.Contains(o, "newest=1/1 minLocatedNewest=8\n") || strings.Contains(o, "SKIP other form=post-tag tags=0 located=0 withheld=0 notFinal=0 newest=0/0 minLocatedNewest") {
		t.Fatalf("%s", o)
	}
	// an explicit override is printed on the row and in the summary
	_, o = run1(mk(7), "--min-located-newest", "1")
	if !strings.Contains(o, "newest=1/1 minLocatedNewest=1\n") || !strings.Contains(o, "minLocatedNewest=1 tagsDigest=") {
		t.Fatalf("%s", o)
	}
}

func TestRowsCheckPassNamesUnlocatedVersions(t *testing.T) {
	files := map[string]string{}
	tags := map[string]string{}
	c := strings.Repeat("a", 40)
	for i := 0; i < 8; i++ {
		v := "1.0." + string(rune('0'+i))
		tags["v"+v] = c
		if i < 6 {
			files["docs/v"+v+".md"] = "## Changes\n\n- a\n"
		}
	}
	fx := rowsFixture(t, files)
	raw := "{"
	n := 0
	for k, v := range tags {
		if n > 0 {
			raw += ","
		}
		raw += `"` + k + `":"` + v + `"`
		n++
	}
	raw += "}"
	if err := os.WriteFile(filepath.Join(fx, "github.com", "example", "notes", "tags.json"), []byte(raw), 0o644); err != nil {
		t.Fatal(err)
	}
	tbl := []changelogentries.Target{{Component: "notes", Repo: extract.RepoRef{Key: "github.com/example/notes"},
		Form: changelogentries.FormPerVersionFile, Path: "docs/v{version}.md", MinLocatedNewest: 5}}
	var out, errb bytes.Buffer
	code := run([]string{"rows-check", "--fixture", fx}, tbl, &out, &errb)
	o := out.String()
	if code != 0 || !strings.Contains(o, "PASS notes") || !strings.Contains(o, "newest=6/8") ||
		!strings.Contains(o, "not located: v1.0.7, v1.0.6\n") {
		t.Fatalf("%d %s", code, o)
	}
	// a row that locates everything names nothing
	tbl[0].MinLocatedNewest = 0
	files2 := rowsFixture(t, map[string]string{"docs/v1.0.0.md": "## Changes\n\n- a\n"})
	out.Reset()
	run([]string{"rows-check", "--fixture", files2}, tbl, &out, &errb)
	if strings.Contains(out.String(), "not located") {
		t.Fatalf("%s", out.String())
	}
}
