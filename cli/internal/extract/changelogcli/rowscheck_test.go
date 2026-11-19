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

const newRowDoc = `{"schema":"prufyx.io/changelog-targets/v1","rows":[` +
	`{"component":"notes","repo":"github.com/example/notes","form":"changelog-per-version-file","path":"docs/v{version}.md"}]}`

func writeTargets(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "targets.json")
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestRowsCheckTargetsFileChecksNewRow(t *testing.T) {
	fx := rowsFixture(t, map[string]string{"docs/v1.0.0.md": "## Changes\n\n- fix a\n"})
	tf := writeTargets(t, newRowDoc)
	// The embedded table has no "notes" row: it is refused without the flag.
	var o0, e0 bytes.Buffer
	if code := Main([]string{"rows-check", "--fixture", fx, "--component", "notes"}, &o0, &e0); code != 2 {
		t.Fatalf("embedded table checked a row it does not have: %d", code)
	}
	var out, errb bytes.Buffer
	code := Main([]string{"rows-check", "--fixture", fx, "--targets", tf}, &out, &errb)
	if code != 0 || !strings.Contains(out.String(), "PASS notes") {
		t.Fatalf("code %d\nout: %s\nerr: %s", code, out.String(), errb.String())
	}
	rows, err := changelogentries.LoadTargets([]byte(newRowDoc))
	if err != nil {
		t.Fatal(err)
	}
	digest, err := changelogentries.CodeDigest()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "check") || !strings.Contains(out.String(), rows[0].RowDigest()) || !strings.Contains(out.String(), digest) {
		t.Fatalf("receipt must carry the file row digest and the reader code digest:\n%s", out.String())
	}
}

func TestRowsCheckTargetsRefusals(t *testing.T) {
	fx := rowsFixture(t, map[string]string{"docs/v1.0.0.md": "## Changes\n\n- fix a\n"})
	hdr := `{"schema":"prufyx.io/changelog-targets/v1","rows":[`
	good := `{"component":"notes","repo":"github.com/example/notes","form":"changelog-per-version-file","path":"docs/v{version}.md"}`
	bodies := map[string]string{
		"unknown field":       hdr + `{"component":"notes","repo":"github.com/example/notes","form":"changelog-per-version-file","path":"docs/v{version}.md","extra":1}]}`,
		"duplicate component": hdr + good + `,` + good + `]}`,
		"free regex":          hdr + `{"component":"notes","repo":"github.com/example/notes","form":"changelog-file","path":"CHANGELOG.md","headingStyle":"^v(.*)$"}]}`,
		"free regex field":    hdr + `{"component":"notes","repo":"github.com/example/notes","form":"changelog-file","path":"CHANGELOG.md","headingRegex":"^v(.*)$"}]}`,
		"non-md path":         hdr + `{"component":"notes","repo":"github.com/example/notes","form":"changelog-file","path":"CHANGELOG.toml","headingStyle":"version-plain"}]}`,
		"dotdot path":         hdr + `{"component":"notes","repo":"github.com/example/notes","form":"changelog-file","path":"../x.md","headingStyle":"version-plain"}]}`,
		"duplicate key":       hdr + `{"component":"notes","component":"notes","repo":"github.com/example/notes","form":"changelog-per-version-file","path":"docs/v{version}.md"}]}`,
		"wrong schema":        `{"schema":"x","rows":[` + good + `]}`,
		"no rows":             hdr + `]}`,
		"trailing data":       hdr + good + `]} {}`,
		"not json":            `nope`,
	}
	for name, body := range bodies {
		t.Run(name, func(t *testing.T) {
			var out, errb bytes.Buffer
			code := Main([]string{"rows-check", "--fixture", fx, "--targets", writeTargets(t, body)}, &out, &errb)
			if code != 2 || out.Len() != 0 {
				t.Fatalf("code %d out %q err %q", code, out.String(), errb.String())
			}
		})
	}
	dir := t.TempDir()
	for name, args := range map[string][]string{
		"missing":   {"--targets", filepath.Join(dir, "none.json")},
		"directory": {"--targets", dir},
		"empty arg": {"--targets", ""},
		"repeated":  {"--targets", writeTargets(t, newRowDoc), "--targets", writeTargets(t, newRowDoc)},
	} {
		t.Run(name, func(t *testing.T) {
			var out, errb bytes.Buffer
			code := Main(append([]string{"rows-check", "--fixture", fx}, args...), &out, &errb)
			if code != 2 || out.Len() != 0 {
				t.Fatalf("code %d out %q err %q", code, out.String(), errb.String())
			}
		})
	}
	if os.Geteuid() != 0 {
		p := writeTargets(t, newRowDoc)
		if err := os.Chmod(p, 0); err != nil {
			t.Fatal(err)
		}
		var out, errb bytes.Buffer
		if code := Main([]string{"rows-check", "--fixture", fx, "--targets", p}, &out, &errb); code != 2 || out.Len() != 0 {
			t.Fatalf("unreadable: code %d", code)
		}
	}
}

// The file supplies rows only: the reader code digest and the reading of an
// unchanged row are the same with and without the flag.
func TestRowsCheckTargetsCannotChangeReader(t *testing.T) {
	fx := rowsFixture(t, map[string]string{"docs/v1.0.0.md": "## Changes\n\n- fix a\n"})
	var a, b, e bytes.Buffer
	embedded := []changelogentries.Target{{Component: "notes", Repo: extract.RepoRef{Key: "github.com/example/notes"},
		Form: changelogentries.FormPerVersionFile, Path: "docs/v{version}.md"}}
	if code := run([]string{"rows-check", "--fixture", fx}, embedded, &a, &e); code != 0 {
		t.Fatalf("embedded run %d %s", code, e.String())
	}
	if code := run([]string{"rows-check", "--fixture", fx, "--targets", writeTargets(t, newRowDoc)}, nil, &b, &e); code != 0 {
		t.Fatalf("targets run %d %s", code, e.String())
	}
	// Only the targets marker may differ.
	norm := func(x string) string {
		i := strings.Index(x, " targets=")
		j := strings.Index(x[i:], "\n")
		return x[:i] + x[i+j:]
	}
	if norm(a.String()) != norm(b.String()) {
		t.Fatalf("same row, different output:\n%s\n---\n%s", a.String(), b.String())
	}
}

func runTargets(t *testing.T, fx, tf string, extra ...string) (int, string) {
	t.Helper()
	var out, errb bytes.Buffer
	args := append([]string{"rows-check", "--fixture", fx, "--targets", tf}, extra...)
	code := Main(args, &out, &errb)
	return code, out.String()
}

func TestRowsCheckTargetsMarker(t *testing.T) {
	fx := rowsFixture(t, map[string]string{"docs/v1.0.0.md": "## Changes\n\n- fix a\n"})
	tf := writeTargets(t, newRowDoc)
	sum := sha256.Sum256([]byte(newRowDoc))
	code, out := runTargets(t, fx, tf)
	if code != 0 || !strings.Contains(out, " targets=file:sha256:"+hex.EncodeToString(sum[:])+"\n") {
		t.Fatalf("code %d\n%s", code, out)
	}
	var o, e bytes.Buffer
	embedded := []changelogentries.Target{{Component: "notes", Repo: extract.RepoRef{Key: "github.com/example/notes"},
		Form: changelogentries.FormPerVersionFile, Path: "docs/v{version}.md"}}
	if c := run([]string{"rows-check", "--fixture", fx}, embedded, &o, &e); c != 0 || !strings.Contains(o.String(), " targets=embedded\n") {
		t.Fatalf("code %d\n%s", c, o.String())
	}
}

func TestRowsCheckTargetsMoreRefusals(t *testing.T) {
	fx := rowsFixture(t, map[string]string{"docs/v1.0.0.md": "## Changes\n\n- fix a\n"})
	hdr := `{"schema":"prufyx.io/changelog-targets/v1","rows":[`
	row := func(c, repo, extra string) string {
		return `{"component":"` + c + `","repo":"github.com/example/` + repo + `","form":"changelog-per-version-file","path":"docs/v{version}.md"` + extra + `}`
	}
	bodies := map[string]string{
		"over 1 MiB":       newRowDoc + strings.Repeat(" ", 1<<20),
		"unsorted":         hdr + row("zeta", "z", "") + `,` + row("alpha", "a", "") + `]}`,
		"maxBytes field":   hdr + row("notes", "notes", `,"maxBytes":99999999`) + `]}`,
		"unknown heading":  hdr + `{"component":"notes","repo":"github.com/example/notes","form":"changelog-file","path":"CHANGELOG.md","headingStyle":"nope"}]}`,
		"unknown boundary": hdr + `{"component":"notes","repo":"github.com/example/notes","form":"changelog-file","path":"CHANGELOG.md","headingStyle":"version-plain","boundaryStyles":["nope"]}]}`,
		"template twice":   hdr + `{"component":"notes","repo":"github.com/example/notes","form":"changelog-per-version-file","path":"docs/{version}/{version}.md"}]}`,
		"template non-md":  hdr + `{"component":"notes","repo":"github.com/example/notes","form":"changelog-per-version-file","path":"docs/v{version}.txt"}]}`,
	}
	for name, body := range bodies {
		t.Run(name, func(t *testing.T) {
			if code, out := runTargets(t, fx, writeTargets(t, body)); code != 2 || out != "" {
				t.Fatalf("code %d out %q", code, out)
			}
		})
	}
	dir := t.TempDir()
	good := writeTargets(t, newRowDoc)
	link := filepath.Join(dir, "dirlink")
	if err := os.Symlink(dir, link); err != nil {
		t.Fatal(err)
	}
	for name, p := range specialTargets(t, dir, link) {
		t.Run(name, func(t *testing.T) {
			if code, out := runTargets(t, fx, p); code != 2 || out != "" {
				t.Fatalf("code %d out %q", code, out)
			}
		})
	}
	t.Run("component absent from file", func(t *testing.T) {
		if code, out := runTargets(t, fx, good, "--component", "other"); code != 2 || out != "" {
			t.Fatalf("code %d out %q", code, out)
		}
	})
	t.Run("override changes rowDigest", func(t *testing.T) {
		a, err := changelogentries.LoadTargets([]byte(newRowDoc))
		if err != nil {
			t.Fatal(err)
		}
		b, err := changelogentries.LoadTargets([]byte(strings.Replace(newRowDoc, "docs/v{version}.md", "other/v{version}.md", 1)))
		if err != nil {
			t.Fatal(err)
		}
		if a[0].Component != b[0].Component || a[0].RowDigest() == b[0].RowDigest() {
			t.Fatal("a different row for the same component must give a different rowDigest")
		}
	})
}

// changelogattest takes its row from its own config and must never depend on
// the CLI or on file-supplied rows.
func TestAttestDoesNotImportCLIOrFileRows(t *testing.T) {
	entries, err := os.ReadDir("../changelogattest")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") {
			continue
		}
		b, err := os.ReadFile(filepath.Join("../changelogattest", e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		for _, bad := range []string{"extract/changelogcli", "LoadTargets"} {
			if strings.Contains(string(b), bad) {
				t.Fatalf("%s mentions %q", e.Name(), bad)
			}
		}
	}
}
