// SPDX-License-Identifier: AGPL-3.0-only

package changelogentries

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/extract"
)

const rcRepo = "github.com/example/notes"

func sha(c byte) string { return strings.Repeat(string(c), 40) }

// rcFixture writes a fixture tree: tags maps a tag to a commit char; files
// maps commit char + "|" + path to bytes. A tag's commit dir exists only when
// it holds a file or is listed in empty.
func rcFixture(t *testing.T, tags map[string]byte, files map[string]string, emptyDirs ...byte) extract.FixtureReader {
	t.Helper()
	root := t.TempDir()
	base := filepath.Join(root, filepath.FromSlash(rcRepo))
	tj := map[string]string{}
	for n, c := range tags {
		tj[n] = sha(c)
	}
	if err := os.MkdirAll(base, 0o755); err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(tj)
	if err := os.WriteFile(filepath.Join(base, "tags.json"), raw, 0o644); err != nil {
		t.Fatal(err)
	}
	for _, c := range emptyDirs {
		if err := os.MkdirAll(filepath.Join(base, "commits", sha(c)), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for k, v := range files {
		c, p, _ := strings.Cut(k, "|")
		full := filepath.Join(base, "commits", sha(c[0]), filepath.FromSlash(p))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(v), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return extract.FixtureReader{Root: root}
}

const pvBody = "## Changes\n\n- fix a\n- fix b\n"

var pvRow = Target{Component: "notes", Repo: extract.RepoRef{Key: rcRepo}, Form: FormPerVersionFile, Path: "docs/releases/v{version}.md"}

var plRow = Target{
	Component: "notes", Repo: extract.RepoRef{Key: rcRepo}, Form: FormPerLineFile, Path: "CHANGELOG/CHANGELOG-{line}.md",
	HeadingPattern:   headingStyles["version-v-prefixed"],
	BoundaryPatterns: []string{boundaryStyles["prerelease-v-prefixed"]},
}

func TestCheckRowPerVersionPass(t *testing.T) {
	src := rcFixture(t,
		map[string]byte{"v1.0.0": 'a', "v1.0.1": 'b', "v1.1.0-rc.1": 'c', "nightly": 'c'},
		map[string]string{"a|docs/releases/v1.0.0.md": pvBody},
		'b', 'c')
	r := CheckRow(src, pvRow, "d")
	if r.Status != RowPass || r.Tags != 2 || r.Located != 1 || r.NotFinal != 2 || r.Withheld[PathMissingAtTag] != 1 {
		t.Fatalf("%+v", r)
	}
}

func TestCheckRowPerLinePass(t *testing.T) {
	file := "# v1.2.1\n\n- fix b\n\n# v1.2.0\n\n- first\n"
	src := rcFixture(t,
		map[string]byte{"v1.2.0": 'a', "v1.2.1": 'b'},
		map[string]string{"a|CHANGELOG/CHANGELOG-1.2.md": file, "b|CHANGELOG/CHANGELOG-1.2.md": file})
	r := CheckRow(src, plRow, "d")
	if r.Status != RowPass || r.Tags != 2 || r.Located != 2 {
		t.Fatalf("%+v", r)
	}
}

func TestCheckRowFailsClosed(t *testing.T) {
	ok := map[string]string{"a|docs/releases/v1.0.0.md": pvBody}
	cases := map[string]struct {
		src extract.FixtureReader
		row Target
	}{
		"path never resolves": {rcFixture(t, map[string]byte{"v1.0.0": 'a', "v1.0.1": 'b'}, map[string]string{"a|other/x.md": "x"}, 'b'),
			pvRow},
		"wrong template for the tree": {rcFixture(t, map[string]byte{"v1.0.0": 'a'}, ok),
			Target{Component: "notes", Repo: pvRow.Repo, Form: FormPerVersionFile, Path: "docs/notes/v{version}.md"}},
		"only non-final tags":                               {rcFixture(t, map[string]byte{"v1.0.0-rc.1": 'a', "main": 'a'}, ok), pvRow},
		"commit not in source (read error is not a reason)": {rcFixture(t, map[string]byte{"v1.0.0": 'a', "v1.0.1": 'z'}, ok), pvRow},
		"row defect: two placeholders": {rcFixture(t, map[string]byte{"v1.0.0": 'a'}, ok),
			Target{Component: "notes", Repo: pvRow.Repo, Form: FormPerVersionFile, Path: "docs/{version}/{version}.md"}},
		"row defect: wrong placeholder": {rcFixture(t, map[string]byte{"v1.0.0": 'a'}, ok),
			Target{Component: "notes", Repo: pvRow.Repo, Form: FormPerVersionFile, Path: "docs/releases/v{line}.md"}},
		"headings never read": {rcFixture(t, map[string]byte{"v1.2.0": 'a'}, map[string]string{"a|CHANGELOG/CHANGELOG-1.2.md": "# 1.2.0\n\n- x\n"}),
			plRow},
		"tags unreadable": {extract.FixtureReader{Root: t.TempDir()}, pvRow},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			r := CheckRow(c.src, c.row, "d")
			if r.Status != RowFail || len(r.Reasons) == 0 {
				t.Fatalf("not failed: %+v", r)
			}
		})
	}
}

func TestCheckRowAnyUntypedErrorFailsDespiteEntries(t *testing.T) {
	src := rcFixture(t, map[string]byte{"v1.0.0": 'a', "v1.0.1": 'z'}, map[string]string{"a|docs/releases/v1.0.0.md": pvBody})
	r := CheckRow(src, pvRow, "d")
	if r.Located != 1 || r.Status != RowFail {
		t.Fatalf("%+v", r)
	}
}

func TestCheckRowsSkipsUnreadFormsButNotWhenAsked(t *testing.T) {
	src := rcFixture(t, map[string]byte{"v1.0.0": 'a'}, nil, 'a')
	rel := Target{Component: "notes", Repo: pvRow.Repo, Form: FormGithubRelease}
	rs, err := CheckRows(src, []Target{rel}, "", "d")
	if err != nil || rs[0].Status != RowSkip {
		t.Fatalf("%v %+v", err, rs)
	}
	rs, err = CheckRows(src, []Target{rel}, "notes", "d")
	if err != nil || rs[0].Status != RowFail {
		t.Fatalf("%v %+v", err, rs)
	}
	if _, err := CheckRows(src, []Target{rel}, "nope", "d"); err == nil {
		t.Fatal("unknown component accepted")
	}
	if _, err := CheckRows(src, nil, "", "d"); err == nil {
		t.Fatal("empty table accepted")
	}
}

func TestTemplatedRowsLoad(t *testing.T) {
	doc := `{"schema":"prufyx.io/changelog-targets/v1","rows":[
	{"component":"a","repo":"github.com/o/a","form":"changelog-per-line-file","path":"CHANGELOG/CHANGELOG-{line}.md","headingStyle":"version-v-prefixed","boundaryStyles":["prerelease-v-prefixed"]},
	{"component":"b","repo":"github.com/o/b","form":"changelog-per-version-file","path":"docs/releases/v{version}.md"},
	{"component":"c","repo":"github.com/o/c","form":"changelog-per-version-file","path":"changelogs/{version}.md"}]}`
	rows, err := parseTargets([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	if rows[0].Form != FormPerLineFile || rows[0].Path != "CHANGELOG/CHANGELOG-{line}.md" || rows[0].HeadingPattern != headingStyles["version-v-prefixed"] ||
		rows[1].Form != FormPerVersionFile || rows[1].HeadingPattern != "" || len(rows[1].BoundaryPatterns) != 0 {
		t.Fatalf("%+v", rows)
	}
	// A loaded row locates on a fixture.
	src := rcFixture(t, map[string]byte{"v1.0.0": 'a'}, map[string]string{"a|docs/releases/v1.0.0.md": pvBody})
	b := rows[1]
	b.Repo = pvRow.Repo
	if r := CheckRow(src, b, "d"); r.Status != RowPass {
		t.Fatalf("%+v", r)
	}
}

func TestTemplatedRowsRefuse(t *testing.T) {
	pl := func(kv string) string {
		return `{"component":"a","repo":"github.com/o/a","form":"changelog-per-line-file",` + kv + `}`
	}
	pv := func(kv string) string {
		return `{"component":"a","repo":"github.com/o/a","form":"changelog-per-version-file",` + kv + `}`
	}
	const st = `"headingStyle":"version-v-prefixed","boundaryStyles":["prerelease-v-prefixed"]`
	cases := map[string]string{
		"unknown form":                    `{"component":"a","repo":"github.com/o/a","form":"per-version-file","path":"x/{version}.md"}`,
		"free text placeholder":           pv(`"path":"docs/{release}.md"`),
		"two placeholders":                pv(`"path":"docs/{version}/{version}.md"`),
		"no placeholder":                  pv(`"path":"docs/notes.md"`),
		"line placeholder in per-version": pv(`"path":"docs/{line}.md"`),
		"version placeholder in per-line": pl(`"path":"docs/{version}.md",` + st),
		"regex in template":               pv(`"path":"docs/.*{version}.md"`),
		"glob in template":                pv(`"path":"docs/*/{version}.md"`),
		"shell in template":               pv(`"path":"docs/$(x){version}.md"`),
		"space in template":               pv(`"path":"docs/a b{version}.md"`),
		"non-ascii in template":           pv("\"path\":\"docs/é{version}.md\""),
		"dotdot":                          pv(`"path":"../docs/v{version}.md"`),
		"dotdot inside":                   pv(`"path":"docs/../v{version}.md"`),
		"absolute":                        pv(`"path":"/docs/v{version}.md"`),
		"placeholder is a whole element":  pv(`"path":"docs/{version}/notes.md"`),
		"digit next to placeholder":       pv(`"path":"docs/1{version}.md"`),
		"no path":                         pv(``),
		"per-version with style":          pv(`"path":"docs/v{version}.md","headingStyle":"version-v-prefixed"`),
		"per-version with boundaries":     pv(`"path":"docs/v{version}.md","boundaryStyles":["unreleased"]`),
		"per-line without style":          pl(`"path":"CHANGELOG-{line}.md"`),
		"per-line without boundary":       pl(`"path":"CHANGELOG-{line}.md","headingStyle":"version-v-prefixed"`),
		"per-line regex style":            pl(`"path":"CHANGELOG-{line}.md","headingStyle":"^v(?P<version>x)$","boundaryStyles":["unreleased"]`),
		"per-line unknown style":          pl(`"path":"CHANGELOG-{line}.md","headingStyle":"nope","boundaryStyles":["unreleased"]`),
		"unknown field (pattern)":         pv(`"path":"docs/v{version}.md","pattern":"x"`),
		"unknown field (window)":          pv(`"path":"docs/v{version}.md","window":"3"`),
	}
	for name, row := range cases {
		t.Run(name, func(t *testing.T) {
			doc := `{"schema":"prufyx.io/changelog-targets/v1","rows":[` + row + `]}`
			if rows, err := parseTargets([]byte(doc)); err == nil || rows != nil {
				t.Fatalf("accepted: %v", rows)
			}
		})
	}
}

func TestNewStylesCompileAndReadOneVersion(t *testing.T) {
	for n, p := range headingStyles {
		re, err := compileAnchored(p)
		if err != nil {
			t.Fatalf("heading %s: %v", n, err)
		}
		if names := re.SubexpNames(); len(names) != 2 || names[1] != "version" {
			t.Fatalf("heading %s: capture groups %v", n, names)
		}
	}
	for n, p := range boundaryStyles {
		if _, err := compileAnchored(p); err != nil {
			t.Fatalf("boundary %s: %v", n, err)
		}
	}
}
