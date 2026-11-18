// SPDX-License-Identifier: AGPL-3.0-only

package changelogentries

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/extract"
)

func propose(t *testing.T, src extract.FixtureReader, only ...string) (*Proposal, error) {
	t.Helper()
	return ProposeRow(src, "notes", rcRepo, only)
}

func wantNoRow(t *testing.T, err error, reason string) {
	t.Helper()
	var nr *NoRow
	if !errors.As(err, &nr) || nr.Reason != reason {
		t.Fatalf("want NO-ROW %s, got %v", reason, err)
	}
}

var threeTags = map[string]byte{"v1.0.0": 'a', "v1.0.1": 'a', "v1.1.0": 'a', "v1.1.0-rc.1": 'a'}

func TestProposePerVersion(t *testing.T) {
	src := rcFixture(t, threeTags, map[string]string{
		"a|docs/releases/v1.0.0.md": pvBody, "a|docs/releases/v1.0.1.md": pvBody, "a|docs/releases/v1.1.0.md": pvBody,
	})
	p, err := propose(t, src)
	if err != nil {
		t.Fatal(err)
	}
	if p.Row.Form != FormPerVersionFile || p.Row.Path != "docs/releases/v{version}.md" || p.Located != 3 || len(p.Hits) != 3 || p.Row.BoundaryStyles != nil {
		t.Fatalf("%+v", p)
	}
}

func TestProposePerLineKeepsOnlyNeededBoundaries(t *testing.T) {
	file := "# v1.2.1\n\n- b\n\n# v1.2.0\n\n- a\n\n# v1.2.0-rc.1\n\n- rc\n"
	src := rcFixture(t, map[string]byte{"v1.2.0": 'a', "v1.2.1": 'a'}, map[string]string{"a|CHANGELOG/CHANGELOG-1.2.md": file})
	p, err := propose(t, src)
	if err != nil {
		t.Fatal(err)
	}
	if p.Row.Form != FormPerLineFile || p.Row.HeadingStyle != "version-v-prefixed" || p.Located != 2 {
		t.Fatalf("%+v", p)
	}
	for _, b := range p.Row.BoundaryStyles {
		if b != "prerelease-v-prefixed" {
			t.Fatalf("unneeded boundary kept: %v", p.Row.BoundaryStyles)
		}
	}
	if len(p.Row.BoundaryStyles) != 1 {
		t.Fatalf("%v", p.Row.BoundaryStyles)
	}
}

func TestProposeHighestRateWinsTieGoesToFirst(t *testing.T) {
	tags := map[string]byte{"v1.0.0": 'a', "v1.0.1": 'a'}
	both := "## 1.0.1\n\n- b\n\n## 1.0.0\n\n- a\n"
	// HISTORY.md locates both tags, CHANGELOG.md only one: HISTORY.md wins on rate.
	src := rcFixture(t, tags, map[string]string{"a|CHANGELOG.md": "## 1.0.1\n\n- b\n", "a|HISTORY.md": both})
	p, err := propose(t, src)
	if err != nil || p.Row.Path != "HISTORY.md" || p.Located != 2 {
		t.Fatalf("%v %+v", err, p)
	}
	// Equal rate: the first in the fixed order.
	src = rcFixture(t, tags, map[string]string{"a|CHANGELOG.md": both, "a|HISTORY.md": both, "a|NEWS.md": both})
	p, err = propose(t, src)
	if err != nil || p.Row.Path != "CHANGELOG.md" {
		t.Fatalf("%v %+v", err, p)
	}
}

func TestProposeIsDeterministicAndLoads(t *testing.T) {
	src := rcFixture(t, threeTags, map[string]string{"a|docs/releases/v1.0.0.md": pvBody, "a|docs/releases/v1.0.1.md": pvBody})
	var prev []byte
	for i := 0; i < 5; i++ {
		p, err := propose(t, src)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := json.Marshal(p)
		if prev != nil && string(prev) != string(b) {
			t.Fatalf("not deterministic:\n%s\n%s", prev, b)
		}
		prev = b
		doc, _ := json.Marshal(map[string]any{"schema": TargetsSchema, "rows": []rowData{p.Row}})
		if _, err := parseTargets(doc); err != nil {
			t.Fatal(err)
		}
	}
}

func TestProposeWindowAndExplicitTags(t *testing.T) {
	src := rcFixture(t, threeTags, map[string]string{"a|docs/releases/v1.0.0.md": pvBody})
	p, err := propose(t, src, "v1.0.0")
	if err != nil || p.Located != 1 || len(p.Hits) != 1 {
		t.Fatalf("%v %+v", err, p)
	}
	for name, tags := range map[string][]string{
		"unrecorded": {"v9.9.9"}, "not final": {"v1.1.0-rc.1"}, "twice": {"v1.0.0", "v1.0.0"},
	} {
		if _, err := propose(t, src, tags...); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
}

func TestProposeRefusesNonMarkdown(t *testing.T) {
	for name, file := range map[string]string{
		"toml": "releases/v1.0.0.toml", "yaml": "changelogs/1.0.0.yaml", "yml": "changelogs/1.0.0.yml",
	} {
		t.Run(name, func(t *testing.T) {
			src := rcFixture(t, map[string]byte{"v1.0.0": 'a'}, map[string]string{"a|" + file: "- a thing\n- another\n"})
			_, err := propose(t, src)
			wantNoRow(t, err, NoRowNonMarkdown)
		})
	}
}

func TestMarkdownOnlyInSchemaAndReader(t *testing.T) {
	for _, p := range []string{"releases/v{version}.toml", "changelogs/{version}.yaml", "changelogs/{version}.yml", "releases/{version}", "releases/{version}.md.toml", "docs/.md{version}"} {
		doc := `{"schema":"prufyx.io/changelog-targets/v1","rows":[{"component":"a","repo":"github.com/o/a","form":"changelog-per-version-file","path":"` + p + `"}]}`
		if rows, err := parseTargets([]byte(doc)); err == nil {
			t.Fatalf("per-version %s accepted: %v", p, rows)
		}
	}
	for _, p := range []string{"CHANGELOG.toml", "CHANGELOG.yaml", "CHANGELOG", "docs/.md"} {
		doc := `{"schema":"prufyx.io/changelog-targets/v1","rows":[{"component":"a","repo":"github.com/o/a","form":"changelog-file","path":"` + p + `","headingStyle":"version-plain","boundaryStyles":["unreleased"]}]}`
		if rows, err := parseTargets([]byte(doc)); err == nil {
			t.Fatalf("file %s accepted: %v", p, rows)
		}
	}
	// The reader refuses a hand-built target with a non-markdown path as well.
	src := rcFixture(t, map[string]byte{"v1.0.0": 'a'}, map[string]string{"a|releases/v1.0.0.toml": "- a\n- b\n"})
	for _, tg := range []Target{
		{Component: "notes", Repo: pvRow.Repo, Form: FormPerVersionFile, Path: "releases/v{version}.toml"},
		{Component: "notes", Repo: pvRow.Repo, Form: FormFile, Path: "releases/v1.0.0.toml", HeadingPattern: headingStyles["version-plain"], BoundaryPatterns: []string{boundaryStyles["unreleased"]}},
	} {
		_, err := Locate(src, tg, extract.Tag{Name: "v1.0.0", Commit: sha('a')})
		if c, ok := CodeOf(err); !ok || c != NoChangelogTarget {
			t.Fatalf("%s: %v", tg.Path, err)
		}
	}
}

func TestProposeNoRow(t *testing.T) {
	_, err := propose(t, rcFixture(t, map[string]byte{"main": 'a', "v1.0.0-rc.1": 'a'}, nil, 'a'))
	wantNoRow(t, err, NoRowNoTags)
	_, err = propose(t, rcFixture(t, map[string]byte{"v1.0.0": 'a'}, map[string]string{"a|README.md": "x"}))
	wantNoRow(t, err, NoRowNoCandidate)
	// A commit the source cannot serve is a read failure, never a NO-ROW or a row.
	_, err = propose(t, rcFixture(t, map[string]byte{"v1.0.0": 'b'}, map[string]string{"a|CHANGELOG.md": "x"}))
	var nr *NoRow
	if err == nil || errors.As(err, &nr) {
		t.Fatalf("%v", err)
	}
	for _, c := range [][2]string{{"Bad", rcRepo}, {"notes", "https://github.com/example/notes"}, {"notes", "github.com/Example/notes"}} {
		if _, err := ProposeRow(rcFixture(t, threeTags, nil), c[0], c[1], nil); err == nil {
			t.Fatalf("%v accepted", c)
		}
	}
}
