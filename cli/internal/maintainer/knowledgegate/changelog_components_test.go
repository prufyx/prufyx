// SPDX-License-Identifier: AGPL-3.0-only

package knowledgegate

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/extract"
	"github.com/prufyx/prufyx/cli/internal/extract/changelogentries"
	"github.com/prufyx/prufyx/cli/internal/lineattest"
)

func treeWithTargets(t *testing.T, data string) Tree {
	t.Helper()
	root := t.TempDir()
	p := filepath.Join(root, filepath.FromSlash(changelogentries.TargetsPath))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if data != "" {
		if err := os.WriteFile(p, []byte(data), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return Tree{Root: root}
}

// The member table is read from the tree, not from the binary, and is derived
// from the rows: the component is the package URL of each row's repository.
func TestChangelogProjectComponentsAreReadFromTheTreeRows(t *testing.T) {
	doc := `{"schema":"prufyx.io/changelog-targets/v1","rows":[{"component":"alpha","repo":"github.com/example/alpha","form":"github-release"},{"component":"beta","repo":"github.com/example/beta","form":"post-tag"}]}`
	got, err := changelogProjectComponents(treeWithTargets(t, doc))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got["alpha"] != "pkg:github/example/alpha" || got["beta"] != "pkg:github/example/beta" {
		t.Fatalf("%v", got)
	}
}

// A tree without the table has no member: nothing is listed, nothing fails.
func TestChangelogProjectComponentsAbsentTableIsEmpty(t *testing.T) {
	got, err := changelogProjectComponents(treeWithTargets(t, ""))
	if err != nil || got == nil || len(got) != 0 {
		t.Fatalf("%v %v", got, err)
	}
}

func TestChangelogProjectComponentsRefuseABadTable(t *testing.T) {
	for name, doc := range map[string]string{
		"not json":       "{",
		"wrong schema":   `{"schema":"x","rows":[{"component":"a","repo":"github.com/e/a","form":"post-tag"}]}`,
		"unknown field":  `{"schema":"prufyx.io/changelog-targets/v1","rows":[{"component":"a","repo":"github.com/e/a","form":"post-tag","extra":1}]}`,
		"unsorted":       `{"schema":"prufyx.io/changelog-targets/v1","rows":[{"component":"b","repo":"github.com/e/b","form":"post-tag"},{"component":"a","repo":"github.com/e/a","form":"post-tag"}]}`,
		"duplicate repo": `{"schema":"prufyx.io/changelog-targets/v1","rows":[{"component":"a","repo":"github.com/e/a","form":"post-tag"},{"component":"b","repo":"github.com/e/a","form":"post-tag"}]}`,
		"no rows":        `{"schema":"prufyx.io/changelog-targets/v1","rows":[]}`,
	} {
		if got, err := changelogProjectComponents(treeWithTargets(t, doc)); err == nil || got != nil {
			t.Errorf("%s: accepted (%v)", name, got)
		}
	}
}

func listedTags(names ...string) []extract.Tag {
	var out []extract.Tag
	for i, n := range names {
		out = append(out, extract.Tag{Name: n, Commit: fmt.Sprintf("%039x%d", 0, i)})
	}
	return out
}

func listedRecord(tags []extract.Tag, from, to []string) lineattest.LineAttestation {
	rel := func(names []string) []lineattest.Release {
		var out []lineattest.Release
		for _, n := range names {
			for _, t := range tags {
				if t.Name == n {
					out = append(out, lineattest.Release{Version: strings.TrimPrefix(n, "v"), Commit: t.Commit})
				}
			}
		}
		return out
	}
	return lineattest.LineAttestation{Component: "pkg:github/example/project", Line: "1.9", FactFamily: lineattest.FamilyChangelogListedEntries,
		Releases: &lineattest.Releases{From: rel(from), To: rel(to)}}
}

// C1 of the listed-entries family: the record names exactly the final
// releases the tags show on both lines, each at its commit.
func TestListedReleasesComplete(t *testing.T) {
	tags := listedTags("v1.8.0", "v1.8.1", "v1.9.0", "v1.9.1", "v1.9.2-rc.1", "v1.10.0")
	if err := listedReleasesComplete(listedRecord(tags, []string{"v1.8.0", "v1.8.1"}, []string{"v1.9.0", "v1.9.1"}), tags); err != nil {
		t.Fatal(err)
	}
	for name, a := range map[string]lineattest.LineAttestation{
		"a patch release of the line left out": listedRecord(tags, []string{"v1.8.0", "v1.8.1"}, []string{"v1.9.0"}),
		"a previous-line release left out":     listedRecord(tags, []string{"v1.8.0"}, []string{"v1.9.0", "v1.9.1"}),
		"a release the tags do not show":       listedRecord(append(tags, extract.Tag{Name: "v1.9.7", Commit: fmt.Sprintf("%040x", 99)}), []string{"v1.8.0", "v1.8.1"}, []string{"v1.9.0", "v1.9.1", "v1.9.7"}),
		"no releases":                          {Component: "pkg:github/example/project", Line: "1.9", FactFamily: lineattest.FamilyChangelogListedEntries},
	} {
		if err := listedReleasesComplete(a, tags); err == nil || !strings.Contains(err.Error(), "empty-list/releases-incomplete") {
			t.Errorf("%s: %v", name, err)
		}
	}
	// A moved tag: the record's commit is not the tags'.
	moved := listedRecord(tags, []string{"v1.8.0", "v1.8.1"}, []string{"v1.9.0", "v1.9.1"})
	moved.Releases.To[1].Commit = fmt.Sprintf("%040x", 77)
	if err := listedReleasesComplete(moved, tags); err == nil {
		t.Error("a moved tag was accepted")
	}
	// A line without a previous minor line has no hop.
	first := listedRecord(tags, nil, []string{"v1.9.0"})
	first.Line = "1.0"
	if err := listedReleasesComplete(first, tags); err == nil {
		t.Error("line 1.0 was accepted")
	}
}
