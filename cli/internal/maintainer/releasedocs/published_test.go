// SPDX-License-Identifier: AGPL-3.0-only

package releasedocs

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/maintainer/releasenotes"
)

const curNotes = "cli/docs/release-notes-" + curTag + ".md"

// publishedRig is a repository where v1.1.0 is published and the base is HEAD
// of the returned state; a test then changes the tree and commits.
func publishedRig(t *testing.T) (root, base string) {
	t.Helper()
	root = build(t, rig{tagCurrent: true}).root
	return root, git(t, root, "rev-parse", "HEAD")
}

func commitAll(t *testing.T, root string) {
	t.Helper()
	git(t, root, "add", "-A")
	git(t, root, "commit", "-q", "--allow-empty", "-m", "change")
}

func read(t *testing.T, root, rel string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(rel)))
	must(t, err)
	return string(b)
}

func edit(t *testing.T, root, rel, old, replacement string) {
	t.Helper()
	doc := read(t, root, rel)
	if !strings.Contains(doc, old) {
		t.Fatalf("%s does not contain %q", rel, old)
	}
	write(t, root, rel, strings.Replace(doc, old, replacement, 1))
}

func published(t *testing.T, root, base string) Result {
	t.Helper()
	res, err := Published(root, base)
	if err != nil {
		t.Fatalf("usage error: %v", err)
	}
	return res
}

// inEntry edits text after the heading of the published CHANGELOG entry.
func inEntry(t *testing.T, root, old, replacement string) {
	t.Helper()
	doc := read(t, root, changelogPath)
	i := strings.Index(doc, "## [1.1.0]")
	if i < 0 || !strings.Contains(doc[i:], old) {
		t.Fatalf("the entry does not contain %q", old)
	}
	write(t, root, changelogPath, doc[:i]+strings.Replace(doc[i:], old, replacement, 1))
}

func TestPublishedAcceptsUntouchedText(t *testing.T) {
	cases := map[string]func(t *testing.T, root string){
		"no change": func(*testing.T, string) {},
		"unrelated file": func(t *testing.T, root string) {
			write(t, root, "x.txt", "x\n")
		},
		"unreleased entry": func(t *testing.T, root string) {
			edit(t, root, changelogPath, "## [Unreleased]\n", "## [Unreleased]\n\n- new\n")
		},
		"new unpublished release": func(t *testing.T, root string) {
			edit(t, root, changelogPath, "## [1.1.0]", "## [1.2.0] - 2026-02-01\n\n- new\n\n## [1.1.0]")
			write(t, root, "cli/docs/release-notes-v1.2.0.md", "# v1.2.0\n")
		},
		"hand text outside the published block": func(t *testing.T, root string) {
			edit(t, root, curNotes, "Hand written text.", "Corrected text.")
		},
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			root, base := publishedRig(t)
			change(t, root)
			commitAll(t, root)
			wantPass(t, published(t, root, base))
		})
	}
}

func TestPublishedRefusesChangedText(t *testing.T) {
	cases := map[string]struct {
		change func(t *testing.T, root string)
		code   int
	}{
		"notes block rewritten": {func(t *testing.T, root string) {
			edit(t, root, curNotes, releasenotes.MarkerBegin+"\n", releasenotes.MarkerBegin+"\nrewritten\n")
		}, CodeNotes},
		"notes markers removed": {func(t *testing.T, root string) {
			edit(t, root, curNotes, releasenotes.MarkerEnd, "")
		}, CodeNotes},
		"notes second block": {func(t *testing.T, root string) {
			write(t, root, curNotes, read(t, root, curNotes)+releasenotes.MarkerBegin+"\n"+releasenotes.MarkerEnd+"\n")
		}, CodeNotes},
		"notes deleted": {func(t *testing.T, root string) {
			must(t, os.Remove(filepath.Join(root, curNotes)))
		}, CodeNotes},
		"notes replaced by a link": {func(t *testing.T, root string) {
			p := filepath.Join(root, curNotes)
			must(t, os.Rename(p, p+".moved"))
			must(t, os.Symlink(filepath.Base(p)+".moved", p))
		}, CodeNotes},
		"notes added for a published version without them": {func(t *testing.T, root string) {
			write(t, root, "cli/docs/release-notes-"+prevTag+".md", "# new\n")
		}, CodeNotes},
		"entry block rewritten": {func(t *testing.T, root string) {
			inEntry(t, root, releasenotes.MarkerBegin+"\n", releasenotes.MarkerBegin+"\nrewritten\n")
		}, CodeChangelog},
		"entry hand text rewritten": {func(t *testing.T, root string) {
			inEntry(t, root, "A hand written entry", "Another entry")
		}, CodeChangelog},
		"entry heading date": {func(t *testing.T, root string) {
			edit(t, root, changelogPath, "2026-01-01", "2026-01-02")
		}, CodeChangelog},
		"entry heading renamed": {func(t *testing.T, root string) {
			edit(t, root, changelogPath, "## [1.1.0]", "## 1.1.0")
		}, CodeChangelog},
		"entry duplicated": {func(t *testing.T, root string) {
			write(t, root, changelogPath, read(t, root, changelogPath)+"\n## [1.1.0] - 2026-01-01\n\n- twice\n")
		}, CodeChangelog},
		"entry cut short by a new heading": {func(t *testing.T, root string) {
			inEntry(t, root, "### Added", "## [0.0.0]\n\n### Added")
		}, CodeChangelog},
		"older entry without notes": {func(t *testing.T, root string) {
			edit(t, root, changelogPath, "99 things", "100 things")
		}, CodeChangelog},
		"changelog deleted": {func(t *testing.T, root string) {
			must(t, os.Remove(filepath.Join(root, changelogPath)))
		}, CodeChangelog},
		"changelog replaced by a link": {func(t *testing.T, root string) {
			p := filepath.Join(root, changelogPath)
			must(t, os.Rename(p, p+".moved"))
			must(t, os.Symlink(changelogPath+".moved", p))
		}, CodeChangelog},
		"notes too large": {func(t *testing.T, root string) {
			write(t, root, curNotes, read(t, root, curNotes)+strings.Repeat("x", maxFile))
		}, CodeNotes},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			root, base := publishedRig(t)
			tc.change(t, root)
			commitAll(t, root)
			res := published(t, root, base)
			wantFail(t, res, tc.code, "")
			if res.ExitCode() == 0 {
				t.Fatal("exit code is 0")
			}
		})
	}
}

// A notes file without a generated block may stay as it is and not change.
func TestPublishedNotesWithoutMarkers(t *testing.T) {
	root := build(t, rig{tagCurrent: true}).root
	name := "cli/docs/release-notes-" + prevTag + ".md"
	write(t, root, name, "# old notes\n")
	commitAll(t, root)
	base := git(t, root, "rev-parse", "HEAD")
	commitAll(t, root)
	wantPass(t, published(t, root, base))
	write(t, root, name, "# rewritten\n")
	commitAll(t, root)
	wantFail(t, published(t, root, base), CodeNotes, prevTag)
}

// The reference is the base, not the tag: text that already differs from the
// tag on the base passes, and restoring the tag's text is a change.
func TestPublishedComparesWithTheBaseNotTheTag(t *testing.T) {
	root := build(t, rig{tagCurrent: true}).root
	edit(t, root, curNotes, releasenotes.MarkerBegin+"\n", releasenotes.MarkerBegin+"\namended on the base\n")
	commitAll(t, root)
	base := git(t, root, "rev-parse", "HEAD")
	commitAll(t, root)
	wantPass(t, published(t, root, base))
	git(t, root, "checkout", "-q", curTag, "--", curNotes)
	commitAll(t, root)
	wantFail(t, published(t, root, base), CodeNotes, curTag)
}

// An unpublished version's text is the business of Check, not of this guard.
func TestPublishedIgnoresUnpublishedVersions(t *testing.T) {
	root := build(t, rig{}).root
	base := git(t, root, "rev-parse", "HEAD")
	edit(t, root, curNotes, releasenotes.MarkerBegin+"\n", releasenotes.MarkerBegin+"\nrewritten\n")
	inEntry(t, root, "A hand written entry", "Another entry")
	commitAll(t, root)
	wantPass(t, published(t, root, base))
	git(t, root, "tag", curTag, base)
	res := published(t, root, base)
	wantFail(t, res, CodeNotes, curTag)
	wantFail(t, res, CodeChangelog, "1.1.0")
}

func TestPublishedFailsClosed(t *testing.T) {
	t.Run("usage", func(t *testing.T) {
		for _, o := range [][2]string{{"", "main"}, {".", ""}} {
			if _, err := Published(o[0], o[1]); err == nil {
				t.Errorf("%q accepted", o)
			}
		}
	})
	t.Run("not a repository", func(t *testing.T) {
		wantFail(t, published(t, t.TempDir(), "main"), CodeTag, "top level")
	})
	t.Run("subdirectory", func(t *testing.T) {
		root, base := publishedRig(t)
		commitAll(t, root)
		wantFail(t, published(t, filepath.Join(root, "cli"), base), CodeTag, "top level")
	})
	t.Run("no tags", func(t *testing.T) {
		root, base := publishedRig(t)
		commitAll(t, root)
		git(t, root, "tag", "-d", prevTag, curTag)
		git(t, root, "tag", "not-a-version")
		wantFail(t, published(t, root, base), CodeTag, "no version tag")
	})
	t.Run("shallow", func(t *testing.T) {
		root, _ := publishedRig(t)
		commitAll(t, root)
		clone := filepath.Join(t.TempDir(), "c")
		git(t, root, "clone", "-q", "--depth=2", "file://"+root, clone)
		git(t, clone, "tag", curTag, "HEAD~1")
		wantFail(t, published(t, clone, "HEAD~1"), CodeTag, "shallow")
	})
	t.Run("broken tag ref store", func(t *testing.T) {
		root, base := publishedRig(t)
		commitAll(t, root)
		write(t, root, ".git/packed-refs", "garbage\n")
		wantFail(t, published(t, root, base), CodeTag, "")
	})
	for name, rev := range map[string]string{"unknown base": "origin/nope", "option as base": "--all", "tree as base": "HEAD^{tree}"} {
		t.Run(name, func(t *testing.T) {
			root, _ := publishedRig(t)
			commitAll(t, root)
			wantFail(t, published(t, root, rev), CodeBase, "does not resolve")
		})
	}
	t.Run("base is the commit under check", func(t *testing.T) {
		root, _ := publishedRig(t)
		wantFail(t, published(t, root, "HEAD"), CodeBase, "itself")
	})
	t.Run("base without a changelog", func(t *testing.T) {
		root, _ := publishedRig(t)
		must(t, os.Remove(filepath.Join(root, changelogPath)))
		commitAll(t, root)
		base := git(t, root, "rev-parse", "HEAD")
		commitAll(t, root)
		wantFail(t, published(t, root, base), CodeBase, "CHANGELOG.md")
	})
	t.Run("base notes are a link", func(t *testing.T) {
		root, _ := publishedRig(t)
		p := filepath.Join(root, curNotes)
		must(t, os.Remove(p))
		must(t, os.Symlink("nowhere", p))
		commitAll(t, root)
		base := git(t, root, "rev-parse", "HEAD")
		commitAll(t, root)
		wantFail(t, published(t, root, base), CodeBase, "base cannot be read")
	})
	t.Run("missing base object", func(t *testing.T) {
		root, base := publishedRig(t)
		blob := git(t, root, "rev-parse", base+":"+curNotes)
		edit(t, root, curNotes, "Hand written text.", "Other text.")
		commitAll(t, root)
		must(t, os.Remove(filepath.Join(root, ".git", "objects", blob[:2], blob[2:])))
		res := published(t, root, base)
		if res.ExitCode() == 0 {
			t.Fatal("a missing base object passed")
		}
	})
}

// GIT_DIR must not move the check to another repository.
func TestPublishedIgnoresGitDirEnvironment(t *testing.T) {
	root, base := publishedRig(t)
	inEntry(t, root, "A hand written entry", "Another entry")
	commitAll(t, root)
	other, _ := publishedRig(t)
	t.Setenv("GIT_DIR", filepath.Join(other, ".git"))
	wantFail(t, published(t, root, base), CodeChangelog, "1.1.0")
}

const (
	betaDef   = "[1.1.0]: https://example.invalid/releases/v1.1.0"
	milestone = "## 0.9.0-alpha.1 - 2025-10-01 (not published as a release)"
	trailer   = "No release has been published yet."
)

// footerRig is a repository whose base CHANGELOG ends with tail, after the
// oldest published entry (1.0.0, tagged v1.0.0).
func footerRig(t *testing.T, tail string) (root, base string) {
	t.Helper()
	root = build(t, rig{tagCurrent: true}).root
	write(t, root, changelogPath, read(t, root, changelogPath)+tail)
	commitAll(t, root)
	return root, git(t, root, "rev-parse", "HEAD")
}

type tailCase struct{ base, head string }

func runTail(t *testing.T, tc tailCase) Result {
	t.Helper()
	root, base := footerRig(t, tc.base)
	doc := read(t, root, changelogPath)
	write(t, root, changelogPath, strings.TrimSuffix(doc, tc.base)+tc.head)
	commitAll(t, root)
	return published(t, root, base)
}

func TestPublishedAcceptsTextAfterTheOldestEntry(t *testing.T) {
	other := "\n[Unreleased]: https://example.invalid/compare/v1.0.0...main\n"
	links := other + betaDef + "\n"
	newer := "\n[Unreleased]: https://example.invalid/compare/v1.1.0...main\n[1.2.0]: https://example.invalid/releases/v1.2.0\n" + betaDef + "\n"
	section := "\n" + milestone + "\n\n- early\n"
	for name, tc := range map[string]tailCase{
		"footer added":                   {"", other},
		"footer removed":                 {other, ""},
		"other definitions changed":      {links, newer},
		"footer with CRLF and spacing":   {links, "\n\n[Unreleased]: https://example.invalid/x\r\n\n" + betaDef + "\r\n\n"},
		"real layout, definitions":       {section + links + "\n" + trailer + "\n", section + newer + "\n" + trailer + "\n"},
		"real layout, trailing prose":    {section + links + "\n" + trailer + "\n", section + links},
		"real layout, milestone section": {section + links, strings.Replace(section, "- early", "- reworded", 1) + links},
	} {
		t.Run(name, func(t *testing.T) {
			wantPass(t, runTail(t, tc))
		})
	}
}

func TestPublishedRefusesTextAfterTheOldestEntry(t *testing.T) {
	links := "\n" + betaDef + "\n"
	section := "\n" + milestone + "\n\n- early\n"
	for name, tc := range map[string]struct {
		tailCase
		version string
	}{
		"prose appended":               {tailCase{"", "\nRewritten.\n"}, "1.0.0"},
		"prose after the footer":       {tailCase{links, links + "\nRewritten.\n"}, "1.0.0"},
		"definition without a blank":   {tailCase{"", "[x]: https://example.invalid/x\n"}, "1.0.0"},
		"definition with a title":      {tailCase{"", "\n[x]: https://example.invalid/x \"Rewritten\"\n"}, "1.0.0"},
		"definition not https":         {tailCase{"", "\n[x]: rewritten\n"}, "1.0.0"},
		"definition on two lines":      {tailCase{"", "\n[x]:\nhttps://example.invalid/x\n"}, "1.0.0"},
		"indented definition":          {tailCase{"", "\n  [x]: https://example.invalid/x\n"}, "1.0.0"},
		"inside an open fence":         {tailCase{"\n```\ncode\n", "\n```\ncode\n\n[x]: https://example.invalid/x\n"}, "1.0.0"},
		"other heading":                {tailCase{"", "\n## Notes\n\nRewritten.\n"}, "1.0.0"},
		"milestone without the words":  {tailCase{"", "\n## 0.9.0 - 2025-10-01\n\nRewritten.\n"}, "1.0.0"},
		"milestone of a tagged one":    {tailCase{"", "\n## 1.0.0 - 2025-10-01 (not published as a release)\n\nRewritten.\n"}, "1.0.0"},
		"published definition changed": {tailCase{links, "\n[1.1.0]: https://example.invalid/other\n"}, "1.1.0"},
		"published definition removed": {tailCase{links, ""}, "1.1.0"},
		"published definition added":   {tailCase{"", links}, "1.1.0"},
		"published definition doubled": {tailCase{links, "\n[1.1.0]: https://example.invalid/other\n" + betaDef + "\n"}, "1.1.0"},
		"changed after a milestone":    {tailCase{section + links, section + "\n[1.1.0]: https://example.invalid/other\n"}, "1.1.0"},
		"quoted second definition":     {tailCase{section + links, section + links + "\n> [ 1.1.0 ]: https://example.invalid/other\n"}, "1.1.0"},
		"listed definition of oldest":  {tailCase{section, section + "\n- [1.0.0]: https://example.invalid/other\n"}, "1.0.0"},
		"destination on the next line": {tailCase{section + "\n[1.1.0]:\n[one]\n", section + "\n[1.1.0]:\n[two]\n"}, "1.1.0"},
		"title on the next line":       {tailCase{section + links, section + links + "\"Rewritten\"\n"}, "1.1.0"},
	} {
		t.Run(name, func(t *testing.T) {
			wantFail(t, runTail(t, tc.tailCase), CodeChangelog, "CHANGELOG.md ["+tc.version+"]")
		})
	}
}

// A milestone heading put inside a published entry cuts it short.
func TestPublishedRefusesAMilestoneInsideAnEntry(t *testing.T) {
	root, base := publishedRig(t)
	inEntry(t, root, "### Added", milestone+"\n\n### Added")
	commitAll(t, root)
	wantFail(t, published(t, root, base), CodeChangelog, "1.1.0")
}

// Letter case does not hide a second definition of a published version.
func TestPublishedLinkDefinitionsIgnoreLetterCase(t *testing.T) {
	root, _ := footerRig(t, "\n[1.2.0-rc.1]: https://example.invalid/a\n")
	git(t, root, "tag", "v1.2.0-rc.1")
	base := git(t, root, "rev-parse", "HEAD")
	commitAll(t, root)
	wantPass(t, published(t, root, base))
	write(t, root, changelogPath, read(t, root, changelogPath)+"\n[1.2.0-RC.1]: https://example.invalid/b\n")
	commitAll(t, root)
	wantFail(t, published(t, root, base), CodeChangelog, "CHANGELOG.md [1.2.0-rc.1]")
}
