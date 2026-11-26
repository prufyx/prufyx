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
