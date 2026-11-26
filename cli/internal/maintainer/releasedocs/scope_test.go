// SPDX-License-Identifier: AGPL-3.0-only

package releasedocs

import (
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/maintainer/releasenotes"
)

// By default regen writes the counts and blocks every change keeps current, and
// no release text, even where the release text is stale.
func TestRegenDefaultWritesNoNotesAndNoChangelog(t *testing.T) {
	e := build(t, rig{notes: replaceIn("| Change |", "| Changed |")})
	editSectionBlock(t, e.root, replaceIn("| Change |", "| Changed |"))
	notes, changelog := read(t, e.root, notesFile), read(t, e.root, changelogPath)
	write(t, e.root, releasenotes.CountsPath, "{}\n")
	res := regenOK(t, RegenOptions{Root: e.root, Mode: ModeUnreleased, Generate: fakeGen{counts: curCounts(t)}})
	if len(res.Changed) != 1 || res.Changed[0] != releasenotes.CountsPath {
		t.Fatalf("changed: %v", res.Changed)
	}
	if read(t, e.root, notesFile) != notes || read(t, e.root, changelogPath) != changelog {
		t.Fatal("release text was written without ReleaseBlocks")
	}
	// The stale release text still fails the strict check.
	wantBothStale(t, check(t, e.opts(ModeUnreleased)))
	// The cut option writes it.
	regenOK(t, RegenOptions{Root: e.root, Mode: ModeUnreleased, ReleaseBlocks: true, Generate: fakeGen{counts: curCounts(t)}})
	wantPass(t, check(t, e.opts(ModeUnreleased)))
}

// A published release's text cannot be reached by default, whatever tags the
// clone holds.
func TestRegenDefaultLeavesReleaseTextWithoutAnyTag(t *testing.T) {
	e := build(t, rig{notes: replaceIn("| Change |", "| Changed |")})
	git(t, e.root, "tag", "-d", prevTag)
	notes := read(t, e.root, notesFile)
	regenOK(t, RegenOptions{Root: e.root, Mode: ModeUnreleased, Generate: fakeGen{counts: curCounts(t)}})
	if read(t, e.root, notesFile) != notes {
		t.Fatal("notes written")
	}
}

func TestUnreleasedChangelogBlockMustBeEmptyInEveryMode(t *testing.T) {
	filled := releasenotes.MarkerBegin + "\nWe cover everything.\n" + releasenotes.MarkerEnd
	empty := releasenotes.MarkerBegin + "\n" + releasenotes.MarkerEnd
	for name, with := range map[string]string{
		"text":          filled,
		"stray begin":   releasenotes.MarkerBegin + "\nhidden 42 projects",
		"stray end":     releasenotes.MarkerEnd,
		"two pairs":     empty + "\n" + empty,
		"reversed pair": releasenotes.MarkerEnd + "\n" + releasenotes.MarkerBegin,
	} {
		t.Run(name, func(t *testing.T) {
			// The first empty pair of the fixture is the [Unreleased] one.
			e := build(t, rig{changelog: replaceIn("## [Unreleased]\n\n"+empty, "## [Unreleased]\n\n"+with)})
			wantFail(t, check(t, e.opts(ModeUnreleased)), CodeChangelog, "[Unreleased]")
			base := git(t, e.root, "rev-parse", "HEAD")
			commitAll(t, e.root, "next")
			wantFail(t, check(t, e.withBase(base)), CodeChangelog, "[Unreleased]")
			git(t, e.root, "tag", curTag)
			wantFail(t, check(t, withDeny(t, e.opts(ModeRelease))), CodeChangelog, "[Unreleased]")
		})
	}
	e := build(t, rig{changelog: replaceIn("## [Unreleased]\n\n"+empty+"\n", "## [Unreleased]\n")})
	res := check(t, e.opts(ModeUnreleased))
	for _, f := range res.Findings {
		if strings.Contains(f.Msg, "[Unreleased]") {
			t.Fatalf("an entry without markers was refused: %v", f.Msg)
		}
	}
}
