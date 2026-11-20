// SPDX-License-Identifier: AGPL-3.0-only

package releasedocs

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/maintainer/releasenotes"
)

// fakeGen stands in for the tree generators: it writes nothing and returns
// the fixture counts.
type fakeGen struct {
	counts []byte
	err    error
}

func (fakeGen) Blocks(string) ([]string, error) { return nil, nil }
func (f fakeGen) Counts(string) ([]byte, error) { return f.counts, f.err }

func regenOpts(e env, counts []byte) RegenOptions {
	return RegenOptions{Root: e.root, Mode: ModeUnreleased, Generate: fakeGen{counts: counts}}
}

func curCounts(t *testing.T) []byte { return []byte(fixture(t, "counts-cur.json")) }

func readAll(t *testing.T, root, rel string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(rel)))
	must(t, err)
	return string(b)
}

func notesRel() string { return "cli/docs/release-notes-" + curTag + ".md" }

// blank replaces the generated block of a notes file or entry with junk.
func blank(s string) string {
	i := strings.Index(s, releasenotes.MarkerBegin)
	j := strings.Index(s[i:], releasenotes.MarkerEnd)
	block := s[i : i+j]
	h := headerLine.FindString(block)
	return s[:i] + releasenotes.MarkerBegin + "\n\n" + h + "\n\nstale 7\n\n" + s[i+j:]
}

func regenOK(t *testing.T, o RegenOptions) RegenResult {
	t.Helper()
	res, err := Regen(o)
	if err != nil {
		t.Fatalf("regen: %v", err)
	}
	return res
}

func TestRegenThenCheckPassesAndIsIdempotent(t *testing.T) {
	e := build(t, rig{toCommit: "first"})
	cc := curCounts(t)
	// Break every derived file the check compares.
	write(t, e.root, releasenotes.CountsPath, "{}\n")
	write(t, e.root, notesRel(), blank(readAll(t, e.root, notesRel())))
	cl := readAll(t, e.root, "CHANGELOG.md")
	i := strings.Index(cl, "## [1.1.0]")
	write(t, e.root, "CHANGELOG.md", cl[:i]+blank(cl[i:]))
	if res := check(t, e.opts(ModeUnreleased)); res.ExitCode() == 0 {
		t.Fatal("the broken tree passes the check")
	}
	res := regenOK(t, regenOpts(e, cc))
	if len(res.Changed) != 3 {
		t.Fatalf("changed %v, want counts, notes and changelog", res.Changed)
	}
	o := e.opts(ModeUnreleased)
	o.Regenerate = fakeRegen{counts: cc}
	wantPass(t, check(t, o))
	// Second run: no diff, nothing reported.
	before := map[string]string{}
	for _, f := range []string{releasenotes.CountsPath, notesRel(), "CHANGELOG.md", "README.md"} {
		before[f] = readAll(t, e.root, f)
	}
	if res := regenOK(t, regenOpts(e, cc)); len(res.Changed) != 0 {
		t.Fatalf("second run changed %v", res.Changed)
	}
	for f, b := range before {
		if readAll(t, e.root, f) != b {
			t.Fatalf("second run changed %s", f)
		}
	}
}

func TestRegenKeepsEverythingOutsideTheMarkers(t *testing.T) {
	e := build(t, rig{toCommit: "first"})
	cc := curCounts(t)
	notes := readAll(t, e.root, notesRel())
	cl := readAll(t, e.root, "CHANGELOG.md")
	i := strings.Index(cl, "## [1.1.0]")
	write(t, e.root, notesRel(), blank(notes))
	write(t, e.root, "CHANGELOG.md", cl[:i]+blank(cl[i:]))
	regenOK(t, regenOpts(e, cc))
	outside := func(s string) (string, string) {
		a := strings.Index(s, releasenotes.MarkerBegin)
		b := strings.Index(s, releasenotes.MarkerEnd)
		return s[:a], s[b:]
	}
	nh, nt := outside(notes)
	gh, gt := outside(readAll(t, e.root, notesRel()))
	if nh != gh || nt != gt {
		t.Fatal("regen touched the notes file outside the markers")
	}
	// The CHANGELOG: other entries and the hand-written entry text are byte-equal.
	got := readAll(t, e.root, "CHANGELOG.md")
	k := strings.Index(got, "## [1.1.0]")
	if got[:k] != cl[:i] {
		t.Fatal("regen touched the CHANGELOG before the entry")
	}
	oh, ot := outside(cl[i:])
	nh2, nt2 := outside(got[k:])
	if oh != nh2 || ot != nt2 {
		t.Fatal("regen touched the CHANGELOG entry outside the markers")
	}
	if !strings.Contains(got[:k], releasenotes.MarkerBegin) {
		t.Fatal("the Unreleased block marker vanished")
	}
}

func TestRegenRefusesWithoutAGitRepository(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "README.md", "x\n")
	_, err := Regen(RegenOptions{Root: dir, Mode: ModeUnreleased, Generate: fakeGen{}})
	var re *RegenError
	if !errors.As(err, &re) || re.Code != CodeTag {
		t.Fatalf("got %v, want a typed tag error", err)
	}
	if readAll(t, dir, "README.md") != "x\n" {
		t.Fatal("files changed")
	}
}

func TestRegenRefusesASubdirectoryOfARepository(t *testing.T) {
	e := build(t, rig{toCommit: "first"})
	sub := filepath.Join(e.root, "cli")
	_, err := Regen(RegenOptions{Root: sub, Mode: ModeUnreleased, Generate: fakeGen{counts: curCounts(t)}})
	var re *RegenError
	if !errors.As(err, &re) || re.Code != CodeTag {
		t.Fatalf("got %v", err)
	}
}

func TestRegenRefusesWhenThePreviousTagIsMissingAndRestores(t *testing.T) {
	e := build(t, rig{toCommit: "first"})
	git(t, e.root, "tag", "-d", prevTag)
	write(t, e.root, releasenotes.CountsPath, "{}\n")
	_, err := Regen(regenOpts(e, curCounts(t)))
	var re *RegenError
	if !errors.As(err, &re) || re.Code != CodeTag {
		t.Fatalf("got %v", err)
	}
	if readAll(t, e.root, releasenotes.CountsPath) != "{}\n" {
		t.Fatal("a refused run wrote the counts file")
	}
}

func TestRegenRefusesNotesWithoutMarkersAndRestoresEarlierWrites(t *testing.T) {
	e := build(t, rig{toCommit: "first"})
	notes := readAll(t, e.root, notesRel())
	nomark := strings.ReplaceAll(strings.ReplaceAll(notes, releasenotes.MarkerBegin, "x"), releasenotes.MarkerEnd, "y")
	write(t, e.root, notesRel(), nomark)
	write(t, e.root, releasenotes.CountsPath, "{}\n")
	_, err := Regen(regenOpts(e, curCounts(t)))
	var re *RegenError
	if !errors.As(err, &re) || re.Code != CodeNotes {
		t.Fatalf("got %v", err)
	}
	if readAll(t, e.root, releasenotes.CountsPath) != "{}\n" || readAll(t, e.root, notesRel()) != nomark {
		t.Fatal("a refused run left written files")
	}
}

func TestRegenRefusesAChangelogWithoutTheEntry(t *testing.T) {
	e := build(t, rig{toCommit: "first", changelog: func(s string) string { return strings.ReplaceAll(s, "## [1.1.0]", "## [1.1.1]") }})
	write(t, e.root, releasenotes.CountsPath, "{}\n")
	_, err := Regen(regenOpts(e, curCounts(t)))
	var re *RegenError
	if !errors.As(err, &re) || re.Code != CodeChangelog {
		t.Fatalf("got %v", err)
	}
	if readAll(t, e.root, releasenotes.CountsPath) != "{}\n" {
		t.Fatal("a refused run left the counts file written")
	}
}

func TestRegenReplacesAStaleCommitLabelWithHead(t *testing.T) {
	e := build(t, rig{toCommit: "first"})
	notes := readAll(t, e.root, notesRel())
	m := headerLine.FindStringSubmatch(notes)
	write(t, e.root, notesRel(), strings.Replace(notes, "to `"+curTag+"` ("+m[4]+")", "to `"+curTag+"` (0123456789ab)", 1))
	regenOK(t, regenOpts(e, curCounts(t)))
	head := git(t, e.root, "rev-parse", "--short=12", "HEAD")
	if !strings.Contains(readAll(t, e.root, notesRel()), "to `"+curTag+"` ("+head+")") {
		t.Fatal("the unknown commit label was not replaced by HEAD")
	}
	o := e.opts(ModeUnreleased)
	o.Regenerate = fakeRegen{counts: curCounts(t)}
	wantPass(t, check(t, o))
}

func TestRegenSkipsPublishedTags(t *testing.T) {
	e := build(t, rig{toCommit: "first", tagCurrent: true})
	notes := blank(readAll(t, e.root, notesRel()))
	write(t, e.root, notesRel(), notes)
	regenOK(t, regenOpts(e, curCounts(t)))
	if readAll(t, e.root, notesRel()) != notes {
		t.Fatal("a published tag's notes were rewritten")
	}
}

func TestRegenRefusesALinkedOutput(t *testing.T) {
	e := build(t, rig{toCommit: "first"})
	p := filepath.Join(e.root, filepath.FromSlash(releasenotes.CountsPath))
	target := filepath.Join(t.TempDir(), "other.json")
	must(t, os.WriteFile(target, []byte("keep"), 0o644))
	must(t, os.Remove(p))
	must(t, os.Symlink(target, p))
	if _, err := Regen(regenOpts(e, curCounts(t))); err == nil {
		t.Fatal("a symlinked counts file was written through")
	}
	if b, _ := os.ReadFile(target); string(b) != "keep" {
		t.Fatal("the link target changed")
	}
}

func TestRegenUsage(t *testing.T) {
	for _, o := range []RegenOptions{{Root: "x"}, {Mode: ModeUnreleased}, {Root: "x", Mode: ModeRelease}} {
		var u *UsageError
		if _, err := Regen(o); !errors.As(err, &u) {
			t.Errorf("%+v: got %v", o, err)
		}
	}
}
