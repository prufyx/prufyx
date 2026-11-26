// SPDX-License-Identifier: AGPL-3.0-only

package releasedocs

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/maintainer/coveragereport"
	"github.com/prufyx/prufyx/cli/internal/maintainer/knowledgegate"
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
	return RegenOptions{ReleaseBlocks: true, Root: e.root, Mode: ModeUnreleased, Generate: fakeGen{counts: counts}}
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
	_, err := Regen(RegenOptions{ReleaseBlocks: true, Root: dir, Mode: ModeUnreleased, Generate: fakeGen{}})
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
	_, err := Regen(RegenOptions{ReleaseBlocks: true, Root: sub, Mode: ModeUnreleased, Generate: fakeGen{counts: curCounts(t)}})
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

// ---- tag state ----

// wantRefusedUnwritten runs regen on a tree with a stale counts file and notes
// block and requires a refusal of the given class that leaves both as they were.
func wantRefusedUnwritten(t *testing.T, root string, code int, contains string) {
	t.Helper()
	write(t, root, releasenotes.CountsPath, "{}\n")
	notes := blank(readAll(t, root, notesRel()))
	write(t, root, notesRel(), notes)
	cl := readAll(t, root, "CHANGELOG.md")
	_, err := Regen(RegenOptions{ReleaseBlocks: true, Root: root, Mode: ModeUnreleased, Generate: fakeGen{counts: curCounts(t)}})
	var re *RegenError
	if !errors.As(err, &re) || re.Code != code || !strings.Contains(re.Msg, contains) {
		t.Fatalf("got %v, want code %d containing %q", err, code, contains)
	}
	if readAll(t, root, releasenotes.CountsPath) != "{}\n" || readAll(t, root, notesRel()) != notes || readAll(t, root, "CHANGELOG.md") != cl {
		t.Fatal("a refused run wrote files")
	}
}

func TestRegenRefusesMoreThanOneUnpublishedNotesFile(t *testing.T) {
	e := build(t, rig{toCommit: "first"})
	write(t, e.root, "cli/docs/release-notes-v1.2.0.md", "# next\n")
	wantRefusedUnwritten(t, e.root, CodeTag, "more than one notes file")
}

func TestRegenRefusesAVersionNotAboveEveryTag(t *testing.T) {
	for _, tag := range []string{"v1.1.1", "v1.2.0", "v2.0.0-rc.1"} {
		e := build(t, rig{toCommit: "first"})
		git(t, e.root, "tag", tag)
		wantRefusedUnwritten(t, e.root, CodeTag, "not higher than the existing tag "+tag)
	}
}

func TestRegenAcceptsAVersionAboveItsPrereleaseTag(t *testing.T) {
	e := build(t, rig{toCommit: "first"})
	git(t, e.root, "tag", curTag+"-rc.1")
	git(t, e.root, "tag", "nightly")
	regenOK(t, regenOpts(e, curCounts(t)))
}

func TestRegenRefusesAShallowClone(t *testing.T) {
	e := build(t, rig{toCommit: "first"})
	dir := filepath.Join(t.TempDir(), "shallow")
	git(t, e.root, "clone", "-q", "--depth", "1", "file://"+e.root, dir)
	wantRefusedUnwritten(t, dir, CodeTag, "shallow")
}

// ---- failures after a write ----

// scriptGen lets a test write files from inside the generator calls.
type scriptGen struct {
	blocks func(root string) error
	counts func(root string) ([]byte, error)
}

func (g scriptGen) Blocks(root string) ([]string, error) { return nil, g.blocks(root) }
func (g scriptGen) Counts(root string) ([]byte, error)   { return g.counts(root) }

func chmod(t *testing.T, root, rel string, mode os.FileMode) {
	t.Helper()
	must(t, os.Chmod(filepath.Join(root, filepath.FromSlash(rel)), mode))
}

func modeOf(t *testing.T, root, rel string) os.FileMode {
	t.Helper()
	st, err := os.Lstat(filepath.Join(root, filepath.FromSlash(rel)))
	must(t, err)
	return st.Mode().Perm()
}

func overwriteBlocks(root string) error {
	for _, rel := range blockPaths() {
		if err := os.WriteFile(filepath.Join(root, filepath.FromSlash(rel)), []byte("half written"), 0o644); err != nil {
			return err
		}
	}
	return nil
}

func TestRegenSnapshotsEveryGeneratedBlockFile(t *testing.T) {
	got := strings.Join(blockPaths(), " ")
	for _, want := range []string{readmePath, knowledgegate.PreviewPath} {
		if !strings.Contains(got, want) {
			t.Fatalf("%s is not in %q", want, got)
		}
	}
}

func TestRegenRestoresAfterAGeneratorFailure(t *testing.T) {
	boom := errors.New("boom")
	cases := map[string]struct {
		gen  scriptGen
		code int
	}{
		"blocks fails after writing": {scriptGen{blocks: func(root string) error {
			if err := overwriteBlocks(root); err != nil {
				return err
			}
			return boom
		}}, CodeReadme},
		"counts fails after blocks": {scriptGen{
			blocks: overwriteBlocks,
			counts: func(string) ([]byte, error) { return nil, boom },
		}, CodeCounts},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			e := build(t, rig{toCommit: "first"})
			write(t, e.root, knowledgegate.PreviewPath, "preview\n")
			chmod(t, e.root, readmePath, 0o600)
			before := map[string]string{}
			for _, f := range []string{readmePath, knowledgegate.PreviewPath, releasenotes.CountsPath, notesRel(), "CHANGELOG.md"} {
				before[f] = readAll(t, e.root, f)
			}
			_, err := Regen(RegenOptions{ReleaseBlocks: true, Root: e.root, Mode: ModeUnreleased, Generate: tc.gen})
			var re *RegenError
			if !errors.As(err, &re) || re.Code != tc.code || strings.Contains(err.Error(), "NOT restored") {
				t.Fatalf("got %v", err)
			}
			for f, b := range before {
				if readAll(t, e.root, f) != b {
					t.Fatalf("%s was not restored", f)
				}
			}
			if modeOf(t, e.root, readmePath) != 0o600 {
				t.Fatal("the restored file lost its mode")
			}
		})
	}
}

func TestRegenReportsFilesItCannotRestore(t *testing.T) {
	e := build(t, rig{toCommit: "first"})
	write(t, e.root, knowledgegate.PreviewPath, "preview\n")
	gen := scriptGen{blocks: overwriteBlocks, counts: func(root string) ([]byte, error) {
		// A non-empty directory cannot be replaced by a rename.
		p := filepath.Join(root, readmePath)
		if err := os.Remove(p); err != nil {
			return nil, err
		}
		if err := os.MkdirAll(filepath.Join(p, "x"), 0o755); err != nil {
			return nil, err
		}
		return nil, errors.New("boom")
	}}
	_, err := Regen(RegenOptions{ReleaseBlocks: true, Root: e.root, Mode: ModeUnreleased, Generate: gen})
	var re *RegenError
	if !errors.As(err, &re) || re.Code != CodeCounts {
		t.Fatalf("got %v", err)
	}
	if !strings.Contains(err.Error(), "boom") || !strings.Contains(err.Error(), "NOT restored: "+readmePath+":") {
		t.Fatalf("the error does not name the unrestored file: %v", err)
	}
	if readAll(t, e.root, knowledgegate.PreviewPath) != "preview\n" {
		t.Fatal("one failed restore stopped the others")
	}
}

func TestRegenKeepsFileModes(t *testing.T) {
	e := build(t, rig{toCommit: "first"})
	modes := map[string]os.FileMode{releasenotes.CountsPath: 0o600, notesRel(): 0o640, "CHANGELOG.md": 0o600}
	write(t, e.root, releasenotes.CountsPath, "{}\n")
	write(t, e.root, notesRel(), blank(readAll(t, e.root, notesRel())))
	for f, m := range modes {
		chmod(t, e.root, f, m)
	}
	regenOK(t, regenOpts(e, curCounts(t)))
	for f, m := range modes {
		if got := modeOf(t, e.root, f); got != m {
			t.Errorf("%s: mode %v, want %v", f, got, m)
		}
	}
}

// ---- links ----

func TestRegenRefusesSymlinks(t *testing.T) {
	cases := map[string]struct {
		rel  string
		code int
	}{
		"notes":            {notesRel(), CodeNotes},
		"changelog":        {"CHANGELOG.md", CodeChangelog},
		"readme":           {readmePath, CodeReadme},
		"parent of counts": {"cli/docs/generated", CodeCounts},
		"docs directory":   {"cli/docs", CodeReadme},
	}
	for name, tc := range cases {
		for _, where := range []string{"inside", "outside"} {
			t.Run(name+" "+where, func(t *testing.T) {
				e := build(t, rig{toCommit: "first"})
				write(t, e.root, knowledgegate.PreviewPath, "preview\n")
				write(t, e.root, releasenotes.CountsPath, "{}\n")
				write(t, e.root, notesRel(), blank(readAll(t, e.root, notesRel())))
				before := map[string]string{}
				for _, f := range []string{readmePath, "CHANGELOG.md", releasenotes.CountsPath, notesRel(), knowledgegate.PreviewPath} {
					before[f] = readAll(t, e.root, f)
				}
				base := e.root
				if where == "outside" {
					base = t.TempDir()
				}
				target := filepath.Join(base, "moved")
				p := filepath.Join(e.root, filepath.FromSlash(tc.rel))
				must(t, os.Rename(p, target))
				must(t, os.Symlink(target, p))
				_, err := Regen(regenOpts(e, curCounts(t)))
				var re *RegenError
				if !errors.As(err, &re) || re.Code != tc.code {
					t.Fatalf("got %v, want code %d", err, tc.code)
				}
				// Read through the link: neither the target nor any other file changed.
				for f, b := range before {
					if readAll(t, e.root, f) != b {
						t.Fatalf("%s changed", f)
					}
				}
				if st, err := os.Lstat(p); err != nil || st.Mode()&os.ModeSymlink == 0 {
					t.Fatal("the link was replaced")
				}
			})
		}
	}
}

// ---- the tree generator ----

// copyRepository copies the regular files of this source tree, without .git.
func copyRepository(t *testing.T, src, dst string) {
	t.Helper()
	must(t, filepath.WalkDir(src, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, p)
		if err != nil {
			return err
		}
		if d.Name() == ".git" {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if d.IsDir() {
			return os.MkdirAll(filepath.Join(dst, rel), 0o755)
		}
		if !d.Type().IsRegular() {
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(dst, rel), b, 0o644)
	}))
}

// staleRegion replaces the text between two marker lines.
func staleRegion(t *testing.T, root, rel, begin, end string) {
	t.Helper()
	s := readAll(t, root, rel)
	i, j := strings.Index(s, begin+"\n"), strings.Index(s, end+"\n")
	if i < 0 || j < i {
		t.Fatalf("%s: no region %s", rel, begin)
	}
	write(t, root, rel, s[:i]+begin+"\n\nstale\n\n"+s[j:])
}

func TestRegenWithTheTreeGeneratorThenCheck(t *testing.T) {
	root := t.TempDir()
	copyRepository(t, "../../../..", root)
	old, err := filepath.Glob(filepath.Join(root, "cli", "docs", "release-notes-*.md"))
	must(t, err)
	for _, p := range old {
		must(t, os.Remove(p))
	}
	git(t, root, "init", "-q", "-b", "main")
	git(t, root, "add", "-A", "-f")
	git(t, root, "commit", "-q", "-m", "previous")
	git(t, root, "tag", "v9.0.0")
	block := releasenotes.MarkerBegin + "\n\nChanges from `v9.0.0` to `v9.1.0`, computed by hand.\n\n" + releasenotes.MarkerEnd + "\n"
	write(t, root, "cli/docs/release-notes-v9.1.0.md", "# Prufyx v9.1.0\n\n"+block)
	cl := readAll(t, root, "CHANGELOG.md")
	i := strings.Index(cl, "\n## [0.")
	if i < 0 {
		t.Fatal("no released CHANGELOG heading to insert before")
	}
	write(t, root, "CHANGELOG.md", cl[:i]+"\n## [9.1.0] - 2026-01-01\n\n"+block+cl[i:])
	git(t, root, "add", "-A", "-f")
	git(t, root, "commit", "-q", "-m", "next")

	generated := []string{readmePath, knowledgegate.PreviewPath, releasenotes.CountsPath}
	committed := map[string]string{}
	for _, f := range generated {
		committed[f] = readAll(t, root, f)
	}
	staleRegion(t, root, readmePath, coveragereport.READMEBegin, coveragereport.READMEEnd)
	staleRegion(t, root, knowledgegate.PreviewPath, coveragereport.PreviewIntroBegin, coveragereport.PreviewIntroEnd)
	write(t, root, releasenotes.CountsPath, "{}\n")
	chmod(t, root, readmePath, 0o600)

	o := RegenOptions{ReleaseBlocks: true, Root: root, Mode: ModeUnreleased}
	res := regenOK(t, o)
	if len(res.Changed) != 5 {
		t.Fatalf("changed %v, want README, preview, counts, notes and CHANGELOG", res.Changed)
	}
	for _, f := range generated {
		if readAll(t, root, f) != committed[f] {
			t.Fatalf("%s differs from the committed generated file", f)
		}
	}
	if modeOf(t, root, readmePath) != 0o600 {
		t.Fatal("the README lost its mode")
	}
	wantPass(t, check(t, Options{Root: root, Mode: ModeUnreleased}))
	if res := regenOK(t, o); len(res.Changed) != 0 {
		t.Fatalf("second run changed %v", res.Changed)
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
