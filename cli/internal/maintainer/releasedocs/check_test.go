// SPDX-License-Identifier: AGPL-3.0-only

package releasedocs

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/maintainer/coveragereport"
	"github.com/prufyx/prufyx/cli/internal/maintainer/releasenotes"
)

const fixtures = "../releasenotes/testdata/"

// fakeRegen stands in for the tree regeneration: unless overridden it agrees
// with whatever the tree commits.
type fakeRegen struct {
	stale     []string
	staleErr  error
	counts    []byte
	countsErr error
}

func (f fakeRegen) ReadmeStale(string) ([]string, error) { return f.stale, f.staleErr }
func (f fakeRegen) Counts(root string) ([]byte, error) {
	if f.counts != nil || f.countsErr != nil {
		return f.counts, f.countsErr
	}
	return os.ReadFile(filepath.Join(root, filepath.FromSlash(releasenotes.CountsPath)))
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func git(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir, "-c", "user.name=t", "-c", "user.email=t@example.invalid", "-c", "commit.gpgsign=false", "-c", "tag.gpgsign=false"}, args...)...)
	b, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v %s", args, err, b)
	}
	return strings.TrimSpace(string(b))
}

func write(t *testing.T, root, rel, text string) {
	t.Helper()
	p := filepath.Join(root, filepath.FromSlash(rel))
	must(t, os.MkdirAll(filepath.Dir(p), 0o755))
	must(t, os.WriteFile(p, []byte(text), 0o644))
}

func fixture(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(fixtures + name)
	must(t, err)
	return string(b)
}

const (
	prevTag = "v1.0.0"
	curTag  = "v1.1.0"
)

// rig describes a synthetic repository: tag v1.0.0 with the previous counts,
// then commits with the current counts, the README, the notes file and the
// CHANGELOG entry for v1.1.0. Mutators run before the last commit.
type rig struct {
	tagCurrent bool
	notes      func(string) string
	changelog  func(string) string
	readme     func(string) string
	counts     func(string) string
	toCommit   string // label in the header; "first" = the commit of the previous tag
	prevLabel  string
	// files are written after the notes are generated from the good tree and
	// before the last commit; an empty text removes the file.
	files map[string]string
	// features replaces the feature file of the tree before the notes are
	// generated (the notes then render it); empty keeps goodFeatures.
	features string
}

type env struct {
	root string
}

func (e env) opts(mode string) Options {
	o := Options{Root: e.root, Mode: mode, Regenerate: fakeRegen{}}
	if mode != ModeUnreleased {
		o.Tag, o.Previous = curTag, prevTag
	}
	return o
}

const goodFeatures = `{
  "schema": "prufyx.io/release-features/v1",
  "features": [
    {"id": "demo-check", "title": "A check that works", "state": "works", "demo": "prufyx demo --flag", "evidence": "file:README.md", "notYet": ""},
    {"id": "later", "title": "A later thing", "state": "not-yet", "demo": "", "evidence": "", "notYet": "It is not built."}
  ]
}
`

const goodSmoke = `{
  "schema": "prufyx.io/release-features-smoke/v1",
  "entries": [
    {"demo": "prufyx demo --flag", "kind": "binary", "args": ["demo", "--flag"], "wantExit": 0, "wantContains": "ok"}
  ]
}
`

const readmeText = "# Title\n\n> **Status: public beta.** The `" + curTag + "` release is out.\n\nIntro line.\n\n" + coveragereport.READMEBegin + "\n\ngenerated text 5\n\n" + coveragereport.READMEEnd + "\n\nTail text.\n"

func identity(s string) string { return s }

func build(t *testing.T, r rig) env {
	t.Helper()
	if r.notes == nil {
		r.notes = identity
	}
	if r.changelog == nil {
		r.changelog = identity
	}
	if r.readme == nil {
		r.readme = identity
	}
	if r.counts == nil {
		r.counts = identity
	}
	root := t.TempDir()
	git(t, root, "init", "-q", "-b", "main")
	write(t, root, releasenotes.CountsPath, fixture(t, "counts-prev.json"))
	write(t, root, "README.md", strings.ReplaceAll(readmeText, curTag, prevTag))
	write(t, root, "CHANGELOG.md", "# Changelog\n\n## [1.0.0] - 2025-12-01\n\n- Old entry with 99 things.\n")
	git(t, root, "add", "-A")
	git(t, root, "commit", "-q", "-m", "one")
	git(t, root, "tag", prevTag)
	first := git(t, root, "rev-parse", "--short=12", "HEAD")

	write(t, root, releasenotes.CountsPath, r.counts(fixture(t, "counts-cur.json")))
	write(t, root, "README.md", r.readme(readmeText))
	toCommit := r.toCommit
	if toCommit == "first" {
		toCommit = first
	}
	prev := r.prevLabel
	if prev == "" {
		prev = prevTag
	}
	feat := goodFeatures
	if r.features != "" {
		feat = r.features
	}
	write(t, root, releasenotes.FeaturesPath, feat)
	write(t, root, releasenotes.SmokePath, goodSmoke)
	write(t, root, SmokeTestPath, "package main\n")
	g := &checker{o: Options{Mode: ModeUnreleased}, root: root}
	git(t, root, "add", "-A")
	git(t, root, "commit", "-q", "-m", "data")
	r3, r4, ok := g.render("gen", curTag, prev, toCommit)
	if !ok {
		t.Fatalf("cannot generate the fixture block: %v", g.res.Findings)
	}
	notes := "# Prufyx " + curTag + "\n\nHand written text.\n\n## Changes\n\n- one change\n\n" + releasenotes.MarkerBegin + "\n" + releasenotes.MarkerEnd + "\n"
	notes, err := releasenotes.ReplaceBlock(notes, r3)
	must(t, err)
	changelog := "# Changelog\n\n## [Unreleased]\n\n" + releasenotes.MarkerBegin + "\n" + releasenotes.MarkerEnd + "\n\n## [1.1.0] - 2026-01-01\n\n" + releasenotes.MarkerBegin + "\n" + releasenotes.MarkerEnd + "\n\n### Added\n\n- A hand written entry, exits 2 on failure.\n\n## [1.0.0] - 2025-12-01\n\n- Old entry with 99 things.\n"
	// Replace the block of the 1.1.0 entry only.
	i := strings.Index(changelog, "## [1.1.0]")
	entry, err := releasenotes.ReplaceBlock(changelog[i:], r4)
	must(t, err)
	changelog = changelog[:i] + entry
	write(t, root, "cli/docs/release-notes-"+curTag+".md", r.notes(notes))
	write(t, root, "CHANGELOG.md", r.changelog(changelog))
	for rel, text := range r.files {
		if text == "" {
			must(t, os.Remove(filepath.Join(root, filepath.FromSlash(rel))))
			continue
		}
		write(t, root, rel, text)
	}
	git(t, root, "add", "-A")
	git(t, root, "commit", "-q", "-m", "docs")
	if r.tagCurrent {
		git(t, root, "tag", curTag)
	}
	return env{root: root}
}

func check(t *testing.T, o Options) Result {
	t.Helper()
	res, err := Check(o)
	if err != nil {
		t.Fatalf("usage error: %v", err)
	}
	return res
}

func wantFail(t *testing.T, res Result, code int, contains string) {
	t.Helper()
	for _, f := range res.Findings {
		if f.Code == code && strings.Contains(f.Msg, contains) {
			return
		}
	}
	t.Fatalf("want a finding with code %d containing %q, got %+v", code, contains, res.Findings)
}

func wantPass(t *testing.T, res Result) {
	t.Helper()
	if len(res.Findings) != 0 {
		t.Fatalf("unexpected findings: %+v", res.Findings)
	}
	if res.ExitCode() != 0 {
		t.Fatal("exit code is not 0")
	}
}

func denyFile(t *testing.T, words ...string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "deny.txt")
	must(t, os.WriteFile(p, []byte("# names\n"+strings.Join(words, "\n")+"\n"), 0o600))
	return p
}

func withDeny(t *testing.T, o Options) Options {
	t.Helper()
	o.DenyFile = denyFile(t, "zorblax")
	return o
}

func replaceIn(old, new string) func(string) string {
	return func(s string) string {
		if !strings.Contains(s, old) {
			panic("fixture does not contain " + old)
		}
		return strings.Replace(s, old, new, 1)
	}
}

func stripMarkers(s string) string {
	s = strings.Replace(s, releasenotes.MarkerBegin+"\n", "", 1)
	return strings.Replace(s, releasenotes.MarkerEnd+"\n", "", 1)
}

// ---- usage ----

func TestUsageErrorsAreRefusals(t *testing.T) {
	deny := denyFile(t, "zorblax")
	site := filepath.Join(t.TempDir(), "site.json")
	must(t, os.WriteFile(site, []byte("{}"), 0o600))
	cases := map[string]Options{
		"no mode":                  {Root: "."},
		"unknown mode":             {Root: ".", Mode: "warn"},
		"no root":                  {Mode: ModeUnreleased},
		"unreleased with tag":      {Root: ".", Mode: ModeUnreleased, Tag: curTag},
		"release without tag":      {Root: ".", Mode: ModeRelease, DenyFile: deny},
		"release without previous": {Root: ".", Mode: ModeRelease, Tag: curTag, DenyFile: deny},
		"release without deny":     {Root: ".", Mode: ModeRelease, Tag: curTag, Previous: prevTag},
		"cut without deny":         {Root: ".", Mode: ModeCut, Tag: curTag, Previous: prevTag, SiteCounts: site},
		"cut without site":         {Root: ".", Mode: ModeCut, Tag: curTag, Previous: prevTag, DenyFile: deny},
		"deny file missing":        {Root: ".", Mode: ModeRelease, Tag: curTag, Previous: prevTag, DenyFile: "/nonexistent/deny"},
		"deny file empty":          {Root: ".", Mode: ModeRelease, Tag: curTag, Previous: prevTag, DenyFile: denyFile(t)},
	}
	for name, o := range cases {
		if _, err := Check(o); err == nil {
			t.Errorf("%s: accepted", name)
		} else if _, ok := err.(*UsageError); !ok {
			t.Errorf("%s: not a usage error: %v", name, err)
		}
	}
}

// ---- generated text ----

func TestReadmeBlockStaleFails(t *testing.T) {
	e := build(t, rig{})
	o := e.opts(ModeUnreleased)
	o.Regenerate = fakeRegen{stale: []string{"README.md"}}
	wantFail(t, check(t, o), CodeReadme, "differs from its regeneration")
}

func TestReadmeMarkerProblemFails(t *testing.T) {
	e := build(t, rig{})
	o := e.opts(ModeUnreleased)
	o.Regenerate = fakeRegen{staleErr: os.ErrInvalid}
	wantFail(t, check(t, o), CodeReadme, "cannot be checked")
}

func TestCountsFileOneByteEditedFails(t *testing.T) {
	e := build(t, rig{})
	o := e.opts(ModeUnreleased)
	raw, err := os.ReadFile(filepath.Join(e.root, releasenotes.CountsPath))
	must(t, err)
	edited := []byte(strings.Replace(string(raw), `"projects": 4`, `"projects": 5`, 1))
	if string(edited) == string(raw) {
		t.Fatal("fixture edit did not apply")
	}
	o.Regenerate = fakeRegen{counts: edited}
	wantFail(t, check(t, o), CodeCounts, "differs from its regeneration")
}

func TestCountsRegenerationErrorFails(t *testing.T) {
	e := build(t, rig{})
	o := e.opts(ModeUnreleased)
	o.Regenerate = fakeRegen{countsErr: os.ErrInvalid}
	wantFail(t, check(t, o), CodeCounts, "cannot be regenerated")
}

func TestCountsUnknownSchemaFails(t *testing.T) {
	// The generator of the fixture cannot read this file either, so the
	// notes cannot be built from it; the check must still refuse it.
	e := build(t, rig{})
	p := filepath.Join(e.root, releasenotes.CountsPath)
	raw, err := os.ReadFile(p)
	must(t, err)
	must(t, os.WriteFile(p, []byte(strings.Replace(string(raw), "prufyx.io/coverage-readme-counts/v1", "prufyx.io/coverage-readme-counts/v9", 1)), 0o644))
	wantFail(t, check(t, e.opts(ModeUnreleased)), CodeCounts, "schema")
}

func TestCountsReadmeBlockShaWrongFails(t *testing.T) {
	e := build(t, rig{})
	p := filepath.Join(e.root, releasenotes.CountsPath)
	raw, err := os.ReadFile(p)
	must(t, err)
	bad := strings.Replace(string(raw), "{\n \"inventoryCounts\"", "{\n \"readmeBlockSha256\": \""+strings.Repeat("0", 64)+"\",\n \"inventoryCounts\"", 1)
	if bad == string(raw) {
		t.Fatal("fixture edit did not apply")
	}
	must(t, os.WriteFile(p, []byte(bad), 0o644))
	wantFail(t, check(t, e.opts(ModeUnreleased)), CodeCounts, "readmeBlockSha256")
}

// ---- notes ----

func TestNotesBlockEditedFails(t *testing.T) {
	e := build(t, rig{notes: replaceIn("| Change |", "| Changed |")})
	wantFail(t, check(t, e.opts(ModeUnreleased)), CodeNotes, "differs from its regeneration")
}

func TestNotesMissingFails(t *testing.T) {
	e := build(t, rig{})
	must(t, os.Remove(filepath.Join(e.root, "cli/docs/release-notes-"+curTag+".md")))
	git(t, e.root, "commit", "-q", "-a", "-m", "rm")
	git(t, e.root, "tag", curTag)
	wantFail(t, check(t, withDeny(t, e.opts(ModeRelease))), CodeNotes, "missing or empty")
}

func TestNotesEmptyFails(t *testing.T) {
	e := build(t, rig{tagCurrent: true, notes: func(string) string { return "  \n" }})
	wantFail(t, check(t, withDeny(t, e.opts(ModeRelease))), CodeNotes, "missing or empty")
}

func TestNotesWithoutMarkersFailsInCIAndRelease(t *testing.T) {
	e := build(t, rig{notes: stripMarkers})
	wantFail(t, check(t, e.opts(ModeUnreleased)), CodeNotes, "")
	e = build(t, rig{tagCurrent: true, notes: stripMarkers})
	wantFail(t, check(t, withDeny(t, e.opts(ModeRelease))), CodeNotes, "")
}

func TestNotesDuplicatedMarkerFails(t *testing.T) {
	e := build(t, rig{notes: func(s string) string { return s + releasenotes.MarkerBegin + "\n" }})
	wantFail(t, check(t, e.opts(ModeUnreleased)), CodeNotes, "two")
}

func TestNotesCountsShaLineChangedFails(t *testing.T) {
	e := build(t, rig{notes: func(s string) string {
		i := strings.Index(s, "counts sha256 `")
		if i < 0 {
			panic("no counts sha line")
		}
		j := i + len("counts sha256 `")
		return s[:j] + strings.Repeat("0", 64) + s[j+64:]
	}})
	wantFail(t, check(t, e.opts(ModeUnreleased)), CodeNotes, "differs from its regeneration")
}

func TestNotesWrongTagInHeadingFails(t *testing.T) {
	e := build(t, rig{notes: replaceIn("# Prufyx "+curTag, "# Prufyx "+prevTag)})
	wantFail(t, check(t, e.opts(ModeUnreleased)), CodeLabels, "first heading")
}

func TestNotesHeadingWithLongerTagFails(t *testing.T) {
	e := build(t, rig{notes: replaceIn("# Prufyx "+curTag, "# Prufyx "+curTag+"0")})
	wantFail(t, check(t, e.opts(ModeUnreleased)), CodeLabels, "first heading")
}

func TestNotesDescribingAnotherTagFails(t *testing.T) {
	e := build(t, rig{notes: replaceIn("to `"+curTag+"`", "to `v1.0.5`")})
	wantFail(t, check(t, e.opts(ModeUnreleased)), CodeLabels, "block describes")
}

func TestNotesCommitLabelMustExistAndBeHistory(t *testing.T) {
	e := build(t, rig{toCommit: "first"})
	wantPass(t, check(t, e.opts(ModeUnreleased)))
	e = build(t, rig{notes: func(s string) string {
		return strings.Replace(s, "to `"+curTag+"`", "to `"+curTag+"` (aaaaaaaaaaaa)", 1)
	}})
	wantFail(t, check(t, e.opts(ModeUnreleased)), CodeLabels, "does not exist")
}

// ---- CHANGELOG ----

func TestChangelogEntryMissingFails(t *testing.T) {
	e := build(t, rig{changelog: replaceIn("## [1.1.0]", "## [1.1.1]")})
	// The entry is then looked for under [Unreleased], where it is not.
	wantFail(t, check(t, e.opts(ModeUnreleased)), CodeChangelog, "[Unreleased]")
	e = build(t, rig{tagCurrent: true, changelog: replaceIn("## [1.1.0]", "## [1.1.1]")})
	wantFail(t, check(t, withDeny(t, e.opts(ModeRelease))), CodeChangelog, "[1.1.0]")
}

func TestChangelogDuplicateEntryFails(t *testing.T) {
	e := build(t, rig{changelog: func(s string) string { return s + "\n## [1.1.0] - 2026-01-02\n\ntext\n" }})
	wantFail(t, check(t, e.opts(ModeUnreleased)), CodeChangelog, "exactly one")
}

func TestChangelogBlockEditedFails(t *testing.T) {
	e := build(t, rig{changelog: replaceIn("| Change |", "| Changed |")})
	wantFail(t, check(t, e.opts(ModeUnreleased)), CodeChangelog, "differs from its regeneration")
}

func TestChangelogBlockWithoutMarkersFails(t *testing.T) {
	e := build(t, rig{changelog: func(s string) string {
		i := strings.Index(s, "## [1.1.0]")
		return s[:i] + stripMarkers(s[i:])
	}})
	wantFail(t, check(t, e.opts(ModeUnreleased)), CodeChangelog, "")
}

func TestChangelogStaleLabelFails(t *testing.T) {
	e := build(t, rig{changelog: func(s string) string {
		i := strings.Index(s, "## [1.1.0]")
		return s[:i] + strings.Replace(s[i:], "to `"+curTag+"`", "to `"+prevTag+"`", 1)
	}})
	wantFail(t, check(t, e.opts(ModeUnreleased)), CodeChangelog, "differs from its regeneration")
}

// ---- previous ----

func TestPreviousProblemsFail(t *testing.T) {
	e := build(t, rig{tagCurrent: true})
	o := withDeny(t, e.opts(ModeRelease))
	o.Previous = "v0.9.0"
	wantFail(t, check(t, o), CodePrevious, "compares against")

	// The notes name a previous tag that does not exist.
	e = build(t, rig{tagCurrent: true, notes: replaceIn("Changes from `"+prevTag+"`", "Changes from `v0.9.0`")})
	o = withDeny(t, e.opts(ModeRelease))
	o.Previous = "v0.9.0"
	wantFail(t, check(t, o), CodePrevious, "does not resolve")
}

func TestPreviousNotLowerFails(t *testing.T) {
	e := build(t, rig{})
	g := &checker{o: Options{Mode: ModeUnreleased}, root: e.root}
	for _, prev := range []string{curTag, "v2.0.0"} {
		if _, _, ok := g.render("x", curTag, prev, ""); ok {
			t.Fatalf("previous %s accepted", prev)
		}
	}
	wantFail(t, Result{Findings: g.res.Findings}, CodePrevious, "not strictly lower")
}

func TestPreviousNotAncestorFails(t *testing.T) {
	e := build(t, rig{})
	git(t, e.root, "checkout", "-q", "--orphan", "side")
	write(t, e.root, "side.txt", "x")
	git(t, e.root, "add", "-A")
	git(t, e.root, "commit", "-q", "-m", "side")
	git(t, e.root, "tag", "v0.5.0")
	git(t, e.root, "checkout", "-q", "-f", "main")
	g := &checker{o: Options{Mode: ModeUnreleased}, root: e.root}
	if _, _, ok := g.render("x", curTag, "v0.5.0", ""); ok {
		t.Fatal("a previous tag that is not an ancestor was accepted")
	}
	wantFail(t, Result{Findings: g.res.Findings}, CodePrevious, "not an ancestor")
}

func TestBootstrapPreviousPinnedByCode(t *testing.T) {
	// A previous release of the bootstrap name reads the bootstrap counts
	// file of the tree under check and compares it with the code constant.
	e := build(t, rig{})
	git(t, e.root, "tag", releasenotes.BootstrapTag, "HEAD~2")
	write(t, e.root, releasenotes.BootstrapCountsPath, "{}")
	g := &checker{o: Options{Mode: ModeUnreleased}, root: e.root}
	if _, _, ok := g.render("x", curTag, releasenotes.BootstrapTag, ""); ok {
		t.Fatal("bootstrap counts with the wrong bytes accepted")
	}
	wantFail(t, Result{Findings: g.res.Findings}, CodePrevious, "pin")

	real, err := os.ReadFile("../../../docs/generated/coverage-counts-v0.1.0-beta.0.json")
	if err != nil {
		t.Skip("no bootstrap counts file in this tree")
	}
	write(t, e.root, releasenotes.BootstrapCountsPath, string(real))
	g = &checker{o: Options{Mode: ModeUnreleased}, root: e.root}
	if _, _, ok := g.render("x", curTag, releasenotes.BootstrapTag, ""); !ok {
		t.Fatalf("the pinned bootstrap counts were refused: %+v", g.res.Findings)
	}
}

// ---- tag binding ----

func TestTagBindingFails(t *testing.T) {
	e := build(t, rig{tagCurrent: true})
	o := withDeny(t, e.opts(ModeRelease))

	missing := o
	missing.Tag = "v1.2.0"
	wantFail(t, check(t, missing), CodeTag, "does not resolve")

	badGrammar := o
	badGrammar.Tag = "1.1.0"
	wantFail(t, check(t, badGrammar), CodeTag, "semantic version")

	// The checkout is not the tagged commit.
	git(t, e.root, "checkout", "-q", "HEAD~1")
	wantFail(t, check(t, o), CodeTag, "not the commit of tag")
	git(t, e.root, "checkout", "-q", "main")

	// A modified tracked file.
	write(t, e.root, "README.md", "changed\n")
	wantFail(t, check(t, o), CodeTag, "modified tracked files")
}

// ---- site counts ----

func TestSiteCountsMustEqualCommittedBytes(t *testing.T) {
	e := build(t, rig{tagCurrent: true})
	site := filepath.Join(t.TempDir(), "site.json")
	raw, err := os.ReadFile(filepath.Join(e.root, releasenotes.CountsPath))
	must(t, err)
	must(t, os.WriteFile(site, append(append([]byte{}, raw...), '\n'), 0o600))
	o := withDeny(t, e.opts(ModeCut))
	o.SiteCounts = site
	wantFail(t, check(t, o), CodeSite, "byte for byte")

	must(t, os.WriteFile(site, raw, 0o600))
	wantPass(t, check(t, o))

	// A missing file fails, and release mode does not need one.
	o.SiteCounts = filepath.Join(t.TempDir(), "absent.json")
	wantFail(t, check(t, o), CodeSite, "site counts")
	o.Mode, o.SiteCounts = ModeRelease, ""
	wantPass(t, check(t, o))
}

// ---- README status line (release) ----

func TestReadmeStatusMustNameTheTag(t *testing.T) {
	e := build(t, rig{tagCurrent: true, readme: replaceIn("`"+curTag+"` release", "`"+prevTag+"` release")})
	wantFail(t, check(t, withDeny(t, e.opts(ModeRelease))), CodeLabels, "status line")
	e = build(t, rig{tagCurrent: true, readme: replaceIn("> **Status", "> **State")})
	wantFail(t, check(t, withDeny(t, e.opts(ModeRelease))), CodeLabels, "status line")
	// Unreleased mode does not require the README to name an unpublished tag.
	e = build(t, rig{readme: replaceIn("`"+curTag+"` release", "`"+prevTag+"` release")})
	wantPass(t, check(t, e.opts(ModeUnreleased)))
}

// ---- prose numbers (R1) ----

func TestBareIntegersOutsideTheBlockFail(t *testing.T) {
	bad := []string{
		"79 CNCF projects", "decided 77", "49 of 79", "A+B 12", "about 12%", "12.5 projects", "(1234)", "in 2 steps", "v1 and 79",
	}
	for _, text := range bad {
		e := build(t, rig{notes: replaceIn("- one change", "- one change: "+text)})
		wantFail(t, check(t, e.opts(ModeUnreleased)), CodeProse, "outside the generated block")
	}
}

func TestIntegerExceptionsPass(t *testing.T) {
	ok := []string{
		"released as v1.2.3-rc.1+build.5 on 2026-11-17", "release v2 and v1.30", "uses sha256 and k8s and OAuth2", "see v0.1.0-beta.0",
	}
	for _, text := range ok {
		e := build(t, rig{notes: replaceIn("- one change", "- one change: "+text)})
		wantPass(t, check(t, e.opts(ModeUnreleased)))
	}
	e := build(t, rig{notes: replaceIn("- one change", "1. first\n2) second")})
	wantPass(t, check(t, e.opts(ModeUnreleased)))
}

func TestIntegersInsideTheGeneratedBlockAreNotProse(t *testing.T) {
	e := build(t, rig{})
	notes, err := os.ReadFile(filepath.Join(e.root, "cli/docs/release-notes-"+curTag+".md"))
	must(t, err)
	if !strings.ContainsAny(string(notes), "0123456789") {
		t.Fatal("fixture block has no number")
	}
	wantPass(t, check(t, e.opts(ModeUnreleased)))
}

func TestReadmeAndChangelogKeywordLinesAreScanned(t *testing.T) {
	// The lines of the design review, typed by hand in README prose, fail.
	for _, l := range []string{"Prufyx holds 79 projects.", "79 CNCF projects.", "Of these, decided 77.", "49 of 79 are covered.", "Seven percent: 7%."} {
		e := build(t, rig{readme: replaceIn("Tail text.", l)})
		wantFail(t, check(t, e.opts(ModeUnreleased)), CodeProse, "README.md")
	}
	// Outside the markers but without a coverage keyword: not a coverage sentence.
	e := build(t, rig{readme: replaceIn("Tail text.", "Needs Go 126 or newer.")})
	wantPass(t, check(t, e.opts(ModeUnreleased)))
	// The generated README block may carry numbers.
	e = build(t, rig{readme: replaceIn("generated text 5", "projects decided 5")})
	wantPass(t, check(t, e.opts(ModeUnreleased)))
	e = build(t, rig{changelog: replaceIn("- A hand written entry, exits 2 on failure.", "- Decided pairs rose to 45.")})
	wantFail(t, check(t, e.opts(ModeUnreleased)), CodeProse, "CHANGELOG.md")
	// An old release entry is history: not scanned.
	// (A published entry may not change at all, see TestTaggedHistoryMustNotBeRewritten;
	// an entry of an unpublished older version is not scanned.)
	e = build(t, rig{changelog: func(s string) string { return s + "\n## [0.9.0] - 2025-11-01\n\n- Older entry with 99 projects.\n" }})
	wantPass(t, check(t, e.opts(ModeUnreleased)))
}

func TestCoverageKeywordSetIsPinned(t *testing.T) {
	want := []string{"project", "pair", "version", "coverage", "covered", "decided", "catalog", "cncf", "attested", "attestation", "%"}
	if strings.Join(CoverageKeywords, ",") != strings.Join(want, ",") {
		t.Fatalf("keywords = %v", CoverageKeywords)
	}
	// The lines of the design review: every one is a coverage line.
	for _, l := range []string{"79 CNCF projects", "decided 77", "49 of 79 pairs", "12 versions", "5 attested", "about 7%"} {
		if !hasKeyword(l) {
			t.Errorf("%q is not a coverage line", l)
		}
	}
	for _, k := range want {
		if !hasKeyword("A " + strings.ToUpper(k) + "x line") {
			t.Errorf("%s is not matched case-insensitively", k)
		}
	}
	if hasKeyword("Needs Go 126") {
		t.Error("an unrelated line is a coverage sentence")
	}
}

// ---- deny list (R3 and design) ----

func TestDenyPhrasesFailAnywhere(t *testing.T) {
	phrases := []string{
		"production-supported", "Production-Supported", "all CNCF", "full coverage", "fully covered", "complete coverage",
		"The verdict is SAFE", "covers 79 projects", "79 projects covered", "supports 12 projects", "79 CNCF projects covered",
	}
	for _, p := range phrases {
		// The deny list reads generated text too, so a phrase inside the README block counts.
		for name, r := range map[string]rig{
			"notes":     {notes: replaceIn("- one change", "- one change "+p)},
			"readme":    {readme: replaceIn("Tail text.", "Tail "+p+".")},
			"readme in": {readme: replaceIn("generated text 5", "generated "+p)},
			"changelog": {changelog: replaceIn("- A hand written entry, exits 2 on failure.", "- "+p)},
		} {
			e := build(t, r)
			res := check(t, e.opts(ModeUnreleased))
			found := false
			for _, f := range res.Findings {
				if f.Code == CodeDeny {
					found = true
				}
			}
			if !found {
				t.Errorf("%s: %q passed the deny list: %+v", name, p, res.Findings)
			}
		}
	}
}

func TestLabeledProjectCountIsNotDenied(t *testing.T) {
	for _, s := range []string{"covers projects catalogued", "projects covered: attestation-only"} {
		if denyUnlabeled.MatchString(s) {
			t.Errorf("%q matched", s)
		}
	}
	if !hasLabel("5 projects covered (rule-decided)") || hasLabel("5 projects covered") {
		t.Error("label detection is wrong")
	}
	if !denyUnlabeled.MatchString("5 projects covered") || hasLabel("5 projects covered") {
		t.Error("an unlabeled count is not caught")
	}
	for _, s := range []string{"all other projects", "safe to read", "Safe harbor"} {
		if denySafe.MatchString(s) {
			t.Errorf("%q matched SAFE", s)
		}
	}
}

func TestDenyFileNamesAreRefused(t *testing.T) {
	// Synthetic words: the real list is supplied by the release manager.
	e := build(t, rig{notes: replaceIn("- one change", "- one change by Zorblax Labs")})
	o := e.opts(ModeUnreleased)
	o.DenyFile = denyFile(t, "zorblax", "Quuxmodel")
	wantFail(t, check(t, o), CodeDeny, "deny list")

	e = build(t, rig{readme: replaceIn("Tail text.", "Tail quuxmodel.")})
	o = e.opts(ModeUnreleased)
	o.DenyFile = denyFile(t, "zorblax", "quuxmodel")
	wantFail(t, check(t, o), CodeDeny, "deny list")

	// Whole words only.
	e = build(t, rig{notes: replaceIn("- one change", "- one change zorblaxes")})
	o = e.opts(ModeUnreleased)
	o.DenyFile = denyFile(t, "zorblax")
	wantPass(t, check(t, o))
}

func TestNameListSkippedOnlyInUnreleasedAndSaid(t *testing.T) {
	e := build(t, rig{})
	res := check(t, e.opts(ModeUnreleased))
	wantPass(t, res)
	if len(res.Notices) != 1 || !strings.Contains(res.Notices[0], "NOT checked") {
		t.Fatalf("notices = %v", res.Notices)
	}
	o := e.opts(ModeUnreleased)
	o.DenyFile = denyFile(t, "zorblax")
	if res := check(t, o); len(res.Notices) != 0 {
		t.Fatalf("notices with a name list: %v", res.Notices)
	}
}

// ---- positives, codes, determinism ----

func TestPositivePaths(t *testing.T) {
	e := build(t, rig{tagCurrent: true, toCommit: "first"})
	wantPass(t, check(t, e.opts(ModeUnreleased))) // the tag exists: nothing is unpublished
	wantPass(t, check(t, withDeny(t, e.opts(ModeRelease))))

	e = build(t, rig{})
	wantPass(t, check(t, e.opts(ModeUnreleased)))
}

func TestPublishedNotesAreNotRegenerated(t *testing.T) {
	// An old notes file without markers belongs to a published tag: not checked.
	e := build(t, rig{})
	write(t, e.root, "cli/docs/release-notes-"+prevTag+".md", "# Old release "+prevTag+"\n\nno block\n")
	wantPass(t, check(t, e.opts(ModeUnreleased)))
	// An unpublished one without markers fails.
	write(t, e.root, "cli/docs/release-notes-v1.2.0.md", "# Next v1.2.0\n\nno block\n")
	wantFail(t, check(t, e.opts(ModeUnreleased)), CodeNotes, "")
}

func TestNotesFileNameMustBeATag(t *testing.T) {
	e := build(t, rig{})
	write(t, e.root, "cli/docs/release-notes-final.md", "# x\n")
	wantFail(t, check(t, e.opts(ModeUnreleased)), CodeLabels, "release-notes-final.md")
}

func TestExitCodeIsTheLowestClassAndDistinct(t *testing.T) {
	codes := []int{CodeUsage, CodeReadme, CodeCounts, CodeNotes, CodeChangelog, CodeSite, CodePrevious, CodeProse, CodeDeny, CodeLabels, CodeTag}
	seen := map[int]bool{}
	for _, c := range codes {
		if seen[c] || c == 0 || c == 1 {
			t.Fatalf("code %d repeated or reserved", c)
		}
		seen[c] = true
	}
	r := Result{Findings: []Finding{{Code: CodeProse}, {Code: CodeReadme}}}
	if r.ExitCode() != CodeReadme {
		t.Fatal("not the lowest class")
	}
}

func TestDeterministic(t *testing.T) {
	e := build(t, rig{notes: replaceIn("- one change", "- one change 79 projects, full coverage")})
	a := check(t, e.opts(ModeUnreleased))
	b := check(t, e.opts(ModeUnreleased))
	if len(a.Findings) == 0 || len(a.Findings) != len(b.Findings) {
		t.Fatal("findings differ between runs")
	}
	for i := range a.Findings {
		if a.Findings[i] != b.Findings[i] {
			t.Fatalf("finding %d differs", i)
		}
	}
}

func TestSemverCompare(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"v0.1.0-beta.0", "v0.1.0-beta.1", -1}, {"v0.1.0-beta.1", "v0.1.0-beta.1", 0}, {"v0.1.0-beta.2", "v0.1.0-beta.10", -1},
		{"v0.1.0-beta.1", "v0.1.0", -1}, {"v0.1.0", "v0.1.0-rc.1", 1}, {"v1.0.0", "v0.9.9", 1}, {"v1.0.0-1", "v1.0.0-a", -1},
		{"v1.0.0-a", "v1.0.0-a.1", -1},
	}
	for _, c := range cases {
		got, err := semverCompare(c.a, c.b)
		if err != nil || got != c.want {
			t.Errorf("%s ? %s = %d, %v; want %d", c.a, c.b, got, err, c.want)
		}
	}
	if _, err := semverCompare("1.0.0", "v1.0.0"); err == nil {
		t.Error("a version without the v accepted")
	}
}

func TestLooseExceptionsOnlyForReadmeAndChangelogLines(t *testing.T) {
	loose := []string{
		"Kubernetes 1.25 and 1.30.", "(exit 10) and exits 2", "exit `0`", "needs 128 GB of memory", "run `tool get 5 things`",
		"in beta.0 and rc.1",
	}
	for _, l := range loose {
		if n := bareIntegers(l, true); len(n) != 0 {
			t.Errorf("loose %q flagged %v", l, n)
		}
	}
	// A bare number, a percentage and a count claim are never excepted.
	for _, l := range []string{"79 projects", "decided 77", "1.30% of projects", "`79` projects", "49 of 79", "exit 10 and 79 pairs"} {
		if n := bareIntegers(l, true); len(n) == 0 {
			t.Errorf("loose %q passed", l)
		}
	}
	// The notes are strict: no dotted version, no exit code, no unit.
	for _, l := range []string{"Kubernetes 1.25", "exits 2", "128 GB"} {
		if n := bareIntegers(l, false); len(n) == 0 {
			t.Errorf("strict %q passed", l)
		}
	}
}

func TestReadmeFencedCodeAndGeneratedRegionsAreNotProse(t *testing.T) {
	e := build(t, rig{readme: replaceIn("Tail text.", "```\n79 projects covered by version 5\n```\n")})
	res := check(t, e.opts(ModeUnreleased))
	for _, f := range res.Findings {
		if f.Code == CodeProse {
			t.Fatalf("a fenced example is prose: %+v", f)
		}
	}
	// The other generated regions of the README are exempt too, and the
	// text between them is scanned.
	e = build(t, rig{readme: replaceIn("Tail text.", coveragereport.READMECRDBegin+"\n87 projects decided\n"+coveragereport.READMECRDEnd+"\n42 projects hand typed\n")})
	res = check(t, e.opts(ModeUnreleased))
	wantFail(t, res, CodeProse, "(42)")
}

func readFile(t *testing.T, root, rel string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(rel)))
	must(t, err)
	return string(b)
}

func osSymlink(root, target, link string) error {
	return os.Symlink(target, filepath.Join(root, link))
}

func siteCopy(t *testing.T, e env) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "site.json")
	must(t, os.WriteFile(p, []byte(readFile(t, e.root, releasenotes.CountsPath)), 0o600))
	return p
}
