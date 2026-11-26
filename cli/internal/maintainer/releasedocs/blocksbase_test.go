// SPDX-License-Identifier: AGPL-3.0-only

package releasedocs

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/maintainer/releasenotes"
)

const (
	notesFile = "cli/docs/release-notes-" + curTag + ".md"
	sectionAt = "## [1.1.0]"
	inventory = "cli/docs/generated/community-support-inventory.json"
)

func read(t *testing.T, root, rel string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(rel)))
	must(t, err)
	return string(b)
}

func commitAll(t *testing.T, root, msg string) string {
	t.Helper()
	git(t, root, "add", "-A")
	git(t, root, "commit", "-q", "--allow-empty", "-m", msg)
	return git(t, root, "rev-parse", "HEAD")
}

// moveData changes the counts of the tree, as a data batch does, so that the
// committed blocks no longer equal their regeneration.
func moveData(t *testing.T, root string) {
	t.Helper()
	write(t, root, releasenotes.CountsPath, fixture(t, "counts-prev.json"))
}

// staleRig returns a repository whose base commit is current and whose HEAD
// changed the data only.
func staleRig(t *testing.T) (env, string) {
	t.Helper()
	e := build(t, rig{})
	base := git(t, e.root, "rev-parse", "HEAD")
	moveData(t, e.root)
	commitAll(t, e.root, "data only")
	return e, base
}

func (e env) withBase(base string) Options {
	o := e.opts(ModeUnreleased)
	o.BlocksBase = base
	return o
}

// editSectionBlock edits the 1.1.0 CHANGELOG entry.
func editSectionBlock(t *testing.T, root string, edit func(string) string) {
	t.Helper()
	doc := read(t, root, changelogPath)
	i := strings.Index(doc, sectionAt)
	if i < 0 {
		t.Fatal("no section")
	}
	write(t, root, changelogPath, doc[:i]+edit(doc[i:]))
}

func stale(res Result) int {
	n := 0
	for _, s := range res.Notices {
		if strings.Contains(s, "STALE") {
			n++
		}
	}
	return n
}

func wantBothStale(t *testing.T, res Result) {
	t.Helper()
	wantFail(t, res, CodeNotes, "differs from its regeneration")
	wantFail(t, res, CodeChangelog, "differs from its regeneration")
}

func TestStaleBlocksEqualToTheBaseAreAcceptedAndPrinted(t *testing.T) {
	e, base := staleRig(t)
	res := check(t, e.withBase(base))
	wantPass(t, res)
	if stale(res) != 2 {
		t.Fatalf("want two stale notices: %v", res.Notices)
	}
}

func TestStaleBlocksWithoutABaseFail(t *testing.T) {
	e, _ := staleRig(t)
	wantBothStale(t, check(t, e.opts(ModeUnreleased)))
}

func TestCurrentBlocksPassWithABaseAndPrintNothingStale(t *testing.T) {
	e := build(t, rig{})
	base := git(t, e.root, "rev-parse", "HEAD")
	commitAll(t, e.root, "next")
	res := check(t, e.withBase(base))
	wantPass(t, res)
	if stale(res) != 0 {
		t.Fatalf("unexpected notices: %v", res.Notices)
	}
}

func TestRegeneratedBlocksPassAgainstABaseThatDiffers(t *testing.T) {
	e := build(t, rig{})
	good := read(t, e.root, notesFile)
	write(t, e.root, notesFile, replaceIn("| Change |", "| Other |")(good))
	base := commitAll(t, e.root, "base")
	write(t, e.root, notesFile, good)
	commitAll(t, e.root, "regenerate")
	res := check(t, e.withBase(base))
	wantPass(t, res)
	if stale(res) != 0 {
		t.Fatalf("unexpected notices: %v", res.Notices)
	}
}

func TestOneByteEditOfEitherStaleBlockFails(t *testing.T) {
	e, base := staleRig(t)
	write(t, e.root, notesFile, replaceIn("| Change |", "| Changed |")(read(t, e.root, notesFile)))
	wantFail(t, check(t, e.withBase(base)), CodeNotes, "differs from its regeneration")

	e, base = staleRig(t)
	editSectionBlock(t, e.root, replaceIn("| Change |", "| Changed |"))
	wantFail(t, check(t, e.withBase(base)), CodeChangelog, "differs from its regeneration")

	e, base = staleRig(t)
	write(t, e.root, notesFile, replaceIn(releasenotes.MarkerEnd, "\n"+releasenotes.MarkerEnd)(read(t, e.root, notesFile)))
	wantFail(t, check(t, e.withBase(base)), CodeNotes, "differs from its regeneration")

	e, base = staleRig(t)
	editSectionBlock(t, e.root, replaceIn("| Change |", "| Change |\r"))
	wantFail(t, check(t, e.withBase(base)), CodeChangelog, "differs from its regeneration")
}

func TestABlockOfAnOlderCommitThatIsNotTheBaseFails(t *testing.T) {
	e := build(t, rig{})
	older := read(t, e.root, notesFile)
	write(t, e.root, notesFile, replaceIn("| Change |", "| Newer |")(older))
	base := commitAll(t, e.root, "base")
	write(t, e.root, notesFile, older)
	moveData(t, e.root)
	commitAll(t, e.root, "back to the older block")
	wantFail(t, check(t, e.withBase(base)), CodeNotes, "differs from its regeneration")
}

func TestUnusableBaseIsRefused(t *testing.T) {
	e, base := staleRig(t)
	head := git(t, e.root, "rev-parse", "HEAD")
	side := git(t, e.root, "commit-tree", base+"^{tree}", "-p", base, "-m", "side")
	tree := git(t, e.root, "rev-parse", base+"^{tree}")
	for name, b := range map[string]string{
		"unknown": strings.Repeat("1", 40), "HEAD": head, "not an ancestor": side, "tree": tree,
	} {
		t.Run(name, func(t *testing.T) {
			res := check(t, e.withBase(b))
			wantFail(t, res, CodeBase, "cannot be used")
			wantBothStale(t, res)
		})
	}
}

func TestAnUnusableBaseFailsEvenWithCurrentBlocks(t *testing.T) {
	e := build(t, rig{})
	res := check(t, e.withBase(strings.Repeat("1", 40)))
	wantFail(t, res, CodeBase, "cannot be used")
	if res.ExitCode() != CodeBase {
		t.Fatalf("exit %d", res.ExitCode())
	}
}

func TestShallowCloneGivesNoBaseAllowance(t *testing.T) {
	e, base := staleRig(t)
	clone := filepath.Join(t.TempDir(), "c")
	git(t, e.root, "clone", "-q", "--depth", "2", "file://"+e.root, clone)
	wantFail(t, check(t, env{root: clone}.withBase(base)), CodeBase, "shallow")
}

func TestARootBelowTheTopLevelGivesNoBaseAllowance(t *testing.T) {
	e, base := staleRig(t)
	o := e.withBase(base)
	o.Root = filepath.Join(e.root, "cli")
	wantFail(t, check(t, o), CodeBase, "top level")
}

func TestMalformedBaseAndOtherModesAreUsageErrors(t *testing.T) {
	e, base := staleRig(t)
	for _, b := range []string{zeroCommit, base[:12], "HEAD", "HEAD^1", strings.Repeat("A", 40), base + " ", "-" + base[1:]} {
		if _, err := Check(e.withBase(b)); err == nil {
			t.Errorf("base %q accepted", b)
		}
	}
	for _, mode := range []string{ModeRelease, ModeCut} {
		o := withDeny(t, e.opts(mode))
		o.SiteCounts = "x"
		o.BlocksBase = base
		if _, err := Check(o); err == nil {
			t.Errorf("%s accepted a blocks base", mode)
		}
	}
}

func TestStaleBlocksFailReleaseAndCutModes(t *testing.T) {
	e := build(t, rig{})
	moveData(t, e.root)
	commitAll(t, e.root, "data only")
	git(t, e.root, "tag", curTag)
	for _, mode := range []string{ModeRelease, ModeCut} {
		o := withDeny(t, e.opts(mode))
		if mode == ModeCut {
			o.SiteCounts = filepath.Join(e.root, filepath.FromSlash(releasenotes.CountsPath))
		}
		wantBothStale(t, check(t, o))
	}
}

func TestANewNotesFileMustEqualRegeneration(t *testing.T) {
	e := build(t, rig{})
	notes := read(t, e.root, notesFile)
	must(t, os.Remove(filepath.Join(e.root, filepath.FromSlash(notesFile))))
	// The base has the CHANGELOG entry but not the notes file, so neither
	// block may be taken from it.
	base := commitAll(t, e.root, "no notes yet")
	write(t, e.root, notesFile, notes)
	moveData(t, e.root)
	commitAll(t, e.root, "add stale notes")
	wantBothStale(t, check(t, e.withBase(base)))
}

func TestANewOrRenamedSectionMustEqualRegeneration(t *testing.T) {
	e := build(t, rig{})
	changelog := read(t, e.root, changelogPath)
	write(t, e.root, changelogPath, replaceIn(sectionAt, "## [next]")(changelog))
	base := commitAll(t, e.root, "before the rename")
	write(t, e.root, changelogPath, changelog)
	moveData(t, e.root)
	commitAll(t, e.root, "rename")
	wantBothStale(t, check(t, e.withBase(base)))
}

func TestABaseWithoutAUsableBlockGivesNoAllowance(t *testing.T) {
	for name, breakBase := range map[string]func(string) string{
		"no markers":  stripMarkers,
		"two markers": func(s string) string { return s + releasenotes.MarkerBegin + "\n" },
	} {
		t.Run(name, func(t *testing.T) {
			e := build(t, rig{})
			write(t, e.root, notesFile, breakBase(read(t, e.root, notesFile)))
			base := commitAll(t, e.root, "broken base")
			moveData(t, e.root)
			commitAll(t, e.root, "data")
			// The notes file is unchanged from the base, and still refused.
			res := check(t, e.withBase(base))
			if res.ExitCode() == 0 || stale(res) != 0 {
				t.Fatalf("accepted from a broken base: %+v", res)
			}
			wantFail(t, res, CodeChangelog, "differs from its regeneration")
		})
	}
	t.Run("empty block", func(t *testing.T) {
		e := build(t, rig{})
		editSectionBlock(t, e.root, func(s string) string {
			u, err := releasenotes.ReplaceBlock(s, "")
			if err != nil {
				t.Fatal(err)
			}
			return u
		})
		base := commitAll(t, e.root, "empty entry block")
		moveData(t, e.root)
		commitAll(t, e.root, "data")
		// Neither block may be taken from such a base.
		res := check(t, e.withBase(base))
		wantBothStale(t, res)
		if stale(res) != 0 {
			t.Fatalf("accepted from a base with an empty block: %+v", res)
		}
	})
}

func TestAnExecutableOrLinkedBaseFileIsRefused(t *testing.T) {
	for name, change := range map[string]func(t *testing.T, path string){
		"executable": func(t *testing.T, p string) { must(t, os.Chmod(p, 0o755)) },
		"symlink": func(t *testing.T, p string) {
			must(t, os.Remove(p))
			must(t, os.Symlink("elsewhere", p))
		},
	} {
		t.Run(name, func(t *testing.T) {
			e := build(t, rig{})
			p := filepath.Join(e.root, filepath.FromSlash(notesFile))
			good := read(t, e.root, notesFile)
			change(t, p)
			base := commitAll(t, e.root, "odd base")
			must(t, os.Remove(p))
			write(t, e.root, notesFile, good)
			moveData(t, e.root)
			commitAll(t, e.root, "data")
			res := check(t, e.withBase(base))
			wantFail(t, res, CodeBase, "not a regular file")
			wantBothStale(t, res)
		})
	}
}

func TestBrokenHeadMarkersFailWithABase(t *testing.T) {
	for name, edit := range map[string]func(string) string{
		"missing":    stripMarkers,
		"duplicated": func(s string) string { return s + releasenotes.MarkerBegin + "\n" },
		"moved":      replaceIn("| Change |", releasenotes.MarkerEnd+"\n| Change |"),
	} {
		t.Run(name, func(t *testing.T) {
			e, base := staleRig(t)
			write(t, e.root, notesFile, edit(read(t, e.root, notesFile)))
			wantFail(t, check(t, e.withBase(base)), CodeNotes, "")
		})
	}
}

func TestOtherChecksStayWithStaleBlocks(t *testing.T) {
	e, base := staleRig(t)
	o := e.withBase(base)
	o.Regenerate = fakeRegen{counts: []byte("{}\n")}
	wantFail(t, check(t, o), CodeCounts, "differs from its regeneration")
	o.Regenerate = fakeRegen{stale: []string{readmePath}}
	wantFail(t, check(t, o), CodeReadme, "differs")

	write(t, e.root, notesFile, read(t, e.root, notesFile)+"\nWe cover 42 things. Full coverage.\n")
	res := check(t, e.withBase(base))
	wantFail(t, res, CodeProse, "42")
	wantFail(t, res, CodeDeny, "full coverage")
}

func TestReplaceRefsDoNotChangeTheBase(t *testing.T) {
	e, base := staleRig(t)
	write(t, e.root, notesFile, replaceIn("| Change |", "| Changed |")(read(t, e.root, notesFile)))
	head := commitAll(t, e.root, "edit the block")
	// A replace ref makes plain git show the edited tree as the base.
	fake := git(t, e.root, "commit-tree", head+"^{tree}", "-p", base+"^", "-m", "fake base")
	git(t, e.root, "replace", base, fake)
	if got := git(t, e.root, "show", base+":"+notesFile); !strings.Contains(got, "| Changed |") {
		t.Fatal("the replace ref is not in effect")
	}
	res := check(t, e.withBase(base))
	wantFail(t, res, CodeNotes, "differs from its regeneration")
}

func TestGitEnvDropsInheritedSettings(t *testing.T) {
	got := strings.Join(GitEnv([]string{"PATH=/bin", "GIT_DIR=/x", "GIT_NO_REPLACE_OBJECTS=0", "GIT_CONFIG_COUNT=1", "HOME=/h"}), "\n")
	want := "PATH=/bin\nHOME=/h\nGIT_CONFIG_NOSYSTEM=1\nGIT_CONFIG_GLOBAL=" + os.DevNull + "\nGIT_NO_REPLACE_OBJECTS=1\nGIT_GRAFT_FILE=" + os.DevNull
	if got != want {
		t.Fatalf("got:\n%s", got)
	}
}

func TestGuardBlockRefusesEveryToken(t *testing.T) {
	for _, bad := range []string{
		"a <!-- b", "[x](y)", "<b>", "a\rb", "a\tb", "a\x00b", "a\x1bb", "a\u0085b",
		"a​b", "a‮b", "a b", "a b", "## [9.9.9]", "x\n## heading", "x\n  ## heading", "a\xffb",
	} {
		if guardBlock(bad) == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	for _, good := range []string{"### Summary\n\n| A | B |\n| --- | --- |\n\n#### x\n- `id` (Name): a > b, [x] (y) — é", ""} {
		if err := guardBlock(good); err != nil {
			t.Errorf("%q refused: %v", good, err)
		}
	}
}

type keepGen struct{}

func (keepGen) Blocks(string) ([]string, error) { return nil, nil }
func (keepGen) Counts(root string) ([]byte, error) {
	return os.ReadFile(filepath.Join(root, filepath.FromSlash(releasenotes.CountsPath)))
}

// A hostile data string that reaches the block is refused by the check, also
// when the committed block is stale and equal to the base, and by regen.
func TestHostileDataStringsAreRefusedByCheckAndRegen(t *testing.T) {
	for _, name := range []string{"x <!-- y", "[x](y)", "<img>", `x\n## [9.9.9]`, `x‮y`} {
		t.Run(name, func(t *testing.T) {
			e := build(t, rig{})
			base := git(t, e.root, "rev-parse", "HEAD")
			write(t, e.root, inventory, `{"projects":[{"projectID":"p","displayName":"`+name+`"}]}`+"\n")
			commitAll(t, e.root, "hostile data")
			wantFail(t, check(t, e.opts(ModeUnreleased)), CodeNotes, "rendered block is refused")
			wantFail(t, check(t, e.withBase(base)), CodeNotes, "rendered block is refused")
			before := read(t, e.root, notesFile)
			if _, err := Regen(RegenOptions{Root: e.root, Mode: ModeUnreleased, ReleaseBlocks: true, Generate: keepGen{}}); err == nil || !strings.Contains(err.Error(), "rendered block is refused") {
				t.Fatalf("regen: %v", err)
			}
			if read(t, e.root, notesFile) != before {
				t.Fatal("regen wrote the refused block")
			}
		})
	}
}

// The CI step takes the base of each event and nothing else.
func TestCIStepPassesTheBaseOfItsEvent(t *testing.T) {
	raw, err := os.ReadFile("../../../../.github/workflows/ci.yml")
	must(t, err)
	_, rest, ok := strings.Cut(string(raw), "      - name: Check release docs\n")
	if !ok {
		t.Fatal("no step")
	}
	rest, _, ok = strings.Cut(rest, "\n      - name: ")
	if !ok {
		t.Fatal("no next step")
	}
	for _, line := range []string{
		"EVENT: ${{ github.event_name }}",
		"PR_BASE: ${{ github.event.pull_request.base.sha }}",
		"GROUP_BASE: ${{ github.event.merge_group.base_sha }}",
		"PUSH_BEFORE: ${{ github.event.before }}",
	} {
		if !strings.Contains(rest, "          "+line+"\n") {
			t.Errorf("the step lacks %q", line)
		}
	}
	_, script, ok := strings.Cut(rest, "        run: |\n")
	if !ok {
		t.Fatal("no run block")
	}
	if strings.Contains(script, "${{") {
		t.Error("an expression is expanded inside the script")
	}
	a, b, c, parent := strings.Repeat("a", 40), strings.Repeat("b", 40), strings.Repeat("c", 40), strings.Repeat("d", 40)
	run := func(event string, vars ...string) (string, error) {
		stub := "go() { printf 'ARGS %s\\n' \"$*\"; }\ngit() { [ \"$*\" = 'rev-parse --verify HEAD^1^{commit}' ] && echo " + parent + "; }\n"
		cmd := exec.Command("bash", "-c", stub+script)
		cmd.Env = append([]string{"PATH=" + os.Getenv("PATH"), "EVENT=" + event, "DENY_NAMES=", "RUNNER_TEMP=" + t.TempDir()}, vars...)
		out, err := cmd.CombinedOutput()
		return string(out), err
	}
	all := []string{"PR_BASE=" + a, "GROUP_BASE=" + b, "PUSH_BEFORE=" + c}
	for event, want := range map[string]string{"pull_request": a, "merge_group": b, "push": c, "schedule": parent} {
		out, err := run(event, all...)
		if err != nil || !strings.Contains(out, "release-docs check --root .. --mode unreleased --blocks-base "+want) {
			t.Errorf("%s: %v %s", event, err, out)
		}
	}
	for _, event := range []string{"pull_request", "merge_group", "push"} {
		for _, bad := range []string{"", "HEAD", a[:12], a + " --mode x"} {
			out, err := run(event, "PR_BASE="+bad, "GROUP_BASE="+bad, "PUSH_BEFORE="+bad)
			if err == nil || strings.Contains(out, "ARGS") {
				t.Errorf("%s with base %q ran the check: %s", event, bad, out)
			}
		}
	}
	if out, err := run("pull_request_target", all...); err == nil || strings.Contains(out, "ARGS") {
		t.Errorf("an unknown event ran the check: %s", out)
	}

	// A manual run takes its base from the history, so it runs real git.
	dispatch := func(dir string) (string, error) {
		cmd := exec.Command("bash", "-c", "go() { printf 'ARGS %s\\n' \"$*\"; }\n"+script)
		cmd.Dir = dir
		cmd.Env = append(GitEnv(os.Environ()), "EVENT=workflow_dispatch", "DENY_NAMES=", "RUNNER_TEMP="+t.TempDir())
		out, err := cmd.CombinedOutput()
		return string(out), err
	}
	repo := t.TempDir()
	git(t, repo, "init", "-q")
	commit := func(msg string, parents ...string) string {
		args := []string{"commit-tree", git(t, repo, "write-tree"), "-m", msg}
		for _, p := range parents {
			args = append(args, "-p", p)
		}
		return git(t, repo, args...)
	}
	at := func(head, main string) {
		git(t, repo, "update-ref", "--no-deref", "HEAD", head)
		git(t, repo, "update-ref", "refs/remotes/origin/main", main)
	}
	wantBase := func(name, want string) {
		t.Helper()
		out, err := dispatch(repo)
		if err != nil || !strings.Contains(out, "--blocks-base "+want+"\n") {
			t.Errorf("%s: want base %s: %v %s", name, want, err, out)
		}
	}
	wantRefused := func(name string) {
		t.Helper()
		out, err := dispatch(repo)
		if err == nil || strings.Contains(out, "ARGS") {
			t.Errorf("%s ran the check: %s", name, out)
		}
	}
	root := commit("root")
	fork := commit("fork", root)
	tip := commit("main moved", fork)
	edit := commit("hand edit", fork)
	later := commit("any later commit", edit)
	at(later, tip)
	wantBase("a branch with two commits", fork)
	at(tip, tip)
	wantBase("the tip of main", fork)
	at(fork, tip)
	wantBase("an older commit of main", root)
	at(root, tip)
	wantRefused("the root commit of main")
	at(later, commit("unrelated"))
	wantRefused("a branch unrelated to main")
	left, right := commit("left", fork), commit("right", fork)
	at(commit("cross one", left, right), commit("cross two", right, left))
	wantRefused("a branch with two merge bases")
	git(t, repo, "update-ref", "-d", "refs/remotes/origin/main")
	// A local branch of the same short name is not main.
	git(t, repo, "update-ref", "refs/heads/origin/main", fork)
	wantRefused("a clone without origin/main")
}
