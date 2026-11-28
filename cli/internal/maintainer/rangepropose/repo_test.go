// SPDX-License-Identifier: AGPL-3.0-only

package rangepropose

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
)

func standardRule(f *fixture) map[string]any {
	return rule("flag-removed", "1.4.1", "1.5.0", f.both())
}

func without(releases []release, tag string) []release {
	var out []release
	for _, r := range releases {
		if r.tag != tag {
			out = append(out, r)
		}
	}
	return out
}

func TestIncompleteTagLinesAreRefused(t *testing.T) {
	longer := append(standard(), release{"v1.5.2", files{"flags.go": newCode}})
	for name, tc := range map[string]struct {
		releases []release
		code     string
	}{
		"patch gap":        {without(longer, "v1.5.1"), CodeTagGap},
		"no first release": {without(standard(), "v1.4.0"), CodeTagGap},
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, tc.releases)
			wantRefused(t, run(t, options(t, f.bare(), standardRule(f))), tc.code)
		})
	}
}

func TestAnUnrecognisedTagNamingALineIsRefused(t *testing.T) {
	f := newFixture(t, standard())
	for _, name := range []string{"v1.5.2-1", "v1.5.2-ce.1", "v1.5.2+build", "v1.5.2.post1", "1.5.2", "api/v1.5.2", "v1_5_2",
		"v1.5.2rc1", "v1.05.2", "v1-5-2", "release-1.5", "v1.5.2-rc.1-hotfix", "app-2-1.5.2", "api-v2-1.5.2", "k8s_1.28_1.5.2"} {
		t.Run(strings.ReplaceAll(name, "/", " "), func(t *testing.T) {
			clone := f.bare()
			git(t, clone, "tag", name, f.commits["v1.5.1"])
			no := wantRefused(t, run(t, options(t, clone, standardRule(f))), CodeTagUnrecognised)
			if !strings.Contains(no.Detail, name) {
				t.Fatalf("detail: %s", no.Detail)
			}
		})
	}
}

func TestPreReleasesAndOtherLinesAreIgnored(t *testing.T) {
	f := newFixture(t, standard())
	// Final releases of other lines need their own commit.
	other := f.commit("other", files{"flags.go": oldCode})
	clone := f.bare()
	for _, name := range []string{"v1.5.0-rc.1", "v1.5.2-alpha.0", "v1.4.0-beta2", "v11.5.0", "v2.1.5", "v1.50.1-1", "nightly"} {
		git(t, clone, "tag", name, other)
	}
	p := wantProposal(t, run(t, options(t, clone, standardRule(f))))
	if p.TagSets[0].TagCount != 3 || p.TagSets[1].TagCount != 2 {
		t.Fatalf("tag sets: %+v", p.TagSets)
	}
}

func TestExpectedTagListMustEqualTheClone(t *testing.T) {
	f := newFixture(t, standard())
	clone := f.bare()
	list := func() []ExpectedTag {
		var out []ExpectedTag
		for _, r := range standard() {
			out = append(out, ExpectedTag{r.tag, f.commits[r.tag]})
		}
		return out
	}
	with := func(tags []ExpectedTag) Options {
		o := options(t, clone, standardRule(f))
		p := o.Config.Projects["demo"]
		p.Tags = &tags
		o.Config.Projects["demo"] = p
		return o
	}
	if p := wantProposal(t, run(t, with(list()))); !p.TagSets[0].ExpectedListGiven {
		t.Fatal("the expected list is not recorded")
	}
	// The list leaves out the highest patch of a line.
	wantRefused(t, run(t, with(list()[:4])), CodeTagUnlisted)
	wantRefused(t, run(t, with([]ExpectedTag{})), CodeTagUnlisted)
	wantRefused(t, run(t, with(append(list(), ExpectedTag{"v1.5.2", f.commits["v1.5.1"]}))), CodeTagMissing)
	moved := list()
	moved[4].Commit = f.commits["v1.5.0"]
	wantRefused(t, run(t, with(moved)), CodeTagMoved)
	// A list never excuses a gap.
	gap := newFixture(t, append(standard(), release{"v1.5.3", files{"flags.go": newCode}}))
	tags := []ExpectedTag{}
	for tag, commit := range gap.commits {
		tags = append(tags, ExpectedTag{tag, commit})
	}
	o := options(t, gap.bare(), standardRule(gap))
	p := o.Config.Projects["demo"]
	p.Tags = &tags
	o.Config.Projects["demo"] = p
	wantRefused(t, run(t, o), CodeTagGap)
}

func TestTagCommitRules(t *testing.T) {
	f := newFixture(t, standard())
	shared := f.bare()
	git(t, shared, "tag", "v1.6.0", f.commits["v1.5.1"])
	wantRefused(t, run(t, options(t, shared, standardRule(f))), CodeCommitOnTwoLines)
	blob := f.bare()
	git(t, blob, "tag", "v9.0.0", git(t, blob, "rev-parse", f.commits["v1.4.0"]+":flags.go"))
	wantRefused(t, run(t, options(t, blob, standardRule(f))), CodeTagNotCommit)
}

func TestIncompleteOrBorrowingClonesAreRefused(t *testing.T) {
	f := newFixture(t, standard())
	add := func(rel, content string) func(*testing.T, string) {
		return func(t *testing.T, dir string) { write(t, filepath.Join(dir, rel), content) }
	}
	set := func(key, value string) func(*testing.T, string) {
		return func(t *testing.T, dir string) { git(t, dir, "config", key, value) }
	}
	for name, tc := range map[string]struct {
		change func(*testing.T, string)
		code   string
	}{
		"shallow":           {add("shallow", f.commits["v1.4.0"]+"\n"), CodeRepoShallow},
		"grafted":           {add("info/grafts", f.commits["v1.5.1"]+"\n"), CodeRepoGrafted},
		"alternates":        {add("objects/info/alternates", "/nonexistent/objects\n"), CodeRepoAlternates},
		"http alternates":   {add("objects/info/http-alternates", "https://example.invalid/objects\n"), CodeRepoAlternates},
		"common directory":  {add("commondir", ".\n"), CodeRepoAlternates},
		"promisor pack":     {add("objects/pack/pack-0.promisor", ""), CodeRepoPartial},
		"promisor remote":   {set("remote.origin.promisor", "true"), CodeRepoPartial},
		"partial filter":    {set("remote.origin.partialclonefilter", "blob:none"), CodeRepoPartial},
		"partial extension": {set("extensions.partialClone", "origin"), CodeRepoPartial},
	} {
		t.Run(name, func(t *testing.T) {
			clone := f.bare()
			tc.change(t, clone)
			wantRefused(t, run(t, options(t, clone, standardRule(f))), tc.code)
		})
	}
}

// git omits a broken tag ref from its listing with only a warning; the omitted
// tag could be the release that differs.
func TestABrokenTagRefIsNotSilentlyOmitted(t *testing.T) {
	f := newFixture(t, standard())
	for name, content := range map[string]string{"garbage": "not an object id\n", "empty": ""} {
		t.Run(name, func(t *testing.T) {
			clone := f.bare()
			write(t, filepath.Join(clone, "refs", "tags", "v1.5.2"), content)
			wantRefused(t, run(t, options(t, clone, standardRule(f))), CodeGit)
		})
	}
}

func TestGitRunsWithAFixedEnvironment(t *testing.T) {
	t.Setenv("GIT_CONFIG_COUNT", "1")
	want := []string{
		"PATH=/usr/bin:/bin:/usr/local/bin", "HOME=/nonexistent", "XDG_CONFIG_HOME=/nonexistent", "LC_ALL=C",
		"GIT_TERMINAL_PROMPT=0", "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_SYSTEM=/dev/null", "GIT_CONFIG_GLOBAL=/dev/null",
		"GIT_NO_REPLACE_OBJECTS=1", "GIT_NO_LAZY_FETCH=1", "GIT_ALLOW_PROTOCOL=none",
	}
	if got := gitEnv(); !slices.Equal(got, want) {
		t.Fatalf("environment: %v", got)
	}
	argv := strings.Join(gitArgv("/x.git", "ls-tree"), " ")
	if argv != "-c core.hooksPath=/dev/null -c core.fsmonitor=false -c protocol.allow=never -c gc.auto=0 --git-dir=/x.git ls-tree" {
		t.Fatalf("arguments: %s", argv)
	}
	b := &boundedBuffer{}
	if _, err := b.Write(make([]byte, maxGitOutput)); err != nil {
		t.Fatalf("at the cap: %v", err)
	}
	if _, err := b.Write([]byte("x")); err == nil || !b.over {
		t.Fatal("output over the cap was accepted")
	}
}

func TestGitIsNotSearchedOnTheCallersPath(t *testing.T) {
	f := newFixture(t, standard())
	o := options(t, f.bare(), standardRule(f))
	dir := t.TempDir()
	fake := filepath.Join(dir, "git")
	if err := os.WriteFile(fake, []byte("#!/bin/sh\nexit 1\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	wantProposal(t, run(t, o))
	if want := []string{"/usr/bin/git", "/usr/local/bin/git", "/bin/git"}; !slices.Equal(gitBinaries, want) {
		t.Fatalf("git places: %v", gitBinaries)
	}
	plain := filepath.Join(dir, "plain")
	if err := os.WriteFile(plain, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if bin, err := findGit([]string{filepath.Join(dir, "missing"), dir, plain}); err == nil {
		t.Fatalf("found %q", bin)
	}
	if bin, err := findGit([]string{plain, fake}); err != nil || bin != fake {
		t.Fatalf("found %q: %v", bin, err)
	}
}

// The tool reads the pack as one file, so the pack of this repository must stay
// under the read cap.
func TestTheRulePackFitsTheReadCap(t *testing.T) {
	info, err := os.Stat(filepath.Join("..", "..", "cncfcheck", "data", filepath.Base(RulesPath)))
	if err != nil {
		t.Fatal(err)
	}
	if info.Size() > maxFileBytes {
		t.Fatalf("the rule pack holds %d bytes, over the read cap of %d", info.Size(), maxFileBytes)
	}
}

func TestAnOversizedRulePackFailsTheRun(t *testing.T) {
	f := newFixture(t, standard())
	pack := packJSON(t, standardRule(f))
	clone := f.bare()
	for name, tc := range map[string]struct {
		size int
		ok   bool
	}{"at the cap": {maxFileBytes, true}, "over the cap": {maxFileBytes + 1, false}} {
		repo, commit := rulesRepo(t, pack+strings.Repeat(" ", tc.size-len(pack)))
		_, err := Run(context.Background(), Options{RulesRepo: repo, RulesCommit: commit, Config: config(clone)})
		if (err == nil) != tc.ok {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestReadCountsAreCapped(t *testing.T) {
	f := newFixture(t, standard())
	clone := f.bare()
	var packed strings.Builder
	for i := 0; i <= maxTagRefs; i++ {
		fmt.Fprintf(&packed, "%s refs/tags/note-%06d\n", f.commits["v1.4.0"], i)
	}
	write(t, filepath.Join(clone, "packed-refs"), packed.String())
	no := wantRefused(t, run(t, options(t, clone, standardRule(f))), CodeGit)
	if !strings.Contains(no.Detail, "too many tags") {
		t.Fatalf("detail: %s", no.Detail)
	}
	r := &repository{gitDir: f.bare(), files: map[string]*treeFile{}}
	for i := 0; i < maxFileReads; i++ {
		r.files[strconv.Itoa(i)] = nil
	}
	if file, err := r.file(context.Background(), f.commits["v1.4.0"], "flags.go"); err == nil {
		t.Fatalf("a read over the limit was accepted: %+v", file)
	}
}

func TestOnlyTheNamedBareRepositoryIsRead(t *testing.T) {
	f := newFixture(t, standard())
	clone := f.bare()
	wantRefused(t, run(t, options(t, filepath.Join(clone, "missing"), standardRule(f))), CodeRepoMissing)
	// No upward search from a directory inside a repository.
	wantRefused(t, run(t, options(t, filepath.Join(clone, "refs"), standardRule(f))), CodeRepoMissing)
	wantRefused(t, run(t, options(t, f.work, standardRule(f))), CodeRepoMissing)
	wantRefused(t, run(t, options(t, filepath.Join(f.work, ".git"), standardRule(f))), CodeRepoNotBare)
}

func TestAmbientGitEnvironmentIsIgnored(t *testing.T) {
	f := newFixture(t, standard())
	o := options(t, f.bare(), standardRule(f))
	for _, key := range []string{"GIT_DIR", "GIT_OBJECT_DIRECTORY", "GIT_COMMON_DIR"} {
		t.Setenv(key, "/nonexistent")
	}
	wantProposal(t, run(t, o))
}

func TestReplaceRefsDoNotHideADifference(t *testing.T) {
	f := newFixture(t, with(standard(), "v1.5.1", "flags.go", oldCode))
	clone := f.bare()
	git(t, clone, "update-ref", "refs/replace/"+f.commits["v1.5.1"], f.commits["v1.5.0"])
	wantReview(t, run(t, options(t, clone, standardRule(f))), ReasonSpanNotStable)
}

func TestAMissingObjectIsARefusalNotAnAbsentPath(t *testing.T) {
	for name, object := range map[string]string{"blob": ":dir/flags.go", "subtree": ":dir", "tree": "^{tree}"} {
		t.Run(name, func(t *testing.T) {
			releases := []release{}
			for _, r := range standard() {
				releases = append(releases, release{r.tag, files{"dir/flags.go": r.tree["flags.go"]}})
			}
			releases = with(releases, "v1.5.1", "dir/flags.go", oldCode+"// only here\n")
			f := newFixture(t, releases)
			clone := f.bare()
			id := git(t, clone, "rev-parse", f.commits["v1.5.1"]+object)
			if err := os.Remove(filepath.Join(clone, "objects", id[:2], id[2:])); err != nil {
				t.Fatal(err)
			}
			sources := []src{f.source("old-flags", "v1.4.1", "dir/flags.go", 3, 5), f.source("new-flags", "v1.5.0", "dir/flags.go", 3, 5)}
			wantRefused(t, run(t, options(t, clone, rule("flag-removed", "1.4.1", "1.5.0", sources))), CodeObjectMissing)
		})
	}
}
