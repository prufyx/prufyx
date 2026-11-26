// SPDX-License-Identifier: AGPL-3.0-only

package knowledgegate

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/maintainer/releasenotes"
)

// countsFixture is an onboarding change whose head also carries the counts
// file edit returns from the correct bytes.
func countsFixture(t *testing.T, edit func(t *testing.T, f *onboardingFixture, path string, want []byte)) (*onboardingFixture, string) {
	t.Helper()
	f := newOnboardingFixture(t)
	ol := DefaultLayout().Onboarding
	want, err := countsOfTree(f.head, ol.TablePath)
	if err != nil {
		t.Fatalf("the fixture head has no counts: %v", err)
	}
	path := filepath.Join(f.head.Root, filepath.FromSlash(ol.CountsPath))
	writeFile(t, path, want)
	if edit != nil {
		edit(t, f, path, want)
	}
	return f, ol.CountsPath
}

func TestOnboardingCountsPathIsTheReleaseNotesOne(t *testing.T) {
	t.Parallel()
	if got := DefaultLayout().Onboarding.CountsPath; got != releasenotes.CountsPath {
		t.Fatalf("counts path %s", got)
	}
}

func TestOnboardingAdmitsRegeneratedCounts(t *testing.T) {
	t.Parallel()
	f, _ := countsFixture(t, nil)
	f.sign(t, f.record(t))
	requirePass(t, f.gate(t))
}

func TestOnboardingRefusesCountsThatAreNotTheRegeneration(t *testing.T) {
	t.Parallel()
	counts := releasenotes.CountsPath
	differs := "O2: " + counts + " differs from its regeneration from the head"
	unreadable := "O2: " + counts + " cannot be read from the head: "
	outside := func(path string) []string {
		return []string{"O2: an onboarding change may change only the batch file", "it also changes 1 other files: " + path}
	}
	type refusal struct {
		edit func(t *testing.T, f *onboardingFixture, path string, want []byte)
		// problem holds the texts the one offline problem must contain.
		problem []string
	}
	cases := map[string]refusal{
		"one more newline": {func(t *testing.T, _ *onboardingFixture, path string, want []byte) {
			writeFile(t, path, append(append([]byte{}, want...), '\n'))
		}, []string{differs}},
		"one byte short": {func(t *testing.T, _ *onboardingFixture, path string, want []byte) {
			writeFile(t, path, want[:len(want)-1])
		}, []string{differs}},
		"stale": {func(t *testing.T, _ *onboardingFixture, path string, _ []byte) {
			writeFile(t, path, []byte("{}\n"))
		}, []string{differs}},
		"executable": {func(t *testing.T, _ *onboardingFixture, path string, _ []byte) {
			if err := os.Chmod(path, 0o755); err != nil {
				t.Fatal(err)
			}
		}, []string{"O2: " + counts + " has an executable bit"}},
		// The target holds the correct bytes and is outside both trees, so
		// only the link itself can be refused.
		"link": {func(t *testing.T, _ *onboardingFixture, path string, want []byte) {
			target := filepath.Join(t.TempDir(), "counts.json")
			writeFile(t, target, want)
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(target, path); err != nil {
				t.Fatal(err)
			}
		}, []string{unreadable}},
		"deleted": {func(t *testing.T, f *onboardingFixture, path string, want []byte) {
			writeFile(t, filepath.Join(f.base.Root, filepath.FromSlash(releasenotes.CountsPath)), want)
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
		}, []string{unreadable}},
		"second counts file": {func(t *testing.T, _ *onboardingFixture, path string, want []byte) {
			writeFile(t, strings.TrimSuffix(path, ".json")+"-copy.json", want)
		}, outside(strings.TrimSuffix(counts, ".json") + "-copy.json")},
		"changelog": {func(t *testing.T, f *onboardingFixture, _ string, _ []byte) {
			writeFile(t, filepath.Join(f.head.Root, "CHANGELOG.md"), []byte("# Changelog\n"))
		}, outside("CHANGELOG.md")},
		"release notes": {func(t *testing.T, f *onboardingFixture, _ string, _ []byte) {
			writeFile(t, filepath.Join(f.head.Root, "cli", "docs", "release-notes-v9.9.9.md"), []byte("# x\n"))
		}, outside("cli/docs/release-notes-v9.9.9.md")},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			f, _ := countsFixture(t, c.edit)
			rec, ok := f.tryRecord(t)
			if ok {
				t.Fatal("the offline checks accept the change")
			}
			// No case expects a change that cannot be read at all.
			if rec.BatchID == "" {
				t.Fatal("no record: the change was not read as an onboarding change")
			}
			layout := DefaultLayout()
			cls, err := Classify(layout, f.base, f.head)
			if err != nil {
				t.Fatal(err)
			}
			paths, err := ChangedPaths(f.base, f.head)
			if err != nil {
				t.Fatal(err)
			}
			st, err := newOnboardingState(layout, f.base, f.head, cls, paths)
			if err != nil {
				t.Fatal(err)
			}
			problems := st.check(rec, layout.Onboarding.Dir+"/"+rec.BatchID+".json")
			if len(problems) != 1 {
				t.Fatalf("want one problem, got %d: %v", len(problems), problems)
			}
			for _, text := range c.problem {
				if !strings.Contains(problems[0], text) {
					t.Fatalf("problem %q does not contain %q", problems[0], text)
				}
			}
			f.sign(t, rec)
			if f.gate(t).Passed() {
				t.Fatal("the gate passed")
			}
		})
	}
}

// With the counts path not configured, a change of the file is refused, however
// correct its bytes are.
func TestOnboardingWithoutACountsPathRefusesCounts(t *testing.T) {
	t.Parallel()
	f, rel := countsFixture(t, nil)
	layout := DefaultLayout()
	layout.Onboarding.CountsPath = ""
	cls, err := Classify(layout, f.base, f.head)
	if err != nil {
		t.Fatal(err)
	}
	paths, err := ChangedPaths(f.base, f.head)
	if err != nil {
		t.Fatal(err)
	}
	st, err := newOnboardingState(layout, f.base, f.head, cls, paths)
	if err != nil {
		t.Fatal(err)
	}
	rec := f.record(t)
	problems := strings.Join(st.check(rec, layout.Onboarding.Dir+"/"+rec.BatchID+".json"), "; ")
	if !strings.Contains(problems, rel) || !strings.Contains(problems, "O2:") {
		t.Fatalf("problems: %s", problems)
	}
}

// A change that is not an onboarding batch does not get the counts admitted for
// automatic merge.
func TestCountsAloneAreNotAutoMerged(t *testing.T) {
	t.Parallel()
	base, head := trees(t)
	writeFile(t, filepath.Join(head.Root, filepath.FromSlash(releasenotes.CountsPath)), []byte("{}\n"))
	r := runGate(t, Options{Base: base, Head: head, Author: obOwner, Sender: obOwner})
	if r.AutoMerge.Eligible {
		t.Fatalf("auto merge %+v", r.AutoMerge)
	}
}
