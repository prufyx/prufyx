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
	cases := map[string]func(t *testing.T, f *onboardingFixture, path string, want []byte){
		"one more newline": func(t *testing.T, _ *onboardingFixture, path string, want []byte) {
			writeFile(t, path, append(append([]byte{}, want...), '\n'))
		},
		"one byte short": func(t *testing.T, _ *onboardingFixture, path string, want []byte) {
			writeFile(t, path, want[:len(want)-1])
		},
		"stale": func(t *testing.T, _ *onboardingFixture, path string, _ []byte) {
			writeFile(t, path, []byte("{}\n"))
		},
		"executable": func(t *testing.T, _ *onboardingFixture, path string, _ []byte) {
			if err := os.Chmod(path, 0o755); err != nil {
				t.Fatal(err)
			}
		},
		"link": func(t *testing.T, _ *onboardingFixture, path string, want []byte) {
			writeFile(t, path+".real", want)
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(filepath.Base(path)+".real", path); err != nil {
				t.Fatal(err)
			}
		},
		"deleted": func(t *testing.T, f *onboardingFixture, path string, want []byte) {
			writeFile(t, filepath.Join(f.base.Root, filepath.FromSlash(releasenotes.CountsPath)), want)
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
		},
		"second counts file": func(t *testing.T, _ *onboardingFixture, path string, want []byte) {
			writeFile(t, strings.TrimSuffix(path, ".json")+"-copy.json", want)
		},
		"changelog": func(t *testing.T, f *onboardingFixture, _ string, _ []byte) {
			writeFile(t, filepath.Join(f.head.Root, "CHANGELOG.md"), []byte("# Changelog\n"))
		},
		"release notes": func(t *testing.T, f *onboardingFixture, _ string, _ []byte) {
			writeFile(t, filepath.Join(f.head.Root, "cli", "docs", "release-notes-v9.9.9.md"), []byte("# x\n"))
		},
	}
	for name, edit := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			f, _ := countsFixture(t, edit)
			rec, ok := f.tryRecord(t)
			if ok {
				t.Fatal("the offline checks accept the change")
			}
			if rec.BatchID == "" {
				return // the tree cannot be read as a change at all
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
