// SPDX-License-Identifier: AGPL-3.0-only

package knowledgegate

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/maintainer/coveragereport"
)

// The Go rendering of the preview counts is the text committed in this
// repository (which scripts/preview-coverage.sh, a wrapper over the same
// code, and CI keep current).
func TestPreviewCountsMatchRepository(t *testing.T) {
	t.Parallel()
	root, err := filepath.Abs(repoRoot)
	if err != nil {
		t.Fatal(err)
	}
	stale, err := RegenerateBlocks(root, true, PreviewPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(stale) != 0 {
		t.Fatalf("the committed preview counts are stale: %v; run scripts/preview-coverage.sh", stale)
	}
}

func editPreview(t *testing.T, tr Tree, edit func(s string) string) {
	t.Helper()
	path := filepath.Join(tr.Root, PreviewPath)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, path, []byte(edit(string(raw))))
}

// alterPreviewDigit changes one digit inside the intro region.
func alterPreviewDigit(s string) string {
	i := strings.Index(s, coveragereport.PreviewIntroBegin)
	k := i + strings.Index(s[i:], "has ") + len("has ")
	repl := byte('1')
	if s[k] == '1' {
		repl = '2'
	}
	return s[:k] + string(repl) + s[k+1:]
}

var previewBreakers = map[string]func(s string) string{
	"prose edited outside the markers": func(s string) string { return s + "\nAn added sentence.\n" },
	"intro count altered":              alterPreviewDigit,
	"pack region altered": func(s string) string {
		return strings.Replace(s, coveragereport.PreviewPackBegin+"\n", coveragereport.PreviewPackBegin+"\nHand written.\n", 1)
	},
	"duplicate begin marker": func(s string) string {
		return strings.Replace(s, coveragereport.PreviewPackBegin, coveragereport.PreviewPackBegin+"\n"+coveragereport.PreviewPackBegin, 1)
	},
	"end marker missing": func(s string) string {
		return strings.Replace(s, coveragereport.PreviewIntroEnd+"\n", "", 1)
	},
}

func TestAdmittedBlocksPreview(t *testing.T) {
	t.Parallel()
	layout := DefaultLayout()
	for name, breaker := range previewBreakers {
		t.Run(name, func(t *testing.T) {
			base, head := trees(t)
			if got := layout.admittedBlocks(base, head); !got[PreviewPath] {
				t.Fatalf("an unchanged preview is not admitted: %v", got)
			}
			editPreview(t, head, breaker)
			if got := layout.admittedBlocks(base, head); got[PreviewPath] {
				t.Fatal("a refused preview was admitted")
			}
		})
	}
	t.Run("regenerated counts", func(t *testing.T) {
		base, head := trees(t)
		editPreview(t, base, alterPreviewDigit)
		if got := layout.admittedBlocks(base, head); !got[PreviewPath] {
			t.Fatal("the base's prose with the head's regenerated counts is not admitted")
		}
	})
}

// A bot's tightening change moves the inventory and with it the preview
// counts; the regenerated preview is part of an automatically mergeable change.
func TestGateAutoMergeAdmitsRegeneratedPreview(t *testing.T) {
	t.Parallel()
	base, head := tightened(t)
	r := runGate(t, Options{Base: base, Head: head, Author: DefaultBotLogin})
	requirePass(t, r)
	if !hasPath(r.ChangedPaths, PreviewPath) {
		t.Fatalf("the change does not move the preview: %v", r.ChangedPaths)
	}
	if c, ok := check(r, "generated/"+PreviewPath); !ok || !c.OK {
		t.Fatalf("block check %+v", c)
	}
	if !r.AutoMerge.Eligible {
		t.Fatalf("not eligible: %v", r.AutoMerge.Reasons)
	}
}

func TestGateAutoMergeRefusesPreviewBreakage(t *testing.T) {
	t.Parallel()
	for name, breaker := range previewBreakers {
		t.Run(name, func(t *testing.T) {
			base, head := tightened(t)
			editPreview(t, head, breaker)
			r := runGate(t, Options{Base: base, Head: head, Author: DefaultBotLogin})
			if r.AutoMerge.Eligible {
				t.Fatal("a broken preview is eligible for automatic merging")
			}
			if name == "prose edited outside the markers" {
				requirePass(t, r)
				if !strings.Contains(strings.Join(r.AutoMerge.Reasons, " "), PreviewPath) {
					t.Fatalf("reasons %v", r.AutoMerge.Reasons)
				}
				return
			}
			requireFail(t, r, "generated/"+PreviewPath)
		})
	}
	t.Run("stale counts", func(t *testing.T) {
		base, head := trees(t)
		ids := readPack(t, base, cncfRulesPath).activeReviewed()
		p := readPack(t, head, cncfRulesPath)
		evidenceOf(p.find(t, ids[0]))["state"] = "withdrawn"
		p.write(t, head, cncfRulesPath)
		regenerateInventoryOnly(t, head)
		r := runGate(t, Options{Base: base, Head: head, Author: DefaultBotLogin})
		requireFail(t, r, "generated/"+PreviewPath)
	})
}

func TestBatchGateAdmitsRegeneratedPreview(t *testing.T) {
	t.Parallel()
	f := newBatchFixture(t, 2)
	editPreview(t, f.base, alterPreviewDigit) // the base counts are behind the data
	f.signAndWrite(t, f.record(t))
	r := runGate(t, Options{Base: f.base, Head: f.head})
	requirePass(t, r)
	if !hasPath(r.ChangedPaths, PreviewPath) {
		t.Fatalf("the change does not move the preview: %v", r.ChangedPaths)
	}
	requireBatchProof(t, r, f.ids)
}

func TestBatchGateRefusesPreviewBreakage(t *testing.T) {
	t.Parallel()
	for name, breaker := range previewBreakers {
		t.Run(name, func(t *testing.T) {
			f := newBatchFixture(t, 2)
			f.signAndWrite(t, f.record(t))
			editPreview(t, f.head, breaker)
			r := runGate(t, Options{Base: f.base, Head: f.head})
			requireFail(t, r, PreviewPath)
			for _, id := range f.ids {
				if c := change(t, r, id); c.OK {
					t.Fatalf("change %s admitted with a broken preview", id)
				}
			}
		})
	}
}

func TestOnboardingGateRefusesPreviewBreakage(t *testing.T) {
	t.Parallel()
	for name, breaker := range previewBreakers {
		t.Run(name, func(t *testing.T) {
			f := newOnboardingFixture(t)
			f.sign(t, f.record(t))
			editPreview(t, f.head, breaker)
			requireFail(t, f.gate(t), PreviewPath)
		})
	}
}
