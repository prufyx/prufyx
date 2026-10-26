// SPDX-License-Identifier: AGPL-3.0-only

package knowledgegate

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/maintainer/coveragereport"
)

// The Go rendering of the README block is the block committed in this
// repository (which scripts/readme-coverage.sh, now a wrapper over the same
// code, and CI keep current).
func TestCoverageBlockMatchesRepositoryREADME(t *testing.T) {
	t.Parallel()
	root, err := filepath.Abs(repoRoot)
	if err != nil {
		t.Fatal(err)
	}
	stale, err := RegenerateBlocks(root, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(stale) != 0 {
		t.Fatalf("the committed README coverage block is stale: %v; run scripts/readme-coverage.sh", stale)
	}
}

func readREADME(t *testing.T, tr Tree) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(tr.Root, readmePath))
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func editREADME(t *testing.T, tr Tree, edit func(s string) string) {
	t.Helper()
	writeFile(t, filepath.Join(tr.Root, readmePath), []byte(edit(readREADME(t, tr))))
}

// alterBlockDigit changes one digit inside the generated block.
func alterBlockDigit(s string) string {
	i := strings.Index(s, coveragereport.READMEBegin)
	j := strings.Index(s[i:], "| CNCF source rules, active | ")
	k := i + j + len("| CNCF source rules, active | ")
	d := s[k]
	repl := byte('1')
	if d == '1' {
		repl = '2'
	}
	return s[:k] + string(repl) + s[k+1:]
}

// breakers are the heads that a README check must refuse, each with the
// README of the head already derived from a correct one.
var readmeBreakers = map[string]func(s string) string{
	"prose edited outside the block": func(s string) string { return s + "\nAn added sentence.\n" },
	"one digit of the block altered": alterBlockDigit,
	"duplicate begin marker": func(s string) string {
		return strings.Replace(s, coveragereport.READMEBegin, coveragereport.READMEBegin+"\n"+coveragereport.READMEBegin, 1)
	},
	"duplicate end marker": func(s string) string {
		return strings.Replace(s, coveragereport.READMEEnd, coveragereport.READMEEnd+"\n"+coveragereport.READMEEnd, 1)
	},
	"end marker missing": func(s string) string {
		return strings.Replace(s, coveragereport.READMEEnd+"\n", "", 1)
	},
	"begin marker missing": func(s string) string {
		return strings.Replace(s, coveragereport.READMEBegin+"\n", "", 1)
	},
	"markers swapped": func(s string) string {
		s = strings.Replace(s, coveragereport.READMEBegin, "@@B@@", 1)
		s = strings.Replace(s, coveragereport.READMEEnd, coveragereport.READMEBegin, 1)
		return strings.Replace(s, "@@B@@", coveragereport.READMEEnd, 1)
	},
	"marker not a whole line": func(s string) string {
		return strings.Replace(s, coveragereport.READMEEnd, coveragereport.READMEEnd+" ", 1)
	},
}

func TestAdmittedBlocksRefusals(t *testing.T) {
	t.Parallel()
	layout := DefaultLayout()
	for name, breaker := range readmeBreakers {
		t.Run(name, func(t *testing.T) {
			base, head := trees(t)
			if got := layout.admittedBlocks(base, head); !got[readmePath] {
				t.Fatalf("an unchanged README is not admitted: %v", got)
			}
			editREADME(t, head, breaker)
			if got := layout.admittedBlocks(base, head); got[readmePath] {
				t.Fatal("a refused README was admitted")
			}
		})
	}
	t.Run("symbolic link", func(t *testing.T) {
		base, head := trees(t)
		real := filepath.Join(head.Root, "README.real")
		writeFile(t, real, []byte(readREADME(t, head)))
		path := filepath.Join(head.Root, readmePath)
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink("README.real", path); err != nil {
			t.Fatal(err)
		}
		if got := layout.admittedBlocks(base, head); got[readmePath] {
			t.Fatal("a README that is a link was admitted")
		}
	})
	t.Run("executable bit", func(t *testing.T) {
		base, head := trees(t)
		if err := os.Chmod(filepath.Join(head.Root, readmePath), 0o755); err != nil {
			t.Fatal(err)
		}
		if got := layout.admittedBlocks(base, head); got[readmePath] {
			t.Fatal("an executable README was admitted")
		}
	})
	t.Run("regenerated block", func(t *testing.T) {
		base, head := trees(t)
		editREADME(t, base, alterBlockDigit)
		if got := layout.admittedBlocks(base, head); !got[readmePath] {
			t.Fatal("the base's prose with the head's regenerated block is not admitted")
		}
	})
}

// tightened returns trees where a bot's tightening change moves the block.
func tightened(t *testing.T) (Tree, Tree) {
	t.Helper()
	base, head := trees(t)
	ids := readPack(t, base, cncfRulesPath).activeReviewed()
	editPack(t, head, cncfRulesPath, func(p *packDoc) {
		evidenceOf(p.find(t, ids[0]))["state"] = "withdrawn"
	})
	return base, head
}

func hasPath(paths []string, p string) bool { return slices.Contains(paths, p) }

// A bot's tightening change moves the inventory and with it the block; the
// regenerated README is part of an automatically mergeable change.
func TestGateAutoMergeAdmitsRegeneratedREADME(t *testing.T) {
	t.Parallel()
	base, head := tightened(t)
	r := runGate(t, Options{Base: base, Head: head, Author: DefaultBotLogin})
	requirePass(t, r)
	if !hasPath(r.ChangedPaths, readmePath) {
		t.Fatalf("the change does not move the README: %v", r.ChangedPaths)
	}
	if c, ok := check(r, "generated/"+readmePath); !ok || !c.OK {
		t.Fatalf("block check %+v", c)
	}
	if !r.AutoMerge.Eligible {
		t.Fatalf("not eligible: %v", r.AutoMerge.Reasons)
	}
}

// Prose outside the block can never change in an automatic merge, and
// neither can anything that is not exactly the regeneration.
func TestGateAutoMergeRefusesREADMEBreakage(t *testing.T) {
	t.Parallel()
	for name, breaker := range readmeBreakers {
		t.Run(name, func(t *testing.T) {
			base, head := tightened(t)
			editREADME(t, head, breaker)
			r := runGate(t, Options{Base: base, Head: head, Author: DefaultBotLogin})
			if r.AutoMerge.Eligible {
				t.Fatal("a broken README is eligible for automatic merging")
			}
			if name != "prose edited outside the block" {
				requireFail(t, r, "generated/"+readmePath)
				return
			}
			// The block is still current, so the gate passes, but the change
			// is the owner's.
			requirePass(t, r)
			if !strings.Contains(strings.Join(r.AutoMerge.Reasons, " "), readmePath) {
				t.Fatalf("reasons %v", r.AutoMerge.Reasons)
			}
		})
	}
	t.Run("stale block", func(t *testing.T) {
		base, head := trees(t)
		ids := readPack(t, base, cncfRulesPath).activeReviewed()
		p := readPack(t, head, cncfRulesPath)
		evidenceOf(p.find(t, ids[0]))["state"] = "withdrawn"
		p.write(t, head, cncfRulesPath)
		regenerateInventoryOnly(t, head)
		r := runGate(t, Options{Base: base, Head: head, Author: DefaultBotLogin})
		requireFail(t, r, "generated/"+readmePath)
	})
	t.Run("symbolic link", func(t *testing.T) {
		base, head := tightened(t)
		real := filepath.Join(head.Root, "README.real")
		writeFile(t, real, []byte(readREADME(t, head)))
		path := filepath.Join(head.Root, readmePath)
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink("README.real", path); err != nil {
			t.Fatal(err)
		}
		r := runGate(t, Options{Base: base, Head: head, Author: DefaultBotLogin})
		if r.Passed() && r.AutoMerge.Eligible {
			t.Fatal("a README that is a link is eligible for automatic merging")
		}
	})
	t.Run("executable bit", func(t *testing.T) {
		base, head := tightened(t)
		if err := os.Chmod(filepath.Join(head.Root, readmePath), 0o755); err != nil {
			t.Fatal(err)
		}
		r := runGate(t, Options{Base: base, Head: head, Author: DefaultBotLogin})
		requireFail(t, r, "file-modes")
		if r.AutoMerge.Eligible {
			t.Fatal("an executable README is eligible for automatic merging")
		}
	})
}

// regenerateInventoryOnly regenerates the attestation and the generated
// pairs of a tree but leaves the README as it is.
func regenerateInventoryOnly(t *testing.T, tr Tree) {
	t.Helper()
	layout := DefaultLayout()
	for _, spec := range layout.Packs {
		raw, err := spec.Attest(tr)
		if err != nil {
			t.Fatal(err)
		}
		writeFile(t, filepath.Join(tr.Root, filepath.FromSlash(spec.AttestationPath)), raw)
	}
	for _, g := range layout.Generated {
		j, md, err := g.Generate(tr)
		if err != nil {
			t.Fatal(err)
		}
		writeFile(t, filepath.Join(tr.Root, filepath.FromSlash(g.JSONPath)), j)
		writeFile(t, filepath.Join(tr.Root, filepath.FromSlash(g.MarkdownPath)), []byte(md))
	}
}

// A batch may carry the README only as the base file with its block
// regenerated from the batch's own data.
func TestBatchGateAdmitsRegeneratedREADME(t *testing.T) {
	t.Parallel()
	f := newBatchFixture(t, 2)
	editREADME(t, f.base, alterBlockDigit) // the base block is behind the data
	f.signAndWrite(t, f.record(t))
	r := runGate(t, Options{Base: f.base, Head: f.head})
	requirePass(t, r)
	if !hasPath(r.ChangedPaths, readmePath) {
		t.Fatalf("the change does not move the README: %v", r.ChangedPaths)
	}
	requireBatchProof(t, r, f.ids)
}

func TestBatchGateRefusesREADMEBreakage(t *testing.T) {
	t.Parallel()
	for name, breaker := range readmeBreakers {
		t.Run(name, func(t *testing.T) {
			f := newBatchFixture(t, 2)
			f.signAndWrite(t, f.record(t))
			editREADME(t, f.head, breaker)
			r := runGate(t, Options{Base: f.base, Head: f.head})
			requireFail(t, r, readmePath)
			for _, id := range f.ids {
				if c := change(t, r, id); c.OK {
					t.Fatalf("change %s admitted with a broken README", id)
				}
			}
		})
	}
}

func TestOnboardingGateAdmitsRegeneratedREADME(t *testing.T) {
	t.Parallel()
	f := newOnboardingFixture(t)
	f.sign(t, f.record(t))
	r := f.gate(t)
	requirePass(t, r)
	if !hasPath(r.ChangedPaths, readmePath) {
		t.Fatalf("the onboarding does not move the README: %v", r.ChangedPaths)
	}
}

func TestOnboardingGateRefusesREADMEBreakage(t *testing.T) {
	t.Parallel()
	for name, breaker := range readmeBreakers {
		t.Run(name, func(t *testing.T) {
			f := newOnboardingFixture(t)
			f.sign(t, f.record(t))
			editREADME(t, f.head, breaker)
			requireFail(t, f.gate(t), readmePath)
		})
	}
}

// A change that moves the renderer of a block cannot be judged by the gate
// built from the base code: the block check does not fail, the head's own
// test decides, and the change is never automatic.
func TestGateRendererSourceChange(t *testing.T) {
	t.Parallel()
	for _, g := range DefaultLayout().GeneratedBlocks {
		if len(g.Sources) == 0 || g.HeadTest == "" {
			t.Fatalf("block %s lists no renderer sources or head test", g.Path)
		}
	}
	src := DefaultLayout().GeneratedBlocks[0].Sources[0]
	t.Run("renderer moved, block differs", func(t *testing.T) {
		t.Parallel()
		base, head := tightened(t)
		editREADME(t, head, alterBlockDigit)
		writeFile(t, filepath.Join(head.Root, filepath.FromSlash(src)), []byte("// changed renderer\n"))
		r := runGate(t, Options{Base: base, Head: head, Author: DefaultBotLogin})
		c, ok := check(r, "generated/"+readmePath)
		if !ok || !c.OK || !strings.Contains(c.Detail, "renderer changed in this change; verified by the head's TestCoverageBlockMatchesRepositoryREADME") {
			t.Fatalf("block check %+v", c)
		}
		if r.AutoMerge.Eligible {
			t.Fatal("a renderer change is eligible for automatic merging")
		}
		if !strings.Contains(strings.Join(r.AutoMerge.Reasons, " "), src) {
			t.Fatalf("reasons %v", r.AutoMerge.Reasons)
		}
	})
	t.Run("renderer unchanged, hand edit", func(t *testing.T) {
		t.Parallel()
		base, head := tightened(t)
		editREADME(t, head, alterBlockDigit)
		r := runGate(t, Options{Base: base, Head: head, Author: DefaultBotLogin})
		requireFail(t, r, "generated/"+readmePath)
		if r.AutoMerge.Eligible {
			t.Fatal("a hand-edited README is eligible for automatic merging")
		}
	})
	t.Run("other file moved, hand edit", func(t *testing.T) {
		t.Parallel()
		base, head := tightened(t)
		editREADME(t, head, alterBlockDigit)
		writeFile(t, filepath.Join(head.Root, "cli/internal/maintainer/coveragereport/render.go"), []byte("// not a README source\n"))
		r := runGate(t, Options{Base: base, Head: head, Author: DefaultBotLogin})
		requireFail(t, r, "generated/"+readmePath)
	})
}
