// SPDX-License-Identifier: AGPL-3.0-only

package knowledgegate

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"testing/fstest"
	"time"

	"github.com/prufyx/prufyx/cli/internal/extract/crdversions"
	"github.com/prufyx/prufyx/cli/internal/maintainer/coveragereport"
)

// readmePath is the file whose coverage block is generated.
const readmePath = "README.md"

// PreviewPath is the document whose rule-count sentences are generated.
const PreviewPath = "cli/docs/CNCF-SOURCE-PREVIEW.md"

// GeneratedBlock is a region of a prose file, between two marker lines, that
// must equal a rendering of the change's own data. A file may hold more
// regions (More); the file then equals its prose with every region rendered.
// The prose outside the markers is never generated and never changes in an
// automatic change.
type GeneratedBlock struct {
	Path, Begin, End string
	// Render returns the text between the markers from the data of a tree.
	Render func(t Tree) (string, error)
	// More are further regions of the same file.
	More []BlockRegion
	// Sources are the repository files of the renderer of this block. A
	// change that moves one is checked by the head's own test (the base
	// gate renders with the base's code, which cannot know the new
	// renderer); it is never admitted as an automatic change.
	Sources []string
	// HeadTest names the test of the head that verifies the block.
	HeadTest string
}

// BlockRegion is one more generated region of a GeneratedBlock's file.
type BlockRegion struct {
	Begin, End string
	Render     func(t Tree) (string, error)
}

// Want returns the file as it must read: the prose of the prose tree with
// every block rendered from the data tree.
func (g GeneratedBlock) Want(prose, data Tree) ([]byte, error) {
	doc, err := prose.Read(g.Path, MaxFileBytes)
	if err != nil {
		return nil, err
	}
	regions := append([]BlockRegion{{Begin: g.Begin, End: g.End, Render: g.Render}}, g.More...)
	for _, r := range regions {
		block, err := r.Render(data)
		if err != nil {
			return nil, err
		}
		if doc, err = coveragereport.SpliceBlock(doc, r.Begin, r.End, block); err != nil {
			return nil, err
		}
	}
	return doc, nil
}

// matches reports whether the head file is a regular file, without an
// executable bit in the base or the head, that equals the base's prose
// spliced with the block rendered from the head's data.
func (g GeneratedBlock) matches(base, head Tree) bool {
	if head.executable(g.Path) || base.executable(g.Path) {
		return false
	}
	want, err := g.Want(base, head)
	if err != nil {
		return false
	}
	have, err := head.Read(g.Path, MaxFileBytes)
	return err == nil && bytes.Equal(want, have)
}

// blockPath reports whether rel is the file of a generated block.
func (l Layout) blockPath(rel string) bool {
	for _, g := range l.GeneratedBlocks {
		if g.Path == rel {
			return true
		}
	}
	return false
}

// admittedBlocks returns the generated-block files that an automatic change
// (an auto-merge, a batch, an onboarding batch) may carry: the head file
// equals the base file with only its block regenerated from the head's data.
// A prose edit, a damaged or duplicated marker, a link or an executable bit
// makes the file not admitted.
func (l Layout) admittedBlocks(base, head Tree) map[string]bool {
	out := map[string]bool{}
	for _, g := range l.GeneratedBlocks {
		if g.matches(base, head) {
			out[g.Path] = true
		}
	}
	return out
}

// sourceChanged returns the renderer source files of the block that the
// change moves.
func (g GeneratedBlock) sourceChanged(changed []string) []string {
	var out []string
	for _, p := range changed {
		if slices.Contains(g.Sources, p) {
			out = append(out, p)
		}
	}
	return out
}

// blockChecks checks, for every change, that each generated block of the
// head equals the rendering of the head's own data. When the change moves
// the renderer of a block, the gate (built from the base code) cannot judge
// the block; the check does not fail then and the head's test
// (TestCoverageBlockMatchesRepositoryREADME or its preview twin) verifies it.
func (r *Report) blockChecks(opts Options) {
	for _, g := range opts.Layout.GeneratedBlocks {
		name := "generated/" + g.Path
		if moved := g.sourceChanged(r.ChangedPaths); len(moved) > 0 {
			r.add(name, true, "renderer changed in this change; verified by the head's %s", g.HeadTest)
			continue
		}
		want, err := g.Want(opts.Head, opts.Head)
		if err != nil {
			r.add(name, false, "cannot regenerate the block: %v", logSafe(err.Error()))
			continue
		}
		have, err := opts.Head.Read(g.Path, MaxFileBytes)
		ok := err == nil && bytes.Equal(want, have)
		r.add(name, ok, "the block of %s %s its regeneration", g.Path, map[bool]string{true: "matches", false: "differs from"}[ok])
	}
}

// coverageBlock renders the README coverage block from a tree's data: its
// CNCF rule pack, the pinned lines snapshot, the generated support
// inventory and the reviewed CRD version targets. Every input is read
// through the tree (no links, bounded sizes). The evaluation time is the
// snapshot's captured date at 12:00:00Z, so nothing depends on the clock.
func coverageBlock(t Tree) (string, error) {
	pack, err := t.Read(cncfRulesPath, MaxFileBytes)
	if err != nil {
		return "", err
	}
	linesRaw, err := t.Read(coveragereport.PinnedLinesPath, MaxFileBytes)
	if err != nil {
		return "", err
	}
	inventory, err := t.Read(inventoryJSON, MaxFileBytes)
	if err != nil {
		return "", err
	}
	community, err := t.Read(commRulesPath, MaxFileBytes)
	if err != nil {
		return "", err
	}
	lines, err := coveragereport.ParseLines(linesRaw)
	if err != nil {
		return "", err
	}
	captured, err := time.Parse("2006-01-02", lines.CapturedOn)
	if err != nil {
		return "", fmt.Errorf("the pinned lines snapshot has no captured date")
	}
	now := captured.Add(12 * time.Hour).UTC()
	crd, err := crdProjectComponents(t)
	if err != nil {
		return "", err
	}
	report, err := coveragereport.Compute(coveragereport.Input{Pack: pack, Lines: linesRaw, Now: now, CRDVersionProjects: len(crd), CRDTargetComponents: crd, CommunityPack: community})
	if err != nil {
		return "", err
	}
	return coveragereport.RenderREADMEBlock(report, inventory, now)
}

// basisBlock and validityBlock render the README sentences about how the
// rules were established and when they stop being valid, from both packs.
func basisBlock(t Tree) (string, error) {
	return claimsRegion(t, coveragereport.RenderBasisSentence)
}

func validityBlock(t Tree) (string, error) {
	return claimsRegion(t, coveragereport.RenderValiditySentence)
}

func claimsRegion(t Tree, render func(packs ...[]byte) (string, error)) (string, error) {
	pack, err := t.Read(cncfRulesPath, MaxFileBytes)
	if err != nil {
		return "", err
	}
	community, err := t.Read(commRulesPath, MaxFileBytes)
	if err != nil {
		return "", err
	}
	return render(pack, community)
}

// previewIntro and previewPack render the two rule-count regions of the
// CNCF source preview from the tree's generated support inventory.
func previewIntro(t Tree) (string, error) {
	return previewRegion(t, coveragereport.RenderPreviewIntro)
}

func previewPack(t Tree) (string, error) {
	return previewRegion(t, coveragereport.RenderPreviewPack)
}

func previewRegion(t Tree, render func([]byte) (string, error)) (string, error) {
	inventory, err := t.Read(inventoryJSON, MaxFileBytes)
	if err != nil {
		return "", err
	}
	return render(inventory)
}

// crdProjectComponents maps the projects among the CRD version targets of the
// tree to their target components, loaded as the onboarding gate loads them.
func crdProjectComponents(t Tree) (map[string]string, error) {
	targets, err := treeTargets(t, defaultOnboardingLayout().TargetsDir)
	if err != nil {
		return nil, err
	}
	fsys := fstest.MapFS{}
	for name, raw := range targets {
		fsys[name] = &fstest.MapFile{Data: raw}
	}
	loaded, err := crdversions.LoadTargets(fsys)
	if err != nil {
		return nil, fmt.Errorf("the CRD version targets do not load: %v", logSafe(err.Error()))
	}
	out := map[string]string{}
	for _, tg := range loaded {
		coveragereport.SetTargetComponent(out, tg.Project, tg.Component)
	}
	return out, nil
}

// RegenerateBlocks rewrites the generated blocks of the tree rooted at root
// with the default layout, or only checks them when check is set. Only the
// files named in only are handled; none named means every block. It returns
// the paths that were stale (check) or rewritten.
func RegenerateBlocks(root string, check bool, only ...string) ([]string, error) {
	tree := Tree{Root: root}
	var changed []string
	for _, g := range DefaultLayout().GeneratedBlocks {
		if len(only) > 0 && !slices.Contains(only, g.Path) {
			continue
		}
		want, err := g.Want(tree, tree)
		if err != nil {
			return changed, fmt.Errorf("%s: %w", g.Path, err)
		}
		have, err := tree.Read(g.Path, MaxFileBytes)
		if err != nil {
			return changed, err
		}
		if bytes.Equal(want, have) {
			continue
		}
		changed = append(changed, g.Path)
		if check {
			continue
		}
		// Read refused a link or a special file, so this is a regular file.
		if err := os.WriteFile(filepath.Join(root, filepath.FromSlash(g.Path)), want, 0o644); err != nil {
			return changed, err
		}
	}
	return changed, nil
}
