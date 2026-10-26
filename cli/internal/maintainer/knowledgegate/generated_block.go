// SPDX-License-Identifier: AGPL-3.0-only

package knowledgegate

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"testing/fstest"
	"time"

	"github.com/prufyx/prufyx/cli/internal/extract/crdversions"
	"github.com/prufyx/prufyx/cli/internal/maintainer/coveragereport"
)

// readmePath is the file whose coverage block is generated.
const readmePath = "README.md"

// GeneratedBlock is a region of a prose file, between two marker lines, that
// must equal a rendering of the change's own data. The prose outside the
// markers is never generated and never changes in an automatic change.
type GeneratedBlock struct {
	Path, Begin, End string
	// Render returns the text between the markers from the data of a tree.
	Render func(t Tree) (string, error)
}

// Want returns the file as it must read: the prose of the prose tree with
// the block rendered from the data tree.
func (g GeneratedBlock) Want(prose, data Tree) ([]byte, error) {
	doc, err := prose.Read(g.Path, MaxFileBytes)
	if err != nil {
		return nil, err
	}
	block, err := g.Render(data)
	if err != nil {
		return nil, err
	}
	return coveragereport.SpliceBlock(doc, g.Begin, g.End, block)
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

// blockChecks checks, for every change, that each generated block of the
// head equals the rendering of the head's own data.
func (r *Report) blockChecks(opts Options) {
	for _, g := range opts.Layout.GeneratedBlocks {
		name := "generated/" + g.Path
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
	lines, err := coveragereport.ParseLines(linesRaw)
	if err != nil {
		return "", err
	}
	captured, err := time.Parse("2006-01-02", lines.CapturedOn)
	if err != nil {
		return "", fmt.Errorf("the pinned lines snapshot has no captured date")
	}
	now := captured.Add(12 * time.Hour).UTC()
	crd, err := crdProjectCount(t)
	if err != nil {
		return "", err
	}
	report, err := coveragereport.Compute(coveragereport.Input{Pack: pack, Lines: linesRaw, Now: now, CRDVersionProjects: crd})
	if err != nil {
		return "", err
	}
	return coveragereport.RenderREADMEBlock(report, inventory, now)
}

// crdProjectCount counts the distinct projects among the CRD version targets
// of the tree, loaded as the onboarding gate loads them.
func crdProjectCount(t Tree) (int, error) {
	targets, err := treeTargets(t, defaultOnboardingLayout().TargetsDir)
	if err != nil {
		return 0, err
	}
	fsys := fstest.MapFS{}
	for name, raw := range targets {
		fsys[name] = &fstest.MapFile{Data: raw}
	}
	loaded, err := crdversions.LoadTargets(fsys)
	if err != nil {
		return 0, fmt.Errorf("the CRD version targets do not load: %v", logSafe(err.Error()))
	}
	seen := map[string]bool{}
	for _, tg := range loaded {
		seen[tg.Project] = true
	}
	return len(seen), nil
}

// RegenerateBlocks rewrites the generated blocks of the tree rooted at root
// with the default layout, or only checks them when check is set. It returns
// the paths that were stale (check) or rewritten.
func RegenerateBlocks(root string, check bool) ([]string, error) {
	tree := Tree{Root: root}
	var changed []string
	for _, g := range DefaultLayout().GeneratedBlocks {
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
