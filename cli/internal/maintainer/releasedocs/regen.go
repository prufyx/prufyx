// SPDX-License-Identifier: AGPL-3.0-only

package releasedocs

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/prufyx/prufyx/cli/internal/maintainer/knowledgegate"
	"github.com/prufyx/prufyx/cli/internal/maintainer/releasenotes"
)

// Generator writes the tree's own generated coverage text. The default is
// the one implementation the gate also uses; tests replace it.
type Generator interface {
	// Blocks rewrites the generated coverage blocks of the tree (the README
	// block and the preview counts) and returns the paths that changed.
	Blocks(root string) ([]string, error)
	// Counts returns the bytes the counts file must have.
	Counts(root string) ([]byte, error)
}

type treeGenerator struct{}

// Blocks renders every block of the default layout with the renderers the
// check uses and replaces each stale file atomically, keeping its mode.
func (treeGenerator) Blocks(root string) ([]string, error) {
	tree := knowledgegate.Tree{Root: root}
	layout := knowledgegate.DefaultLayout()
	var changed []string
	for _, g := range layout.GeneratedBlocks {
		want, err := g.Want(tree, tree, layout.Onboarding)
		if err != nil {
			return changed, fmt.Errorf("%s: %w", g.Path, err)
		}
		// Read refuses a link or a special file.
		have, err := tree.Read(g.Path, knowledgegate.MaxFileBytes)
		if err != nil {
			return changed, err
		}
		if bytes.Equal(want, have) {
			continue
		}
		p := filepath.Join(root, filepath.FromSlash(g.Path))
		st, err := os.Lstat(p)
		if err != nil {
			return changed, err
		}
		if err := atomicWrite(p, want, st.Mode().Perm()); err != nil {
			return changed, err
		}
		changed = append(changed, g.Path)
	}
	return changed, nil
}

func (treeGenerator) Counts(root string) ([]byte, error) { return knowledgegate.ReadmeCounts(root) }

// blockPaths lists the files Blocks may write, from the same layout.
func blockPaths() []string {
	var out []string
	for _, g := range knowledgegate.DefaultLayout().GeneratedBlocks {
		out = append(out, g.Path)
	}
	return out
}

// RegenOptions of one regeneration.
type RegenOptions struct {
	Root     string
	Mode     string // only ModeUnreleased
	Generate Generator
}

// RegenResult lists the files whose bytes changed, sorted.
type RegenResult struct {
	Changed []string
}

// RegenError is a refused regeneration. Code is the exit code of the failed
// class (the Code* constants). The files written before the failure are
// restored; when a restore fails too, the returned error joins this one with
// an error naming the files that are not restored.
type RegenError struct {
	Code int
	Msg  string
}

func (e *RegenError) Error() string { return e.Msg }

// Regen is the inverse of Check in unreleased mode: it writes what the check
// compares. Order matters and is the one the check reads in: the README
// block, the preview counts and the counts file first, then, for every notes
// file whose tag is not published, the generated block of the notes file and
// of the CHANGELOG entry, rendered by the check's own render. Only the
// generated blocks (between the marker lines) and the counts file are
// written; every other byte of every file is kept. It reads files and local
// git objects only. When a step returns an error every file written so far is
// restored; a restore failure is reported in the returned error. A killed
// process restores nothing.
//
// A notes file counts as unpublished when the local repository has no tag of
// its name, so the tags must be fetched. Regen refuses a shallow clone, more
// than one unpublished notes file, and an unpublished version that is not
// higher than every local version tag. It cannot detect a checkout that lacks
// only the newest tag while no later notes file exists.
func Regen(o RegenOptions) (res RegenResult, err error) {
	if o.Mode != ModeUnreleased {
		return res, &UsageError{"--mode must be unreleased"}
	}
	if o.Root == "" {
		return res, &UsageError{"--root is required"}
	}
	abs, aerr := filepath.Abs(o.Root)
	if aerr != nil {
		return res, &UsageError{"--root is unusable"}
	}
	root, eerr := filepath.EvalSymlinks(abs)
	if eerr != nil {
		return res, &UsageError{"--root is unusable"}
	}
	gen := o.Generate
	if gen == nil {
		gen = treeGenerator{}
	}
	c := &checker{o: Options{Root: root, Mode: ModeUnreleased}, root: root}
	// The tree must be the top level of a git work tree with its tags.
	top, gerr := c.git("rev-parse", "--show-toplevel")
	if gerr != nil {
		return res, &RegenError{CodeTag, "the root is not inside a git work tree: " + gerr.Error()}
	}
	if top, gerr = filepath.EvalSymlinks(top); gerr != nil || top != root {
		return res, &RegenError{CodeTag, "the root is not the top level of its git work tree"}
	}
	if _, gerr = c.git("rev-parse", "--verify", "HEAD^{commit}"); gerr != nil {
		return res, &RegenError{CodeTag, "the repository has no commit: " + gerr.Error()}
	}

	w := &regenWriter{root: root}
	defer func() {
		if err != nil {
			if rerr := w.rollback(); rerr != nil {
				err = errors.Join(err, rerr)
			}
		}
	}()

	tags := c.unpublishedNotes()
	if len(c.res.Findings) > 0 {
		return res, regenFailure(c.res.Findings)
	}
	if terr := c.provableTagState(tags); terr != nil {
		return res, &RegenError{CodeTag, terr.Error() + " (fetch the tags: git fetch --tags)"}
	}
	// Plan the notes before writing anything that is not restorable: every
	// header is read from the committed file.
	type plan struct{ tag, prev, toCommit string }
	var plans []plan
	for _, tag := range tags {
		name := notesPrefix + tag + notesSuffix
		raw, rerr := c.readRoot(name)
		if rerr != nil || len(strings.TrimSpace(string(raw))) == 0 {
			return res, &RegenError{CodeNotes, name + " is missing or empty"}
		}
		m := headerLine.FindStringSubmatch(string(raw))
		if m == nil {
			return res, &RegenError{CodeNotes, name + ": the generated block has no \"Changes from\" line to read the previous tag from (markers missing or the block was reworded)"}
		}
		if m[3] != tag {
			return res, &RegenError{CodeLabels, fmt.Sprintf("%s: the block describes %s, not %s", name, m[3], tag)}
		}
		if !tagGrammar.MatchString(m[1]) {
			return res, &RegenError{CodePrevious, fmt.Sprintf("%s: %q is not a v-prefixed semantic version", name, m[1])}
		}
		if _, ok, terr := c.tagCommit(m[1]); terr != nil || !ok {
			return res, &RegenError{CodeTag, fmt.Sprintf("%s: the previous tag %s is not in this repository (fetch the tags): %v", name, m[1], terr)}
		}
		plans = append(plans, plan{tag: tag, prev: m[1], toCommit: m[4]})
	}

	// 1. README block, preview counts, counts file.
	if berr := w.guardBlocks(gen); berr != nil {
		return res, &RegenError{CodeReadme, "cannot regenerate the coverage blocks: " + berr.Error()}
	}
	counts, cerr := gen.Counts(root)
	if cerr != nil {
		return res, &RegenError{CodeCounts, "the counts file cannot be regenerated: " + cerr.Error()}
	}
	if werr := w.write(releasenotes.CountsPath, counts); werr != nil {
		return res, &RegenError{CodeCounts, werr.Error()}
	}

	// 2. Notes blocks and CHANGELOG entries.
	changelogBytes, lerr := c.readRoot(changelogPath)
	if lerr != nil {
		return res, &RegenError{CodeChangelog, "CHANGELOG.md: " + lerr.Error()}
	}
	changelog := string(changelogBytes)
	for _, p := range plans {
		name := notesPrefix + p.tag + notesSuffix
		toCommit, terr := c.keepOrHead(p.toCommit)
		if terr != nil {
			return res, &RegenError{CodeTag, terr.Error()}
		}
		before := len(c.res.Findings)
		r3, r4, ok := c.render(name, p.tag, p.prev, toCommit)
		if !ok {
			return res, regenFailure(c.res.Findings[before:])
		}
		raw, _ := c.readRoot(name)
		updated, rerr := releasenotes.ReplaceBlock(string(raw), r3)
		if rerr != nil {
			return res, &RegenError{CodeNotes, name + ": " + rerr.Error()}
		}
		if werr := w.write(name, []byte(updated)); werr != nil {
			return res, &RegenError{CodeNotes, werr.Error()}
		}
		version := strings.TrimPrefix(p.tag, "v")
		s, e, found := changelogSpan(changelog, version)
		if !found {
			return res, &RegenError{CodeChangelog, fmt.Sprintf("CHANGELOG.md needs exactly one [%s] heading", version)}
		}
		entry, rerr := releasenotes.ReplaceBlock(changelog[s:e], r4)
		if rerr != nil {
			return res, &RegenError{CodeChangelog, fmt.Sprintf("CHANGELOG.md [%s]: %v", version, rerr)}
		}
		changelog = changelog[:s] + entry + changelog[e:]
	}
	if len(plans) > 0 {
		if werr := w.write(changelogPath, []byte(changelog)); werr != nil {
			return res, &RegenError{CodeChangelog, werr.Error()}
		}
	}
	res.Changed = w.changed()
	return res, nil
}

// provableTagState refuses the local tag states under which a notes file that
// looks unpublished may belong to a published release: a shallow clone, more
// than one such file, or a version not higher than every local version tag.
func (c *checker) provableTagState(unpublished []string) error {
	if len(unpublished) == 0 {
		return nil
	}
	shallow, err := c.git("rev-parse", "--is-shallow-repository")
	if err != nil || shallow != "false" {
		return errors.New("the clone is shallow or its depth cannot be read, so the tag state is not complete")
	}
	if len(unpublished) > 1 {
		return fmt.Errorf("more than one notes file has no local tag (%s); only the next release may be unpublished", strings.Join(unpublished, ", "))
	}
	refs, err := c.git("for-each-ref", "--format=%(refname)", "refs/tags")
	if err != nil {
		return fmt.Errorf("cannot list the tags: %v", err)
	}
	for _, ref := range strings.Split(refs, "\n") {
		tag := strings.TrimPrefix(ref, "refs/tags/")
		if !tagGrammar.MatchString(tag) {
			continue
		}
		if cmp, err := semverCompare(unpublished[0], tag); err != nil || cmp <= 0 {
			return fmt.Errorf("%s has no local tag but is not higher than the existing tag %s", unpublished[0], tag)
		}
	}
	return nil
}

// keepOrHead keeps the commit label of the existing header when it names a
// commit in the history of HEAD (so a second run changes nothing), otherwise
// it is the short HEAD commit.
func (c *checker) keepOrHead(label string) (string, error) {
	head, err := c.git("rev-parse", "--verify", "HEAD^{commit}")
	if err != nil {
		return "", err
	}
	if label != "" {
		if full, err := c.git("rev-parse", "--verify", "--end-of-options", label+"^{commit}"); err == nil {
			if _, err := c.git("merge-base", "--is-ancestor", full, head); err == nil {
				return label, nil
			}
		}
	}
	short, err := c.git("rev-parse", "--short=12", "--verify", head+"^{commit}")
	if err != nil {
		return "", err
	}
	return short, nil
}

func regenFailure(fs []Finding) error {
	if len(fs) == 0 {
		return errors.New("regeneration failed")
	}
	sorted := append([]Finding(nil), fs...)
	sort.SliceStable(sorted, func(i, j int) bool { return sorted[i].Code < sorted[j].Code })
	var parts []string
	for _, f := range sorted {
		parts = append(parts, f.Msg)
	}
	return &RegenError{Code: sorted[0].Code, Msg: strings.Join(parts, "; ")}
}

// regenWriter writes whole files atomically and remembers the original bytes
// of each, so a later failure can restore them.
type regenWriter struct {
	root  string
	order []string
	orig  map[string]*origFile
}

type origFile struct {
	data   []byte
	mode   os.FileMode
	exists bool
}

func (w *regenWriter) abs(rel string) string { return filepath.Join(w.root, filepath.FromSlash(rel)) }

// remember records the current state of rel; it refuses anything that is not
// a regular file inside the root (a link or a special file, as the file or as
// a parent directory, is never followed or replaced).
func (w *regenWriter) remember(rel string) error {
	if w.orig == nil {
		w.orig = map[string]*origFile{}
	}
	if _, ok := w.orig[rel]; ok {
		return nil
	}
	p := w.abs(rel)
	dir, err := filepath.EvalSymlinks(filepath.Dir(p))
	// The root is already resolved, so any difference is a linked parent.
	if err != nil || dir != filepath.Dir(p) {
		return fmt.Errorf("%s: a parent directory is missing or is a symbolic link", rel)
	}
	st, err := os.Lstat(p)
	switch {
	case errors.Is(err, os.ErrNotExist):
		w.orig[rel] = &origFile{mode: 0o644}
	case err != nil:
		return fmt.Errorf("%s: %v", rel, err)
	case !st.Mode().IsRegular():
		return fmt.Errorf("%s is not a regular file", rel)
	default:
		data, err := readBounded(p)
		if err != nil {
			return err
		}
		w.orig[rel] = &origFile{data: data, mode: st.Mode().Perm(), exists: true}
	}
	w.order = append(w.order, rel)
	return nil
}

func (w *regenWriter) write(rel string, data []byte) error {
	if err := w.remember(rel); err != nil {
		return err
	}
	return atomicWrite(w.abs(rel), data, w.orig[rel].mode)
}

// guardBlocks snapshots every file of the layout's generated blocks before the
// generator rewrites them, so they can be restored.
func (w *regenWriter) guardBlocks(g Generator) error {
	for _, rel := range blockPaths() {
		if err := w.remember(rel); err != nil {
			return err
		}
	}
	_, err := g.Blocks(w.root)
	return err
}

func (w *regenWriter) changed() []string {
	var out []string
	for _, rel := range w.order {
		o := w.orig[rel]
		now, err := os.ReadFile(w.abs(rel))
		if err != nil && !o.exists {
			continue
		}
		if err != nil || !o.exists || string(now) != string(o.data) {
			out = append(out, rel)
		}
	}
	sort.Strings(out)
	return out
}

// rollback restores every remembered file that differs from its original. It
// tries all of them and returns an error naming those it could not restore.
func (w *regenWriter) rollback() error {
	var names []string
	var causes []error
	for _, rel := range w.order {
		if err := w.restore(rel); err != nil {
			names = append(names, rel)
			causes = append(causes, err)
		}
	}
	if len(names) == 0 {
		return nil
	}
	return fmt.Errorf("restore failed, these files are NOT restored: %s: %w", strings.Join(names, ", "), errors.Join(causes...))
}

func (w *regenWriter) restore(rel string) error {
	o, p := w.orig[rel], w.abs(rel)
	if !o.exists {
		if err := os.Remove(p); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return nil
	}
	if st, err := os.Lstat(p); err == nil && st.Mode().IsRegular() && st.Mode().Perm() == o.mode {
		if now, err := readBounded(p); err == nil && bytes.Equal(now, o.data) {
			return nil
		}
	}
	return atomicWrite(p, o.data, o.mode)
}

// atomicWrite replaces path through a temporary file and a rename.
func atomicWrite(path string, data []byte, mode os.FileMode) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".regen-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	_, werr := f.Write(data)
	cerr := f.Close()
	if werr != nil || cerr != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("cannot write %s", filepath.Base(path))
	}
	if err := os.Chmod(tmp, mode); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}
