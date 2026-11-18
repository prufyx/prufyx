// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/prufyx/prufyx/cli/internal/maintainer/releasenotes"
)

const releaseNotesUsage = "release-notes: usage: prufyx-maintainer release-notes (--from REV --previous-counts-sha256 HEX [--to REV] [--repo DIR] | --from-dir DIR --to-dir DIR) [--to-label NAME] [--omit-merged-prs] [--bind-counts] [--level 3|4] [--out FILE | --into FILE [--check]]"

// runReleaseNotes prints, as Markdown, what the data files of one tree add to
// another: projects, rules, line attestations, onboarding batches and the
// coverage figures. It compares two git revisions of a repository (the default
// for --to is HEAD) or two checked-out directories, and evaluates no rule.
func runReleaseNotes(args []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("release-notes", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	repo := flags.String("repo", ".", "git repository for --from and --to")
	fromRev := flags.String("from", "", "previous tag or revision")
	toRev := flags.String("to", "HEAD", "revision to describe")
	fromDir := flags.String("from-dir", "", "previous tree as a directory (instead of --from)")
	toDir := flags.String("to-dir", "", "tree to describe as a directory (instead of --to)")
	toLabel := flags.String("to-label", "", "name for the tree to describe in the output (default: --to); pass the same value on every regeneration")
	out := flags.String("out", "", "write the Markdown to this file (default: stdout)")
	into := flags.String("into", "", "replace the block between the "+releasenotes.MarkerBegin+" and "+releasenotes.MarkerEnd+" lines of this Markdown file")
	check := flags.Bool("check", false, "with --into: do not write; exit 1 when the block of the file differs from the regeneration")
	prevSha := flags.String("previous-counts-sha256", "", "sha256 of the previous release's counts file (required with --from)")
	omitPRs := flags.Bool("omit-merged-prs", false, "omit the merged pull request list")
	bindCounts := flags.Bool("bind-counts", false, "name the described tree by the sha256 of its counts file instead of a commit (rebase-stable; for notes of an unreleased tree)")
	level := flags.Int("level", 3, "heading level of the sections: 3, or 4 under the level-3 categories of a CHANGELOG entry")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 || (*out != "" && *into != "") || (*check && *into == "") || (*level != 3 && *level != 4) {
		return &commandError{code: 2, message: releaseNotesUsage, err: err}
	}
	var from, to releasenotes.Tree
	var pin releasenotes.PreviousPin
	opts := releasenotes.Options{}
	switch {
	case *fromRev != "" && *fromDir == "" && *toDir == "":
		from = releasenotes.GitTree{Repo: *repo, Rev: *fromRev}
		to = releasenotes.GitTree{Repo: *repo, Rev: *toRev}
		opts.FromLabel, opts.ToLabel = *fromRev, *toRev
		if *toLabel != "" {
			opts.ToLabel = *toLabel
		}
		var err error
		if opts.FromCommit, err = releasenotes.Commit(*repo, *fromRev); err != nil {
			return &commandError{code: 2, message: "release-notes: cannot resolve --from", err: err}
		}
		if opts.ToCommit, err = releasenotes.Commit(*repo, *toRev); err != nil {
			return &commandError{code: 2, message: "release-notes: cannot resolve --to", err: err}
		}
		if *bindCounts {
			opts.ToCommit = ""
		}
		pin = releasenotes.PreviousPin{Tag: *fromRev, Commit: opts.FromCommit}
		if ok, err := releasenotes.IsAncestor(*repo, *fromRev, *toRev); err != nil || !ok {
			return &commandError{code: 2, message: "release-notes: --from is not an ancestor of --to", err: err}
		}
		if !*omitPRs {
			prs, err := releasenotes.MergedPRs(*repo, *fromRev, *toRev)
			if err != nil {
				return &commandError{code: 2, message: "release-notes: cannot list the merged pull requests", err: err}
			}
			opts.PRs = prs
		}
	case *fromDir != "" && *toDir != "" && *fromRev == "" && *prevSha == "":
		from = releasenotes.DirTree{Root: *fromDir}
		to = releasenotes.DirTree{Root: *toDir}
		opts.FromLabel, opts.ToLabel = *fromDir, *toDir
		pin = releasenotes.PreviousPin{Tag: *fromDir, Commit: "tree directory"}
		opts.PRNote = "Merged pull requests are listed only when the trees are git revisions."
	default:
		return &commandError{code: 2, message: releaseNotesUsage}
	}
	a, err := releasenotes.ReadSnapshot(from)
	if err != nil {
		return &commandError{code: 2, message: "release-notes: cannot read the previous tree", err: err}
	}
	b, err := releasenotes.ReadSnapshot(to)
	if err != nil {
		return &commandError{code: 2, message: "release-notes: cannot read the tree to describe", err: err}
	}
	if opts.Cur, err = releasenotes.ReadCounts(to, releasenotes.CountsPath); err != nil {
		return &commandError{code: 2, message: "release-notes: cannot read the counts of the tree to describe", err: err}
	}
	if *fromRev != "" {
		opts.Prev, err = releasenotes.ReadPreviousCounts(from, to, *fromRev, *prevSha)
	} else {
		opts.Prev, err = releasenotes.ReadCounts(from, releasenotes.CountsPath)
	}
	if err != nil {
		return &commandError{code: 2, message: "release-notes: cannot read the counts of the previous release", err: err}
	}
	pin.CountsSha256 = opts.Prev.Sha256
	opts.Previous = pin
	opts.BindToCounts = *bindCounts
	opts.OmitMergedPRs = *omitPRs
	opts.Level = *level
	text, err := releasenotes.Render(a, b, opts)
	if err != nil {
		return &commandError{code: 2, message: "release-notes: " + err.Error(), err: err}
	}
	if *into != "" {
		doc, err := os.ReadFile(*into)
		if err != nil {
			return &commandError{code: 2, message: "release-notes: cannot read the file", err: err}
		}
		updated, err := releasenotes.ReplaceBlock(string(doc), text)
		if err != nil {
			return &commandError{code: 2, message: "release-notes: " + err.Error(), err: err}
		}
		if *check {
			if updated != string(doc) {
				return &commandError{code: 1, message: "release-notes: the generated block of " + *into + " differs from its regeneration; rerun with --into (and the same --from, --to and --to-label) to update it"}
			}
			return nil
		}
		if err := os.WriteFile(*into, []byte(updated), 0o644); err != nil {
			return &commandError{code: 2, message: "release-notes: cannot write the file", err: err}
		}
		return nil
	}
	if *out == "" {
		_, err = io.WriteString(stdout, text)
	} else {
		err = os.WriteFile(*out, []byte(text), 0o644)
	}
	if err != nil {
		return &commandError{code: 2, message: fmt.Sprintf("release-notes: cannot write the output: %v", err), err: err}
	}
	return nil
}
