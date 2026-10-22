// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/prufyx/prufyx/cli/internal/maintainer/releasenotes"
)

const releaseNotesUsage = "release-notes: usage: prufyx-maintainer release-notes (--from REV [--to REV] [--repo DIR] | --from-dir DIR --to-dir DIR) [--level 3|4] [--out FILE | --into FILE]"

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
	out := flags.String("out", "", "write the Markdown to this file (default: stdout)")
	into := flags.String("into", "", "replace the block between the "+releasenotes.MarkerBegin+" and "+releasenotes.MarkerEnd+" lines of this Markdown file")
	level := flags.Int("level", 3, "heading level of the sections: 3, or 4 under the level-3 categories of a CHANGELOG entry")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 || (*out != "" && *into != "") || (*level != 3 && *level != 4) {
		return &commandError{code: 2, message: releaseNotesUsage, err: err}
	}
	var from, to releasenotes.Tree
	opts := releasenotes.Options{}
	switch {
	case *fromRev != "" && *fromDir == "" && *toDir == "":
		from = releasenotes.GitTree{Repo: *repo, Rev: *fromRev}
		to = releasenotes.GitTree{Repo: *repo, Rev: *toRev}
		opts.FromLabel, opts.ToLabel = *fromRev, *toRev
		var err error
		if opts.FromCommit, err = releasenotes.Commit(*repo, *fromRev); err != nil {
			return &commandError{code: 2, message: "release-notes: cannot resolve --from", err: err}
		}
		if opts.ToCommit, err = releasenotes.Commit(*repo, *toRev); err != nil {
			return &commandError{code: 2, message: "release-notes: cannot resolve --to", err: err}
		}
		prs, err := releasenotes.MergedPRs(*repo, *fromRev, *toRev)
		if err != nil {
			return &commandError{code: 2, message: "release-notes: cannot list the merged pull requests", err: err}
		}
		opts.PRs = prs
	case *fromDir != "" && *toDir != "" && *fromRev == "":
		from = releasenotes.DirTree{Root: *fromDir}
		to = releasenotes.DirTree{Root: *toDir}
		opts.FromLabel, opts.ToLabel = *fromDir, *toDir
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
	opts.Level = *level
	text := releasenotes.Render(a, b, opts)
	if *into != "" {
		doc, err := os.ReadFile(*into)
		if err != nil {
			return &commandError{code: 2, message: "release-notes: cannot read the file", err: err}
		}
		updated, err := releasenotes.ReplaceBlock(string(doc), text)
		if err != nil {
			return &commandError{code: 2, message: "release-notes: " + err.Error(), err: err}
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
