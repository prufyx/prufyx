// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/prufyx/prufyx/cli/internal/maintainer/releasedocs"
)

const releaseDocsUsage = "release-docs: usage: prufyx-maintainer release-docs regen --root DIR --mode unreleased | release-docs check --root DIR --mode unreleased|release|cut [--tag TAG --previous TAG] [--site-counts FILE] [--deny-file FILE] [--blocks-base COMMIT (unreleased only)]"

// runReleaseDocs is the release-docs gate: it fails (exit code of the lowest
// failed class, see releasedocs.Code*) unless the generated coverage text and
// the prose around it are consistent. It writes nothing.
func runReleaseDocs(args []string, stdout io.Writer) error {
	// Every git call of this command, the release-notes renderer's included,
	// runs without inherited git settings.
	restore, err := hardenGitEnv()
	if err != nil {
		return &commandError{code: 2, message: "release-docs: cannot clean the git environment", err: err}
	}
	defer restore()
	if len(args) > 0 && args[0] == "regen" {
		return runReleaseDocsRegen(args[1:], stdout)
	}
	if len(args) == 0 || args[0] != "check" {
		return &commandError{code: 2, message: releaseDocsUsage}
	}
	flags := flag.NewFlagSet("release-docs check", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	root := flags.String("root", "", "repository root")
	mode := flags.String("mode", "", "unreleased (CI), release (tag job) or cut (release manager, before the tag)")
	tag := flags.String("tag", "", "tag being released (release and cut)")
	previous := flags.String("previous", "", "previous release tag (release and cut)")
	site := flags.String("site-counts", "", "the site's copy of the counts file (mandatory in cut mode)")
	deny := flags.String("deny-file", "", "file with the vendor and model names to refuse, one per line (mandatory in release and cut mode)")
	blocksBase := flags.String("blocks-base", "", "unreleased: full commit id; a stale notes or CHANGELOG block passes only as that commit has it")
	if err := flags.Parse(args[1:]); err != nil || flags.NArg() != 0 {
		return &commandError{code: 2, message: releaseDocsUsage, err: err}
	}
	emptyBase := false
	flags.Visit(func(f *flag.Flag) {
		if f.Name == "blocks-base" && *blocksBase == "" {
			emptyBase = true
		}
	})
	if emptyBase {
		return &commandError{code: releasedocs.CodeUsage, message: "release-docs: --blocks-base is empty\n" + releaseDocsUsage}
	}
	res, err := releasedocs.Check(releasedocs.Options{Root: *root, Mode: *mode, Tag: *tag, Previous: *previous, SiteCounts: *site, DenyFile: *deny, BlocksBase: *blocksBase})
	var usage *releasedocs.UsageError
	if errors.As(err, &usage) {
		return &commandError{code: releasedocs.CodeUsage, message: "release-docs: " + usage.Msg + "\n" + releaseDocsUsage}
	}
	if err != nil {
		return &commandError{code: 2, message: "release-docs: " + err.Error(), err: err}
	}
	for _, n := range res.Notices {
		fmt.Fprintln(stdout, n)
	}
	if code := res.ExitCode(); code != 0 {
		var b strings.Builder
		for _, f := range res.Findings {
			fmt.Fprintf(&b, "release-docs: [%d] %s\n", f.Code, f.Msg)
		}
		return &commandError{code: code, message: strings.TrimRight(b.String(), "\n")}
	}
	fmt.Fprintln(stdout, "release-docs: ok ("+*mode+")")
	return nil
}

// runReleaseDocsRegen is the inverse of check in unreleased mode: it writes
// the generated files the check compares (see releasedocs.Regen). It reads
// files and local git objects only and writes only the generated blocks and
// the counts file.
func runReleaseDocsRegen(args []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("release-docs regen", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	root := flags.String("root", "", "repository root (the top level of a git work tree with its tags)")
	mode := flags.String("mode", "", "unreleased")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 {
		return &commandError{code: 2, message: releaseDocsUsage, err: err}
	}
	res, err := releasedocs.Regen(releasedocs.RegenOptions{Root: *root, Mode: *mode})
	var usage *releasedocs.UsageError
	if errors.As(err, &usage) {
		return &commandError{code: releasedocs.CodeUsage, message: "release-docs: " + usage.Msg + "\n" + releaseDocsUsage}
	}
	var refused *releasedocs.RegenError
	if errors.As(err, &refused) {
		return &commandError{code: refused.Code, message: fmt.Sprintf("release-docs: [%d] %v", refused.Code, err), err: err}
	}
	if err != nil {
		return &commandError{code: 2, message: "release-docs: " + err.Error(), err: err}
	}
	for _, p := range res.Changed {
		fmt.Fprintf(stdout, "updated %s\n", p)
	}
	fmt.Fprintln(stdout, "release-docs: regenerated (unreleased)")
	return nil
}

// hardenGitEnv replaces the git variables of the process environment with the
// release-docs ones and returns the function that puts the old ones back.
func hardenGitEnv() (restore func(), err error) {
	old := os.Environ()
	apply := func(env []string) error {
		for _, kv := range os.Environ() {
			if name, _, _ := strings.Cut(kv, "="); strings.HasPrefix(name, "GIT_") {
				if err := os.Unsetenv(name); err != nil {
					return err
				}
			}
		}
		for _, kv := range env {
			if name, value, _ := strings.Cut(kv, "="); strings.HasPrefix(name, "GIT_") {
				if err := os.Setenv(name, value); err != nil {
					return err
				}
			}
		}
		return nil
	}
	restore = func() { _ = apply(old) }
	if err := apply(releasedocs.GitEnv(old)); err != nil {
		restore()
		return nil, err
	}
	return restore, nil
}
