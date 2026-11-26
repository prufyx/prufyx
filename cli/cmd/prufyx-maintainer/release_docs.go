// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"

	"github.com/prufyx/prufyx/cli/internal/maintainer/releasedocs"
)

const releaseDocsUsage = "release-docs: usage: prufyx-maintainer release-docs check --root DIR --mode unreleased|release|cut [--tag TAG --previous TAG] [--site-counts FILE] [--deny-file FILE]\n       prufyx-maintainer release-docs published --root DIR --base REV"

// runReleaseDocs is the release-docs gate: it fails (exit code of the lowest
// failed class, see releasedocs.Code*) unless the generated coverage text and
// the prose around it are consistent. It writes nothing.
func runReleaseDocs(args []string, stdout io.Writer) error {
	if len(args) > 0 && args[0] == "published" {
		return runReleaseDocsPublished(args[1:], stdout)
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
	if err := flags.Parse(args[1:]); err != nil || flags.NArg() != 0 {
		return &commandError{code: 2, message: releaseDocsUsage, err: err}
	}
	res, err := releasedocs.Check(releasedocs.Options{Root: *root, Mode: *mode, Tag: *tag, Previous: *previous, SiteCounts: *site, DenyFile: *deny})
	var usage *releasedocs.UsageError
	if errors.As(err, &usage) {
		return &commandError{code: releasedocs.CodeUsage, message: "release-docs: " + usage.Msg + "\n" + releaseDocsUsage}
	}
	if err != nil {
		return &commandError{code: 2, message: "release-docs: " + err.Error(), err: err}
	}
	return reportReleaseDocs(res, *mode, stdout)
}

// runReleaseDocsPublished is the pull request guard: the text of a published
// release may not differ from the base revision. It writes nothing.
func runReleaseDocsPublished(args []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("release-docs published", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	root := flags.String("root", "", "repository root")
	base := flags.String("base", "", "base revision of the pull request")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 {
		return &commandError{code: 2, message: releaseDocsUsage, err: err}
	}
	res, err := releasedocs.Published(*root, *base)
	if err != nil {
		return &commandError{code: releasedocs.CodeUsage, message: "release-docs: " + err.Error() + "\n" + releaseDocsUsage, err: err}
	}
	return reportReleaseDocs(res, "published", stdout)
}

func reportReleaseDocs(res releasedocs.Result, what string, stdout io.Writer) error {
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
	fmt.Fprintln(stdout, "release-docs: ok ("+what+")")
	return nil
}
