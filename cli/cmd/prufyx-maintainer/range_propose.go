// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime/debug"
	"time"

	"github.com/prufyx/prufyx/cli/internal/maintainer/rangepropose"
)

const rangeProposeUsage = "range propose: usage: prufyx-maintainer range-propose --rules-repo DIR --rules-commit SHA --repos FILE --out DIR [--gaps FILE]"

// runRangePropose writes unreviewed version range proposals for exact-pair
// rules from local bare clones. It uses no network, takes no key or token and
// writes only into the output directory. A completed run exits 0 whatever the
// rules showed.
func runRangePropose(args []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("range-propose", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	rulesRepo := flags.String("rules-repo", "", "local repository holding the rule pack")
	rulesCommit := flags.String("rules-commit", "", "full commit id the rule pack is read from")
	repos := flags.String("repos", "", "projects file: subject repository, local bare clone and tags per project (JSON)")
	out := flags.String("out", "", "new or empty output directory outside any git work tree")
	gaps := flags.String("gaps", "", "optional file of rule ids that orders the output")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 || *rulesRepo == "" || *rulesCommit == "" || *repos == "" || *out == "" {
		return &commandError{code: 2, message: rangeProposeUsage, err: err}
	}
	fail := func(err error) error {
		return &commandError{code: 2, message: "range propose: " + err.Error(), err: err}
	}
	// Refuse a bad output directory before doing any work.
	if _, err := rangepropose.OutputDir(*out); err != nil {
		return fail(err)
	}
	raw, err := os.ReadFile(*repos)
	if err != nil {
		return fail(errors.New("projects file unreadable"))
	}
	// The evaluation time is the clock's; no flag moves it.
	options := rangepropose.Options{RulesRepo: *rulesRepo, RulesCommit: *rulesCommit, ToolRevision: toolRevision(), Now: time.Now().UTC()}
	if options.Config, err = rangepropose.DecodeConfig(raw); err != nil {
		return fail(err)
	}
	if *gaps != "" {
		raw, err := os.ReadFile(*gaps)
		if err != nil {
			return fail(errors.New("gap list unreadable"))
		}
		if options.Gaps, err = rangepropose.ParseGaps(raw); err != nil {
			return fail(err)
		}
	}
	report, err := rangepropose.Run(context.Background(), options)
	if err != nil {
		return fail(err)
	}
	if err := rangepropose.Write(*out, report); err != nil {
		return fail(err)
	}
	_, err = fmt.Fprint(stdout, rangepropose.Summary(report))
	return err
}

// readBuildInfo is a variable so a test can state what the build recorded.
var readBuildInfo = debug.ReadBuildInfo

// toolRevision is the commit this binary was built from. It is a bare commit
// id only when the build recorded it and recorded an unmodified tree; the run
// refuses every other value.
func toolRevision() string {
	info, ok := readBuildInfo()
	if !ok {
		return "unknown"
	}
	revision, modified := "", ""
	for _, s := range info.Settings {
		switch s.Key {
		case "vcs.revision":
			revision = s.Value
		case "vcs.modified":
			modified = s.Value
		}
	}
	switch {
	case modified == "true" && revision == "":
		return "unknown+modified"
	case modified == "true":
		return revision + "+modified"
	case modified != "false" || revision == "":
		return "unknown"
	}
	return revision
}
