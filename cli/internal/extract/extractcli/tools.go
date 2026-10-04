// SPDX-License-Identifier: AGPL-3.0-only

package extractcli

import (
	"errors"
	"flag"
	"fmt"
	"io"

	"github.com/prufyx/prufyx/cli/internal/extract"
	"github.com/prufyx/prufyx/cli/internal/extract/extractpack"
	"github.com/prufyx/prufyx/cli/internal/extract/inventory"
)

func cmdApply(args []string, existing []string, stdout, stderr io.Writer) (int, error) {
	f := flag.NewFlagSet("extract apply", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	var runDir, pack string
	var withdraw bool
	f.StringVar(&runDir, "out", "", "run output directory (from extract run)")
	f.StringVar(&pack, "pack", "", "rule pack file to edit in place")
	f.BoolVar(&withdraw, "withdraw", false, "withdraw the rules the run no longer produces instead of adding its rules")
	if err := f.Parse(args); err != nil || f.NArg() != 0 || runDir == "" || pack == "" {
		return 2, errors.New("command rejected\n" + usage)
	}
	rep, err := extractpack.Apply(extractpack.Options{PackPath: pack, RunDir: runDir, Withdraw: withdraw, ExistingRules: existing})
	if errors.Is(err, extractpack.ErrStale) {
		fmt.Fprintf(stderr, "extract: %v\n", err)
		return 3, nil
	}
	if err != nil {
		return 2, err
	}
	if withdraw {
		fmt.Fprintf(stdout, "withdrawn %d rule(s)\n", len(rep.Withdrawn))
		for _, id := range rep.Withdrawn {
			fmt.Fprintln(stdout, "withdrawn "+id)
		}
		return 0, nil
	}
	fmt.Fprintf(stdout, "added %d rule(s), %d already present, %d attestation(s) added, %d already present\n", len(rep.Added), len(rep.Unchanged), len(rep.AttAdded), len(rep.AttUnchanged))
	for _, id := range rep.Added {
		fmt.Fprintln(stdout, "added "+id)
	}
	for _, k := range rep.AttAdded {
		fmt.Fprintln(stdout, "attested "+k)
	}
	if rep.SchemaFrom != rep.SchemaTo {
		fmt.Fprintf(stdout, "schema %s -> %s\n", rep.SchemaFrom, rep.SchemaTo)
	}
	return 0, nil
}

func cmdInventory(args []string, stdout, stderr io.Writer) (int, error) {
	var c common
	var repoArg, commit string
	f := flags("extract inventory", &c, true)
	f.StringVar(&repoArg, "repo", "", "repository, owner/name (github.com assumed) or github.com/owner/name")
	f.StringVar(&commit, "commit", "", "full commit SHA")
	if err := f.Parse(args); err != nil || f.NArg() != 0 || c.extractor == "" || repoArg == "" || commit == "" || c.out != "" {
		return 2, errors.New("command rejected\n" + usage)
	}
	if len(repoArg) > 0 && len(repoArg) < 200 && countSlashes(repoArg) == 1 {
		repoArg = "github.com/" + repoArg
	}
	repo, err := extract.ParseRepo(repoArg)
	if err != nil {
		return 2, err
	}
	_, ex, src, _, err := c.open()
	if err != nil {
		return 2, err
	}
	ctx, stop := signalContext()
	defer stop()
	doc, err := inventory.Build(ctx, ex, src, repo, commit)
	if inc, ok := inventory.IsIncomplete(err); ok {
		fmt.Fprintln(stderr, inc.Error())
		return 3, nil
	}
	if err != nil {
		return 2, err
	}
	_, err = stdout.Write(doc)
	return 0, err
}

func countSlashes(s string) int {
	n := 0
	for _, r := range s {
		if r == '/' {
			n++
		}
	}
	return n
}
