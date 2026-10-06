// SPDX-License-Identifier: AGPL-3.0-only

package rulecheck

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
)

// CLIOptions configures the "rule validate" subcommand.
type CLIOptions struct {
	// ExistingRulesPaths are the default published pack files to check
	// candidate rule IDs against, set by the caller (main.go) from the CLI
	// root so this package stays free of repo-layout assumptions.
	ExistingRulesPaths []string
}

// Run implements `prufyx-maintainer rule validate --file <candidate.json>
// [--fetch] [--print-span]`. It returns a process exit code: 0 when every
// entry validates cleanly, 1 when the candidate is well-formed JSON but has
// one or more findings, 2 for a usage error or a candidate file that could
// not even be decoded.
func Run(args []string, stdout, stderr io.Writer, defaults CLIOptions) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "usage: prufyx-maintainer rule <validate|verify-citations> ...")
		return 2
	}
	switch args[0] {
	case "validate":
		return runValidate(args[1:], stdout, stderr, defaults)
	case "verify-citations":
		return runVerifyCitations(args[1:], stdout, stderr, defaults, nil)
	default:
		fmt.Fprintf(stderr, "rule: unknown subcommand %q\n", args[0])
		return 2
	}
}

func runValidate(args []string, stdout, stderr io.Writer, defaults CLIOptions) int {
	flags := flag.NewFlagSet("rule validate", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	filePath := flags.String("file", "", "candidate rule file (JSON array of pack entries)")
	fetch := flags.Bool("fetch", false, "opt in to the online check: fetch each cited blob and verify contentDigest and endLine")
	printSpan := flags.Bool("print-span", false, "print the cited lines for each evidence source")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 || *filePath == "" {
		fmt.Fprintln(stderr, "usage: prufyx-maintainer rule validate --file <candidate.json> [--fetch] [--print-span]")
		return 2
	}
	raw, err := os.ReadFile(*filePath)
	if err != nil {
		fmt.Fprintf(stderr, "rule validate: could not read %s: %v\n", *filePath, err)
		return 2
	}
	opts := Options{
		Fetch:              *fetch,
		PrintSpan:          *printSpan,
		ExistingRulesPaths: defaults.ExistingRulesPaths,
	}
	if *fetch {
		opts.Fetcher = HTTPFetcher{}
	}
	result, err := Validate(raw, opts)
	if err != nil {
		fmt.Fprintf(stderr, "rule validate: %v\n", err)
		return 2
	}
	encoded, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		fmt.Fprintf(stderr, "rule validate: could not encode result: %v\n", err)
		return 2
	}
	fmt.Fprintln(stdout, string(encoded))
	if *printSpan {
		printSpans(stdout, stderr, result.Spans, *fetch)
	}
	for _, finding := range result.Findings {
		fmt.Fprintf(stderr, "FAIL entry %d rule=%q [%s]: %s\n", finding.EntryIndex, finding.RuleID, finding.Check, finding.Message)
	}
	if !result.Valid {
		return 1
	}
	return 0
}

func printSpans(stdout, stderr io.Writer, spans []Span, fetch bool) {
	for _, span := range spans {
		fmt.Fprintf(stdout, "\n--- %s (%s:%d-%d) ---\n", span.RuleID, span.SourceID, span.StartLine, span.EndLine)
		fmt.Fprintf(stdout, "%s\n", span.URL)
		if !fetch {
			fmt.Fprintln(stdout, "(re-run with --fetch to print the cited lines)")
			continue
		}
		owner, repo, revision, ok := githubBlobURL(span.URL)
		if !ok || revision != span.Revision {
			fmt.Fprintln(stderr, "rule validate: could not re-derive the raw URL for", span.URL)
			continue
		}
		lines, err := PrintSpanLines(context.Background(), HTTPFetcher{}, span, owner, repo)
		if err != nil {
			fmt.Fprintf(stderr, "rule validate: could not print span for %s: %v\n", span.RuleID, err)
			continue
		}
		for _, line := range lines {
			fmt.Fprintln(stdout, line)
		}
	}
}
