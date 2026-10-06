// SPDX-License-Identifier: AGPL-3.0-only

package rulecheck

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"time"
)

// citationDeps are the network dependencies of verify-citations; tests
// inject fakes, production passes nil.
type citationDeps struct {
	resolver RevisionResolver
	fetcher  Fetcher
}

// runVerifyCitations implements `prufyx-maintainer rule verify-citations
// [--rules <pack.json>] [--out <report.json>] [--concurrency n]`. It reads
// every rule of the pack, verifies each cited source (revision is a commit,
// whole-file sha256 equals contentDigest), writes the JSON report, and exits
// 0 only when every citation passes, 1 on any finding, 2 on a usage or I/O
// error. It only reads from GitHub and never modifies a pack. There is no
// flag that skips or downgrades a check.
func runVerifyCitations(args []string, stdout, stderr io.Writer, defaults CLIOptions, deps *citationDeps) int {
	const usage = "usage: prufyx-maintainer rule verify-citations [--rules <pack.json>] [--out <report.json>] [--concurrency n]"
	flags := flag.NewFlagSet("rule verify-citations", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	rulesPath := flags.String("rules", "", "rule pack to verify (default: the embedded CNCF pack path)")
	outPath := flags.String("out", "", "write the JSON report to this file (default: stdout)")
	concurrency := flags.Int("concurrency", 4, "parallel source checks")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 || *concurrency < 1 || *concurrency > 16 {
		fmt.Fprintln(stderr, usage)
		return 2
	}
	if *rulesPath == "" {
		if len(defaults.ExistingRulesPaths) == 0 {
			fmt.Fprintln(stderr, usage)
			return 2
		}
		*rulesPath = defaults.ExistingRulesPaths[0]
	}
	raw, err := os.ReadFile(*rulesPath)
	if err != nil {
		fmt.Fprintf(stderr, "rule verify-citations: could not read %s: %v\n", *rulesPath, err)
		return 2
	}
	var pack struct {
		Entries []struct {
			Rule json.RawMessage `json:"rule"`
		} `json:"entries"`
	}
	if err := json.Unmarshal(raw, &pack); err != nil || len(pack.Entries) == 0 {
		fmt.Fprintf(stderr, "rule verify-citations: %s is not a rule pack with entries\n", *rulesPath)
		return 2
	}
	rules := make([]json.RawMessage, 0, len(pack.Entries))
	for _, entry := range pack.Entries {
		rules = append(rules, entry.Rule)
	}
	verifier := &CitationVerifier{Concurrency: *concurrency}
	if deps != nil {
		verifier.Resolver, verifier.Fetcher = deps.resolver, deps.fetcher
	} else {
		token := os.Getenv("GITHUB_TOKEN")
		if token == "" {
			token = os.Getenv("GH_TOKEN")
		}
		verifier.Resolver = GitHubObjects{Token: token}
		verifier.Fetcher = HTTPFetcher{}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	report, err := verifier.Verify(ctx, rules)
	if err != nil {
		fmt.Fprintf(stderr, "rule verify-citations: %v\n", err)
		return 2
	}
	encoded, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		fmt.Fprintf(stderr, "rule verify-citations: could not encode report: %v\n", err)
		return 2
	}
	encoded = append(encoded, '\n')
	if *outPath != "" {
		if err := os.WriteFile(*outPath, encoded, 0o644); err != nil {
			fmt.Fprintf(stderr, "rule verify-citations: could not write %s: %v\n", *outPath, err)
			return 2
		}
	} else {
		stdout.Write(encoded)
	}
	for _, finding := range report.Findings {
		fmt.Fprintf(stderr, "FAIL rule=%q source=%q [%s]: %s\n", finding.RuleID, finding.SourceID, finding.Check, finding.Message)
	}
	fmt.Fprintf(stderr, "verify-citations: %d rules, %d sources, %d findings in %d rules\n", report.RulesChecked, report.SourcesChecked, len(report.Findings), len(report.FailedRules))
	if !report.Pass {
		return 1
	}
	return 0
}
