// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/prufyx/prufyx/cli/internal/cncfcheck"
	"github.com/prufyx/prufyx/cli/internal/maintainer/coveragereport"
	"github.com/prufyx/prufyx/cli/internal/maintainer/knowledgegate"
)

const maxCoverageInput = 32 << 20

func readBounded(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, maxCoverageInput+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > maxCoverageInput {
		return nil, fmt.Errorf("input exceeds %d bytes", maxCoverageInput)
	}
	return raw, nil
}

// runCoverage serves the reporting-only coverage commands. They read a rule
// pack and a snapshot of release lines and never evaluate a rule.
func runCoverage(args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		return &commandError{code: 2, message: "usage: prufyx-maintainer coverage <report|readme|preview|lines-from-tags> [options]"}
	}
	switch args[0] {
	case "report":
		return runCoverageReport(args[1:], stdout)
	case "readme":
		return runCoverageReadme(args[1:], stdout, stderr)
	case "preview":
		return runCoveragePreview(args[1:], stdout)
	case "lines-from-tags":
		return runCoverageLinesFromTags(args[1:], stdout)
	}
	return &commandError{code: 2, message: "usage: prufyx-maintainer coverage <report|readme|preview|lines-from-tags> [options]"}
}

// runCoverageReadme regenerates the coverage block of README.md from the
// tree's own data (the one implementation, also the gate's), or with --check
// fails when the block is stale.
func runCoverageReadme(args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("coverage readme", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	check := flags.Bool("check", false, "do not write; fail if the README coverage block differs from its regeneration")
	root := flags.String("root", ".", "repository root")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 {
		return &commandError{code: 2, message: "coverage readme: usage: [--check] [--root DIR]"}
	}
	abs, err := filepath.Abs(*root)
	if err != nil {
		return &commandError{code: 2, message: "coverage readme: root is unusable", err: err}
	}
	changed, err := knowledgegate.RegenerateBlocks(abs, *check, "README.md")
	if err != nil {
		return &commandError{code: 2, message: "coverage readme: cannot regenerate the block", err: err}
	}
	if *check && len(changed) > 0 {
		return &commandError{code: 1, message: strings.Join(changed, ", ") + " coverage block is stale; run scripts/readme-coverage.sh"}
	}
	for _, p := range changed {
		fmt.Fprintf(stdout, "updated %s\n", p)
	}
	return nil
}

// runCoveragePreview regenerates the rule-count sentences of
// cli/docs/CNCF-SOURCE-PREVIEW.md from the generated support inventory (the
// one implementation, also the gate's), or with --check fails when stale.
func runCoveragePreview(args []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("coverage preview", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	check := flags.Bool("check", false, "do not write; fail if the preview counts differ from their regeneration")
	root := flags.String("root", ".", "repository root")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 {
		return &commandError{code: 2, message: "coverage preview: usage: [--check] [--root DIR]"}
	}
	abs, err := filepath.Abs(*root)
	if err != nil {
		return &commandError{code: 2, message: "coverage preview: root is unusable", err: err}
	}
	changed, err := knowledgegate.RegenerateBlocks(abs, *check, knowledgegate.PreviewPath)
	if err != nil {
		return &commandError{code: 2, message: "coverage preview: cannot regenerate the counts", err: err}
	}
	if *check && len(changed) > 0 {
		return &commandError{code: 1, message: "CNCF-SOURCE-PREVIEW.md counts are stale; run scripts/preview-coverage.sh"}
	}
	for _, p := range changed {
		fmt.Fprintf(stdout, "updated %s\n", p)
	}
	return nil
}

func runCoverageReport(args []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("coverage report", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	packPath := flags.String("pack", "", "rule pack file (default: the embedded pack)")
	linesPath := flags.String("lines", "", "lines snapshot file (required)")
	nowText := flags.String("now", "", "evaluation time, RFC 3339 UTC (required)")
	windowText := flags.String("window", "", "lines per project window: a number (default 6) or ALL for every line from minFrom")
	declaredPath := flags.String("declared", "", "declared-unknown file (ALL window only; default: the embedded file)")
	completeOnly := flags.Bool("complete", false, "print the projects whose complete is true, one per line (implies --window ALL)")
	jsonOut := flags.String("json-out", "", "write the JSON report to this file")
	mdOut := flags.String("md-out", "", "write the Markdown summary to this file")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 || *linesPath == "" || *nowText == "" {
		return &commandError{code: 2, message: "coverage report: usage: --lines FILE --now RFC3339 [--pack FILE] [--window N|ALL] [--declared FILE] [--complete] [--json-out FILE] [--md-out FILE]"}
	}
	all, window := false, 0
	switch {
	case *windowText == "ALL":
		all = true
	case *windowText != "":
		n, err := strconv.Atoi(*windowText)
		if err != nil {
			return &commandError{code: 2, message: "coverage report: --window is not a number or ALL", err: err}
		}
		window = n
	}
	if *completeOnly {
		if *windowText != "" && !all {
			return &commandError{code: 2, message: "coverage report: --complete uses the ALL window and takes no --window N"}
		}
		if *jsonOut != "" || *mdOut != "" {
			return &commandError{code: 2, message: "coverage report: --complete prints the project list and takes no --json-out or --md-out"}
		}
		all = true
	}
	if *declaredPath != "" && !all {
		return &commandError{code: 2, message: "coverage report: --declared needs --window ALL or --complete"}
	}
	now, err := time.Parse(time.RFC3339, *nowText)
	if err != nil {
		return &commandError{code: 2, message: "coverage report: --now is not an RFC 3339 time", err: err}
	}
	var pack []byte
	if *packPath == "" {
		pack, err = cncfcheck.EmbeddedRulePack()
	} else {
		pack, err = readBounded(*packPath)
	}
	if err != nil {
		return &commandError{code: 2, message: "coverage report: pack is unreadable", err: err}
	}
	lines, err := readBounded(*linesPath)
	if err != nil {
		return &commandError{code: 2, message: "coverage report: lines file is unreadable", err: err}
	}
	var declared []byte
	if *declaredPath != "" {
		if declared, err = readBounded(*declaredPath); err != nil {
			return &commandError{code: 2, message: "coverage report: declared file is unreadable", err: err}
		}
	}
	report, err := coveragereport.Compute(coveragereport.Input{Pack: pack, Lines: lines, Now: now, Window: window, All: all, Declared: declared, CRDVersionProjects: coveragereport.CRDProjectCount(), CRDTargetComponents: coveragereport.CRDProjectComponents()})
	if err != nil {
		return &commandError{code: 2, message: "coverage report: input rejected", err: err}
	}
	if *completeOnly {
		for _, project := range report.CompleteProjects() {
			if _, err := fmt.Fprintln(stdout, project); err != nil {
				return err
			}
		}
		return nil
	}
	raw, err := report.JSON()
	if err != nil {
		return &commandError{code: 2, message: "coverage report: encoding failed", err: err}
	}
	if *jsonOut == "" && *mdOut == "" {
		_, err = stdout.Write(raw)
		return err
	}
	if *jsonOut != "" {
		if err := os.WriteFile(filepath.Clean(*jsonOut), raw, 0o644); err != nil {
			return &commandError{code: 2, message: "coverage report: cannot write JSON", err: err}
		}
	}
	if *mdOut != "" {
		if err := os.WriteFile(filepath.Clean(*mdOut), report.Markdown(), 0o644); err != nil {
			return &commandError{code: 2, message: "coverage report: cannot write Markdown", err: err}
		}
	}
	return nil
}

// runCoverageLinesFromTags converts tag listings that an operator captured
// separately (for example with git ls-remote --tags) into a lines snapshot.
// It performs no network access.
func runCoverageLinesFromTags(args []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("coverage lines-from-tags", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	dir := flags.String("tags-dir", "", "directory of <project>.tags files (required)")
	out := flags.String("out", "", "lines snapshot to write (required)")
	priority := flags.String("priority", "", "comma-separated priority project slugs")
	captured := flags.String("captured-on", "", "snapshot date, YYYY-MM-DD")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 || *dir == "" || *out == "" {
		return &commandError{code: 2, message: "coverage lines-from-tags: usage: --tags-dir DIR --out FILE [--priority a,b] [--captured-on YYYY-MM-DD]"}
	}
	entries, err := os.ReadDir(*dir)
	if err != nil {
		return &commandError{code: 2, message: "coverage lines-from-tags: directory is unreadable", err: err}
	}
	listings := map[string][]byte{}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".tags") {
			continue
		}
		raw, err := readBounded(filepath.Join(*dir, name))
		if err != nil {
			return &commandError{code: 2, message: "coverage lines-from-tags: a tag file is unreadable", err: err}
		}
		listings[strings.TrimSuffix(name, ".tags")] = raw
	}
	prio := map[string]bool{}
	for _, p := range strings.Split(*priority, ",") {
		if p = strings.TrimSpace(p); p != "" {
			prio[p] = true
		}
	}
	file, err := coveragereport.LinesFromTags(listings, prio, *captured)
	if err != nil {
		return &commandError{code: 2, message: "coverage lines-from-tags: input rejected", err: err}
	}
	raw, err := coveragereport.MarshalLines(file)
	if err != nil {
		return &commandError{code: 2, message: "coverage lines-from-tags: encoding failed", err: err}
	}
	if err := os.WriteFile(filepath.Clean(*out), raw, 0o644); err != nil {
		return &commandError{code: 2, message: "coverage lines-from-tags: cannot write output", err: err}
	}
	fmt.Fprintf(stdout, "wrote %d projects\n", len(file.Projects))
	return nil
}
