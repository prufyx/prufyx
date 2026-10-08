// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/prufyx/prufyx/cli/internal/cncfcheck"
	"github.com/prufyx/prufyx/cli/internal/maintainer/coveragereport"
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
		return &commandError{code: 2, message: "usage: prufyx-maintainer coverage <report|lines-from-tags> [options]"}
	}
	switch args[0] {
	case "report":
		return runCoverageReport(args[1:], stdout)
	case "lines-from-tags":
		return runCoverageLinesFromTags(args[1:], stdout)
	}
	return &commandError{code: 2, message: "usage: prufyx-maintainer coverage <report|lines-from-tags> [options]"}
}

func runCoverageReport(args []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("coverage report", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	packPath := flags.String("pack", "", "rule pack file (default: the embedded pack)")
	linesPath := flags.String("lines", "", "lines snapshot file (required)")
	nowText := flags.String("now", "", "evaluation time, RFC 3339 UTC (required)")
	window := flags.Int("window", coveragereport.DefaultWindow, "lines per project window")
	jsonOut := flags.String("json-out", "", "write the JSON report to this file")
	mdOut := flags.String("md-out", "", "write the Markdown summary to this file")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 || *linesPath == "" || *nowText == "" {
		return &commandError{code: 2, message: "coverage report: usage: --lines FILE --now RFC3339 [--pack FILE] [--window N] [--json-out FILE] [--md-out FILE]"}
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
	report, err := coveragereport.Compute(coveragereport.Input{Pack: pack, Lines: lines, Now: now, Window: *window})
	if err != nil {
		return &commandError{code: 2, message: "coverage report: input rejected", err: err}
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
