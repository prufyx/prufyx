// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"flag"
	"io"

	"github.com/prufyx/prufyx/cli/internal/maintainer/qareport"
)

const qaReportUsage = "qa-report: usage: prufyx-maintainer qa-report --results-dir DIR --out FILE.json --md FILE.md [--static-results FILE.tsv --static-digests FILE] [--check]"

// runQAReport regenerates the public QA report from a directory of run
// results (DIR/<run>/RESULT.json). With --check it writes nothing and exits 1
// when the committed files differ from the regeneration.
func runQAReport(args []string) error {
	flags := flag.NewFlagSet("qa-report", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	dir := flags.String("results-dir", "", "directory holding one subdirectory per run, each with a RESULT.json")
	out := flags.String("out", "", "generated JSON file")
	md := flags.String("md", "", "generated Markdown file (same directory as --out)")
	staticTSV := flags.String("static-results", "", "served-API sweep results (TSV); needs --static-digests")
	staticDig := flags.String("static-digests", "", "pinned swagger digests, one '<tag> <commit> <sha256>' per line; needs --static-results")
	check := flags.Bool("check", false, "write nothing; exit 1 when the files differ from the regeneration")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 || *dir == "" || *out == "" || *md == "" || (*staticTSV == "") != (*staticDig == "") {
		return &commandError{code: 2, message: qaReportUsage, err: err}
	}
	rep, err := qareport.Build(*dir)
	if err != nil {
		return &commandError{code: 2, message: "qa-report: " + err.Error(), err: err}
	}
	if *staticTSV != "" {
		if rep.ServedAPI, err = qareport.BuildServedAPI(*staticTSV, *staticDig); err != nil {
			return &commandError{code: 2, message: "qa-report: " + err.Error(), err: err}
		}
	}
	jsonDoc, mdDoc, err := qareport.Render(rep)
	if err != nil {
		return &commandError{code: 2, message: "qa-report: " + err.Error(), err: err}
	}
	if *check {
		a, b, err := readOutputPair(*out, *md)
		if err != nil {
			return &commandError{code: 2, message: "qa-report: cannot read the generated files", err: err}
		}
		if !bytes.Equal(a, jsonDoc) || !bytes.Equal(b, mdDoc) {
			return &commandError{code: 1, message: "qa-report: the generated files differ from their regeneration; rerun without --check"}
		}
		return nil
	}
	if err := writeOutputPair(*out, jsonDoc, *md, mdDoc); err != nil {
		return &commandError{code: 2, message: "qa-report: cannot write the generated files: " + err.Error(), err: err}
	}
	return nil
}
