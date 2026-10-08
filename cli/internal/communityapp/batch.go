// SPDX-License-Identifier: AGPL-3.0-only

package communityapp

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"time"

	"github.com/prufyx/prufyx/cli/internal/batchcheck"
)

func (r runtime) batch(args []string) int {
	if hasHelp(args) {
		if _, err := fmt.Fprintln(r.stdout, "Usage:\n  prufyx check batch --plan FILE --root DIR --now RFC3339 [--format human|json] [--exit-mode legacy|detailed]\n  prufyx check batch --plan FILE --root DIR --knowledge-db DIR [--format human|json] [--exit-mode legacy|detailed]\nEmbedded plans require --now. Plans declaring external_cncf_embedded_community require one selected signed local CNCF store through --knowledge-db and reject --now; its verifier clock evaluates every CNCF and neutral community item. All plans and files are preflighted before a store opens. No cluster, network, subprocess, or raw-input output is used. The store path and operator labels are not reported."); err != nil {
			return ExitIntegrity
		}
		return ExitOK
	}
	fs := flag.NewFlagSet("check batch", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	plan := fs.String("plan", "", "batch plan JSON")
	root := fs.String("root", "", "root directory for relative item inputs")
	nowText := fs.String("now", "", "explicit UTC evaluation time")
	storeRoot := fs.String("knowledge-db", "", "selected signed local CNCF knowledge store")
	format := fs.String("format", "human", "human or json")
	exitMode := fs.String("exit-mode", "legacy", "legacy or detailed")
	nowProvided, storeProvided := flagProvided(args, "now"), flagProvided(args, "knowledge-db")
	if duplicateFlags(args) || fs.Parse(args) != nil || fs.NArg() != 0 || *plan == "" || *root == "" || nowProvided == storeProvided || nowProvided && *nowText == "" || storeProvided && *storeRoot == "" || (*format != "human" && *format != "json") || (*exitMode != "legacy" && *exitMode != "detailed") {
		return r.usage("invalid batch check arguments; use --help")
	}
	var report batchcheck.Report
	var exit int
	var err error
	if *storeRoot != "" {
		report, exit, err = batchcheck.EvaluateWithStore(*plan, *root, *storeRoot)
	} else {
		now, parseErr := time.Parse(time.RFC3339, *nowText)
		if parseErr != nil || now.Location() != time.UTC || now.Nanosecond() != 0 || now.Format(time.RFC3339) != *nowText {
			return r.usage("invalid batch check UTC time; use --help")
		}
		report, exit, err = batchcheck.Evaluate(*plan, *root, now)
	}
	if err != nil {
		if exit == ExitIntegrity {
			return r.fail("batch check integrity failure", ExitIntegrity)
		}
		if exit == ExitUnknown {
			return r.fail("batch check has no verified signed CNCF revision selected", ExitUnknown)
		}
		return r.fail("batch check input failed admission", ExitUsage)
	}
	exit, exitErr := batchcheck.ExitForMode(report, *exitMode)
	if exitErr != nil {
		return r.fail("invalid batch exit mode", ExitUsage)
	}
	if *format == "json" {
		encoded, encodeErr := json.Marshal(report)
		if encodeErr != nil {
			return r.fail("batch report encoding failed", ExitIntegrity)
		}
		encoded = append(encoded, '\n')
		if n, writeErr := r.stdout.Write(encoded); writeErr != nil || n != len(encoded) {
			return ExitIntegrity
		}
		r.knowledgeAgeNote(batchAgeNote(report))
		return exit
	}
	var output bytes.Buffer
	fmt.Fprintf(&output, "batch check: %s\nevaluated at: %s\nknowledge: %s\n", report.AggregateCategory, report.EvaluatedAt, report.KnowledgeMode)
	if report.KnowledgeRevision != "" {
		fmt.Fprintf(&output, "knowledge revision: %s\nknowledge bundle digest: %s\nknowledge trust receipt digest: %s\n", report.KnowledgeRevision, report.KnowledgeBundleDigest, report.KnowledgeTrustReceiptDigest)
	}
	for _, item := range report.Items {
		fmt.Fprintf(&output, "%s: %s (%s; %s; knowledge %s)\n", item.ID, item.Outcome, item.Category, item.ReasonCode, item.KnowledgeOrigin)
		for _, note := range item.Notes() {
			fmt.Fprintf(&output, "  %s\n", note)
		}
	}
	fmt.Fprintln(&output, "compatibility decision: UNKNOWN")
	if n, writeErr := r.stdout.Write(output.Bytes()); writeErr != nil || n != output.Len() {
		return ExitIntegrity
	}
	r.knowledgeAgeNote(batchAgeNote(report))
	return exit
}
