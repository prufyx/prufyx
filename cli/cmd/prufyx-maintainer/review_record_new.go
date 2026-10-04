// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/prufyx/prufyx/cli/internal/maintainer/evidencereattest"
	"github.com/prufyx/prufyx/cli/internal/maintainer/sourcecorpus"
)

const reviewRecordNewUsage = "usage: prufyx-maintainer review-record new --statement ABS --pack cncf|community --rules ABS --worklist ABS --rule RULE_ID --reviewer NAME --decided-at RFC3339 --output ABS [--rules-worklist-path STR]"

// reviewRecordNowFunc is the clock review-record new refuses a future
// decision time against. Tests replace it.
var reviewRecordNowFunc = func() time.Time { return time.Now().UTC() }

// runReviewRecordNew writes the sample review record for one rule a
// prepared human statement sampled for full review. Every binding is
// computed by evidencereattest.NewSampleReview from the statement after it
// has been checked against the prior pack, the worklist and this binary's
// engine; nothing in the record is taken from a flag except the rule ID,
// the reviewer's name and the decision time.
func runReviewRecordNew(args []string, stdout, stderr io.Writer) error {
	rejected := func() error {
		return &commandError{code: 2, message: "review-record new: rejected"}
	}
	flags := flag.NewFlagSet("review-record new", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	var statementPath, packName, rulesPath, rulesWorklistPath, worklistPath, ruleID, reviewer, decidedAtFlag, output string
	flags.StringVar(&statementPath, "statement", "", "statement.json written by evidence reattest prepare (absolute path)")
	flags.StringVar(&packName, "pack", "", "cncf or community")
	flags.StringVar(&rulesPath, "rules", "", "the rule pack the statement was prepared from (absolute path)")
	flags.StringVar(&rulesWorklistPath, "rules-worklist-path", "", "the rule pack path as it appears in the worklist, if different from --rules")
	flags.StringVar(&worklistPath, "worklist", "", "the worklist the statement was prepared from (absolute path)")
	flags.StringVar(&ruleID, "rule", "", "the sampled rule's ID")
	flags.StringVar(&reviewer, "reviewer", "", "the reviewer's public name or handle")
	flags.StringVar(&decidedAtFlag, "decided-at", "", "exact UTC RFC3339 decision time, not before the statement's attestedAt and not in the future")
	flags.StringVar(&output, "output", "", "new record file, normally <review-record-dir>/<rule id>.json (absolute path; never overwritten)")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			_, e := fmt.Fprintln(stdout, reviewRecordNewUsage)
			return e
		}
		return rejected()
	}
	if flags.NArg() != 0 || duplicateFlag(args) || statementPath == "" || rulesPath == "" || worklistPath == "" || ruleID == "" || reviewer == "" || decidedAtFlag == "" || output == "" || !filepath.IsAbs(output) {
		return rejected()
	}
	if packName != evidencereattest.PackCNCF && packName != evidencereattest.PackCommunity {
		return rejected()
	}
	if rulesWorklistPath == "" {
		rulesWorklistPath = rulesPath
	}
	decidedAt, err := time.Parse(time.RFC3339, decidedAtFlag)
	if err != nil || decidedAt.UTC().Format(time.RFC3339) != decidedAtFlag {
		return rejected()
	}
	statementRaw, err := readCanonicalInput(statementPath, evidencereattest.MaxStatementBytes)
	if err != nil {
		return rejected()
	}
	packRaw, err := readReattestInput(rulesPath, evidencereattest.MaxPackBytes)
	if err != nil {
		return rejected()
	}
	worklistRaw, err := readReattestInput(worklistPath, evidencereattest.MaxWorklistBytes)
	if err != nil {
		return rejected()
	}
	capability, err := engineCapabilityDigestFor(packName)
	if err != nil {
		return rejected()
	}
	record, err := evidencereattest.NewSampleReview(evidencereattest.SampleReviewOptions{
		StatementRaw: statementRaw, PriorPackRaw: packRaw, WorklistRaw: worklistRaw,
		PackName: packName, PackPath: rulesWorklistPath, EngineCapabilityDigest: capability,
		RuleID: ruleID, Reviewer: reviewer, DecidedAt: decidedAt.UTC(), Now: reviewRecordNowFunc(),
	})
	if err != nil {
		fmt.Fprintf(stderr, "review-record new: %v\n", err)
		return &commandError{code: 2, message: "review-record new: rejected", printed: true}
	}
	if filepath.Base(output) != ruleID+".json" {
		fmt.Fprintf(stderr, "review-record new: the output file must be named %s.json\n", ruleID)
		return &commandError{code: 2, message: "review-record new: rejected", printed: true}
	}
	file, err := os.OpenFile(output, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		fmt.Fprintf(stderr, "review-record new: cannot create %s (it must not exist yet)\n", filepath.Base(output))
		return &commandError{code: 2, message: "review-record new: rejected", printed: true}
	}
	_, writeErr := file.Write(record)
	closeErr := file.Close()
	if writeErr != nil || closeErr != nil {
		return rejected()
	}
	fmt.Fprintf(stdout, "review-record new: rule=%s recordDigest=%s\n", ruleID, sourcecorpus.SHA(record))
	return nil
}

// duplicateFlag reports whether any flag is given more than once.
func duplicateFlag(args []string) bool {
	seen := map[string]bool{}
	for _, arg := range args {
		if len(arg) < 2 || arg[0] != '-' || arg == "--" {
			continue
		}
		name := arg[1:]
		if name[0] == '-' {
			name = name[1:]
		}
		for i := 0; i < len(name); i++ {
			if name[i] == '=' {
				name = name[:i]
				break
			}
		}
		if name == "" {
			continue
		}
		if seen[name] {
			return true
		}
		seen[name] = true
	}
	return false
}
