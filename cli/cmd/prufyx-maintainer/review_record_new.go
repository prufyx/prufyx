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

const reviewRecordNewUsage = "usage: prufyx-maintainer review-record new --statement ABS --pack cncf|community --rules ABS --worklist ABS --rule RULE_ID --reviewer NAME --decided-at RFC3339 --output ABS [--rules-worklist-path STR] [--individual]"

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
	individual := flags.Bool("individual", false, "write an individual review of a rule the statement renews or holds back only by the consecutive-cycle cap, instead of a sampled rule's review")
	flags.StringVar(&output, "output", "", "new record file, normally <review-record-dir>/<rule id>.json (absolute path; never overwritten)")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			_, e := fmt.Fprintln(stdout, reviewRecordNewUsage)
			return e
		}
		return rejected()
	}
	if flags.NArg() != 0 || statementPath == "" || rulesPath == "" || worklistPath == "" || ruleID == "" || reviewer == "" || decidedAtFlag == "" || output == "" || !filepath.IsAbs(output) {
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
		RuleID: ruleID, Reviewer: reviewer, DecidedAt: decidedAt.UTC(), Now: reviewRecordNowFunc(), Individual: *individual,
	})
	if err != nil {
		fmt.Fprintf(stderr, "review-record new: %v\n", err)
		return &commandError{code: 2, message: "review-record new: rejected", printed: true}
	}
	if filepath.Base(output) != ruleID+".json" {
		fmt.Fprintf(stderr, "review-record new: the output file must be named %s.json\n", ruleID)
		return &commandError{code: 2, message: "review-record new: rejected", printed: true}
	}
	if err := writeNewFile(output, record); err != nil {
		if errors.Is(err, os.ErrExist) {
			fmt.Fprintf(stderr, "review-record new: %s already exists; a record the statement chain already counted is replaced by deleting it first (the change then modifies it)\n", filepath.Base(output))
		} else {
			fmt.Fprintf(stderr, "review-record new: cannot write %s (the directory must allow creating a file and a hard link to it): %v\n", filepath.Base(output), err)
		}
		return &commandError{code: 2, message: "review-record new: rejected", printed: true}
	}
	fmt.Fprintf(stdout, "review-record new: rule=%s recordDigest=%s\n", ruleID, sourcecorpus.SHA(record))
	return nil
}

// writeNewFile writes data to a temporary file in path's directory and then
// links it to path, which must not exist yet. A failed write leaves nothing
// at path, and an existing file or symlink at path is never replaced.
func writeNewFile(path string, data []byte) error {
	if _, err := os.Lstat(path); err == nil {
		return os.ErrExist
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), reviewRecordTempPrefix+"*"+reviewRecordTempSuffix)
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	_, writeErr := tmp.Write(data)
	syncErr := tmp.Sync()
	closeErr := tmp.Close()
	if writeErr != nil || syncErr != nil || closeErr != nil {
		return errors.Join(writeErr, syncErr, closeErr)
	}
	if err := os.Chmod(name, 0o644); err != nil {
		return err
	}
	// os.Link fails if path exists (including a dangling symlink), so a
	// file created meanwhile is not overwritten, unlike os.Rename.
	return os.Link(name, path)
}
