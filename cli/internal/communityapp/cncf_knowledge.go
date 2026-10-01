// SPDX-License-Identifier: AGPL-3.0-only

package communityapp

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/prufyx/prufyx/cli/internal/cncfcheck"
	"github.com/prufyx/prufyx/cli/internal/cncfknowledge"
	"github.com/prufyx/prufyx/cli/internal/knowledge"
)

func (r runtime) externalCNCF(req cncfknowledge.Request, replayPath, format string) int {
	if replayPath != "" {
		expected, err := readCNCFPrivate(replayPath, 4<<20)
		if err != nil {
			return r.cncfError("external CNCF replay report failed local admission", err)
		}
		replay, err := cncfknowledge.ReplayHistorical(req, expected)
		if err != nil {
			return r.cncfKnowledgeError("external CNCF historical replay failed", err)
		}
		raw, err := cncfknowledge.MarshalHistoricalReplay(replay)
		if err != nil {
			return r.fail("external CNCF replay integrity failure", ExitIntegrity)
		}
		if format == "json" {
			_, err = fmt.Fprintln(r.stdout, string(raw))
		} else {
			_, err = fmt.Fprintf(r.stdout, "historical external CNCF replay: MATCH\noriginal report digest: %s\ncurrent non-revocation: not checked offline\nwhole-upgrade assessment: UNKNOWN\n", replay.OriginalReportDigest)
		}
		if err != nil {
			return ExitIntegrity
		}
		return cncfknowledge.HistoricalClaimExit(replay)
	}
	report, err := cncfknowledge.EvaluateCurrent(req)
	if err != nil {
		return r.cncfKnowledgeError("external CNCF check failed", err)
	}
	raw, err := cncfknowledge.MarshalReport(report)
	if err != nil {
		return r.fail("external CNCF report integrity failure", ExitIntegrity)
	}
	if format == "json" {
		_, err = fmt.Fprintln(r.stdout, string(raw))
	} else {
		var output bytes.Buffer
		fmt.Fprintf(&output, "%s source-constraint check\nwhole-upgrade assessment: UNKNOWN\nknowledge: external signed local revision %s\npurpose: %s\ntrust source: %s\nsource references: operator-declared; runtime behavior unverified\n", report.Check.Project, report.Knowledge.Revision, report.Knowledge.Purpose, report.Knowledge.TrustSource)
		for _, claim := range report.Check.Check.Claims {
			fmt.Fprintf(&output, "%s: %s (%s)\nnext action: %s\n", claim.RuleID, claim.Status, claim.ReasonCode, claim.NextAction)
			fmt.Fprintln(&output, claim.EvidenceBasisLine())
		}
		fmt.Fprintf(&output, "input digest: %s\nbundle digest: %s\ntrust receipt digest: %s\nevaluated at: %s\ncurrent non-revocation: not checked offline\nnetwork used: false\nnext action: %s\n", report.Check.InputFileDigest, report.Knowledge.BundleDigest, report.Knowledge.TrustReceiptDigest, report.Knowledge.EvaluatedAt, report.Check.NextAction)
		if report.Knowledge.Purpose == "synthetic_test_only" {
			fmt.Fprintln(&output, "authority: synthetic test knowledge only; no official Prufyx signing root or compatibility proof")
		}
		_, err = r.stdout.Write(output.Bytes())
	}
	if err != nil {
		return ExitIntegrity
	}
	return cncfknowledge.ClaimExit(report)
}

func (r runtime) cncfKnowledgeError(message string, err error) int {
	if errors.Is(err, knowledge.ErrNoSelection) {
		return r.fail(message+"; no verified CNCF revision selected", ExitUnknown)
	}
	if errors.Is(err, cncfknowledge.ErrInvalid) || errors.Is(err, cncfcheck.ErrInvalid) {
		return r.fail(message, ExitUsage)
	}
	return r.knowledgeError(message, err)
}
