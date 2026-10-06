// SPDX-License-Identifier: AGPL-3.0-only

package communityapp

import (
	"bytes"
	"errors"
	"fmt"
	"io"

	"github.com/prufyx/prufyx/cli/internal/cncfcheck"
	"github.com/prufyx/prufyx/cli/internal/cncfknowledge"
	"github.com/prufyx/prufyx/cli/internal/constraintengine"
	"github.com/prufyx/prufyx/cli/internal/knowledge"
)

func (r runtime) externalCNCF(req cncfknowledge.Request, replayPath, format string) int {
	if replayPath != "" {
		expected, err := readCNCFPrivate(replayPath, 4<<20)
		if err != nil {
			return r.cncfError("external CNCF replay report failed local admission", err)
		}
		replay, err := cncfknowledge.ReplayHistorical(r.withTrustPolicy(req), expected)
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
	report, err := r.evaluateCurrent(req)
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
		if r.knowledgeSource != "" {
			fmt.Fprintf(&output, "knowledge source: %s\n", r.knowledgeSource)
		}
		_ = writeBasisHeadline(&output, report.Check.Check.Claims, report.Check.TrustPolicy)
		_ = writeExternalClaims(&output, report.Check.Check.Claims)
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

// writeExternalClaims prints every claim of an external-knowledge report.
// External knowledge refuses one-way notices today; printing them with the
// notice wording is defence in depth.
func writeExternalClaims(out io.Writer, claims []constraintengine.Claim) error {
	for _, claim := range claims {
		printed, err := writeClaimHeadline(out, claim)
		if err != nil {
			return err
		}
		if !printed {
			continue
		}
		if line, ok := claim.MatchedMembersLine(); ok {
			if _, err := fmt.Fprintln(out, line); err != nil {
				return err
			}
		}
		if _, err := fmt.Fprintln(out, claim.EvidenceBasisLine()); err != nil {
			return err
		}
	}
	if err := writeNoVerdictLine(out, claims); err != nil {
		return err
	}
	return writeCustomResourceScope(out, claims)
}
