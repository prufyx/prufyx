// SPDX-License-Identifier: AGPL-3.0-only

package communityapp

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/prufyx/prufyx/cli/internal/cncfcheck"
	"github.com/prufyx/prufyx/cli/internal/cncfknowledge"
	"github.com/prufyx/prufyx/cli/internal/constraintengine"
	"github.com/prufyx/prufyx/cli/internal/knowledge"
)

func (r runtime) externalCNCF(req cncfknowledge.Request, replayPath, format string) int {
	return r.externalCNCFGated(req, replayPath, format, nil)
}

// apiGate returns the API-version gaps of the checked resources at the
// evaluation time of the report (never the wall clock), nil when none.
type apiGate func(evaluatedAt time.Time) []string

// reportEvaluatedAt reads knowledge.evaluatedAt of a report; the zero time
// when it cannot be read, which no served list is current at.
func reportEvaluatedAt(report []byte) time.Time {
	var shape struct {
		Knowledge struct {
			EvaluatedAt string `json:"evaluatedAt"`
		} `json:"knowledge"`
	}
	if json.Unmarshal(report, &shape) != nil {
		return time.Time{}
	}
	at, err := time.Parse(time.RFC3339, shape.Knowledge.EvaluatedAt)
	if err != nil {
		return time.Time{}
	}
	return at.UTC()
}

// gateExit turns an exit 0 into UNKNOWN when the gate names gaps at the
// evaluation time of the report; other exits and a nil gate pass through.
func gateExit(gate apiGate, exit int, report []byte) (int, []string) {
	if gate == nil || exit != 0 {
		return exit, nil
	}
	if gaps := gate(reportEvaluatedAt(report)); len(gaps) > 0 {
		return ExitUnknown, gaps
	}
	return exit, nil
}

// externalCNCFGated is externalCNCF with an API-version gate: when the report
// would exit 0 and the gate names gaps, the result is UNKNOWN (exit 11) with
// the reasons in the same output.
func (r runtime) externalCNCFGated(req cncfknowledge.Request, replayPath, format string, gate apiGate) int {
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
		// The clock of the original report, so a replay is deterministic.
		exit, gaps := gateExit(gate, cncfknowledge.HistoricalClaimExit(replay), replay.OriginalReport)
		if format == "json" {
			if len(gaps) > 0 {
				if raw, err = spliceAPIVersionGaps(raw, gaps); err != nil {
					return r.fail("external CNCF replay integrity failure", ExitIntegrity)
				}
			}
			_, err = fmt.Fprintln(r.stdout, string(raw))
		} else {
			for _, line := range apiGapHeadline(gaps) {
				fmt.Fprintln(r.stdout, line)
			}
			_, err = fmt.Fprintf(r.stdout, "historical external CNCF replay: MATCH\noriginal report digest: %s\ncurrent non-revocation: not checked offline\nwhole-upgrade assessment: UNKNOWN\n", replay.OriginalReportDigest)
		}
		if err != nil {
			return ExitIntegrity
		}
		return exit
	}
	report, err := r.evaluateCurrent(req)
	if err != nil {
		return r.cncfKnowledgeError("external CNCF check failed", err)
	}
	raw, err := cncfknowledge.MarshalReport(report)
	if err != nil {
		return r.fail("external CNCF report integrity failure", ExitIntegrity)
	}
	exit, gaps := gateExit(gate, cncfknowledge.ClaimExit(report), raw)
	if format == "json" {
		if len(gaps) > 0 {
			if raw, err = spliceAPIVersionGaps(raw, gaps); err != nil {
				return r.fail("external CNCF report integrity failure", ExitIntegrity)
			}
		}
		_, err = fmt.Fprintln(r.stdout, string(raw))
	} else {
		var output bytes.Buffer
		for _, line := range apiGapHeadline(gaps) {
			fmt.Fprintln(&output, line)
		}
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
	return exit
}

func (r runtime) cncfKnowledgeError(message string, err error) int {
	if errors.Is(err, constraintengine.ErrReplayOlderContract) {
		return r.fail(olderContractMessage, ExitUsage)
	}
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
