// SPDX-License-Identifier: AGPL-3.0-only

package communityapp

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/prufyx/prufyx/cli/internal/cncfcheck"
	"github.com/prufyx/prufyx/cli/internal/cncfknowledge"
	"github.com/prufyx/prufyx/cli/internal/cncfprepare"
	"github.com/prufyx/prufyx/cli/internal/knowledge"
)

type inTotoPreparedDocument struct {
	Proposed struct {
		Components []struct {
			Component string                                  `json:"component"`
			Facts     []struct{ ID, State, EnumValue string } `json:"facts"`
		} `json:"components"`
	} `json:"proposed"`
}
type inTotoFactSummary struct{ state, value string }

func (r runtime) cncfInTotoRun(path, pin, from, to string, now time.Time, format string, selection *knowledge.SelectionRequest, replayPath string) int {
	raw, err := readCNCFPrivate(path, 1<<20)
	if err != nil {
		return r.inTotoInputFailure(err)
	}
	rawDigest := digestCommunityBytes(raw)
	if pin != "" && pin != rawDigest {
		return r.knativeIntegrityFailure()
	}
	prepared, err := cncfprepare.PrepareInTotoRun(raw, from, to)
	if err != nil {
		return r.inTotoInputFailure(err)
	}
	if prepared.SourceDigest != rawDigest || prepared.InputDigest != digestCommunityBytes(prepared.CanonicalInputJSON) || !json.Valid(prepared.CanonicalInputJSON) {
		return r.knativeIntegrityFailure()
	}
	fact, err := summarizeInTotoPrepared(prepared.CanonicalInputJSON)
	if err != nil {
		return r.knativeIntegrityFailure()
	}
	if selection != nil {
		return r.cncfInTotoExternal(*selection, replayPath, format, from, to, rawDigest, prepared.CanonicalInputJSON, prepared.InputDigest, fact)
	}
	report, err := cncfcheck.Check("in-toto", prepared.CanonicalInputJSON, now)
	if err != nil {
		return r.cncfError("CNCF source-constraint check failed", err)
	}
	encoded, err := cncfcheck.MarshalReport(report)
	if err != nil {
		return r.fail("CNCF report integrity failure", ExitIntegrity)
	}
	if format == "json" {
		if _, err := fmt.Fprintln(r.stdout, string(encoded)); err != nil {
			return ExitIntegrity
		}
		return cncfcheck.ClaimExit(report)
	}
	if err := writeInTotoHuman(r.stdout, report, from, to, rawDigest, fact, "embedded"); err != nil {
		return ExitIntegrity
	}
	return cncfcheck.ClaimExit(report)
}

func (r runtime) cncfInTotoExternal(selection knowledge.SelectionRequest, replayPath, format, from, to, rawDigest string, input []byte, inputDigest string, fact inTotoFactSummary) int {
	req := cncfknowledge.Request{Selection: selection, Project: "in-toto", Input: input, InputDigest: inputDigest}
	if replayPath != "" {
		expected, err := readCNCFPrivate(replayPath, 4<<20)
		if err != nil {
			return r.cncfError("external CNCF replay report failed local admission", err)
		}
		replay, err := cncfknowledge.ReplayHistorical(req, expected)
		if err != nil {
			return r.cncfKnowledgeError("external CNCF historical replay failed", err)
		}
		encoded, err := cncfknowledge.MarshalHistoricalReplay(replay)
		if err != nil {
			return r.fail("external CNCF replay integrity failure", ExitIntegrity)
		}
		if format == "json" {
			_, err = fmt.Fprintln(r.stdout, string(encoded))
		} else {
			err = writeInTotoReplay(r.stdout, replay, from, to, rawDigest, inputDigest, fact, selection)
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
	encoded, err := cncfknowledge.MarshalReport(report)
	if err != nil {
		return r.fail("external CNCF report integrity failure", ExitIntegrity)
	}
	if format == "json" {
		_, err = fmt.Fprintln(r.stdout, string(encoded))
	} else {
		err = writeInTotoExternalHuman(r.stdout, report, from, to, rawDigest, fact)
	}
	if err != nil {
		return ExitIntegrity
	}
	return cncfknowledge.ClaimExit(report)
}

func summarizeInTotoPrepared(raw []byte) (inTotoFactSummary, error) {
	var input inTotoPreparedDocument
	if json.Unmarshal(raw, &input) != nil || len(input.Proposed.Components) != 1 || input.Proposed.Components[0].Component != cncfprepare.InTotoComponent || len(input.Proposed.Components[0].Facts) != 1 {
		return inTotoFactSummary{}, cncfcheck.ErrIntegrity
	}
	f := input.Proposed.Components[0].Facts[0]
	if f.ID != cncfprepare.InTotoRunKeyFact {
		return inTotoFactSummary{}, cncfcheck.ErrIntegrity
	}
	return inTotoFactSummary{state: f.State, value: f.EnumValue}, nil
}

func writeInTotoHuman(out interface{ Write([]byte) (int, error) }, report cncfcheck.Report, from, to, rawDigest string, fact inTotoFactSummary, origin string) error {
	if len(report.Check.Claims) != 1 {
		return cncfcheck.ErrIntegrity
	}
	claim := report.Check.Claims[0]
	if _, err := fmt.Fprintf(out, "in-toto-run key argument upgrade review\ntransition: Python CLI %s -> %s\npre-boundary key option: %s\nscoped result: %s (%s)\naggregate: UNKNOWN\nraw argv digest: %s\nprepared input digest: %s\nevaluated at: %s\nknowledge: %s revision %s\nknowledge pack digest: %s\nnetwork used: false\ninput file handling: Prufyx reads but does not modify the supplied argv file.\n", from, to, formatInTotoFact(fact), claim.Status, claim.ReasonCode, rawDigest, report.InputFileDigest, report.Check.EvaluatedAt, origin, report.KnowledgeRevision, report.KnowledgePackDigest); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(out, claim.EvidenceBasisLine()); err != nil {
		return err
	}
	for _, s := range claim.Sources {
		if _, err := fmt.Fprintf(out, "pinned source: %s lines %d-%d; revision %s; digest %s\n", s.URL, s.StartLine, s.EndLine, s.Revision, s.ContentDigest); err != nil {
			return err
		}
	}
	if fact.state != "declared" {
		_, err := fmt.Fprintln(out, "next action: this planned argv is outside the reviewed in-toto-run prefix grammar and remains UNKNOWN; inspect the target CLI before changing the command.")
		return err
	}
	if _, err := fmt.Fprintf(out, "next action: %s\n", claim.NextAction); err != nil {
		return err
	}
	_, err := fmt.Fprintln(out, "scope: this checks only removal of the pre-boundary -k/--key spelling. Key conversion, loading, password handling, signing, wrapped-command execution, trust, process provenance, and whole-upgrade safety remain UNKNOWN.")
	return err
}

func writeInTotoExternalHuman(out interface{ Write([]byte) (int, error) }, report cncfknowledge.Report, from, to, rawDigest string, fact inTotoFactSummary) error {
	claims := report.Check.Check.Claims
	status, reason := "UNKNOWN", "RULE_TRANSITION_NOT_REVIEWED"
	if len(claims) > 1 {
		return cncfcheck.ErrIntegrity
	}
	if len(claims) == 1 {
		status, reason = claims[0].Status, claims[0].ReasonCode
	}
	if _, err := fmt.Fprintf(out, "in-toto-run key argument upgrade review\ntransition: Python CLI %s -> %s\npre-boundary key option: %s\nscoped result: %s (%s)\naggregate: UNKNOWN\nraw argv digest: %s\nprepared input digest: %s\nevaluated at: %s\nknowledge: external signed local revision %s\nknowledge bundle digest: %s\nknowledge trust receipt digest: %s\nknowledge purpose: %s\ncurrent non-revocation: not checked offline\nnetwork used: false\n", from, to, formatInTotoFact(fact), status, reason, rawDigest, report.Check.InputFileDigest, report.Knowledge.EvaluatedAt, report.Knowledge.Revision, report.Knowledge.BundleDigest, report.Knowledge.TrustReceiptDigest, report.Knowledge.Purpose); err != nil {
		return err
	}
	if len(claims) == 0 {
		if _, err := fmt.Fprintln(out, "next action: the selected external revision has no rule for this exact transition; no embedded rule was used."); err != nil {
			return err
		}
	} else {
		if _, err := fmt.Fprintln(out, claims[0].EvidenceBasisLine()); err != nil {
			return err
		}
		for _, s := range claims[0].Sources {
			if _, err := fmt.Fprintf(out, "pinned source: %s lines %d-%d; revision %s; digest %s\n", s.URL, s.StartLine, s.EndLine, s.Revision, s.ContentDigest); err != nil {
				return err
			}
		}
		if fact.state != "declared" {
			if _, err := fmt.Fprintln(out, "next action: this planned argv is outside the selected in-toto-run prefix grammar and remains UNKNOWN."); err != nil {
				return err
			}
		} else if _, err := fmt.Fprintf(out, "next action: %s\n", claims[0].NextAction); err != nil {
			return err
		}
	}
	if report.Knowledge.Purpose == "synthetic_test_only" {
		if _, err := fmt.Fprintln(out, "authority: synthetic test knowledge only; no official Prufyx signing root or compatibility proof"); err != nil {
			return err
		}
	}
	_, err := fmt.Fprintln(out, "scope: selected local knowledge is authoritative with no embedded fallback. Only the pre-boundary key-option removal is checked; keys, execution, trust, process provenance, and whole-upgrade safety remain UNKNOWN.")
	return err
}

func writeInTotoReplay(out interface{ Write([]byte) (int, error) }, replay cncfknowledge.HistoricalReplay, from, to, rawDigest, inputDigest string, fact inTotoFactSummary, selection knowledge.SelectionRequest) error {
	_, err := fmt.Fprintf(out, "historical external in-toto-run replay: MATCH\ntransition: Python CLI %s -> %s\npre-boundary key option: %s\nraw argv digest verified now: %s\nprepared input digest: %s\nknowledge revision: %s\nknowledge bundle digest: %s\nknowledge trust receipt digest: %s\noriginal report digest: %s\ncurrent non-revocation: not checked offline\nnetwork used: false\nwhole-upgrade assessment: UNKNOWN\nraw identity: the caller-supplied digest matched this argv file, but the saved report binds the minimized key-option observation, selected knowledge, and recorded time rather than original argv bytes; retain the raw file and digest separately.\n", from, to, formatInTotoFact(fact), rawDigest, inputDigest, selection.ExpectedRevision, selection.ExpectedBundleDigest, selection.ExpectedTrustReceiptDigest, replay.OriginalReportDigest)
	return err
}

func formatInTotoFact(f inTotoFactSummary) string {
	if f.state != "declared" || f.value == "" {
		return f.state
	}
	if f.value == cncfprepare.InTotoRunKeyLegacy {
		return "-k/--key (read from supplied argv)"
	}
	return "--signing-key (read from supplied argv)"
}
