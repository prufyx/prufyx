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

type tufFactSummary struct {
	state, category string
	present         *bool
}

func (r runtime) cncfTUFUpdater(path, pin, from, to string, now time.Time, format string, selection *knowledge.SelectionRequest, replayPath string) int {
	raw, err := readCNCFPrivate(path, 1<<20)
	if err != nil {
		return r.tufInputFailure(err)
	}
	rawDigest := digestCommunityBytes(raw)
	if pin != "" && pin != rawDigest {
		return r.knativeIntegrityFailure()
	}
	prepared, err := cncfprepare.PrepareTUFUpdater(raw, from, to)
	if err != nil {
		return r.tufInputFailure(err)
	}
	if prepared.SourceDigest != rawDigest || prepared.InputDigest != digestCommunityBytes(prepared.CanonicalInputJSON) || !json.Valid(prepared.CanonicalInputJSON) {
		return r.knativeIntegrityFailure()
	}
	fact, err := summarizeTUFPrepared(prepared.CanonicalInputJSON, prepared.UnsupportedCategory)
	if err != nil {
		return r.knativeIntegrityFailure()
	}
	if selection != nil {
		return r.cncfTUFExternal(*selection, replayPath, format, from, to, rawDigest, prepared.CanonicalInputJSON, prepared.InputDigest, fact)
	}
	report, err := r.cncfChecker().Check("the-update-framework-tuf", prepared.CanonicalInputJSON, now)
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
	if done, err := writeTrustPolicyOutcome(r.stdout, report.Check.Claims, report.TrustPolicy); err != nil {
		return ExitIntegrity
	} else if done {
		return cncfcheck.ClaimExit(report)
	}
	if err := writeTUFHuman(r.stdout, report, from, to, rawDigest, fact, "embedded"); err != nil {
		return ExitIntegrity
	}
	return cncfcheck.ClaimExit(report)
}

func (r runtime) cncfTUFExternal(selection knowledge.SelectionRequest, replayPath, format, from, to, rawDigest string, input []byte, inputDigest string, fact tufFactSummary) int {
	req := cncfknowledge.Request{Selection: selection, Project: "the-update-framework-tuf", Input: input, InputDigest: inputDigest}
	if replayPath != "" {
		expected, err := readCNCFPrivate(replayPath, 4<<20)
		if err != nil {
			return r.cncfError("external CNCF replay report failed local admission", err)
		}
		replay, err := cncfknowledge.ReplayHistorical(r.withTrustPolicy(req), expected)
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
			_, err = fmt.Fprintf(r.stdout, "historical external TUF Updater source replay: MATCH\ntransition: Python API %s -> %s\nbootstrap keyword: %s\nraw source digest verified now: %s\nprepared input digest: %s\nknowledge revision: %s\nknowledge bundle digest: %s\nknowledge trust receipt digest: %s\noriginal report digest: %s\ncurrent non-revocation: not checked offline\nnetwork used: false\nwhole-upgrade assessment: UNKNOWN\nraw identity: the caller-supplied digest matched this source file, but the saved report binds the minimized keyword observation, selected knowledge, and recorded time rather than original source bytes.\n", from, to, formatTUFFact(fact), rawDigest, inputDigest, selection.ExpectedRevision, selection.ExpectedBundleDigest, selection.ExpectedTrustReceiptDigest, replay.OriginalReportDigest)
		}
		if err != nil {
			return ExitIntegrity
		}
		return cncfknowledge.HistoricalClaimExit(replay)
	}
	report, err := cncfknowledge.EvaluateCurrent(r.withTrustPolicy(req))
	if err != nil {
		return r.cncfKnowledgeError("external CNCF check failed", err)
	}
	encoded, err := cncfknowledge.MarshalReport(report)
	if err != nil {
		return r.fail("external CNCF report integrity failure", ExitIntegrity)
	}
	if format != "json" {
		if done, err := writeTrustPolicyOutcome(r.stdout, report.Check.Check.Claims, report.Check.TrustPolicy); err != nil {
			return ExitIntegrity
		} else if done {
			return cncfknowledge.ClaimExit(report)
		}
	}
	if format == "json" {
		_, err = fmt.Fprintln(r.stdout, string(encoded))
	} else {
		err = writeTUFExternalHuman(r.stdout, report, from, to, rawDigest, fact)
	}
	if err != nil {
		return ExitIntegrity
	}
	return cncfknowledge.ClaimExit(report)
}

func summarizeTUFPrepared(raw []byte, category string) (tufFactSummary, error) {
	var input struct {
		Proposed struct {
			Components []struct {
				Component string `json:"component"`
				Facts     []struct {
					ID, State string
					BoolValue *bool `json:"boolValue,omitempty"`
				} `json:"facts"`
			} `json:"components"`
		} `json:"proposed"`
	}
	if json.Unmarshal(raw, &input) != nil || len(input.Proposed.Components) != 1 || input.Proposed.Components[0].Component != cncfprepare.TUFComponent || len(input.Proposed.Components[0].Facts) != 1 {
		return tufFactSummary{}, cncfcheck.ErrIntegrity
	}
	f := input.Proposed.Components[0].Facts[0]
	if f.ID != cncfprepare.TUFBootstrapFact || (f.State == "declared") != (f.BoolValue != nil) {
		return tufFactSummary{}, cncfcheck.ErrIntegrity
	}
	return tufFactSummary{state: f.State, present: f.BoolValue, category: category}, nil
}

func writeTUFHuman(out interface{ Write([]byte) (int, error) }, report cncfcheck.Report, from, to, rawDigest string, fact tufFactSummary, origin string) error {
	if len(report.Check.Claims) != 1 {
		return cncfcheck.ErrIntegrity
	}
	claim := report.Check.Claims[0]
	if _, err := fmt.Fprintf(out, "TUF Updater source-call review\ntransition: Python API %s -> %s\nbootstrap keyword: %s\nscoped result: %s (%s)\naggregate: UNKNOWN\nraw source digest: %s\nprepared input digest: %s\nevaluated at: %s\nknowledge: %s revision %s\nknowledge pack digest: %s\nsource parser: Go lexical subset; no Python interpreter, import, or execution is used\nnetwork used: false\ninput file handling: Prufyx reads but does not modify or execute the supplied Python source.\n", from, to, formatTUFFact(fact), claim.Status, claim.ReasonCode, rawDigest, report.InputFileDigest, report.Check.EvaluatedAt, origin, report.KnowledgeRevision, report.KnowledgePackDigest); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(out, claim.EvidenceBasisLine()); err != nil {
		return err
	}
	for _, source := range claim.Sources {
		if _, err := fmt.Fprintf(out, "pinned source: %s lines %d-%d; revision %s; digest %s\n", source.URL, source.StartLine, source.EndLine, source.Revision, source.ContentDigest); err != nil {
			return err
		}
	}
	return writeTUFScopeAndAction(out, claim.Status, claim.ReasonCode, claim.NextAction, fact, false)
}

func writeTUFExternalHuman(out interface{ Write([]byte) (int, error) }, report cncfknowledge.Report, from, to, rawDigest string, fact tufFactSummary) error {
	claims := report.Check.Check.Claims
	if len(claims) > 1 {
		return cncfcheck.ErrIntegrity
	}
	status, reason, action := "UNKNOWN", "RULE_TRANSITION_NOT_REVIEWED", "the selected external revision has no rule for this exact transition; no embedded rule was used"
	if len(claims) == 1 {
		status, reason, action = claims[0].Status, claims[0].ReasonCode, claims[0].NextAction
	}
	if _, err := fmt.Fprintf(out, "TUF Updater source-call review\ntransition: Python API %s -> %s\nbootstrap keyword: %s\nscoped result: %s (%s)\naggregate: UNKNOWN\nraw source digest: %s\nprepared input digest: %s\nevaluated at: %s\nknowledge: external signed local revision %s\nknowledge bundle digest: %s\nknowledge trust receipt digest: %s\nknowledge purpose: %s\nsource parser: Go lexical subset; no Python interpreter, import, or execution is used\ncurrent non-revocation: not checked offline\nnetwork used: false\n", from, to, formatTUFFact(fact), status, reason, rawDigest, report.Check.InputFileDigest, report.Knowledge.EvaluatedAt, report.Knowledge.Revision, report.Knowledge.BundleDigest, report.Knowledge.TrustReceiptDigest, report.Knowledge.Purpose); err != nil {
		return err
	}
	if len(claims) == 1 {
		if _, err := fmt.Fprintln(out, claims[0].EvidenceBasisLine()); err != nil {
			return err
		}
		for _, source := range claims[0].Sources {
			if _, err := fmt.Fprintf(out, "pinned source: %s lines %d-%d; revision %s; digest %s\n", source.URL, source.StartLine, source.EndLine, source.Revision, source.ContentDigest); err != nil {
				return err
			}
		}
	}
	if err := writeTUFScopeAndAction(out, status, reason, action, fact, true); err != nil {
		return err
	}
	if report.Knowledge.Purpose == "synthetic_test_only" {
		_, err := fmt.Fprintln(out, "authority: synthetic test knowledge only; no official Prufyx signing root or compatibility proof")
		return err
	}
	return nil
}

func writeTUFScopeAndAction(out interface{ Write([]byte) (int, error) }, status, reason, action string, fact tufFactSummary, external bool) error {
	if status == "PASS" {
		action = "the admitted direct call already supplies bootstrap explicitly; separately validate its value, cached-root or trusted-root intent, metadata, updates, and runtime behavior"
	} else if status == "UNKNOWN" && reason != "RULE_TRANSITION_NOT_REVIEWED" && fact.state != "declared" {
		action = "the supplied source is outside this reviewed direct-call shape (" + fact.category + "); review the target API for the intended code without reshaping it only to obtain a result"
	}
	if _, err := fmt.Fprintf(out, "next action: %s\n", action); err != nil {
		return err
	}
	scope := "scope: this checks only explicit bootstrap keyword presence in one conservatively bound direct tuf.ngclient.Updater call. Values, key/root/cache contents, trust, metadata, update behavior, installed-package or process provenance, and whole-upgrade safety remain UNKNOWN."
	if external {
		scope += " Selected local knowledge is authoritative with no embedded fallback."
	}
	_, err := fmt.Fprintln(out, scope)
	return err
}

func formatTUFFact(f tufFactSummary) string {
	if f.state != "declared" || f.present == nil {
		return "unsupported (" + f.category + ")"
	}
	if *f.present {
		return "present in supplied direct call"
	}
	return "absent from supplied direct call"
}
