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

type cubeFSFactSummary struct {
	phaseState string
	guardState string
	guardValue *bool
	reason     cncfprepare.Reason
}

func (r runtime) cncfCubeFSMetaNode(path, pin, from, to, phase string, now time.Time, format string, selection *knowledge.SelectionRequest, replayPath string) int {
	raw, err := readCNCFPrivate(path, 1<<20)
	if err != nil {
		return r.cubeFSInputFailure(err)
	}
	rawDigest := digestCommunityBytes(raw)
	if pin != "" && pin != rawDigest {
		return r.knativeIntegrityFailure()
	}
	prepared, err := cncfprepare.PrepareCubeFSMetaNode(raw, from, to, phase)
	if err != nil {
		return r.cubeFSInputFailure(err)
	}
	if prepared.SourceDigest != rawDigest || prepared.InputDigest != digestCommunityBytes(prepared.CanonicalInputJSON) || !json.Valid(prepared.CanonicalInputJSON) {
		return r.knativeIntegrityFailure()
	}
	facts, err := summarizeCubeFSPrepared(prepared.CanonicalInputJSON, prepared.Reason)
	if err != nil {
		return r.knativeIntegrityFailure()
	}
	if selection != nil {
		return r.cncfCubeFSExternal(*selection, replayPath, format, from, to, phase, rawDigest, prepared.CanonicalInputJSON, prepared.InputDigest, facts)
	}
	report, err := cncfcheck.Check("cubefs", prepared.CanonicalInputJSON, now)
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
	if err := writeCubeFSHuman(r.stdout, report, from, to, phase, rawDigest, facts, "embedded"); err != nil {
		return ExitIntegrity
	}
	return cncfcheck.ClaimExit(report)
}

func (r runtime) cncfCubeFSExternal(selection knowledge.SelectionRequest, replayPath, format, from, to, phase, rawDigest string, input []byte, inputDigest string, facts cubeFSFactSummary) int {
	req := cncfknowledge.Request{Selection: selection, Project: "cubefs", Input: input, InputDigest: inputDigest}
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
			_, err = fmt.Fprintf(r.stdout, "historical external CubeFS MetaNode replay: MATCH\ntransition: %s -> %s\ndeclared phase: %s\nplanned config raftSyncSnapFormatVersion: %s\nraw config digest verified now: %s\nprepared input digest: %s\nknowledge revision: %s\nknowledge bundle digest: %s\nknowledge trust receipt digest: %s\noriginal report digest: %s\ncurrent non-revocation: not checked offline\nnetwork used: false\nwhole-upgrade assessment: UNKNOWN\nraw identity: the caller-supplied digest matched this planned config file, but the saved report binds the minimized phase and guard observations, selected knowledge, and recorded time rather than original config bytes.\n", from, to, formatCubeFSPhase(phase, facts.phaseState), formatCubeFSGuard(facts), rawDigest, inputDigest, selection.ExpectedRevision, selection.ExpectedBundleDigest, selection.ExpectedTrustReceiptDigest, replay.OriginalReportDigest)
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
		err = writeCubeFSExternalHuman(r.stdout, report, from, to, phase, rawDigest, facts)
	}
	if err != nil {
		return ExitIntegrity
	}
	return cncfknowledge.ClaimExit(report)
}

func summarizeCubeFSPrepared(raw []byte, reason cncfprepare.Reason) (cubeFSFactSummary, error) {
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
	if json.Unmarshal(raw, &input) != nil || len(input.Proposed.Components) != 1 || input.Proposed.Components[0].Component != cncfprepare.CubeFSComponent || len(input.Proposed.Components[0].Facts) != 2 {
		return cubeFSFactSummary{}, cncfcheck.ErrIntegrity
	}
	facts := input.Proposed.Components[0].Facts
	if facts[0].ID != cncfprepare.CubeFSUpgradePhaseFact || facts[1].ID != cncfprepare.CubeFSRaftSnapshotZeroFact {
		return cubeFSFactSummary{}, cncfcheck.ErrIntegrity
	}
	return cubeFSFactSummary{phaseState: facts[0].State, guardState: facts[1].State, guardValue: facts[1].BoolValue, reason: reason}, nil
}

func writeCubeFSHuman(out interface{ Write([]byte) (int, error) }, report cncfcheck.Report, from, to, phase, rawDigest string, facts cubeFSFactSummary, origin string) error {
	if len(report.Check.Claims) != 1 {
		return cncfcheck.ErrIntegrity
	}
	claim := report.Check.Claims[0]
	if _, err := fmt.Fprintf(out, "CubeFS MetaNode planned-upgrade review\ntransition: %s -> %s\ndeclared phase: %s\nplanned config raftSyncSnapFormatVersion: %s\nscoped result: %s (%s)\naggregate: UNKNOWN\nraw config digest: %s\nprepared input digest: %s\nevaluated at: %s\nknowledge: %s revision %s\nknowledge pack digest: %s\nnetwork used: false\ninput file handling: Prufyx reads but does not modify the supplied planned config.\n", from, to, formatCubeFSPhase(phase, facts.phaseState), formatCubeFSGuard(facts), claim.Status, claim.ReasonCode, rawDigest, report.InputFileDigest, report.Check.EvaluatedAt, origin, report.KnowledgeRevision, report.KnowledgePackDigest); err != nil {
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
	return writeCubeFSScopeAndAction(out, claim.Status, claim.ReasonCode, claim.NextAction, facts)
}

func writeCubeFSExternalHuman(out interface{ Write([]byte) (int, error) }, report cncfknowledge.Report, from, to, phase, rawDigest string, facts cubeFSFactSummary) error {
	claims := report.Check.Check.Claims
	if len(claims) > 1 {
		return cncfcheck.ErrIntegrity
	}
	status, reason, nextAction := "UNKNOWN", "RULE_TRANSITION_NOT_REVIEWED", "the selected external revision has no rule for this exact transition; no embedded rule was used"
	if len(claims) == 1 {
		status, reason, nextAction = claims[0].Status, claims[0].ReasonCode, claims[0].NextAction
	}
	if _, err := fmt.Fprintf(out, "CubeFS MetaNode planned-upgrade review\ntransition: %s -> %s\ndeclared phase: %s\nplanned config raftSyncSnapFormatVersion: %s\nscoped result: %s (%s)\naggregate: UNKNOWN\nraw config digest: %s\nprepared input digest: %s\nevaluated at: %s\nknowledge: external signed local revision %s\nknowledge bundle digest: %s\nknowledge trust receipt digest: %s\nknowledge purpose: %s\ncurrent non-revocation: not checked offline\nnetwork used: false\n", from, to, formatCubeFSPhase(phase, facts.phaseState), formatCubeFSGuard(facts), status, reason, rawDigest, report.Check.InputFileDigest, report.Knowledge.EvaluatedAt, report.Knowledge.Revision, report.Knowledge.BundleDigest, report.Knowledge.TrustReceiptDigest, report.Knowledge.Purpose); err != nil {
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
	if _, err := fmt.Fprintf(out, "next action: %s\n", cubeFSNextAction(status, reason, nextAction, facts)); err != nil {
		return err
	}
	if report.Knowledge.Purpose == "synthetic_test_only" {
		if _, err := fmt.Fprintln(out, "authority: synthetic test knowledge only; no official Prufyx signing root or compatibility proof"); err != nil {
			return err
		}
	}
	_, err := fmt.Fprintln(out, cubeFSScopeText+" Selected local knowledge is authoritative with no embedded fallback.")
	return err
}

func writeCubeFSScopeAndAction(out interface{ Write([]byte) (int, error) }, status, reason, nextAction string, facts cubeFSFactSummary) error {
	if _, err := fmt.Fprintf(out, "next action: %s\n", cubeFSNextAction(status, reason, nextAction, facts)); err != nil {
		return err
	}
	_, err := fmt.Fprintln(out, cubeFSScopeText)
	return err
}

func cubeFSNextAction(status, reason, nextAction string, facts cubeFSFactSummary) string {
	if status == "PASS" {
		return "the supplied planned config already declares numeric 0 for this phase; keep it while MetaNodes upgrade, then follow the unverified remove-setting, restart-all-MetaNodes, and client-last steps"
	}
	if status == "UNKNOWN" && reason != "RULE_TRANSITION_NOT_REVIEWED" && (facts.phaseState != "declared" || facts.guardState != "declared") {
		return "this input is outside the reviewed planned MetaNode guard: supply the intended native config and declare --phase metanode-upgrade, or retain UNKNOWN; do not reshape a real config only to obtain a result"
	}
	return nextAction
}

const cubeFSScopeText = "scope: this checks only the source-prescribed snapshot-format guard in one caller-supplied planned MetaNode config for the declared phase. It does not observe effective cluster configuration, peers, rollout completion, restarts, client ordering, mounts, runtime behavior, or data safety. Removing the setting after all MetaNodes upgrade, restarting all MetaNodes, and upgrading the client last remain unverified follow-up requirements."

func formatCubeFSPhase(phase, state string) string {
	if state != "declared" {
		return "unsupported or not declared"
	}
	return phase + " (caller-declared)"
}

func formatCubeFSGuard(facts cubeFSFactSummary) string {
	if facts.guardState != "declared" || facts.guardValue == nil {
		return "unsupported or ambiguous"
	}
	switch facts.reason {
	case cncfprepare.ReasonCubeFSMetaNodeGuardAbsent:
		return "absent in supplied planned config (target source-defined default is 1)"
	case cncfprepare.ReasonCubeFSMetaNodeGuardZero:
		return "explicit numeric 0 in supplied planned config"
	case cncfprepare.ReasonCubeFSMetaNodeGuardOne:
		return "explicit numeric 1 in supplied planned config"
	default:
		return "integrity-unavailable"
	}
}
