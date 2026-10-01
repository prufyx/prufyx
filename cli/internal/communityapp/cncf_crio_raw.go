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

type crioFactSummary struct {
	operationState string
	shortState     string
	shortValue     *bool
	reason         cncfprepare.Reason
}

func (r runtime) cncfCRIOArtifactName(path, pin, from, to, operation string, now time.Time, format string, selection *knowledge.SelectionRequest, replayPath string) int {
	raw, err := readCNCFPrivate(path, 1<<20)
	if err != nil {
		return r.crioInputFailure(err)
	}
	rawDigest := digestCommunityBytes(raw)
	if pin != "" && pin != rawDigest {
		return r.knativeIntegrityFailure()
	}
	prepared, err := cncfprepare.PrepareCRIOArtifactName(raw, from, to, operation)
	if err != nil {
		return r.crioInputFailure(err)
	}
	if prepared.SourceDigest != rawDigest || prepared.InputDigest != digestCommunityBytes(prepared.CanonicalInputJSON) || !json.Valid(prepared.CanonicalInputJSON) {
		return r.knativeIntegrityFailure()
	}
	facts, err := summarizeCRIOPrepared(prepared.CanonicalInputJSON, prepared.Reason)
	if err != nil {
		return r.knativeIntegrityFailure()
	}
	if selection != nil {
		return r.cncfCRIOExternal(*selection, replayPath, format, from, to, operation, rawDigest, prepared.CanonicalInputJSON, prepared.InputDigest, facts)
	}
	report, err := cncfcheck.Check("cri-o", prepared.CanonicalInputJSON, now)
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
	if err := writeCRIOHuman(r.stdout, report, from, to, operation, rawDigest, facts, "embedded"); err != nil {
		return ExitIntegrity
	}
	return cncfcheck.ClaimExit(report)
}

func (r runtime) cncfCRIOExternal(selection knowledge.SelectionRequest, replayPath, format, from, to, operation, rawDigest string, input []byte, inputDigest string, facts crioFactSummary) int {
	req := cncfknowledge.Request{Selection: selection, Project: "cri-o", Input: input, InputDigest: inputDigest}
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
			_, err = fmt.Fprintf(r.stdout, "historical external CRI-O named-reference replay: MATCH\ntransition: %s -> %s\ndeclared operation: %s\nsupplied artifact reference class: %s\nraw ImageStatusRequest digest verified now: %s\nprepared input digest: %s\nknowledge revision: %s\nknowledge bundle digest: %s\nknowledge trust receipt digest: %s\noriginal report digest: %s\ncurrent non-revocation: not checked offline\nnetwork used: false\naggregate readiness: UNKNOWN\nraw identity: the caller-supplied digest matched this request file, but the saved report binds minimized intent and reference classification, selected knowledge, and recorded time rather than original request bytes.\n", from, to, formatCRIOOperation(operation, facts.operationState), formatCRIOReference(facts), rawDigest, inputDigest, selection.ExpectedRevision, selection.ExpectedBundleDigest, selection.ExpectedTrustReceiptDigest, replay.OriginalReportDigest)
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
		err = writeCRIOExternalHuman(r.stdout, report, from, to, operation, rawDigest, facts)
	}
	if err != nil {
		return ExitIntegrity
	}
	return cncfknowledge.ClaimExit(report)
}

func summarizeCRIOPrepared(raw []byte, reason cncfprepare.Reason) (crioFactSummary, error) {
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
	if json.Unmarshal(raw, &input) != nil || len(input.Proposed.Components) != 1 || input.Proposed.Components[0].Component != cncfprepare.CRIOComponent || len(input.Proposed.Components[0].Facts) != 2 {
		return crioFactSummary{}, cncfcheck.ErrIntegrity
	}
	facts := input.Proposed.Components[0].Facts
	if facts[0].ID != cncfprepare.CRIOShortFact || facts[1].ID != cncfprepare.CRIOPlannedFact {
		return crioFactSummary{}, cncfcheck.ErrIntegrity
	}
	return crioFactSummary{operationState: facts[1].State, shortState: facts[0].State, shortValue: facts[0].BoolValue, reason: reason}, nil
}

func writeCRIOHuman(out interface{ Write([]byte) (int, error) }, report cncfcheck.Report, from, to, operation, rawDigest string, facts crioFactSummary, origin string) error {
	if len(report.Check.Claims) != 1 {
		return cncfcheck.ErrIntegrity
	}
	claim := report.Check.Claims[0]
	if _, err := fmt.Fprintf(out, "CRI-O planned ArtifactStore named-reference review\ntransition: %s -> %s\ndeclared operation: %s\nsupplied artifact reference class: %s\nscoped result: %s (%s)\naggregate readiness: UNKNOWN\nraw ImageStatusRequest digest: %s\nprepared input digest: %s\nevaluated at: %s\nknowledge: %s revision %s\nknowledge pack digest: %s\nnetwork used: false\ninput file handling: Prufyx reads but does not modify the supplied request.\n", from, to, formatCRIOOperation(operation, facts.operationState), formatCRIOReference(facts), claim.Status, claim.ReasonCode, rawDigest, report.InputFileDigest, report.Check.EvaluatedAt, origin, report.KnowledgeRevision, report.KnowledgePackDigest); err != nil {
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
	return writeCRIOScopeAndAction(out, claim.Status, claim.ReasonCode, claim.NextAction, facts)
}

func writeCRIOExternalHuman(out interface{ Write([]byte) (int, error) }, report cncfknowledge.Report, from, to, operation, rawDigest string, facts crioFactSummary) error {
	claims := report.Check.Check.Claims
	if len(claims) > 1 {
		return cncfcheck.ErrIntegrity
	}
	status, reason, nextAction := "UNKNOWN", "RULE_TRANSITION_NOT_REVIEWED", "the selected external revision has no rule for this exact transition; no embedded rule was used"
	if len(claims) == 1 {
		status, reason, nextAction = claims[0].Status, claims[0].ReasonCode, claims[0].NextAction
	}
	if _, err := fmt.Fprintf(out, "CRI-O planned ArtifactStore named-reference review\ntransition: %s -> %s\ndeclared operation: %s\nsupplied artifact reference class: %s\nscoped result: %s (%s)\naggregate readiness: UNKNOWN\nraw ImageStatusRequest digest: %s\nprepared input digest: %s\nevaluated at: %s\nknowledge: external signed local revision %s\nknowledge bundle digest: %s\nknowledge trust receipt digest: %s\nknowledge purpose: %s\ncurrent non-revocation: not checked offline\nnetwork used: false\n", from, to, formatCRIOOperation(operation, facts.operationState), formatCRIOReference(facts), status, reason, rawDigest, report.Check.InputFileDigest, report.Knowledge.EvaluatedAt, report.Knowledge.Revision, report.Knowledge.BundleDigest, report.Knowledge.TrustReceiptDigest, report.Knowledge.Purpose); err != nil {
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
	if _, err := fmt.Fprintf(out, "next action: %s\n", crioNextAction(status, reason, nextAction, facts)); err != nil {
		return err
	}
	if report.Knowledge.Purpose == "synthetic_test_only" {
		if _, err := fmt.Fprintln(out, "authority: synthetic test knowledge only; no official Prufyx signing root or compatibility proof"); err != nil {
			return err
		}
	}
	_, err := fmt.Fprintln(out, crioScopeText+" Selected local knowledge is authoritative with no embedded fallback.")
	return err
}

func writeCRIOScopeAndAction(out interface{ Write([]byte) (int, error) }, status, reason, nextAction string, facts crioFactSummary) error {
	if _, err := fmt.Fprintf(out, "next action: %s\n", crioNextAction(status, reason, nextAction, facts)); err != nil {
		return err
	}
	_, err := fmt.Fprintln(out, crioScopeText)
	return err
}

func crioNextAction(status, reason, nextAction string, facts crioFactSummary) string {
	if status == "PASS" {
		return "the supplied request uses a fully-qualified explicit-tag reference in the reviewed grammar; separately validate ArtifactStore contents, target request routing, registry access and runtime behavior"
	}
	if status == "UNKNOWN" && reason != "RULE_TRANSITION_NOT_REVIEWED" && (facts.operationState != "declared" || facts.shortState != "declared") {
		return "this input is outside the reviewed named-reference condition; supply the intended native request and declare --artifact-operation named-reference-resolution, or retain UNKNOWN; do not reshape a real request only to obtain a result"
	}
	return nextAction
}

const crioScopeText = "scope: this checks only the CRI-O 1.35.0 short-name guard for one caller-supplied planned ArtifactStore ImageStatusRequest and declared named-reference-resolution operation. It does not resolve aliases, infer registries, inspect store contents, prove request routing, contact a registry, execute CRI-O, or validate ordinary images, access, pulls, removal, runtime behavior, or whole-upgrade compatibility."

func formatCRIOOperation(operation, state string) string {
	if state != "declared" {
		return "unsupported or not declared"
	}
	return operation + " (caller-declared)"
}

func formatCRIOReference(facts crioFactSummary) string {
	if facts.shortState != "declared" || facts.shortValue == nil {
		return "unsupported or ambiguous"
	}
	if *facts.shortValue {
		return "short explicit-tag reference"
	}
	return "fully-qualified explicit-tag reference"
}
