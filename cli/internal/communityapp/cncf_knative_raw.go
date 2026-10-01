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

type knativePreparedDocument struct {
	Proposed struct {
		Components []struct {
			Component string `json:"component"`
			Facts     []struct {
				ID        string `json:"id"`
				State     string `json:"state"`
				BoolValue *bool  `json:"boolValue,omitempty"`
			} `json:"facts"`
		} `json:"components"`
	} `json:"proposed"`
}

type knativeFactSummary struct {
	state string
	value *bool
}

func (r runtime) cncfKnativeService(path, pin, from, to string, now time.Time, format string, selection *knowledge.SelectionRequest, replayPath string) int {
	raw, err := readCNCFPrivate(path, 1<<20)
	if err != nil {
		return r.knativeInputFailure(err)
	}
	sourceDigest := digestCommunityBytes(raw)
	if pin != "" && pin != sourceDigest {
		return r.knativeIntegrityFailure()
	}
	prepared, err := cncfprepare.PrepareKnativeServing(raw, from, to)
	if err != nil {
		return r.knativeInputFailure(err)
	}
	if prepared.SourceDigest != sourceDigest || prepared.InputDigest != digestCommunityBytes(prepared.CanonicalInputJSON) || !json.Valid(prepared.CanonicalInputJSON) {
		return r.knativeIntegrityFailure()
	}
	fact, err := summarizeKnativePrepared(prepared.CanonicalInputJSON)
	if err != nil {
		return r.knativeIntegrityFailure()
	}
	if selection != nil {
		return r.cncfKnativeExternal(*selection, replayPath, format, from, to, sourceDigest, prepared.CanonicalInputJSON, prepared.InputDigest, fact)
	}
	report, err := cncfcheck.Check("knative", prepared.CanonicalInputJSON, now)
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
	if err := writeKnativeHumanReview(r.stdout, report, from, to, sourceDigest, fact); err != nil {
		return ExitIntegrity
	}
	return cncfcheck.ClaimExit(report)
}

func (r runtime) cncfKnativeExternal(selection knowledge.SelectionRequest, replayPath, format, from, to, sourceDigest string, input []byte, inputDigest string, fact knativeFactSummary) int {
	req := cncfknowledge.Request{Selection: selection, Project: "knative", Input: input, InputDigest: inputDigest}
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
			err = writeKnativeExternalReplay(r.stdout, replay, from, to, sourceDigest, inputDigest, fact, selection)
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
		err = writeKnativeExternalHumanReview(r.stdout, report, from, to, sourceDigest, fact)
	}
	if err != nil {
		return ExitIntegrity
	}
	return cncfknowledge.ClaimExit(report)
}

func summarizeKnativePrepared(raw []byte) (knativeFactSummary, error) {
	var input knativePreparedDocument
	if err := json.Unmarshal(raw, &input); err != nil || len(input.Proposed.Components) != 1 || input.Proposed.Components[0].Component != cncfprepare.KnativeComponent || len(input.Proposed.Components[0].Facts) != 1 {
		return knativeFactSummary{}, cncfcheck.ErrIntegrity
	}
	fact := input.Proposed.Components[0].Facts[0]
	if fact.ID != cncfprepare.KnativeStartupPortFact {
		return knativeFactSummary{}, cncfcheck.ErrIntegrity
	}
	return knativeFactSummary{state: fact.State, value: fact.BoolValue}, nil
}

func writeKnativeHumanReview(out interface{ Write([]byte) (int, error) }, report cncfcheck.Report, from, to, sourceDigest string, fact knativeFactSummary) error {
	if len(report.Check.Claims) != 1 {
		return cncfcheck.ErrIntegrity
	}
	claim := report.Check.Claims[0]
	if _, err := fmt.Fprintf(out, "Knative Serving Service upgrade review\ntransition: %s -> %s\nsetting spec.template.spec.containers[0].ports[0].name versus spec.template.spec.containers[0].startupProbe.httpGet.port: %s\nscoped result: %s (%s)\naggregate: UNKNOWN\nraw Service digest: %s\nprepared input digest: %s\nevaluated at: %s\nknowledge: embedded revision %s\nknowledge pack digest: %s\nnetwork used: false\nService changed: false\n", from, to, formatKnativePortFact(fact), claim.Status, claim.ReasonCode, sourceDigest, report.InputFileDigest, report.Check.EvaluatedAt, report.KnowledgeRevision, report.KnowledgePackDigest); err != nil {
		return err
	}
	for _, source := range claim.Sources {
		if _, err := fmt.Fprintf(out, "pinned source: %s lines %d-%d; revision %s; digest %s\n", source.URL, source.StartLine, source.EndLine, source.Revision, source.ContentDigest); err != nil {
			return err
		}
	}
	if claim.ReasonCode == "RULE_TRANSITION_NOT_REVIEWED" {
		_, err := fmt.Fprintf(out, "next action: %s\n", claim.NextAction)
		return err
	}
	if fact.state != "declared" || fact.value == nil {
		_, err := fmt.Fprintln(out, "next action: this input is outside the reviewed named HTTP startup-probe port condition and remains UNKNOWN; review upstream Knative validation for the intended Service. Do not add a probe or reshape the Service only to obtain a Prufyx result.")
		return err
	}
	if _, err := fmt.Fprintf(out, "next action: %s\n", claim.NextAction); err != nil {
		return err
	}
	_, err := fmt.Fprintln(out, "scope: this evaluates only the Knative Serving v1.23 target named HTTP startup-probe port constraint; other admission rules, API-server behavior, startup, traffic, runtime, and whole-upgrade safety remain unverified.")
	return err
}

func writeKnativeExternalHumanReview(out interface{ Write([]byte) (int, error) }, report cncfknowledge.Report, from, to, sourceDigest string, fact knativeFactSummary) error {
	claims := report.Check.Check.Claims
	status, reason := "UNKNOWN", "RULE_TRANSITION_NOT_REVIEWED"
	if len(claims) > 1 {
		return cncfcheck.ErrIntegrity
	}
	if len(claims) == 1 {
		status, reason = claims[0].Status, claims[0].ReasonCode
	}
	if _, err := fmt.Fprintf(out, "Knative Serving Service upgrade review\ntransition: %s -> %s\nsetting spec.template.spec.containers[0].ports[0].name versus spec.template.spec.containers[0].startupProbe.httpGet.port: %s\nscoped result: %s (%s)\naggregate: UNKNOWN\nraw Service digest: %s\nprepared input digest: %s\nevaluated at: %s\nknowledge: external signed local revision %s\nknowledge bundle digest: %s\nknowledge trust receipt digest: %s\nknowledge purpose: %s\ncurrent non-revocation: not checked offline\nnetwork used: false\nService changed: false\n", from, to, formatKnativePortFact(fact), status, reason, sourceDigest, report.Check.InputFileDigest, report.Knowledge.EvaluatedAt, report.Knowledge.Revision, report.Knowledge.BundleDigest, report.Knowledge.TrustReceiptDigest, report.Knowledge.Purpose); err != nil {
		return err
	}
	if len(claims) == 0 {
		if _, err := fmt.Fprintln(out, "next action: the selected external revision has no rule for this exact transition; no embedded rule was used. Import and explicitly select independently trusted knowledge for the intended transition, or keep the result UNKNOWN."); err != nil {
			return err
		}
	} else {
		claim := claims[0]
		for _, source := range claim.Sources {
			if _, err := fmt.Fprintf(out, "pinned source: %s lines %d-%d; revision %s; digest %s\n", source.URL, source.StartLine, source.EndLine, source.Revision, source.ContentDigest); err != nil {
				return err
			}
		}
		if fact.state != "declared" || fact.value == nil {
			if _, err := fmt.Fprintln(out, "next action: this input is outside the selected named HTTP startup-probe port condition and remains UNKNOWN; review upstream Knative validation for the intended Service. Do not add a probe or reshape the Service only to obtain a Prufyx result."); err != nil {
				return err
			}
		} else if _, err := fmt.Fprintf(out, "next action: %s\n", claim.NextAction); err != nil {
			return err
		}
	}
	if report.Knowledge.Purpose == "synthetic_test_only" {
		if _, err := fmt.Fprintln(out, "authority: synthetic test knowledge only; no official Prufyx signing root or compatibility proof"); err != nil {
			return err
		}
	}
	_, err := fmt.Fprintln(out, "scope: selected local knowledge is authoritative for this check and has no embedded fallback. This evaluates only its exact named HTTP startup-probe port rule; other admission rules, API-server behavior, startup, traffic, runtime, and whole-upgrade safety remain unverified.")
	return err
}

func writeKnativeExternalReplay(out interface{ Write([]byte) (int, error) }, replay cncfknowledge.HistoricalReplay, from, to, sourceDigest, inputDigest string, fact knativeFactSummary, selection knowledge.SelectionRequest) error {
	_, err := fmt.Fprintf(out, "historical external Knative Serving replay: MATCH\ntransition: %s -> %s\nsetting spec.template.spec.containers[0].ports[0].name versus spec.template.spec.containers[0].startupProbe.httpGet.port: %s\nraw Service digest verified now: %s\nprepared input digest: %s\nknowledge revision: %s\nknowledge bundle digest: %s\nknowledge trust receipt digest: %s\noriginal report digest: %s\ncurrent non-revocation: not checked offline\nnetwork used: false\nwhole-upgrade assessment: UNKNOWN\nraw identity: the caller-supplied digest matched this Service, but the saved report binds the minimized prepared observation, selected knowledge, and recorded time rather than the original raw bytes; retain the raw Service and its digest separately.\n", from, to, formatKnativePortFact(fact), sourceDigest, inputDigest, selection.ExpectedRevision, selection.ExpectedBundleDigest, selection.ExpectedTrustReceiptDigest, replay.OriginalReportDigest)
	return err
}

func formatKnativePortFact(fact knativeFactSummary) string {
	if fact.state != "declared" || fact.value == nil {
		return fact.state
	}
	if *fact.value {
		return "mismatch (read from Service)"
	}
	return "match (read from Service)"
}
