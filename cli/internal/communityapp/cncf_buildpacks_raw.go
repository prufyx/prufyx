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

type buildpacksFactSummary struct{ currentSupport, proposedSupport string }

func (r runtime) cncfBuildpacksLifecycle(currentPath, proposedPath, currentPin, proposedPin, from, to, currentAPI, proposedAPI string, now time.Time, format string, selection *knowledge.SelectionRequest, replayPath string) int {
	currentRaw, err := readCNCFPrivate(currentPath, 1<<20)
	if err != nil {
		return r.buildpacksInputFailure(err)
	}
	proposedRaw, err := readCNCFPrivate(proposedPath, 1<<20)
	if err != nil {
		return r.buildpacksInputFailure(err)
	}
	currentDigest, proposedDigest := digestCommunityBytes(currentRaw), digestCommunityBytes(proposedRaw)
	if (currentPin != "" && currentPin != currentDigest) || (proposedPin != "" && proposedPin != proposedDigest) {
		return r.knativeIntegrityFailure()
	}
	prepared, err := cncfprepare.PrepareBuildpacksLifecycle(currentRaw, proposedRaw, from, to, currentAPI, proposedAPI)
	if err != nil {
		return r.buildpacksInputFailure(err)
	}
	if prepared.CurrentSourceDigest != currentDigest || prepared.ProposedSourceDigest != proposedDigest || prepared.InputDigest != digestCommunityBytes(prepared.CanonicalInputJSON) || !json.Valid(prepared.CanonicalInputJSON) {
		return r.knativeIntegrityFailure()
	}
	facts, err := summarizeBuildpacksPrepared(prepared.CanonicalInputJSON)
	if err != nil {
		return r.knativeIntegrityFailure()
	}
	if selection != nil {
		return r.cncfBuildpacksExternal(*selection, replayPath, format, from, to, currentAPI, proposedAPI, currentDigest, proposedDigest, prepared.CanonicalInputJSON, prepared.InputDigest, facts)
	}
	report, err := cncfcheck.Check("buildpacks", prepared.CanonicalInputJSON, now)
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
	if err := writeBuildpacksHuman(r.stdout, report, from, to, currentAPI, proposedAPI, currentDigest, proposedDigest, facts, "embedded"); err != nil {
		return ExitIntegrity
	}
	return cncfcheck.ClaimExit(report)
}

func (r runtime) cncfBuildpacksExternal(selection knowledge.SelectionRequest, replayPath, format, from, to, currentAPI, proposedAPI, currentDigest, proposedDigest string, input []byte, inputDigest string, facts buildpacksFactSummary) int {
	req := cncfknowledge.Request{Selection: selection, Project: "buildpacks", Input: input, InputDigest: inputDigest}
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
			_, err = fmt.Fprintf(r.stdout, "historical external Buildpacks Lifecycle replay: MATCH\ntransition: %s -> %s\nCNB_PLATFORM_API: current %s; proposed %s\ncurrent supplied config digest verified now: %s\nproposed supplied config digest verified now: %s\nprepared input digest: %s\nknowledge revision: %s\nknowledge bundle digest: %s\nknowledge trust receipt digest: %s\noriginal report digest: %s\ncurrent non-revocation: not checked offline\nnetwork used: false\nwhole-upgrade assessment: UNKNOWN\nraw identity: both caller-supplied digests matched these files, but the saved report binds minimized API declarations, support observations, selected knowledge, and recorded time rather than original supplied bytes.\n", from, to, currentAPI, proposedAPI, currentDigest, proposedDigest, inputDigest, selection.ExpectedRevision, selection.ExpectedBundleDigest, selection.ExpectedTrustReceiptDigest, replay.OriginalReportDigest)
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
		err = writeBuildpacksExternalHuman(r.stdout, report, from, to, currentAPI, proposedAPI, currentDigest, proposedDigest, facts)
	}
	if err != nil {
		return ExitIntegrity
	}
	return cncfknowledge.ClaimExit(report)
}

func summarizeBuildpacksPrepared(raw []byte) (buildpacksFactSummary, error) {
	var input struct {
		Current, Proposed struct {
			Components []struct {
				Component string `json:"component"`
				Facts     []struct {
					ID, State string
					BoolValue *bool `json:"boolValue,omitempty"`
				} `json:"facts"`
			} `json:"components"`
		}
	}
	if json.Unmarshal(raw, &input) != nil || len(input.Current.Components) != 1 || len(input.Proposed.Components) != 1 || input.Current.Components[0].Component != cncfprepare.BuildpacksComponent || input.Proposed.Components[0].Component != cncfprepare.BuildpacksComponent {
		return buildpacksFactSummary{}, cncfcheck.ErrIntegrity
	}
	find := func(facts []struct {
		ID, State string
		BoolValue *bool `json:"boolValue,omitempty"`
	}) (string, error) {
		for _, fact := range facts {
			if fact.ID == cncfprepare.BuildpacksSupportsAPIFact {
				if fact.State != "declared" || fact.BoolValue == nil {
					return fact.State, nil
				}
				if *fact.BoolValue {
					return "declared supported", nil
				}
				return "not declared supported", nil
			}
		}
		return "", cncfcheck.ErrIntegrity
	}
	current, err := find(input.Current.Components[0].Facts)
	if err != nil {
		return buildpacksFactSummary{}, err
	}
	proposed, err := find(input.Proposed.Components[0].Facts)
	if err != nil {
		return buildpacksFactSummary{}, err
	}
	return buildpacksFactSummary{currentSupport: current, proposedSupport: proposed}, nil
}

func writeBuildpacksHuman(out interface{ Write([]byte) (int, error) }, report cncfcheck.Report, from, to, currentAPI, proposedAPI, currentDigest, proposedDigest string, facts buildpacksFactSummary, origin string) error {
	if len(report.Check.Claims) != 1 {
		return cncfcheck.ErrIntegrity
	}
	claim := report.Check.Claims[0]
	if _, err := fmt.Fprintf(out, "Buildpacks Lifecycle Platform API plan review\ntransition: Lifecycle %s -> %s\nCNB_PLATFORM_API: current %s (%s); proposed %s (%s)\nscoped result: %s (%s)\naggregate: UNKNOWN\ncurrent supplied config digest: %s\nproposed supplied config digest: %s\nprepared input digest: %s\nevaluated at: %s\nknowledge: %s revision %s\nknowledge pack digest: %s\nnetwork used: false\ninput file handling: Prufyx does not modify the supplied files; their separate digests do not assert that their complete contents are equal.\n", from, to, currentAPI, facts.currentSupport, proposedAPI, facts.proposedSupport, claim.Status, claim.ReasonCode, currentDigest, proposedDigest, report.InputFileDigest, report.Check.EvaluatedAt, origin, report.KnowledgeRevision, report.KnowledgePackDigest); err != nil {
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
	nextAction := claim.NextAction
	if claim.Status == "UNKNOWN" && claim.ReasonCode != "RULE_TRANSITION_NOT_REVIEWED" {
		nextAction = "the supplied config-shaped labels or selected API are outside this reviewed projection; verify the Lifecycle identities and API declarations from your own trusted source before choosing a compatible plan"
	}
	if _, err := fmt.Fprintf(out, "next action: %s\n", nextAction); err != nil {
		return err
	}
	_, err := fmt.Fprintln(out, "scope: Lifecycle labels are declarations in supplied bytes, not official registry provenance. PASS means only that target metadata declares the selected API; deprecation policy, platform implementation support, negotiation, build, runtime, and whole-upgrade safety remain unverified. CNB_DEPRECATION_MODE=error can reject a deprecated but supported API.")
	return err
}

func writeBuildpacksExternalHuman(out interface{ Write([]byte) (int, error) }, report cncfknowledge.Report, from, to, currentAPI, proposedAPI, currentDigest, proposedDigest string, facts buildpacksFactSummary) error {
	claims := report.Check.Check.Claims
	if len(claims) == 0 {
		_, err := fmt.Fprintf(out, "Buildpacks Lifecycle Platform API plan review\ntransition: Lifecycle %s -> %s\nCNB_PLATFORM_API: current %s (%s); proposed %s (%s)\nscoped result: UNKNOWN (RULE_TRANSITION_NOT_REVIEWED)\naggregate: UNKNOWN\ncurrent supplied config digest: %s\nproposed supplied config digest: %s\nprepared input digest: %s\nevaluated at: %s\nknowledge: external signed local revision %s\nknowledge bundle digest: %s\nknowledge trust receipt digest: %s\nnetwork used: false\nnext action: the selected external revision has no rule for this exact plan; no embedded rule was used.\nscope: selected local knowledge is authoritative with no embedded fallback; supplied Lifecycle metadata is not registry provenance and whole-upgrade safety remains UNKNOWN.\n", from, to, currentAPI, facts.currentSupport, proposedAPI, facts.proposedSupport, currentDigest, proposedDigest, report.Check.InputFileDigest, report.Knowledge.EvaluatedAt, report.Knowledge.Revision, report.Knowledge.BundleDigest, report.Knowledge.TrustReceiptDigest)
		return err
	}
	if len(claims) != 1 {
		return cncfcheck.ErrIntegrity
	}
	if err := writeBuildpacksHuman(out, report.Check, from, to, currentAPI, proposedAPI, currentDigest, proposedDigest, facts, "external signed local"); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(out, "knowledge bundle digest: %s\nknowledge trust receipt digest: %s\n", report.Knowledge.BundleDigest, report.Knowledge.TrustReceiptDigest); err != nil {
		return err
	}
	if report.Knowledge.Purpose != "" {
		if _, err := fmt.Fprintf(out, "knowledge purpose: %s\n", report.Knowledge.Purpose); err != nil {
			return err
		}
	}
	_, err := fmt.Fprintln(out, "external authority: the selected verified local revision is authoritative; no embedded fallback was used.")
	return err
}
