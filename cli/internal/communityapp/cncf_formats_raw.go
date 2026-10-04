// SPDX-License-Identifier: AGPL-3.0-only

package communityapp

import (
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	"github.com/prufyx/prufyx/cli/internal/cncfcheck"
	"github.com/prufyx/prufyx/cli/internal/cncfknowledge"
	"github.com/prufyx/prufyx/cli/internal/cncfprepare"
	"github.com/prufyx/prufyx/cli/internal/knowledge"
)

func (r runtime) cncfNativeFormat(project, path, pin, from, to, operation string, now time.Time, format string, selection *knowledge.SelectionRequest, replayPath string) int {
	raw, err := readCNCFPrivate(path, 1<<20)
	if err != nil {
		return r.fail(withPermissionHint("NATIVE_FORMAT_PREPARATION_INPUT_INVALID", err), ExitUsage)
	}
	rawDigest := digestCommunityBytes(raw)
	if pin != "" && pin != rawDigest {
		return r.knativeIntegrityFailure()
	}

	var prepared cncfprepare.Prepared
	switch project {
	case "distribution":
		prepared, err = cncfprepare.PrepareDistributionManifest(raw, from, to)
	case "container-network-interface-cni":
		prepared, err = cncfprepare.PrepareCNISpecConfiguration(raw, from, to, operation)
	case "emissary-ingress":
		prepared, err = cncfprepare.PrepareEmissary(raw, from, to)
	case "openfga":
		var complete *bool
		if operation != "" {
			value, parseErr := strconv.ParseBool(operation)
			if parseErr != nil {
				return r.fail("OPENFGA_EFFECTIVE_CONFIG_INPUT_INVALID", ExitUsage)
			}
			complete = &value
		}
		prepared, err = cncfprepare.PrepareOpenFGAOIDC(raw, from, to, complete)
	default:
		return r.knativeIntegrityFailure()
	}
	if err != nil {
		return r.fail("NATIVE_FORMAT_PREPARATION_INPUT_INVALID", ExitUsage)
	}
	if prepared.SourceDigest != rawDigest || prepared.InputDigest != digestCommunityBytes(prepared.CanonicalInputJSON) || !json.Valid(prepared.CanonicalInputJSON) {
		return r.knativeIntegrityFailure()
	}
	if selection != nil {
		return r.cncfNativeFormatExternal(project, *selection, replayPath, format, from, to, operation, rawDigest, prepared)
	}

	report, err := r.cncfChecker().Check(project, prepared.CanonicalInputJSON, now)
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
	if err := writeNativeFormatHuman(r.stdout, report, project, from, to, operation, rawDigest, prepared); err != nil {
		return ExitIntegrity
	}
	return cncfcheck.ClaimExit(report)
}

func (r runtime) cncfNativeFormatExternal(project string, selection knowledge.SelectionRequest, replayPath, format, from, to, operation, rawDigest string, prepared cncfprepare.Prepared) int {
	req := cncfknowledge.Request{Selection: selection, Project: project, Input: prepared.CanonicalInputJSON, InputDigest: prepared.InputDigest}
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
			_, err = fmt.Fprintf(r.stdout, "historical external native-format replay: MATCH\nproject: %s\ntransition: %s -> %s\nraw input digest verified now: %s\nprepared input digest: %s\nknowledge revision: %s\nknowledge bundle digest: %s\nknowledge trust receipt digest: %s\noriginal report digest: %s\ncurrent non-revocation: not checked offline\nnetwork used: false\nwhole-migration assessment: UNKNOWN\n", project, from, to, rawDigest, prepared.InputDigest, selection.ExpectedRevision, selection.ExpectedBundleDigest, selection.ExpectedTrustReceiptDigest, replay.OriginalReportDigest)
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
		claims := report.Check.Check.Claims
		status, reason, action := "UNKNOWN", "RULE_TRANSITION_NOT_REVIEWED", "the selected external revision has no rule for this exact transition; no embedded rule was used"
		if len(claims) > 1 {
			return r.knativeIntegrityFailure()
		}
		if len(claims) == 1 {
			status, reason, action = claims[0].Status, claims[0].ReasonCode, claims[0].NextAction
		}
		declaredOperation := ""
		if project == "container-network-interface-cni" {
			declaredOperation = "unsupported or not declared"
			if operation == cncfprepare.CNISpecMigrationOperation {
				declaredOperation = cncfprepare.CNISpecMigrationOperation
			}
			declaredOperation = "\ndeclared operation: " + declaredOperation
		}
		_, err = fmt.Fprintf(r.stdout, "native-format preflight\nproject: %s\ntransition: %s -> %s%s\ninput classification: %s\nscoped result: %s (%s)\naggregate: UNKNOWN\nraw input digest: %s\nprepared input digest: %s\nevaluated at: %s\nknowledge: external signed local revision %s\nknowledge bundle digest: %s\nknowledge trust receipt digest: %s\nknowledge purpose: %s\ncurrent non-revocation: not checked offline\nnetwork used: false\nnext action: %s\nscope: selected local knowledge is authoritative for this exact input and has no embedded fallback; registry, plugin, network, and runtime behavior remain unresolved.\n", project, from, to, declaredOperation, prepared.Reason, status, reason, rawDigest, report.Check.InputFileDigest, report.Knowledge.EvaluatedAt, report.Knowledge.Revision, report.Knowledge.BundleDigest, report.Knowledge.TrustReceiptDigest, report.Knowledge.Purpose, action)
	}
	if err != nil {
		return ExitIntegrity
	}
	return cncfknowledge.ClaimExit(report)
}

func writeNativeFormatHuman(out interface{ Write([]byte) (int, error) }, report cncfcheck.Report, project, from, to, operation, rawDigest string, prepared cncfprepare.Prepared) error {
	if len(report.Check.Claims) != 1 {
		return cncfcheck.ErrIntegrity
	}
	claim := report.Check.Claims[0]
	title := "Distribution image-manifest format preflight"
	subject := "caller-supplied image manifest"
	intent := ""
	scope := "scope: this checks only removal of Distribution's Docker schema1 manifest handler in the exact source plan. It does not contact a registry, establish source deployment settings, validate signatures or referenced content, store or pull an image, select a platform, or prove runtime compatibility."
	if project == "container-network-interface-cni" {
		title = "CNI configuration-spec migration preflight"
		subject = "caller-supplied CNI configuration"
		if operation == cncfprepare.CNISpecMigrationOperation {
			intent = "declared operation: configuration-spec-migration\n"
		} else {
			intent = "declared operation: unsupported or not declared\n"
		}
		scope = "scope: the versions identify CNI configuration specifications, not the containernetworking/cni library, a plugin, or a runtime. This checks only the target 1.0.0 List shape for one caller-supplied configuration and declared migration intent; plugin support, chained execution, networking, and runtime compatibility remain unresolved."
	} else if project == "emissary-ingress" {
		title = "Emissary-Ingress direct diagd argv preflight"
		subject = "caller-declared direct diagd argv JSON"
		scope = "scope: this checks only the reviewed removed --metrics-endpoint option in a bounded direct diagd argv. Wrappers, environment, Helm values, banner endpoint behavior, and runtime remain unresolved."
	} else if project == "openfga" {
		title = "OpenFGA effective configuration preflight"
		subject = "caller-supplied effective configuration"
		if operation == "true" {
			scope = "scope: this reads strictly parsed nested authn JSON only. The caller declares file, environment, and flag precedence complete; custom or patched upstream behavior, URL validation, tokens, startup, and runtime remain outside this check."
		} else {
			scope = "scope: this reads strictly parsed nested authn JSON only. File, environment, and flag precedence was not declared complete, so this input cannot produce a conclusive claim. Custom or patched upstream behavior, URL validation, tokens, startup, and runtime remain outside this check."
		}
	}
	if _, err := fmt.Fprintf(out, "%s\ntransition: %s -> %s\n%sinput classification: %s\nscoped result: %s (%s)\naggregate: UNKNOWN\nraw input digest: %s\nprepared input digest: %s\nevaluated at: %s\nknowledge: embedded revision %s\nknowledge pack digest: %s\nnetwork used: false\ninput file handling: Prufyx reads but does not modify the %s.\n", title, from, to, intent, prepared.Reason, claim.Status, claim.ReasonCode, rawDigest, report.InputFileDigest, report.Check.EvaluatedAt, report.KnowledgeRevision, report.KnowledgePackDigest, subject); err != nil {
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
	if _, err := fmt.Fprintf(out, "next action: %s\n", claim.NextAction); err != nil {
		return err
	}
	_, err := fmt.Fprintln(out, scope)
	return err
}
