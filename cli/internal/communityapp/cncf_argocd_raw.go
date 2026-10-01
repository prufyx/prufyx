// SPDX-License-Identifier: AGPL-3.0-only

package communityapp

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/prufyx/prufyx/cli/internal/cncfcheck"
	"github.com/prufyx/prufyx/cli/internal/cncfprepare"
)

type argoCDPreparedDocument struct {
	Proposed struct {
		Components []struct {
			Component string `json:"component"`
			Version   string `json:"version"`
			Facts     []struct {
				ID        string `json:"id"`
				State     string `json:"state"`
				BoolValue *bool  `json:"boolValue,omitempty"`
			} `json:"facts"`
		} `json:"components"`
	} `json:"proposed"`
}

type argoCDFactSummary struct {
	state string
	value *bool
}

func (r runtime) cncfArgoCDConfigMap(path, pin, from, to, intentText string, now time.Time, format string) int {
	raw, err := readCNCFPrivate(path, 1<<20)
	if err != nil {
		return r.argoCDInputFailure(err)
	}
	sourceDigest := digestCommunityBytes(raw)
	if pin != "" && pin != sourceDigest {
		return r.argoCDIntegrityFailure()
	}
	var intent *bool
	if intentText != "" {
		value := intentText == "true"
		intent = &value
	}
	prepared, err := cncfprepare.PrepareArgoCD(raw, from, to, intent)
	if err != nil {
		return r.argoCDInputFailure(err)
	}
	if prepared.SourceDigest != sourceDigest || prepared.InputDigest != digestCommunityBytes(prepared.CanonicalInputJSON) || !json.Valid(prepared.CanonicalInputJSON) {
		return r.argoCDIntegrityFailure()
	}
	setting, preparedIntent, err := summarizeArgoCDPrepared(prepared.CanonicalInputJSON)
	if err != nil {
		return r.argoCDIntegrityFailure()
	}
	report, err := cncfcheck.CheckRule("argo-cd", "argo-cd.required-rbac-inheritance.3-0", prepared.CanonicalInputJSON, now)
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
	if err := writeArgoCDHumanReview(r.stdout, report, from, to, sourceDigest, setting, preparedIntent); err != nil {
		return ExitIntegrity
	}
	return cncfcheck.ClaimExit(report)
}

func digestCommunityBytes(raw []byte) string {
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func summarizeArgoCDPrepared(raw []byte) (argoCDFactSummary, argoCDFactSummary, error) {
	var input argoCDPreparedDocument
	if err := json.Unmarshal(raw, &input); err != nil || len(input.Proposed.Components) != 1 || input.Proposed.Components[0].Component != cncfprepare.ArgoCDComponent {
		return argoCDFactSummary{}, argoCDFactSummary{}, cncfcheck.ErrIntegrity
	}
	facts := map[string]argoCDFactSummary{}
	for _, fact := range input.Proposed.Components[0].Facts {
		facts[fact.ID] = argoCDFactSummary{state: fact.State, value: fact.BoolValue}
	}
	setting, settingOK := facts[cncfprepare.ArgoCDInheritanceDisabledFact]
	intent, intentOK := facts[cncfprepare.ArgoCDInheritedPermissionsFact]
	if !settingOK || !intentOK || len(facts) != 2 {
		return argoCDFactSummary{}, argoCDFactSummary{}, cncfcheck.ErrIntegrity
	}
	return setting, intent, nil
}

func writeArgoCDHumanReview(out interface{ Write([]byte) (int, error) }, report cncfcheck.Report, from, to, sourceDigest string, setting, intent argoCDFactSummary) error {
	if len(report.Check.Claims) != 1 {
		return cncfcheck.ErrIntegrity
	}
	claim := report.Check.Claims[0]
	if _, err := fmt.Fprintf(out, "Argo CD ConfigMap upgrade review\ntransition: %s -> %s\nsetting server.rbac.disableApplicationFineGrainedRBACInheritance: %s\nrequires inherited application update/delete permissions: %s\nscoped result: %s (%s)\naggregate: UNKNOWN\nraw ConfigMap digest: %s\nprepared input digest: %s\nevaluated at: %s\nknowledge: embedded revision %s\nknowledge pack digest: %s\nnetwork used: false\nConfigMap or RBAC changed: false\n", from, to, formatArgoCDSetting(setting), formatArgoCDIntent(intent), claim.Status, claim.ReasonCode, sourceDigest, report.InputFileDigest, report.Check.EvaluatedAt, report.KnowledgeRevision, report.KnowledgePackDigest); err != nil {
		return err
	}
	for _, source := range claim.Sources {
		if _, err := fmt.Fprintf(out, "pinned source: %s lines %d-%d; revision %s; digest %s\n", source.URL, source.StartLine, source.EndLine, source.Revision, source.ContentDigest); err != nil {
			return err
		}
	}
	switch {
	case intent.state == "missing":
		_, err := fmt.Fprintln(out, "decision needed: do managed resources need to inherit application-level update/delete permissions? Review the intended RBAC model, then repeat with --requires-inherited-application-permissions true or false.")
		return err
	case intent.state == "declared" && intent.value != nil && !*intent.value:
		_, err := fmt.Fprintln(out, "next action: this rule does not apply when inherited application permissions are not required; review explicit resource grants and do not change the setting based on this UNKNOWN result.")
		return err
	case claim.ReasonCode == "RULE_FACT_UNAVAILABLE":
		_, err := fmt.Fprintln(out, "next action: inspect the ConfigMap key and provide the exact string true or false; a missing or malformed value remains UNKNOWN.")
		return err
	default:
		if _, err := fmt.Fprintf(out, "next action: %s\n", claim.NextAction); err != nil {
			return err
		}
		if claim.Status == "BLOCKED" || claim.Status == "PASS" {
			_, err := fmt.Fprintln(out, "permission impact: false restores v2 inheritance behavior, which can cause application-level update/delete grants to apply to managed resources; review explicit resource grants and the intended access model before editing.")
			return err
		}
	}
	return nil
}

func formatArgoCDSetting(fact argoCDFactSummary) string {
	if fact.state != "declared" || fact.value == nil {
		return fact.state
	}
	if *fact.value {
		return "true (read from ConfigMap)"
	}
	return "false (read from ConfigMap)"
}

func formatArgoCDIntent(fact argoCDFactSummary) string {
	if fact.state != "declared" || fact.value == nil {
		return fact.state
	}
	if *fact.value {
		return "true (operator-declared)"
	}
	return "false (operator-declared)"
}
