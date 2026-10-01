// SPDX-License-Identifier: AGPL-3.0-only

package communityapp

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/prufyx/prufyx/cli/internal/cncfcheck"
	"github.com/prufyx/prufyx/cli/internal/cncfprepare"
)

const argoCDResourceExclusionsRuleID = "argo-cd.resource-exclusions-v2-visibility-preservation.3-0"

func (r runtime) cncfArgoCDResourceExclusions(path, pin, from, to string, complete, precedence bool, intentText string, now time.Time, format string) int {
	raw, err := readCNCFPrivate(path, 1<<20)
	if err != nil {
		return r.fail(withPermissionHint("ARGO_CD_RESOURCE_EXCLUSIONS_INPUT_INVALID", err), ExitUsage)
	}
	sourceDigest := digestCommunityBytes(raw)
	if pin != "" && pin != sourceDigest {
		return r.fail("ARGO_CD_RESOURCE_EXCLUSIONS_INTEGRITY_FAILURE", ExitIntegrity)
	}
	var intent *bool
	if intentText == "true" {
		value := true
		intent = &value
	}
	prepared, err := cncfprepare.PrepareArgoCDResourceExclusions(raw, from, to, complete, precedence, intent)
	if err != nil || prepared.SourceDigest != sourceDigest || prepared.InputDigest != digestCommunityBytes(prepared.CanonicalInputJSON) || !json.Valid(prepared.CanonicalInputJSON) {
		return r.fail("ARGO_CD_RESOURCE_EXCLUSIONS_INPUT_INVALID", ExitUsage)
	}
	report, err := cncfcheck.CheckRule("argo-cd", argoCDResourceExclusionsRuleID, prepared.CanonicalInputJSON, now)
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
	if len(report.Check.Claims) != 1 {
		return r.fail("CNCF report integrity failure", ExitIntegrity)
	}
	claim := report.Check.Claims[0]
	if _, err := fmt.Fprintf(r.stdout, "Argo CD resource-exclusions review\ntransition: %s -> %s\nraw ConfigMap digest: %s\nprepared input digest: %s\nscope: declared v2 visibility preservation only; resource existence, watches, UI, reconciliation, runtime, and whole upgrade remain UNKNOWN\nscoped result: %s (%s)\naggregate: UNKNOWN\nnetwork used: false\n", from, to, sourceDigest, prepared.InputDigest, claim.Status, claim.ReasonCode); err != nil {
		return ExitIntegrity
	}
	for _, source := range claim.Sources {
		if _, err := fmt.Fprintf(r.stdout, "pinned source: %s lines %d-%d; revision %s; digest %s\n", source.URL, source.StartLine, source.EndLine, source.Revision, source.ContentDigest); err != nil {
			return ExitIntegrity
		}
	}
	if _, err := fmt.Fprintf(r.stdout, "next action: %s\n", claim.NextAction); err != nil {
		return ExitIntegrity
	}
	return cncfcheck.ClaimExit(report)
}
