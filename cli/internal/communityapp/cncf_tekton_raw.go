// SPDX-License-Identifier: AGPL-3.0-only

package communityapp

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/prufyx/prufyx/cli/internal/cncfcheck"
	"github.com/prufyx/prufyx/cli/internal/cncfprepare"
)

// cncfTektonConfigObservabilityCheck is the native one-step route for the
// reviewed Tekton Pipelines metrics-protocol migration rule. It reads only the
// one reviewed data key from one caller-selected config-observability
// ConfigMap, and leaves distribution, effective-composition completeness, the
// retention requirement and the proposed system namespace as the caller's own
// declarations. It authors no new compatibility claim and never reads a
// cluster.
func (r runtime) cncfTektonConfigObservabilityCheck(path, pin, from, to, distribution, systemNamespace, completeText, retainText string, now time.Time, format string) int {
	raw, err := readCNCFPrivate(path, 1<<20)
	if err != nil {
		return r.fail(withPermissionHint("TEKTON_CONFIG_OBSERVABILITY_INPUT_INVALID", err), ExitUsage)
	}
	sourceDigest := digestCommunityBytes(raw)
	if pin != "" && pin != sourceDigest {
		return r.fail("TEKTON_CONFIG_OBSERVABILITY_INTEGRITY_FAILURE", ExitIntegrity)
	}
	complete := cncfOptionalBool(completeText)
	retainRequired := cncfOptionalBool(retainText)
	prepared, err := cncfprepare.PrepareTektonConfigObservability(raw, from, to, distribution, systemNamespace, complete, retainRequired)
	if err != nil || prepared.SourceDigest != sourceDigest || prepared.InputDigest != digestCommunityBytes(prepared.CanonicalInputJSON) || !json.Valid(prepared.CanonicalInputJSON) {
		return r.fail("TEKTON_CONFIG_OBSERVABILITY_INPUT_INVALID", ExitUsage)
	}
	report, err := cncfcheck.Check("tekton", prepared.CanonicalInputJSON, now)
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
	if _, err := fmt.Fprintf(r.stdout, "Tekton config-observability review\ntransition: %s -> %s\nraw ConfigMap digest: %s\nprepared input digest: %s\nscope: the one reviewed metrics-protocol data key in one caller-selected config-observability ConfigMap only; the removed legacy metrics.backend-destination key is never read as a protocol, effective composition, endpoint configuration, scrape availability, dashboards, alerts, runtime rollout and whole upgrade remain UNKNOWN\naggregate: UNKNOWN\nnetwork used: false\n", from, to, sourceDigest, prepared.InputDigest); err != nil {
		return ExitIntegrity
	}
	for _, claim := range report.Check.Claims {
		if _, err := fmt.Fprintf(r.stdout, "%s: %s (%s)\nnext action: %s\n", claim.RuleID, claim.Status, claim.ReasonCode, claim.NextAction); err != nil {
			return ExitIntegrity
		}
		for _, source := range claim.Sources {
			if _, err := fmt.Fprintf(r.stdout, "pinned source: %s lines %d-%d; revision %s; digest %s\n", source.URL, source.StartLine, source.EndLine, source.Revision, source.ContentDigest); err != nil {
				return ExitIntegrity
			}
		}
	}
	return cncfcheck.ClaimExit(report)
}

// cncfOptionalBool converts one already-validated explicit true/false operator
// declaration. An empty selector stays undeclared; it is never defaulted.
func cncfOptionalBool(text string) *bool {
	if text != "true" && text != "false" {
		return nil
	}
	value := text == "true"
	return &value
}
