// SPDX-License-Identifier: AGPL-3.0-only

package communityapp

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/prufyx/prufyx/cli/internal/cncfcheck"
	"github.com/prufyx/prufyx/cli/internal/cncfprepare"
)

// cncfArgoCDLatestRepository is the native one-step route for the reviewed
// Helm 4 plain-HTTP OCI repository rule. It reuses the already-existing
// PrepareArgoCDLatestRepository adapter, which already evaluated all five
// reviewed 3.5.2 latest-target origins via the two-step prepare/check flow
// before this route was wired; it authors no new compatibility claim.
func (r runtime) cncfArgoCDLatestRepository(path, pin, from, to, distribution string, settingsResolvedText, usesPlainHTTPText string, now time.Time, format string) int {
	raw, err := readCNCFPrivate(path, 1<<20)
	if err != nil {
		return r.fail(withPermissionHint("ARGO_CD_REPOSITORY_INPUT_INVALID", err), ExitUsage)
	}
	sourceDigest := digestCommunityBytes(raw)
	if pin != "" && pin != sourceDigest {
		return r.fail("ARGO_CD_REPOSITORY_INTEGRITY_FAILURE", ExitIntegrity)
	}
	var settingsResolved, usesPlainHTTP *bool
	if settingsResolvedText == "true" || settingsResolvedText == "false" {
		value := settingsResolvedText == "true"
		settingsResolved = &value
	}
	if usesPlainHTTPText == "true" || usesPlainHTTPText == "false" {
		value := usesPlainHTTPText == "true"
		usesPlainHTTP = &value
	}
	prepared, err := cncfprepare.PrepareArgoCDLatestRepository(raw, from, to, distribution, settingsResolved, usesPlainHTTP)
	if err != nil || prepared.SourceDigest != sourceDigest || prepared.InputDigest != digestCommunityBytes(prepared.CanonicalInputJSON) || !json.Valid(prepared.CanonicalInputJSON) {
		return r.fail("ARGO_CD_REPOSITORY_INPUT_INVALID", ExitUsage)
	}
	report, err := cncfcheck.Check("argo-cd", prepared.CanonicalInputJSON, now)
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
	if _, err := fmt.Fprintf(r.stdout, "Argo CD repository review\ntransition: %s -> %s\nraw Secret digest: %s\nprepared input digest: %s\nscope: one caller-selected pre-apply repository Secret only; connectivity, Helm execution, and whole upgrade remain UNKNOWN\naggregate: UNKNOWN\nnetwork used: false\n", from, to, sourceDigest, prepared.InputDigest); err != nil {
		return ExitIntegrity
	}
	for _, claim := range report.Check.Claims {
		if _, err := fmt.Fprintf(r.stdout, "%s: %s (%s)\nnext action: %s\n", claim.RuleID, claim.Status, claim.ReasonCode, claim.NextAction); err != nil {
			return ExitIntegrity
		}
		if _, err := fmt.Fprintln(r.stdout, claim.EvidenceBasisLine()); err != nil {
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
