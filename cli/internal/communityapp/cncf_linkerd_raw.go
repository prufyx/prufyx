// SPDX-License-Identifier: AGPL-3.0-only

package communityapp

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/prufyx/prufyx/cli/internal/cncfcheck"
	"github.com/prufyx/prufyx/cli/internal/cncfprepare"
)

// cncfLinkerdCheck is the native one-step route for the reviewed Linkerd
// mTLS identity-selector rule. It reuses the already-existing PrepareLinkerd
// adapter, which already evaluated the 2.13.7 -> 2.14.0 pair via the
// two-step prepare/check flow before this route was wired; it authors no
// new compatibility claim.
func (r runtime) cncfLinkerdCheck(path, pin, from, to, distribution, schemaValidation string, now time.Time, format string) int {
	raw, err := readCNCFPrivate(path, 1<<20)
	if err != nil {
		return r.fail(withPermissionHint("LINKERD_RESOURCE_INPUT_INVALID", err), ExitUsage)
	}
	sourceDigest := digestCommunityBytes(raw)
	if pin != "" && pin != sourceDigest {
		return r.fail("LINKERD_RESOURCE_INTEGRITY_FAILURE", ExitIntegrity)
	}
	prepared, err := cncfprepare.PrepareLinkerd(raw, from, to, distribution, schemaValidation)
	if err != nil || prepared.SourceDigest != sourceDigest || prepared.InputDigest != digestCommunityBytes(prepared.CanonicalInputJSON) || !json.Valid(prepared.CanonicalInputJSON) {
		return r.fail("LINKERD_RESOURCE_INPUT_INVALID", ExitUsage)
	}
	report, err := r.cncfChecker().Check("linkerd", prepared.CanonicalInputJSON, now)
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
	if _, err := fmt.Fprintf(r.stdout, "Linkerd resource review\ntransition: %s -> %s\nraw resource digest: %s\nprepared input digest: %s\nscope: one caller-selected MeshTLSAuthentication resource only; CRD schema, admission, and whole upgrade remain UNKNOWN\naggregate: UNKNOWN\nnetwork used: false\n", from, to, sourceDigest, prepared.InputDigest); err != nil {
		return ExitIntegrity
	}
	for _, claim := range report.Check.Claims {
		printed, err := writeClaimHeadline(r.stdout, claim)
		if err != nil {
			return ExitIntegrity
		}
		if !printed {
			continue
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
