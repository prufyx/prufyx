// SPDX-License-Identifier: AGPL-3.0-only

package communityapp

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/prufyx/prufyx/cli/internal/cncfcheck"
	"github.com/prufyx/prufyx/cli/internal/cncfprepare"
)

// cncfKarmadaCheck is the native one-step route for the reviewed Karmada
// legacy application purgeMode rule. It reuses the already-existing
// PrepareKarmada adapter, which already evaluated the 1.18.3 -> 1.19.0 pair
// via the two-step prepare/check flow before this route was wired; it
// authors no new compatibility claim.
func (r runtime) cncfKarmadaCheck(path, pin, from, to, distribution, admission string, now time.Time, format string) int {
	raw, err := readCNCFPrivate(path, 1<<20)
	if err != nil {
		return r.fail(withPermissionHint("KARMADA_RESOURCE_INPUT_INVALID", err), ExitUsage)
	}
	sourceDigest := digestCommunityBytes(raw)
	if pin != "" && pin != sourceDigest {
		return r.fail("KARMADA_RESOURCE_INTEGRITY_FAILURE", ExitIntegrity)
	}
	prepared, err := cncfprepare.PrepareKarmada(raw, from, to, distribution, admission)
	if err != nil || prepared.SourceDigest != sourceDigest || prepared.InputDigest != digestCommunityBytes(prepared.CanonicalInputJSON) || !json.Valid(prepared.CanonicalInputJSON) {
		return r.fail("KARMADA_RESOURCE_INPUT_INVALID", ExitUsage)
	}
	report, err := cncfcheck.Check("karmada", prepared.CanonicalInputJSON, now)
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
	if _, err := fmt.Fprintf(r.stdout, "Karmada resource review\ntransition: %s -> %s\nraw resource digest: %s\nprepared input digest: %s\nscope: one caller-selected PropagationPolicy or ClusterPropagationPolicy resource only; a witness is conclusive but absence is never proven; CRD schema, admission, and whole upgrade remain UNKNOWN\naggregate: UNKNOWN\nnetwork used: false\n", from, to, sourceDigest, prepared.InputDigest); err != nil {
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
