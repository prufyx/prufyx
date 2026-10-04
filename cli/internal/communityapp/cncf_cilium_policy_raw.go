// SPDX-License-Identifier: AGPL-3.0-only

package communityapp

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/prufyx/prufyx/cli/internal/cncfcheck"
	"github.com/prufyx/prufyx/cli/internal/cncfprepare"
)

// cncfCiliumPolicyCheck is the native one-step route for the reviewed Cilium
// nonempty fromRequires/toRequires removal rules. It reuses the
// already-existing PrepareCilium adapter, which already evaluated both the
// 1.18.6 -> 1.19.0 and 1.18.13 -> 1.19.7 pairs via the two-step prepare/check
// flow before this route was wired; it authors no new compatibility claim.
// A completeSet declaration can only ever be used to project an absent
// witness; the adapter never discovers set completeness from a cluster.
func (r runtime) cncfCiliumPolicyCheck(path, pin, from, to, completeSetText string, now time.Time, format string) int {
	raw, err := readCNCFPrivate(path, 1<<20)
	if err != nil {
		return r.fail(withPermissionHint("CILIUM_POLICY_INPUT_INVALID", err), ExitUsage)
	}
	sourceDigest := digestCommunityBytes(raw)
	if pin != "" && pin != sourceDigest {
		return r.fail("CILIUM_POLICY_INTEGRITY_FAILURE", ExitIntegrity)
	}
	var completeSet *bool
	if completeSetText == "true" || completeSetText == "false" {
		value := completeSetText == "true"
		completeSet = &value
	}
	prepared, err := cncfprepare.PrepareCilium(raw, from, to, completeSet)
	if err != nil || prepared.SourceDigest != sourceDigest || prepared.InputDigest != digestCommunityBytes(prepared.CanonicalInputJSON) || !json.Valid(prepared.CanonicalInputJSON) {
		return r.fail("CILIUM_POLICY_INPUT_INVALID", ExitUsage)
	}
	report, err := r.cncfChecker().Check("cilium", prepared.CanonicalInputJSON, now)
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
	if _, err := fmt.Fprintf(r.stdout, "Cilium policy review\ntransition: %s -> %s\nraw policy digest: %s\nprepared input digest: %s\nscope: one caller-selected CiliumNetworkPolicy, CiliumClusterwideNetworkPolicy, or flat list only; CNP/CCNP set completeness is operator-declared, pagination is never assumed complete, and whole upgrade remains UNKNOWN\naggregate: UNKNOWN\nnetwork used: false\n", from, to, sourceDigest, prepared.InputDigest); err != nil {
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
