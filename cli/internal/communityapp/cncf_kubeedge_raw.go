// SPDX-License-Identifier: AGPL-3.0-only

package communityapp

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/prufyx/prufyx/cli/internal/cncfcheck"
	"github.com/prufyx/prufyx/cli/internal/cncfprepare"
)

// cncfKubeEdgeInitArgvCheck is the native one-step route for the reviewed
// KubeEdge keadm init version-selector rule. It derives the selector form from
// one caller-declared effective argv using only the grammar the reviewed
// evidence already states, and leaves argv completeness, distribution, and the
// command surface as the caller's own declarations. It authors no new
// compatibility claim and never opens a --profile values file.
func (r runtime) cncfKubeEdgeInitArgvCheck(path, pin, from, to, distribution, argvCompleteText string, now time.Time, format string) int {
	raw, err := readCNCFPrivate(path, 1<<20)
	if err != nil {
		return r.fail(withPermissionHint("KUBEEDGE_INIT_ARGV_INPUT_INVALID", err), ExitUsage)
	}
	sourceDigest := digestCommunityBytes(raw)
	if pin != "" && pin != sourceDigest {
		return r.fail("KUBEEDGE_INIT_ARGV_INTEGRITY_FAILURE", ExitIntegrity)
	}
	var argvComplete *bool
	if argvCompleteText == "true" || argvCompleteText == "false" {
		value := argvCompleteText == "true"
		argvComplete = &value
	}
	prepared, err := cncfprepare.PrepareKubeEdgeInitArgv(raw, from, to, distribution, argvComplete)
	if err != nil || prepared.SourceDigest != sourceDigest || prepared.InputDigest != digestCommunityBytes(prepared.CanonicalInputJSON) || !json.Valid(prepared.CanonicalInputJSON) {
		return r.fail("KUBEEDGE_INIT_ARGV_INPUT_INVALID", ExitUsage)
	}
	report, err := cncfcheck.Check("kubeedge", prepared.CanonicalInputJSON, now)
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
	if _, err := fmt.Fprintf(r.stdout, "KubeEdge keadm init argv review\ntransition: %s -> %s\nraw argv digest: %s\nprepared input digest: %s\nscope: one caller-declared effective keadm init argv only; the declared argv is never executed, no --profile values file is opened, and wrappers, Helm values, chart defaults, runtime behavior, and whole upgrade remain UNKNOWN\naggregate: UNKNOWN\nnetwork used: false\n", from, to, sourceDigest, prepared.InputDigest); err != nil {
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
