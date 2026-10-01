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

// cncfJaegerNativeCheck reuses the already-reviewed PrepareJaeger adapter for
// a one-step native check, mirroring the containerd dedicated-route pattern
// because Jaeger needs two extra caller-declared tri-state facts the shared
// native-resource dispatcher does not carry. Only the existing explicit
// --config witness is derived from the private argv document; non-memory
// storage requirement and official distribution remain caller declarations,
// never inferred from the argv or any runtime state.
func (r runtime) cncfJaegerNativeCheck(path, pin string, nonMemoryStorage, officialDistribution *bool, from, to, nowText, storeRoot, revision, bundle, receipt, replayPath, format string) int {
	raw, err := readCNCFPrivate(path, 1<<20)
	if err != nil {
		return r.fail(withPermissionHint("NATIVE_CNCF_RESOURCE_INPUT_INVALID", err), ExitUsage)
	}
	sourceDigest := digestCommunityBytes(raw)
	if pin != "" && pin != sourceDigest {
		return r.fail("NATIVE_CNCF_RESOURCE_INTEGRITY_FAILURE", ExitIntegrity)
	}
	prepared, err := cncfprepare.PrepareJaeger(raw, from, to, nonMemoryStorage, officialDistribution)
	if err != nil || prepared.SourceDigest != sourceDigest || prepared.InputDigest != digestCommunityBytes(prepared.CanonicalInputJSON) || !json.Valid(prepared.CanonicalInputJSON) {
		return r.fail("NATIVE_CNCF_RESOURCE_INPUT_INVALID", ExitUsage)
	}
	if _, err := cncfcheck.Catalog(false, "jaeger"); err != nil {
		return r.cncfError("CNCF project selection failed", err)
	}
	if storeRoot != "" {
		if nowText != "" || (replayPath != "" && (pin == "" || revision == "" || bundle == "" || receipt == "")) {
			return r.usage("external jaeger replay requires the raw argv digest and all knowledge pins")
		}
		return r.externalCNCF(cncfknowledge.Request{
			Selection:   knowledge.SelectionRequest{StoreRoot: storeRoot, ExpectedRevision: revision, ExpectedBundleDigest: bundle, ExpectedTrustReceiptDigest: receipt},
			Project:     "jaeger",
			Input:       prepared.CanonicalInputJSON,
			InputDigest: prepared.InputDigest,
		}, replayPath, format)
	}
	if revision != "" || bundle != "" || receipt != "" || nowText == "" || replayPath != "" {
		return r.usage("jaeger native checks require canonical --now or an explicit signed knowledge selection")
	}
	now, err := parseUTC(nowText)
	if err != nil || now.Nanosecond() != 0 || now.Format(time.RFC3339) != nowText {
		return r.usage("CNCF check time must be explicit canonical UTC with whole seconds")
	}
	report, err := cncfcheck.Check("jaeger", prepared.CanonicalInputJSON, now)
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
	if _, err := fmt.Fprintf(r.stdout, "jaeger native input review\nraw input digest: %s\nprepared input digest: %s\naggregate: UNKNOWN\nnetwork used: false\nwhole-upgrade compatibility: UNKNOWN\n", sourceDigest, prepared.InputDigest); err != nil {
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
