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

const containerdRemovedOfficialShimRuleID = "containerd.selected-official-runtime-shim-removed.1-7-28-to-2-0-0"

// cncfContainerdConfig evaluates only the selected CRI runtime_type against
// the exact reviewed containerd transition. The raw TOML and handler selector
// are never included in the canonical input or report.
func (r runtime) cncfContainerdConfig(path, pin, handler, from, to string, complete, precedenceResolved, officialUpstream, officialBundledRuntimesOnly bool, nowText, storeRoot, revision, bundle, receipt, replayPath, format string) int {
	raw, err := readCNCFPrivate(path, 1<<20)
	if err != nil {
		return r.fail(withPermissionHint("CONTAINERD_CONFIG_INPUT_INVALID", err), ExitUsage)
	}
	sourceDigest := digestCommunityBytes(raw)
	if pin != "" && pin != sourceDigest {
		return r.fail("CONTAINERD_CONFIG_INTEGRITY_FAILURE", ExitIntegrity)
	}
	prepared, err := cncfprepare.PrepareContainerdConfig(raw, handler, from, to, complete, precedenceResolved, officialUpstream, officialBundledRuntimesOnly)
	if err != nil || prepared.SourceDigest != sourceDigest || prepared.InputDigest != digestCommunityBytes(prepared.CanonicalInputJSON) || !json.Valid(prepared.CanonicalInputJSON) {
		return r.fail("CONTAINERD_CONFIG_INPUT_INVALID", ExitUsage)
	}
	if _, err := cncfcheck.Catalog(false, "containerd"); err != nil {
		return r.cncfError("CNCF project selection failed", err)
	}
	if storeRoot != "" {
		if nowText != "" || (replayPath != "" && (pin == "" || revision == "" || bundle == "" || receipt == "")) {
			return r.usage("external containerd replay requires the raw config digest and all knowledge pins")
		}
		return r.externalCNCF(cncfknowledge.Request{
			Selection:      knowledge.SelectionRequest{StoreRoot: storeRoot, ExpectedRevision: revision, ExpectedBundleDigest: bundle, ExpectedTrustReceiptDigest: receipt},
			Project:        "containerd",
			SelectedRuleID: containerdRemovedOfficialShimRuleID,
			Input:          prepared.CanonicalInputJSON,
			InputDigest:    prepared.InputDigest,
		}, replayPath, format)
	}
	if revision != "" || bundle != "" || receipt != "" || nowText == "" || replayPath != "" {
		return r.usage("containerd configuration checks require canonical --now or an explicit signed knowledge selection")
	}
	now, err := parseUTC(nowText)
	if err != nil || now.Nanosecond() != 0 || now.Format(time.RFC3339) != nowText {
		return r.usage("CNCF check time must be explicit canonical UTC with whole seconds")
	}
	report, err := cncfcheck.CheckRule("containerd", containerdRemovedOfficialShimRuleID, prepared.CanonicalInputJSON, now)
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
	if _, err := fmt.Fprintf(r.stdout, "containerd selected runtime upgrade review\ntransition: %s -> %s\nsupported configuration formats: v2 and v3\nscoped result: %s (%s)\naggregate: UNKNOWN\nprepared input digest: %s\nevaluated at: %s\nknowledge: embedded revision %s\nknowledge pack digest: %s\nnetwork used: false\ncontainerd executed: false\nselected handler and raw TOML retained: false\nscope: selected official bundled runtime shim availability only; configuration migration, startup, container creation, custom shims, and whole-upgrade compatibility remain unverified\n", from, to, claim.Status, claim.ReasonCode, report.InputFileDigest, report.Check.EvaluatedAt, report.KnowledgeRevision, report.KnowledgePackDigest); err != nil {
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
	return cncfcheck.ClaimExit(report)
}
