// SPDX-License-Identifier: AGPL-3.0-only

package communityapp

import (
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/prufyx/prufyx/cli/internal/cncfcheck"
	"github.com/prufyx/prufyx/cli/internal/cncfprepare"
	"github.com/prufyx/prufyx/cli/internal/constraintengine"
)

// cncfKubernetesComponentConfig reads one caller-written selection document
// and the local files it names, reduces them to the component-configuration
// facts for the crossed minor line, and evaluates exactly the published rules
// that consume those facts. Paths, argument values and raw documents never
// reach the canonical input or the report.
func (r runtime) cncfKubernetesComponentConfig(path, pin, from, to, distribution, nowText, storeRoot, revision, bundle, receipt, replayPath, format string) int {
	if distribution != "" && distribution != "official_upstream" && distribution != "custom_build" {
		return r.usage("invalid Kubernetes distribution; use --help")
	}
	if storeRoot != "" || revision != "" || bundle != "" || receipt != "" || replayPath != "" {
		return r.usage("Kubernetes component configuration checks use embedded knowledge with --now; external knowledge selection and replay are not available for this mode")
	}
	if nowText == "" {
		return r.usage("Kubernetes component configuration checks require canonical --now")
	}
	now, err := parseUTC(nowText)
	if err != nil || now.Nanosecond() != 0 || now.Format(time.RFC3339) != nowText {
		return r.usage("CNCF check time must be explicit canonical UTC with whole seconds")
	}
	raw, err := readCNCFPrivate(path, 1<<20)
	if err != nil {
		return r.fail(withPermissionHint("KUBERNETES_COMPONENT_SELECTION_INPUT_INVALID", err), ExitUsage)
	}
	if pin != "" && pin != digestCommunityBytes(raw) {
		return r.fail("KUBERNETES_COMPONENT_SELECTION_INTEGRITY_FAILURE", ExitIntegrity)
	}
	selection, err := cncfprepare.ParseKubernetesComponentSelection(raw)
	if err != nil {
		return r.fail("KUBERNETES_COMPONENT_SELECTION_INPUT_INVALID", ExitUsage)
	}
	contents := make([][]byte, len(selection.Sources))
	for index, source := range selection.Sources {
		content, readErr := readCNCFPrivate(source.Path, cncfprepare.MaxKubernetesComponentSourceBytes)
		if readErr != nil {
			return r.fail(withPermissionHint(fmt.Sprintf("KUBERNETES_COMPONENT_SOURCE_INPUT_INVALID: source %d", index+1), readErr), ExitUsage)
		}
		if source.Digest != "" && source.Digest != digestCommunityBytes(content) {
			return r.fail(fmt.Sprintf("KUBERNETES_COMPONENT_SOURCE_INTEGRITY_FAILURE: source %d", index+1), ExitIntegrity)
		}
		contents[index] = content
	}
	prepared, err := cncfprepare.PrepareKubernetesComponentConfig(selection, contents, from, to, distribution, cncfcheck.RegisteredFact)
	if err != nil || prepared.SourceDigest != cncfprepare.KubernetesComponentSourceDigest(raw, contents) || prepared.InputDigest != digestCommunityBytes(prepared.CanonicalInputJSON) || !json.Valid(prepared.CanonicalInputJSON) {
		return r.fail("KUBERNETES_COMPONENT_SELECTION_INPUT_INVALID", ExitUsage)
	}
	if _, err := cncfcheck.Catalog(false, "kubernetes"); err != nil {
		return r.cncfError("CNCF project selection failed", err)
	}
	report, err := cncfcheck.CheckFacts("kubernetes", cncfprepare.KubernetesComponentConfigAllFacts(), prepared.CanonicalInputJSON, now)
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
	if _, err := fmt.Fprintf(r.stdout, "Kubernetes component configuration review\ntransition: %s -> %s\nselected sources: %d\npreparation: %s (%s)\nprepared input digest: %s\naggregate: UNKNOWN\nevaluated at: %s\nknowledge: embedded revision %s\nknowledge pack digest: %s\nnetwork used: false\npaths, argument values and raw documents retained: false\nscope: removed component settings named by reviewed rules only; component startup, runtime behavior, and whole-upgrade compatibility remain unverified\n", from, to, len(selection.Sources), prepared.State, prepared.Reason, prepared.InputDigest, report.Check.EvaluatedAt, report.KnowledgeRevision, report.KnowledgePackDigest); err != nil {
		return ExitIntegrity
	}
	if err := writeKubernetesComponentResult(r.stdout, report.Check.Claims, report.NextAction); err != nil {
		return ExitIntegrity
	}
	return cncfcheck.ClaimExit(report)
}

// writeKubernetesComponentResult prints the "no reviewed rule" line when no
// verdict claim exists (one-way notices do not count), then every claim.
func writeKubernetesComponentResult(out io.Writer, claims []constraintengine.Claim, nextAction string) error {
	if verdictClaims(claims) == 0 {
		if _, err := fmt.Fprintf(out, "scoped result: UNKNOWN (no reviewed rule for this input and transition)\nnext action: %s\n", nextAction); err != nil {
			return err
		}
	}
	return writeKubernetesComponentClaims(out, claims)
}

// writeKubernetesComponentClaims prints each claim, its evidence basis, and
// its pinned sources, in the order every human writer uses.
func writeKubernetesComponentClaims(out io.Writer, claims []constraintengine.Claim) error {
	for _, claim := range claims {
		printed, err := writeClaimHeadline(out, claim)
		if err != nil {
			return err
		}
		if !printed {
			continue
		}
		if line, ok := claim.MatchedMembersLine(); ok {
			if _, err := fmt.Fprintln(out, line); err != nil {
				return err
			}
		}
		if _, err := fmt.Fprintln(out, claim.EvidenceBasisLine()); err != nil {
			return err
		}
		for _, source := range claim.Sources {
			if _, err := fmt.Fprintf(out, "pinned source: %s lines %d-%d; revision %s; digest %s\n", source.URL, source.StartLine, source.EndLine, source.Revision, source.ContentDigest); err != nil {
				return err
			}
		}
	}
	return nil
}
