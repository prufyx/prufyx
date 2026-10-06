// SPDX-License-Identifier: AGPL-3.0-only

package communityapp

import (
	"bytes"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/constraintengine"
)

// TestUnsupportedHumanOutput: the headline names how many component
// combinations are outside their documented support range exactly when a
// report holds an UNSUPPORTED claim, and the claim line carries the rule's
// next action.
func TestUnsupportedHumanOutput(t *testing.T) {
	t.Parallel()
	unsupported := constraintengine.Claim{RuleID: "cert-manager.k8s-support.1-16", Operator: "require_component_version", Status: constraintengine.StatusUnsupported, ReasonCode: "ADDON_KUBERNETES_SUPPORT_RANGE", NextAction: "upgrade cert-manager to a release line that supports the target Kubernetes minor", Severity: constraintengine.SeverityUnsupported}
	supported := unsupported
	supported.RuleID, supported.Status = "cert-manager.k8s-support.1-17", "PASS"
	blocked := constraintengine.Claim{RuleID: "kubernetes.removed-api", Operator: "forbid_target_version", Status: "BLOCKED", ReasonCode: "FEATURE_REMOVED", NextAction: "migrate the removed API"}
	headline := func(claims ...constraintengine.Claim) string {
		var out bytes.Buffer
		if err := writeBasisHeadline(&out, claims, nil); err != nil {
			t.Fatal(err)
		}
		return out.String()
	}
	if got := headline(supported, blocked); got != "" {
		t.Fatalf("headline without UNSUPPORTED: %q", got)
	}
	if got := headline(supported, unsupported); got != "1 component combination is outside its documented support range (not verified, not shown to be broken)\n" {
		t.Fatalf("headline=%q", got)
	}
	second := unsupported
	second.RuleID = "argo-cd.k8s-support.2-12"
	if got := headline(unsupported, second, blocked); got != "2 component combinations are outside their documented support range (not verified, not shown to be broken)\n" {
		t.Fatalf("headline=%q", got)
	}
	// The claim is listed, never collapsed with passes, and prints its next
	// action.
	claims := []constraintengine.Claim{supported, unsupported}
	summary := summarizeClaims(claims, false)
	if summary.passes != 1 || len(summary.shown) != 1 || len(summary.notices) != 0 {
		t.Fatalf("summary=%+v", summary)
	}
	var out bytes.Buffer
	if err := writeNativeClaims(&out, summary, claims); err != nil {
		t.Fatal(err)
	}
	want := "cert-manager.k8s-support.1-16: UNSUPPORTED (ADDON_KUBERNETES_SUPPORT_RANGE)\nnext action: upgrade cert-manager to a release line that supports the target Kubernetes minor\n" +
		"evidence basis: reviewed by maintainer\n" +
		"1 rules PASS (not listed; use --show-passes)\n"
	if out.String() != want {
		t.Fatalf("output:\n%s\nwant:\n%s", out.String(), want)
	}
	out.Reset()
	if printed, err := writeClaimHeadline(&out, unsupported); err != nil || !printed || !strings.Contains(out.String(), "next action: "+unsupported.NextAction) {
		t.Fatalf("claim headline=%q", out.String())
	}
	for _, line := range strings.Split(headline(unsupported, second), "\n") {
		lower := strings.ToLower(line)
		if len(line) > 256 || strings.Contains(lower, "safe") || strings.Contains(lower, "compatible") {
			t.Fatalf("headline wording: %q", line)
		}
	}
}

// TestCheckHelpExitLegend: the check cncf exit legend names every status
// that exits 11.
func TestCheckHelpExitLegend(t *testing.T) {
	t.Parallel()
	code, stdout, _ := runCNCFCLI(t, "check", "cncf", "--help")
	if code != 0 || !strings.Contains(stdout, "11: UNKNOWN, UNSUPPORTED, NO_KNOWN_ISSUE or no rules;") {
		t.Fatalf("code=%d help:\n%s", code, stdout)
	}
}
