// SPDX-License-Identifier: AGPL-3.0-only

package scanrun

import (
	"fmt"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/lineattest"
	"github.com/prufyx/prufyx/cli/internal/scanreport"
)

// rangedRemovals are the Kubernetes API removals of 1.32 to 1.37 that the
// embedded knowledge decides for every patch of the previous line going to
// every patch of the line that stops serving them: the kind, its removed and
// served API versions, the rule (supersedeids.ID names the rule of the
// shipped generation) and the patch pairs, the line anchor among them.
var rangedRemovals = []struct {
	kind, removed, served, rule string
	pairs                       [][2]string
}{
	{"FlowSchema", "flowcontrol.apiserver.k8s.io/v1beta3", "flowcontrol.apiserver.k8s.io/v1", "kubernetes.served-api-removal.flowcontrol-apiserver-k8s-io-v1beta3.1-31-0-to-1-32-0", [][2]string{{"1.31.0", "1.32.0"}, {"1.31.14", "1.32.11"}, {"1.31.0", "1.32.11"}, {"1.31.14", "1.32.0"}}},
	{"PriorityLevelConfiguration", "flowcontrol.apiserver.k8s.io/v1beta3", "flowcontrol.apiserver.k8s.io/v1", "kubernetes.served-api-removal.flowcontrol-apiserver-k8s-io-v1beta3.1-31-0-to-1-32-0", [][2]string{{"1.31.14", "1.32.11"}}},
	{"SelfSubjectReview", "authentication.k8s.io/v1beta1", "authentication.k8s.io/v1", "kubernetes.served-api-removal.authentication-k8s-io-v1beta1.1-32-0-to-1-33-0", [][2]string{{"1.32.0", "1.33.0"}, {"1.32.11", "1.33.7"}}},
	{"ValidatingAdmissionPolicy", "admissionregistration.k8s.io/v1beta1", "admissionregistration.k8s.io/v1", "kubernetes.served-api-removal.admissionregistration-k8s-io-v1beta1.1-33-0-to-1-34-0", [][2]string{{"1.33.0", "1.34.0"}, {"1.33.7", "1.34.3"}}},
	{"ValidatingAdmissionPolicyBinding", "admissionregistration.k8s.io/v1beta1", "admissionregistration.k8s.io/v1", "kubernetes.served-api-removal.admissionregistration-k8s-io-v1beta1.1-33-0-to-1-34-0", [][2]string{{"1.33.7", "1.34.3"}}},
	{"IPAddress", "networking.k8s.io/v1beta1", "networking.k8s.io/v1", "kubernetes.served-api-removal.networking-k8s-io-v1beta1.1-36-0-to-1-37-0", [][2]string{{"1.36.0", "1.37.0"}, {"1.36.4", "1.37.1"}}},
	{"ServiceCIDR", "networking.k8s.io/v1beta1", "networking.k8s.io/v1", "kubernetes.served-api-removal.networking-k8s-io-v1beta1.1-36-0-to-1-37-0", [][2]string{{"1.36.4", "1.37.1"}}},
	{"VolumeAttributesClass", "storage.k8s.io/v1beta1", "storage.k8s.io/v1", "kubernetes.served-api-removal.storage-k8s-io-v1beta1.1-36-0-to-1-37-0", [][2]string{{"1.36.0", "1.37.0"}, {"1.36.4", "1.37.1"}}},
}

// TestScanRangedRemovalsBlockEveryPatchPair: with the embedded knowledge
// alone, a manifest at an API version that the target line stops serving is
// BLOCKED (exit 10) by the rule of that line for any patch of the previous
// line going to any patch of the line, not only at the line anchors. The
// served version of the same kind is no finding, and the answer is never a
// pass (the embedded knowledge has no line review or served list).
func TestScanRangedRemovalsBlockEveryPatchPair(t *testing.T) {
	knowledge := embeddedOnly(t)
	for _, removal := range rangedRemovals {
		id := removal.rule
		for _, pair := range removal.pairs {
			name := removal.kind + "/" + pair[0] + "->" + pair[1]
			t.Run(name+"/removed", func(t *testing.T) {
				_, paths := files(t, map[string]string{"applyset.yaml": "apiVersion: " + removal.removed + "\nkind: " + removal.kind + "\nmetadata: {name: a}\n"})
				result := mustScan(t, knowledge, args(paths, "--from", "kubernetes="+pair[0], "--to", "kubernetes="+pair[1])...)
				if result.Exit != scanreport.ExitBlocked || len(result.Report.Findings) != 1 || result.Report.Findings[0].RuleID != id {
					t.Fatalf("exit %d findings %+v gaps %v", result.Exit, result.Report.Findings, gapReasons(result.Report))
				}
				if hasGap(result.Report, "API_VERSION_NOT_SERVED", "") {
					t.Fatalf("a decided removal is still reported as not served: %v", gapReasons(result.Report))
				}
			})
			t.Run(name+"/served", func(t *testing.T) {
				_, paths := files(t, map[string]string{"applyset.yaml": "apiVersion: " + removal.served + "\nkind: " + removal.kind + "\nmetadata: {name: a}\n"})
				result := mustScan(t, knowledge, args(paths, "--from", "kubernetes="+pair[0], "--to", "kubernetes="+pair[1])...)
				if result.Exit == scanreport.ExitPass || result.Exit == scanreport.ExitBlocked || len(result.Report.Findings) != 0 {
					t.Fatalf("exit %d findings %+v", result.Exit, result.Report.Findings)
				}
				passed := false
				for _, pass := range result.Report.Passes {
					passed = passed || pass.RuleID == id
				}
				if !passed {
					t.Fatalf("the rule of the line did not decide the served version: passes %+v", result.Report.Passes)
				}
			})
		}
	}
	// The removed version on the line before the removal is still served:
	// no rule decides it there and nothing blocks.
	for _, removal := range rangedRemovals {
		to := removal.pairs[0][0]
		line, ok := lineattest.LineOf(to)
		if !ok {
			t.Fatalf("no line of %s", to)
		}
		from := lineBefore(t, line) + ".3"
		_, paths := files(t, map[string]string{"applyset.yaml": "apiVersion: " + removal.removed + "\nkind: " + removal.kind + "\nmetadata: {name: a}\n"})
		result := mustScan(t, knowledge, args(paths, "--from", "kubernetes="+from, "--to", "kubernetes="+to)...)
		if result.Exit == scanreport.ExitPass || result.Exit == scanreport.ExitBlocked || len(result.Report.Findings) != 0 {
			t.Fatalf("%s %s -> %s: exit %d findings %+v", removal.kind, from, to, result.Exit, result.Report.Findings)
		}
	}
}

// lineBefore returns the Kubernetes line before line ("1.33" -> "1.32").
func lineBefore(t *testing.T, line string) string {
	t.Helper()
	var major, minor int
	if _, err := fmt.Sscanf(line, "%d.%d", &major, &minor); err != nil || minor < 1 {
		t.Fatalf("no line before %q", line)
	}
	return fmt.Sprintf("%d.%d", major, minor-1)
}

// TestScanLinesWithoutRemovableAPIAreNotBlocked: 1.35 and 1.36 remove no API
// version a manifest can target, so a manifest at the versions removed on the
// neighbouring lines is not blocked by a hop into them (it is served there),
// and the answer is never a pass.
func TestScanLinesWithoutRemovableAPIAreNotBlocked(t *testing.T) {
	knowledge := embeddedOnly(t)
	for _, hop := range [][2]string{{"1.34.0", "1.35.0"}, {"1.34.3", "1.35.2"}, {"1.35.0", "1.36.0"}, {"1.35.2", "1.36.4"}} {
		for _, removal := range rangedRemovals {
			_, paths := files(t, map[string]string{"applyset.yaml": "apiVersion: " + removal.removed + "\nkind: " + removal.kind + "\nmetadata: {name: a}\n"})
			result := mustScan(t, knowledge, args(paths, "--from", "kubernetes="+hop[0], "--to", "kubernetes="+hop[1])...)
			if result.Exit == scanreport.ExitPass || result.Exit == scanreport.ExitBlocked || len(result.Report.Findings) != 0 {
				t.Fatalf("%s %s -> %s: exit %d findings %+v", removal.kind, hop[0], hop[1], result.Exit, result.Report.Findings)
			}
		}
	}
}
