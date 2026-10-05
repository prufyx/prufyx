// SPDX-License-Identifier: AGPL-3.0-only

package communityapp

import (
	"path/filepath"
	"strings"
	"testing"
)

func kubernetesNativeArgs(path string) []string {
	return []string{"check", "cncf", "--project", "kubernetes", "--native-resource", path, "--from", "1.31.0", "--to", "1.32.0", "--distribution", "official_upstream", "--target-api-apply-required", "--resource-scope-complete", "--now", "2026-09-12T10:00:00Z", "--format", "json"}
}

func TestKubernetesNativeFlowControlCheck_BoundedOutcomesAndPrivacy(t *testing.T) {
	for _, test := range []struct {
		name, raw, reason string
		want              int
		complete          bool
	}{
		{"removed blocks", `{"apiVersion":"flowcontrol.apiserver.k8s.io/v1beta3","kind":"FlowSchema","metadata":{"name":"private-flow"}}`, "REVIEWED_SOURCE_CONSTRAINT", ExitBlocked, true},
		{"v1 passes", `{"apiVersion":"v1","kind":"List","items":[{"apiVersion":"flowcontrol.apiserver.k8s.io/v1","kind":"PriorityLevelConfiguration","metadata":{"name":"private-flow"}},{"apiVersion":"v1","kind":"Service"}]}`, "REVIEWED_SOURCE_CONSTRAINT", ExitOK, true},
		{"incomplete remains unknown", `{"apiVersion":"flowcontrol.apiserver.k8s.io/v1","kind":"FlowSchema"}`, "RULE_FACT_UNAVAILABLE", ExitUnknown, false},
		{"unreviewed version remains unknown", `{"apiVersion":"flowcontrol.apiserver.k8s.io/v9","kind":"FlowSchema"}`, "RULE_FACT_UNAVAILABLE", ExitUnknown, true},
		{"nested list remains unknown", `{"apiVersion":"v1","kind":"List","items":[{"apiVersion":"v1","kind":"List","items":[]}]}`, "RULE_FACT_UNAVAILABLE", ExitUnknown, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := writeCNCFFile(t, "kubernetes.json", []byte(test.raw), 0o600)
			args := kubernetesNativeArgs(path)
			if !test.complete {
				for index, value := range args {
					if value == "--resource-scope-complete" {
						args = append(args[:index], args[index+1:]...)
						break
					}
				}
			}
			code, stdout, stderr := runCNCFCLI(t, args...)
			if code != test.want || stderr != "" || !strings.Contains(stdout, test.reason) || !strings.Contains(stdout, `"assessment":"UNKNOWN"`) || strings.Contains(stdout, "private-flow") || strings.Contains(stdout, path) {
				t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout, stderr)
			}
		})
	}
}

func TestKubernetesNativeFlowControlCheck_RejectsMalformedAndWrongRoute(t *testing.T) {
	path := writeCNCFFile(t, "kubernetes.json", []byte(`{"apiVersion":"flowcontrol.apiserver.k8s.io/v1beta3","apiVersion":"flowcontrol.apiserver.k8s.io/v1","kind":"FlowSchema"}`), 0o600)
	code, stdout, stderr := runCNCFCLI(t, kubernetesNativeArgs(path)...)
	if code != ExitUsage || stdout != "" || strings.Contains(stderr, path) {
		t.Fatalf("duplicate key code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	clear := writeCNCFFile(t, "clear.json", []byte(`{"apiVersion":"flowcontrol.apiserver.k8s.io/v1","kind":"FlowSchema"}`), 0o600)
	args := kubernetesNativeArgs(clear)
	for i := range args {
		if args[i] == "1.32.0" {
			args[i] = "1.32.1"
		}
	}
	code, stdout, stderr = runCNCFCLI(t, args...)
	if code != ExitUnknown || stderr != "" || !strings.Contains(stdout, "RULE_TRANSITION_NOT_REVIEWED") {
		t.Fatalf("wrong pair code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
}

func TestKubernetesNativeFlowControlExternalStoreHasNoEmbeddedFallback(t *testing.T) {
	fixture := makeExternalCLIFixture(t)
	raw := []byte(`{"apiVersion":"flowcontrol.apiserver.k8s.io/v1beta3","kind":"FlowSchema","metadata":{"name":"private-flow"}}`)
	path := writeCNCFFile(t, "kubernetes.json", raw, 0o600)
	args := []string{
		"check", "cncf", "--project", "kubernetes", "--native-resource", path, "--native-resource-digest", cncfDigest(raw),
		"--from", "1.31.0", "--to", "1.32.0", "--distribution", "official_upstream", "--target-api-apply-required", "--resource-scope-complete",
		"--knowledge-db", fixture.store, "--knowledge-revision", "1", "--knowledge-bundle-digest", fixture.manifest.Revisions[0].BundleDigest, "--knowledge-trust-receipt-digest", fixture.receipt1.TrustReceiptDigest, "--format", "json",
	}
	code, stdout, stderr := runCNCFCLI(t, args...)
	if code != ExitUnknown || stderr != "" || !strings.Contains(stdout, `"knowledgeOrigin":"external_declared"`) || strings.Contains(stdout, "private-flow") || strings.Contains(stdout, filepath.Base(path)) {
		t.Fatalf("external no-fallback code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
}

func TestNewNativeExternalModesRejectExplicitNowBeforePrivateRead(t *testing.T) {
	for _, args := range [][]string{
		{"check", "cncf", "--project", "kubernetes", "--native-resource", "PRIVATE-NOT-READ.json", "--from", "1.31.0", "--to", "1.32.0", "--distribution", "official_upstream", "--target-api-apply-required", "--resource-scope-complete", "--knowledge-db", "PRIVATE-NOT-OPENED-STORE", "--now=", "--format", "json"},
		{"check", "cncf", "--project", "cilium", "--cilium-config-map", "PRIVATE-NOT-READ.yaml", "--from", "1.16.19", "--to", "1.17.18", "--cilium-distribution", "official_upstream", "--cilium-config-complete", "--cilium-config-precedence-resolved", "--knowledge-db", "PRIVATE-NOT-OPENED-STORE", "--now=", "--format", "json"},
	} {
		code, stdout, stderr := runCNCFCLI(t, args...)
		if code != ExitUsage || stdout != "" || strings.Contains(stderr, "PRIVATE-NOT-READ") || strings.Contains(stderr, "PRIVATE-NOT-OPENED-STORE") {
			t.Fatalf("args=%q code=%d stdout=%q stderr=%q", args, code, stdout, stderr)
		}
	}
}

func TestKubernetesPrepareFlowControlFeedsBatch(t *testing.T) {
	raw := []byte(`{"apiVersion":"flowcontrol.apiserver.k8s.io/v1beta3","kind":"FlowSchema","metadata":{"name":"private-flow"}}`)
	path := writeCNCFFile(t, "kubernetes.json", raw, 0o600)
	prepareArgs := []string{"prepare", "cncf", "--project", "kubernetes", "--input", path, "--from", "1.31.0", "--to", "1.32.0", "--distribution", "official_upstream", "--target-api-apply-required", "--resource-scope-complete", "--format", "input"}
	code, canonical, stderr := runCNCFCLI(t, prepareArgs...)
	if code != ExitOK || stderr != "" || !strings.Contains(canonical, "component.kubernetes.flowcontrol_v1beta3_removed_gvk_present") || strings.Contains(canonical, "private-flow") {
		t.Fatalf("prepare code=%d stdout=%q stderr=%q", code, canonical, stderr)
	}
	prepared := writeCNCFFile(t, "kubernetes-canonical.json", []byte(canonical), 0o600)
	code, report, stderr := runCNCFCLI(t, "check", "cncf", "--project", "kubernetes", "--input", prepared, "--input-digest", cncfDigest([]byte(canonical)), "--now", "2026-09-12T10:00:00Z", "--format", "json")
	if code != ExitBlocked || stderr != "" || !strings.Contains(report, `"status":"BLOCKED"`) {
		t.Fatalf("batch code=%d stdout=%q stderr=%q", code, report, stderr)
	}
}

// An object of a non-List kind with a top-level items array is left out of
// the apply set, but a removed version among the other documents still
// blocks (exit 10); the object itself is never a witness.
func TestKubernetesNativeItemsBesideARemovedVersion(t *testing.T) {
	configMap := "apiVersion: v1\nkind: ConfigMap\nmetadata: {name: c}\nitems: []\n"
	for _, tc := range []struct {
		name, from, to, docs string
		want                 int
	}{
		{"removed CronJob beside items", "1.24.0", "1.25.0", "apiVersion: batch/v1beta1\nkind: CronJob\nmetadata: {name: n}\n---\n" + configMap, ExitBlocked},
		{"removed FlowSchema beside items", "1.31.0", "1.32.0", "apiVersion: flowcontrol.apiserver.k8s.io/v1beta3\nkind: FlowSchema\nmetadata: {name: f}\n---\n" + configMap, ExitBlocked},
		{"removed CronJob carrying items", "1.24.0", "1.25.0", "apiVersion: batch/v1beta1\nkind: CronJob\nmetadata: {name: n}\nitems: []\n", ExitUnknown},
	} {
		path := writeCNCFFile(t, "applyset.yaml", []byte(tc.docs), 0o600)
		code, stdout, stderr := runCNCFCLI(t, "check", "cncf", "--project", "kubernetes", "--native-resource", path, "--from", tc.from, "--to", tc.to, "--distribution", "official_upstream", "--target-api-apply-required", "--resource-scope-complete", "--now", "2026-10-01T00:00:00Z", "--format", "json")
		if code != tc.want || stderr != "" || (tc.want == ExitBlocked) != strings.Contains(stdout, `"status":"BLOCKED"`) {
			t.Fatalf("%s: code=%d stdout=%q stderr=%q", tc.name, code, stdout, stderr)
		}
	}
}
