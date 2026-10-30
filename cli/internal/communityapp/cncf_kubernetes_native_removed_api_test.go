// SPDX-License-Identifier: AGPL-3.0-only

package communityapp

import (
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/extract/supersedeids"
)

func kubernetesNativeAPIArgs(path, from, to, format string, extra ...string) []string {
	args := []string{"check", "cncf", "--project", "kubernetes", "--native-resource", path, "--from", from, "--to", to, "--distribution", "official_upstream", "--target-api-apply-required", "--resource-scope-complete", "--now", supersedeids.ClockString(), "--format", format}
	return append(args, extra...)
}

// A resource at an API version the target does not serve is never a pass on
// the native route, whatever the output format.
func TestKubernetesNativeResource_RemovedOrUnservedAPIIsUnknown(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name, raw, from, to string
	}{
		{"Ingress extensions/v1beta1 1.25 to 1.26", `{"apiVersion":"extensions/v1beta1","kind":"Ingress","metadata":{"name":"a"}}`, "1.25.0", "1.26.0"},
		{"CronJob batch/v1beta1 1.25 to 1.26", `{"apiVersion":"batch/v1beta1","kind":"CronJob","metadata":{"name":"a"}}`, "1.25.0", "1.26.0"},
		{"ClusterCIDR v1alpha1 1.28 to 1.29", `{"apiVersion":"networking.k8s.io/v1alpha1","kind":"ClusterCIDR","metadata":{"name":"a"}}`, "1.28.0", "1.29.0"},
		{"made-up apps/v1beta9", `{"apiVersion":"apps/v1beta9","kind":"Deployment","metadata":{"name":"a"}}`, "1.25.0", "1.26.0"},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := writeCNCFFile(t, "kubernetes.json", []byte(test.raw), 0o600)
			for _, format := range []string{"human", "json"} {
				for _, strict := range []bool{false, true} {
					var extra []string
					want := ExitUnknown
					if strict {
						extra = []string{"--strict-exit"}
					}
					code, stdout, stderr := runCNCFCLI(t, kubernetesNativeAPIArgs(path, test.from, test.to, format, extra...)...)
					if code != want || strings.Contains(stdout, "PASS") && format == "human" {
						t.Fatalf("%s strict=%v: code=%d stdout=%q stderr=%q", format, strict, code, stdout, stderr)
					}
					if format == "human" && !strings.HasPrefix(stdout, "UNKNOWN") {
						t.Fatalf("headline not UNKNOWN: %q", stdout)
					}
					if format == "json" && !strings.Contains(stdout, `"apiVersionGaps"`) {
						t.Fatalf("json lacks apiVersionGaps: %q", stdout)
					}
				}
			}
		})
	}
}

// Control: a served apps/v1 Deployment keeps the previous behaviour.
func TestKubernetesNativeResource_ServedAPIKeepsPreviousBehaviour(t *testing.T) {
	t.Parallel()
	path := writeCNCFFile(t, "kubernetes.json", []byte(`{"apiVersion":"apps/v1","kind":"Deployment","metadata":{"name":"a"}}`), 0o600)
	code, stdout, stderr := runCNCFCLI(t, kubernetesNativeAPIArgs(path, "1.31.0", "1.32.0", "human")...)
	if code != ExitOK || !strings.HasPrefix(stdout, "PASS") || strings.Contains(stdout, "not shown served") {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
}
