// SPDX-License-Identifier: AGPL-3.0-only

package communityapp

import (
	"strings"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/cncfcheck"
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

func TestKubernetesNativeResource_ShapesOfInput(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name, raw string
		want      int
		gap       string
	}{
		{"multi-document with one removed", "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: a\n---\napiVersion: extensions/v1beta1\nkind: Ingress\nmetadata:\n  name: b\n", ExitUnknown, "extensions/v1beta1 Ingress"},
		{"List with one removed", `{"apiVersion":"v1","kind":"List","items":[{"apiVersion":"apps/v1","kind":"Deployment","metadata":{"name":"a"}},{"apiVersion":"batch/v1beta1","kind":"CronJob","metadata":{"name":"b"}}]}`, ExitUnknown, "batch/v1beta1 CronJob"},
		{"List all served", `{"apiVersion":"v1","kind":"List","items":[{"apiVersion":"apps/v1","kind":"Deployment","metadata":{"name":"a"}},{"apiVersion":"v1","kind":"Service","metadata":{"name":"b"}}]}`, ExitOK, ""},
		{"custom resource passes", `{"apiVersion":"example.com/v1","kind":"Widget","metadata":{"name":"a"}}`, ExitOK, ""},
		{"uppercase group", `{"apiVersion":"Extensions/v1beta1","kind":"Ingress","metadata":{"name":"a"}}`, ExitUnknown, ""},
		{"whitespace group", `{"apiVersion":" extensions/v1beta1","kind":"Ingress","metadata":{"name":"a"}}`, ExitUnknown, ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := writeCNCFFile(t, "kubernetes.json", []byte(test.raw), 0o600)
			if !strings.HasPrefix(test.raw, "{") {
				path = writeCNCFFile(t, "kubernetes.yaml", []byte(test.raw), 0o600)
			}
			code, stdout, stderr := runCNCFCLI(t, kubernetesNativeAPIArgs(path, "1.31.0", "1.32.0", "human")...)
			if code != test.want || (test.gap != "" && !strings.Contains(stdout, test.gap)) || (test.want == ExitOK && !strings.HasPrefix(stdout, "PASS")) {
				t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout, stderr)
			}
		})
	}
}

// The store and replay routes gate a pass at the report's own evaluation
// time (never the wall clock) and print the same UNKNOWN block and JSON member.
func TestKubernetesNativeResource_StoreRouteGate(t *testing.T) {
	t.Parallel()
	at := supersedeids.Clock().Format(time.RFC3339)
	report := []byte(`{"knowledge":{"evaluatedAt":"` + at + `"}}`)
	gateFor := func(raw string) apiGate {
		return func(evaluatedAt time.Time) []string {
			return kubernetesNativeAPIGaps(cncfcheck.TrustPolicy{}, []byte(raw), "1.32.0", evaluatedAt)
		}
	}
	removed := gateFor(`{"apiVersion":"extensions/v1beta1","kind":"Ingress"}`)
	exit, gaps := gateExit(removed, ExitOK, report)
	if exit != ExitUnknown || len(gaps) != 1 {
		t.Fatalf("exit=%d gaps=%q", exit, gaps)
	}
	if exit, gaps = gateExit(removed, ExitBlocked, report); exit != ExitBlocked || gaps != nil {
		t.Fatalf("blocked changed: %d %q", exit, gaps)
	}
	if exit, _ = gateExit(nil, ExitOK, report); exit != ExitOK {
		t.Fatalf("nil gate changed exit: %d", exit)
	}
	served := gateFor(`{"apiVersion":"apps/v1","kind":"Deployment"}`)
	// The wall clock is long past the list's validity; the replay still
	// judges at the report's evaluation time and stays the same.
	if exit, gaps = gateExit(served, ExitOK, report); exit != ExitOK || gaps != nil {
		t.Fatalf("served object gated: %d %q", exit, gaps)
	}
	// A report without a readable evaluation time is never a pass.
	if exit, _ = gateExit(served, ExitOK, []byte(`{}`)); exit != ExitUnknown {
		t.Fatalf("unreadable clock exit=%d", exit)
	}
	head := strings.Join(apiGapHeadline(gaps2(removed, report)), "\n")
	if !strings.HasPrefix(head, "UNKNOWN") || !strings.Contains(head, "extensions/v1beta1 Ingress") {
		t.Fatalf("headline=%q", head)
	}
	spliced, err := spliceAPIVersionGaps([]byte("{\"a\":1}\n"), gaps2(removed, report))
	if err != nil || !strings.Contains(string(spliced), `"apiVersionGaps":["extensions/v1beta1 Ingress`) {
		t.Fatalf("spliced=%q err=%v", spliced, err)
	}
}

func gaps2(gate apiGate, report []byte) []string {
	_, gaps := gateExit(gate, ExitOK, report)
	return gaps
}

// The store route with the synthetic fixture knowledge holds no Kubernetes
// rule, so it is UNKNOWN before the gate; the route must still run the gate.
func TestKubernetesNativeResource_StoreRouteCLI(t *testing.T) {
	t.Parallel()
	fixture := makeExternalCLIFixture(t)
	raw := []byte(`{"apiVersion":"extensions/v1beta1","kind":"Ingress","metadata":{"name":"a"}}`)
	path := writeCNCFFile(t, "kubernetes.json", raw, 0o600)
	for _, format := range []string{"human", "json"} {
		args := []string{"check", "cncf", "--project", "kubernetes", "--native-resource", path, "--native-resource-digest", cncfDigest(raw),
			"--from", "1.25.0", "--to", "1.26.0", "--distribution", "official_upstream", "--target-api-apply-required", "--resource-scope-complete",
			"--knowledge-db", fixture.store, "--knowledge-revision", "1", "--knowledge-bundle-digest", fixture.manifest.Revisions[0].BundleDigest,
			"--knowledge-trust-receipt-digest", fixture.receipt1.TrustReceiptDigest, "--format", format}
		code, stdout, stderr := runCNCFCLI(t, args...)
		if code != ExitUnknown || strings.Contains(stdout, "PASS") || stderr != "" {
			t.Fatalf("%s code=%d stdout=%q stderr=%q", format, code, stdout, stderr)
		}
	}
}
