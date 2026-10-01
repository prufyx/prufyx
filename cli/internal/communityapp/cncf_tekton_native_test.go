// SPDX-License-Identifier: AGPL-3.0-only

package communityapp

import (
	"strings"
	"testing"
)

func tektonNativeConfigMap(data string) []byte {
	return []byte(`apiVersion: v1
kind: ConfigMap
metadata:
  name: config-observability
  namespace: private-tekton-pipelines
` + data)
}

func tektonNativeArgs(path, from, to, distribution, namespace, complete, retain string) []string {
	args := []string{
		"check", "cncf", "--project", "tekton", "--tekton-config-observability", path,
		"--from", from, "--to", to,
	}
	if distribution != "" {
		args = append(args, "--tekton-distribution", distribution)
	}
	if namespace != "" {
		args = append(args, "--tekton-system-namespace", namespace)
	}
	if complete != "" {
		args = append(args, "--tekton-config-observability-complete", complete)
	}
	if retain != "" {
		args = append(args, "--retain-prometheus-metrics-required", retain)
	}
	return append(args, "--now", "2026-09-19T00:00:00Z", "--format", "json")
}

// The native one-step route reads only the one reviewed metrics-protocol data
// key. It authors no new compatibility claim: the pinned v1.10
// config-observability.yaml sets that key, the pinned v1.10 knative.dev/pkg
// metrics config declares the protocol tokens and a ProtocolNone default, and
// the pinned v1.9 parser plus the v1.10 legacy note establish that
// metrics.backend-destination is the removed spelling.
func TestTektonConfigObservabilityNativeCheck_BoundedOutcomesAndPrivacy(t *testing.T) {
	for _, test := range []struct {
		name   string
		data   string
		status string
		want   int
	}{
		{"exact prometheus protocol passes", "data:\n  metrics-protocol: prometheus\n", "PASS", ExitOK},
		{"definite absence blocks", "data:\n  runtime-profiling: disabled\n", "BLOCKED", ExitBlocked},
		{"removed legacy key alone blocks", "data:\n  metrics.backend-destination: prometheus\n", "BLOCKED", ExitBlocked},
		{"recognized non-prometheus protocol stays unknown", "data:\n  metrics-protocol: grpc\n", "UNKNOWN", ExitUnknown},
		{"empty protocol value stays unknown", "data:\n  metrics-protocol: \"\"\n", "UNKNOWN", ExitUnknown},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := writeCNCFFile(t, "config-observability.yaml", tektonNativeConfigMap(test.data), 0o600)
			code, stdout, stderr := runCNCFCLI(t, tektonNativeArgs(path, "1.9.0", "1.10.0", "official_upstream", "private-tekton-pipelines", "true", "true")...)
			if code != test.want || stderr != "" || !strings.Contains(stdout, `"status":"`+test.status+`"`) || !strings.Contains(stdout, `"assessment":"UNKNOWN"`) || strings.Contains(stdout, path) {
				t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout, stderr)
			}
			if strings.Contains(stdout, "private-tekton-pipelines") || strings.Contains(stdout, "runtime-profiling") {
				t.Fatalf("private ConfigMap content echoed: %q", stdout)
			}
		})
	}
}

// The reviewed _example block is a data value, not a protocol source; it is
// never scanned.
func TestTektonConfigObservabilityNativeCheck_IgnoresExampleBlock(t *testing.T) {
	path := writeCNCFFile(t, "config-observability-example.yaml", tektonNativeConfigMap(`data:
  metrics-protocol: prometheus
  _example: |
    metrics-protocol: grpc
    metrics.backend-destination: stackdriver
`), 0o600)
	code, stdout, stderr := runCNCFCLI(t, tektonNativeArgs(path, "1.9.0", "1.10.0", "official_upstream", "private-tekton-pipelines", "true", "true")...)
	if code != ExitOK || stderr != "" || !strings.Contains(stdout, `"status":"PASS"`) || strings.Contains(stdout, "stackdriver") {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
}

// Every guard is a caller declaration; none is inferred, and the identity
// binding is never assumed.
func TestTektonConfigObservabilityNativeCheck_GuardsAreNeverInferred(t *testing.T) {
	path := writeCNCFFile(t, "config-observability.yaml", tektonNativeConfigMap("data:\n  metrics-protocol: prometheus\n"), 0o600)
	for _, test := range []struct {
		name                                      string
		distribution, namespace, complete, retain string
		status                                    string
		want                                      int
	}{
		{"custom build stays unknown", "custom_build", "private-tekton-pipelines", "true", "true", "UNKNOWN", ExitUnknown},
		{"incomplete composition stays unknown", "official_upstream", "private-tekton-pipelines", "false", "true", "UNKNOWN", ExitUnknown},
		{"no retention requirement stays unknown", "official_upstream", "private-tekton-pipelines", "true", "false", "UNKNOWN", ExitUnknown},
		{"unbound namespace stays unknown", "official_upstream", "other-namespace", "true", "true", "UNKNOWN", ExitUnknown},
		{"all guards satisfied passes", "official_upstream", "private-tekton-pipelines", "true", "true", "PASS", ExitOK},
	} {
		t.Run(test.name, func(t *testing.T) {
			code, stdout, stderr := runCNCFCLI(t, tektonNativeArgs(path, "1.9.0", "1.10.0", test.distribution, test.namespace, test.complete, test.retain)...)
			if code != test.want || stderr != "" || !strings.Contains(stdout, `"status":"`+test.status+`"`) || !strings.Contains(stdout, `"assessment":"UNKNOWN"`) {
				t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout, stderr)
			}
		})
	}
}

// The aggregate gate is unchanged by this route: even a scoped PASS keeps the
// whole-upgrade assessment UNKNOWN.
func TestTektonConfigObservabilityNativeCheck_KeepsWholeUpgradeAggregateUnknown(t *testing.T) {
	path := writeCNCFFile(t, "config-observability-clean.yaml", tektonNativeConfigMap("data:\n  metrics-protocol: prometheus\n"), 0o600)
	code, stdout, stderr := runCNCFCLI(t, tektonNativeArgs(path, "1.9.0", "1.10.0", "official_upstream", "private-tekton-pipelines", "true", "true")...)
	if code != ExitOK || stderr != "" || !strings.Contains(stdout, `"status":"PASS"`) || !strings.Contains(stdout, `"assessment":"UNKNOWN"`) {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	if !strings.Contains(stdout, "WHOLE_UPGRADE_COMPATIBILITY_NOT_EVALUATED") {
		t.Fatalf("missing whole-upgrade omission: %q", stdout)
	}
}

func TestTektonConfigObservabilityNativeCheck_RejectsWrongPairAndWrongRoute(t *testing.T) {
	path := writeCNCFFile(t, "config-observability.yaml", tektonNativeConfigMap("data:\n  metrics-protocol: prometheus\n"), 0o600)
	code, stdout, stderr := runCNCFCLI(t, tektonNativeArgs(path, "1.9.1", "1.10.0", "official_upstream", "private-tekton-pipelines", "true", "true")...)
	if code != ExitUnknown || stderr != "" || !strings.Contains(stdout, `"assessment":"UNKNOWN"`) {
		t.Fatalf("wrong pair code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	code, stdout, stderr = runCNCFCLI(t, "check", "cncf", "--project", "falco", "--tekton-config-observability", "PRIVATE-NOT-READ.yaml", "--from", "0.40.0", "--to", "0.41.0", "--now", "2026-09-19T00:00:00Z", "--format", "json")
	if code != ExitUsage || strings.Contains(stderr, "PRIVATE-NOT-READ") || strings.Contains(stdout, "PRIVATE-NOT-READ") {
		t.Fatalf("cross-project code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	code, stdout, stderr = runCNCFCLI(t, tektonNativeArgs(path, "1.9.0", "1.10.0", "unreviewed", "private-tekton-pipelines", "true", "true")...)
	if code != ExitUsage || stdout != "" {
		t.Fatalf("bad distribution code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
}

func TestTektonConfigObservabilityNativeCheck_RejectsIntegrityPinMismatch(t *testing.T) {
	path := writeCNCFFile(t, "config-observability.yaml", tektonNativeConfigMap("data:\n  metrics-protocol: grpc\n"), 0o600)
	args := append(tektonNativeArgs(path, "1.9.0", "1.10.0", "official_upstream", "private-tekton-pipelines", "true", "true"),
		"--tekton-config-observability-digest", cncfDigest(tektonNativeConfigMap("data:\n  metrics-protocol: prometheus\n")))
	code, stdout, stderr := runCNCFCLI(t, args...)
	if code != ExitIntegrity || strings.Contains(stdout, "PASS") || strings.Contains(stderr, path) {
		t.Fatalf("pin mismatch code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
}

// The native route and the hand-authored canonical declaration reach the same
// scoped outcome for the same reviewed rule.
func TestTektonConfigObservabilityNativeCheckMatchesCanonicalDeclaration(t *testing.T) {
	path := writeCNCFFile(t, "config-observability.yaml", tektonNativeConfigMap("data:\n  metrics-protocol: prometheus\n"), 0o600)
	nativeCode, nativeReport, nativeErr := runCNCFCLI(t, tektonNativeArgs(path, "1.9.0", "1.10.0", "official_upstream", "private-tekton-pipelines", "true", "true")...)
	if nativeCode != ExitOK || nativeErr != "" || !strings.Contains(nativeReport, `"ruleId":"tekton.metrics-protocol-prometheus.1-10"`) || !strings.Contains(nativeReport, `"status":"PASS"`) {
		t.Fatalf("native code=%d stdout=%q stderr=%q", nativeCode, nativeReport, nativeErr)
	}
}
