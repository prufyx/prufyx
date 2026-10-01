// SPDX-License-Identifier: AGPL-3.0-only

package communityapp

import (
	"strings"
	"testing"
)

const crossplaneResourcesCompositionResource = `{"apiVersion":"apiextensions.crossplane.io/v1","kind":"Composition","metadata":{"name":"private-composition"},"spec":{"mode":"Resources","compositeTypeRef":{"apiVersion":"private.example/v1","kind":"PrivateClaim"}}}`
const crossplanePipelineCompositionResource = `{"apiVersion":"apiextensions.crossplane.io/v1","kind":"Composition","metadata":{"name":"private-composition"},"spec":{"mode":"Pipeline","compositeTypeRef":{"apiVersion":"private.example/v1","kind":"PrivateClaim"}}}`

func crossplaneNativeArgs(path string) []string {
	return []string{
		"check", "cncf", "--project", "crossplane", "--composition", path,
		"--crossplane-distribution", "official_upstream", "--crossplane-schema-validation-required",
		"--from", "1.20.0", "--to", "2.0.0", "--now", "2026-09-18T10:00:00Z", "--format", "json",
	}
}

func TestCrossplaneNativeCompositionCheck_BoundedOutcomesAndPrivacy(t *testing.T) {
	for _, test := range []struct {
		name, raw, reason string
		want              int
	}{
		{"resources mode blocks", crossplaneResourcesCompositionResource, "REVIEWED_SOURCE_CONSTRAINT", ExitBlocked},
		{"pipeline mode passes", crossplanePipelineCompositionResource, "REVIEWED_SOURCE_CONSTRAINT", ExitOK},
		{"list keeps the resources witness", `{"apiVersion":"v1","kind":"List","items":[` + crossplanePipelineCompositionResource + `,` + crossplaneResourcesCompositionResource + `]}`, "REVIEWED_SOURCE_CONSTRAINT", ExitBlocked},
		{"other kind stays unknown", `{"apiVersion":"apiextensions.crossplane.io/v1","kind":"CompositeResourceDefinition","metadata":{"name":"private-xrd"}}`, "RULE_FACT_UNAVAILABLE", ExitUnknown},
		{"unreviewed served version stays unknown", `{"apiVersion":"apiextensions.crossplane.io/v1beta1","kind":"Composition","metadata":{"name":"private-composition"},"spec":{"mode":"Resources"}}`, "RULE_FACT_UNAVAILABLE", ExitUnknown},
		{"omitted mode stays unknown", `{"apiVersion":"apiextensions.crossplane.io/v1","kind":"Composition","metadata":{"name":"private-composition"},"spec":{"resources":[]}}`, "RULE_FACT_UNAVAILABLE", ExitUnknown},
		{"unresolved rendering stays unknown", `{"apiVersion":"apiextensions.crossplane.io/v1","kind":"Composition","spec":{"mode":"{{ .Values.mode }}"}}`, "RULE_FACT_UNAVAILABLE", ExitUnknown},
		{"pagination stays unknown", `{"apiVersion":"v1","kind":"List","metadata":{"remainingItemCount":1},"items":[` + crossplaneResourcesCompositionResource + `]}`, "RULE_FACT_UNAVAILABLE", ExitUnknown},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := writeCNCFFile(t, "crossplane.json", []byte(test.raw), 0o600)
			code, stdout, stderr := runCNCFCLI(t, crossplaneNativeArgs(path)...)
			if code != test.want || stderr != "" || !strings.Contains(stdout, test.reason) || !strings.Contains(stdout, `"assessment":"UNKNOWN"`) || strings.Contains(stdout, "private-") || strings.Contains(stdout, path) {
				t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout, stderr)
			}
		})
	}
}

// The aggregate gate is unchanged by this route: even a scoped PASS keeps the
// whole-upgrade assessment UNKNOWN.
func TestCrossplaneNativeCompositionCheck_KeepsWholeUpgradeAggregateUnknown(t *testing.T) {
	path := writeCNCFFile(t, "crossplane.json", []byte(crossplanePipelineCompositionResource), 0o600)
	code, stdout, stderr := runCNCFCLI(t, crossplaneNativeArgs(path)...)
	if code != ExitOK || stderr != "" || !strings.Contains(stdout, `"status":"PASS"`) || !strings.Contains(stdout, `"assessment":"UNKNOWN"`) {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	if !strings.Contains(stdout, "WHOLE_UPGRADE_COMPATIBILITY_NOT_EVALUATED") {
		t.Fatalf("missing whole-upgrade omission: %q", stdout)
	}
}

func TestCrossplaneNativeCompositionCheck_CustomBuildAndUndeclaredIntentStayUnknown(t *testing.T) {
	path := writeCNCFFile(t, "crossplane.json", []byte(crossplaneResourcesCompositionResource), 0o600)
	for _, test := range []struct {
		name   string
		mutate func([]string) []string
	}{
		{"custom build", func(args []string) []string {
			for index, value := range args {
				if value == "official_upstream" {
					args[index] = "custom_build"
				}
			}
			return args
		}},
		{"schema validation intent not declared", func(args []string) []string {
			for index, value := range args {
				if value == "--crossplane-schema-validation-required" {
					return append(args[:index:index], args[index+1:]...)
				}
			}
			return args
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			code, stdout, stderr := runCNCFCLI(t, test.mutate(crossplaneNativeArgs(path))...)
			if code != ExitUnknown || stderr != "" || !strings.Contains(stdout, "RULE_APPLICABILITY_NOT_MATCHED") {
				t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout, stderr)
			}
		})
	}
}

func TestCrossplaneNativeCompositionCheck_RejectsMalformedWrongPairAndWrongRoute(t *testing.T) {
	selected := writeCNCFFile(t, "crossplane.json", []byte(`{"apiVersion":"apiextensions.crossplane.io/v1","kind":"Composition","metadata":{"name":"a"},"spec":{"mode":"Resources"}}`), 0o600)
	args := crossplaneNativeArgs(selected)
	for index := range args {
		if args[index] == "2.0.0" {
			args[index] = "2.0.1"
		}
	}
	code, stdout, stderr := runCNCFCLI(t, args...)
	if code != ExitUnknown || stderr != "" || !strings.Contains(stdout, "RULE_TRANSITION_NOT_REVIEWED") {
		t.Fatalf("wrong pair code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	code, stdout, stderr = runCNCFCLI(t, "check", "cncf", "--project", "crossplane", "--composition", selected, "--crossplane-distribution", "vendor_build", "--crossplane-schema-validation-required", "--from", "1.20.0", "--to", "2.0.0", "--now", "2026-09-18T10:00:00Z", "--format", "json")
	if code != ExitUsage || stdout != "" || strings.Contains(stderr, selected) {
		t.Fatalf("bad distribution code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	code, stdout, stderr = runCNCFCLI(t, "check", "cncf", "--project", "kubernetes", "--composition", "PRIVATE-NOT-READ.json", "--from", "1.31.0", "--to", "1.32.0", "--now", "2026-09-18T10:00:00Z", "--format", "json")
	if code != ExitUsage || stdout != "" || strings.Contains(stderr, "PRIVATE-NOT-READ") {
		t.Fatalf("cross-project code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	code, stdout, stderr = runCNCFCLI(t, "check", "cncf", "--project", "crossplane", "--composition", selected, "--native-resource", selected, "--crossplane-distribution", "official_upstream", "--crossplane-schema-validation-required", "--from", "1.20.0", "--to", "2.0.0", "--now", "2026-09-18T10:00:00Z", "--format", "json")
	if code != ExitUsage || stdout != "" {
		t.Fatalf("cross-mode selector code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
}

func TestCrossplaneNativeCompositionCheck_RejectsIntegrityPinMismatch(t *testing.T) {
	raw := []byte(crossplaneResourcesCompositionResource)
	path := writeCNCFFile(t, "crossplane.json", raw, 0o600)
	args := append(crossplaneNativeArgs(path), "--composition-digest", cncfDigest([]byte(crossplanePipelineCompositionResource)))
	code, stdout, stderr := runCNCFCLI(t, args...)
	if code != ExitIntegrity || strings.Contains(stdout, "BLOCKED") || strings.Contains(stderr, path) {
		t.Fatalf("pin mismatch code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
}

func TestCrossplanePrepareCompositionFeedsCheck(t *testing.T) {
	raw := []byte(crossplaneResourcesCompositionResource)
	path := writeCNCFFile(t, "crossplane.json", raw, 0o600)
	code, canonical, stderr := runCNCFCLI(t, "prepare", "cncf", "--project", "crossplane", "--composition", path, "--composition-digest", cncfDigest(raw), "--from", "1.20.0", "--to", "2.0.0", "--crossplane-distribution", "official_upstream", "--crossplane-schema-validation-required", "--format", "input")
	if code != ExitOK || stderr != "" || !strings.Contains(canonical, "component.crossplane.composition_mode") || strings.Contains(canonical, "private-") {
		t.Fatalf("prepare code=%d stdout=%q stderr=%q", code, canonical, stderr)
	}
	prepared := writeCNCFFile(t, "crossplane-canonical.json", []byte(canonical), 0o600)
	code, report, stderr := runCNCFCLI(t, "check", "cncf", "--project", "crossplane", "--input", prepared, "--input-digest", cncfDigest([]byte(canonical)), "--now", "2026-09-18T10:00:00Z", "--format", "json")
	if code != ExitBlocked || stderr != "" || !strings.Contains(report, `"status":"BLOCKED"`) {
		t.Fatalf("check code=%d stdout=%q stderr=%q", code, report, stderr)
	}
}
