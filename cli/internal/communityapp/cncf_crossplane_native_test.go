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
		"--from", "1.20.0", "--to", "2.0.0", "--now", "2026-11-19T10:00:00Z", "--format", "json",
	}
}

func TestCrossplaneNativeCompositionCheck_BoundedOutcomesAndPrivacy(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name, raw, reason string
		want              int
	}{
		{"resources mode blocks", crossplaneResourcesCompositionResource, "REVIEWED_SOURCE_CONSTRAINT", ExitBlocked},
		{"pipeline mode passes", crossplanePipelineCompositionResource, "REVIEWED_SOURCE_CONSTRAINT", passExit(batchRuleIDs("crossplane"))},
		{"list keeps the resources witness", `{"apiVersion":"v1","kind":"List","items":[` + crossplanePipelineCompositionResource + `,` + crossplaneResourcesCompositionResource + `]}`, "REVIEWED_SOURCE_CONSTRAINT", ExitBlocked},
		{"xrd only stays unknown", `{"apiVersion":"apiextensions.crossplane.io/v1","kind":"CompositeResourceDefinition","metadata":{"name":"private-xrd"}}`, "RULE_FACT_UNAVAILABLE", ExitUnknown},
		{"usage stays unknown", `{"apiVersion":"apiextensions.crossplane.io/v1alpha1","kind":"Usage","metadata":{"name":"private-usage"}}`, "RULE_FACT_UNAVAILABLE", ExitUnknown},
		{"xrd with usage stays unknown", `{"apiVersion":"v1","kind":"List","items":[{"apiVersion":"apiextensions.crossplane.io/v1","kind":"CompositeResourceDefinition","metadata":{"name":"private-xrd"}},{"apiVersion":"apiextensions.crossplane.io/v1alpha1","kind":"Usage","metadata":{"name":"private-usage"}}]}`, "RULE_FACT_UNAVAILABLE", ExitUnknown},
		{"xrd with resources blocks", `{"apiVersion":"v1","kind":"List","items":[{"apiVersion":"apiextensions.crossplane.io/v1","kind":"CompositeResourceDefinition","metadata":{"name":"private-xrd"}},` + crossplaneResourcesCompositionResource + `]}`, "REVIEWED_SOURCE_CONSTRAINT", ExitBlocked},
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
			checkBatchClaims(t, stdout, batchRuleIDs("crossplane"))
		})
	}
}

// The aggregate gate is unchanged by this route: even a scoped PASS keeps the
// whole-upgrade assessment UNKNOWN.
func TestCrossplaneNativeCompositionCheck_KeepsWholeUpgradeAggregateUnknown(t *testing.T) {
	t.Parallel()
	path := writeCNCFFile(t, "crossplane.json", []byte(crossplanePipelineCompositionResource), 0o600)
	code, stdout, stderr := runCNCFCLI(t, crossplaneNativeArgs(path)...)
	if code != passExit(batchRuleIDs("crossplane")) || stderr != "" || !strings.Contains(stdout, `"status":"PASS"`) || !strings.Contains(stdout, `"assessment":"UNKNOWN"`) {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	checkBatchClaims(t, stdout, batchRuleIDs("crossplane"))
	if !strings.Contains(stdout, "WHOLE_UPGRADE_COMPATIBILITY_NOT_EVALUATED") {
		t.Fatalf("missing whole-upgrade omission: %q", stdout)
	}
}

func TestCrossplaneNativeCompositionCheck_CustomBuildAndUndeclaredIntentStayUnknown(t *testing.T) {
	t.Parallel()
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
	t.Parallel()
	selected := writeCNCFFile(t, "crossplane.json", []byte(`{"apiVersion":"apiextensions.crossplane.io/v1","kind":"Composition","metadata":{"name":"a"},"spec":{"mode":"Resources"}}`), 0o600)
	args := crossplaneNativeArgs(selected)
	for index := range args {
		if args[index] == "2.0.0" {
			args[index] = "2.1.0"
		}
	}
	code, stdout, stderr := runCNCFCLI(t, args...)
	if stderr != "" {
		t.Fatalf("wrong pair stderr=%q", stderr)
	}
	// A hop outside every reviewed range: each Composition range rule answers
	// UNKNOWN (transition not reviewed) and nothing decides.
	if code != ExitUnknown || strings.Contains(stdout, `"status":"BLOCKED"`) || strings.Contains(stdout, `"status":"PASS"`) {
		t.Fatalf("off-range code=%d stdout=%q", code, stdout)
	}
	for _, id := range []string{"1-18-2-0", "1-19-2-0", "1-20-2-0"} {
		if !strings.Contains(stdout, `"ruleId":"crossplane.composition-resources-mode-removed.`+id+`"`) {
			t.Fatalf("missing claim for %s: %q", id, stdout)
		}
	}
	checkBatchClaims(t, stdout, batchRuleIDs("crossplane"))
	code, stdout, stderr = runCNCFCLI(t, "check", "cncf", "--project", "crossplane", "--composition", selected, "--crossplane-distribution", "vendor_build", "--crossplane-schema-validation-required", "--from", "1.20.0", "--to", "2.0.0", "--now", "2026-11-19T10:00:00Z", "--format", "json")
	if code != ExitUsage || stdout != "" || strings.Contains(stderr, selected) {
		t.Fatalf("bad distribution code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	code, stdout, stderr = runCNCFCLI(t, "check", "cncf", "--project", "kubernetes", "--composition", "PRIVATE-NOT-READ.json", "--from", "1.31.0", "--to", "1.32.0", "--now", "2026-11-19T10:00:00Z", "--format", "json")
	if code != ExitUsage || stdout != "" || strings.Contains(stderr, "PRIVATE-NOT-READ") {
		t.Fatalf("cross-project code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	code, stdout, stderr = runCNCFCLI(t, "check", "cncf", "--project", "crossplane", "--composition", selected, "--native-resource", selected, "--crossplane-distribution", "official_upstream", "--crossplane-schema-validation-required", "--from", "1.20.0", "--to", "2.0.0", "--now", "2026-11-19T10:00:00Z", "--format", "json")
	if code != ExitUsage || stdout != "" {
		t.Fatalf("cross-mode selector code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
}

func TestCrossplaneNativeCompositionCheck_RejectsIntegrityPinMismatch(t *testing.T) {
	t.Parallel()
	raw := []byte(crossplaneResourcesCompositionResource)
	path := writeCNCFFile(t, "crossplane.json", raw, 0o600)
	args := append(crossplaneNativeArgs(path), "--composition-digest", cncfDigest([]byte(crossplanePipelineCompositionResource)))
	code, stdout, stderr := runCNCFCLI(t, args...)
	if code != ExitIntegrity || strings.Contains(stdout, "BLOCKED") || strings.Contains(stderr, path) {
		t.Fatalf("pin mismatch code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
}

func TestCrossplanePrepareCompositionFeedsCheck(t *testing.T) {
	t.Parallel()
	raw := []byte(crossplaneResourcesCompositionResource)
	path := writeCNCFFile(t, "crossplane.json", raw, 0o600)
	code, canonical, stderr := runCNCFCLI(t, "prepare", "cncf", "--project", "crossplane", "--composition", path, "--composition-digest", cncfDigest(raw), "--from", "1.20.0", "--to", "2.0.0", "--crossplane-distribution", "official_upstream", "--crossplane-schema-validation-required", "--format", "input")
	if code != ExitOK || stderr != "" || !strings.Contains(canonical, "component.crossplane.composition_mode") || strings.Contains(canonical, "private-") {
		t.Fatalf("prepare code=%d stdout=%q stderr=%q", code, canonical, stderr)
	}
	prepared := writeCNCFFile(t, "crossplane-canonical.json", []byte(canonical), 0o600)
	code, report, stderr := runCNCFCLI(t, "check", "cncf", "--project", "crossplane", "--input", prepared, "--input-digest", cncfDigest([]byte(canonical)), "--now", "2026-11-19T10:00:00Z", "--format", "json")
	if code != ExitBlocked || stderr != "" || !strings.Contains(report, `"status":"BLOCKED"`) {
		t.Fatalf("check code=%d stdout=%q stderr=%q", code, report, stderr)
	}
}

const crossplaneOmittedModeComposition = `{"apiVersion":"apiextensions.crossplane.io/v1","kind":"Composition","metadata":{"name":"private-composition"},"spec":{"resources":[{"name":"private-res","base":{"canary":"canary-patch-text"}}]}}`

func crossplaneRangeArgs(path, from, to string, extra ...string) []string {
	args := []string{
		"check", "cncf", "--project", "crossplane", "--composition", path,
		"--crossplane-distribution", "official_upstream", "--crossplane-schema-validation-required",
		"--from", from, "--to", to, "--now", "2026-11-19T10:00:00Z", "--format", "json",
	}
	return append(args, extra...)
}

// An omitted spec.mode on a cited from-version is the 1.x CRD default
// (Resources): BLOCKED against the 2.0 enum, with the source of the mode and
// the caller-supplied nature of the manifest stated beside it. Never a PASS.
func TestCrossplaneNativeCompositionCheck_OmittedModeBlocksOnCitedRange(t *testing.T) {
	t.Parallel()
	path := writeCNCFFile(t, "crossplane.json", []byte(crossplaneOmittedModeComposition), 0o600)
	for _, pair := range [][2]string{{"1.20.14", "2.0.0"}, {"1.20.0", "2.0.8"}, {"1.19.3", "2.0.0"}, {"1.18.0", "2.0.8"}} {
		code, stdout, stderr := runCNCFCLI(t, crossplaneRangeArgs(path, pair[0], pair[1])...)
		if code != ExitBlocked || stderr != "" || !strings.Contains(stdout, `"status":"BLOCKED"`) {
			t.Fatalf("%v code=%d stdout=%q stderr=%q", pair, code, stdout, stderr)
		}
		if !strings.Contains(stdout, "target Composition CRD enum rejects Resources; mode taken from the from-version CRD default") || !strings.Contains(stdout, "caller-supplied manifests, not a live observation") {
			t.Fatalf("%v missing defaulted-mode wording: %q", pair, stdout)
		}
		if strings.Contains(stdout, "private-") || strings.Contains(stdout, "canary-patch-text") || strings.Contains(stdout, path) || strings.Contains(stdout, "upgrade fails") {
			t.Fatalf("%v leaked or overclaimed: %q", pair, stdout)
		}
	}
	// The same human wording is shown on the human report.
	args := crossplaneRangeArgs(path, "1.20.14", "2.0.0")
	args[len(args)-1] = "human"
	code, stdout, _ := runCNCFCLI(t, args...)
	if code != ExitBlocked || !strings.Contains(stdout, "target Composition CRD enum rejects Resources; mode taken from the from-version CRD default") {
		t.Fatalf("human code=%d stdout=%q", code, stdout)
	}
}

func TestCrossplaneNativeCompositionCheck_OmittedModeNeverPassesAndIgnoresUncitedVersions(t *testing.T) {
	t.Parallel()
	path := writeCNCFFile(t, "crossplane.json", []byte(crossplaneOmittedModeComposition), 0o600)
	for _, pair := range [][2]string{{"1.20.15", "2.0.0"}, {"1.17.4", "2.0.0"}, {"1.21.0", "2.0.0"}, {"1.20.14", "2.0.9"}, {"1.20.14", "2.1.0"}} {
		code, stdout, _ := runCNCFCLI(t, crossplaneRangeArgs(path, pair[0], pair[1])...)
		if code == ExitBlocked || code == ExitOK || strings.Contains(stdout, `"status":"PASS"`) || strings.Contains(stdout, `"status":"BLOCKED"`) && !strings.Contains(stdout, "UNKNOWN") {
			t.Fatalf("%v code=%d stdout=%q", pair, code, stdout)
		}
	}
	// Without the declared guards the omitted mode stays UNKNOWN.
	for _, mutate := range []func([]string) []string{
		func(args []string) []string {
			for index, value := range args {
				if value == "--crossplane-schema-validation-required" {
					return append(args[:index:index], args[index+1:]...)
				}
			}
			return args
		},
		func(args []string) []string {
			for index, value := range args {
				if value == "official_upstream" {
					args[index] = "custom_build"
				}
			}
			return args
		},
	} {
		code, stdout, _ := runCNCFCLI(t, mutate(crossplaneRangeArgs(path, "1.20.14", "2.0.0"))...)
		if code != ExitUnknown || strings.Contains(stdout, `"status":"BLOCKED"`) {
			t.Fatalf("guard mutation code=%d stdout=%q", code, stdout)
		}
	}
}

func TestCrossplanePrepareCompositionNamesTheFlagAndTheDefault(t *testing.T) {
	t.Parallel()
	raw := []byte(crossplaneOmittedModeComposition)
	path := writeCNCFFile(t, "crossplane.json", raw, 0o600)
	base := []string{"prepare", "cncf", "--project", "crossplane", "--composition", path, "--from", "1.20.14", "--to", "2.0.0"}
	code, stdout, stderr := runCNCFCLI(t, append(append([]string(nil), base...), "--crossplane-distribution", "official_upstream", "--crossplane-schema-validation-required")...)
	if code != ExitOK || stderr != "" || !strings.Contains(stdout, "CROSSPLANE_COMPOSITION_MODE_DEFAULTED_RESOURCES") || !strings.Contains(stdout, "MODE_DEFAULT_FROM_PINNED_FROM_VERSION_CRD") || strings.Contains(stdout, "private-") {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	code, stdout, _ = runCNCFCLI(t, append(append([]string(nil), base...), "--crossplane-distribution", "official_upstream")...)
	if code != ExitUnknown || !strings.Contains(stdout, "CROSSPLANE_SCHEMA_VALIDATION_NOT_DECLARED") {
		t.Fatalf("schema flag code=%d stdout=%q", code, stdout)
	}
}
