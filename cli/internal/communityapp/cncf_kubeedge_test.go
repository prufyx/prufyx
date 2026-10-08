// SPDX-License-Identifier: AGPL-3.0-only

package communityapp

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func kubeEdgeExampleDeclaration(t *testing.T, selectorState, selectorValue string, complete bool, distribution, surface, currentVersion string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "examples", "cncf", "kubeedge-input.json"))
	if err != nil {
		t.Fatal(err)
	}
	var input map[string]any
	if err := json.Unmarshal(raw, &input); err != nil {
		t.Fatal(err)
	}
	current := input["current"].(map[string]any)["components"].([]any)[0].(map[string]any)
	current["version"] = currentVersion
	proposed := input["proposed"].(map[string]any)["components"].([]any)[0].(map[string]any)
	facts := []any{
		map[string]any{"id": "component.kubeedge.distribution", "state": "declared", "enumValue": distribution},
		map[string]any{"id": "component.kubeedge.effective_argv_complete", "state": "declared", "boolValue": complete},
		map[string]any{"id": "component.kubeedge.execution_surface", "state": "declared", "enumValue": surface},
	}
	if selectorState != "" {
		selector := map[string]any{"id": "component.kubeedge.init_version_selection_form", "state": selectorState}
		if selectorState == "declared" {
			selector["enumValue"] = selectorValue
		}
		facts = append(facts, selector)
	}
	proposed["facts"] = facts
	encoded, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	return append(encoded, '\n')
}

func runKubeEdgeDeclaration(t *testing.T, raw []byte) (int, string, string) {
	t.Helper()
	input := writeCNCFFile(t, "kubeedge-input.json", raw, 0o600)
	return runCNCFCLI(t,
		"check", "cncf", "--project", "kubeedge", "--input", input,
		"--input-digest", cncfDigest(raw), "--now", "2026-09-10T14:30:00Z", "--format", "json",
	)
}

func TestKubeEdgeCanonicalExampleFeedsExistingScopedRule(t *testing.T) {
	t.Parallel()
	raw, err := os.ReadFile(filepath.Join("..", "..", "examples", "cncf", "kubeedge-input.json"))
	if err != nil {
		t.Fatal(err)
	}
	code, output, stderr := runKubeEdgeDeclaration(t, raw)
	for _, want := range []string{
		"\"ruleId\":\"kubeedge.keadm-init-profile-version-selector.1-18-to-1-19\"",
		"\"status\":\"BLOCKED\"",
		"\"assessment\":\"UNKNOWN\"",
		"\"networkUsed\":false",
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("output missing %q: %s", want, output)
		}
	}
	if code != ExitBlocked || stderr != "" {
		t.Fatalf("code=%d stderr=%q output=%s", code, stderr, output)
	}
}

func TestKubeEdgeDeclarationsPreserveIntentAndApplicabilityBoundaries(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name                                  string
		selectorState, selectorValue          string
		complete                              bool
		distribution, surface, currentVersion string
		wantCode                              int
		wantStatus                            string
	}{
		{name: "explicit target flag and absent profile passes scoped predicate", selectorState: "declared", selectorValue: "kubeedge_version_flag_only", complete: true, distribution: "official_upstream", surface: "keadm_init", currentVersion: "1.18.0", wantCode: ExitOK, wantStatus: "PASS"},
		{name: "external profile meaning stays unknown", selectorState: "", complete: true, distribution: "official_upstream", surface: "keadm_init", currentVersion: "1.18.0", wantCode: ExitUnknown, wantStatus: "UNKNOWN"},
		{name: "both selector meanings stay unknown", selectorState: "conflict", complete: true, distribution: "official_upstream", surface: "keadm_init", currentVersion: "1.18.0", wantCode: ExitUnknown, wantStatus: "UNKNOWN"},
		{name: "unsupported selector meaning stays unknown", selectorState: "unsupported", complete: true, distribution: "official_upstream", surface: "keadm_init", currentVersion: "1.18.0", wantCode: ExitUnknown, wantStatus: "UNKNOWN"},
		{name: "partial argv stays unknown", selectorState: "declared", selectorValue: "legacy_profile_version", complete: false, distribution: "official_upstream", surface: "keadm_init", currentVersion: "1.18.0", wantCode: ExitUnknown, wantStatus: "UNKNOWN"},
		{name: "custom build stays unknown", selectorState: "declared", selectorValue: "legacy_profile_version", complete: true, distribution: "custom_build", surface: "keadm_init", currentVersion: "1.18.0", wantCode: ExitUnknown, wantStatus: "UNKNOWN"},
		{name: "other command stays unknown", selectorState: "declared", selectorValue: "legacy_profile_version", complete: true, distribution: "official_upstream", surface: "other", currentVersion: "1.18.0", wantCode: ExitUnknown, wantStatus: "UNKNOWN"},
		{name: "wrong tuple stays unknown", selectorState: "declared", selectorValue: "legacy_profile_version", complete: true, distribution: "official_upstream", surface: "keadm_init", currentVersion: "1.18.1", wantCode: ExitUnknown, wantStatus: "UNKNOWN"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := kubeEdgeExampleDeclaration(t, tc.selectorState, tc.selectorValue, tc.complete, tc.distribution, tc.surface, tc.currentVersion)
			code, output, stderr := runKubeEdgeDeclaration(t, raw)
			if code != tc.wantCode || stderr != "" || !strings.Contains(output, "\"status\":\""+tc.wantStatus+"\"") || !strings.Contains(output, "\"assessment\":\"UNKNOWN\"") || strings.Contains(output, "kubeedge-input.json") {
				t.Fatalf("code=%d stderr=%q output=%s", code, stderr, output)
			}
		})
	}
}

func TestKubeEdgeCanonicalExampleRejectsMalformedIntentWithoutEcho(t *testing.T) {
	t.Parallel()
	raw, err := os.ReadFile(filepath.Join("..", "..", "examples", "cncf", "kubeedge-input.json"))
	if err != nil {
		t.Fatal(err)
	}
	malformed := bytes.Replace(raw, []byte("\"legacy_profile_version\""), []byte("\"version=v1.19.0\""), 1)
	if bytes.Equal(malformed, raw) {
		t.Fatal("malformed fixture replacement did not apply")
	}
	input := writeCNCFFile(t, "private-kubeedge-version=v1.19.0.json", malformed, 0o600)
	code, output, stderr := runCNCFCLI(t,
		"check", "cncf", "--project", "kubeedge", "--input", input,
		"--input-digest", cncfDigest(malformed), "--now", "2026-09-10T14:30:00Z", "--format", "json",
	)
	if code != ExitUsage || output != "" || stderr != "prufyx: CNCF source-constraint check failed\n" || strings.Contains(stderr, input) || strings.Contains(stderr, "version=v1.19.0") {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, output, stderr)
	}
}
