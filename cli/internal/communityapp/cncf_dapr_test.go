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

func daprExampleDeclaration(t *testing.T, complete, present *bool, currentVersion string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "examples", "cncf", "dapr-input.json"))
	if err != nil {
		t.Fatal(err)
	}
	var input map[string]any
	if err := json.Unmarshal(raw, &input); err != nil {
		t.Fatal(err)
	}
	current := input["current"].(map[string]any)["components"].([]any)[0].(map[string]any)
	current["version"] = currentVersion
	facts := make([]any, 0, 2)
	if complete != nil {
		facts = append(facts, map[string]any{"id": "component.dapr.scheduler_embedded_etcd_inventory_complete", "state": "declared", "boolValue": *complete})
	}
	if present != nil {
		facts = append(facts, map[string]any{"id": "component.dapr.scheduler_persisted_data_present", "state": "declared", "boolValue": *present})
	}
	current["facts"] = facts
	encoded, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	return append(encoded, '\n')
}

func TestDaprCanonicalExampleFeedsExistingScopedRule(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "examples", "cncf", "dapr-input.json"))
	if err != nil {
		t.Fatal(err)
	}
	input := writeCNCFFile(t, "dapr-input.json", raw, 0o600)
	code, output, stderr := runCNCFCLI(t,
		"check", "cncf", "--project", "dapr", "--input", input,
		"--input-digest", cncfDigest(raw), "--now", "2026-09-10T14:00:00Z", "--format", "json",
	)
	for _, want := range []string{
		`"ruleId":"dapr.scheduler-persisted-data-loss.1-14-to-1-15"`,
		`"status":"BLOCKED"`,
		`"assessment":"UNKNOWN"`,
		`"networkUsed":false`,
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("output missing %q: %s", want, output)
		}
	}
	if code != ExitBlocked || stderr != "" || strings.Contains(output, input) {
		t.Fatalf("code=%d stderr=%q output=%s", code, stderr, output)
	}
}

func TestDaprCanonicalExampleRejectsMalformedFactWithoutEcho(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "examples", "cncf", "dapr-input.json"))
	if err != nil {
		t.Fatal(err)
	}
	malformed := bytes.Replace(raw, []byte(`"boolValue": true`), []byte(`"boolValue": "true"`), 1)
	if bytes.Equal(malformed, raw) {
		t.Fatal("malformed fixture replacement did not apply")
	}
	input := writeCNCFFile(t, "private-dapr-malformed.json", malformed, 0o600)
	code, output, stderr := runCNCFCLI(t,
		"check", "cncf", "--project", "dapr", "--input", input,
		"--input-digest", cncfDigest(malformed), "--now", "2026-09-10T14:00:00Z", "--format", "json",
	)
	if code != ExitUsage || output != "" || stderr != "prufyx: CNCF source-constraint check failed\n" || strings.Contains(stderr, input) || strings.Contains(stderr, "scheduler_") {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, output, stderr)
	}
}

func TestDaprOperatorDeclarationsPreservePassAndUnknownBoundaries(t *testing.T) {
	yes, no := true, false
	for _, tc := range []struct {
		name              string
		complete, present *bool
		currentVersion    string
		wantCode          int
		wantStatus        string
	}{
		{name: "complete applicable inventory with no data passes scoped predicate", complete: &yes, present: &no, currentVersion: "1.14.0", wantCode: ExitOK, wantStatus: "PASS"},
		{name: "missing completeness stays unknown", complete: nil, present: &yes, currentVersion: "1.14.0", wantCode: ExitUnknown, wantStatus: "UNKNOWN"},
		{name: "scheduler version pair without data knowledge stays unknown", complete: nil, present: nil, currentVersion: "1.14.0", wantCode: ExitUnknown, wantStatus: "UNKNOWN"},
		{name: "external custom or incomplete inventory stays unknown", complete: &no, present: &yes, currentVersion: "1.14.0", wantCode: ExitUnknown, wantStatus: "UNKNOWN"},
		{name: "unreviewed version tuple stays unknown", complete: &yes, present: &yes, currentVersion: "1.14.1", wantCode: ExitUnknown, wantStatus: "UNKNOWN"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := daprExampleDeclaration(t, tc.complete, tc.present, tc.currentVersion)
			input := writeCNCFFile(t, "dapr-input.json", raw, 0o600)
			code, output, stderr := runCNCFCLI(t,
				"check", "cncf", "--project", "dapr", "--input", input,
				"--input-digest", cncfDigest(raw), "--now", "2026-09-10T14:00:00Z", "--format", "json",
			)
			if code != tc.wantCode || stderr != "" || !strings.Contains(output, `"status":"`+tc.wantStatus+`"`) || !strings.Contains(output, `"assessment":"UNKNOWN"`) || strings.Contains(output, input) {
				t.Fatalf("code=%d stderr=%q output=%s", code, stderr, output)
			}
		})
	}
}
