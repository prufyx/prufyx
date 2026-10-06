// SPDX-License-Identifier: AGPL-3.0-only

package communityapp

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestOpenCostSourceSelectionPreparationFeedsCNCFRule(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name, current, proposed, status string
		prepareCode, checkCode          int
	}{
		{
			name:        "provider-only target blocked",
			current:     `{"cloudCostEnabled":true,"sourceSelectionComplete":true,"selectedSource":"provider_derived"}`,
			proposed:    `{"cloudCostEnabled":true,"sourceSelectionComplete":true,"selectedSource":"provider_derived","cloudIntegrationConfigSource":"absent"}`,
			status:      "BLOCKED",
			prepareCode: ExitOK,
			checkCode:   ExitBlocked,
		},
		{
			name:        "declared target integration file passes source-kind constraint",
			current:     `{"cloudCostEnabled":true,"sourceSelectionComplete":true,"selectedSource":"provider_derived"}`,
			proposed:    `{"cloudCostEnabled":true,"sourceSelectionComplete":true,"selectedSource":"cloud_integration","cloudIntegrationConfigSource":"present"}`,
			status:      "PASS",
			prepareCode: ExitOK,
			checkCode:   ExitOK,
		},
		{
			name:        "unresolved target source remains unknown",
			current:     `{"cloudCostEnabled":true,"sourceSelectionComplete":true,"selectedSource":"provider_derived"}`,
			proposed:    `{"cloudCostEnabled":true,"sourceSelectionComplete":true,"selectedSource":"api_managed","cloudIntegrationConfigSource":"unknown"}`,
			status:      "UNKNOWN",
			prepareCode: ExitUnknown,
			checkCode:   ExitUnknown,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			const canary = "opencost-private-source-canary"
			raw := []byte(`{"schema":"prufyx.io/opencost-cloud-cost-source-selection/v1alpha1","current":` + test.current + `,"proposed":` + test.proposed + `}`)
			path := writeCNCFFile(t, canary+".json", raw, 0o600)
			code, input, stderr := runCNCFCLI(t, "prepare", "cncf", "--project", "opencost", "--input", path, "--input-digest", cncfDigest(raw), "--from", "1.119.0", "--to", "1.120.0", "--format", "input")
			if code != test.prepareCode || stderr != "" || !json.Valid([]byte(input)) || strings.Contains(input, canary) || strings.Contains(input, path) || strings.Contains(input, "selectedSource") {
				t.Fatalf("prepare code=%d stderr=%q input=%s", code, stderr, input)
			}
			prepared := writeCNCFFile(t, "opencost-prepared.json", []byte(input), 0o600)
			code, report, stderr := runCNCFCLI(t, "check", "cncf", "--project", "opencost", "--input", prepared, "--input-digest", cncfDigest([]byte(input)), "--now", "2026-09-11T22:00:00Z", "--format", "json")
			if code != test.checkCode || stderr != "" || !strings.Contains(report, `"status":"`+test.status+`"`) || strings.Contains(report, canary) || strings.Contains(report, path) {
				t.Fatalf("check code=%d stderr=%q report=%s", code, stderr, report)
			}
			if !strings.Contains(report, "SOURCE_SELECTION_AND_FILE_PRESENCE_ARE_CALLER_DECLARED_NOT_OBSERVED") && test.status == "UNKNOWN" {
				// The generic report does not carry preparer omissions; the canonical
				// unknown fact must still remain non-conclusive.
				if !strings.Contains(report, `"assessment":"UNKNOWN"`) {
					t.Fatalf("unknown assessment missing: %s", report)
				}
			}
		})
	}
}

func TestOpenCostPreparationRejectsCrossProjectOptionsBeforeReadingInput(t *testing.T) {
	t.Parallel()
	args := []string{"prepare", "cncf", "--project", "opencost", "--input", "/private/not-opened", "--from", "1.119.0", "--to", "1.120.0", "--operation", "configuration-spec-migration"}
	code, stdout, stderr := runCNCFCLI(t, args...)
	if code != ExitUsage || stdout != "" || stderr == "" || strings.Contains(stderr, "/private/not-opened") {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
}

func TestOpenCostPreparationRejectsInvalidRequiredArgumentsBeforeReadingInput(t *testing.T) {
	t.Parallel()
	const privatePath = "/private/opencost-source-must-not-be-opened"
	tests := [][]string{
		{"prepare", "cncf", "--project", "opencost", "--from", "1.119.0", "--to", "1.120.0"},
		{"prepare", "cncf", "--project", "opencost", "--input", privatePath, "--from", "1.119.0", "--to", "1.120.0", "--input-digest="},
		{"prepare", "cncf", "--project", "opencost", "--input", privatePath, "--from", "1.119.0", "--to", "1.120.0", "--input-digest", "not-a-digest"},
	}
	for _, args := range tests {
		code, stdout, stderr := runCNCFCLI(t, args...)
		if code != ExitUsage || stdout != "" || stderr != "prufyx: OPENCOST_PREPARATION_INPUT_INVALID\n" || strings.Contains(stderr, privatePath) {
			t.Fatalf("args=%v code=%d stdout=%q stderr=%q", args, code, stdout, stderr)
		}
	}
}

func TestOpenCostPreparationRejectsMalformedWithoutEcho(t *testing.T) {
	t.Parallel()
	const canary = "opencost-private-malformed-canary"
	raw := []byte(`{"schema":"prufyx.io/opencost-cloud-cost-source-selection/v1alpha1","current":{"cloudCostEnabled":"` + canary + `"},"proposed":{}}`)
	path := writeCNCFFile(t, canary+".json", raw, 0o600)
	code, stdout, stderr := runCNCFCLI(t, "prepare", "cncf", "--project", "opencost", "--input", path, "--from", "1.119.0", "--to", "1.120.0", "--format", "json")
	if code != ExitUsage || stdout != "" || stderr == "" || strings.Contains(stderr, canary) || strings.Contains(stderr, path) {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
}

func TestOpenCostLatestFiveOriginRoutes(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name, proposed, status string
		prepareCode, checkCode int
	}{
		{"blocked", `{"cloudCostEnabled":true,"sourceSelectionComplete":true,"selectedSource":"provider_derived","cloudIntegrationConfigSource":"absent"}`, "BLOCKED", ExitOK, ExitBlocked},
		{"clear", `{"cloudCostEnabled":true,"sourceSelectionComplete":true,"selectedSource":"cloud_integration","cloudIntegrationConfigSource":"present"}`, "PASS", ExitOK, ExitOK},
		{"ambiguous", `{"cloudCostEnabled":true,"sourceSelectionComplete":true,"selectedSource":"api_managed","cloudIntegrationConfigSource":"unknown"}`, "UNKNOWN", ExitUnknown, ExitUnknown},
	}
	for _, from := range []string{"1.116.0", "1.117.6", "1.118.0", "1.119.2", "1.120.4"} {
		for _, test := range tests {
			t.Run(from+"/"+test.name, func(t *testing.T) {
				raw := []byte(`{"schema":"prufyx.io/opencost-cloud-cost-source-selection/v1alpha1","current":{"cloudCostEnabled":true,"sourceSelectionComplete":true,"selectedSource":"provider_derived"},"proposed":` + test.proposed + `}`)
				path := writeCNCFFile(t, "private-selection.json", raw, 0o600)
				code, input, stderr := runCNCFCLI(t, "prepare", "cncf", "--project", "opencost", "--input", path, "--input-digest", cncfDigest(raw), "--from", from, "--to", "1.121.2", "--format", "input")
				if code != test.prepareCode || stderr != "" || !json.Valid([]byte(input)) || !strings.Contains(input, `"version":"`+from+`"`) || !strings.Contains(input, `"version":"1.121.2"`) || strings.Contains(input, "selectedSource") || strings.Contains(input, path) {
					t.Fatalf("prepare code=%d stderr=%q input=%q", code, stderr, input)
				}
				prepared := writeCNCFFile(t, "prepared.json", []byte(input), 0o600)
				code, report, stderr := runCNCFCLI(t, "check", "cncf", "--project", "opencost", "--input", prepared, "--input-digest", cncfDigest([]byte(input)), "--now", "2026-09-12T10:00:00Z", "--format", "json")
				ruleID := "opencost.cloud-cost-source-migration." + strings.ReplaceAll(from, ".", "-") + "-to-1-121-2"
				if code != test.checkCode || stderr != "" || !strings.Contains(report, `"ruleId":"`+ruleID+`"`) || !strings.Contains(report, `"status":"`+test.status+`"`) || !strings.Contains(report, `"assessment":"UNKNOWN"`) || strings.Contains(report, path) {
					t.Fatalf("check code=%d stderr=%q report=%q", code, stderr, report)
				}
			})
		}
	}

	raw := []byte(`{"schema":"prufyx.io/opencost-cloud-cost-source-selection/v1alpha1","current":{"cloudCostEnabled":true,"sourceSelectionComplete":true,"selectedSource":"provider_derived"},"proposed":{"cloudCostEnabled":true,"sourceSelectionComplete":true,"selectedSource":"cloud_integration","cloudIntegrationConfigSource":"present"}}`)
	path := writeCNCFFile(t, "outside-origin.json", raw, 0o600)
	code, output, stderr := runCNCFCLI(t, "prepare", "cncf", "--project", "opencost", "--input", path, "--from", "1.115.0", "--to", "1.121.2", "--format", "input")
	if code != ExitOK || stderr != "" || !json.Valid([]byte(output)) {
		t.Fatalf("outside-origin preparation code=%d stderr=%q output=%q", code, stderr, output)
	}
	prepared := writeCNCFFile(t, "outside-origin-prepared.json", []byte(output), 0o600)
	code, report, stderr := runCNCFCLI(t, "check", "cncf", "--project", "opencost", "--input", prepared, "--now", "2026-09-12T10:00:00Z", "--format", "json")
	if code != ExitUnknown || stderr != "" || !strings.Contains(report, `"assessment":"UNKNOWN"`) {
		t.Fatalf("outside-origin check code=%d stderr=%q report=%q", code, stderr, report)
	}
}
