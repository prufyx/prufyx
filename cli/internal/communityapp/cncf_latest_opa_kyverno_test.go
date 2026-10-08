// SPDX-License-Identifier: AGPL-3.0-only

package communityapp

import (
	"encoding/json"
	"strings"
	"testing"
)

func latestOPAInput(t *testing.T, from, to, producerState string, producerValue *bool) []byte {
	t.Helper()
	facts := []any{
		map[string]any{"id": "component.opa.modules_use_rego_v1_import", "state": "declared", "boolValue": false},
	}
	producer := map[string]any{"id": "component.opa.producer_v0_compatible", "state": producerState}
	if producerValue != nil {
		producer["boolValue"] = *producerValue
	}
	facts = append(facts, producer)
	facts = append(facts, map[string]any{"id": "component.opa.v0_consumers_remain", "state": "declared", "boolValue": true})
	document := map[string]any{
		"schema":    "prufyx.io/operator-declared-constraint-input/v1alpha1",
		"authority": "OPERATOR_DECLARED_MINIMIZED",
		"current":   map[string]any{"components": []any{map[string]any{"component": "pkg:github/open-policy-agent/opa", "version": from, "facts": []any{}}}},
		"proposed":  map[string]any{"components": []any{map[string]any{"component": "pkg:github/open-policy-agent/opa", "version": to, "facts": facts}}},
	}
	raw, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestLatestOPAExactOriginsGenericCLI(t *testing.T) {
	t.Parallel()
	truth, falsity := true, false
	for _, from := range []string{"1.15.2", "1.16.2", "1.17.1", "1.18.2", "1.19.1"} {
		for _, tc := range []struct {
			name, to, state, status string
			value                   *bool
			code                    int
		}{
			{"blocked", "1.20.2", "declared", "BLOCKED", &falsity, ExitBlocked},
			{"pass", "1.20.2", "declared", "PASS", &truth, ExitOK},
			{"missing", "1.20.2", "missing", "UNKNOWN", nil, ExitUnknown},
			{"conflict", "1.20.2", "conflict", "UNKNOWN", nil, ExitUnknown},
			{"wrong-target", "1.20.3", "declared", "UNKNOWN", &falsity, ExitUnknown},
		} {
			t.Run(from+"/"+tc.name, func(t *testing.T) {
				raw := latestOPAInput(t, from, tc.to, tc.state, tc.value)
				path := writeCNCFFile(t, "opa-input.json", raw, 0o600)
				code, output, stderr := runCNCFCLI(t, "check", "cncf", "--project", "opa", "--input", path, "--input-digest", cncfDigest(raw), "--now", "2026-09-12T09:34:00Z", "--format", "json")
				if code != tc.code || stderr != "" || !strings.Contains(output, `"assessment":"UNKNOWN"`) || (tc.status != "UNKNOWN" && !strings.Contains(output, `"status":"`+tc.status+`"`)) {
					t.Fatalf("code=%d stderr=%q output=%s", code, stderr, output)
				}
			})
		}
	}
}

func TestLatestKyvernoExactOriginsNativeCLI(t *testing.T) {
	t.Parallel()
	for _, from := range []string{"1.14.5", "1.15.3", "1.16.4", "1.17.2", "1.18.2"} {
		for _, tc := range []struct {
			name, to, distribution, status string
			command, args                  []string
			prepareCode, checkCode         int
		}{
			{"blocked", "1.19.1", "official_upstream", "BLOCKED", []string{"reports-controller"}, []string{"--reportsChunkSize=16"}, ExitOK, ExitBlocked},
			{"pass", "1.19.1", "official_upstream", "PASS", []string{"reports-controller"}, nil, ExitOK, ExitOK},
			{"missing-distribution", "1.19.1", "", "UNKNOWN", []string{"reports-controller"}, nil, ExitUnknown, ExitUnknown},
			{"custom", "1.19.1", "custom_build", "UNKNOWN", []string{"reports-controller"}, nil, ExitUnknown, ExitUnknown},
			{"wrapper", "1.19.1", "official_upstream", "UNKNOWN", []string{"/bin/sh", "-c"}, []string{"reports-controller --reportsChunkSize=16"}, ExitUnknown, ExitUnknown},
			{"wrong-target", "1.19.2", "official_upstream", "UNKNOWN", []string{"reports-controller"}, []string{"--reportsChunkSize=16"}, ExitUnknown, ExitUnknown},
		} {
			t.Run(from+"/"+tc.name, func(t *testing.T) {
				raw := kyvernoProposal(t, tc.command, tc.args, "private-latest-kyverno")
				path := writeCNCFFile(t, "kyverno-workload.json", raw, 0o600)
				prepare := []string{"prepare", "cncf", "--project", "kyverno", "--input", path, "--container", "selected", "--from", from, "--to", tc.to, "--format", "input"}
				if tc.distribution != "" {
					prepare = append(prepare, "--distribution", tc.distribution)
				}
				prepareCode, prepared, prepareErr := runCNCFCLI(t, prepare...)
				if prepareCode != tc.prepareCode || prepareErr != "" || !json.Valid([]byte(prepared)) || strings.Contains(prepared, "private-latest-kyverno") {
					t.Fatalf("prepare code=%d stderr=%q output=%s", prepareCode, prepareErr, prepared)
				}
				preparedRaw := []byte(prepared)
				preparedPath := writeCNCFFile(t, "kyverno-prepared.json", preparedRaw, 0o600)
				checkCode, output, checkErr := runCNCFCLI(t, "check", "cncf", "--project", "kyverno", "--input", preparedPath, "--input-digest", cncfDigest(preparedRaw), "--now", "2026-09-12T09:34:00Z", "--format", "json")
				if checkCode != tc.checkCode || checkErr != "" || !strings.Contains(output, `"assessment":"UNKNOWN"`) || (tc.status != "UNKNOWN" && !strings.Contains(output, `"status":"`+tc.status+`"`)) || strings.Contains(output, "private-latest-kyverno") {
					t.Fatalf("check code=%d stderr=%q output=%s", checkCode, checkErr, output)
				}
			})
		}
	}
}

func TestKyvernoMisleading11520TagIsNotAdmitted(t *testing.T) {
	t.Parallel()
	raw := kyvernoProposal(t, []string{"reports-controller"}, []string{"--reportsChunkSize=16"}, "private-rejected-kyverno-tag")
	path := writeCNCFFile(t, "kyverno-rejected-origin.json", raw, 0o600)
	prepareCode, prepared, prepareErr := runCNCFCLI(t, "prepare", "cncf", "--project", "kyverno", "--input", path, "--container", "selected", "--from", "1.15.20", "--to", "1.19.1", "--distribution", "official_upstream", "--format", "input")
	if prepareCode != ExitUnknown || prepareErr != "" || !json.Valid([]byte(prepared)) || !strings.Contains(prepared, `"state":"unsupported"`) || strings.Contains(prepared, "private-rejected-kyverno-tag") {
		t.Fatalf("prepare code=%d stderr=%q output=%s", prepareCode, prepareErr, prepared)
	}
	preparedRaw := []byte(prepared)
	preparedPath := writeCNCFFile(t, "kyverno-rejected-prepared.json", preparedRaw, 0o600)
	checkCode, output, checkErr := runCNCFCLI(t, "check", "cncf", "--project", "kyverno", "--input", preparedPath, "--input-digest", cncfDigest(preparedRaw), "--now", "2026-09-12T09:34:00Z", "--format", "json")
	if checkCode != ExitUnknown || checkErr != "" || !strings.Contains(output, `"assessment":"UNKNOWN"`) || strings.Contains(output, "from-1-15-20") {
		t.Fatalf("check code=%d stderr=%q output=%s", checkCode, checkErr, output)
	}
}
