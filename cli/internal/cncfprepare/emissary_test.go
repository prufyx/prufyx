// SPDX-License-Identifier: AGPL-3.0-only

package cncfprepare

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/cncfcheck"
)

func emissaryDeclaration(argv ...string) []byte {
	raw, _ := json.Marshal(argv)
	return raw
}

func TestPrepareEmissaryRemovedMetricsEndpoint(t *testing.T) {
	legacy := emissaryDeclaration("diagd", "--metrics-endpoint", "https://example.invalid/metrics")
	prepared, err := PrepareEmissary(legacy, EmissaryFrom, EmissaryTo)
	if err != nil || prepared.State != StatePrepared || prepared.Reason != ReasonEmissaryMetricsPresent || !bytes.Contains(prepared.CanonicalInputJSON, []byte(`"boolValue":true`)) {
		t.Fatalf("legacy=%+v err=%v", prepared, err)
	}
	fixed := emissaryDeclaration("diagd")
	prepared, err = PrepareEmissary(fixed, EmissaryFrom, EmissaryTo)
	if err != nil || prepared.State != StatePrepared || prepared.Reason != ReasonEmissaryMetricsAbsent || !bytes.Contains(prepared.CanonicalInputJSON, []byte(`"boolValue":false`)) {
		t.Fatalf("fixed=%+v err=%v", prepared, err)
	}
	report, err := cncfcheck.Check("emissary-ingress", prepared.CanonicalInputJSON, time.Date(2026, 9, 11, 0, 0, 0, 0, time.UTC))
	if err != nil || report.Assessment != "UNKNOWN" || report.Check.Claims[0].Status != "PASS" {
		t.Fatalf("report=%+v err=%v", report, err)
	}
}

func TestPrepareEmissaryBoundaries(t *testing.T) {
	for name, raw := range map[string][]byte{
		"wrong executable":                    emissaryDeclaration("other"),
		"unknown option":                      emissaryDeclaration("diagd", "--unsupported", "8004"),
		"missing split value":                 emissaryDeclaration("diagd", "--metrics-endpoint"),
		"empty equals value is present":       emissaryDeclaration("diagd", "--metrics-endpoint="),
		"wrapped command":                     emissaryDeclaration("/bin/sh", "-c", "diagd --metrics-endpoint x"),
		"opaque tail":                         emissaryDeclaration("diagd", "--", "--metrics-endpoint", "x"),
		"positional before flag":              emissaryDeclaration("diagd", "/snapshots.json", "--metrics-endpoint", "x"),
		"option value equals flag":            emissaryDeclaration("diagd", "--kick=--metrics-endpoint"),
		"string value consumes flag spelling": emissaryDeclaration("diagd", "--kick", "--metrics-endpoint"),
		"invalid integer value":               emissaryDeclaration("diagd", "--port=bogus"),
		"negative integer value":              emissaryDeclaration("diagd", "--port", "-1"),
		"wrong pair":                          emissaryDeclaration("diagd", "--metrics-endpoint", "x"),
	} {
		t.Run(name, func(t *testing.T) {
			from, to := EmissaryFrom, EmissaryTo
			if name == "wrong pair" {
				from = "3.9.0"
			}
			prepared, err := PrepareEmissary(raw, from, to)
			wantState := StateUnknown
			if name == "opaque tail" || name == "option value equals flag" || name == "string value consumes flag spelling" || name == "positional before flag" || name == "empty equals value is present" || name == "negative integer value" {
				wantState = StatePrepared
			}
			if err != nil || prepared.State != wantState || bytes.Contains(prepared.CanonicalInputJSON, []byte("metrics-endpoint")) {
				t.Fatalf("prepared=%+v err=%v", prepared, err)
			}
			if name == "positional before flag" && !bytes.Contains(prepared.CanonicalInputJSON, []byte(`"boolValue":true`)) {
				t.Fatal("metrics option after positional was not observed")
			}
			if name == "empty equals value is present" && !bytes.Contains(prepared.CanonicalInputJSON, []byte(`"boolValue":true`)) {
				t.Fatal("empty equals metrics option was not observed")
			}
		})
	}
}
