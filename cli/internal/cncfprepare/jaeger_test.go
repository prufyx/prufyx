// SPDX-License-Identifier: AGPL-3.0-only

package cncfprepare

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/cncfcheck"
)

func jaegerBool(value bool) *bool { return &value }

func jaegerDeclaration(t *testing.T, authority string, argv any) []byte {
	t.Helper()
	raw, err := json.Marshal(map[string]any{"authority": authority, "argv": argv})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func jaegerFact(t *testing.T, prepared Prepared, id string) map[string]any {
	t.Helper()
	return preparedFacts(t, prepared)[id]
}

func TestPrepareJaegerSingletonLiteralFeedsOnlyExistingScopedRule(t *testing.T) {
	const canary = "private-jaeger-config-canary-7e8d"
	raw := jaegerDeclaration(t, jaegerDirectInvocationAuthority, []any{"--config=/etc/jaeger/" + canary + ".yaml"})
	prepared, err := PrepareJaeger(raw, JaegerFrom, JaegerTo, jaegerBool(true), jaegerBool(true))
	if err != nil || prepared.State != StatePrepared || prepared.Reason != ReasonJaegerConfigWitness || bytes.Contains(prepared.CanonicalInputJSON, []byte(canary)) {
		t.Fatalf("prepared=%+v err=%v", prepared, err)
	}
	fact := jaegerFact(t, prepared, JaegerExplicitConfigFact)
	if fact["state"] != "declared" || fact["boolValue"] != true {
		t.Fatalf("config fact=%v", fact)
	}
	for _, id := range []string{JaegerNonMemoryStorageFact, JaegerOfficialDistributionFact} {
		if fact := jaegerFact(t, prepared, id); fact["state"] != "declared" || fact["boolValue"] != true {
			t.Fatalf("manual fact %s=%v", id, fact)
		}
	}
	report, err := cncfcheck.Check("jaeger", prepared.CanonicalInputJSON, time.Date(2026, 9, 10, 0, 0, 0, 0, time.UTC))
	if err != nil || report.Check.Claims[0].Status != "PASS" || report.Assessment != "UNKNOWN" {
		t.Fatalf("report=%+v err=%v", report, err)
	}
}

func TestPrepareJaegerSingletonBoundariesStayUnknown(t *testing.T) {
	const canary = "private-jaeger-boundary-canary-1a73"
	cases := []struct {
		name      string
		authority string
		argv      any
		from, to  string
		reason    Reason
	}{
		{"missing authority", "", []any{"--config=/" + canary}, JaegerFrom, JaegerTo, ReasonJaegerArgumentsUnknown},
		{"zero args", jaegerDirectInvocationAuthority, []any{}, JaegerFrom, JaegerTo, ReasonJaegerArgumentsUnknown},
		{"multiple args", jaegerDirectInvocationAuthority, []any{"--config=/one", "--config=/two"}, JaegerFrom, JaegerTo, ReasonJaegerArgumentsUnknown},
		{"split flag", jaegerDirectInvocationAuthority, []any{"--config", "/" + canary}, JaegerFrom, JaegerTo, ReasonJaegerArgumentsUnknown},
		{"empty value", jaegerDirectInvocationAuthority, []any{"--config="}, JaegerFrom, JaegerTo, ReasonJaegerArgumentsUnknown},
		{"delimiter", jaegerDirectInvocationAuthority, []any{"--"}, JaegerFrom, JaegerTo, ReasonJaegerArgumentsUnknown},
		{"executable", jaegerDirectInvocationAuthority, []any{"jaeger"}, JaegerFrom, JaegerTo, ReasonJaegerArgumentsUnknown},
		{"wrapper", jaegerDirectInvocationAuthority, []any{"/bin/sh -c --config=/" + canary}, JaegerFrom, JaegerTo, ReasonJaegerArgumentsUnknown},
		{"expansion", jaegerDirectInvocationAuthority, []any{"--config=$CONFIG"}, JaegerFrom, JaegerTo, ReasonJaegerArgumentsUnknown},
		{"provider", jaegerDirectInvocationAuthority, []any{"--config=env:CONFIG"}, JaegerFrom, JaegerTo, ReasonJaegerArgumentsUnknown},
		{"remote", jaegerDirectInvocationAuthority, []any{"--config=https://example.invalid/" + canary}, JaegerFrom, JaegerTo, ReasonJaegerArgumentsUnknown},
		{"wrong pair", jaegerDirectInvocationAuthority, []any{"--config=/" + canary}, "1.75.0", JaegerTo, ReasonJaegerUnsupportedPair},
		{"non-array argv", jaegerDirectInvocationAuthority, "--config=/" + canary, JaegerFrom, JaegerTo, ReasonJaegerArgumentsUnknown},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			prepared, err := PrepareJaeger(jaegerDeclaration(t, tc.authority, tc.argv), tc.from, tc.to, jaegerBool(true), jaegerBool(true))
			if err != nil || prepared.State != StateUnknown || prepared.Reason != tc.reason || bytes.Contains(prepared.CanonicalInputJSON, []byte(canary)) {
				t.Fatalf("prepared=%+v err=%v", prepared, err)
			}
			if fact := jaegerFact(t, prepared, JaegerExplicitConfigFact); fact["state"] == "declared" {
				t.Fatalf("unexpected decisive config fact=%v", fact)
			}
			report, err := cncfcheck.Check("jaeger", prepared.CanonicalInputJSON, time.Date(2026, 9, 10, 0, 0, 0, 0, time.UTC))
			if err != nil || report.Check.Claims[0].Status != "UNKNOWN" || report.Assessment != "UNKNOWN" {
				t.Fatalf("report=%+v err=%v", report, err)
			}
		})
	}
}

func TestPrepareJaegerLeavesManualGuardsOperatorBound(t *testing.T) {
	raw := jaegerDeclaration(t, jaegerDirectInvocationAuthority, []any{"--config=config.yaml"})
	for _, tc := range []struct {
		name                string
		nonMemory, official *bool
		status              string
	}{
		{"both guards true", jaegerBool(true), jaegerBool(true), "PASS"},
		{"missing storage guard", nil, jaegerBool(true), "UNKNOWN"},
		{"missing official guard", jaegerBool(true), nil, "UNKNOWN"},
		{"false storage guard", jaegerBool(false), jaegerBool(true), "UNKNOWN"},
		{"false official guard", jaegerBool(true), jaegerBool(false), "UNKNOWN"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			prepared, err := PrepareJaeger(raw, JaegerFrom, JaegerTo, tc.nonMemory, tc.official)
			if err != nil || prepared.State != StatePrepared || prepared.Reason != ReasonJaegerConfigWitness {
				t.Fatalf("prepared=%+v err=%v", prepared, err)
			}
			report, err := cncfcheck.Check("jaeger", prepared.CanonicalInputJSON, time.Date(2026, 9, 10, 0, 0, 0, 0, time.UTC))
			if err != nil || report.Check.Claims[0].Status != tc.status || report.Assessment != "UNKNOWN" {
				t.Fatalf("report=%+v err=%v", report, err)
			}
		})
	}
}

func TestPrepareJaegerLatestPairsRemainTargetScoped(t *testing.T) {
	for _, from := range []string{"2.15.1", "2.16.0", "2.17.0", "2.18.0", "2.19.0"} {
		t.Run(from, func(t *testing.T) {
			prepared, err := PrepareJaeger(jaegerDeclaration(t, jaegerDirectInvocationAuthority, []any{"--config=/etc/jaeger/config.yaml"}), from, JaegerTo, jaegerBool(true), jaegerBool(true))
			if err != nil || prepared.State != StatePrepared || prepared.Reason != ReasonJaegerConfigWitness {
				t.Fatalf("prepared=%+v err=%v", prepared, err)
			}
			report, err := cncfcheck.Check("jaeger", prepared.CanonicalInputJSON, time.Date(2026, 9, 12, 8, 39, 0, 0, time.UTC))
			if err != nil || len(report.Check.Claims) != 1 || report.Check.Claims[0].Status != "PASS" || report.Assessment != "UNKNOWN" {
				t.Fatalf("report=%+v err=%v", report, err)
			}
		})
	}
	wrong, err := PrepareJaeger(jaegerDeclaration(t, jaegerDirectInvocationAuthority, []any{"--config=/etc/jaeger/config.yaml"}), "2.14.0", JaegerTo, jaegerBool(true), jaegerBool(true))
	if err != nil || wrong.State != StateUnknown || wrong.Reason != ReasonJaegerUnsupportedPair {
		t.Fatalf("wrong pair=%+v err=%v", wrong, err)
	}
}
