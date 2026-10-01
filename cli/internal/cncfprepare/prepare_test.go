// SPDX-License-Identifier: AGPL-3.0-only

package cncfprepare

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/cncfcheck"
)

func kyvernoWorkload(t *testing.T, command, args []string, image string) []byte {
	t.Helper()
	container := map[string]any{"name": "selected", "image": image}
	if command != nil {
		container["command"] = command
	}
	if args != nil {
		container["args"] = args
	}
	raw, err := json.Marshal(map[string]any{
		"apiVersion": "v1", "kind": "Pod", "metadata": map[string]any{"name": "private-workload"},
		"spec": map[string]any{"containers": []any{container}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func preparedFacts(t *testing.T, prepared Prepared) map[string]map[string]any {
	t.Helper()
	var input map[string]any
	if err := json.Unmarshal(prepared.CanonicalInputJSON, &input); err != nil {
		t.Fatal(err)
	}
	facts := input["proposed"].(map[string]any)["components"].([]any)[0].(map[string]any)["facts"].([]any)
	result := make(map[string]map[string]any, len(facts))
	for _, raw := range facts {
		fact := raw.(map[string]any)
		result[fact["id"].(string)] = fact
	}
	return result
}

func TestPrepareKyvernoLegacySignatureIsAlwaysScopeUnknown(t *testing.T) {
	raw := kyvernoWorkload(t, []string{"reports-controller"}, nil, "private.example/secret")
	prepared, err := PrepareKyverno(raw, "selected", FromVersion, ToVersion)
	if err != nil {
		t.Fatal(err)
	}
	if prepared.State != StateUnknown || prepared.Reason != ReasonDistributionMissing {
		t.Fatalf("legacy state=%q reason=%q", prepared.State, prepared.Reason)
	}
	facts := preparedFacts(t, prepared)
	if facts[KyvernoDistributionFact]["state"] != "missing" || facts[KyvernoExecutionSurfaceFact]["state"] != "unsupported" || facts[KyvernoFact]["state"] != "unsupported" {
		t.Fatalf("legacy facts=%v", facts)
	}
	if strings.Contains(string(prepared.CanonicalInputJSON), "private.example") || strings.Contains(string(prepared.CanonicalInputJSON), "selected") {
		t.Fatal("private workload fields leaked into minimized declaration")
	}
}

func TestPrepareKyvernoScopedFeedsScopedRule(t *testing.T) {
	cases := []struct {
		name          string
		command, args []string
		wantStatus    string
		wantValue     bool
	}{
		{"zero args absence", []string{"reports-controller"}, nil, "PASS", false},
		{"one dash attached", []string{"reports-controller", "-reportsChunkSize=1"}, nil, "BLOCKED", true},
		{"two dash attached", []string{"reports-controller", "--reportsChunkSize=0x10"}, nil, "BLOCKED", true},
		{"one dash following", []string{"reports-controller", "-reportsChunkSize", "-1"}, nil, "BLOCKED", true},
		{"two dash following repeated", []string{"reports-controller"}, []string{"--reportsChunkSize", "1", "-reportsChunkSize=2"}, "BLOCKED", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			raw := kyvernoWorkload(t, tc.command, tc.args, "private.example/secret")
			prepared, err := PrepareKyvernoScoped(raw, "selected", FromVersion, ToVersion, KyvernoDistributionOfficial)
			if err != nil {
				t.Fatal(err)
			}
			if prepared.State != StatePrepared || prepared.Reason != ReasonDirectCommandParsed || !bytes.HasSuffix(prepared.CanonicalInputJSON, []byte{'\n'}) {
				t.Fatalf("state=%q reason=%q input=%s", prepared.State, prepared.Reason, prepared.CanonicalInputJSON)
			}
			facts := preparedFacts(t, prepared)
			if facts[KyvernoDistributionFact]["enumValue"] != KyvernoDistributionOfficial || facts[KyvernoExecutionSurfaceFact]["enumValue"] != KyvernoSurfaceReportsController || facts[KyvernoFact]["boolValue"] != tc.wantValue {
				t.Fatalf("facts=%v", facts)
			}
			report, err := cncfcheck.Check("kyverno", prepared.CanonicalInputJSON, time.Date(2026, 9, 9, 1, 0, 0, 0, time.UTC))
			if err != nil || len(report.Check.Claims) != 1 || report.Check.Claims[0].Status != tc.wantStatus || report.Assessment != "UNKNOWN" {
				t.Fatalf("report=%+v err=%v", report, err)
			}
		})
	}
}

func TestPrepareKyvernoScopedDeterministicIntegerBounds(t *testing.T) {
	cases := []struct {
		value string
		valid bool
	}{
		{"2147483647", true}, {"-2147483648", true}, {"2147483648", false}, {"-2147483649", false},
		{"0x7fffffff", true}, {"-0x80000000", true}, {"0x80000000", false}, {"-0x80000001", false},
		{"017777777777", true}, {"-020000000000", true}, {"020000000000", false}, {"-020000000001", false},
	}
	forms := []struct {
		name string
		args func(string) []string
	}{
		{"one dash attached", func(v string) []string { return []string{"-reportsChunkSize=" + v} }},
		{"two dash attached", func(v string) []string { return []string{"--reportsChunkSize=" + v} }},
		{"one dash following", func(v string) []string { return []string{"-reportsChunkSize", v} }},
		{"two dash following", func(v string) []string { return []string{"--reportsChunkSize", v} }},
	}
	for _, tc := range cases {
		for _, form := range forms {
			t.Run(tc.value+"/"+form.name, func(t *testing.T) {
				raw := kyvernoWorkload(t, []string{"reports-controller"}, form.args(tc.value), "private.example/secret")
				prepared, err := PrepareKyvernoScoped(raw, "selected", FromVersion, ToVersion, KyvernoDistributionOfficial)
				if err != nil {
					t.Fatal(err)
				}
				if tc.valid && prepared.State != StatePrepared {
					t.Fatalf("valid %q became %s/%s", tc.value, prepared.State, prepared.Reason)
				}
				if !tc.valid && (prepared.State != StateUnknown || strings.Contains(string(prepared.CanonicalInputJSON), `"boolValue"`)) {
					t.Fatalf("invalid %q became %s/%s %s", tc.value, prepared.State, prepared.Reason, prepared.CanonicalInputJSON)
				}
			})
		}
	}
}

func TestPrepareKyvernoScopedUnknownBoundariesNeverDeclareFalse(t *testing.T) {
	cases := []struct {
		name, distribution string
		command, args      []string
		reason             Reason
	}{
		{"omitted distribution", "", []string{"reports-controller"}, nil, ReasonDistributionMissing},
		{"custom distribution", KyvernoDistributionCustom, []string{"reports-controller"}, nil, ReasonCustomDistribution},
		{"implicit entrypoint", KyvernoDistributionOfficial, nil, nil, ReasonImplicitEntrypoint},
		{"kyverno executable", KyvernoDistributionOfficial, []string{"kyverno"}, nil, ReasonUnsupportedCommand},
		{"absolute reports executable unproved", KyvernoDistributionOfficial, []string{"/reports-controller"}, nil, ReasonUnsupportedCommand},
		{"shell wrapper", KyvernoDistributionOfficial, []string{"/bin/sh", "-c", "reports-controller --reportsChunkSize=1"}, nil, ReasonUnsupportedCommand},
		{"unrelated option", KyvernoDistributionOfficial, []string{"reports-controller"}, []string{"--name=literal"}, ReasonUnsupportedArguments},
		{"positional", KyvernoDistributionOfficial, []string{"reports-controller"}, []string{"literal"}, ReasonUnsupportedArguments},
		{"delimiter", KyvernoDistributionOfficial, []string{"reports-controller"}, []string{"--", "--reportsChunkSize=1"}, ReasonFlagAfterDelimiter},
		{"noninteger", KyvernoDistributionOfficial, []string{"reports-controller"}, []string{"--reportsChunkSize=false"}, ReasonUnsupportedArguments},
		{"near prefix", KyvernoDistributionOfficial, []string{"reports-controller"}, []string{"--reportsChunkSizeExtra=1"}, ReasonUnsupportedArguments},
		{"expansion", KyvernoDistributionOfficial, []string{"reports-controller"}, []string{"--reportsChunkSize=$SIZE"}, ReasonUnsupportedArguments},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			raw := kyvernoWorkload(t, tc.command, tc.args, "private.example/secret")
			prepared, err := PrepareKyvernoScoped(raw, "selected", FromVersion, ToVersion, tc.distribution)
			if err != nil {
				t.Fatal(err)
			}
			if prepared.State != StateUnknown || prepared.Reason != tc.reason || strings.Contains(string(prepared.CanonicalInputJSON), `"boolValue"`) {
				t.Fatalf("state=%q reason=%q input=%s", prepared.State, prepared.Reason, prepared.CanonicalInputJSON)
			}
		})
	}
}

func TestPrepareKyvernoScopedSelectionVersionAndStrictInput(t *testing.T) {
	valid := kyvernoWorkload(t, []string{"reports-controller"}, nil, "private.example/secret")
	if _, err := PrepareKyvernoScoped(valid, "selected", "v1.12.5", ToVersion, KyvernoDistributionOfficial); err == nil {
		t.Fatal("invalid version syntax accepted")
	}
	for _, raw := range []string{
		`{"apiVersion":"v1","apiVersion":"v1","kind":"Pod","spec":{"containers":[]}}`,
		`{"apiVersion":"v1","kind":"Pod","unknown":true,"spec":{"containers":[]}}`,
		`{"apiVersion":"v1","kind":"Pod","spec":{"containers":[{"name":"selected","command":["reports-controller"],"args":[1]}]}}`,
	} {
		if _, err := PrepareKyvernoScoped([]byte(raw), "selected", FromVersion, ToVersion, KyvernoDistributionOfficial); err == nil {
			t.Fatal("invalid private input accepted")
		}
	}
	for _, tc := range []struct {
		name, container, from, to string
		reason                    Reason
	}{
		{"missing container", "missing", FromVersion, ToVersion, ReasonSelectedContainerMissing},
		{"outside pair", "selected", "1.12.4", ToVersion, ReasonUnsupportedVersionPair},
	} {
		t.Run(tc.name, func(t *testing.T) {
			prepared, err := PrepareKyvernoScoped(valid, tc.container, tc.from, tc.to, KyvernoDistributionOfficial)
			if err != nil || prepared.State != StateUnknown || prepared.Reason != tc.reason {
				t.Fatalf("prepared=%+v err=%v", prepared, err)
			}
		})
	}
	if _, err := PrepareKyvernoScoped(valid, "selected", FromVersion, ToVersion, "private-value"); err == nil || strings.Contains(err.Error(), "private-value") {
		t.Fatal("invalid distribution was accepted or echoed")
	}
}
