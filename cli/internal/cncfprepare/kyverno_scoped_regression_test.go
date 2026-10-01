// SPDX-License-Identifier: AGPL-3.0-only

package cncfprepare

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

func testSHA256(raw []byte) string {
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// These regression cases retain pre-scope strict-input boundaries while using
// only the admitted official_upstream/bare reports-controller scope.
func TestKyvernoScopedRegressionBindsExactBytesAndOneNewline(t *testing.T) {
	raw := []byte(`{"apiVersion":"v1","kind":"Pod","metadata":{"name":"private-workload-canary"},"spec":{"containers":[{"name":"selected","image":"private.example/secret-image","command":["reports-controller"]}]}}`)
	prepared, err := PrepareKyvernoScoped(raw, "selected", FromVersion, ToVersion, KyvernoDistributionOfficial)
	if err != nil {
		t.Fatal(err)
	}
	if prepared.State != StatePrepared || prepared.Reason != ReasonDirectCommandParsed {
		t.Fatalf("state=%q reason=%q", prepared.State, prepared.Reason)
	}
	if prepared.SourceDigest != testSHA256(raw) || prepared.InputDigest != testSHA256(prepared.CanonicalInputJSON) {
		t.Fatal("source or prepared-input digest did not bind exact bytes")
	}
	if !bytes.HasSuffix(prepared.CanonicalInputJSON, []byte{'\n'}) || bytes.HasSuffix(bytes.TrimSuffix(prepared.CanonicalInputJSON, []byte{'\n'}), []byte{'\n'}) {
		t.Fatal("canonical input does not have exactly one trailing newline")
	}
	for _, forbidden := range []string{"private-workload-canary", "private.example", "secret-image", "selected"} {
		if strings.Contains(string(prepared.CanonicalInputJSON), forbidden) {
			t.Fatal("private workload field leaked into minimized declaration")
		}
	}
	facts := preparedFacts(t, prepared)
	if facts[KyvernoDistributionFact]["enumValue"] != KyvernoDistributionOfficial || facts[KyvernoExecutionSurfaceFact]["enumValue"] != KyvernoSurfaceReportsController || facts[KyvernoFact]["boolValue"] != false {
		t.Fatalf("unexpected scoped absence facts: %v", facts)
	}
}

func TestKyvernoScopedRegressionRejectsPrivateUnknownFieldsWithoutEcho(t *testing.T) {
	raw := []byte(`{"apiVersion":"v1","kind":"Pod","x-private-secret-canary":"redacted","spec":{"containers":[{"name":"selected","command":["reports-controller"]}]}}`)
	_, err := PrepareKyvernoScoped(raw, "selected", FromVersion, ToVersion, KyvernoDistributionOfficial)
	if err == nil || strings.Contains(err.Error(), "x-private-secret-canary") || strings.Contains(err.Error(), "redacted") {
		t.Fatalf("unknown private field was accepted or echoed: %v", err)
	}
}

func TestKyvernoScopedRegressionRejectsUnknownDeploymentAndSecondaryContainerShapes(t *testing.T) {
	invalid := []string{
		`{"apiVersion":"apps/v1","kind":"Deployment","metadata":{"name":"d"},"spec":{"futurePrivateWrapper":{"token":"redacted"},"template":{"spec":{"containers":[{"name":"selected","command":["reports-controller"]}]}}}}`,
		`{"apiVersion":"v1","kind":"Pod","spec":{"containers":[{"name":"selected","command":["reports-controller"]}],"initContainers":{}}}`,
		`{"apiVersion":"v1","kind":"Pod","spec":{"containers":[{"name":"selected","command":["reports-controller"]}],"ephemeralContainers":[{"command":["/bin/sh"]}]}}`,
	}
	for index, raw := range invalid {
		if _, err := PrepareKyvernoScoped([]byte(raw), "selected", FromVersion, ToVersion, KyvernoDistributionOfficial); err == nil {
			t.Fatalf("malformed scoped workload %d was accepted", index)
		}
	}
}

func TestKyvernoScopedRegressionDuplicateAndSecondarySelectionRemainUnknown(t *testing.T) {
	cases := []struct {
		name string
		raw  string
	}{
		{"duplicate regular", `{"apiVersion":"v1","kind":"Pod","spec":{"containers":[{"name":"selected","command":["reports-controller"]},{"name":"selected","command":["reports-controller"]}]}}`},
		{"regular init collision", `{"apiVersion":"v1","kind":"Pod","spec":{"containers":[{"name":"selected","command":["reports-controller"]}],"initContainers":[{"name":"selected","command":["/bin/sh"]}]}}`},
		{"regular ephemeral collision", `{"apiVersion":"v1","kind":"Pod","spec":{"containers":[{"name":"selected","command":["reports-controller"]}],"ephemeralContainers":[{"name":"selected","command":["/bin/sh"]}]}}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			prepared, err := PrepareKyvernoScoped([]byte(tc.raw), "selected", FromVersion, ToVersion, KyvernoDistributionOfficial)
			if err != nil {
				t.Fatal(err)
			}
			if prepared.State != StateUnknown || prepared.Reason != ReasonSelectedContainerAmbiguous || bytes.Contains(prepared.CanonicalInputJSON, []byte(`"boolValue"`)) {
				t.Fatalf("selection became decidable: state=%q reason=%q input=%s", prepared.State, prepared.Reason, prepared.CanonicalInputJSON)
			}
		})
	}
}

func TestKyvernoScopedRegressionStrictCaseAliasAndNullJSON(t *testing.T) {
	invalid := []string{
		`{"apiVersion":"v1","ApiVersion":"v1","kind":"Pod","spec":{"containers":[]}}`,
		`{"apiVersion":"v1","kind":"Pod","spec":null}`,
		`{"apiVersion":"v1","kind":"Pod","spec":{"containers":[{"name":"selected","command":null}]}}`,
	}
	for index, raw := range invalid {
		if _, err := PrepareKyvernoScoped([]byte(raw), "selected", FromVersion, ToVersion, KyvernoDistributionOfficial); err == nil {
			t.Fatalf("strict JSON malformed case %d was accepted", index)
		}
	}
}

func TestKyvernoScopedRegressionSeparateExpandedAndEmptyValuesRemainUnknown(t *testing.T) {
	for _, value := range []string{"$SIZE", ""} {
		raw := kyvernoWorkload(t, []string{"reports-controller"}, []string{"--reportsChunkSize", value}, "private.example/ignored")
		prepared, err := PrepareKyvernoScoped(raw, "selected", FromVersion, ToVersion, KyvernoDistributionOfficial)
		if err != nil {
			t.Fatal(err)
		}
		if prepared.State != StateUnknown || prepared.Reason != ReasonUnsupportedArguments || bytes.Contains(prepared.CanonicalInputJSON, []byte(`"boolValue"`)) {
			t.Fatalf("separate value %q became decidable: state=%q reason=%q", value, prepared.State, prepared.Reason)
		}
	}
}

func TestKyvernoScopedRegressionUnsupportedEndpointRemainsDeclaredUnknown(t *testing.T) {
	raw := kyvernoWorkload(t, []string{"reports-controller"}, nil, "private.example/ignored")
	prepared, err := PrepareKyvernoScoped(raw, "selected", "1.12.4", ToVersion, KyvernoDistributionOfficial)
	if err != nil {
		t.Fatal(err)
	}
	if prepared.State != StateUnknown || prepared.Reason != ReasonUnsupportedVersionPair || bytes.Contains(prepared.CanonicalInputJSON, []byte(`"boolValue"`)) || !bytes.Contains(prepared.CanonicalInputJSON, []byte(`"version":"1.12.4"`)) {
		t.Fatalf("unsupported endpoint became decidable or lost identity: state=%q reason=%q input=%s", prepared.State, prepared.Reason, prepared.CanonicalInputJSON)
	}
	facts := preparedFacts(t, prepared)
	if facts[KyvernoDistributionFact]["enumValue"] != KyvernoDistributionOfficial || facts[KyvernoExecutionSurfaceFact]["state"] != "unsupported" || facts[KyvernoFact]["state"] != "unsupported" {
		t.Fatalf("unsupported endpoint facts=%v", facts)
	}
}
