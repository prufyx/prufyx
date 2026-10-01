// SPDX-License-Identifier: AGPL-3.0-only

package cncfprepare

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/cncfcheck"
)

func linkerdResource(t *testing.T, spec map[string]any, metadata any) []byte {
	t.Helper()
	resource := map[string]any{"apiVersion": "policy.linkerd.io/v1alpha1", "kind": "MeshTLSAuthentication", "spec": spec}
	if metadata != nil {
		resource["metadata"] = metadata
	}
	raw, err := json.Marshal(resource)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func linkerdSpec(selector string, value any) map[string]any {
	if selector == "" {
		return map[string]any{}
	}
	return map[string]any{selector: value}
}

func TestPrepareLinkerdSelectorsAndCheckOutcomes(t *testing.T) {
	tests := []struct {
		name       string
		spec       map[string]any
		wantState  State
		wantReason Reason
		wantFact   any
		wantCheck  string
	}{
		{"identities empty", linkerdSpec("identities", []any{}), StatePrepared, ReasonLinkerdSelectorDerived, true, "BLOCKED"},
		{"identities nonempty", linkerdSpec("identities", []any{"spiffe://example.org/a"}), StatePrepared, ReasonLinkerdSelectorDerived, false, "PASS"},
		{"identity refs empty", linkerdSpec("identityRefs", []any{}), StatePrepared, ReasonLinkerdSelectorDerived, true, "BLOCKED"},
		{"identity refs nonempty", linkerdSpec("identityRefs", []any{map[string]any{"kind": "ServiceAccount"}}), StatePrepared, ReasonLinkerdSelectorDerived, false, "PASS"},
		{"both selectors", map[string]any{"identities": []any{}, "identityRefs": []any{}}, StateUnknown, ReasonLinkerdSelectorConflict, nil, "UNKNOWN"},
		{"neither selector", map[string]any{}, StateUnknown, ReasonLinkerdSelectorMissing, nil, "UNKNOWN"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			raw := linkerdResource(t, tc.spec, map[string]any{"name": "private-name", "namespace": "private-namespace"})
			prepared, err := PrepareLinkerd(raw, LinkerdFrom, LinkerdTo, LinkerdDistributionOfficial, LinkerdSchemaRequired)
			if err != nil {
				t.Fatal(err)
			}
			if prepared.State != tc.wantState || prepared.Reason != tc.wantReason {
				t.Fatalf("state=%q reason=%q", prepared.State, prepared.Reason)
			}
			var input map[string]any
			if err := json.Unmarshal(prepared.CanonicalInputJSON, &input); err != nil {
				t.Fatal(err)
			}
			facts := input["proposed"].(map[string]any)["components"].([]any)[0].(map[string]any)["facts"].([]any)
			if len(facts) != 4 {
				t.Fatalf("facts=%v", facts)
			}
			selector := facts[2].(map[string]any)
			if selector["id"] != LinkerdFact {
				t.Fatalf("selector fact=%v", selector)
			}
			if tc.wantFact == nil {
				if selector["state"] != "missing" && selector["state"] != "conflict" {
					t.Fatalf("unknown selector fact=%v", selector)
				}
			} else if selector["boolValue"] != tc.wantFact || selector["state"] != "declared" {
				t.Fatalf("selector fact=%v", selector)
			}
			if strings.Contains(string(prepared.CanonicalInputJSON), "private-name") || strings.Contains(string(prepared.CanonicalInputJSON), "private-namespace") || strings.Contains(string(prepared.CanonicalInputJSON), "spiffe://") {
				t.Fatalf("private values escaped: %s", prepared.CanonicalInputJSON)
			}
			if !bytes.Equal(prepared.CanonicalInputJSON, append(bytes.TrimSuffix(prepared.CanonicalInputJSON, []byte{'\n'}), '\n')) || bytes.HasSuffix(prepared.CanonicalInputJSON, []byte("\n\n")) {
				t.Fatalf("canonical newline invalid")
			}
			if got, err := cncfcheck.Check("linkerd", prepared.CanonicalInputJSON, time.Date(2026, 9, 8, 23, 0, 0, 0, time.UTC)); err != nil {
				t.Fatal(err)
			} else if len(got.Check.Claims) != 1 || got.Check.Claims[0].Status != tc.wantCheck {
				t.Fatalf("check=%+v", got.Check.Claims)
			}
		})
	}
}

func TestPrepareLinkerdGuardBoundaries(t *testing.T) {
	raw := linkerdResource(t, linkerdSpec("identities", []any{"a"}), nil)
	tests := []struct {
		name, distribution, schema, wantReason string
		wantState                              State
		wantDistState, wantSchemaState         string
	}{
		{"missing distribution", "", LinkerdSchemaRequired, ReasonLinkerdGuardMissing, StateUnknown, "missing", "declared"},
		{"missing schema intent", LinkerdDistributionOfficial, "", ReasonLinkerdGuardMissing, StateUnknown, "declared", "missing"},
		{"custom distribution", LinkerdDistributionCustom, LinkerdSchemaRequired, ReasonLinkerdSelectorDerived, StatePrepared, "declared", "declared"},
		{"schema disabled", LinkerdDistributionOfficial, LinkerdSchemaDisabled, ReasonLinkerdSelectorDerived, StatePrepared, "declared", "declared"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			prepared, err := PrepareLinkerd(raw, LinkerdFrom, LinkerdTo, tc.distribution, tc.schema)
			if err != nil || prepared.State != tc.wantState || prepared.Reason != tc.wantReason {
				t.Fatalf("prepared=%+v err=%v", prepared, err)
			}
			var input map[string]any
			if err := json.Unmarshal(prepared.CanonicalInputJSON, &input); err != nil {
				t.Fatal(err)
			}
			facts := input["proposed"].(map[string]any)["components"].([]any)[0].(map[string]any)["facts"].([]any)
			if facts[0].(map[string]any)["state"] != tc.wantDistState || facts[3].(map[string]any)["state"] != tc.wantSchemaState {
				t.Fatalf("facts=%v", facts)
			}
			got, err := cncfcheck.Check("linkerd", prepared.CanonicalInputJSON, time.Date(2026, 9, 8, 23, 0, 0, 0, time.UTC))
			if err != nil || len(got.Check.Claims) != 1 || got.Check.Claims[0].Status != "UNKNOWN" {
				t.Fatalf("check=%+v err=%v", got.Check.Claims, err)
			}
		})
	}
}

func TestPrepareLinkerdUnsupportedPairPreservesDeclaredVersionsAndUnknown(t *testing.T) {
	raw := linkerdResource(t, linkerdSpec("identities", []any{}), nil)
	prepared, err := PrepareLinkerd(raw, "2.14.0", "2.15.0", LinkerdDistributionOfficial, LinkerdSchemaRequired)
	if err != nil || prepared.State != StateUnknown || prepared.Reason != ReasonLinkerdUnsupportedVersion {
		t.Fatalf("prepared=%+v err=%v", prepared, err)
	}
	if !bytes.Contains(prepared.CanonicalInputJSON, []byte(`"version":"2.14.0"`)) || !bytes.Contains(prepared.CanonicalInputJSON, []byte(`"version":"2.15.0"`)) || !bytes.Contains(prepared.CanonicalInputJSON, []byte(`"state":"unsupported"`)) {
		t.Fatalf("unsupported pair was not retained conservatively: %s", prepared.CanonicalInputJSON)
	}
}

func TestPrepareLinkerdInvalidShapesHaveNoPreparedOutput(t *testing.T) {
	valid := linkerdResource(t, linkerdSpec("identities", []any{}), nil)
	invalids := map[string][]byte{
		"wrong api version": func() []byte {
			r := map[string]any{"apiVersion": "policy.linkerd.io/v1beta1", "kind": "MeshTLSAuthentication", "spec": map[string]any{}}
			b, _ := json.Marshal(r)
			return b
		}(),
		"wrong kind": func() []byte {
			r := map[string]any{"apiVersion": linkerdAPIVersion, "kind": "AuthorizationPolicy", "spec": map[string]any{}}
			b, _ := json.Marshal(r)
			return b
		}(),
		"selector wrong type": linkerdResource(t, map[string]any{"identities": "private-canary"}, nil),
		"selector null":       []byte(`{"apiVersion":"policy.linkerd.io/v1alpha1","kind":"MeshTLSAuthentication","spec":{"identities":null}}`),
		"unknown top member":  []byte(`{"apiVersion":"policy.linkerd.io/v1alpha1","kind":"MeshTLSAuthentication","private":"canary","spec":{}}`),
		"unknown spec member": []byte(`{"apiVersion":"policy.linkerd.io/v1alpha1","kind":"MeshTLSAuthentication","spec":{"private":"canary"}}`),
		"duplicate key":       []byte(`{"apiVersion":"policy.linkerd.io/v1alpha1","APIversion":"x","kind":"MeshTLSAuthentication","spec":{}}`),
		"both malformed":      []byte(`{"apiVersion":"policy.linkerd.io/v1alpha1","kind":"MeshTLSAuthentication","spec":{"identities":[],"identityRefs":[{"name":"private"}]}}`),
		"empty identity":      linkerdResource(t, map[string]any{"identities": []any{""}}, nil),
		"ref missing kind":    linkerdResource(t, map[string]any{"identityRefs": []any{map[string]any{}}}, nil),
		"ref unknown member":  linkerdResource(t, map[string]any{"identityRefs": []any{map[string]any{"kind": "ServiceAccount", "private": "canary"}}}, nil),
		"metadata null":       []byte(`{"apiVersion":"policy.linkerd.io/v1alpha1","kind":"MeshTLSAuthentication","metadata":null,"spec":{}}`),
		"metadata extra":      []byte(`{"apiVersion":"policy.linkerd.io/v1alpha1","kind":"MeshTLSAuthentication","metadata":{"private":"canary"},"spec":{}}`),
		"spec null":           []byte(`{"apiVersion":"policy.linkerd.io/v1alpha1","kind":"MeshTLSAuthentication","spec":null}`),
	}
	_ = valid
	for name, raw := range invalids {
		t.Run(name, func(t *testing.T) {
			prepared, err := PrepareLinkerd(raw, LinkerdFrom, LinkerdTo, LinkerdDistributionOfficial, LinkerdSchemaRequired)
			if err == nil || !errorsIs(err, ErrInvalidLinkerd) || len(prepared.CanonicalInputJSON) != 0 || prepared.SourceDigest != "" {
				t.Fatalf("prepared=%+v err=%v", prepared, err)
			}
		})
	}
	for _, version := range []struct{ from, to string }{{"v2.13.7", LinkerdTo}, {LinkerdFrom, "2.14"}, {LinkerdFrom, LinkerdFrom}} {
		if _, err := PrepareLinkerd(valid, version.from, version.to, LinkerdDistributionOfficial, LinkerdSchemaRequired); err == nil {
			t.Fatalf("accepted invalid endpoints %v", version)
		}
	}
	invalidUTF8 := append([]byte(`{"apiVersion":"policy.linkerd.io/v1alpha1","kind":"MeshTLSAuthentication","spec":{`), 0xff, '}')
	if _, err := PrepareLinkerd(invalidUTF8, LinkerdFrom, LinkerdTo, LinkerdDistributionOfficial, LinkerdSchemaRequired); !errorsIs(err, ErrInvalidLinkerd) {
		t.Fatalf("accepted invalid UTF-8: %v", err)
	}
	if _, err := PrepareLinkerd(valid, LinkerdFrom, LinkerdTo, "invalid", LinkerdSchemaRequired); err == nil {
		t.Fatal("accepted invalid distribution")
	}
	if _, err := PrepareLinkerd(valid, LinkerdFrom, LinkerdTo, LinkerdDistributionOfficial, "invalid"); err == nil {
		t.Fatal("accepted invalid schema intent")
	}
}

func TestPrepareLinkerdLimitsAndPrivacy(t *testing.T) {
	boundary := strings.Repeat("a", maxLinkerdString)
	identityBoundary := strings.Repeat("b", maxLinkerdIdentity)
	good := linkerdResource(t, map[string]any{"identities": []any{identityBoundary}}, map[string]any{"name": boundary, "namespace": ""})
	if prepared, err := PrepareLinkerd(good, LinkerdFrom, LinkerdTo, LinkerdDistributionOfficial, LinkerdSchemaRequired); err != nil || prepared.State != StatePrepared {
		t.Fatalf("boundary rejected: %+v %v", prepared, err)
	} else if strings.Contains(string(prepared.CanonicalInputJSON), boundary) || strings.Contains(string(prepared.CanonicalInputJSON), identityBoundary) {
		t.Fatal("boundary private values escaped")
	}
	for name, raw := range map[string][]byte{
		"metadata too long":       linkerdResource(t, map[string]any{}, map[string]any{"name": strings.Repeat("a", maxLinkerdString+1)}),
		"identity too long":       linkerdResource(t, map[string]any{"identities": []any{strings.Repeat("a", maxLinkerdIdentity+1)}}, nil),
		"ref optional wrong type": linkerdResource(t, map[string]any{"identityRefs": []any{map[string]any{"kind": "ServiceAccount", "name": 7}}}, nil),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := PrepareLinkerd(raw, LinkerdFrom, LinkerdTo, LinkerdDistributionOfficial, LinkerdSchemaRequired); err == nil {
				t.Fatal("accepted overbound input")
			}
		})
	}
	if _, err := PrepareLinkerd(linkerdResource(t, map[string]any{"identities": []any{nil}}, nil), LinkerdFrom, LinkerdTo, LinkerdDistributionOfficial, LinkerdSchemaRequired); err == nil {
		t.Fatal("accepted null selector item")
	}
}

func TestPrepareLinkerdCanonicalFactAndOmissionOrder(t *testing.T) {
	prepared, err := PrepareLinkerd(linkerdResource(t, linkerdSpec("identityRefs", []any{}), nil), LinkerdFrom, LinkerdTo, LinkerdDistributionOfficial, LinkerdSchemaRequired)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"schema":"prufyx.io/operator-declared-constraint-input/v1alpha1","authority":"OPERATOR_DECLARED_MINIMIZED","current":{"components":[{"component":"pkg:github/linkerd/linkerd2","version":"2.13.7","facts":[]}]},"proposed":{"components":[{"component":"pkg:github/linkerd/linkerd2","version":"2.14.0","facts":[{"id":"component.linkerd.distribution","state":"declared","enumValue":"official_upstream"},{"id":"component.linkerd.execution_surface","state":"declared","enumValue":"meshtls_authentication_crd"},{"id":"component.linkerd.mtls_identity_selector_empty","state":"declared","boolValue":true},{"id":"component.linkerd.schema_validation_required","state":"declared","boolValue":true}]}]}}` + "\n"
	if string(prepared.CanonicalInputJSON) != want {
		t.Fatalf("canonical changed:\n%s", prepared.CanonicalInputJSON)
	}
	if got, wantOmissions := fmt.Sprint(prepared.Omissions), "[CRD_SCHEMA_VALIDATION_NOT_PERFORMED LIVE_OBSERVATION_NOT_PERFORMED WHOLE_UPGRADE_COMPATIBILITY_NOT_EVALUATED]"; got != wantOmissions {
		t.Fatalf("omissions=%q", got)
	}
	if prepared.SourceDigest == prepared.InputDigest || prepared.SourceDigest == "" || prepared.InputDigest == "" {
		t.Fatal("digests missing or unexpectedly equal")
	}
}

func errorsIs(err, target error) bool {
	return err == target
}
