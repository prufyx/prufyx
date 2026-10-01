// SPDX-License-Identifier: AGPL-3.0-only

package cncfprepare

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/cncfcheck"
)

func ciliumBool(value bool) *bool { return &value }

func ciliumPolicyDocument(t *testing.T, kind string, spec any, specs any) []byte {
	t.Helper()
	document := map[string]any{
		"apiVersion": ciliumAPIVersion,
		"kind":       kind,
		"metadata":   map[string]any{"name": "private-policy-never-retain"},
	}
	if spec != nil {
		document["spec"] = spec
	}
	if specs != nil {
		document["specs"] = specs
	}
	raw, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func ciliumPreparedFact(t *testing.T, prepared Prepared) map[string]any {
	t.Helper()
	return preparedFacts(t, prepared)[CiliumRequiresFact]
}

func TestPrepareCiliumScansBothPolicyKindsAndRuleContainers(t *testing.T) {
	cases := []struct {
		name string
		raw  []byte
	}{
		{"cnp ingress requires", ciliumPolicyDocument(t, "CiliumNetworkPolicy", map[string]any{"ingress": []any{map[string]any{"fromRequires": []any{map[string]any{"private": "value"}}}}}, nil)},
		{"ccnp ingress deny requires", ciliumPolicyDocument(t, "CiliumClusterwideNetworkPolicy", map[string]any{"ingressDeny": []any{map[string]any{"fromRequires": []any{map[string]any{}}}}}, nil)},
		{"cnp egress requires in specs", ciliumPolicyDocument(t, "CiliumNetworkPolicy", nil, []any{map[string]any{"egress": []any{map[string]any{"toRequires": []any{map[string]any{}}}}}})},
		{"ccnp egress deny requires in specs", ciliumPolicyDocument(t, "CiliumClusterwideNetworkPolicy", nil, []any{map[string]any{"egressDeny": []any{map[string]any{"toRequires": []any{map[string]any{}}}}}})},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			prepared, err := PrepareCilium(tc.raw, CiliumFrom, CiliumTo, nil)
			if err != nil || prepared.State != StatePrepared || prepared.Reason != ReasonCiliumRequiresWitness || bytes.Contains(prepared.CanonicalInputJSON, []byte("private-policy-never-retain")) {
				t.Fatalf("prepared=%+v err=%v", prepared, err)
			}
			fact := ciliumPreparedFact(t, prepared)
			if fact["state"] != "declared" || fact["boolValue"] != true {
				t.Fatalf("fact=%v", fact)
			}
			report, err := cncfcheck.Check("cilium", prepared.CanonicalInputJSON, time.Date(2026, 9, 9, 0, 0, 0, 0, time.UTC))
			if err != nil || report.Check.Claims[0].Status != "BLOCKED" || report.Assessment != "UNKNOWN" {
				t.Fatalf("report=%+v err=%v", report, err)
			}
		})
	}
}

func TestPrepareCiliumSupportsOnlyReviewedExactPairs(t *testing.T) {
	raw := ciliumPolicyDocument(t, "CiliumNetworkPolicy", map[string]any{"ingress": []any{map[string]any{"fromRequires": []any{map[string]any{}}}}}, nil)
	for _, tc := range []struct {
		name        string
		from, to    string
		state       State
		reason      Reason
		checkStatus string
	}{
		{"legacy pair", CiliumFrom, CiliumTo, StatePrepared, ReasonCiliumRequiresWitness, "BLOCKED"},
		{"target CRD pair", CiliumTargetCRDFrom, CiliumTargetCRDTo, StatePrepared, ReasonCiliumRequiresWitness, "BLOCKED"},
		{"crossed old to new", CiliumFrom, CiliumTargetCRDTo, StateUnknown, ReasonCiliumUnsupportedPair, "UNKNOWN"},
		{"crossed new to old", CiliumTargetCRDFrom, CiliumTo, StateUnknown, ReasonCiliumUnsupportedPair, "UNKNOWN"},
		{"other pair", "1.18.12", CiliumTargetCRDTo, StateUnknown, ReasonCiliumUnsupportedPair, "UNKNOWN"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			prepared, err := PrepareCilium(raw, tc.from, tc.to, nil)
			if err != nil || prepared.State != tc.state || prepared.Reason != tc.reason {
				t.Fatalf("prepared=%+v err=%v", prepared, err)
			}
			fact := ciliumPreparedFact(t, prepared)
			if tc.state == StatePrepared {
				if fact["state"] != "declared" || fact["boolValue"] != true {
					t.Fatalf("fact=%v", fact)
				}
			} else if fact["state"] == "declared" {
				t.Fatalf("unsupported pair declared a fact: %v", fact)
			}
			report, err := cncfcheck.Check("cilium", prepared.CanonicalInputJSON, time.Date(2026, 9, 10, 0, 0, 0, 0, time.UTC))
			if err != nil || report.Check.Claims[0].Status != tc.checkStatus || report.Assessment != "UNKNOWN" {
				t.Fatalf("report=%+v err=%v", report, err)
			}
		})
	}
}

func TestPrepareCiliumTargetCRDPairPreservesUnknownBoundaries(t *testing.T) {
	clean := ciliumPolicyDocument(t, "CiliumClusterwideNetworkPolicy", map[string]any{"egress": []any{map[string]any{"toRequires": []any{}}}}, nil)
	partial, err := json.Marshal(map[string]any{
		"apiVersion": ciliumAPIVersion,
		"kind":       "CiliumClusterwideNetworkPolicyList",
		"metadata":   map[string]any{"remainingItemCount": 1},
		"items":      []any{json.RawMessage(clean)},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name     string
		raw      []byte
		complete *bool
		state    State
		reason   Reason
	}{
		{"omitted completeness", clean, nil, StateUnknown, ReasonCiliumSetIncomplete},
		{"false completeness", clean, ciliumBool(false), StateUnknown, ReasonCiliumSetIncomplete},
		{"explicit complete set", clean, ciliumBool(true), StatePrepared, ReasonCiliumNoRequiresWitness},
		{"partial complete set", partial, ciliumBool(true), StateUnknown, ReasonCiliumPartialList},
		{"malformed policy", []byte(`{"apiVersion":"cilium.io/v2","kind":"CiliumNetworkPolicy","spec":{"ingress":{}}}`), ciliumBool(true), StateUnknown, ReasonCiliumUnsupportedShape},
	} {
		t.Run(tc.name, func(t *testing.T) {
			prepared, err := PrepareCilium(tc.raw, CiliumTargetCRDFrom, CiliumTargetCRDTo, tc.complete)
			if err != nil || prepared.State != tc.state || prepared.Reason != tc.reason {
				t.Fatalf("prepared=%+v err=%v", prepared, err)
			}
			fact := ciliumPreparedFact(t, prepared)
			if tc.reason == ReasonCiliumNoRequiresWitness {
				if fact["state"] != "declared" || fact["boolValue"] != false {
					t.Fatalf("fact=%v", fact)
				}
			} else if fact["state"] == "declared" {
				t.Fatalf("unresolved input declared a fact: %v", fact)
			}
		})
	}
}

func TestPrepareCiliumRequiresExplicitCompleteSetForScopedFalse(t *testing.T) {
	raw := ciliumPolicyDocument(t, "CiliumNetworkPolicy", map[string]any{"ingress": []any{map[string]any{"fromRequires": []any{}}}}, nil)
	for _, tc := range []struct {
		name     string
		complete *bool
		state    State
		reason   Reason
		status   string
	}{
		{"omitted completeness stays unknown", nil, StateUnknown, ReasonCiliumSetIncomplete, "UNKNOWN"},
		{"false completeness stays unknown", ciliumBool(false), StateUnknown, ReasonCiliumSetIncomplete, "UNKNOWN"},
		{"complete set declares scoped false", ciliumBool(true), StatePrepared, ReasonCiliumNoRequiresWitness, "PASS"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			prepared, err := PrepareCilium(raw, CiliumFrom, CiliumTo, tc.complete)
			if err != nil || prepared.State != tc.state || prepared.Reason != tc.reason {
				t.Fatalf("prepared=%+v err=%v", prepared, err)
			}
			fact := ciliumPreparedFact(t, prepared)
			if tc.complete != nil && *tc.complete {
				if fact["state"] != "declared" || fact["boolValue"] != false {
					t.Fatalf("fact=%v", fact)
				}
			} else if fact["state"] == "declared" {
				t.Fatalf("fact unexpectedly declared: %v", fact)
			}
			report, err := cncfcheck.Check("cilium", prepared.CanonicalInputJSON, time.Date(2026, 9, 9, 0, 0, 0, 0, time.UTC))
			if err != nil || report.Check.Claims[0].Status != tc.status || report.Assessment != "UNKNOWN" {
				t.Fatalf("report=%+v err=%v", report, err)
			}
		})
	}
}

func TestPrepareCiliumListAndMalformedBoundaries(t *testing.T) {
	witness := map[string]any{"apiVersion": ciliumAPIVersion, "kind": "CiliumNetworkPolicy", "spec": map[string]any{"ingress": []any{map[string]any{"fromRequires": []any{map[string]any{}}}}}}
	cleanTypedList, err := json.Marshal(map[string]any{"apiVersion": ciliumAPIVersion, "kind": "CiliumNetworkPolicyList", "items": []any{witness}})
	if err != nil {
		t.Fatal(err)
	}
	clusterWitness := map[string]any{"apiVersion": ciliumAPIVersion, "kind": "CiliumClusterwideNetworkPolicy", "specs": []any{map[string]any{"egressDeny": []any{map[string]any{"toRequires": []any{map[string]any{}}}}}}}
	cleanClusterTypedList, err := json.Marshal(map[string]any{"apiVersion": ciliumAPIVersion, "kind": "CiliumClusterwideNetworkPolicyList", "items": []any{clusterWitness}})
	if err != nil {
		t.Fatal(err)
	}
	cleanGenericList, err := json.Marshal(map[string]any{"apiVersion": "v1", "kind": "List", "items": []any{map[string]any{"apiVersion": "v1", "kind": "ConfigMap"}, witness}})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		raw    []byte
		state  State
		reason Reason
	}{
		{"typed list scans policies", cleanTypedList, StatePrepared, ReasonCiliumRequiresWitness},
		{"clusterwide typed list scans policies", cleanClusterTypedList, StatePrepared, ReasonCiliumRequiresWitness},
		{"generic list ignores typed unrelated objects", cleanGenericList, StatePrepared, ReasonCiliumRequiresWitness},
		{"generic list rejects untyped object", []byte(`{"apiVersion":"v1","kind":"List","items":[{}]}`), StateUnknown, ReasonCiliumUnsupportedShape},
		{"generic list rejects policy with wrong API", []byte(`{"apiVersion":"v1","kind":"List","items":[{"apiVersion":"v1","kind":"CiliumClusterwideNetworkPolicy","spec":{}}]}`), StateUnknown, ReasonCiliumUnsupportedShape},
		{"wrong policy API remains unknown", []byte(`{"apiVersion":"v1","kind":"CiliumNetworkPolicy","spec":{}}`), StateUnknown, ReasonCiliumUnsupportedShape},
		{"nested list remains unknown", []byte(`{"apiVersion":"v1","kind":"List","items":[{"apiVersion":"v1","kind":"List","items":[]}]}`), StateUnknown, ReasonCiliumUnsupportedShape},
		{"wrong target shape remains unknown", ciliumPolicyDocument(t, "CiliumNetworkPolicy", map[string]any{"egress": []any{map[string]any{"toRequires": map[string]any{}}}}, nil), StateUnknown, ReasonCiliumUnsupportedShape},
	} {
		t.Run(tc.name, func(t *testing.T) {
			prepared, err := PrepareCilium(tc.raw, CiliumFrom, CiliumTo, ciliumBool(true))
			if err != nil || prepared.State != tc.state || prepared.Reason != tc.reason {
				t.Fatalf("prepared=%+v err=%v", prepared, err)
			}
		})
	}
}

func TestPrepareCiliumPartialListsCannotEstablishScopedFalse(t *testing.T) {
	clean := map[string]any{"apiVersion": ciliumAPIVersion, "kind": "CiliumNetworkPolicy", "spec": map[string]any{"ingress": []any{map[string]any{"fromRequires": []any{}}}}}
	witness := map[string]any{"apiVersion": ciliumAPIVersion, "kind": "CiliumNetworkPolicy", "spec": map[string]any{"ingress": []any{map[string]any{"fromRequires": []any{map[string]any{}}}}}}
	for _, tc := range []struct {
		name   string
		items  []any
		meta   map[string]any
		state  State
		reason Reason
		want   any
	}{
		{"continue token keeps clean list unknown", []any{clean}, map[string]any{"continue": "private-continuation-token"}, StateUnknown, ReasonCiliumPartialList, nil},
		{"remaining count keeps clean list unknown", []any{clean}, map[string]any{"remainingItemCount": 1}, StateUnknown, ReasonCiliumPartialList, nil},
		{"partial page can still witness blocker", []any{witness}, map[string]any{"continue": "private-continuation-token"}, StatePrepared, ReasonCiliumRequiresWitness, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw, err := json.Marshal(map[string]any{"apiVersion": ciliumAPIVersion, "kind": "CiliumNetworkPolicyList", "metadata": tc.meta, "items": tc.items})
			if err != nil {
				t.Fatal(err)
			}
			prepared, err := PrepareCilium(raw, CiliumFrom, CiliumTo, ciliumBool(true))
			if err != nil || prepared.State != tc.state || prepared.Reason != tc.reason || bytes.Contains(prepared.CanonicalInputJSON, []byte("private-continuation-token")) {
				t.Fatalf("prepared=%+v err=%v", prepared, err)
			}
			fact := ciliumPreparedFact(t, prepared)
			if tc.want == nil {
				if fact["state"] == "declared" {
					t.Fatalf("partial list unexpectedly declared false: %v", fact)
				}
			} else if fact["boolValue"] != tc.want {
				t.Fatalf("fact=%v", fact)
			}
		})
	}
}
