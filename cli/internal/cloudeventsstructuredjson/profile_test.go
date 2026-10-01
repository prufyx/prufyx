// SPDX-License-Identifier: AGPL-3.0-only

package cloudeventsstructuredjson

import (
	"encoding/json"
	"testing"
	"time"
)

func TestEmbeddedProfileAndClosedSourceAdmission(t *testing.T) {
	p, err := ParseProfile(EmbeddedProfile())
	if err != nil {
		t.Fatal(err)
	}
	if p.Revision != "1" || p.Purpose != "standards_conformance" || len(p.NormativeSources) != 2 {
		t.Fatalf("profile=%+v", p)
	}
	if claim := Evaluate(p, mustObserve(t, `{"specversion":"1.0","id":"a","source":"x","type":"t"}`), time.Date(2029, 1, 1, 0, 0, 0, 0, time.UTC)); claim.Status != "PASS" {
		t.Fatalf("claim=%+v", claim)
	}
	var document map[string]any
	if err := json.Unmarshal(EmbeddedProfile(), &document); err != nil {
		t.Fatal(err)
	}
	sources := document["normativeSources"].([]any)
	cases := []func(){
		func() { sources[0].(map[string]any)["repositoryURL"] = "https://example.invalid" },
		func() { sources[0].(map[string]any)["path"] = "spec/spec.md" },
		func() { sources[1].(map[string]any)["role"] = "spec" },
		func() {
			sources[0].(map[string]any)["spans"] = []any{map[string]any{"startLine": 10.0, "endLine": 20.0}, map[string]any{"startLine": 20.0, "endLine": 21.0}}
		},
	}
	for i, mutate := range cases {
		if err := json.Unmarshal(EmbeddedProfile(), &document); err != nil {
			t.Fatal(err)
		}
		sources = document["normativeSources"].([]any)
		mutate()
		raw, _ := json.Marshal(document)
		if _, err := ParseProfile(raw); err == nil {
			t.Fatalf("case %d admitted", i)
		}
	}
}

func TestProfileRejectsTrailingAndUnknownData(t *testing.T) {
	for _, raw := range [][]byte{
		append(append([]byte{}, EmbeddedProfile()...), []byte(`{"extra":true}`)...),
		append(append([]byte{}, EmbeddedProfile()...), []byte(`"`)...),
	} {
		if _, err := ParseProfile(raw); err == nil {
			t.Fatal("trailing data admitted")
		}
	}
}

func TestRuleEvidenceExpiryIsScopedUnknown(t *testing.T) {
	p, err := ParseProfile(EmbeddedProfile())
	if err != nil {
		t.Fatal(err)
	}
	o := mustObserve(t, `{"specversion":"1.0","id":"a","source":"x","type":"t"}`)
	claim := Evaluate(p, o, time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC))
	if claim.Status != "UNKNOWN" || claim.ReasonCode != "PROFILE_EVIDENCE_EXPIRED" {
		t.Fatalf("claim=%+v", claim)
	}
}

func mustObserve(t *testing.T, raw string) Observation {
	t.Helper()
	o, err := Observe([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	return o
}
