// SPDX-License-Identifier: AGPL-3.0-only

package cncfprepare

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestPrepareCRIOArtifactName(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name, raw, operation, plannedState, shortState string
		short                                          *bool
		wantErr                                        bool
	}{
		{"short", `{"image":{"image":"library/widget:latest"},"auth":{"password":"private-canary"}}`, CRIOOperation, "declared", "declared", boolPointer(true), false},
		{"qualified", `{"image":{"image":"quay.io/crio/widget:v1"},"verbose":true}`, CRIOOperation, "declared", "declared", boolPointer(false), false},
		{"missing-intent", `{"image":{"image":"widget:v1"}}`, "", "unsupported", "declared", boolPointer(true), false},
		{"other-intent", `{"image":{"image":"widget:v1"}}`, "ordinary-image", "unsupported", "declared", boolPointer(true), false},
		{"missing-image", `{"image":{}}`, CRIOOperation, "declared", "unsupported", nil, false},
		{"non-string", `{"image":{"image":1}}`, CRIOOperation, "declared", "unsupported", nil, false},
		{"root-case-ambiguous", `{"image":{"image":"widget:v1"},"Image":{"image":"widget:v1"}}`, CRIOOperation, "declared", "unsupported", nil, false},
		{"nested-duplicate", `{"image":{"image":"widget:v1","image":"quay.io/x/y:v1"}}`, CRIOOperation, "declared", "unsupported", nil, false},
		{"nested-case-ambiguous", `{"image":{"image":"widget:v1","Image":"widget:v1"}}`, CRIOOperation, "declared", "unsupported", nil, false},
		{"unrelated-image-keys", `{"image":{"image":"widget:v1"},"metadata":{"image":"ignored","Image":"also-ignored"}}`, CRIOOperation, "declared", "declared", boolPointer(true), false},
		{"unrelated-empty-key", `{"image":{"image":"widget:v1"},"metadata":{"":"ignored"}}`, CRIOOperation, "declared", "declared", boolPointer(true), false},
		{"digest", `{"image":{"image":"widget@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}`, CRIOOperation, "declared", "unsupported", nil, false},
		{"no-tag", `{"image":{"image":"quay.io/crio/widget"}}`, CRIOOperation, "declared", "unsupported", nil, false},
		{"localhost", `{"image":{"image":"localhost/widget:v1"}}`, CRIOOperation, "declared", "unsupported", nil, false},
		{"port", `{"image":{"image":"registry.example:5000/widget:v1"}}`, CRIOOperation, "declared", "unsupported", nil, false},
		{"ipv4", `{"image":{"image":"127.0.0.1/widget:v1"}}`, CRIOOperation, "declared", "unsupported", nil, false},
		{"uppercase-name", `{"image":{"image":"quay.io/Crio/widget:v1"}}`, CRIOOperation, "declared", "unsupported", nil, false},
		{"malformed", `{"image":`, CRIOOperation, "", "", nil, true},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := PrepareCRIOArtifactName([]byte(tt.raw), CRIOFrom, CRIOTo, tt.operation)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil || got.SourceDigest != digestBytes([]byte(tt.raw)) || got.InputDigest != digestBytes(got.CanonicalInputJSON) {
				t.Fatalf("PrepareCRIOArtifactName() = %#v, %v", got, err)
			}
			var doc struct {
				Proposed struct {
					Components []struct {
						Facts []inputFact `json:"facts"`
					} `json:"components"`
				} `json:"proposed"`
			}
			if json.Unmarshal(got.CanonicalInputJSON, &doc) != nil || len(doc.Proposed.Components) != 1 || len(doc.Proposed.Components[0].Facts) != 2 {
				t.Fatalf("canonical=%s", got.CanonicalInputJSON)
			}
			facts := doc.Proposed.Components[0].Facts
			if facts[0].ID != CRIOShortFact || facts[0].State != tt.shortState || facts[1].ID != CRIOPlannedFact || facts[1].State != tt.plannedState {
				t.Fatalf("facts=%#v", facts)
			}
			if tt.short == nil && facts[0].BoolValue != nil {
				t.Fatalf("unexpected short value")
			}
			if tt.short != nil && (facts[0].BoolValue == nil || *facts[0].BoolValue != *tt.short) {
				t.Fatalf("short=%v", facts[0].BoolValue)
			}
			if strings.Contains(string(got.CanonicalInputJSON), "private-canary") || strings.Contains(string(got.CanonicalInputJSON), "quay.io") || strings.Contains(string(got.CanonicalInputJSON), "widget") {
				t.Fatalf("private input leaked: %s", got.CanonicalInputJSON)
			}
		})
	}
}

func TestClassifyCRIOReferenceBoundaries(t *testing.T) {
	t.Parallel()
	short237 := strings.Repeat("a", 237) + ":v"
	short238 := strings.Repeat("a", 238) + ":v"
	full255 := "a.b/" + strings.Repeat("c", 251) + ":v"
	full256 := "a.b/" + strings.Repeat("c", 252) + ":v"
	for _, tt := range []struct {
		name, value string
		short, ok   bool
	}{
		{"short-237", short237, true, true}, {"short-238", short238, false, false},
		{"full-255", full255, false, true}, {"full-256", full256, false, false},
		{"tag-max", "x:" + strings.Repeat("a", 128), true, true}, {"tag-over", "x:" + strings.Repeat("a", 129), false, false},
		{"qualified-repeated-host-hyphen", "registry--edge.example/repository/widget:v1", false, true},
		{"trailing-dot", "repo./widget:v1", false, false},
		{"trailing-path-separator", "registry.example/repo_:v1", false, false},
		{"consecutive-path-separators", "registry.example/repo__name:v1", false, false},
		{"ipv6", "[2001:db8::1]/widget:v1", false, false},
		{"transport-prefix", "docker://registry.example/widget:v1", false, false},
	} {
		if got, ok := classifyCRIOReference(tt.value); got != tt.short || ok != tt.ok {
			t.Fatalf("%s=(%t,%t)", tt.name, got, ok)
		}
	}
}

func TestPrepareCRIOArtifactNameCanonicalIgnoresUnrelatedFields(t *testing.T) {
	t.Parallel()
	one, err := PrepareCRIOArtifactName([]byte(`{"image":{"image":"widget:v1"},"auth":{"username":"PRIVATE_ONE"}}`), CRIOFrom, CRIOTo, CRIOOperation)
	if err != nil {
		t.Fatal(err)
	}
	two, err := PrepareCRIOArtifactName([]byte(`{"verbose":true,"image":{"image":"widget:v1"},"sandboxImage":"PRIVATE_TWO"}`), CRIOFrom, CRIOTo, CRIOOperation)
	if err != nil {
		t.Fatal(err)
	}
	if one.SourceDigest == two.SourceDigest || one.InputDigest != two.InputDigest || string(one.CanonicalInputJSON) != string(two.CanonicalInputJSON) {
		t.Fatalf("raw/canonical boundary lost: rawEqual=%t inputEqual=%t", one.SourceDigest == two.SourceDigest, one.InputDigest == two.InputDigest)
	}
}
