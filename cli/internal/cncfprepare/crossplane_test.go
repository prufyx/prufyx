// SPDX-License-Identifier: AGPL-3.0-only

package cncfprepare

import (
	"strings"
	"testing"
)

const crossplaneResourcesComposition = `{"apiVersion":"apiextensions.crossplane.io/v1","kind":"Composition","metadata":{"name":"private-composition"},"spec":{"mode":"Resources","compositeTypeRef":{"apiVersion":"private.example/v1","kind":"PrivateClaim"}}}`
const crossplanePipelineComposition = `{"apiVersion":"apiextensions.crossplane.io/v1","kind":"Composition","metadata":{"name":"private-composition"},"spec":{"mode":"Pipeline","compositeTypeRef":{"apiVersion":"private.example/v1","kind":"PrivateClaim"}}}`

func TestPrepareCrossplaneComposition_BoundedSelectedResources(t *testing.T) {
	tests := []struct {
		name, raw, reason string
		state             State
	}{
		{"resources mode present", crossplaneResourcesComposition, string(ReasonCrossplaneResourcesMode), StatePrepared},
		{"pipeline mode only", crossplanePipelineComposition, string(ReasonCrossplanePipelineMode), StatePrepared},
		{"mixed list keeps resources witness", `{"apiVersion":"v1","kind":"List","items":[` + crossplanePipelineComposition + `,` + crossplaneResourcesComposition + `]}`, string(ReasonCrossplaneResourcesMode), StatePrepared},
		{"clear list", `{"apiVersion":"v1","kind":"List","items":[` + crossplanePipelineComposition + `]}`, string(ReasonCrossplanePipelineMode), StatePrepared},
		{"other kind in group", `{"apiVersion":"apiextensions.crossplane.io/v1","kind":"CompositeResourceDefinition","metadata":{"name":"private-xrd"}}`, string(ReasonCrossplaneSurfaceOther), StateUnknown},
		{"unrelated group", `{"apiVersion":"example.test/v1","kind":"Composition","metadata":{"name":"private-composition"},"spec":{"mode":"Pipeline"}}`, string(ReasonCrossplaneSurfaceOther), StateUnknown},
		{"other kind inside list", `{"apiVersion":"v1","kind":"List","items":[` + crossplaneResourcesComposition + `,{"apiVersion":"v1","kind":"Service","metadata":{"name":"private-service","namespace":"private-ns"}}]}`, string(ReasonCrossplaneSurfaceOther), StateUnknown},
		{"unreviewed served version", `{"apiVersion":"apiextensions.crossplane.io/v1beta1","kind":"Composition","metadata":{"name":"private-composition"},"spec":{"mode":"Resources"}}`, string(ReasonCrossplaneUnreviewedAPI), StateUnknown},
		{"omitted mode is never defaulted", `{"apiVersion":"apiextensions.crossplane.io/v1","kind":"Composition","metadata":{"name":"private-composition"},"spec":{"resources":[]}}`, string(ReasonCrossplaneModeUnresolved), StateUnknown},
		{"unreviewed mode literal", `{"apiVersion":"apiextensions.crossplane.io/v1","kind":"Composition","metadata":{"name":"private-composition"},"spec":{"mode":"resources"}}`, string(ReasonCrossplaneModeUnresolved), StateUnknown},
		{"non-string mode", `{"apiVersion":"apiextensions.crossplane.io/v1","kind":"Composition","metadata":{"name":"private-composition"},"spec":{"mode":1}}`, string(ReasonCrossplaneModeUnresolved), StateUnknown},
		{"missing spec", `{"apiVersion":"apiextensions.crossplane.io/v1","kind":"Composition","metadata":{"name":"private-composition"}}`, string(ReasonCrossplaneModeUnresolved), StateUnknown},
		{"omitted mode inside list", `{"apiVersion":"v1","kind":"List","items":[` + crossplaneResourcesComposition + `,{"apiVersion":"apiextensions.crossplane.io/v1","kind":"Composition","metadata":{"name":"private-other"},"spec":{}}]}`, string(ReasonCrossplaneModeUnresolved), StateUnknown},
		{"missing name", `{"apiVersion":"apiextensions.crossplane.io/v1","kind":"Composition","metadata":{},"spec":{"mode":"Resources"}}`, string(ReasonCrossplaneInputUnsupported), StateUnknown},
		{"empty list", `{"apiVersion":"v1","kind":"List","items":[]}`, string(ReasonCrossplaneInputUnsupported), StateUnknown},
		{"typed list", `{"apiVersion":"apiextensions.crossplane.io/v1","kind":"CompositionList","items":[]}`, string(ReasonCrossplaneInputUnsupported), StateUnknown},
		{"nested list", `{"apiVersion":"v1","kind":"List","items":[{"apiVersion":"v1","kind":"List","items":[]}]}`, string(ReasonCrossplaneInputUnsupported), StateUnknown},
		{"non-v1 list", `{"apiVersion":"apiextensions.crossplane.io/v1","kind":"List","items":[` + crossplanePipelineComposition + `]}`, string(ReasonCrossplaneInputUnsupported), StateUnknown},
		{"bad list metadata", `{"apiVersion":"v1","kind":"List","metadata":{"continue":1},"items":[` + crossplanePipelineComposition + `]}`, string(ReasonCrossplaneInputUnsupported), StateUnknown},
		{"pagination", `{"apiVersion":"v1","kind":"List","metadata":{"remainingItemCount":1},"items":[` + crossplanePipelineComposition + `]}`, string(ReasonCrossplanePagination), StateUnknown},
		{"template", `{"apiVersion":"apiextensions.crossplane.io/v1","kind":"Composition","spec":{"mode":"{{ .Values.mode }}"}}`, string(ReasonCrossplaneTemplated), StateUnknown},
		{"shell substitution", `{"apiVersion":"apiextensions.crossplane.io/v1","kind":"Composition","spec":{"mode":"${MODE}"}}`, string(ReasonCrossplaneTemplated), StateUnknown},
		{"scalar root", `"composition"`, string(ReasonCrossplaneInputUnsupported), StateUnknown},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			prepared, err := PrepareCrossplaneComposition([]byte(test.raw), CrossplaneFrom, CrossplaneTo, CrossplaneDistributionOfficial, true)
			if err != nil || prepared.Reason != Reason(test.reason) || prepared.State != test.state {
				t.Fatalf("prepared=%+v err=%v", prepared, err)
			}
			if strings.Contains(string(prepared.CanonicalInputJSON), "private-") {
				t.Fatalf("canonical input retained private names: %s", prepared.CanonicalInputJSON)
			}
		})
	}
}

func TestPrepareCrossplaneComposition_GuardsPrecedeModeClassification(t *testing.T) {
	tests := []struct {
		name, from, to, distribution, reason string
	}{
		{"unreviewed pair", "1.19.0", "2.0.0", CrossplaneDistributionOfficial, string(ReasonCrossplanePairUnsupported)},
		{"unreviewed target", CrossplaneFrom, "2.1.0", CrossplaneDistributionOfficial, string(ReasonCrossplanePairUnsupported)},
		{"missing distribution", CrossplaneFrom, CrossplaneTo, "", string(ReasonCrossplaneGuardUnresolved)},
		{"unknown distribution token", CrossplaneFrom, CrossplaneTo, "vendor_build", string(ReasonCrossplaneGuardUnresolved)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			prepared, err := PrepareCrossplaneComposition([]byte(crossplaneResourcesComposition), test.from, test.to, test.distribution, true)
			if err != nil || prepared.State != StateUnknown || prepared.Reason != Reason(test.reason) {
				t.Fatalf("prepared=%+v err=%v", prepared, err)
			}
		})
	}
}

// A custom build is a declared fact, not a guard failure: the adapter still
// derives the mode fact and lets the rule's own applicability keep the claim
// UNKNOWN. This must never become a PASS route for unreviewed builds.
func TestPrepareCrossplaneComposition_CustomBuildStaysDeclaredNotOfficial(t *testing.T) {
	prepared, err := PrepareCrossplaneComposition([]byte(crossplanePipelineComposition), CrossplaneFrom, CrossplaneTo, CrossplaneDistributionCustom, true)
	if err != nil || prepared.State != StatePrepared || prepared.Reason != ReasonCrossplanePipelineMode {
		t.Fatalf("prepared=%+v err=%v", prepared, err)
	}
	canonical := string(prepared.CanonicalInputJSON)
	if !strings.Contains(canonical, `"enumValue":"`+CrossplaneDistributionCustom+`"`) {
		t.Fatalf("custom build not declared: %s", canonical)
	}
}

func TestPrepareCrossplaneComposition_RecordsDeclaredSchemaValidationIntent(t *testing.T) {
	for _, required := range []bool{true, false} {
		prepared, err := PrepareCrossplaneComposition([]byte(crossplaneResourcesComposition), CrossplaneFrom, CrossplaneTo, CrossplaneDistributionOfficial, required)
		if err != nil {
			t.Fatalf("required=%v err=%v", required, err)
		}
		canonical := string(prepared.CanonicalInputJSON)
		want := `{"id":"` + CrossplaneSchemaValidationFact + `","state":"declared","boolValue":`
		if !strings.Contains(canonical, want+boolText(required)) {
			t.Fatalf("required=%v canonical=%s", required, canonical)
		}
	}
}

func TestPrepareCrossplaneComposition_RejectsRawBoundsAndMalformedJSON(t *testing.T) {
	for _, raw := range [][]byte{
		nil,
		{0xff},
		make([]byte, maxInputBytes+1),
	} {
		if _, err := PrepareCrossplaneComposition(raw, CrossplaneFrom, CrossplaneTo, CrossplaneDistributionOfficial, true); err == nil {
			t.Fatalf("accepted raw input of %d bytes", len(raw))
		}
	}
	for _, from := range []string{"", "1.20", "v1.20.0", CrossplaneTo} {
		if _, err := PrepareCrossplaneComposition([]byte(crossplanePipelineComposition), from, CrossplaneTo, CrossplaneDistributionOfficial, true); err == nil {
			t.Fatalf("accepted from version %q", from)
		}
	}
	for _, raw := range []string{
		`{"apiVersion":"apiextensions.crossplane.io/v1","apiVersion":"apiextensions.crossplane.io/v1","kind":"Composition"}`,
		`{"apiVersion":`,
	} {
		prepared, err := PrepareCrossplaneComposition([]byte(raw), CrossplaneFrom, CrossplaneTo, CrossplaneDistributionOfficial, true)
		if err != nil || prepared.State != StateUnknown || prepared.Reason != ReasonCrossplaneInputUnsupported {
			t.Fatalf("raw=%q prepared=%+v err=%v", raw, prepared, err)
		}
	}
}

func TestPrepareCrossplaneComposition_DigestsAndOmissionsAreStable(t *testing.T) {
	first, err := PrepareCrossplaneComposition([]byte(crossplaneResourcesComposition), CrossplaneFrom, CrossplaneTo, CrossplaneDistributionOfficial, true)
	if err != nil {
		t.Fatal(err)
	}
	second, err := PrepareCrossplaneComposition([]byte(crossplaneResourcesComposition), CrossplaneFrom, CrossplaneTo, CrossplaneDistributionOfficial, true)
	if err != nil {
		t.Fatal(err)
	}
	if first.SourceDigest != second.SourceDigest || first.InputDigest != second.InputDigest {
		t.Fatalf("unstable digests %+v %+v", first, second)
	}
	if first.SourceDigest != digestBytes([]byte(crossplaneResourcesComposition)) || first.InputDigest != digestBytes(first.CanonicalInputJSON) {
		t.Fatalf("digest bindings %+v", first)
	}
	if len(first.Omissions) != 3 || first.Omissions[2] != OmissionNoWholeUpgrade {
		t.Fatalf("omissions = %v", first.Omissions)
	}
}
