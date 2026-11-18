// SPDX-License-Identifier: AGPL-3.0-only

package cncfprepare

import (
	"strings"
	"testing"
)

const (
	cpxAPI        = `"apiVersion":"apiextensions.crossplane.io/v1","kind":"Composition"`
	cpxOmitted    = `{` + cpxAPI + `,"metadata":{"name":"private-omitted"},"spec":{"resources":[{"name":"private-res","base":{"secret":"canary-patch-text"}}]}}`
	cpxPipeline   = `{` + cpxAPI + `,"metadata":{"name":"private-pipeline"},"spec":{"mode":"Pipeline","pipeline":[{"step":"s"}]}}`
	cpxXRD        = `{"apiVersion":"apiextensions.crossplane.io/v2","kind":"CompositeResourceDefinition","metadata":{"name":"private-xrd"},"spec":{"versions":[{"schema":{"canary":"canary-xrd-schema"}}]}}`
	cpxXRDv1      = `{"apiVersion":"apiextensions.crossplane.io/v1","kind":"CompositeResourceDefinition","metadata":{"name":"private-xrd"},"spec":{}}`
	cpxResExplict = `{` + cpxAPI + `,"metadata":{"name":"private-explicit"},"spec":{"mode":"Resources"}}`
)

func cpxList(items ...string) string {
	return `{"apiVersion":"v1","kind":"List","items":[` + strings.Join(items, ",") + `]}`
}

func cpxPrepare(t *testing.T, raw, from, to string) Prepared {
	t.Helper()
	prepared, err := PrepareCrossplaneComposition([]byte(raw), from, to, CrossplaneDistributionOfficial, true)
	if err != nil {
		t.Fatalf("raw=%q from=%s to=%s err=%v", raw, from, to, err)
	}
	return prepared
}

func cpxMode(prepared Prepared) string {
	canonical := string(prepared.CanonicalInputJSON)
	switch {
	case strings.Contains(canonical, `"enumValue":"resources"`):
		return "resources"
	case strings.Contains(canonical, `"enumValue":"pipeline"`):
		return "pipeline"
	}
	return ""
}

func TestCrossplaneCitedTableShape(t *testing.T) {
	from, to := CrossplaneCitedVersions()
	if len(from) != 6+4+15 || len(to) != 9 {
		t.Fatalf("table sizes from=%d to=%d", len(from), len(to))
	}
	for _, version := range []string{"1.18.0", "1.18.5", "1.19.0", "1.19.3", "1.20.0", "1.20.14"} {
		if !crossplaneCited(crossplaneCitedFromSeries, version) {
			t.Fatalf("%s must be cited", version)
		}
	}
	for _, version := range []string{"1.17.4", "1.18.6", "1.19.4", "1.20.15", "1.21.0", "2.0.0", "", "1.20", "v1.20.0", "1.20.14-rc.1", "1.18.0-rc", "01.20.0"} {
		if crossplaneCited(crossplaneCitedFromSeries, version) {
			t.Fatalf("%q must not be a cited from version", version)
		}
	}
	for _, version := range []string{"2.0.0", "2.0.7", "2.0.8"} {
		if !crossplaneCited(crossplaneCitedToSeries, version) {
			t.Fatalf("%s must be cited", version)
		}
	}
	for _, version := range []string{"2.0.9", "2.1.0", "1.99.0", "1.20.14", "2.0.8-rc.1", "2.0.0+build"} {
		if crossplaneCited(crossplaneCitedToSeries, version) {
			t.Fatalf("%q must not be a cited to version", version)
		}
	}
}

func TestPrepareCrossplane_OmittedModeDefaultsOnlyToResourcesOnCitedFrom(t *testing.T) {
	for _, from := range []string{"1.18.0", "1.18.5", "1.19.0", "1.19.3", "1.20.0", "1.20.14"} {
		for _, to := range []string{"2.0.0", "2.0.8"} {
			prepared := cpxPrepare(t, cpxOmitted, from, to)
			if prepared.State != StatePrepared || prepared.Reason != ReasonCrossplaneModeDefaulted || cpxMode(prepared) != "resources" {
				t.Fatalf("%s->%s prepared=%+v", from, to, prepared)
			}
			if !cpxContains(prepared.Omissions, OmissionCrossplaneModeDefaulted) || len(prepared.ModeDefaultedItems) != 1 || prepared.ModeDefaultedItems[0] != 1 {
				t.Fatalf("omissions=%v items=%v", prepared.Omissions, prepared.ModeDefaultedItems)
			}
			if prepared.Omissions[len(prepared.Omissions)-1] != OmissionNoWholeUpgrade || !cpxContains(prepared.Omissions, "SELECTED_COMPOSITIONS_ARE_CALLER_SUPPLIED_NOT_LIVE_OBSERVATION") {
				t.Fatalf("omissions=%v", prepared.Omissions)
			}
		}
	}
}

func TestPrepareCrossplane_UncitedVersionsNeverPrepare(t *testing.T) {
	for _, pair := range [][2]string{
		{"1.17.4", "2.0.0"}, {"1.17.0", "2.0.0"}, {"1.20.15", "2.0.0"}, {"1.21.0", "2.0.0"},
		{"1.20.0", "2.0.9"}, {"1.20.0", "2.1.0"}, {"1.20.0", "1.99.0"}, {"1.18.6", "2.0.0"}, {"1.19.4", "2.0.0"},
	} {
		for _, raw := range []string{cpxOmitted, cpxResExplict, cpxPipeline} {
			prepared := cpxPrepare(t, raw, pair[0], pair[1])
			if prepared.State != StateUnknown || prepared.Reason != ReasonCrossplanePairUnsupported || cpxMode(prepared) != "" {
				t.Fatalf("%v prepared=%+v", pair, prepared)
			}
		}
	}
	// Pre-release or build suffixes are refused before any classification.
	for _, from := range []string{"1.20.14-rc.1", "1.18.0-rc", "1.20.0+build"} {
		prepared, err := PrepareCrossplaneComposition([]byte(cpxOmitted), from, "2.0.0", CrossplaneDistributionOfficial, true)
		if err == nil && prepared.State == StatePrepared {
			t.Fatalf("%q prepared", from)
		}
	}
}

func TestPrepareCrossplane_OmittedModeRefusedOutsideTheAdmittedShape(t *testing.T) {
	wrap := func(spec string) string {
		return `{` + cpxAPI + `,"metadata":{"name":"private-x"},"spec":` + spec + `}`
	}
	for name, raw := range map[string]string{
		"empty array":              wrap(`{"resources":[]}`),
		"empty object":             wrap(`{"resources":{}}`),
		"null resources":           wrap(`{"resources":null}`),
		"string resources":         wrap(`{"resources":"x"}`),
		"map resources":            wrap(`{"resources":{"a":1}}`),
		"number resources":         wrap(`{"resources":1}`),
		"neither":                  wrap(`{}`),
		"pipeline only":            wrap(`{"pipeline":[{"step":"s"}]}`),
		"resources and pipeline":   wrap(`{"resources":[{"name":"a"}],"pipeline":[{"step":"s"}]}`),
		"resources, null pipeline": wrap(`{"resources":[{"name":"a"}],"pipeline":null}`),
		"mode null":                wrap(`{"mode":null,"resources":[{"name":"a"}]}`),
		"mode empty":               wrap(`{"mode":"","resources":[{"name":"a"}]}`),
		"mode lower":               wrap(`{"mode":"resources","resources":[{"name":"a"}]}`),
		"mode upper":               wrap(`{"mode":"RESOURCES","resources":[{"name":"a"}]}`),
		"mode number":              wrap(`{"mode":1,"resources":[{"name":"a"}]}`),
		"mode array":               wrap(`{"mode":[],"resources":[{"name":"a"}]}`),
		"mode trailing space":      wrap(`{"mode":"Pipeline ","resources":[{"name":"a"}]}`),
		"spec null":                wrap(`null`),
		"spec missing":             `{` + cpxAPI + `,"metadata":{"name":"private-x"}}`,
		"v1beta1 with resources":   `{"apiVersion":"apiextensions.crossplane.io/v1beta1","kind":"Composition","metadata":{"name":"private-x"},"spec":{"resources":[{"name":"a"}]}}`,
	} {
		prepared := cpxPrepare(t, raw, "1.20.14", "2.0.0")
		if prepared.State != StateUnknown || cpxMode(prepared) != "" || len(prepared.ModeDefaultedItems) != 0 || cpxContains(prepared.Omissions, OmissionCrossplaneModeDefaulted) {
			t.Fatalf("%s prepared=%+v", name, prepared)
		}
	}
}

func TestPrepareCrossplane_OmittedModeNeverYieldsPipeline(t *testing.T) {
	for _, raw := range []string{cpxOmitted, cpxList(cpxPipeline, cpxOmitted), cpxList(cpxOmitted, cpxOmitted)} {
		prepared := cpxPrepare(t, raw, "1.20.14", "2.0.0")
		if cpxMode(prepared) != "resources" {
			t.Fatalf("raw=%s prepared=%+v", raw, prepared)
		}
	}
	// Explicit Pipeline on every Composition stays the only route to pipeline.
	if prepared := cpxPrepare(t, cpxList(cpxPipeline, cpxPipeline), "1.20.14", "2.0.0"); cpxMode(prepared) != "pipeline" || prepared.Reason != ReasonCrossplanePipelineMode || len(prepared.ModeDefaultedItems) != 0 {
		t.Fatalf("prepared=%+v", prepared)
	}
}

func TestPrepareCrossplane_MixedSelectionNamesOnlyTheDefaultedPosition(t *testing.T) {
	prepared := cpxPrepare(t, cpxList(cpxPipeline, cpxOmitted, cpxPipeline), "1.20.14", "2.0.0")
	if cpxMode(prepared) != "resources" || len(prepared.ModeDefaultedItems) != 1 || prepared.ModeDefaultedItems[0] != 2 || prepared.Reason != ReasonCrossplaneModeDefaulted {
		t.Fatalf("prepared=%+v", prepared)
	}
	// An explicit Resources witness keeps its own reason; the defaulted
	// position is still reported.
	prepared = cpxPrepare(t, cpxList(cpxOmitted, cpxResExplict), "1.20.14", "2.0.0")
	if prepared.Reason != ReasonCrossplaneResourcesMode || len(prepared.ModeDefaultedItems) != 1 || prepared.ModeDefaultedItems[0] != 1 {
		t.Fatalf("prepared=%+v", prepared)
	}
	// Pipeline plus a malformed mode is UNKNOWN, never pipeline.
	bad := `{` + cpxAPI + `,"metadata":{"name":"private-bad"},"spec":{"mode":null,"resources":[{"name":"a"}]}}`
	if prepared = cpxPrepare(t, cpxList(cpxPipeline, bad), "1.20.14", "2.0.0"); prepared.State != StateUnknown || cpxMode(prepared) != "" || (prepared.Reason != ReasonCrossplaneModeUnresolved && prepared.Reason != ReasonCrossplaneInputUnsupported) {
		t.Fatalf("prepared=%+v", prepared)
	}
}

func TestPrepareCrossplane_ExplicitPipelineIsNotBlockedFacts(t *testing.T) {
	prepared := cpxPrepare(t, cpxPipeline, "1.20.14", "2.0.0")
	if prepared.State != StatePrepared || cpxMode(prepared) != "pipeline" {
		t.Fatalf("prepared=%+v", prepared)
	}
}

func TestPrepareCrossplane_XRDSkipIsExactAndNeverImpliesSafety(t *testing.T) {
	for _, xrd := range []string{cpxXRD, cpxXRDv1} {
		prepared := cpxPrepare(t, cpxList(xrd, cpxResExplict), "1.20.14", "2.0.0")
		if cpxMode(prepared) != "resources" || !cpxContains(prepared.Omissions, OmissionCrossplaneXRDContentNotEvaluated) {
			t.Fatalf("XRD + Resources prepared=%+v", prepared)
		}
		prepared = cpxPrepare(t, cpxList(xrd, cpxPipeline), "1.20.14", "2.0.0")
		if cpxMode(prepared) != "pipeline" || !cpxContains(prepared.Omissions, OmissionCrossplaneXRDContentNotEvaluated) {
			t.Fatalf("XRD + Pipeline prepared=%+v", prepared)
		}
		if prepared = cpxPrepare(t, cpxList(xrd, cpxOmitted), "1.20.14", "2.0.0"); cpxMode(prepared) != "resources" || len(prepared.ModeDefaultedItems) != 1 || prepared.ModeDefaultedItems[0] != 1 {
			t.Fatalf("XRD + omitted prepared=%+v", prepared)
		}
	}
	usage := `{"apiVersion":"apiextensions.crossplane.io/v1alpha1","kind":"Usage","metadata":{"name":"private-usage"}}`
	for name, raw := range map[string]string{
		"xrd only":             cpxList(cpxXRD),
		"single xrd":           cpxXRD,
		"xrd and usage":        cpxList(cpxXRD, usage),
		"other group xrd":      cpxList(strings.Replace(cpxXRD, "apiextensions.crossplane.io", "apiextensions.example.io", 1), cpxPipeline),
		"crd kind":             cpxList(`{"apiVersion":"apiextensions.k8s.io/v1","kind":"CustomResourceDefinition","metadata":{"name":"private-crd"}}`, cpxPipeline),
		"crd kind crossplane":  cpxList(strings.Replace(cpxXRD, "CompositeResourceDefinition", "CustomResourceDefinition", 1), cpxPipeline),
		"xrd lowercase kind":   cpxList(strings.Replace(cpxXRD, "CompositeResourceDefinition", "compositeresourcedefinition", 1), cpxPipeline),
		"xrd no name":          cpxList(`{"apiVersion":"apiextensions.crossplane.io/v1","kind":"CompositeResourceDefinition","metadata":{}}`, cpxPipeline),
		"xrd no metadata":      cpxList(`{"apiVersion":"apiextensions.crossplane.io/v1","kind":"CompositeResourceDefinition"}`, cpxResExplict),
		"xrd empty name":       cpxList(`{"apiVersion":"apiextensions.crossplane.io/v1","kind":"CompositeResourceDefinition","metadata":{"name":""}}`, cpxPipeline),
		"xrd group no version": cpxList(`{"apiVersion":"apiextensions.crossplane.io","kind":"CompositeResourceDefinition","metadata":{"name":"x"}}`, cpxPipeline),
		"xrd typed list":       `{"apiVersion":"apiextensions.crossplane.io/v1","kind":"CompositeResourceDefinitionList","items":[]}`,
		"usage and pipeline":   cpxList(usage, cpxPipeline),
	} {
		prepared := cpxPrepare(t, raw, "1.20.14", "2.0.0")
		if prepared.State != StateUnknown || cpxMode(prepared) != "" {
			t.Fatalf("%s prepared=%+v", name, prepared)
		}
	}
	prepared := cpxPrepare(t, cpxList(cpxXRD), "1.20.14", "2.0.0")
	if prepared.Reason != ReasonCrossplaneSurfaceOther {
		t.Fatalf("xrd only reason=%s", prepared.Reason)
	}
}

func TestPrepareCrossplane_NoSelectedContentLeaksIntoOutput(t *testing.T) {
	prepared := cpxPrepare(t, cpxList(cpxXRD, cpxOmitted, cpxPipeline), "1.20.14", "2.0.0")
	text := string(prepared.CanonicalInputJSON) + strings.Join(prepared.Omissions, ",") + string(prepared.Reason)
	for _, canary := range []string{"canary-patch-text", "canary-xrd-schema", "private-"} {
		if strings.Contains(text, canary) {
			t.Fatalf("output carries %q: %s", canary, text)
		}
	}
}

func TestPrepareCrossplane_GuardReasonsNameTheFlag(t *testing.T) {
	cases := []struct {
		name         string
		distribution string
		schema       bool
		reason       Reason
	}{
		{"distribution missing", "", true, ReasonCrossplaneGuardUnresolved},
		{"distribution invalid", "vendor", true, ReasonCrossplaneGuardUnresolved},
		{"schema intent absent or false", CrossplaneDistributionOfficial, false, ReasonCrossplaneSchemaIntent},
		{"schema intent false custom", CrossplaneDistributionCustom, false, ReasonCrossplaneSchemaIntent},
	}
	for _, test := range cases {
		prepared, err := PrepareCrossplaneComposition([]byte(cpxResExplict), "1.20.14", "2.0.0", test.distribution, test.schema)
		if err != nil || prepared.State != StateUnknown || prepared.Reason != test.reason {
			t.Fatalf("%s prepared=%+v err=%v", test.name, prepared, err)
		}
		if strings.Contains(string(prepared.CanonicalInputJSON), `"boolValue":true`) && !test.schema {
			t.Fatalf("%s canonical=%s", test.name, prepared.CanonicalInputJSON)
		}
	}
	// A custom build with the intent declared stays prepared as before: the
	// rule's own applicability keeps it UNKNOWN.
	prepared, err := PrepareCrossplaneComposition([]byte(cpxPipeline), "1.20.14", "2.0.0", CrossplaneDistributionCustom, true)
	if err != nil || prepared.State != StatePrepared {
		t.Fatalf("prepared=%+v err=%v", prepared, err)
	}
}

func cpxContains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
