// SPDX-License-Identifier: AGPL-3.0-only

package cncfprepare

import (
	"strings"
	"unicode/utf8"
)

const (
	CrossplaneComponent            = "pkg:github/crossplane/crossplane"
	CrossplaneCompositionModeFact  = "component.crossplane.composition_mode"
	CrossplaneDistributionFact     = "component.crossplane.distribution"
	CrossplaneSchemaValidationFact = "component.crossplane.schema_validation_required"

	CrossplaneDistributionOfficial = "official_upstream"
	CrossplaneDistributionCustom   = "custom_build"
	CrossplaneModePipeline         = "pipeline"
	CrossplaneModeResources        = "resources"

	CrossplaneFrom = "1.20.0"
	CrossplaneTo   = "2.0.0"

	crossplaneGroup            = "apiextensions.crossplane.io"
	crossplaneCompositionKind  = "Composition"
	crossplaneTargetAPIVersion = "apiextensions.crossplane.io/v1"
	crossplaneLiteralPipeline  = "Pipeline"
	crossplaneLiteralResources = "Resources"
)

const (
	ReasonCrossplaneResourcesMode    Reason = "CROSSPLANE_COMPOSITION_RESOURCES_MODE_DECLARED"
	ReasonCrossplanePipelineMode     Reason = "CROSSPLANE_COMPOSITION_PIPELINE_MODE_DECLARED"
	ReasonCrossplaneSurfaceOther     Reason = "CROSSPLANE_SELECTED_SURFACE_NOT_COMPOSITION"
	ReasonCrossplaneGuardUnresolved  Reason = "CROSSPLANE_DISTRIBUTION_DECLARATION_MISSING"
	ReasonCrossplanePairUnsupported  Reason = "CROSSPLANE_TRANSITION_NOT_REVIEWED"
	ReasonCrossplaneUnreviewedAPI    Reason = "CROSSPLANE_COMPOSITION_API_VERSION_UNREVIEWED"
	ReasonCrossplaneModeUnresolved   Reason = "CROSSPLANE_COMPOSITION_MODE_UNRESOLVED"
	ReasonCrossplaneInputUnsupported Reason = "CROSSPLANE_COMPOSITION_SHAPE_UNRESOLVED"
	ReasonCrossplaneTemplated        Reason = "CROSSPLANE_COMPOSITION_RENDERING_UNRESOLVED"
	ReasonCrossplanePagination       Reason = "CROSSPLANE_COMPOSITION_LIST_PAGINATION_UNRESOLVED"
)

// PrepareCrossplaneComposition minimizes one caller-selected rendered
// Composition custom resource, or one flat v1 List of rendered resources, into
// the three facts the reviewed Crossplane 1.20.0 -> 2.0.0 rule already
// requires. It is not a CRD schema validator, an admission simulator, or a
// cluster reader: it decides only which Composition mode the supplied
// documents literally declare. An omitted spec.mode is never resolved to a
// historical default; unresolved rendering, pagination, other kinds, and other
// served versions stay UNKNOWN.
func PrepareCrossplaneComposition(raw []byte, from, to, distribution string, schemaValidationRequired bool) (Prepared, error) {
	if len(raw) == 0 || len(raw) > maxInputBytes || !utf8.Valid(raw) || !validVersionSyntax(from) || !validVersionSyntax(to) || from == to {
		return Prepared{}, ErrInvalid
	}
	facts := []inputFact{
		{ID: CrossplaneCompositionModeFact, State: "unsupported"},
		{ID: CrossplaneDistributionFact, State: "missing"},
		{ID: CrossplaneSchemaValidationFact, State: "declared", BoolValue: &schemaValidationRequired},
	}
	if distribution == CrossplaneDistributionOfficial || distribution == CrossplaneDistributionCustom {
		facts[1] = inputFact{ID: CrossplaneDistributionFact, State: "declared", EnumValue: distribution}
	}
	state, reason := StateUnknown, ReasonCrossplaneGuardUnresolved
	switch {
	case !crossplaneReviewedPair(from, to):
		reason = ReasonCrossplanePairUnsupported
	case facts[1].State != "declared":
		reason = ReasonCrossplaneGuardUnresolved
	default:
		inspected := inspectCrossplaneCompositions(raw)
		reason = inspected.Reason
		if inspected.Mode != "" {
			facts[0] = inputFact{ID: CrossplaneCompositionModeFact, State: "declared", EnumValue: inspected.Mode}
			state = StatePrepared
		}
	}
	canonical, err := marshalComponentInput(CrossplaneComponent, from, to, facts)
	if err != nil {
		return Prepared{}, ErrInvalid
	}
	return Prepared{
		CanonicalInputJSON: canonical,
		SourceDigest:       digestBytes(raw),
		InputDigest:        digestBytes(canonical),
		State:              state,
		Reason:             reason,
		Omissions: []string{
			"SELECTED_COMPOSITIONS_ARE_CALLER_SUPPLIED_NOT_LIVE_OBSERVATION",
			"TARGET_CRD_INSTALLATION_ADMISSION_CONVERSION_AND_RUNTIME_NOT_EVALUATED",
			OmissionNoWholeUpgrade,
		},
	}, nil
}

// crossplaneInspection reports the resolved Composition mode for the whole
// caller-selected set. Mode stays empty whenever any selected document cannot
// be classified against the two reviewed mode literals.
type crossplaneInspection struct {
	Mode   string
	Reason Reason
}

func inspectCrossplaneCompositions(raw []byte) crossplaneInspection {
	text := string(raw)
	if strings.Contains(text, "{{") || strings.Contains(text, "${") {
		return crossplaneInspection{Reason: ReasonCrossplaneTemplated}
	}
	value, err := decodeStrict(raw)
	if err != nil {
		return crossplaneInspection{Reason: ReasonCrossplaneInputUnsupported}
	}
	root, ok := value.(map[string]any)
	if !ok {
		return crossplaneInspection{Reason: ReasonCrossplaneInputUnsupported}
	}
	api, kind, ok := kubernetesGVK(root)
	if !ok {
		return crossplaneInspection{Reason: ReasonCrossplaneInputUnsupported}
	}
	documents := []map[string]any{root}
	if kind == "List" {
		if api != "v1" {
			return crossplaneInspection{Reason: ReasonCrossplaneInputUnsupported}
		}
		items, found := root["items"].([]any)
		if !found || len(items) == 0 {
			return crossplaneInspection{Reason: ReasonCrossplaneInputUnsupported}
		}
		paginated, metadataOK := kubernetesListPagination(root)
		if !metadataOK {
			return crossplaneInspection{Reason: ReasonCrossplaneInputUnsupported}
		}
		if paginated {
			return crossplaneInspection{Reason: ReasonCrossplanePagination}
		}
		documents = make([]map[string]any, 0, len(items))
		for _, item := range items {
			document, ok := item.(map[string]any)
			if !ok {
				return crossplaneInspection{Reason: ReasonCrossplaneInputUnsupported}
			}
			documents = append(documents, document)
		}
	} else if strings.HasSuffix(kind, "List") {
		// A typed list can carry items this one-level contract never sees.
		return crossplaneInspection{Reason: ReasonCrossplaneInputUnsupported}
	}
	resources := false
	for _, document := range documents {
		api, kind, ok := kubernetesGVK(document)
		if !ok || kind == "List" || strings.HasSuffix(kind, "List") {
			return crossplaneInspection{Reason: ReasonCrossplaneInputUnsupported}
		}
		group, _, hasVersion := strings.Cut(api, "/")
		if !hasVersion || group != crossplaneGroup || kind != crossplaneCompositionKind {
			// CompositeResourceDefinition, Usage, claims, and unrelated objects
			// are outside the reviewed surface. The whole selection then stays
			// UNKNOWN rather than silently ignoring them.
			return crossplaneInspection{Reason: ReasonCrossplaneSurfaceOther}
		}
		if !crossplaneNamedResource(document) {
			return crossplaneInspection{Reason: ReasonCrossplaneInputUnsupported}
		}
		if api != crossplaneTargetAPIVersion {
			// The reviewed Composition CRD span pins one served version. Any
			// other apiextensions.crossplane.io Composition version cannot
			// establish either mode predicate.
			return crossplaneInspection{Reason: ReasonCrossplaneUnreviewedAPI}
		}
		mode, ok := crossplaneCompositionMode(document)
		if !ok {
			// An omitted or unreviewed spec.mode is not resolved to any
			// historical default. Inferring one would author a new claim.
			return crossplaneInspection{Reason: ReasonCrossplaneModeUnresolved}
		}
		if mode == crossplaneLiteralResources {
			resources = true
		}
	}
	if resources {
		return crossplaneInspection{Mode: CrossplaneModeResources, Reason: ReasonCrossplaneResourcesMode}
	}
	return crossplaneInspection{Mode: CrossplaneModePipeline, Reason: ReasonCrossplanePipelineMode}
}

// crossplaneCompositionMode returns the literal spec.mode value only when it is
// exactly one of the two reviewed CRD enum literals.
func crossplaneCompositionMode(document map[string]any) (string, bool) {
	spec, ok := document["spec"].(map[string]any)
	if !ok {
		return "", false
	}
	mode, ok := spec["mode"].(string)
	if !ok || (mode != crossplaneLiteralPipeline && mode != crossplaneLiteralResources) {
		return "", false
	}
	return mode, true
}

// crossplaneNamedResource keeps a supplied Composition structurally meaningful
// without asserting that it was admitted by any cluster. Composition is
// cluster-scoped, so no namespace is required or expected.
func crossplaneNamedResource(document map[string]any) bool {
	metadata, ok := document["metadata"].(map[string]any)
	if !ok {
		return false
	}
	name, nameOK := metadata["name"].(string)
	return nameOK && name != ""
}

func crossplaneReviewedPair(from, to string) bool {
	return from == CrossplaneFrom && to == CrossplaneTo
}
