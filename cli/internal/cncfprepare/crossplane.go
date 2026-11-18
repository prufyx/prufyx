// SPDX-License-Identifier: AGPL-3.0-only

package cncfprepare

import (
	"fmt"
	"strconv"
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

	// CrossplaneFrom and CrossplaneTo are the original reviewed anchor pair;
	// the cited tables above hold the full reviewed range around it.
	CrossplaneFrom = "1.20.0"
	CrossplaneTo   = "2.0.0"

	crossplaneGroup            = "apiextensions.crossplane.io"
	crossplaneCompositionKind  = "Composition"
	crossplaneTargetAPIVersion = "apiextensions.crossplane.io/v1"
	crossplaneLiteralPipeline  = "Pipeline"
	crossplaneLiteralResources = "Resources"

	crossplaneXRDKind = "CompositeResourceDefinition"
)

// Omissions the Crossplane preparer adds only when they apply, plus the one
// that always applies: the reviewed rule range covers whole minor series, so it
// admits patch releases newer than the last cited tag; this preparer's table
// of cited versions is the gate for the check route.
const (
	OmissionCrossplaneRangeAdmitsUnlistedPatches = "RULE_RANGE_ADMITS_UNLISTED_PATCH_VERSIONS_PREPARER_TABLE_IS_THE_GATE"
	OmissionCrossplaneModeDefaulted              = "MODE_DEFAULT_FROM_PINNED_FROM_VERSION_CRD"
	OmissionCrossplaneXRDContentNotEvaluated     = "XRD_CONTENT_NOT_EVALUATED"
)

// crossplaneCitedSeries lists, per minor series, the last patch release whose
// Composition CRD bytes were read and pinned (patch 0 through last, every one
// cited). A version outside this table is never prepared, whatever a rule range
// admits. Keep it equal to the evidence rows of the rule sources; a test ties
// the table to the shipped rule ranges.
type crossplaneCitedSeries struct {
	major, minor, last uint32
}

var (
	crossplaneCitedFromSeries = []crossplaneCitedSeries{{1, 18, 5}, {1, 19, 3}, {1, 20, 14}}
	crossplaneCitedToSeries   = []crossplaneCitedSeries{{2, 0, 8}}
)

// CrossplaneCitedVersions returns every cited from and to version in the
// preparer table, for the rule-range drift test.
func CrossplaneCitedVersions() (from, to []string) {
	expand := func(series []crossplaneCitedSeries) []string {
		var out []string
		for _, entry := range series {
			for patch := uint32(0); patch <= entry.last; patch++ {
				out = append(out, fmt.Sprintf("%d.%d.%d", entry.major, entry.minor, patch))
			}
		}
		return out
	}
	return expand(crossplaneCitedFromSeries), expand(crossplaneCitedToSeries)
}

func crossplaneCited(series []crossplaneCitedSeries, version string) bool {
	if !validVersionSyntax(version) {
		return false
	}
	parts := strings.Split(version, ".")
	numbers := [3]uint32{}
	for index, part := range parts {
		value, err := strconv.ParseUint(part, 10, 32)
		if err != nil {
			return false
		}
		numbers[index] = uint32(value)
	}
	for _, entry := range series {
		if numbers[0] == entry.major && numbers[1] == entry.minor && numbers[2] <= entry.last {
			return true
		}
	}
	return false
}

const (
	ReasonCrossplaneResourcesMode    Reason = "CROSSPLANE_COMPOSITION_RESOURCES_MODE_DECLARED"
	ReasonCrossplanePipelineMode     Reason = "CROSSPLANE_COMPOSITION_PIPELINE_MODE_DECLARED"
	ReasonCrossplaneSurfaceOther     Reason = "CROSSPLANE_SELECTED_SURFACE_NOT_COMPOSITION"
	ReasonCrossplaneGuardUnresolved  Reason = "CROSSPLANE_DISTRIBUTION_DECLARATION_MISSING"
	ReasonCrossplaneSchemaIntent     Reason = "CROSSPLANE_SCHEMA_VALIDATION_NOT_DECLARED"
	ReasonCrossplaneModeDefaulted    Reason = "CROSSPLANE_COMPOSITION_MODE_DEFAULTED_RESOURCES"
	ReasonCrossplanePairUnsupported  Reason = "CROSSPLANE_TRANSITION_NOT_REVIEWED"
	ReasonCrossplaneUnreviewedAPI    Reason = "CROSSPLANE_COMPOSITION_API_VERSION_UNREVIEWED"
	ReasonCrossplaneModeUnresolved   Reason = "CROSSPLANE_COMPOSITION_MODE_UNRESOLVED"
	ReasonCrossplaneInputUnsupported Reason = "CROSSPLANE_COMPOSITION_SHAPE_UNRESOLVED"
	ReasonCrossplaneTemplated        Reason = "CROSSPLANE_COMPOSITION_RENDERING_UNRESOLVED"
	ReasonCrossplanePagination       Reason = "CROSSPLANE_COMPOSITION_LIST_PAGINATION_UNRESOLVED"
)

// PrepareCrossplaneComposition minimizes one caller-selected rendered
// Composition custom resource, or one flat v1 List of rendered resources, into
// the three facts the reviewed Crossplane 1.18-1.20 -> 2.0 rules require. It is
// not a CRD schema validator, an admission simulator, or a cluster reader: it
// decides only which Composition mode the supplied documents declare. A mode
// is resolved by default in exactly one case: spec.mode is absent, the from
// version is in the cited table (whose pinned Composition CRD defaults the
// field to Resources), the Composition is apiextensions.crossplane.io/v1, and
// spec.resources is an array with at least one element while spec.pipeline is
// absent. The default can only produce the fact value resources, never
// pipeline. Unresolved rendering, pagination, other kinds, and other served
// versions stay UNKNOWN. CompositeResourceDefinition documents (exact group and
// kind) are skipped without reading their content.
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
	omissions := []string{
		"SELECTED_COMPOSITIONS_ARE_CALLER_SUPPLIED_NOT_LIVE_OBSERVATION",
		"TARGET_CRD_INSTALLATION_ADMISSION_CONVERSION_AND_RUNTIME_NOT_EVALUATED",
		OmissionCrossplaneRangeAdmitsUnlistedPatches,
	}
	state, reason := StateUnknown, ReasonCrossplaneGuardUnresolved
	var defaulted []int
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
			if !schemaValidationRequired {
				// The intent guard is the caller's declaration; without it the
				// rule is not applicable and no verdict may follow.
				state, reason = StateUnknown, ReasonCrossplaneSchemaIntent
			}
		}
		if len(inspected.Defaulted) > 0 {
			defaulted = inspected.Defaulted
			omissions = append(omissions, OmissionCrossplaneModeDefaulted)
		}
		if inspected.XRDSkipped {
			omissions = append(omissions, OmissionCrossplaneXRDContentNotEvaluated)
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
		Omissions:          append(omissions, OmissionNoWholeUpgrade),
		ModeDefaultedItems: defaulted,
	}, nil
}

// crossplaneInspection reports the resolved Composition mode for the whole
// caller-selected set. Mode stays empty whenever any selected document cannot
// be classified against the two reviewed mode literals.
type crossplaneInspection struct {
	Mode   string
	Reason Reason
	// Defaulted holds the 1-based positions of the selected Compositions whose
	// mode came from the pinned from-version CRD default. XRDSkipped is true
	// when a CompositeResourceDefinition was skipped unread.
	Defaulted  []int
	XRDSkipped bool
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
	explicitResources := false
	compositions := 0
	var defaulted []int
	xrdSkipped := false
	for _, document := range documents {
		api, kind, ok := kubernetesGVK(document)
		if !ok || kind == "List" || strings.HasSuffix(kind, "List") {
			return crossplaneInspection{Reason: ReasonCrossplaneInputUnsupported}
		}
		group, _, hasVersion := strings.Cut(api, "/")
		if hasVersion && group == crossplaneGroup && kind == crossplaneXRDKind {
			// Exact group and kind only. Read for apiVersion, kind and name;
			// nothing else is interpreted or retained, and an XRD says nothing
			// about any Composition mode.
			if !crossplaneNamedResource(document) {
				return crossplaneInspection{Reason: ReasonCrossplaneInputUnsupported}
			}
			xrdSkipped = true
			continue
		}
		if !hasVersion || group != crossplaneGroup || kind != crossplaneCompositionKind {
			// Usage, EnvironmentConfig, claims, lookalike kinds in other
			// groups, and unrelated objects are outside the reviewed surface.
			// The whole selection then stays UNKNOWN rather than silently
			// ignoring them.
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
		compositions++
		mode, fromDefault, ok := crossplaneCompositionMode(document)
		if !ok {
			// A present but unreviewed spec.mode, or an omitted one outside the
			// single admitted default shape, is never resolved.
			return crossplaneInspection{Reason: ReasonCrossplaneModeUnresolved}
		}
		if mode == crossplaneLiteralResources {
			resources = true
			if !fromDefault {
				explicitResources = true
			}
		}
		if fromDefault {
			defaulted = append(defaulted, compositions)
		}
	}
	if compositions == 0 {
		return crossplaneInspection{Reason: ReasonCrossplaneSurfaceOther, XRDSkipped: xrdSkipped}
	}
	if resources {
		reason := ReasonCrossplaneResourcesMode
		if len(defaulted) > 0 && !explicitResources {
			reason = ReasonCrossplaneModeDefaulted
		}
		return crossplaneInspection{Mode: CrossplaneModeResources, Reason: reason, Defaulted: defaulted, XRDSkipped: xrdSkipped}
	}
	return crossplaneInspection{Mode: CrossplaneModePipeline, Reason: ReasonCrossplanePipelineMode, XRDSkipped: xrdSkipped}
}

// crossplaneCompositionMode returns the Composition mode literal. A present
// spec.mode must be exactly one of the two reviewed CRD enum literals. When the
// key is absent, the mode is the from-version CRD default (Resources) only for
// a spec that carries spec.resources as an array with at least one element and
// no spec.pipeline key; only presence and array length are read. The caller
// guarantees the from-version is in the cited table and the apiVersion is v1.
func crossplaneCompositionMode(document map[string]any) (mode string, fromDefault, ok bool) {
	spec, isMap := document["spec"].(map[string]any)
	if !isMap {
		return "", false, false
	}
	value, present := spec["mode"]
	if present {
		literal, isString := value.(string)
		if !isString || (literal != crossplaneLiteralPipeline && literal != crossplaneLiteralResources) {
			return "", false, false
		}
		return literal, false, true
	}
	if _, hasPipeline := spec["pipeline"]; hasPipeline {
		return "", false, false
	}
	items, isArray := spec["resources"].([]any)
	if !isArray || len(items) == 0 {
		return "", false, false
	}
	return crossplaneLiteralResources, true, true
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
	return crossplaneCited(crossplaneCitedFromSeries, from) && crossplaneCited(crossplaneCitedToSeries, to)
}
