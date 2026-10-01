// SPDX-License-Identifier: AGPL-3.0-only

package cncfprepare

import (
	"strings"
	"unicode/utf8"
)

const (
	StrimziComponent              = "pkg:github/strimzi/strimzi-kafka-operator"
	StrimziDistributionFact       = "component.strimzi.distribution"
	StrimziExecutionSurfaceFact   = "component.strimzi.execution_surface"
	StrimziKafkaV1Beta2Fact       = "component.strimzi.kafka_v1beta2_api_present"
	StrimziTargetCRDAdmissionFact = "component.strimzi.target_kafka_crd_admission_required"

	StrimziDistributionOfficial = "official_upstream"
	StrimziDistributionCustom   = "custom_build"
	StrimziSurfaceKafkaResource = "kafka_custom_resource"
	StrimziSurfaceOther         = "other"

	StrimziFrom = "0.51.0"
	StrimziTo   = "1.0.0"

	strimziGroup             = "kafka.strimzi.io"
	strimziKafkaKind         = "Kafka"
	strimziRemovedAPIVersion = "kafka.strimzi.io/v1beta2"
	strimziTargetAPIVersion  = "kafka.strimzi.io/v1"
)

const (
	ReasonStrimziV1Beta2Present   Reason = "STRIMZI_KAFKA_V1BETA2_API_PRESENT"
	ReasonStrimziV1Beta2Absent    Reason = "STRIMZI_KAFKA_V1BETA2_API_ABSENT"
	ReasonStrimziSurfaceOther     Reason = "STRIMZI_SELECTED_SURFACE_NOT_KAFKA_CUSTOM_RESOURCE"
	ReasonStrimziGuardUnresolved  Reason = "STRIMZI_DISTRIBUTION_DECLARATION_MISSING"
	ReasonStrimziPairUnsupported  Reason = "STRIMZI_TRANSITION_NOT_REVIEWED"
	ReasonStrimziUnreviewedAPI    Reason = "STRIMZI_KAFKA_API_VERSION_UNREVIEWED"
	ReasonStrimziInputUnsupported Reason = "STRIMZI_KAFKA_RESOURCE_SHAPE_UNRESOLVED"
	ReasonStrimziTemplated        Reason = "STRIMZI_KAFKA_RENDERING_UNRESOLVED"
	ReasonStrimziPagination       Reason = "STRIMZI_KAFKA_LIST_PAGINATION_UNRESOLVED"
)

// PrepareStrimziKafkaResource minimizes one caller-selected rendered Kafka
// custom resource, or one flat v1 List of rendered resources, into the four
// facts the reviewed Strimzi 0.51.0 -> 1.0.0 rule already requires. It is not a
// CRD schema validator, an admission simulator, or a cluster reader: it decides
// only which Kafka API version the supplied documents literally use. Unresolved
// rendering, pagination, other kinds, and other served versions stay UNKNOWN.
func PrepareStrimziKafkaResource(raw []byte, from, to, distribution string, targetCRDAdmissionRequired bool) (Prepared, error) {
	if len(raw) == 0 || len(raw) > maxInputBytes || !utf8.Valid(raw) || !validVersionSyntax(from) || !validVersionSyntax(to) || from == to {
		return Prepared{}, ErrInvalid
	}
	facts := []inputFact{
		{ID: StrimziDistributionFact, State: "missing"},
		{ID: StrimziExecutionSurfaceFact, State: "unsupported"},
		{ID: StrimziKafkaV1Beta2Fact, State: "unsupported"},
		{ID: StrimziTargetCRDAdmissionFact, State: "declared", BoolValue: &targetCRDAdmissionRequired},
	}
	if distribution == StrimziDistributionOfficial || distribution == StrimziDistributionCustom {
		facts[0] = inputFact{ID: StrimziDistributionFact, State: "declared", EnumValue: distribution}
	}
	state, reason := StateUnknown, ReasonStrimziGuardUnresolved
	switch {
	case !strimziReviewedPair(from, to):
		reason = ReasonStrimziPairUnsupported
	case facts[0].State != "declared":
		reason = ReasonStrimziGuardUnresolved
	default:
		inspected := inspectStrimziKafkaResources(raw)
		reason = inspected.Reason
		if inspected.Surface != "" {
			facts[1] = inputFact{ID: StrimziExecutionSurfaceFact, State: "declared", EnumValue: inspected.Surface}
		}
		if inspected.Surface == StrimziSurfaceKafkaResource && inspected.Removed != nil {
			facts[2] = inputFact{ID: StrimziKafkaV1Beta2Fact, State: "declared", BoolValue: inspected.Removed}
			state = StatePrepared
		}
	}
	canonical, err := marshalComponentInput(StrimziComponent, from, to, facts)
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
			"SELECTED_KAFKA_RESOURCES_ARE_CALLER_SUPPLIED_NOT_LIVE_OBSERVATION",
			"CRD_INSTALLATION_ADMISSION_CONVERSION_OPERATOR_AND_RUNTIME_NOT_EVALUATED",
			OmissionNoWholeUpgrade,
		},
	}, nil
}

// strimziInspection reports the resolved surface and, when that surface is the
// reviewed Kafka custom-resource surface, whether the removed v1beta2 API is
// literally used. Removed stays nil whenever any selected document cannot be
// classified against the two reviewed served versions.
type strimziInspection struct {
	Surface string
	Removed *bool
	Reason  Reason
}

func inspectStrimziKafkaResources(raw []byte) strimziInspection {
	text := string(raw)
	if strings.Contains(text, "{{") || strings.Contains(text, "${") {
		return strimziInspection{Reason: ReasonStrimziTemplated}
	}
	value, err := decodeStrict(raw)
	if err != nil {
		return strimziInspection{Reason: ReasonStrimziInputUnsupported}
	}
	root, ok := value.(map[string]any)
	if !ok {
		return strimziInspection{Reason: ReasonStrimziInputUnsupported}
	}
	api, kind, ok := kubernetesGVK(root)
	if !ok {
		return strimziInspection{Reason: ReasonStrimziInputUnsupported}
	}
	documents := []map[string]any{root}
	if kind == "List" {
		if api != "v1" {
			return strimziInspection{Reason: ReasonStrimziInputUnsupported}
		}
		items, found := root["items"].([]any)
		if !found || len(items) == 0 {
			return strimziInspection{Reason: ReasonStrimziInputUnsupported}
		}
		paginated, metadataOK := kubernetesListPagination(root)
		if !metadataOK {
			return strimziInspection{Reason: ReasonStrimziInputUnsupported}
		}
		if paginated {
			return strimziInspection{Reason: ReasonStrimziPagination}
		}
		documents = make([]map[string]any, 0, len(items))
		for _, item := range items {
			document, ok := item.(map[string]any)
			if !ok {
				return strimziInspection{Reason: ReasonStrimziInputUnsupported}
			}
			documents = append(documents, document)
		}
	} else if strings.HasSuffix(kind, "List") {
		// A typed list can carry items this one-level contract never sees.
		return strimziInspection{Reason: ReasonStrimziInputUnsupported}
	}
	removed := false
	for _, document := range documents {
		api, kind, ok := kubernetesGVK(document)
		if !ok || kind == "List" || strings.HasSuffix(kind, "List") {
			return strimziInspection{Reason: ReasonStrimziInputUnsupported}
		}
		group, _, hasVersion := strings.Cut(api, "/")
		if !hasVersion || group != strimziGroup || kind != strimziKafkaKind {
			// KafkaTopic, KafkaUser, and unrelated objects are outside the
			// reviewed surface. The rule's applicability guard then keeps the
			// whole selection UNKNOWN rather than silently ignoring them.
			return strimziInspection{Surface: StrimziSurfaceOther, Reason: ReasonStrimziSurfaceOther}
		}
		if !strimziNamespacedResource(document) {
			return strimziInspection{Reason: ReasonStrimziInputUnsupported}
		}
		switch api {
		case strimziRemovedAPIVersion:
			removed = true
		case strimziTargetAPIVersion:
		default:
			// The two reviewed served versions are v1beta2 and v1. Any other
			// kafka.strimzi.io Kafka version cannot establish either predicate.
			return strimziInspection{Reason: ReasonStrimziUnreviewedAPI}
		}
	}
	reason := ReasonStrimziV1Beta2Absent
	if removed {
		reason = ReasonStrimziV1Beta2Present
	}
	return strimziInspection{Surface: StrimziSurfaceKafkaResource, Removed: &removed, Reason: reason}
}

// strimziNamespacedResource keeps a supplied Kafka object structurally
// meaningful without asserting that it was admitted by any cluster.
func strimziNamespacedResource(document map[string]any) bool {
	metadata, ok := document["metadata"].(map[string]any)
	if !ok {
		return false
	}
	name, nameOK := metadata["name"].(string)
	namespace, namespaceOK := metadata["namespace"].(string)
	return nameOK && name != "" && namespaceOK && namespace != ""
}

func strimziReviewedPair(from, to string) bool {
	return from == StrimziFrom && to == StrimziTo
}
