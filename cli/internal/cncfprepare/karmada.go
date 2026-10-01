// SPDX-License-Identifier: AGPL-3.0-only

package cncfprepare

import "unicode/utf8"

const (
	KarmadaComponent        = "pkg:github/karmada-io/karmada"
	KarmadaDistributionFact = "component.karmada.distribution"
	KarmadaSurfaceFact      = "component.karmada.execution_surface"
	KarmadaLegacyFact       = "component.karmada.removed_application_purge_mode_present"
	KarmadaAdmissionFact    = "component.karmada.target_policy_crd_admission_required"
	KarmadaFrom             = "1.18.3"
	KarmadaTo               = "1.19.0"

	KarmadaDistributionOfficial = "official_upstream"
	KarmadaDistributionCustom   = "custom_build"
	KarmadaSurface              = "karmada_policy_application_failover"
	KarmadaAdmissionRequired    = "required"
	KarmadaAdmissionDisabled    = "disabled"
	karmadaAPIVersion           = "policy.karmada.io/v1alpha1"
)

var ErrInvalidKarmada = ErrInvalid

const (
	ReasonKarmadaLegacyWitness   Reason = "KARMADA_LEGACY_PURGE_MODE_WITNESS"
	ReasonKarmadaPathMissing     Reason = "KARMADA_APPLICATION_FAILOVER_PATH_MISSING"
	ReasonKarmadaPathUnsupported Reason = "KARMADA_APPLICATION_FAILOVER_PATH_UNSUPPORTED"
	ReasonKarmadaUnsupportedPair Reason = "UNSUPPORTED_VERSION_PAIR"
	ReasonKarmadaGuardMissing    Reason = "GUARD_DECLARATION_MISSING"
)

// PrepareKarmada derives a proposed-side legacy-value witness from exactly one
// rendered Karmada policy resource. It can establish legacy presence, never
// aggregate absence across all proposed resources, so it never emits false.
func PrepareKarmada(raw []byte, from, to, distribution, admission string) (Prepared, error) {
	if len(raw) == 0 || len(raw) > maxInputBytes || !utf8.Valid(raw) ||
		!validVersionSyntax(from) || !validVersionSyntax(to) || from == to ||
		!validKarmadaGuards(distribution, admission) {
		return Prepared{}, ErrInvalidKarmada
	}
	value, err := decodeStrictAllowNull(raw)
	if err != nil {
		return Prepared{}, ErrInvalidKarmada
	}
	root, ok := value.(map[string]any)
	if !ok || allowFields(root, map[string]bool{"apiVersion": true, "kind": true, "metadata": true, "spec": true}) != nil {
		return Prepared{}, ErrInvalidKarmada
	}
	apiVersion, ok := karmadaRequiredString(root, "apiVersion")
	if !ok || apiVersion != karmadaAPIVersion {
		return Prepared{}, ErrInvalidKarmada
	}
	kind, ok := karmadaRequiredString(root, "kind")
	if !ok || (kind != "PropagationPolicy" && kind != "ClusterPropagationPolicy") {
		return Prepared{}, ErrInvalidKarmada
	}
	if metadata, present := root["metadata"]; present {
		if _, ok := metadata.(map[string]any); !ok {
			return Prepared{}, ErrInvalidKarmada
		}
	}
	spec, ok := root["spec"].(map[string]any)
	if !ok {
		return Prepared{}, ErrInvalidKarmada
	}

	surfaceState, conditionState, conditionValue, reason := inspectKarmadaPurgeMode(spec)
	if from != KarmadaFrom || to != KarmadaTo {
		surfaceState, conditionState, conditionValue, reason = "unsupported", "unsupported", nil, ReasonKarmadaUnsupportedPair
	}
	state := StateUnknown
	if conditionValue != nil {
		state = StatePrepared
	}
	if distribution == "" || admission == "" {
		state, reason = StateUnknown, ReasonKarmadaGuardMissing
	}
	canonical, err := marshalKarmadaInput(from, to, distribution, admission, surfaceState, conditionState, conditionValue)
	if err != nil {
		return Prepared{}, ErrInvalidKarmada
	}
	return Prepared{
		CanonicalInputJSON: canonical,
		SourceDigest:       digestBytes(raw),
		InputDigest:        digestBytes(canonical),
		State:              state,
		Reason:             reason,
		Omissions: []string{
			"CRD_SCHEMA_VALIDATION_NOT_PERFORMED",
			"STORED_RESOURCE_INSPECTION_NOT_PERFORMED",
			"RUNTIME_BEHAVIOR_NOT_EVALUATED",
			OmissionNoLiveObservation,
			OmissionNoWholeUpgrade,
		},
	}, nil
}

func validKarmadaGuards(distribution, admission string) bool {
	return (distribution == "" || distribution == KarmadaDistributionOfficial || distribution == KarmadaDistributionCustom) &&
		(admission == "" || admission == KarmadaAdmissionRequired || admission == KarmadaAdmissionDisabled)
}

func karmadaRequiredString(object map[string]any, key string) (string, bool) {
	value, exists := object[key]
	if !exists {
		return "", false
	}
	text, ok := value.(string)
	return text, ok
}

func inspectKarmadaPurgeMode(spec map[string]any) (surfaceState, conditionState string, conditionValue *bool, reason Reason) {
	failover, present := spec["failover"]
	if !present {
		return "missing", "missing", nil, ReasonKarmadaPathMissing
	}
	failoverObject, ok := failover.(map[string]any)
	if !ok {
		return "unsupported", "unsupported", nil, ReasonKarmadaPathUnsupported
	}
	application, present := failoverObject["application"]
	if !present {
		return "missing", "missing", nil, ReasonKarmadaPathMissing
	}
	applicationObject, ok := application.(map[string]any)
	if !ok {
		return "unsupported", "unsupported", nil, ReasonKarmadaPathUnsupported
	}
	value, present := applicationObject["purgeMode"]
	if !present {
		return "declared", "missing", nil, ReasonKarmadaPathMissing
	}
	mode, ok := value.(string)
	if !ok || mode == "" {
		return "declared", "unsupported", nil, ReasonKarmadaPathUnsupported
	}
	switch mode {
	case "Immediately", "Graciously":
		legacy := true
		return "declared", "declared", &legacy, ReasonKarmadaLegacyWitness
	default:
		// A singleton safe or unrecognized value cannot prove that all proposed
		// in-scope resources are legacy-free.
		return "declared", "unsupported", nil, ReasonKarmadaPathUnsupported
	}
}

func marshalKarmadaInput(from, to, distribution, admission, surfaceState, conditionState string, conditionValue *bool) ([]byte, error) {
	facts := make([]inputFact, 0, 4)
	if distribution == "" {
		facts = append(facts, inputFact{ID: KarmadaDistributionFact, State: "missing"})
	} else {
		facts = append(facts, inputFact{ID: KarmadaDistributionFact, State: "declared", EnumValue: distribution})
	}
	facts = append(facts, inputFact{ID: KarmadaSurfaceFact, State: surfaceState})
	if surfaceState == "declared" {
		facts[len(facts)-1].EnumValue = KarmadaSurface
	}
	facts = append(facts, inputFact{ID: KarmadaLegacyFact, State: conditionState, BoolValue: conditionValue})
	if admission == "" {
		facts = append(facts, inputFact{ID: KarmadaAdmissionFact, State: "missing"})
	} else {
		value := admission == KarmadaAdmissionRequired
		facts = append(facts, inputFact{ID: KarmadaAdmissionFact, State: "declared", BoolValue: &value})
	}
	return marshalComponentInput(KarmadaComponent, from, to, facts)
}
