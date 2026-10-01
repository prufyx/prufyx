// SPDX-License-Identifier: AGPL-3.0-only

package cncfprepare

import (
	"strings"
	"unicode/utf8"
)

const (
	KEDAComponent              = "pkg:github/kedacore/keda"
	KEDAExternalScalerFact     = "component.keda.external_scaler_present"
	KEDALegacyTLSTransportFact = "component.keda.legacy_tls_cert_file_required_for_transport"

	KEDADeclarationRequired    = "true"
	KEDADeclarationNotRequired = "false"

	KEDAFrom = "2.16.0"
	KEDATo   = "2.17.0"

	kedaGroup                   = "keda.sh"
	kedaScaledObjectKind        = "ScaledObject"
	kedaTargetAPIVersion        = "keda.sh/v1alpha1"
	kedaExternalTriggerType     = "external"
	kedaExternalPushTriggerType = "external-push"
	kedaLegacyTLSCertFileKey    = "tlsCertFile"
)

const (
	ReasonKEDAPairUnsupported      Reason = "KEDA_TRANSITION_NOT_REVIEWED"
	ReasonKEDASelectionIncomplete  Reason = "KEDA_SELECTION_COMPLETENESS_DECLARATION_MISSING"
	ReasonKEDATemplated            Reason = "KEDA_SCALED_OBJECT_RENDERING_UNRESOLVED"
	ReasonKEDAInputUnsupported     Reason = "KEDA_SCALED_OBJECT_SHAPE_UNRESOLVED"
	ReasonKEDAPagination           Reason = "KEDA_SCALED_OBJECT_LIST_PAGINATION_UNRESOLVED"
	ReasonKEDASurfaceOther         Reason = "KEDA_SELECTED_SURFACE_NOT_SCALED_OBJECT"
	ReasonKEDAUnreviewedAPI        Reason = "KEDA_SCALED_OBJECT_API_VERSION_UNREVIEWED"
	ReasonKEDAExternalScalerAbsent Reason = "KEDA_EXTERNAL_SCALER_TRIGGER_ABSENT"
	ReasonKEDATransportUndeclared  Reason = "KEDA_LEGACY_TLS_TRANSPORT_DECLARATION_MISSING"
	ReasonKEDATransportConflict    Reason = "KEDA_LEGACY_TLS_TRANSPORT_DECLARATION_CONFLICTS_WITH_SELECTION"
	ReasonKEDATransportRequired    Reason = "KEDA_LEGACY_TLS_TRANSPORT_REQUIRED_DECLARED"
	ReasonKEDATransportNotRequired Reason = "KEDA_LEGACY_TLS_TRANSPORT_NOT_REQUIRED_DECLARED"
	ReasonKEDALegacyCertFileAbsent Reason = "KEDA_LEGACY_TLS_CERT_FILE_METADATA_ABSENT"
)

// PrepareKEDAScaledObject minimizes one caller-selected rendered ScaledObject
// custom resource, or one flat v1 List of rendered resources, into the two
// facts the reviewed KEDA 2.16.0 -> 2.17.0 rule already requires.
//
// It authors no new compatibility claim, and it deliberately derives less from
// the document than a reader might expect. The reviewed condition fact states
// in its own description that a raw tlsCertFile metadata field can still be
// forwarded to the external scaler and is therefore not sufficient to
// establish reliance on the removed direct transport. This adapter honors that
// exactly: it never turns the presence of tlsCertFile into a true condition
// fact. Presence makes the condition an explicit operator declaration; only its
// definite absence across the whole declared-complete selection, with nothing
// able to supply it out of band, derives false.
//
// What is derived natively is the rule's applicability guard: whether the
// selected ScaledObject set declares an External Scaler trigger at all.
//
// It is not a CRD schema validator, an admission simulator, or a cluster
// reader. An unreviewed pair, an undeclared selection scope, another kind,
// another served version, unresolved rendering, pagination, a trigger whose
// effective metadata could come from a TriggerAuthentication reference, and an
// unparseable shape all stay UNKNOWN rather than becoming a negative-presence
// PASS.
func PrepareKEDAScaledObject(raw []byte, from, to, legacyTransportDeclaration string, selectionComplete bool) (Prepared, error) {
	if len(raw) == 0 || len(raw) > maxInputBytes || !utf8.Valid(raw) || !validVersionSyntax(from) || !validVersionSyntax(to) || from == to {
		return Prepared{}, ErrInvalid
	}
	if legacyTransportDeclaration != "" && legacyTransportDeclaration != KEDADeclarationRequired && legacyTransportDeclaration != KEDADeclarationNotRequired {
		return Prepared{}, ErrInvalid
	}
	facts := []inputFact{
		{ID: KEDAExternalScalerFact, State: "unsupported"},
		{ID: KEDALegacyTLSTransportFact, State: "unsupported"},
	}
	state, reason := StateUnknown, ReasonKEDAPairUnsupported
	switch {
	case !kedaReviewedPair(from, to):
		reason = ReasonKEDAPairUnsupported
	case !selectionComplete:
		// Deriving "no external scaler declares tlsCertFile" from a selection
		// the caller has not declared complete would be exactly the
		// negative-presence PASS this route must never emit.
		reason = ReasonKEDASelectionIncomplete
	default:
		inspected := inspectKEDAScaledObjects(raw)
		reason = inspected.Reason
		if inspected.ExternalScalerPresent != nil {
			facts[0] = inputFact{ID: KEDAExternalScalerFact, State: "declared", BoolValue: inspected.ExternalScalerPresent}
			if *inspected.ExternalScalerPresent {
				required, resolved, conditionReason := kedaLegacyTransportFact(inspected, legacyTransportDeclaration)
				reason = conditionReason
				if resolved {
					facts[1] = inputFact{ID: KEDALegacyTLSTransportFact, State: "declared", BoolValue: &required}
					state = StatePrepared
				}
			}
			// A selection with no External Scaler trigger declares the guard
			// false and stops. The condition fact is never declared from it:
			// the rule's own applicability guard then keeps the claim UNKNOWN.
		}
	}
	canonical, err := marshalComponentInput(KEDAComponent, from, to, facts)
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
			"SELECTED_SCALED_OBJECTS_ARE_CALLER_SUPPLIED_NOT_LIVE_OBSERVATION",
			"TRIGGER_AUTHENTICATION_SCALER_REACHABILITY_TLS_MATERIAL_AND_RUNTIME_NOT_EVALUATED",
			OmissionNoLiveObservation,
			OmissionNoWholeUpgrade,
		},
	}, nil
}

// kedaLegacyTransportFact resolves the reviewed condition fact.
//
// The reviewed fact description is explicit that a raw tlsCertFile metadata
// field is not sufficient to establish reliance on the removed direct
// transport, so presence is never promoted to true here; it makes the fact an
// operator declaration instead. Absence derives false only when the whole
// declared-complete selection carries neither the key nor an authenticationRef
// that could supply the effective value from a TriggerAuthentication this route
// does not read.
func kedaLegacyTransportFact(inspected kedaInspection, declaration string) (required, resolved bool, reason Reason) {
	if !inspected.LegacyCertFileMetadataPresent && !inspected.AuthenticationRefPresent {
		if declaration == KEDADeclarationRequired {
			// The declaration asserts reliance on a removed behavior that reads
			// a field the selection does not carry and cannot obtain out of
			// band. The two disagree, so nothing is established.
			return false, false, ReasonKEDATransportConflict
		}
		return false, true, ReasonKEDALegacyCertFileAbsent
	}
	switch declaration {
	case KEDADeclarationRequired:
		return true, true, ReasonKEDATransportRequired
	case KEDADeclarationNotRequired:
		return false, true, ReasonKEDATransportNotRequired
	default:
		return false, false, ReasonKEDATransportUndeclared
	}
}

// kedaInspection reports what the caller-selected documents literally declare.
// ExternalScalerPresent stays nil whenever the selection cannot be classified
// against the reviewed ScaledObject surface at all.
type kedaInspection struct {
	ExternalScalerPresent         *bool
	LegacyCertFileMetadataPresent bool
	AuthenticationRefPresent      bool
	Reason                        Reason
}

func inspectKEDAScaledObjects(raw []byte) kedaInspection {
	text := string(raw)
	if strings.Contains(text, "{{") || strings.Contains(text, "${") {
		return kedaInspection{Reason: ReasonKEDATemplated}
	}
	value, err := decodeStrict(raw)
	if err != nil {
		return kedaInspection{Reason: ReasonKEDAInputUnsupported}
	}
	root, ok := value.(map[string]any)
	if !ok {
		return kedaInspection{Reason: ReasonKEDAInputUnsupported}
	}
	api, kind, ok := kubernetesGVK(root)
	if !ok {
		return kedaInspection{Reason: ReasonKEDAInputUnsupported}
	}
	documents := []map[string]any{root}
	if kind == "List" {
		if api != "v1" {
			return kedaInspection{Reason: ReasonKEDAInputUnsupported}
		}
		items, found := root["items"].([]any)
		if !found || len(items) == 0 {
			return kedaInspection{Reason: ReasonKEDAInputUnsupported}
		}
		paginated, metadataOK := kubernetesListPagination(root)
		if !metadataOK {
			return kedaInspection{Reason: ReasonKEDAInputUnsupported}
		}
		if paginated {
			// A truncated page is never a complete selection.
			return kedaInspection{Reason: ReasonKEDAPagination}
		}
		documents = make([]map[string]any, 0, len(items))
		for _, item := range items {
			document, ok := item.(map[string]any)
			if !ok {
				return kedaInspection{Reason: ReasonKEDAInputUnsupported}
			}
			documents = append(documents, document)
		}
	} else if strings.HasSuffix(kind, "List") {
		// A typed list can carry items this one-level contract never sees.
		return kedaInspection{Reason: ReasonKEDAInputUnsupported}
	}
	result := kedaInspection{}
	external := false
	for _, document := range documents {
		api, kind, ok := kubernetesGVK(document)
		if !ok || kind == "List" || strings.HasSuffix(kind, "List") {
			return kedaInspection{Reason: ReasonKEDAInputUnsupported}
		}
		group, _, hasVersion := strings.Cut(api, "/")
		if !hasVersion || group != kedaGroup || kind != kedaScaledObjectKind {
			// ScaledJob, TriggerAuthentication, ClusterTriggerAuthentication,
			// and unrelated objects are outside the reviewed surface. The whole
			// selection then stays UNKNOWN rather than silently ignoring them.
			return kedaInspection{Reason: ReasonKEDASurfaceOther}
		}
		if !kedaNamedResource(document) {
			return kedaInspection{Reason: ReasonKEDAInputUnsupported}
		}
		if api != kedaTargetAPIVersion {
			// Any other served keda.sh ScaledObject version cannot establish
			// either predicate against the reviewed external-scaler evidence.
			return kedaInspection{Reason: ReasonKEDAUnreviewedAPI}
		}
		triggers, ok := kedaTriggers(document)
		if !ok {
			return kedaInspection{Reason: ReasonKEDAInputUnsupported}
		}
		for _, trigger := range triggers {
			triggerType, ok := trigger["type"].(string)
			if !ok || triggerType == "" {
				return kedaInspection{Reason: ReasonKEDAInputUnsupported}
			}
			if triggerType != kedaExternalTriggerType && triggerType != kedaExternalPushTriggerType {
				continue
			}
			external = true
			if _, found := trigger["authenticationRef"]; found {
				// A TriggerAuthentication can supply the effective value this
				// route does not read, so absence in the document is not
				// absence in the effective trigger metadata.
				result.AuthenticationRefPresent = true
			}
			metadata, ok := trigger["metadata"].(map[string]any)
			if !ok {
				return kedaInspection{Reason: ReasonKEDAInputUnsupported}
			}
			for _, item := range metadata {
				if _, ok := item.(string); !ok {
					// Reviewed external-scaler trigger metadata is a string
					// map; any other value shape leaves it unresolved.
					return kedaInspection{Reason: ReasonKEDAInputUnsupported}
				}
			}
			if _, found := metadata[kedaLegacyTLSCertFileKey]; found {
				result.LegacyCertFileMetadataPresent = true
			}
		}
	}
	result.ExternalScalerPresent = &external
	if !external {
		result.Reason = ReasonKEDAExternalScalerAbsent
	}
	return result
}

// kedaTriggers returns the literal spec.triggers objects. An absent, empty, or
// otherwise unusable triggers list leaves the selection unresolved; it is never
// read as "no external scaler".
func kedaTriggers(document map[string]any) ([]map[string]any, bool) {
	spec, ok := document["spec"].(map[string]any)
	if !ok {
		return nil, false
	}
	items, ok := spec["triggers"].([]any)
	if !ok || len(items) == 0 || len(items) > maxArrayItems {
		return nil, false
	}
	triggers := make([]map[string]any, 0, len(items))
	for _, item := range items {
		trigger, ok := item.(map[string]any)
		if !ok {
			return nil, false
		}
		triggers = append(triggers, trigger)
	}
	return triggers, true
}

// kedaNamedResource keeps a supplied ScaledObject structurally meaningful
// without asserting that it was admitted by any cluster.
func kedaNamedResource(document map[string]any) bool {
	metadata, ok := document["metadata"].(map[string]any)
	if !ok {
		return false
	}
	name, nameOK := metadata["name"].(string)
	return nameOK && name != ""
}

// kedaReviewedPair covers exactly the one packaged KEDA transition.
func kedaReviewedPair(from, to string) bool {
	return from == KEDAFrom && to == KEDATo
}
