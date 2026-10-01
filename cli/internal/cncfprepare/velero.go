// SPDX-License-Identifier: AGPL-3.0-only

package cncfprepare

import (
	"strings"
	"unicode/utf8"
)

const (
	VeleroComponent    = "pkg:github/velero-io/velero"
	VeleroCRDOrderFact = "component.velero.crd_update_before_server"

	VeleroFrom             = "1.17.0"
	VeleroTo               = "1.18.0"
	VeleroIntermediateFrom = "1.16.2"

	veleroCRDGroup        = "velero.io"
	veleroCRDAPIVersion   = "apiextensions.k8s.io/v1"
	veleroCRDKind         = "CustomResourceDefinition"
	veleroDeploymentAPI   = "apps/v1"
	veleroDeploymentKind  = "Deployment"
	veleroMissingPosition = -1
)

const (
	ReasonVeleroCRDsBeforeServer    Reason = "VELERO_TARGET_CRDS_ORDERED_BEFORE_SERVER"
	ReasonVeleroCRDsAfterServer     Reason = "VELERO_TARGET_CRDS_NOT_ORDERED_BEFORE_SERVER"
	ReasonVeleroPlanGuardUnresolved Reason = "VELERO_UPGRADE_PLAN_ORDER_DECLARATION_MISSING"
	ReasonVeleroPairUnsupported     Reason = "VELERO_TRANSITION_NOT_REVIEWED"
	ReasonVeleroServerUnresolved    Reason = "VELERO_SERVER_DEPLOYMENT_SELECTION_UNRESOLVED"
	ReasonVeleroCRDsAbsent          Reason = "VELERO_TARGET_CRD_DOCUMENTS_ABSENT"
	ReasonVeleroInputUnsupported    Reason = "VELERO_UPGRADE_PLAN_SHAPE_UNRESOLVED"
	ReasonVeleroTemplated           Reason = "VELERO_UPGRADE_PLAN_RENDERING_UNRESOLVED"
	ReasonVeleroPagination          Reason = "VELERO_UPGRADE_PLAN_LIST_PAGINATION_UNRESOLVED"
)

// PrepareVeleroUpgradePlan minimizes one caller-selected ordered upgrade plan
// into the single ordering fact the reviewed Velero 1.17.0 -> 1.18.0 rule
// already requires. The plan is one flat v1 List of rendered documents whose
// item order the caller declares to be the apply order, plus the literal name
// of the Velero server Deployment inside it.
//
// The adapter derives nothing but the literal relative position of the
// velero.io target CRD documents and that one named Deployment. It is not a
// cluster reader, an apply engine, or an execution receipt: an absent CRD
// document, an unresolved server selection, unresolved rendering, pagination,
// and a structurally unresolved object all stay UNKNOWN rather than becoming a
// negative-presence PASS.
//
// The reviewed 1.16.2 -> 1.18.0 pair is also admitted, because its own reviewed
// rule requires no facts. That rule blocks the direct transition on the pair
// alone; this adapter neither suppresses nor weakens it.
func PrepareVeleroUpgradePlan(raw []byte, from, to, serverDeployment string, planOrdered bool) (Prepared, error) {
	if len(raw) == 0 || len(raw) > maxInputBytes || !utf8.Valid(raw) || !validVersionSyntax(from) || !validVersionSyntax(to) || from == to {
		return Prepared{}, ErrInvalid
	}
	facts := []inputFact{{ID: VeleroCRDOrderFact, State: "unsupported"}}
	state, reason := StateUnknown, ReasonVeleroPlanGuardUnresolved
	switch {
	case !veleroReviewedPair(from, to):
		reason = ReasonVeleroPairUnsupported
	case !planOrdered || serverDeployment == "":
		// Without an explicit declaration that the supplied item order is the
		// declared apply order, document position establishes nothing.
		reason = ReasonVeleroPlanGuardUnresolved
	default:
		inspected := inspectVeleroUpgradePlan(raw, serverDeployment)
		reason = inspected.Reason
		if inspected.Ordered != nil {
			facts[0] = inputFact{ID: VeleroCRDOrderFact, State: "declared", BoolValue: inspected.Ordered}
			state = StatePrepared
		}
	}
	canonical, err := marshalComponentInput(VeleroComponent, from, to, facts)
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
			"SELECTED_PLAN_IS_A_CALLER_DECLARATION_NOT_AN_APPLY_OR_EXECUTION_RECEIPT",
			"APPLIED_CRDS_PLUGINS_NODE_AGENTS_BACKUPS_AND_RESTORES_NOT_EVALUATED",
			OmissionNoWholeUpgrade,
		},
	}, nil
}

// veleroInspection reports whether every velero.io target CRD document
// literally precedes the selected server Deployment in the declared plan
// order. Ordered stays nil whenever either side of that comparison is
// unresolved.
type veleroInspection struct {
	Ordered *bool
	Reason  Reason
}

func inspectVeleroUpgradePlan(raw []byte, serverDeployment string) veleroInspection {
	text := string(raw)
	if strings.Contains(text, "{{") || strings.Contains(text, "${") {
		return veleroInspection{Reason: ReasonVeleroTemplated}
	}
	value, err := decodeStrict(raw)
	if err != nil {
		return veleroInspection{Reason: ReasonVeleroInputUnsupported}
	}
	root, ok := value.(map[string]any)
	if !ok {
		return veleroInspection{Reason: ReasonVeleroInputUnsupported}
	}
	api, kind, ok := kubernetesGVK(root)
	if !ok {
		return veleroInspection{Reason: ReasonVeleroInputUnsupported}
	}
	documents := []map[string]any{root}
	if kind == "List" {
		if api != "v1" {
			return veleroInspection{Reason: ReasonVeleroInputUnsupported}
		}
		items, found := root["items"].([]any)
		if !found || len(items) == 0 {
			return veleroInspection{Reason: ReasonVeleroInputUnsupported}
		}
		paginated, metadataOK := kubernetesListPagination(root)
		if !metadataOK {
			return veleroInspection{Reason: ReasonVeleroInputUnsupported}
		}
		if paginated {
			// A truncated page cannot establish the order of the whole plan.
			return veleroInspection{Reason: ReasonVeleroPagination}
		}
		documents = make([]map[string]any, 0, len(items))
		for _, item := range items {
			document, ok := item.(map[string]any)
			if !ok {
				return veleroInspection{Reason: ReasonVeleroInputUnsupported}
			}
			documents = append(documents, document)
		}
	} else if strings.HasSuffix(kind, "List") {
		// A typed list can carry items this one-level contract never sees.
		return veleroInspection{Reason: ReasonVeleroInputUnsupported}
	}
	lastCRD, server, servers := veleroMissingPosition, veleroMissingPosition, 0
	for position, document := range documents {
		api, kind, ok := kubernetesGVK(document)
		if !ok || kind == "List" || strings.HasSuffix(kind, "List") || !veleroNamedResource(document) {
			return veleroInspection{Reason: ReasonVeleroInputUnsupported}
		}
		if api == veleroCRDAPIVersion && kind == veleroCRDKind {
			group, resolved := veleroCustomResourceGroup(document)
			if !resolved {
				return veleroInspection{Reason: ReasonVeleroInputUnsupported}
			}
			if group == veleroCRDGroup {
				lastCRD = position
			}
			continue
		}
		if api == veleroDeploymentAPI && kind == veleroDeploymentKind && veleroResourceName(document) == serverDeployment {
			server, servers = position, servers+1
		}
	}
	if servers != 1 {
		// Zero or several Deployments carrying the selected name leave the
		// server position unresolved; it is never guessed from another kind.
		return veleroInspection{Reason: ReasonVeleroServerUnresolved}
	}
	if lastCRD == veleroMissingPosition {
		// The plan declares no velero.io target CRD document at all. Absence is
		// not evidence that the CRDs are updated first, so this stays UNKNOWN.
		return veleroInspection{Reason: ReasonVeleroCRDsAbsent}
	}
	ordered := lastCRD < server
	reason := ReasonVeleroCRDsAfterServer
	if ordered {
		reason = ReasonVeleroCRDsBeforeServer
	}
	return veleroInspection{Ordered: &ordered, Reason: reason}
}

// veleroCustomResourceGroup reads the literal spec.group of a supplied CRD
// document. It does not validate the rest of the CRD schema.
func veleroCustomResourceGroup(document map[string]any) (string, bool) {
	spec, ok := document["spec"].(map[string]any)
	if !ok {
		return "", false
	}
	group, ok := spec["group"].(string)
	if !ok || group == "" {
		return "", false
	}
	return group, true
}

func veleroResourceName(document map[string]any) string {
	metadata, ok := document["metadata"].(map[string]any)
	if !ok {
		return ""
	}
	name, _ := metadata["name"].(string)
	return name
}

// veleroNamedResource keeps each supplied plan document structurally
// meaningful without asserting that any of them was applied.
func veleroNamedResource(document map[string]any) bool {
	return veleroResourceName(document) != ""
}

func veleroReviewedPair(from, to string) bool {
	return to == VeleroTo && (from == VeleroFrom || from == VeleroIntermediateFrom)
}
