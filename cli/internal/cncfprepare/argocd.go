// SPDX-License-Identifier: AGPL-3.0-only

package cncfprepare

import "unicode/utf8"

const (
	ArgoCDComponent                   = "pkg:github/argoproj/argo-cd"
	ArgoCDInheritanceDisabledFact     = "component.argo_cd.disable_fine_grained_inheritance"
	ArgoCDInheritedPermissionsFact    = "component.argo_cd.requires_inherited_application_permissions"
	ArgoCDFrom                        = "2.14.0"
	ArgoCDTo                          = "3.0.0"
	argoCDConfigMapAPIVersion         = "v1"
	argoCDConfigMapKind               = "ConfigMap"
	argoCDConfigMapName               = "argocd-cm"
	argoCDInheritanceConfigurationKey = "server.rbac.disableApplicationFineGrainedRBACInheritance"
)

var ErrInvalidArgoCD = ErrInvalid

const (
	ReasonArgoCDExplicitValue            Reason = "ARGO_CD_INHERITANCE_CONFIGURATION_WITNESS"
	ReasonArgoCDConfigurationMissing     Reason = "ARGO_CD_INHERITANCE_CONFIGURATION_MISSING"
	ReasonArgoCDConfigurationUnsupported Reason = "ARGO_CD_INHERITANCE_CONFIGURATION_UNSUPPORTED"
	ReasonArgoCDIntentMissing            Reason = "ARGO_CD_INHERITED_PERMISSIONS_DECLARATION_MISSING"
	ReasonArgoCDUnsupportedPair          Reason = "ARGO_CD_UNSUPPORTED_VERSION_PAIR"
)

// PrepareArgoCD derives only the two facts consumed by the existing Argo CD
// inheritance rule from a private proposed argocd-cm JSON resource. The access
// intent is deliberately an explicit operator declaration: it is never inferred
// from RBAC policy, users, roles, or a live cluster. A missing ConfigMap key is
// unresolved rather than a claimed effective default.
func PrepareArgoCD(raw []byte, from, to string, requiresInheritedPermissions *bool) (Prepared, error) {
	if len(raw) == 0 || len(raw) > maxInputBytes || !utf8.Valid(raw) ||
		!validVersionSyntax(from) || !validVersionSyntax(to) || from == to {
		return Prepared{}, ErrInvalidArgoCD
	}
	value, err := decodeStrict(raw)
	if err != nil {
		return Prepared{}, ErrInvalidArgoCD
	}
	root, ok := value.(map[string]any)
	if !ok || allowFields(root, map[string]bool{"apiVersion": true, "kind": true, "metadata": true, "data": true}) != nil {
		return Prepared{}, ErrInvalidArgoCD
	}
	apiVersion, ok := karmadaRequiredString(root, "apiVersion")
	if !ok || apiVersion != argoCDConfigMapAPIVersion {
		return Prepared{}, ErrInvalidArgoCD
	}
	kind, ok := karmadaRequiredString(root, "kind")
	if !ok || kind != argoCDConfigMapKind {
		return Prepared{}, ErrInvalidArgoCD
	}
	metadata, ok := root["metadata"].(map[string]any)
	if !ok {
		return Prepared{}, ErrInvalidArgoCD
	}
	name, ok := karmadaRequiredString(metadata, "name")
	if !ok || name != argoCDConfigMapName {
		return Prepared{}, ErrInvalidArgoCD
	}

	configurationState, configurationValue, reason := inspectArgoCDInheritance(root)
	if from != ArgoCDFrom || to != ArgoCDTo {
		configurationState, configurationValue, reason = "unsupported", nil, ReasonArgoCDUnsupportedPair
	}
	intentState := "missing"
	if requiresInheritedPermissions != nil {
		intentState = "declared"
	}
	if requiresInheritedPermissions == nil && reason == ReasonArgoCDExplicitValue {
		reason = ReasonArgoCDIntentMissing
	}
	state := StateUnknown
	if configurationState == "declared" && intentState == "declared" {
		state = StatePrepared
	}
	canonical, err := marshalArgoCDInput(from, to, configurationState, configurationValue, intentState, requiresInheritedPermissions)
	if err != nil {
		return Prepared{}, ErrInvalidArgoCD
	}
	return Prepared{
		CanonicalInputJSON: canonical,
		SourceDigest:       digestBytes(raw),
		InputDigest:        digestBytes(canonical),
		State:              state,
		Reason:             reason,
		Omissions: []string{
			"CONFIG_MAP_COMPLETENESS_NOT_VERIFIED",
			"RBAC_POLICY_NOT_EVALUATED",
			"CLI_AND_ENVIRONMENT_CONFIGURATION_NOT_EVALUATED",
			OmissionNoLiveObservation,
			OmissionNoWholeUpgrade,
		},
	}, nil
}

func inspectArgoCDInheritance(root map[string]any) (string, *bool, Reason) {
	data, exists := root["data"]
	if !exists {
		return "missing", nil, ReasonArgoCDConfigurationMissing
	}
	values, ok := data.(map[string]any)
	if !ok {
		return "unsupported", nil, ReasonArgoCDConfigurationUnsupported
	}
	raw, exists := values[argoCDInheritanceConfigurationKey]
	if !exists {
		return "missing", nil, ReasonArgoCDConfigurationMissing
	}
	text, ok := raw.(string)
	if !ok {
		return "unsupported", nil, ReasonArgoCDConfigurationUnsupported
	}
	switch text {
	case "true":
		value := true
		return "declared", &value, ReasonArgoCDExplicitValue
	case "false":
		value := false
		return "declared", &value, ReasonArgoCDExplicitValue
	default:
		return "unsupported", nil, ReasonArgoCDConfigurationUnsupported
	}
}

func marshalArgoCDInput(from, to, configurationState string, configurationValue *bool, intentState string, intentValue *bool) ([]byte, error) {
	return marshalComponentInput(ArgoCDComponent, from, to, []inputFact{
		{ID: ArgoCDInheritanceDisabledFact, State: configurationState, BoolValue: configurationValue},
		{ID: ArgoCDInheritedPermissionsFact, State: intentState, BoolValue: intentValue},
	})
}
