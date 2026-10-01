// SPDX-License-Identifier: AGPL-3.0-only

package cncfprepare

import (
	"encoding/json"
	"unicode/utf8"
)

const (
	LinkerdComponent   = "pkg:github/linkerd/linkerd2"
	LinkerdFact        = "component.linkerd.mtls_identity_selector_empty"
	LinkerdFrom        = "2.13.7"
	LinkerdTo          = "2.14.0"
	linkerdAPIVersion  = "policy.linkerd.io/v1alpha1"
	linkerdKind        = "MeshTLSAuthentication"
	maxLinkerdString   = 256
	maxLinkerdIdentity = 1024
)

// ErrInvalidLinkerd aliases the package's existing invalid-input sentinel so
// callers can handle both preparation adapters uniformly.
var ErrInvalidLinkerd = ErrInvalid

const (
	ReasonLinkerdSelectorDerived    Reason = "LINKERD_SELECTOR_DERIVED"
	ReasonLinkerdUnsupportedVersion Reason = "UNSUPPORTED_VERSION_PAIR"
	ReasonLinkerdSelectorMissing    Reason = "SELECTOR_STATE_MISSING"
	ReasonLinkerdSelectorConflict   Reason = "SELECTOR_STATE_CONFLICT"
	ReasonLinkerdGuardMissing       Reason = "GUARD_DECLARATION_MISSING"
)

type linkerdSelectorState string

const (
	linkerdSelectorDeclared    linkerdSelectorState = "declared"
	linkerdSelectorMissing     linkerdSelectorState = "missing"
	linkerdSelectorConflict    linkerdSelectorState = "conflict"
	linkerdSelectorUnsupported linkerdSelectorState = "unsupported"
)

const (
	LinkerdDistributionOfficial = "official_upstream"
	LinkerdDistributionCustom   = "custom_build"
	LinkerdSurface              = "meshtls_authentication_crd"
	LinkerdSchemaRequired       = "required"
	LinkerdSchemaDisabled       = "disabled"
)

// PrepareLinkerd derives the minimized proposed Linkerd MeshTLSAuthentication
// declaration. It validates only the bounded resource shape and selector
// cardinality; it never validates a CRD, resolves references, or observes a
// cluster. Distribution and schema-validation are explicit operator guards.
func PrepareLinkerd(raw []byte, from, to, distribution, schemaValidation string) (Prepared, error) {
	if len(raw) == 0 || len(raw) > maxInputBytes || !utf8.Valid(raw) {
		return Prepared{}, ErrInvalidLinkerd
	}
	value, err := decodeStrict(raw)
	if err != nil {
		return Prepared{}, ErrInvalidLinkerd
	}
	root, ok := value.(map[string]any)
	if !ok || allowFields(root, map[string]bool{"apiVersion": true, "kind": true, "metadata": true, "spec": true}) != nil {
		return Prepared{}, ErrInvalidLinkerd
	}
	apiVersion, ok := linkerdString(root, "apiVersion", true, 0)
	if !ok || apiVersion != linkerdAPIVersion {
		return Prepared{}, ErrInvalidLinkerd
	}
	kind, ok := linkerdString(root, "kind", true, 0)
	if !ok || kind != linkerdKind {
		return Prepared{}, ErrInvalidLinkerd
	}
	if metadata, exists := root["metadata"]; exists {
		if !validateLinkerdMetadata(metadata) {
			return Prepared{}, ErrInvalidLinkerd
		}
	}
	spec, ok := root["spec"].(map[string]any)
	if !ok || allowFields(spec, map[string]bool{"identities": true, "identityRefs": true}) != nil {
		return Prepared{}, ErrInvalidLinkerd
	}
	identities, identitiesPresent, err := parseLinkerdIdentities(spec)
	if err != nil {
		return Prepared{}, ErrInvalidLinkerd
	}
	identityRefs, refsPresent, err := parseLinkerdIdentityRefs(spec)
	if err != nil {
		return Prepared{}, ErrInvalidLinkerd
	}
	if !validVersionSyntax(from) || !validVersionSyntax(to) || from == to || !validLinkerdGuards(distribution, schemaValidation) {
		return Prepared{}, ErrInvalidLinkerd
	}

	selectorState := linkerdSelectorMissing
	var selectorValue *bool
	switch {
	case identitiesPresent && refsPresent:
		selectorState = linkerdSelectorConflict
	case !identitiesPresent && !refsPresent:
		selectorState = linkerdSelectorMissing
	case identitiesPresent:
		selectorState = linkerdSelectorDeclared
		v := len(identities) == 0
		selectorValue = &v
	case refsPresent:
		selectorState = linkerdSelectorDeclared
		v := len(identityRefs) == 0
		selectorValue = &v
	}
	state := StatePrepared
	reason := ReasonLinkerdSelectorDerived
	if from != LinkerdFrom || to != LinkerdTo {
		state, reason, selectorState = StateUnknown, ReasonLinkerdUnsupportedVersion, linkerdSelectorUnsupported
		selectorValue = nil
	} else if selectorState == linkerdSelectorMissing {
		state, reason = StateUnknown, ReasonLinkerdSelectorMissing
	} else if selectorState == linkerdSelectorConflict {
		state, reason = StateUnknown, ReasonLinkerdSelectorConflict
	} else if distribution == "" || schemaValidation == "" {
		state, reason = StateUnknown, ReasonLinkerdGuardMissing
	}
	canonical, err := marshalLinkerdInput(from, to, distribution, schemaValidation, selectorState, selectorValue)
	if err != nil {
		return Prepared{}, ErrInvalidLinkerd
	}
	return Prepared{
		CanonicalInputJSON: canonical,
		SourceDigest:       digestBytes(raw),
		InputDigest:        digestBytes(canonical),
		State:              state,
		Reason:             reason,
		Omissions:          []string{"CRD_SCHEMA_VALIDATION_NOT_PERFORMED", OmissionNoLiveObservation, OmissionNoWholeUpgrade},
	}, nil
}

func validLinkerdGuards(distribution, schemaValidation string) bool {
	return (distribution == "" || distribution == LinkerdDistributionOfficial || distribution == LinkerdDistributionCustom) && (schemaValidation == "" || schemaValidation == LinkerdSchemaRequired || schemaValidation == LinkerdSchemaDisabled)
}

func parseLinkerdIdentities(spec map[string]any) ([]string, bool, error) {
	value, present := spec["identities"]
	if !present {
		return nil, false, nil
	}
	items, ok := value.([]any)
	if !ok || len(items) > maxArrayItems {
		return nil, true, ErrInvalidLinkerd
	}
	result := make([]string, len(items))
	for i, item := range items {
		text, ok := item.(string)
		if !ok || text == "" || len(text) > maxLinkerdIdentity {
			return nil, true, ErrInvalidLinkerd
		}
		result[i] = text
	}
	return result, true, nil
}

func parseLinkerdIdentityRefs(spec map[string]any) ([]map[string]any, bool, error) {
	value, present := spec["identityRefs"]
	if !present {
		return nil, false, nil
	}
	items, ok := value.([]any)
	if !ok || len(items) > maxArrayItems {
		return nil, true, ErrInvalidLinkerd
	}
	result := make([]map[string]any, len(items))
	for i, item := range items {
		object, ok := item.(map[string]any)
		if !ok || allowFields(object, map[string]bool{"kind": true, "group": true, "name": true, "namespace": true}) != nil {
			return nil, true, ErrInvalidLinkerd
		}
		kind, ok := linkerdString(object, "kind", true, maxLinkerdString)
		if !ok || kind == "" {
			return nil, true, ErrInvalidLinkerd
		}
		for _, key := range []string{"group", "name", "namespace"} {
			if _, exists := object[key]; exists {
				if _, ok := linkerdString(object, key, true, maxLinkerdString); !ok {
					return nil, true, ErrInvalidLinkerd
				}
			}
		}
		result[i] = object
	}
	return result, true, nil
}

func validateLinkerdMetadata(value any) bool {
	object, ok := value.(map[string]any)
	if !ok || allowFields(object, map[string]bool{"name": true, "namespace": true}) != nil {
		return false
	}
	for _, key := range []string{"name", "namespace"} {
		if _, exists := object[key]; exists {
			if _, ok := linkerdString(object, key, true, maxLinkerdString); !ok {
				return false
			}
		}
	}
	return true
}

func linkerdString(object map[string]any, key string, required bool, maxBytes int) (string, bool) {
	value, exists := object[key]
	if !exists {
		return "", !required
	}
	text, ok := value.(string)
	if !ok {
		return "", false
	}
	if maxBytes > 0 && len(text) > maxBytes {
		return "", false
	}
	return text, true
}

type linkerdInput struct {
	Schema    string           `json:"schema"`
	Authority string           `json:"authority"`
	Current   linkerdInputSide `json:"current"`
	Proposed  linkerdInputSide `json:"proposed"`
}
type linkerdInputSide struct {
	Components []linkerdInputComponent `json:"components"`
}
type linkerdInputComponent struct {
	Component string             `json:"component"`
	Version   string             `json:"version"`
	Facts     []linkerdInputFact `json:"facts"`
}
type linkerdInputFact struct {
	ID        string `json:"id"`
	State     string `json:"state"`
	BoolValue *bool  `json:"boolValue,omitempty"`
	EnumValue string `json:"enumValue,omitempty"`
}

func marshalLinkerdInput(from, to, distribution, schemaValidation string, selectorState linkerdSelectorState, selectorValue *bool) ([]byte, error) {
	facts := make([]linkerdInputFact, 0, 4)
	if distribution == "" {
		facts = append(facts, linkerdInputFact{ID: "component.linkerd.distribution", State: "missing"})
	} else {
		facts = append(facts, linkerdInputFact{ID: "component.linkerd.distribution", State: "declared", EnumValue: distribution})
	}
	facts = append(facts, linkerdInputFact{ID: "component.linkerd.execution_surface", State: "declared", EnumValue: LinkerdSurface})
	selector := linkerdInputFact{ID: LinkerdFact, State: string(selectorState), BoolValue: selectorValue}
	facts = append(facts, selector)
	if schemaValidation == "" {
		facts = append(facts, linkerdInputFact{ID: "component.linkerd.schema_validation_required", State: "missing"})
	} else {
		value := schemaValidation == LinkerdSchemaRequired
		facts = append(facts, linkerdInputFact{ID: "component.linkerd.schema_validation_required", State: "declared", BoolValue: &value})
	}
	input := linkerdInput{
		Schema: InputSchema, Authority: InputAuthority,
		Current:  linkerdInputSide{Components: []linkerdInputComponent{{Component: LinkerdComponent, Version: from, Facts: []linkerdInputFact{}}}},
		Proposed: linkerdInputSide{Components: []linkerdInputComponent{{Component: LinkerdComponent, Version: to, Facts: facts}}},
	}
	compact, err := json.Marshal(input)
	if err != nil {
		return nil, err
	}
	return append(compact, '\n'), nil
}
