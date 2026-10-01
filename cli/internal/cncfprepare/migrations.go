// SPDX-License-Identifier: AGPL-3.0-only

package cncfprepare

import "strings"

// These adapters accept one caller-selected native Kubernetes resource and
// emit one reviewed boolean fact. They never infer cluster state, defaults,
// admission, or runtime compatibility.
const (
	MetalLBComponent = "pkg:github/metallb/metallb"
	MetalLBFact      = "component.metallb.legacy_configmap_present"
	MetalLBFrom      = "0.12.1"
	MetalLBTo        = "0.13.2"

	ContourComponent = "pkg:github/projectcontour/contour"
	ContourFact      = "component.contour.gateway_v1alpha1_present"
	ContourFrom      = "1.19.0"
	ContourTo        = "1.20.0"
)

const (
	ReasonMetalLBConfigMap           Reason = "METALLB_LEGACY_CONFIGMAP_PRESENT"
	ReasonMetalLBCR                  Reason = "METALLB_CR_CONFIGURATION_DECLARED"
	ReasonContourGatewayAlpha        Reason = "CONTOUR_GATEWAY_V1ALPHA1_PRESENT"
	ReasonContourGatewayTarget       Reason = "CONTOUR_GATEWAY_TARGET_API_DECLARED"
	ReasonNativeMigrationUnsupported Reason = "NATIVE_MIGRATION_INPUT_UNSUPPORTED"
)

// PrepareNativeMigration dispatches the approved MetalLB and Contour native
// resource adapters. Other projects remain separate until their source
// contracts are approved.
func PrepareNativeMigration(raw []byte, project, from, to string) (Prepared, error) {
	if len(raw) == 0 || len(raw) > maxInputBytes || !validVersionSyntax(from) || !validVersionSyntax(to) || from == to {
		return Prepared{}, ErrInvalid
	}
	value, err := decodeStrict(raw)
	if err != nil {
		return Prepared{}, ErrInvalid
	}
	var component, factID string
	var valueFact *bool
	state, reason := StateUnknown, ReasonNativeMigrationUnsupported
	switch project {
	case "metallb":
		component, factID = MetalLBComponent, MetalLBFact
		valueFact, reason = metalLBFact(value)
		if valueFact != nil {
			state = StatePrepared
		}
	case "contour":
		component, factID = ContourComponent, ContourFact
		valueFact, reason = contourFact(value)
		if valueFact != nil {
			state = StatePrepared
		}
	default:
		return Prepared{}, ErrInvalid
	}
	fact := inputFact{ID: factID, State: "unsupported"}
	if valueFact != nil {
		fact.State = "declared"
		fact.BoolValue = valueFact
	}
	canonical, err := marshalComponentInput(component, from, to, []inputFact{fact})
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
			"NATIVE_RESOURCE_IS_CALLER_SUPPLIED_NOT_LIVE_OBSERVATION",
			"WHOLE_UPGRADE_AND_RUNTIME_COMPATIBILITY_NOT_EVALUATED",
		},
	}, nil
}

func metalLBFact(value any) (*bool, Reason) {
	root, ok := value.(map[string]any)
	if !ok {
		return nil, ReasonNativeMigrationUnsupported
	}
	api, apiOK := root["apiVersion"].(string)
	kind, kindOK := root["kind"].(string)
	metadata, metadataOK := root["metadata"].(map[string]any)
	name, nameOK := metadata["name"].(string)
	namespace, namespaceOK := metadata["namespace"].(string)
	if !apiOK || !kindOK || !metadataOK || !nameOK || name == "" || !namespaceOK || namespace == "" {
		return nil, ReasonNativeMigrationUnsupported
	}
	if api == "v1" && kind == "ConfigMap" && name == "config" {
		data, ok := root["data"].(map[string]any)
		config, configOK := data["config"].(string)
		if !ok || len(data) == 0 || !configOK || strings.TrimSpace(config) == "" {
			return nil, ReasonNativeMigrationUnsupported
		}
		value := true
		return &value, ReasonMetalLBConfigMap
	}
	// These are the six v1beta1 names in the target CRD set. AddressPool is
	// the separately deprecated v1alpha1 CRD and is intentionally unsupported
	// by this narrow target-shape adapter.
	if api == "metallb.io/v1beta1" && oneOf(kind, "IPAddressPool", "L2Advertisement", "BGPAdvertisement", "BFDProfile", "BGPPeer", "Community") {
		if _, ok := root["spec"].(map[string]any); !ok {
			return nil, ReasonNativeMigrationUnsupported
		}
		value := false
		return &value, ReasonMetalLBCR
	}
	return nil, ReasonNativeMigrationUnsupported
}

func contourFact(value any) (*bool, Reason) {
	root, ok := value.(map[string]any)
	if !ok {
		return nil, ReasonNativeMigrationUnsupported
	}
	api, apiOK := root["apiVersion"].(string)
	kind, kindOK := root["kind"].(string)
	if !apiOK || !kindOK || !oneOf(kind, "GatewayClass", "Gateway", "HTTPRoute", "TLSRoute") {
		return nil, ReasonNativeMigrationUnsupported
	}
	metadata, metadataOK := root["metadata"].(map[string]any)
	name, nameOK := metadata["name"].(string)
	if !metadataOK || !nameOK || name == "" {
		return nil, ReasonNativeMigrationUnsupported
	}
	// GatewayClass is cluster-scoped; the other selected Gateway API
	// resources are namespaced. This keeps an explicitly supplied object
	// structurally meaningful without asserting cluster admission state.
	namespace, namespacePresent := metadata["namespace"]
	if kind == "GatewayClass" {
		if namespacePresent && namespace != nil {
			return nil, ReasonNativeMigrationUnsupported
		}
	} else {
		if !namespacePresent {
			return nil, ReasonNativeMigrationUnsupported
		}
		ns, ok := namespace.(string)
		if !ok || ns == "" {
			return nil, ReasonNativeMigrationUnsupported
		}
	}
	if api == "networking.x-k8s.io/v1alpha1" {
		value := true
		return &value, ReasonContourGatewayAlpha
	}
	if api == "gateway.networking.k8s.io/v1alpha2" {
		value := false
		return &value, ReasonContourGatewayTarget
	}
	return nil, ReasonNativeMigrationUnsupported
}

func oneOf(value string, options ...string) bool {
	for _, option := range options {
		if value == option {
			return true
		}
	}
	return false
}
