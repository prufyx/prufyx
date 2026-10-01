// SPDX-License-Identifier: AGPL-3.0-only

package cncfprepare

import (
	"bytes"
	"unicode/utf8"
)

// Envoy's current 1.39.1 rules forbid a direct, static v2 transport witness.
// This adapter intentionally does not establish an absence result: the
// bootstrap has further ConfigSource and Any/extension surfaces outside its
// three reviewed dynamic-resource paths.
const (
	EnvoyComponent = "pkg:github/envoyproxy/envoy"
	EnvoyFact      = "component.envoy.xds_api_major"
	EnvoyLatestTo  = "1.39.1"
)

const (
	ReasonEnvoyV2TransportWitness   Reason = "ENVOY_DIRECT_V2_TRANSPORT_WITNESS"
	ReasonEnvoyBootstrapUnselected  Reason = "ENVOY_BOOTSTRAP_SELECTION_UNDECLARED"
	ReasonEnvoyBootstrapUnsupported Reason = "ENVOY_BOOTSTRAP_SELECTED_SHAPE_UNSUPPORTED"
	ReasonEnvoyPairUnsupported      Reason = "ENVOY_TRANSITION_NOT_REVIEWED"
)

// PrepareEnvoyBootstrap derives the existing v2 fact only when one of three
// direct DynamicResources ApiConfigSource paths explicitly selects V2. It does
// not parse YAML, protobuf JSON aliases, ConfigSource resource/self versions,
// static resources, typed Any payloads, or fetched xDS configuration.
func PrepareEnvoyBootstrap(raw []byte, from, to string, selected bool) (Prepared, error) {
	if len(raw) == 0 || len(raw) > maxInputBytes || !utf8.Valid(raw) || !validVersionSyntax(from) || !validVersionSyntax(to) || from == to {
		return Prepared{}, ErrInvalid
	}
	fact := inputFact{ID: EnvoyFact, State: "unsupported"}
	state, reason := StateUnknown, ReasonEnvoyPairUnsupported
	var root map[string]any
	jsonInput := envoyJSONObject(raw)
	if jsonInput {
		value, err := decodeStrict(raw)
		if err != nil {
			return Prepared{}, ErrInvalid
		}
		root, _ = value.(map[string]any)
	}
	if !envoyReviewedPair(from, to) {
		reason = ReasonEnvoyPairUnsupported
	} else if !selected {
		reason = ReasonEnvoyBootstrapUnselected
	} else if root != nil && envoyDirectV2Transport(root) {
		fact = inputFact{ID: EnvoyFact, State: "declared", EnumValue: "v2"}
		state, reason = StatePrepared, ReasonEnvoyV2TransportWitness
	} else {
		reason = ReasonEnvoyBootstrapUnsupported
	}
	canonical, err := marshalComponentInput(EnvoyComponent, from, to, []inputFact{fact})
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
			"BOOTSTRAP_BYTES_ARE_CALLER_SELECTED_NOT_LIVE_OBSERVATION",
			"YAML_STATIC_RESOURCES_OTHER_CONFIGSOURCES_TYPED_CONFIG_FETCHED_XDS_AND_RUNTIME_NOT_EVALUATED",
			OmissionNoWholeUpgrade,
		},
	}, nil
}

func envoyReviewedPair(from, to string) bool {
	if to != EnvoyLatestTo {
		return false
	}
	switch from {
	case "1.34.14", "1.35.13", "1.36.10", "1.37.6", "1.38.4":
		return true
	default:
		return false
	}
}

func envoyJSONObject(raw []byte) bool {
	trimmed := bytes.TrimSpace(raw)
	return len(trimmed) > 0 && (trimmed[0] == '{' || trimmed[0] == '[')
}

func envoyDirectV2Transport(root map[string]any) bool {
	dynamic, ok := envoyExactObject(root, "dynamic_resources", "dynamicResources")
	if !ok {
		return false
	}
	return envoyADSDirectV2(dynamic) || envoyConfigSourceDirectV2(dynamic, "lds_config", "ldsConfig") || envoyConfigSourceDirectV2(dynamic, "cds_config", "cdsConfig")
}

func envoyADSDirectV2(dynamic map[string]any) bool {
	ads, ok := envoyExactObject(dynamic, "ads_config", "adsConfig")
	if !ok || !envoyExactString(ads, "api_type", "apiType", "GRPC") {
		return false
	}
	return envoyExactString(ads, "transport_api_version", "transportApiVersion", "V2")
}

func envoyConfigSourceDirectV2(dynamic map[string]any, key, alias string) bool {
	source, ok := envoyExactObject(dynamic, key, alias)
	if !ok || envoyConfigSourceOneofConflict(source) {
		return false
	}
	api, ok := envoyExactObject(source, "api_config_source", "apiConfigSource")
	if !ok || !envoyAPIType(api) {
		return false
	}
	return envoyExactString(api, "transport_api_version", "transportApiVersion", "V2")
}

// envoyExactObject and envoyExactString deliberately reject lowerCamel aliases
// and an alias/snake pair. The strict generic JSON decoder cannot identify
// underscore-only aliases by case folding alone.
func envoyExactObject(object map[string]any, key, alias string) (map[string]any, bool) {
	if _, ambiguous := object[alias]; ambiguous {
		return nil, false
	}
	value, ok := object[key]
	if !ok {
		return nil, false
	}
	child, ok := value.(map[string]any)
	return child, ok
}

func envoyExactString(object map[string]any, key, alias, wanted string) bool {
	if _, ambiguous := object[alias]; ambiguous {
		return false
	}
	value, ok := object[key].(string)
	return ok && value == wanted
}

func envoyConfigSourceOneofConflict(source map[string]any) bool {
	// Lower-camel protobuf JSON aliases must not coexist with the admitted
	// snake-case ConfigSource oneof. They are not interchangeable for this
	// deliberately narrow parser.
	if _, present := source["apiConfigSource"]; present {
		return true
	}
	if _, present := source["pathConfigSource"]; present {
		return true
	}
	count := 0
	for _, key := range []string{"path", "path_config_source", "api_config_source", "ads", "self"} {
		if _, present := source[key]; present {
			count++
		}
	}
	return count != 1
}

func envoyAPIType(api map[string]any) bool {
	if _, ambiguous := api["apiType"]; ambiguous {
		return false
	}
	value, ok := api["api_type"].(string)
	if !ok {
		return false
	}
	switch value {
	case "REST", "GRPC", "DELTA_GRPC", "AGGREGATED_GRPC", "AGGREGATED_DELTA_GRPC":
		return true
	default:
		return false
	}
}
