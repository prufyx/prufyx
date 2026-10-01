// SPDX-License-Identifier: AGPL-3.0-only

package cncfprepare

import (
	"regexp"
	"unicode/utf8"
)

const (
	BuildpacksComponent       = "pkg:oci/buildpacksio/lifecycle"
	BuildpacksSelectedAPIFact = "component.buildpacks.selected_platform_api"
	BuildpacksSupportsAPIFact = "component.buildpacks.lifecycle_supports_selected_platform_api"
	BuildpacksFrom            = "0.16.5"
	BuildpacksTo              = "0.17.7"
)

const (
	ReasonBuildpacksMetadataObserved    Reason = "BUILDPACKS_LIFECYCLE_API_METADATA_OBSERVED"
	ReasonBuildpacksMetadataUnsupported Reason = "BUILDPACKS_LIFECYCLE_OCI_CONFIG_UNSUPPORTED"
)

var platformAPIPattern = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$`)

type BuildpacksPrepared struct {
	CanonicalInputJSON   []byte
	CurrentSourceDigest  string
	ProposedSourceDigest string
	InputDigest          string
	State                State
	Reason               Reason
	Omissions            []string
}

// PrepareBuildpacksLifecycle compares operator-selected Platform APIs with the
// declarations in two supplied Lifecycle config-shaped JSON documents. The
// label values are declarations in caller-supplied bytes, not registry
// provenance.
func PrepareBuildpacksLifecycle(currentRaw, proposedRaw []byte, from, to, currentAPI, proposedAPI string) (BuildpacksPrepared, error) {
	if len(currentRaw) == 0 || len(currentRaw) > maxInputBytes || !utf8.Valid(currentRaw) || len(proposedRaw) == 0 || len(proposedRaw) > maxInputBytes || !utf8.Valid(proposedRaw) || !validVersionSyntax(from) || !validVersionSyntax(to) || from == to || !platformAPIPattern.MatchString(currentAPI) || !platformAPIPattern.MatchString(proposedAPI) {
		return BuildpacksPrepared{}, ErrInvalid
	}
	currentValue, err := decodeStrictAllowNull(currentRaw)
	if err != nil {
		return BuildpacksPrepared{}, ErrInvalid
	}
	proposedValue, err := decodeStrictAllowNull(proposedRaw)
	if err != nil {
		return BuildpacksPrepared{}, ErrInvalid
	}
	currentKnown := knownSelectedPlatformAPI(currentAPI, true)
	proposedKnown := knownSelectedPlatformAPI(proposedAPI, false)
	currentFacts := buildpacksUnavailableFacts(currentAPI, currentKnown)
	proposedFacts := buildpacksUnavailableFacts(proposedAPI, proposedKnown)
	state, reason := StateUnknown, ReasonBuildpacksMetadataUnsupported
	currentSupport, currentOK := inspectLifecycleConfig(currentValue, from, currentAPI)
	proposedSupport, proposedOK := inspectLifecycleConfig(proposedValue, to, proposedAPI)
	if currentOK && currentKnown {
		currentFacts = buildpacksDeclaredFacts(currentAPI, currentSupport)
	}
	if proposedOK && proposedKnown {
		proposedFacts = buildpacksDeclaredFacts(proposedAPI, proposedSupport)
	}
	if currentOK && proposedOK && currentKnown && proposedKnown {
		state, reason = StatePrepared, ReasonBuildpacksMetadataObserved
	}
	canonical, err := marshalComponentInputBoth(BuildpacksComponent, from, to, currentFacts, proposedFacts)
	if err != nil {
		return BuildpacksPrepared{}, ErrInvalid
	}
	return BuildpacksPrepared{CanonicalInputJSON: canonical, CurrentSourceDigest: digestBytes(currentRaw), ProposedSourceDigest: digestBytes(proposedRaw), InputDigest: digestBytes(canonical), State: state, Reason: reason, Omissions: []string{"OCI_REGISTRY_PROVENANCE_NOT_ESTABLISHED", "PLATFORM_IMPLEMENTATION_API_SUPPORT_NOT_EVALUATED", "LIFECYCLE_NEGOTIATION_BUILD_AND_RUNTIME_NOT_EVALUATED", OmissionNoWholeUpgrade}}, nil
}

func knownSelectedPlatformAPI(value string, current bool) bool {
	if current {
		return value == "0.11"
	}
	return value == "0.12" || value == "0.13"
}

func buildpacksUnavailableFacts(api string, known bool) []inputFact {
	selected := inputFact{ID: BuildpacksSelectedAPIFact, State: "unsupported"}
	if known {
		selected = inputFact{ID: BuildpacksSelectedAPIFact, State: "declared", EnumValue: api}
	}
	return []inputFact{{ID: BuildpacksSupportsAPIFact, State: "unsupported"}, selected}
}

func buildpacksDeclaredFacts(api string, supported bool) []inputFact {
	return []inputFact{{ID: BuildpacksSupportsAPIFact, State: "declared", BoolValue: &supported}, {ID: BuildpacksSelectedAPIFact, State: "declared", EnumValue: api}}
}

func inspectLifecycleConfig(value any, expectedVersion, selectedAPI string) (bool, bool) {
	root, ok := value.(map[string]any)
	if !ok {
		return false, false
	}
	config := objectField(root, "config")
	labels := objectField(config, "Labels")
	if labels == nil || stringField(labels, "io.buildpacks.lifecycle.version") != expectedVersion {
		return false, false
	}
	if metadataValue, exists := labels["io.buildpacks.builder.metadata"]; exists {
		metadataRaw, ok := metadataValue.(string)
		if !ok {
			return false, false
		}
		metadata, err := decodeStrictAllowNull([]byte(metadataRaw))
		if err != nil {
			return false, false
		}
		metadataRoot, ok := metadata.(map[string]any)
		if !ok || stringField(objectField(metadataRoot, "lifecycle"), "version") != expectedVersion {
			return false, false
		}
	}
	apisRaw, ok := labels["io.buildpacks.lifecycle.apis"].(string)
	if !ok || apisRaw == "" {
		return false, false
	}
	apisValue, err := decodeStrictAllowNull([]byte(apisRaw))
	if err != nil {
		return false, false
	}
	apis, ok := apisValue.(map[string]any)
	if !ok {
		return false, false
	}
	platform := objectField(apis, "platform")
	if platform == nil {
		return false, false
	}
	supported, ok := platformAPISet(platform["supported"])
	if !ok || len(supported) == 0 {
		return false, false
	}
	deprecated, ok := platformAPISet(platform["deprecated"])
	if !ok {
		return false, false
	}
	for api := range deprecated {
		if !supported[api] {
			return false, false
		}
	}
	return supported[selectedAPI], true
}

func platformAPISet(value any) (map[string]bool, bool) {
	items, ok := value.([]any)
	if !ok {
		return nil, false
	}
	result := map[string]bool{}
	for _, item := range items {
		api, ok := item.(string)
		if !ok || !platformAPIPattern.MatchString(api) || result[api] {
			return nil, false
		}
		result[api] = true
	}
	return result, true
}
