// SPDX-License-Identifier: AGPL-3.0-only

package cncfprepare

import (
	"encoding/json"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Flux 2.7 removes five beta API versions from its CRDs. This adapter examines
// only a caller-selected proposed rendered-resource JSON document. It does not
// inspect stored versions, a cluster inventory, reconciliation, or runtime.
const (
	FluxComponent                  = "pkg:github/fluxcd/flux2"
	FluxFact                       = "component.flux.removed_beta_api_present"
	FluxLatestFact                 = "component.flux.latest_removed_beta_api_present"
	FluxFrom                       = "2.6.4"
	FluxTo                         = "2.7.0"
	FluxLatestTo                   = "2.9.5"
	FluxLatestSourceContractDigest = "sha256:8bcb1766d46fdab5dd7367400bbc3d026a02542c51b093202924f1034d0c8dba"
)

// fluxLatestRemovedAPIs is the union removed by the v2.8 and v2.9 releases.
// The slice is private so callers cannot alter the source-bound predicate.
var fluxLatestRemovedAPIs = [...]string{
	"source.toolkit.fluxcd.io/v1beta2",
	"kustomize.toolkit.fluxcd.io/v1beta2",
	"helm.toolkit.fluxcd.io/v2beta2",
	"image.toolkit.fluxcd.io/v1beta2",
	"notification.toolkit.fluxcd.io/v1beta2",
}

var fluxLatestServedVersions = map[string]map[string]string{
	"source.toolkit.fluxcd.io":       {"Bucket": "v1", "ExternalArtifact": "v1", "GitRepository": "v1", "HelmChart": "v1", "HelmRepository": "v1", "OCIRepository": "v1"},
	"kustomize.toolkit.fluxcd.io":    {"Kustomization": "v1"},
	"helm.toolkit.fluxcd.io":         {"HelmRelease": "v2"},
	"image.toolkit.fluxcd.io":        {"ImagePolicy": "v1", "ImageRepository": "v1", "ImageUpdateAutomation": "v1"},
	"notification.toolkit.fluxcd.io": {"Alert": "v1beta3", "Provider": "v1beta3", "Receiver": "v1"},
}

const (
	ReasonFluxRemovedAPIWitness   Reason = "FLUX_REMOVED_BETA_API_PRESENT"
	ReasonFluxSelectedSetClear    Reason = "FLUX_SELECTED_RESOURCE_SET_CLEAR"
	ReasonFluxResourceUnsupported Reason = "FLUX_NATIVE_RESOURCE_SET_UNSUPPORTED"
	ReasonFluxPagination          Reason = "FLUX_RESOURCE_LIST_PAGINATION_UNRESOLVED"
	ReasonFluxScopeIncomplete     Reason = "FLUX_SELECTED_RESOURCE_SCOPE_INCOMPLETE"
	ReasonFluxLatestTransition    Reason = "FLUX_LATEST_TRANSITION_UNSUPPORTED"
)

// PrepareFlux derives the existing Flux fact from one selected JSON object or
// a v1 List. A positive removed-API witness is conclusive for that supplied
// resource even when the caller has not declared the selected set complete.
// A clear result requires a nonempty complete selected set with no pagination.
func PrepareFlux(raw []byte, from, to string, selectedScopeComplete bool) (Prepared, error) {
	if to == FluxLatestTo {
		return prepareFlux(raw, from, to, selectedScopeComplete, fluxLatestRemovedAPIs[:], FluxLatestFact)
	}
	return prepareFlux(raw, from, to, selectedScopeComplete, nil, FluxFact)
}

func fluxLatestOrigin(version string) bool {
	switch version {
	case "2.8.8", "2.7.5", "2.6.4", "2.5.1", "2.4.0":
		return true
	default:
		return false
	}
}

func prepareFlux(raw []byte, from, to string, selectedScopeComplete bool, latestAPIs []string, factID string) (Prepared, error) {
	if len(raw) == 0 || len(raw) > maxInputBytes || !utf8.Valid(raw) || !validVersionSyntax(from) || !validVersionSyntax(to) || from == to {
		return Prepared{}, ErrInvalid
	}
	value, err := decodeStrict(raw)
	if err != nil {
		return Prepared{}, ErrInvalid
	}
	removed, completeShape, paginated := fluxRemovedAPIFor(value, latestAPIs)
	fact := inputFact{ID: factID, State: "unsupported"}
	state, reason := StateUnknown, ReasonFluxResourceUnsupported
	if removed {
		value := true
		fact = inputFact{ID: factID, State: "declared", BoolValue: &value}
		state, reason = StatePrepared, ReasonFluxRemovedAPIWitness
	} else if completeShape && selectedScopeComplete && !paginated {
		value := false
		fact = inputFact{ID: factID, State: "declared", BoolValue: &value}
		state, reason = StatePrepared, ReasonFluxSelectedSetClear
	} else if completeShape && paginated {
		reason = ReasonFluxPagination
	} else if completeShape {
		reason = ReasonFluxScopeIncomplete
	}
	if len(latestAPIs) > 0 && !fluxLatestOrigin(from) {
		fact = inputFact{ID: factID, State: "unsupported"}
		state, reason = StateUnknown, ReasonFluxLatestTransition
	}
	canonical, err := marshalComponentInput(FluxComponent, from, to, []inputFact{fact})
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
			"SELECTED_RENDERED_RESOURCE_SET_IS_CALLER_SUPPLIED_NOT_LIVE_OBSERVATION",
			"STORED_CRD_VERSIONS_CLUSTER_INVENTORY_RECONCILIATION_AND_RUNTIME_NOT_EVALUATED",
		},
	}, nil
}

func fluxRemovedAPI(value any) (removed, completeShape, paginated bool) {
	return fluxRemovedAPIFor(value, nil)
}

func fluxRemovedAPIFor(value any, latestAPIs []string) (removed, completeShape, paginated bool) {
	root, ok := value.(map[string]any)
	if !ok {
		return false, false, false
	}
	api, apiOK := root["apiVersion"].(string)
	kind, kindOK := root["kind"].(string)
	if !apiOK || !fluxIdentity(api) || !kindOK || !fluxIdentity(kind) {
		return false, false, false
	}
	if api == "v1" && kind == "List" {
		if metadata, exists := root["metadata"]; exists {
			if _, ok := metadata.(map[string]any); !ok {
				return false, false, false
			}
		}
		items, ok := root["items"].([]any)
		if !ok || len(items) == 0 {
			return false, false, fluxListPaginated(root)
		}
		paginated = fluxListPaginated(root)
		for _, item := range items {
			itemRemoved, itemOK := fluxResourceAPIFor(item, latestAPIs)
			if !itemOK {
				return false, false, false
			}
			removed = removed || itemRemoved
		}
		return removed, true, paginated
	}
	removed, ok = fluxResourceAPIFor(root, latestAPIs)
	return removed, ok, false
}

func fluxResourceAPI(value any) (bool, bool) {
	return fluxResourceAPIFor(value, nil)
}

func fluxResourceAPIFor(value any, latestAPIs []string) (bool, bool) {
	root, ok := value.(map[string]any)
	if !ok {
		return false, false
	}
	api, apiOK := root["apiVersion"].(string)
	kind, kindOK := root["kind"].(string)
	metadata, metadataOK := root["metadata"].(map[string]any)
	if !apiOK || !fluxIdentity(api) || !kindOK || !fluxIdentity(kind) || strings.HasSuffix(strings.ToLower(kind), "list") || !metadataOK || !fluxIdentityString(metadata["name"]) {
		return false, false
	}
	if _, exists := root["items"]; exists {
		return false, false
	}
	removed := oneOf(api,
		"source.toolkit.fluxcd.io/v1beta1",
		"kustomize.toolkit.fluxcd.io/v1beta1",
		"helm.toolkit.fluxcd.io/v2beta1",
		"image.toolkit.fluxcd.io/v1beta1",
		"notification.toolkit.fluxcd.io/v1beta1",
	)
	if len(latestAPIs) > 0 {
		removed = removed || oneOf(api, latestAPIs...)
		if targetVersion, affected := fluxLatestTargetVersion(api, kind); affected {
			if removed {
				return true, true
			}
			_, version, _ := strings.Cut(api, "/")
			return false, version == targetVersion
		} else if fluxLatestGroup(api) {
			return false, false
		}
	}
	return removed, true
}

func fluxLatestTargetVersion(api, kind string) (string, bool) {
	group, _, ok := strings.Cut(api, "/")
	if !ok {
		return "", false
	}
	version, exists := fluxLatestServedVersions[group][kind]
	return version, exists
}

func fluxLatestGroup(api string) bool {
	group, _, ok := strings.Cut(api, "/")
	if !ok {
		return false
	}
	_, exists := fluxLatestServedVersions[group]
	return exists
}

// fluxIdentity keeps this adapter short of schema validation while rejecting
// whitespace and control-bearing identity values that cannot safely establish
// an absence result from a caller-selected resource.
func fluxIdentity(value string) bool {
	return value != "" && !strings.ContainsFunc(value, func(r rune) bool {
		return unicode.IsSpace(r) || unicode.IsControl(r)
	})
}

func fluxIdentityString(value any) bool {
	text, ok := value.(string)
	return ok && fluxIdentity(text)
}

func fluxListPaginated(root map[string]any) bool {
	metadata, ok := root["metadata"].(map[string]any)
	if !ok {
		return false
	}
	if continueToken, exists := metadata["continue"]; exists {
		value, ok := continueToken.(string)
		if !ok || value != "" {
			return true
		}
	}
	if remaining, exists := metadata["remainingItemCount"]; exists {
		number, ok := remaining.(json.Number)
		if !ok {
			return true
		}
		value, err := number.Int64()
		if err != nil || value < 0 || value > 0 {
			return true
		}
	}
	return false
}
