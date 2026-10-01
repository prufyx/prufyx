// SPDX-License-Identifier: AGPL-3.0-only

package cncfprepare

import (
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/BurntSushi/toml"
)

const (
	ContainerdComponent                    = "pkg:github/containerd/containerd"
	ContainerdFrom                         = "1.7.28"
	ContainerdTo                           = "2.0.0"
	ContainerdRemovedRuntimeFact           = "component.containerd.selected_runtime_uses_removed_official_shim"
	ContainerdOfficialDistributionFact     = "component.containerd.official_upstream_distribution"
	ContainerdBundledRuntimesOnlyFact      = "component.containerd.official_bundled_runtimes_only"
	ContainerdRuntimeV1Linux               = "io.containerd.runtime.v1.linux"
	ContainerdRuncV1                       = "io.containerd.runc.v1"
	ContainerdRuncV2                       = "io.containerd.runc.v2"
	containerdConfigV2CRIPlugin            = "io.containerd.grpc.v1.cri"
	containerdConfigV3CRIRuntimePlugin     = "io.containerd.cri.v1.runtime"
	ReasonContainerdRemovedRuntime         = "CONTAINERD_SELECTED_OFFICIAL_RUNTIME_REMOVED"
	ReasonContainerdRuncV2                 = "CONTAINERD_SELECTED_RUNTIME_USES_RUNC_V2"
	ReasonContainerdDeclarationsIncomplete = "CONTAINERD_CONFIG_DECLARATIONS_INCOMPLETE"
	ReasonContainerdConfigUnsupported      = "CONTAINERD_CONFIG_SHAPE_UNSUPPORTED"
	ReasonContainerdImportsUnsupported     = "CONTAINERD_CONFIG_IMPORTS_UNRESOLVED"
	ReasonContainerdHandlerMissing         = "CONTAINERD_SELECTED_RUNTIME_HANDLER_MISSING"
	ReasonContainerdRuntimePathUnsupported = "CONTAINERD_SELECTED_RUNTIME_PATH_OVERRIDE_UNSUPPORTED"
	ReasonContainerdRuntimeTypeUnsupported = "CONTAINERD_SELECTED_RUNTIME_TYPE_UNSUPPORTED"
)

// PrepareContainerdConfig classifies the runtime_type for one explicitly
// selected CRI runtime handler in a caller-supplied effective containerd TOML
// configuration. It supports config versions 2 and 3 without treating version
// 2 as a blocker: containerd 2.0 migrates version 2 plugin configuration on
// startup and preserves runtime_type. Imports and runtime_path overrides remain
// unresolved because this adapter never reads another file or searches PATH.
func PrepareContainerdConfig(raw []byte, handler, from, to string, complete, precedenceResolved, officialUpstream, officialBundledRuntimesOnly bool) (Prepared, error) {
	if len(raw) == 0 || len(raw) > maxInputBytes || !utf8.Valid(raw) || !validVersionSyntax(from) || !validVersionSyntax(to) || from == to || !validContainerdHandler(handler) {
		return Prepared{}, ErrInvalid
	}

	removed, parseReason, supported, err := parseContainerdSelectedRuntime(raw, handler)
	if err != nil {
		return Prepared{}, err
	}

	facts := []inputFact{
		{ID: ContainerdBundledRuntimesOnlyFact, State: "unsupported"},
		{ID: ContainerdOfficialDistributionFact, State: "unsupported"},
		{ID: ContainerdRemovedRuntimeFact, State: "unsupported"},
	}
	if officialBundledRuntimesOnly {
		facts[0] = boolFact(ContainerdBundledRuntimesOnlyFact, true)
	}
	if officialUpstream {
		facts[1] = boolFact(ContainerdOfficialDistributionFact, true)
	}

	state, reason := StateUnknown, ReasonContainerdDeclarationsIncomplete
	switch {
	case !supported:
		reason = parseReason
	case !complete || !precedenceResolved || !officialUpstream || !officialBundledRuntimesOnly:
		reason = ReasonContainerdDeclarationsIncomplete
	default:
		facts[2] = boolFact(ContainerdRemovedRuntimeFact, removed)
		state = StatePrepared
		reason = parseReason
	}

	canonical, err := marshalComponentInput(ContainerdComponent, from, to, facts)
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
			"CALLER_SUPPLIED_EFFECTIVE_CONTAINERD_CONFIG_NOT_LIVE_OBSERVATION",
			"CONFIG_COMPLETENESS_PRECEDENCE_DISTRIBUTION_AND_BUNDLED_RUNTIME_SCOPE_ARE_CALLER_DECLARATIONS",
			"VERSION_PAIR_COVERAGE_IS_SELECTED_BY_THE_RULE_PACK_NOT_THE_PREPARER",
			"SELECTED_RUNTIME_HANDLER_NAME_AND_UNRELATED_TOML_VALUES_ARE_MINIMIZED_OUT",
			"IMPORTS_RUNTIME_PATH_OVERRIDES_CUSTOM_SHIMS_AND_PATH_CONTENTS_NOT_RESOLVED",
			"RUNTIME_EXECUTION_CONTAINER_CREATION_AND_WHOLE_UPGRADE_COMPATIBILITY_NOT_EVALUATED",
		},
	}, nil
}

func parseContainerdSelectedRuntime(raw []byte, handler string) (removed bool, reason Reason, supported bool, err error) {
	var root map[string]any
	if _, decodeErr := toml.Decode(string(raw), &root); decodeErr != nil {
		return false, ReasonContainerdConfigUnsupported, false, ErrInvalid
	}
	if _, exists := root["imports"]; exists {
		return false, ReasonContainerdImportsUnsupported, false, nil
	}
	version, ok := root["version"].(int64)
	if !ok || version != 2 && version != 3 {
		return false, ReasonContainerdConfigUnsupported, false, nil
	}
	plugins, ok := containerdTOMLMap(root["plugins"])
	if !ok {
		return false, ReasonContainerdHandlerMissing, false, nil
	}
	pluginID := containerdConfigV2CRIPlugin
	otherPluginID := containerdConfigV3CRIRuntimePlugin
	if version == 3 {
		pluginID, otherPluginID = otherPluginID, pluginID
	}
	if containerdPluginDefinesHandler(plugins[otherPluginID], handler) {
		return false, ReasonContainerdConfigUnsupported, false, nil
	}
	pluginConfig, ok := containerdTOMLMap(plugins[pluginID])
	if !ok {
		return false, ReasonContainerdHandlerMissing, false, nil
	}
	containerdConfig, ok := containerdTOMLMap(pluginConfig["containerd"])
	if !ok {
		return false, ReasonContainerdHandlerMissing, false, nil
	}
	runtimes, ok := containerdTOMLMap(containerdConfig["runtimes"])
	if !ok {
		return false, ReasonContainerdHandlerMissing, false, nil
	}
	runtimeConfig, ok := containerdTOMLMap(runtimes[handler])
	if !ok {
		return false, ReasonContainerdHandlerMissing, false, nil
	}
	if _, exists := runtimeConfig["runtime_path"]; exists {
		return false, ReasonContainerdRuntimePathUnsupported, false, nil
	}
	runtimeType, ok := runtimeConfig["runtime_type"].(string)
	if !ok {
		return false, ReasonContainerdRuntimeTypeUnsupported, false, nil
	}
	switch runtimeType {
	case ContainerdRuntimeV1Linux, ContainerdRuncV1:
		return true, ReasonContainerdRemovedRuntime, true, nil
	case ContainerdRuncV2:
		return false, ReasonContainerdRuncV2, true, nil
	default:
		return false, ReasonContainerdRuntimeTypeUnsupported, false, nil
	}
}

func containerdPluginDefinesHandler(value any, handler string) bool {
	pluginConfig, ok := containerdTOMLMap(value)
	if !ok {
		return false
	}
	containerdConfig, ok := containerdTOMLMap(pluginConfig["containerd"])
	if !ok {
		return false
	}
	runtimes, ok := containerdTOMLMap(containerdConfig["runtimes"])
	if !ok {
		return false
	}
	_, exists := runtimes[handler]
	return exists
}

func containerdTOMLMap(value any) (map[string]any, bool) {
	result, ok := value.(map[string]any)
	return result, ok
}

func validContainerdHandler(handler string) bool {
	if handler == "" || len(handler) > 128 || !utf8.ValidString(handler) || strings.TrimSpace(handler) != handler {
		return false
	}
	for _, r := range handler {
		if unicode.IsControl(r) || unicode.IsSpace(r) {
			return false
		}
	}
	return true
}
