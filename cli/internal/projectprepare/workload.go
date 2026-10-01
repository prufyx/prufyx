// SPDX-License-Identifier: AGPL-3.0-only

package projectprepare

import (
	"bytes"
	"encoding/json"
	"io"
	"strings"
)

const (
	ArgoWorkflowsProject   = "argo-workflows"
	ArgoWorkflowsComponent = "pkg:github/argoproj/argo-workflows"
	ArgoWorkflowsFrom      = "3.5.0"
	ArgoWorkflowsTo        = "3.6.0"
	ArgoWorkflowsFact      = "component.argo-workflows.server_legacy_basehref_flag_present"
	ArgoWorkflowsLatestTo  = "4.1.3"
	argoWorkflowsImage     = "quay.io/argoproj/argocli:v3.6.0"
)

var argoWorkflowsLatestOrigins = [...]string{"3.4.18", "3.5.15", "3.6.19", "3.7.18", "4.0.11"}

// PrepareWorkload inspects one caller-supplied Kubernetes workload JSON file.
// complete is an explicit declaration about the supplied selected-container
// argv; it is never inferred from cluster state.
func PrepareWorkload(project string, raw []byte, from, to string, complete bool) (Prepared, error) {
	if project != ArgoWorkflowsProject || len(raw) == 0 || len(raw) > maxInputBytes || !versionRE.MatchString(from) || !versionRE.MatchString(to) || from == to {
		return Prepared{}, ErrInvalid
	}
	targetImage, pairSupported := argoWorkflowsTargetImage(from, to)
	found, supported, sourceDerivedCommand, err := argoWorkflowsServerBaseHref(raw, targetImage)
	if err != nil {
		return Prepared{}, ErrInvalid
	}
	fact := inputFact{ID: ArgoWorkflowsFact, State: "unsupported"}
	state, reason := "UNKNOWN", "WORKLOAD_OR_SELECTED_ARGV_INCOMPLETE_OR_UNSUPPORTED"
	if complete && pairSupported && supported {
		value := found
		fact = inputFact{ID: ArgoWorkflowsFact, State: "declared", BoolValue: &value}
		state, reason = "PREPARED", "NATIVE_WORKLOAD_SELECTED_SERVER_ARGV_INSPECTED"
	}
	canonical, err := marshalInput(ArgoWorkflowsComponent, from, to, []inputFact{fact})
	if err != nil {
		return Prepared{}, ErrInvalid
	}
	omissions := []string{
		"CALLER_SUPPLIED_WORKLOAD_NOT_LIVE_OBSERVATION",
		"IMAGE_PROVENANCE_AND_RUNTIME_NOT_VERIFIED",
		"WHOLE_UPGRADE_COMPATIBILITY_NOT_EVALUATED",
	}
	if sourceDerivedCommand {
		omissions = append(omissions, "COMMAND_DEFAULT_DERIVED_FROM_REVIEWED_IMAGE_ENTRYPOINT_SOURCE")
	}
	return Prepared{
		CanonicalInputJSON: canonical,
		SourceDigest:       digest(raw),
		InputDigest:        digest(canonical),
		State:              state,
		Reason:             reason,
		Omissions:          omissions,
	}, nil
}

func argoWorkflowsTargetImage(from, to string) (string, bool) {
	if from == ArgoWorkflowsFrom && to == ArgoWorkflowsTo {
		return argoWorkflowsImage, true
	}
	if to == ArgoWorkflowsLatestTo {
		for _, origin := range argoWorkflowsLatestOrigins {
			if from == origin {
				return "quay.io/argoproj/argocli:v4.1.3", true
			}
		}
	}
	return "", false
}

func argoWorkflowsServerBaseHref(raw []byte, targetImage string) (bool, bool, bool, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	value, err := decodeJSONValue(decoder)
	if err != nil {
		return false, false, false, ErrInvalid
	}
	if token, extra := decoder.Token(); extra != io.EOF || token != nil {
		return false, false, false, ErrInvalid
	}
	root, ok := value.(map[string]any)
	if !ok {
		return false, false, false, ErrInvalid
	}
	apiVersion, ok := exactString(root, "apiVersion")
	if !ok || apiVersion != "apps/v1" {
		return false, false, false, nil
	}
	kind, ok := exactString(root, "kind")
	if !ok || kind != "Deployment" {
		return false, false, false, nil
	}
	spec, ok := exactObject(root, "spec")
	if !ok {
		return false, false, false, nil
	}
	template, ok := exactObject(spec, "template")
	if !ok {
		return false, false, false, nil
	}
	podSpec, ok := exactObject(template, "spec")
	if !ok {
		return false, false, false, nil
	}
	containers, ok := exactArray(podSpec, "containers")
	if !ok || len(containers) == 0 {
		return false, false, false, nil
	}
	seenNames := map[string]bool{}
	var selected map[string]any
	for _, rawContainer := range containers {
		container, ok := rawContainer.(map[string]any)
		if !ok {
			return false, false, false, nil
		}
		name, ok := exactString(container, "name")
		if !ok || name == "" || seenNames[name] {
			return false, false, false, nil
		}
		seenNames[name] = true
		if name == "argo-server" {
			selected = container
		}
	}
	if selected == nil {
		return false, false, false, nil
	}
	image, ok := exactString(selected, "image")
	if !ok || targetImage == "" || image != targetImage {
		return false, false, false, nil
	}
	commandSourceDerived, commandSupported := argoWorkflowsCommand(selected)
	if !commandSupported {
		return false, false, false, nil
	}
	if unresolvedArgoWorkflowsEnvironment(selected) {
		return false, false, false, nil
	}
	args, ok := exactStringArray(selected, "args")
	if !ok {
		return false, false, false, nil
	}
	legacy, supported, err := inspectArgoWorkflowsServerArgs(args)
	return legacy, supported, commandSourceDerived, err
}

func argoWorkflowsCommand(container map[string]any) (bool, bool) {
	if hasCaseVariant(container, "command") {
		return false, false
	}
	raw, exists := container["command"]
	if !exists {
		return true, true
	}
	values, ok := raw.([]any)
	if !ok || len(values) != 1 {
		return false, false
	}
	command, ok := values[0].(string)
	return false, ok && command == "argo"
}

func exactString(object map[string]any, key string) (string, bool) {
	if hasCaseVariant(object, key) {
		return "", false
	}
	value, ok := object[key].(string)
	return value, ok
}

func exactObject(object map[string]any, key string) (map[string]any, bool) {
	if hasCaseVariant(object, key) {
		return nil, false
	}
	value, ok := object[key].(map[string]any)
	return value, ok
}

func exactArray(object map[string]any, key string) ([]any, bool) {
	if hasCaseVariant(object, key) {
		return nil, false
	}
	value, ok := object[key].([]any)
	return value, ok
}

func exactStringArray(object map[string]any, key string) ([]string, bool) {
	values, ok := exactArray(object, key)
	if !ok {
		return nil, false
	}
	result := make([]string, len(values))
	for index, raw := range values {
		value, ok := raw.(string)
		if !ok {
			return nil, false
		}
		result[index] = value
	}
	return result, true
}

func unresolvedArgoWorkflowsEnvironment(container map[string]any) bool {
	if hasCaseVariant(container, "env") || hasCaseVariant(container, "envFrom") {
		return true
	}
	if value, exists := container["envFrom"]; exists {
		envFrom, ok := value.([]any)
		if !ok || len(envFrom) != 0 {
			return true
		}
	}
	if value, exists := container["env"]; exists {
		env, ok := value.([]any)
		if !ok || len(env) != 0 {
			return true
		}
	}
	return false
}

func inspectArgoWorkflowsServerArgs(args []string) (bool, bool, error) {
	if len(args) == 0 || args[0] != "server" {
		return false, false, nil
	}
	legacy, target := false, false
	for index := 1; index < len(args); index++ {
		token := args[index]
		if token == "" || token == "--" || strings.HasPrefix(token, "@") || strings.Contains(token, "$") {
			return false, false, nil
		}
		name, value, inline := strings.Cut(token, "=")
		if inline && strings.HasPrefix(value, "@") {
			return false, false, nil
		}
		if name != "--basehref" && name != "--base-href" {
			if !inline || !literalArgoWorkflowsOption(name) {
				return false, false, nil
			}
			continue
		}
		if (name == "--basehref" && legacy) || (name == "--base-href" && target) {
			return false, false, nil
		}
		if inline {
			if name == "--basehref" {
				legacy = true
			} else {
				target = true
			}
			continue
		}
		if index+1 >= len(args) || args[index+1] == "" || strings.HasPrefix(args[index+1], "-") || strings.HasPrefix(args[index+1], "@") || strings.Contains(args[index+1], "$") {
			return false, false, nil
		}
		index++
		if name == "--basehref" {
			legacy = true
		} else {
			target = true
		}
	}
	return legacy, true, nil
}

func literalArgoWorkflowsOption(name string) bool {
	if len(name) < 3 || !strings.HasPrefix(name, "--") {
		return false
	}
	body := name[2:]
	alphanumeric := func(character byte) bool {
		return character >= 'a' && character <= 'z' || character >= '0' && character <= '9'
	}
	if !alphanumeric(body[0]) || !alphanumeric(body[len(body)-1]) {
		return false
	}
	for _, character := range body {
		if character < 'a' || character > 'z' {
			if character < '0' || character > '9' {
				if character != '-' {
					return false
				}
			}
		}
	}
	return true
}
