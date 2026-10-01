// SPDX-License-Identifier: AGPL-3.0-only

package cncfprepare

// KubeVirt 1.9 requires each submitted interface to have exactly one binding
// method or binding plugin. This adapter checks only caller-supplied VM/VMI
// JSON and does not inspect admission, feature gates, plugins, or a cluster.
const (
	KubeVirtComponent = "pkg:github/kubevirt/kubevirt"
	KubeVirtFact      = "component.kubevirt.interface_binding_cardinality_invalid"
	KubeVirtFrom      = "1.8.4"
	KubeVirtTo        = "1.9.0"
)

const (
	ReasonKubeVirtBindingInvalid Reason = "KUBEVIRT_INTERFACE_BINDING_CARDINALITY_INVALID"
	ReasonKubeVirtBindingValid   Reason = "KUBEVIRT_INTERFACE_BINDING_CARDINALITY_VALID"
	ReasonKubeVirtUnsupported    Reason = "KUBEVIRT_INTERFACE_INPUT_UNSUPPORTED"
)

func PrepareKubeVirt(raw []byte, from, to string) (Prepared, error) {
	if len(raw) == 0 || len(raw) > maxInputBytes || !validVersionSyntax(from) || !validVersionSyntax(to) || from == to {
		return Prepared{}, ErrInvalid
	}
	value, err := decodeStrict(raw)
	if err != nil {
		return Prepared{}, ErrInvalid
	}
	invalid, ok := kubeVirtBindingFact(value)
	fact := inputFact{ID: KubeVirtFact, State: "unsupported"}
	state, reason := StateUnknown, ReasonKubeVirtUnsupported
	if ok {
		fact.State = "declared"
		fact.BoolValue = &invalid
		state = StatePrepared
		if invalid {
			reason = ReasonKubeVirtBindingInvalid
		} else {
			reason = ReasonKubeVirtBindingValid
		}
	}
	canonical, err := marshalComponentInput(KubeVirtComponent, from, to, []inputFact{fact})
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
			"NATIVE_VM_OR_VMI_IS_CALLER_SUPPLIED_NOT_LIVE_OBSERVATION",
			"FEATURE_GATES_PLUGINS_ADMISSION_AND_RUNTIME_NOT_EVALUATED",
		},
	}, nil
}

func kubeVirtBindingFact(value any) (bool, bool) {
	root, ok := value.(map[string]any)
	if !ok || root["apiVersion"] != "kubevirt.io/v1" {
		return false, false
	}
	kind, ok := root["kind"].(string)
	if !ok || !oneOf(kind, "VirtualMachine", "VirtualMachineInstance") {
		return false, false
	}
	metadata, ok := root["metadata"].(map[string]any)
	if !ok || !nonemptyString(metadata["name"]) || !nonemptyString(metadata["namespace"]) {
		return false, false
	}
	spec, ok := root["spec"].(map[string]any)
	if !ok {
		return false, false
	}
	if kind == "VirtualMachine" {
		template, ok := spec["template"].(map[string]any)
		if !ok {
			return false, false
		}
		spec, ok = template["spec"].(map[string]any)
		if !ok {
			return false, false
		}
	}
	domain, ok := spec["domain"].(map[string]any)
	if !ok {
		return false, false
	}
	devices, ok := domain["devices"].(map[string]any)
	if !ok {
		return false, false
	}
	interfaces, ok := devices["interfaces"].([]any)
	if !ok {
		return false, false
	}
	invalid := false
	for _, value := range interfaces {
		iface, ok := value.(map[string]any)
		if !ok || !nonemptyString(iface["name"]) {
			return false, false
		}
		count, ok := kubeVirtInterfaceBindingCount(iface)
		if !ok {
			return false, false
		}
		if count != 1 {
			invalid = true
		}
	}
	return invalid, true
}

func kubeVirtInterfaceBindingCount(iface map[string]any) (int, bool) {
	count := 0
	if value, present := iface["binding"]; present && value != nil {
		if _, ok := value.(map[string]any); !ok {
			return 0, false
		}
		count++
	}
	// InterfaceBindingMethod is an inline API struct, so these fields are
	// direct members of the interface JSON object. The plugin is the only
	// binding slot represented by the separate nested `binding` member above.
	for _, name := range []string{"bridge", "masquerade", "sriov", "passtBinding"} {
		value, present := iface[name]
		if !present || value == nil {
			continue
		}
		if _, ok := value.(map[string]any); !ok {
			return 0, false
		}
		count++
	}
	return count, true
}

func nonemptyString(value any) bool {
	s, ok := value.(string)
	return ok && s != ""
}
