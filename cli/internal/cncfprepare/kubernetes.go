// SPDX-License-Identifier: AGPL-3.0-only

package cncfprepare

import (
	"encoding/json"
	"strings"
	"unicode/utf8"

	"github.com/prufyx/prufyx/cli/internal/intake"
)

const KubernetesComponent = "pkg:github/kubernetes/kubernetes"
const KubernetesFlowControlFact = "component.kubernetes.flowcontrol_v1beta3_removed_gvk_present"

const (
	ReasonKubernetesRemovedWitness   Reason = "KUBERNETES_FLOWCONTROL_V1BETA3_REMOVED"
	ReasonKubernetesSelectedSetClear Reason = "KUBERNETES_FLOWCONTROL_V1BETA3_ABSENT"
	ReasonKubernetesScopeIncomplete  Reason = "KUBERNETES_API_MANIFEST_SET_INCOMPLETE"
	ReasonKubernetesPagination       Reason = "KUBERNETES_API_LIST_PAGINATION_UNRESOLVED"
	ReasonKubernetesUnresolved       Reason = "KUBERNETES_API_RESOURCE_SHAPE_UNRESOLVED"
	ReasonKubernetesUnreviewed       Reason = "KUBERNETES_FLOWCONTROL_GVK_VERSION_UNREVIEWED"
	ReasonKubernetesTemplated        Reason = "KUBERNETES_API_RENDERING_UNRESOLVED"
	ReasonKubernetesTargetGuard      Reason = "KUBERNETES_API_TARGET_APPLY_OR_OFFICIAL_DISTRIBUTION_UNRESOLVED"
)

// PrepareKubernetesFlowControl converts a bounded caller-selected rendered apply
// set to one canonical fact. It never reads a cluster or validates unrelated GVKs.
func PrepareKubernetesFlowControl(raw []byte, from, to, distribution string, targetApplyRequired, complete bool) (Prepared, error) {
	if len(raw) == 0 || len(raw) > maxInputBytes || !utf8.Valid(raw) {
		return Prepared{}, ErrInvalid
	}
	prepared, _, err := prepareKubernetesFlowControl(func() (kubernetesApplySet, error) { return kubernetesApplySetFromBytes(raw) }, digestBytes(raw), from, to, distribution, targetApplyRequired, complete)
	return prepared, err
}

// prepareKubernetesFlowControl is the flow-control preparation over an apply
// set that read resolves on demand, after the target guard. It also returns
// the documents that made the fact true, when it is declared true.
func prepareKubernetesFlowControl(read func() (kubernetesApplySet, error), sourceDigest, from, to, distribution string, targetApplyRequired, complete bool) (Prepared, map[string][]intake.Source, error) {
	if !targetApplyRequired || distribution != "official_upstream" {
		prepared, err := kubernetesPrepared(sourceDigest, from, to, inputFact{ID: KubernetesFlowControlFact, State: "unsupported"}, StateUnknown, ReasonKubernetesTargetGuard)
		return prepared, nil, err
	}
	set, err := read()
	if err != nil {
		return Prepared{}, nil, ErrInvalid
	}
	inspected := inspectKubernetesFlowControl(set, complete)
	fact := inputFact{ID: KubernetesFlowControlFact, State: "unsupported"}
	state := StateUnknown
	reason := inspected.Reason
	var sources map[string][]intake.Source
	if inspected.Complete && !inspected.Paginated && inspected.Reason == ReasonKubernetesRemovedWitness {
		v := true
		fact = inputFact{ID: KubernetesFlowControlFact, State: "declared", BoolValue: &v}
		state = StatePrepared
		sources = map[string][]intake.Source{KubernetesFlowControlFact: inspected.Matched}
	}
	if inspected.Complete && !inspected.Paginated && inspected.Reason == ReasonKubernetesSelectedSetClear {
		v := false
		fact = inputFact{ID: KubernetesFlowControlFact, State: "declared", BoolValue: &v}
		state = StatePrepared
	}
	if inspected.PresentOnly {
		// The set is unresolved, but a document that was read is at the
		// removed version: the fact is true and the set stays UNKNOWN.
		v := true
		fact = inputFact{ID: KubernetesFlowControlFact, State: "declared", BoolValue: &v}
		sources = map[string][]intake.Source{KubernetesFlowControlFact: inspected.Matched}
	}
	prepared, err := kubernetesPrepared(sourceDigest, from, to, fact, state, reason)
	if err != nil {
		return Prepared{}, nil, err
	}
	return prepared, sources, nil
}

// kubernetesInspection is intentionally a flat, bounded GVK classifier. It
// does not accept typed or nested Lists because either can hide resources
// outside this adapter's one-level reviewed set contract.
type kubernetesInspection struct {
	Removed, Complete, Paginated bool
	// PresentOnly is set when the apply set is unresolved but a document
	// that was read is at the removed version. Reason is then the reason
	// the set is unresolved.
	PresentOnly bool
	Reason      Reason
	// Matched lists the documents at the removed version.
	Matched []intake.Source
}

func inspectKubernetesFlowControl(set kubernetesApplySet, complete bool) kubernetesInspection {
	if set.reason != "" {
		// The documents that were read can only show the removed version
		// present; they never show it absent.
		if complete && !set.readablePaginated {
			if removed, matched, reason := classifyKubernetesFlowControl(set.readable); reason == "" && removed {
				return kubernetesInspection{Removed: true, PresentOnly: true, Reason: set.reason, Matched: matched}
			}
		}
		return kubernetesInspection{Reason: set.reason}
	}
	removed, matched, reason := classifyKubernetesFlowControl(set.documents)
	if reason != "" {
		return kubernetesInspection{Reason: reason}
	}
	result := kubernetesInspection{Removed: removed, Complete: complete, Paginated: set.paginated, Matched: matched}
	switch {
	case !complete:
		result.Reason = ReasonKubernetesScopeIncomplete
	case set.paginated:
		result.Reason = ReasonKubernetesPagination
	case removed:
		result.Reason = ReasonKubernetesRemovedWitness
	default:
		result.Reason = ReasonKubernetesSelectedSetClear
	}
	return result
}

// classifyKubernetesFlowControl reports whether a document is at the removed
// flow-control version and which ones are. A non-empty reason means the
// documents cannot establish the fact either way.
func classifyKubernetesFlowControl(documents []kubernetesDocument) (bool, []intake.Source, Reason) {
	removed := false
	var matched []intake.Source
	for _, document := range documents {
		api, kind, ok := kubernetesGVK(document.value)
		if !ok {
			return false, nil, ReasonKubernetesUnresolved
		}
		if kind != "FlowSchema" && kind != "PriorityLevelConfiguration" {
			continue
		}
		group, _, hasVersion := strings.Cut(api, "/")
		if !hasVersion || group != "flowcontrol.apiserver.k8s.io" {
			continue
		}
		if api == "flowcontrol.apiserver.k8s.io/v1beta3" {
			removed = true
			matched = append(matched, document.source)
			continue
		}
		if api != "flowcontrol.apiserver.k8s.io/v1" {
			// The two reviewed served GVKs are v1beta3 and v1. A group/kind
			// match with another version cannot establish either predicate.
			return false, nil, ReasonKubernetesUnreviewed
		}
	}
	return removed, matched, ""
}

func kubernetesGVK(value map[string]any) (string, string, bool) {
	api, apiOK := value["apiVersion"].(string)
	kind, kindOK := value["kind"].(string)
	return api, kind, apiOK && kindOK && kubernetesAPIVersion(api) && kubernetesKind(kind)
}

func kubernetesAPIVersion(value string) bool {
	if value == "v1" {
		return true
	}
	group, version, found := strings.Cut(value, "/")
	return found && !strings.Contains(version, "/") && kubernetesGroup(group) && kubernetesVersion(version)
}

func kubernetesGroup(value string) bool {
	if value == "" || len(value) > 253 || value[0] == '.' || value[0] == '-' || value[len(value)-1] == '.' || value[len(value)-1] == '-' || strings.Contains(value, "..") {
		return false
	}
	for _, character := range value {
		if !(character >= 'a' && character <= 'z' || character >= '0' && character <= '9' || character == '.' || character == '-') {
			return false
		}
	}
	return true
}

func kubernetesVersion(value string) bool {
	if len(value) < 2 || value[0] != 'v' || value[1] < '0' || value[1] > '9' {
		return false
	}
	for _, character := range value[2:] {
		if !(character >= 'a' && character <= 'z' || character >= '0' && character <= '9') {
			return false
		}
	}
	return true
}

func kubernetesKind(value string) bool {
	if value == "" || len(value) > 63 || value[0] < 'A' || value[0] > 'Z' {
		return false
	}
	for _, character := range value[1:] {
		if !(character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9') {
			return false
		}
	}
	return true
}

func kubernetesListPagination(root map[string]any) (bool, bool) {
	value, found := root["metadata"]
	if !found || value == nil {
		return false, true
	}
	metadata, ok := value.(map[string]any)
	if !ok {
		return false, false
	}
	paginated := false
	if continuation, found := metadata["continue"]; found && continuation != nil {
		text, ok := continuation.(string)
		if !ok {
			return false, false
		}
		paginated = text != ""
	}
	if remaining, found := metadata["remainingItemCount"]; found && remaining != nil {
		number, ok := remaining.(json.Number)
		if !ok {
			return false, false
		}
		count, err := number.Int64()
		if err != nil || count < 0 {
			return false, false
		}
		paginated = paginated || count > 0
	}
	return paginated, true
}
func kubernetesPrepared(sourceDigest, from, to string, fact inputFact, state State, reason Reason) (Prepared, error) {
	if !validVersionSyntax(from) || !validVersionSyntax(to) || from == to {
		return Prepared{}, ErrInvalid
	}
	canonical, err := marshalComponentInput(KubernetesComponent, from, to, []inputFact{fact})
	if err != nil {
		return Prepared{}, ErrInvalid
	}
	return Prepared{CanonicalInputJSON: canonical, SourceDigest: sourceDigest, InputDigest: digestBytes(canonical), State: state, Reason: reason, Omissions: []string{"SELECTED_RENDERED_APPLY_SET_IS_CALLER_SUPPLIED_NOT_LIVE_OBSERVATION", "CLUSTER_OBJECTS_CRDS_RUNTIME_CLIENTS_AND_STORAGE_VERSIONS_NOT_EVALUATED"}}, nil
}
