// SPDX-License-Identifier: AGPL-3.0-only

// Package kamajipredicate computes a minimized, declared pod-CIDR predicate.
// It has no evidence adapter, rule admission, catalogue or command integration.
package kamajipredicate

import (
	"encoding/json"
	"errors"
	"net/netip"

	"github.com/prufyx/prufyx/cli/internal/strictjson"
)

const (
	Component     = "pkg:github/clastix/kamaji"
	FactID        = "component.kamaji.pod_cidrs_same_family"
	RuleID        = "kamaji.tcp-pod-cidrs-distinct-family"
	Profile       = "kamaji.tcp-pod-cidrs-family.v1"
	MaxInputBytes = 64 << 10
	maxDepth      = 24
	maxMembers    = 1024
	maxResources  = 16
)

// ErrInvalid is deliberately fixed: parser diagnostics must not retain input.
var ErrInvalid = errors.New("invalid declared pod-CIDR input")

// Selection identifies an index in a complete declared resource array, or zero
// for a standalone resource. These are declarations, not verified evidence.
type Selection struct {
	Index    int
	Explicit bool
	Complete bool
}

// Result retains no resource names, raw manifests or network addresses. A
// declared value is not a verified claim and cannot establish admission.
type Result struct {
	FactID    string `json:"factId"`
	State     string `json:"state"`
	BoolValue *bool  `json:"boolValue,omitempty"`
	Reason    string `json:"reason"`
}

func unknown(reason string) Result { return Result{FactID: FactID, State: "UNKNOWN", Reason: reason} }

// Produce accepts one JSON resource or a JSON array with explicit selection.
// Kubernetes List wrappers and other envelopes are unsupported. Unsupported
// values remain UNKNOWN; malformed or ambiguous JSON is an integrity refusal.
func Produce(raw []byte, selection Selection) (Result, error) {
	if len(raw) == 0 || len(raw) > MaxInputBytes || strictjson.CheckDepth(raw, maxDepth) != nil {
		return Result{}, ErrInvalid
	}
	var doc any
	if json.Unmarshal(raw, &doc) != nil {
		return Result{}, ErrInvalid
	}
	remaining := maxMembers
	if !bounded(doc, &remaining) {
		return Result{}, ErrInvalid
	}
	if !selection.Explicit || !selection.Complete {
		return unknown("RESOURCE_SELECTION_OR_COMPLETENESS_MISSING"), nil
	}
	resources := []any{doc}
	if list, ok := doc.([]any); ok {
		resources = list
	}
	if len(resources) == 0 || len(resources) > maxResources || selection.Index < 0 || selection.Index >= len(resources) {
		return unknown("RESOURCE_SELECTION_UNSUPPORTED"), nil
	}
	resource, ok := resources[selection.Index].(map[string]any)
	if !ok || resource["apiVersion"] != "kamaji.clastix.io/v1alpha1" || resource["kind"] != "TenantControlPlane" {
		return unknown("RESOURCE_GVK_UNSUPPORTED"), nil
	}
	// Do not reinterpret an envelope as a resource, even with a plausible GVK.
	if _, ok := resource["items"]; ok {
		return unknown("RESOURCE_WRAPPER_UNSUPPORTED"), nil
	}
	if _, ok := resource["resources"]; ok {
		return unknown("RESOURCE_WRAPPER_UNSUPPORTED"), nil
	}
	spec, ok := resource["spec"].(map[string]any)
	if !ok {
		return unknown("NETWORK_PROFILE_MISSING_OR_UNSUPPORTED"), nil
	}
	network, ok := spec["networkProfile"].(map[string]any)
	if !ok {
		return unknown("NETWORK_PROFILE_MISSING_OR_UNSUPPORTED"), nil
	}
	values, ok := network["podCidrs"].([]any)
	if !ok || len(values) < 1 || len(values) > 2 {
		return unknown("POD_CIDRS_MISSING_OR_UNSUPPORTED"), nil
	}
	var families [2]bool
	for i, value := range values {
		text, ok := value.(string)
		if !ok || len(text) > 64 {
			return unknown("POD_CIDR_REPRESENTATION_UNSUPPORTED"), nil
		}
		prefix, err := netip.ParsePrefix(text)
		if err != nil || prefix.Addr().Is4In6() || prefix != prefix.Masked() || prefix.String() != text {
			return unknown("POD_CIDR_REPRESENTATION_UNSUPPORTED"), nil
		}
		families[i] = prefix.Addr().Is4()
	}
	// Evaluate the array directly: two identical entries still count as two.
	value := len(values) == 2 && families[0] == families[1]
	return Result{FactID: FactID, State: "DECLARED", BoolValue: &value, Reason: "DECLARED_PREDICATE_ONLY_EVIDENCE_UNVERIFIED"}, nil
}

func bounded(v any, remaining *int) bool {
	*remaining--
	if *remaining < 0 {
		return false
	}
	switch v := v.(type) {
	case map[string]any:
		for key, child := range v {
			if len(key) > 256 || !bounded(child, remaining) {
				return false
			}
		}
	case []any:
		for _, child := range v {
			if !bounded(child, remaining) {
				return false
			}
		}
	}
	return true
}
