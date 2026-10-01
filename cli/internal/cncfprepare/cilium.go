// SPDX-License-Identifier: AGPL-3.0-only

package cncfprepare

import (
	"encoding/json"
	"unicode/utf8"
)

const (
	CiliumComponent     = "pkg:github/cilium/cilium"
	CiliumRequiresFact  = "component.cilium.nonempty_requires_fields"
	CiliumFrom          = "1.18.6"
	CiliumTo            = "1.19.0"
	CiliumTargetCRDFrom = "1.18.13"
	CiliumTargetCRDTo   = "1.19.7"
	ciliumAPIVersion    = "cilium.io/v2"
)

var ErrInvalidCilium = ErrInvalid

const (
	ReasonCiliumRequiresWitness   Reason = "CILIUM_NONEMPTY_REQUIRES_WITNESS"
	ReasonCiliumNoRequiresWitness Reason = "CILIUM_REQUIRES_FIELDS_ABSENT_IN_COMPLETE_SET"
	ReasonCiliumSetIncomplete     Reason = "CILIUM_POLICY_SET_COMPLETENESS_MISSING"
	ReasonCiliumPartialList       Reason = "CILIUM_POLICY_LIST_PARTIAL"
	ReasonCiliumUnsupportedShape  Reason = "CILIUM_POLICY_SHAPE_UNSUPPORTED"
	ReasonCiliumUnsupportedPair   Reason = "UNSUPPORTED_VERSION_PAIR"
)

// PrepareCilium derives the existing Cilium requires-field fact from a bounded
// local policy document. A true witness is sufficient for the existing blocker.
// A false result requires an explicit operator declaration that the input is a
// complete CNP and CCNP set; the adapter never discovers that set from a cluster.
func PrepareCilium(raw []byte, from, to string, completeSet *bool) (Prepared, error) {
	if len(raw) == 0 || len(raw) > maxInputBytes || !utf8.Valid(raw) || !validVersionSyntax(from) || !validVersionSyntax(to) || from == to {
		return Prepared{}, ErrInvalidCilium
	}
	value, err := decodeStrictAllowNull(raw)
	if err != nil {
		return Prepared{}, ErrInvalidCilium
	}
	witness, malformed, partial := ciliumDocument(value)
	reason, state := ReasonCiliumSetIncomplete, StateUnknown
	var fact *bool
	switch {
	case !supportedCiliumPair(from, to):
		reason = ReasonCiliumUnsupportedPair
	case witness:
		value := true
		fact = &value
		state = StatePrepared
		reason = ReasonCiliumRequiresWitness
	case malformed:
		reason = ReasonCiliumUnsupportedShape
	case partial:
		reason = ReasonCiliumPartialList
	case completeSet != nil && *completeSet:
		value := false
		fact = &value
		state = StatePrepared
		reason = ReasonCiliumNoRequiresWitness
	}
	canonical, err := marshalComponentInput(CiliumComponent, from, to, []inputFact{{ID: CiliumRequiresFact, State: map[bool]string{true: "declared", false: "missing"}[fact != nil], BoolValue: fact}})
	if err != nil {
		return Prepared{}, ErrInvalidCilium
	}
	return Prepared{CanonicalInputJSON: canonical, SourceDigest: digestBytes(raw), InputDigest: digestBytes(canonical), State: state, Reason: reason, Omissions: []string{"CNP_CCNP_SET_COMPLETENESS_IS_OPERATOR_DECLARED", "CNP_CCNP_LIST_PAGINATION_NOT_COMPLETE", "CILIUM_POLICY_SEMANTICS_NOT_EVALUATED", OmissionNoLiveObservation, OmissionNoWholeUpgrade}}, nil
}

func supportedCiliumPair(from, to string) bool {
	return (from == CiliumFrom && to == CiliumTo) || (from == CiliumTargetCRDFrom && to == CiliumTargetCRDTo)
}

func ciliumDocument(value any) (witness, malformed, partial bool) {
	root, ok := value.(map[string]any)
	if !ok {
		return false, true, false
	}
	api, apiOK := root["apiVersion"].(string)
	kind, kindOK := root["kind"].(string)
	if !apiOK || !kindOK {
		return false, true, false
	}
	if kind == "List" {
		if api != "v1" {
			return false, true, false
		}
		items, ok := root["items"].([]any)
		if !ok {
			return false, true, false
		}
		partial, malformed = ciliumListPartial(root)
		for _, item := range items {
			w, bad := ciliumGenericListItem(item)
			witness = witness || w
			malformed = malformed || bad
		}
		return
	}
	if kind == "CiliumNetworkPolicyList" || kind == "CiliumClusterwideNetworkPolicyList" {
		if api != ciliumAPIVersion {
			return false, true, false
		}
		items, ok := root["items"].([]any)
		if !ok {
			return false, true, false
		}
		partial, malformed = ciliumListPartial(root)
		itemKind := "CiliumNetworkPolicy"
		if kind == "CiliumClusterwideNetworkPolicyList" {
			itemKind = "CiliumClusterwideNetworkPolicy"
		}
		for _, item := range items {
			w, bad := ciliumPolicy(item, itemKind)
			witness = witness || w
			malformed = malformed || bad
		}
		return
	}
	witness, malformed = ciliumPolicy(root, kind)
	return
}

func ciliumListPartial(root map[string]any) (partial, malformed bool) {
	value, exists := root["metadata"]
	if !exists || value == nil {
		return false, false
	}
	metadata, ok := value.(map[string]any)
	if !ok {
		return false, true
	}
	if continuation, exists := metadata["continue"]; exists && continuation != nil {
		text, ok := continuation.(string)
		if !ok {
			return false, true
		}
		partial = text != ""
	}
	if count, exists := metadata["remainingItemCount"]; exists && count != nil {
		number, ok := count.(json.Number)
		if !ok {
			return false, true
		}
		remaining, err := number.Int64()
		if err != nil || remaining < 0 {
			return false, true
		}
		partial = partial || remaining > 0
	}
	return partial, false
}

func ciliumGenericListItem(value any) (bool, bool) {
	item, ok := value.(map[string]any)
	if !ok {
		return false, true
	}
	api, apiOK := item["apiVersion"].(string)
	kind, kindOK := item["kind"].(string)
	if !apiOK || !kindOK || kind == "List" {
		return false, true
	}
	if kind == "CiliumNetworkPolicy" || kind == "CiliumClusterwideNetworkPolicy" {
		if api != ciliumAPIVersion {
			return false, true
		}
		return ciliumPolicy(item, kind)
	}
	return false, false // A clearly typed unrelated Kubernetes object is outside this bounded input.
}

func ciliumPolicy(value any, expectedKind string) (witness, malformed bool) {
	root, ok := value.(map[string]any)
	if !ok {
		return false, true
	}
	api, apiOK := root["apiVersion"].(string)
	kind, kindOK := root["kind"].(string)
	if !apiOK || !kindOK || api != ciliumAPIVersion || kind != expectedKind || (kind != "CiliumNetworkPolicy" && kind != "CiliumClusterwideNetworkPolicy") {
		return false, true
	}
	for _, key := range []string{"spec", "specs"} {
		part, exists := root[key]
		if !exists || part == nil {
			continue
		}
		if key == "spec" {
			w, bad := ciliumRule(part)
			witness = witness || w
			malformed = malformed || bad
		} else {
			items, ok := part.([]any)
			if !ok {
				malformed = true
				continue
			}
			for _, item := range items {
				w, bad := ciliumRule(item)
				witness = witness || w
				malformed = malformed || bad
			}
		}
	}
	return
}

func ciliumRule(value any) (witness, malformed bool) {
	rule, ok := value.(map[string]any)
	if !ok {
		return false, true
	}
	for container, target := range map[string]string{"ingress": "fromRequires", "ingressDeny": "fromRequires", "egress": "toRequires", "egressDeny": "toRequires"} {
		part, exists := rule[container]
		if !exists || part == nil {
			continue
		}
		items, ok := part.([]any)
		if !ok {
			malformed = true
			continue
		}
		for _, item := range items {
			entry, ok := item.(map[string]any)
			if !ok {
				malformed = true
				continue
			}
			field, exists := entry[target]
			if !exists || field == nil {
				continue
			}
			values, ok := field.([]any)
			if !ok {
				malformed = true
				continue
			}
			if len(values) > 0 {
				witness = true
			}
		}
	}
	return
}
