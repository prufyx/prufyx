// SPDX-License-Identifier: AGPL-3.0-only

package cncfprepare

import (
	"bytes"
	"io"
	"strings"
	"unicode/utf8"

	"gopkg.in/yaml.v3"
)

const CiliumInvalidEffectiveClusterNameFact = "component.cilium.invalid_effective_cluster_name"

const (
	ReasonCiliumClusterNameInvalid      Reason = "CILIUM_EFFECTIVE_CLUSTER_NAME_INVALID"
	ReasonCiliumClusterNameValid        Reason = "CILIUM_EFFECTIVE_CLUSTER_NAME_VALID"
	ReasonCiliumClusterNameUnresolved   Reason = "CILIUM_CONFIGMAP_CLUSTER_NAME_UNRESOLVED"
	ReasonCiliumClusterNameScopeMissing Reason = "CILIUM_CONFIGMAP_AUTHORITY_UNRESOLVED"
)

// PrepareCiliumClusterName classifies only the trimmed literal cluster-name in
// one caller-selected v1 ConfigMap. The caller declarations bind that mapping
// as the complete, precedence-resolved official-upstream effective input; the
// adapter never discovers ConfigMaps or configuration precedence from a cluster.
func PrepareCiliumClusterName(raw []byte, from, to, distribution string, complete, precedenceResolved bool) (Prepared, error) {
	if len(raw) == 0 || len(raw) > maxInputBytes || !utf8.Valid(raw) || !validVersionSyntax(from) || !validVersionSyntax(to) || from == to {
		return Prepared{}, ErrInvalid
	}
	fact := inputFact{ID: CiliumInvalidEffectiveClusterNameFact, State: "unsupported"}
	state, reason := StateUnknown, ReasonCiliumClusterNameScopeMissing
	if distribution == "official_upstream" && complete && precedenceResolved {
		invalid, parsed := ciliumConfigMapClusterName(raw)
		if parsed {
			fact.State = "declared"
			fact.BoolValue = &invalid
			state = StatePrepared
			if invalid {
				reason = ReasonCiliumClusterNameInvalid
			} else {
				reason = ReasonCiliumClusterNameValid
			}
		} else {
			reason = ReasonCiliumClusterNameUnresolved
		}
	}
	canonical, err := marshalComponentInput(CiliumComponent, from, to, []inputFact{fact})
	if err != nil {
		return Prepared{}, ErrInvalid
	}
	return Prepared{CanonicalInputJSON: canonical, SourceDigest: digestBytes(raw), InputDigest: digestBytes(canonical), State: state, Reason: reason,
		Omissions: []string{"CALLER_SELECTED_CONFIGMAP_AND_PRECEDENCE_NOT_LIVE_OBSERVATION", "CILIUM_CLUSTER_MESH_NETWORK_AND_NAME_COLLISION_NOT_EVALUATED", OmissionNoWholeUpgrade}}, nil
}

func ciliumConfigMapClusterName(raw []byte) (bool, bool) {
	root, ok := ciliumClusterSingleYAML(raw)
	if !ok || root.Kind != yaml.MappingNode {
		return false, false
	}
	api, state := argoCDExactField(root, "apiVersion")
	if state != argoCDFieldFound || !argoCDString(api, "v1") {
		return false, false
	}
	kind, state := argoCDExactField(root, "kind")
	if state != argoCDFieldFound || !argoCDString(kind, "ConfigMap") {
		return false, false
	}
	metadata, state := argoCDExactField(root, "metadata")
	if state != argoCDFieldFound || metadata.Kind != yaml.MappingNode {
		return false, false
	}
	name, state := argoCDExactField(metadata, "name")
	if state != argoCDFieldFound || name.Kind != yaml.ScalarNode || name.ShortTag() != yamlStrTag || strings.TrimSpace(name.Value) == "" {
		return false, false
	}
	data, state := argoCDExactField(root, "data")
	if state != argoCDFieldFound || data.Kind != yaml.MappingNode || !argoCDStrictStringData(data) {
		return false, false
	}
	if binaryData, state := argoCDExactField(root, "binaryData"); state == argoCDFieldInvalid || (state == argoCDFieldFound && ciliumBinaryClusterNameOverlap(binaryData)) {
		return false, false
	}
	clusterName, state := argoCDExactField(data, "cluster-name")
	if state != argoCDFieldFound || clusterName.Kind != yaml.ScalarNode || clusterName.ShortTag() != yamlStrTag {
		return false, false
	}
	return ciliumInvalidClusterName(strings.TrimSpace(clusterName.Value)), true
}

// ciliumClusterSingleYAML permits ordinary scalar metadata (for example
// immutable:false and creationTimestamp:null) while keeping ConfigMap data
// itself string-only. It is separate from the stricter Argo CD parser because
// the Cilium source predicate has no reason to reject unrelated metadata.
func ciliumClusterSingleYAML(raw []byte) (*yaml.Node, bool) {
	d := yaml.NewDecoder(bytes.NewReader(raw))
	var document yaml.Node
	if d.Decode(&document) != nil || len(document.Content) != 1 {
		return nil, false
	}
	var trailing yaml.Node
	if d.Decode(&trailing) != io.EOF || !ciliumClusterSafeNode(document.Content[0]) {
		return nil, false
	}
	return document.Content[0], true
}

func ciliumClusterSafeNode(node *yaml.Node) bool {
	if node == nil || node.Kind == yaml.AliasNode || node.Alias != nil || node.Anchor != "" || node.Style&yaml.TaggedStyle != 0 {
		return false
	}
	switch node.Kind {
	case yaml.MappingNode:
		if node.ShortTag() != yamlMapTag || len(node.Content)%2 != 0 {
			return false
		}
		seen := map[string]bool{}
		for i := 0; i < len(node.Content); i += 2 {
			key, value := node.Content[i], node.Content[i+1]
			if key.Kind != yaml.ScalarNode || key.ShortTag() != yamlStrTag || key.Value == "<<" || seen[key.Value] || !ciliumClusterSafeNode(key) || !ciliumClusterSafeNode(value) {
				return false
			}
			seen[key.Value] = true
		}
		return true
	case yaml.SequenceNode:
		if node.ShortTag() != yamlSeqTag {
			return false
		}
		for _, child := range node.Content {
			if !ciliumClusterSafeNode(child) {
				return false
			}
		}
		return true
	case yaml.ScalarNode:
		if node.ShortTag() != yamlNullTag && node.ShortTag() != yamlBoolTag && node.ShortTag() != yamlStrTag && node.ShortTag() != yamlIntTag && node.ShortTag() != yamlFloatTag && node.ShortTag() != yamlTimestampTag {
			return false
		}
		return !strings.Contains(node.Value, "${") && !strings.Contains(node.Value, "{{") && !strings.Contains(node.Value, "{%")
	default:
		return false
	}
}

func ciliumBinaryClusterNameOverlap(node *yaml.Node) bool {
	if node == nil || node.Kind != yaml.MappingNode || len(node.Content)%2 != 0 {
		return true
	}
	for i := 0; i < len(node.Content); i += 2 {
		key := node.Content[i]
		if key.Kind != yaml.ScalarNode || key.ShortTag() != yamlStrTag {
			return true
		}
		if key.Value == "cluster-name" || strings.EqualFold(strings.TrimSpace(key.Value), "cluster-name") {
			return true
		}
	}
	return false
}

// ciliumInvalidClusterName matches the target v1.17.18 validation boundary:
// nonempty, at most 32 bytes, lowercase ASCII alphanumeric or dash, and an
// alphanumeric first and last byte.
func ciliumInvalidClusterName(value string) bool {
	if len(value) == 0 || len(value) > 32 || !utf8.ValidString(value) {
		return true
	}
	for index := range len(value) {
		character := value[index]
		alphanumeric := character >= 'a' && character <= 'z' || character >= '0' && character <= '9'
		if !alphanumeric && character != '-' {
			return true
		}
		if (index == 0 || index == len(value)-1) && !alphanumeric {
			return true
		}
	}
	return false
}
