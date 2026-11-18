// SPDX-License-Identifier: AGPL-3.0-only

package projectprepare

import (
	"bytes"
	"errors"
	"io"
	"unicode/utf8"

	"gopkg.in/yaml.v3"

	"github.com/prufyx/prufyx/cli/internal/constraintengine"
)

const (
	IngressNginxProject   = "ingress-nginx"
	IngressNginxComponent = "pkg:github/kubernetes/ingress-nginx"
	// The pair is the controller versions; chart 4.10.0 and 4.15.0 are only
	// declared by the caller, never inferred.
	IngressNginxFrom               = "1.10.0"
	IngressNginxTo                 = "1.15.0"
	IngressNginxAllowSnippetFact   = "component.ingress_nginx.allow_snippet_annotations"
	IngressNginxRiskLevelFact      = "component.ingress_nginx.annotations_risk_level_below_critical"
	IngressNginxSnippetPresentFact = "component.ingress_nginx.configuration_snippet_annotation_present"

	ingressNginxAllowKey   = "allow-snippet-annotations"
	ingressNginxRiskKey    = "annotations-risk-level"
	ingressNginxSnippetKey = "nginx.ingress.kubernetes.io/configuration-snippet"
	// ingressNginxMaxDocuments bounds the YAML stream of either input.
	ingressNginxMaxDocuments = 4096
)

// PrepareIngressNginx reduces one caller-selected controller ConfigMap and the
// caller-selected rendered Ingress objects to three facts. Nothing else of
// either input is retained: only the two ConfigMap values reduced to a bool and
// the presence of one annotation key. Every declaration is the caller's; none
// is inferred. Any input that cannot be read exactly leaves its fact
// unsupported, so the check stays UNKNOWN.
//
// configMapComplete declares the ConfigMap holds the controller's complete
// rendered configuration; ingressSetComplete declares the supplied Ingresses
// are the complete apply set; scopeDeclared declares that every supplied
// Ingress is served by this controller and that the controller uses the default
// annotation prefix (controller arguments are not read).
func PrepareIngressNginx(configMapRaw, ingressRaw []byte, from, to string, configMapComplete, ingressSetComplete, scopeDeclared bool) (Prepared, error) {
	if !versionRE.MatchString(from) || !versionRE.MatchString(to) {
		return Prepared{}, ErrInvalid
	}
	facts := []inputFact{
		{ID: IngressNginxAllowSnippetFact, State: "unsupported"},
		{ID: IngressNginxRiskLevelFact, State: "unsupported"},
		{ID: IngressNginxSnippetPresentFact, State: "unsupported"},
	}
	omissions := []string{
		"CONFIG_MAP_AND_INGRESS_SELECTED_BY_CALLER_NOT_LIVE",
		"OTHER_CRITICAL_ANNOTATIONS_NOT_EVALUATED",
		"CONTROLLER_ARGS_NOT_EVALUATED",
		"INGRESS_SCOPE_AND_ANNOTATION_PREFIX_ARE_CALLER_DECLARATIONS",
		"WHOLE_UPGRADE_COMPATIBILITY_NOT_EVALUATED",
	}
	state, reason := "UNKNOWN", "INGRESS_NGINX_INPUT_OR_DECLARATION_UNRESOLVED"
	if !(constraintengine.RuleTransition{Component: IngressNginxComponent, From: IngressNginxFrom, To: IngressNginxTo}).IsAnchor(from, to) {
		reason = "UNSUPPORTED_VERSION_PAIR"
	} else {
		allow, below, defaulted := ingressNginxConfigMapFacts(configMapRaw, configMapComplete)
		snippet := ingressNginxSnippetFact(ingressRaw, ingressSetComplete, scopeDeclared)
		for i, value := range []*bool{allow, below, snippet} {
			if value != nil {
				facts[i].State, facts[i].BoolValue = "declared", value
			}
		}
		if defaulted {
			omissions = append(omissions, "DEFAULT_FROM_REVIEWED_SOURCE")
		}
		if allow != nil && below != nil && snippet != nil {
			state, reason = "PREPARED", "INGRESS_NGINX_SNIPPET_FACTS_DECLARED"
		}
	}
	canonical, err := marshalInput(IngressNginxComponent, from, to, facts)
	if err != nil {
		return Prepared{}, ErrInvalid
	}
	return Prepared{
		CanonicalInputJSON: canonical,
		SourceDigest:       digest([]byte(digest(configMapRaw) + "\n" + digest(ingressRaw))),
		InputDigest:        digest(canonical),
		State:              state,
		Reason:             reason,
		Omissions:          omissions,
	}, nil
}

// ingressNginxYAMLDocuments splits a YAML (or JSON) stream into its non-empty
// documents without interpreting any scalar. ok is false when the stream is
// oversize, not UTF-8, syntactically invalid or has too many documents.
func ingressNginxYAMLDocuments(raw []byte) ([]*yaml.Node, bool) {
	if len(raw) == 0 || len(raw) > maxInputBytes || !utf8.Valid(raw) {
		return nil, false
	}
	decoder := yaml.NewDecoder(bytes.NewReader(raw))
	var documents []*yaml.Node
	for count := 0; ; count++ {
		if count >= ingressNginxMaxDocuments {
			return nil, false
		}
		node := new(yaml.Node)
		if err := decoder.Decode(node); err != nil {
			if errors.Is(err, io.EOF) {
				return documents, true
			}
			return nil, false
		}
		if node.Kind == 0 || node.Kind == yaml.DocumentNode && (len(node.Content) == 0 || isNullScalar(node.Content[0])) {
			continue
		}
		if node.Kind != yaml.DocumentNode || len(node.Content) != 1 {
			return nil, false
		}
		documents = append(documents, node.Content[0])
	}
}

func isNullScalar(node *yaml.Node) bool {
	return node.Kind == yaml.ScalarNode && node.Tag == "!!null" && node.Anchor == ""
}

// yamlLookup finds one string key of a mapping node. ok is false when the
// mapping cannot be read exactly: a merge key, an anchor, an alias, a duplicate
// of the wanted key, or a wanted key that is not a plain string scalar.
func yamlLookup(mapping *yaml.Node, key string) (value *yaml.Node, found, ok bool) {
	if mapping == nil || mapping.Kind != yaml.MappingNode || mapping.Anchor != "" || len(mapping.Content)%2 != 0 {
		return nil, false, false
	}
	for i := 0; i < len(mapping.Content); i += 2 {
		k := mapping.Content[i]
		if k.Kind == yaml.AliasNode || k.Anchor != "" || k.Tag == "!!merge" {
			return nil, false, false
		}
		if k.Kind != yaml.ScalarNode || k.Value != key {
			continue
		}
		if k.Tag != "!!str" || found {
			return nil, false, false
		}
		value, found = mapping.Content[i+1], true
	}
	if found && (value.Kind == yaml.AliasNode || value.Anchor != "") {
		return nil, false, false
	}
	return value, found, true
}

// yamlExactString reads a plain string scalar and nothing else.
func yamlExactString(node *yaml.Node) (string, bool) {
	if node == nil || node.Kind != yaml.ScalarNode || node.Tag != "!!str" || node.Anchor != "" {
		return "", false
	}
	return node.Value, true
}

// ingressNginxKind reads apiVersion and kind of a document root and nothing
// else; it never descends into the document.
func ingressNginxKind(root *yaml.Node) (apiVersion, kind string, ok bool) {
	apiNode, apiFound, apiOK := yamlLookup(root, "apiVersion")
	kindNode, kindFound, kindOK := yamlLookup(root, "kind")
	if !apiOK || !kindOK || !apiFound || !kindFound {
		return "", "", false
	}
	apiVersion, apiOK = yamlExactString(apiNode)
	kind, kindOK = yamlExactString(kindNode)
	return apiVersion, kind, apiOK && kindOK
}

func ingressNginxBool(value bool) *bool { return &value }

// ingressNginxConfigMapFacts reads only data["allow-snippet-annotations"] and
// data["annotations-risk-level"] of exactly one v1 ConfigMap. A nil result is
// unsupported. defaulted reports that the risk level came from the reviewed
// 1.15.0 source default (config.go "High") instead of the file.
func ingressNginxConfigMapFacts(raw []byte, complete bool) (allow, belowCritical *bool, defaulted bool) {
	documents, ok := ingressNginxYAMLDocuments(raw)
	if !ok || len(documents) != 1 {
		return nil, nil, false
	}
	root := documents[0]
	apiVersion, kind, ok := ingressNginxKind(root)
	if !ok || apiVersion != "v1" || kind != "ConfigMap" {
		return nil, nil, false
	}
	// A key present in binaryData is ambiguous (a ConfigMap cannot hold one key in
	// both maps); no binaryData value is read.
	if binary, found, ok := yamlLookup(root, "binaryData"); !ok {
		return nil, nil, false
	} else if found && !isNullScalar(binary) {
		for _, key := range []string{ingressNginxAllowKey, ingressNginxRiskKey} {
			if _, present, ok := yamlLookup(binary, key); !ok || present {
				return nil, nil, false
			}
		}
	}
	data, found, ok := yamlLookup(root, "data")
	if !ok {
		return nil, nil, false
	}
	if found && !isNullScalar(data) && data.Kind != yaml.MappingNode {
		return nil, nil, false
	}
	if !found || isNullScalar(data) {
		data = nil
	}
	lookup := func(key string) (*yaml.Node, bool, bool) {
		if data == nil {
			return nil, false, true
		}
		return yamlLookup(data, key)
	}
	// allow-snippet-annotations: chart 4.10.0 renders the key unconditionally,
	// chart 4.15.0 only when true, so an absent key is false only for a complete
	// ConfigMap.
	if value, present, ok := lookup(ingressNginxAllowKey); ok {
		if present {
			if text, isString := yamlExactString(value); isString && (text == "true" || text == "false") {
				allow = ingressNginxBool(text == "true")
			}
		} else if complete {
			allow = ingressNginxBool(false)
		}
	}
	if value, present, ok := lookup(ingressNginxRiskKey); ok {
		if present {
			if text, isString := yamlExactString(value); isString {
				switch text {
				case "Low", "Medium", "High":
					belowCritical = ingressNginxBool(true)
				case "Critical":
					belowCritical = ingressNginxBool(false)
				}
			}
		} else if complete {
			// config.go at 1.15.0: AnnotationsRiskLevel defaults to "High".
			belowCritical, defaulted = ingressNginxBool(true), true
		}
	}
	return allow, belowCritical, defaulted && belowCritical != nil
}

// ingressNginxSnippetFact reports whether any supplied networking.k8s.io/v1
// Ingress carries the exact configuration-snippet annotation key. Annotation
// values and every other key are never read. A document whose kind is not
// exactly Ingress ends the read: nothing of it is interpreted.
func ingressNginxSnippetFact(raw []byte, setComplete, scopeDeclared bool) *bool {
	if !scopeDeclared {
		return nil
	}
	documents, ok := ingressNginxYAMLDocuments(raw)
	if !ok || len(documents) == 0 {
		return nil
	}
	present, unreadable := false, false
	for _, root := range documents {
		apiVersion, kind, ok := ingressNginxKind(root)
		if !ok || kind != "Ingress" || apiVersion != "networking.k8s.io/v1" {
			return nil
		}
		metadata, found, ok := yamlLookup(root, "metadata")
		if !ok || !found {
			unreadable = true
			continue
		}
		annotations, found, ok := yamlLookup(metadata, "annotations")
		if !ok {
			unreadable = true
			continue
		}
		if !found || isNullScalar(annotations) {
			continue
		}
		if _, exists, ok := yamlLookup(annotations, ingressNginxSnippetKey); !ok {
			unreadable = true
		} else if exists {
			present = true
		}
	}
	switch {
	case present:
		// Presence is decisive even when the set is incomplete or a document was unreadable.
		return ingressNginxBool(true)
	case unreadable || !setComplete:
		return nil
	}
	return ingressNginxBool(false)
}
