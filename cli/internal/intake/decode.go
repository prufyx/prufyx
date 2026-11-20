// SPDX-License-Identifier: AGPL-3.0-only

package intake

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// The Kubernetes component-configuration route accepts the formats operators
// actually hold: YAML (single or multi-document) and JSON, which is a YAML
// subset. Decoding is deliberately narrower than the YAML language. Anchors,
// aliases, merge keys, custom tags, non-string keys and duplicate keys are
// rejected, because each of them can make the bytes a reader sees differ from
// the value a Kubernetes component decodes.

const (
	// MaxDocuments and MaxNodes bound one decode call.
	MaxDocuments = 256
	MaxNodes     = 200000
	// MaxDepth, MaxObjectMembers and MaxArrayItems bound one document. They
	// equal the limits of the strict JSON decoder used by the preparers.
	MaxDepth = 32
	// MaxManifestDepth bounds one Kubernetes manifest document. Published
	// CustomResourceDefinitions nest their schemas deeper than a component
	// configuration does (cert-manager's Challenge CRD is 38 levels deep), so
	// the manifest path admits twice the configuration depth, the depth limit
	// of the strict JSON checker.
	MaxManifestDepth = 64
	MaxObjectMembers = 4096
	MaxArrayItems    = 2048
)

// ErrUnsupported reports bytes outside the accepted YAML subset or outside the
// bounds.
var ErrUnsupported = errors.New("unsupported Kubernetes component YAML")

var errK8sComponentYAML = ErrUnsupported

// errStructure is returned when a document parsed but broke a bound or a
// uniqueness rule: nesting depth, member or item count, a duplicate key. It
// wraps ErrUnsupported. Template syntax cannot cause it, so such a refusal is
// never reported as unrendered templates.
var errStructure = fmt.Errorf("%w: structure", ErrUnsupported)

// DecodeDocuments returns every non-empty document as plain values:
// map[string]any, []any, string, bool, json.Number or nil.
func DecodeDocuments(raw []byte) ([]any, error) {
	documents, err := decodeDocuments(raw, decodeOptions{})
	if err != nil {
		return nil, errK8sComponentYAML
	}
	return documents, nil
}

// decodeOptions tightens or relaxes the base decoder for the manifest path.
type decodeOptions struct {
	// foldKeys rejects two keys in one mapping that differ only in case,
	// as the strict JSON decoder of the preparers does.
	foldKeys bool
	// timestampStrings reads an untagged timestamp scalar such as 2026-01-02
	// as the string it is written as.
	timestampStrings bool
	// maxDepth bounds nesting; zero means MaxDepth.
	maxDepth int
	// maxDocuments bounds the documents of this call; zero means MaxDocuments
	// and a negative value allows none.
	maxDocuments int
	// nodes is the node budget shared with the caller, so one budget can span
	// several files; nil means a fresh MaxNodes budget.
	nodes *int
	// lines, when not nil, receives the apiVersion lines of every returned
	// document, in the same order.
	lines *[]documentLines
}

// documentLines is where the apiVersion key of a document, and of each item
// of a top-level items sequence, starts: a 1-based line, 0 when absent.
type documentLines struct {
	root  int
	items []int
}

// apiVersionLine returns the line of the apiVersion key of a mapping node.
func apiVersionLine(node *yaml.Node) int {
	if node == nil || node.Kind != yaml.MappingNode {
		return 0
	}
	for index := 0; index+1 < len(node.Content); index += 2 {
		if key := node.Content[index]; key.Kind == yaml.ScalarNode && key.Value == "apiVersion" {
			return key.Line
		}
	}
	return 0
}

// linesOf records the apiVersion lines of a document root and of the items of
// its top-level items sequence, the only list level intake flattens.
func linesOf(root *yaml.Node) documentLines {
	lines := documentLines{root: apiVersionLine(root)}
	if root.Kind != yaml.MappingNode {
		return lines
	}
	for index := 0; index+1 < len(root.Content); index += 2 {
		key, value := root.Content[index], root.Content[index+1]
		if key.Kind == yaml.ScalarNode && key.Value == "items" && value.Kind == yaml.SequenceNode {
			lines.items = make([]int, len(value.Content))
			for item, child := range value.Content {
				lines.items[item] = apiVersionLine(child)
			}
		}
	}
	return lines
}

// errLimit and the limit names let Open report which bound was exceeded.
type limitReached struct{ limit string }

func (e limitReached) Error() string { return "limit reached: " + e.limit }

// structuralTokens returns a cheap upper bound on the number of YAML nodes in
// raw, from bytes alone: every flow indicator, comma, colon and line break, and
// every dash that starts a sequence entry, can introduce at most one node, plus
// one for the root. It lets the caller refuse input before the YAML decoder
// allocates a tree that is roughly two hundred bytes per node.
func structuralTokens(raw []byte) int {
	count := 1
	for i, b := range raw {
		switch b {
		case '[', '{', ',', ':', '\n', '\r':
			count++
		case '-':
			if i+1 == len(raw) || raw[i+1] == ' ' || raw[i+1] == '\n' || raw[i+1] == '\r' || raw[i+1] == '\t' {
				count++
			}
		}
	}
	return count
}

// refusal names a construct the decoder deliberately refuses, and where it
// is. It is an unsupported-input error like errK8sComponentYAML.
type refusal struct {
	line int
	what string
}

func (e refusal) Error() string { return fmt.Sprintf("line %d: %s", e.line, e.what) }

func (e refusal) Is(target error) bool { return target == errK8sComponentYAML }

// structuralRefusal is a refusal of a bound or uniqueness rule. It is also an
// errStructure, so template syntax is never blamed for it.
type structuralRefusal struct{ refusal }

func (e structuralRefusal) Unwrap() error { return e.refusal }

func structural(line int, what string) error { return structuralRefusal{refusal{line, what}} }

func (e structuralRefusal) Is(target error) bool {
	return target == errK8sComponentYAML || target == errStructure
}

const (
	whatAnchor  = "YAML anchors and aliases are not supported; expand them (for example `yq 'explode(.)'`)"
	whatMerge   = "YAML merge keys (`<<:`) are not supported; expand them (for example `yq 'explode(.)'`)"
	whatTag     = "custom or non-standard YAML tags are not supported; write the value as a plain scalar"
	whatKey     = "mapping keys must be non-empty plain strings"
	whatDup     = "duplicate mapping keys are not supported"
	whatFold    = "mapping keys that differ only in letter case are not supported"
	whatMembers = "a mapping with more than 4096 keys is not supported"
	whatItems   = "a sequence with more than 2048 items is not supported"
	whatScalar  = "this scalar type is not supported; quote the value"
)

func depthWhat(limit int) string {
	return fmt.Sprintf("nesting deeper than %d levels is not supported", limit)
}

func decodeDocuments(raw []byte, opts decodeOptions) ([]any, error) {
	decoder := yaml.NewDecoder(bytes.NewReader(raw))
	documents := make([]any, 0, 1)
	local := MaxNodes
	budget := &local
	if opts.nodes != nil {
		budget = opts.nodes
	}
	if structuralTokens(raw) > *budget {
		return nil, limitReached{"nodes"}
	}
	maxDocuments := MaxDocuments
	if opts.maxDocuments != 0 {
		maxDocuments = max(opts.maxDocuments, 0)
	}
	for {
		var node yaml.Node
		err := decoder.Decode(&node)
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, parseRefusal(err)
		}
		if node.Kind != yaml.DocumentNode {
			return nil, errK8sComponentYAML
		}
		if len(node.Content) == 0 {
			continue
		}
		if len(node.Content) != 1 {
			return nil, errK8sComponentYAML
		}
		if root := node.Content[0]; root.Kind == yaml.ScalarNode && root.ShortTag() == "!!null" {
			// An empty document between separators carries no configuration.
			continue
		}
		value, err := opts.yamlValue(node.Content[0], 0, budget, crdContext(node.Content[0]))
		if err != nil {
			return nil, err
		}
		documents = append(documents, value)
		if opts.lines != nil {
			*opts.lines = append(*opts.lines, linesOf(node.Content[0]))
		}
		if len(documents) > maxDocuments {
			return nil, limitReached{"documents"}
		}
	}
	return documents, nil
}

// Decode contexts for a CustomResourceDefinition document. Field names in a
// structural schema's properties map are distinct keys even when they differ
// only in case (alertmanagerconfigs declares both proxyURL and proxyUrl), so
// the case-folded duplicate check does not apply to those maps. The exemption
// holds only at real schema positions: spec.versions[].schema.openAPIV3Schema
// or spec.validation.openAPIV3Schema, followed only by schema keywords. A path
// through default, example, enum, const, x-kubernetes-* or any other data keeps
// the check. Exact duplicates are refused everywhere.
const (
	ctxNone   = iota // not a CustomResourceDefinition
	ctxRoot          // CRD root mapping
	ctxSpec          // spec
	ctxVers          // spec.versions
	ctxVer           // spec.versions[]
	ctxHolder        // spec.versions[].schema
	ctxValid         // spec.validation
	ctxSchema        // a schema node
	ctxProps         // a properties map (keys are field names)
	ctxOther         // data or any non-schema position
)

// crdContext returns ctxRoot when root is a CustomResourceDefinition.
func crdContext(root *yaml.Node) int {
	if root == nil || root.Kind != yaml.MappingNode {
		return 0
	}
	api, kind := "", ""
	for index := 0; index+1 < len(root.Content); index += 2 {
		key, value := root.Content[index], root.Content[index+1]
		if key.Kind != yaml.ScalarNode || value.Kind != yaml.ScalarNode {
			continue
		}
		switch key.Value {
		case "apiVersion":
			api = value.Value
		case "kind":
			kind = value.Value
		}
	}
	if kind == "CustomResourceDefinition" && strings.HasPrefix(api, "apiextensions.k8s.io/") {
		return ctxRoot
	}
	return ctxNone
}

// childContext returns the context of the value under key in a mapping.
func childContext(ctx int, key string) int {
	switch ctx {
	case ctxNone:
		return ctxNone
	case ctxRoot:
		if key == "spec" {
			return ctxSpec
		}
	case ctxSpec:
		switch key {
		case "versions":
			return ctxVers
		case "validation":
			return ctxValid
		}
	case ctxVer:
		if key == "schema" {
			return ctxHolder
		}
	case ctxHolder, ctxValid:
		if key == "openAPIV3Schema" {
			return ctxSchema
		}
	case ctxSchema:
		switch key {
		case "properties", "patternProperties":
			return ctxProps
		case "items", "additionalProperties", "additionalItems", "not", "allOf", "anyOf", "oneOf":
			return ctxSchema
		}
	case ctxProps:
		// A property name: its value is a schema.
		return ctxSchema
	}
	return ctxOther
}

// elementContext returns the context of an element of a sequence.
func elementContext(ctx int) int {
	switch ctx {
	case ctxVers:
		return ctxVer
	case ctxSchema:
		return ctxSchema
	case ctxNone:
		return ctxNone
	}
	return ctxOther
}

func (opts decodeOptions) depthLimit() int {
	if opts.maxDepth > 0 {
		return opts.maxDepth
	}
	return MaxDepth
}

func (opts decodeOptions) yamlValue(node *yaml.Node, depth int, budget *int, ctx int) (any, error) {
	*budget--
	if *budget < 0 {
		return nil, limitReached{"nodes"}
	}
	if node == nil {
		return nil, errK8sComponentYAML
	}
	if node.Anchor != "" || node.Alias != nil || node.Kind == yaml.AliasNode {
		return nil, refusal{node.Line, whatAnchor}
	}
	if depth > opts.depthLimit() {
		return nil, structural(node.Line, depthWhat(opts.depthLimit()))
	}
	switch node.Kind {
	case yaml.MappingNode:
		if node.ShortTag() != "!!map" {
			return nil, refusal{node.Line, whatTag}
		}
		if len(node.Content)%2 != 0 {
			return nil, errK8sComponentYAML
		}
		if len(node.Content)/2 > MaxObjectMembers {
			return nil, structural(node.Line, whatMembers)
		}
		object := make(map[string]any, len(node.Content)/2)
		seen := map[string]bool{}
		for index := 0; index < len(node.Content); index += 2 {
			key := node.Content[index]
			switch {
			case key.Anchor != "" || key.Alias != nil || key.Kind == yaml.AliasNode:
				return nil, refusal{key.Line, whatAnchor}
			case key.Kind == yaml.ScalarNode && key.Value == "<<":
				return nil, refusal{key.Line, whatMerge}
			case key.Kind != yaml.ScalarNode || key.ShortTag() != "!!str" || key.Value == "":
				return nil, refusal{key.Line, whatKey}
			}
			if _, duplicate := object[key.Value]; duplicate {
				return nil, structural(key.Line, whatDup)
			}
			if opts.foldKeys && ctx != ctxProps {
				folded := strings.ToLower(key.Value)
				if seen[folded] {
					return nil, structural(key.Line, whatFold)
				}
				seen[folded] = true
			}
			value, err := opts.yamlValue(node.Content[index+1], depth+1, budget, childContext(ctx, key.Value))
			if err != nil {
				return nil, err
			}
			object[key.Value] = value
		}
		return object, nil
	case yaml.SequenceNode:
		if node.ShortTag() != "!!seq" {
			return nil, refusal{node.Line, whatTag}
		}
		if len(node.Content) > MaxArrayItems {
			return nil, structural(node.Line, whatItems)
		}
		items := make([]any, 0, len(node.Content))
		for _, child := range node.Content {
			value, err := opts.yamlValue(child, depth+1, budget, elementContext(ctx))
			if err != nil {
				return nil, err
			}
			items = append(items, value)
		}
		return items, nil
	case yaml.ScalarNode:
		switch node.ShortTag() {
		case "!!str":
			return node.Value, nil
		case "!!bool":
			switch node.Value {
			case "true", "True", "TRUE":
				return true, nil
			case "false", "False", "FALSE":
				return false, nil
			}
			return nil, refusal{node.Line, whatScalar}
		case "!!int", "!!float":
			return json.Number(node.Value), nil
		case "!!null":
			return nil, nil
		case "!!timestamp":
			if opts.timestampStrings {
				return node.Value, nil
			}
		}
		return nil, refusal{node.Line, whatScalar}
	}
	return nil, errK8sComponentYAML
}

var parseLine = regexp.MustCompile(`^yaml: (?:unmarshal errors:\n\s*)?line (\d+): (.*)$`)

// parseRefusal names the line and the parser's reason for bytes that are not
// YAML at all. Anything it cannot place stays the unnamed refusal.
func parseRefusal(err error) error {
	match := parseLine.FindStringSubmatch(strings.SplitN(err.Error(), "\n", 2)[0])
	if match == nil {
		return errK8sComponentYAML
	}
	line, convErr := strconv.Atoi(match[1])
	if convErr != nil {
		return errK8sComponentYAML
	}
	reason := strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return '?'
		}
		return r
	}, match[2])
	if len(reason) > 120 {
		reason = strings.ToValidUTF8(reason[:120], "")
	}
	return refusal{line, "not valid YAML or JSON: " + reason}
}
