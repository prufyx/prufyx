// SPDX-License-Identifier: AGPL-3.0-only

package intake

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"unicode/utf8"
)

// Reason names why a document, or a whole file, contributed no usable
// document to a Workspace.
type Reason string

const (
	// ReasonTemplated marks a document with template syntax in a string scalar.
	// Nothing is rendered: the caller must pass rendered output.
	ReasonTemplated Reason = "TEMPLATED"
	// ReasonUnparseable marks a file that does not parse because of raw
	// template syntax.
	ReasonUnparseable Reason = "UNPARSEABLE"
	// ReasonNotKubernetesShaped marks a document that is not an object with a
	// string apiVersion and a string kind.
	ReasonNotKubernetesShaped Reason = "NOT_KUBERNETES_SHAPED"
	// ReasonNestedList marks a list found inside a list's items.
	ReasonNestedList Reason = "NESTED_LIST"
	// ReasonListShape marks a list that cannot be flattened: a core List that
	// is not v1, no items, an item that is not an object, or invalid list
	// metadata.
	ReasonListShape Reason = "LIST_SHAPE_UNRESOLVED"
)

// Source says where a document came from. Display is the path as the caller
// gave it; it is provenance for local reports and is never part of a digest.
type Source struct {
	Display  string
	Digest   string // sha256 of the raw bytes of the file
	Document int    // 0-based index among the non-empty YAML documents of the file
	Item     int    // -1, or the 0-based index inside a List's items
}

// Document is one Kubernetes-shaped object. Secret payloads are never present.
type Document struct {
	Source     Source
	APIVersion string
	Kind       string
	Namespace  string
	Name       string
	Value      map[string]any
	// ListMetadata is the metadata value of the containing List, when Source.Item >= 0.
	ListMetadata any
}

// Omission records content that was seen but not used.
type Omission struct {
	Source Source
	Reason Reason
}

// Workspace is the decoded content of one file.
type Workspace struct {
	Documents []Document
	Omissions []Omission
}

// ErrDecode reports bytes that are not valid or not within bounds.
var ErrDecode = errors.New("input is not a bounded YAML or JSON document set")

// Decode reads one file's bytes as single or multi-document YAML or JSON. The
// manifest options keep the strictness of the JSON preparers (duplicate keys
// that differ only in case are rejected) and read untagged timestamps as text.
//
// Typed lists and core v1 Lists are flattened one level. Secret data and
// stringData are removed before the value is stored. A document with template
// syntax in a string scalar, and a file that cannot be parsed because of such
// syntax, become omissions; any other undecodable input is an error.
func Decode(display string, raw []byte) (Workspace, error) {
	if len(raw) == 0 || !utf8.Valid(raw) {
		return Workspace{}, ErrDecode
	}
	sum := sha256.Sum256(raw)
	digest := "sha256:" + hex.EncodeToString(sum[:])
	values, err := decodeDocuments(raw, decodeOptions{foldKeys: true, timestampStrings: true})
	if err != nil {
		if hasTemplateSyntax(string(raw)) {
			return Workspace{Omissions: []Omission{{Source: Source{Display: display, Digest: digest, Item: -1}, Reason: ReasonUnparseable}}}, nil
		}
		return Workspace{}, ErrDecode
	}
	var workspace Workspace
	for index, value := range values {
		source := Source{Display: display, Digest: digest, Document: index, Item: -1}
		workspace.add(source, value, nil, "", "")
	}
	return workspace, nil
}

func (w *Workspace) omit(source Source, reason Reason) {
	w.Omissions = append(w.Omissions, Omission{Source: source, Reason: reason})
}

// add classifies one decoded top-level value.
func (w *Workspace) add(source Source, value any, listMetadata any, listAPI, itemKind string) {
	object, ok := value.(map[string]any)
	if !ok {
		w.omit(source, ReasonNotKubernetesShaped)
		return
	}
	// Scan for template syntax before the Secret payload is removed, then
	// keep only the boolean: the payload is not retained anywhere.
	templated := valueHasTemplateSyntax(object)
	api, apiOK := object["apiVersion"].(string)
	kind, kindOK := object["kind"].(string)
	if itemKind != "" && !apiOK && !kindOK {
		// A typed list's items may omit apiVersion and kind; the list's own
		// group, version and kind apply.
		api, kind, apiOK, kindOK = listAPI, itemKind, true, true
		object["apiVersion"], object["kind"] = api, kind
	}
	if kind == "Secret" {
		stripSecret(object)
	}
	if !apiOK || !kindOK || api == "" || kind == "" {
		w.omit(source, ReasonNotKubernetesShaped)
		return
	}
	if templated {
		w.omit(source, ReasonTemplated)
		return
	}
	isList := kind == "List" || strings.HasSuffix(kind, "List")
	if isList {
		if source.Item >= 0 {
			w.omit(source, ReasonNestedList)
			return
		}
		if kind == "List" && api != "v1" {
			w.omit(source, ReasonListShape)
			return
		}
		items, found := object["items"].([]any)
		if !found || len(items) == 0 {
			w.omit(source, ReasonListShape)
			return
		}
		inferred := ""
		if kind != "List" {
			inferred = strings.TrimSuffix(kind, "List")
		}
		for index, item := range items {
			itemSource := source
			itemSource.Item = index
			w.add(itemSource, item, object["metadata"], api, inferred)
		}
		return
	}
	document := Document{Source: source, APIVersion: api, Kind: kind, Value: object, ListMetadata: listMetadata}
	if metadata, ok := object["metadata"].(map[string]any); ok {
		document.Namespace, _ = metadata["namespace"].(string)
		document.Name, _ = metadata["name"].(string)
	}
	w.Documents = append(w.Documents, document)
}

// stripSecret removes every place a Secret's payload can be held: data,
// stringData and the last-applied copy of the whole object.
func stripSecret(object map[string]any) {
	delete(object, "data")
	delete(object, "stringData")
	if metadata, ok := object["metadata"].(map[string]any); ok {
		if annotations, ok := metadata["annotations"].(map[string]any); ok {
			delete(annotations, "kubectl.kubernetes.io/last-applied-configuration")
		}
	}
}

func hasTemplateSyntax(text string) bool {
	return strings.Contains(text, "{{") || strings.Contains(text, "${")
}

func valueHasTemplateSyntax(value any) bool {
	switch typed := value.(type) {
	case string:
		return hasTemplateSyntax(typed)
	case map[string]any:
		for key, child := range typed {
			if hasTemplateSyntax(key) || valueHasTemplateSyntax(child) {
				return true
			}
		}
	case []any:
		for _, child := range typed {
			if valueHasTemplateSyntax(child) {
				return true
			}
		}
	}
	return false
}
