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
	// ReasonSymlinkNotFollowed marks a symlink met while walking a directory.
	// Symlinks are never followed, so the file it names is not read.
	ReasonSymlinkNotFollowed Reason = "SYMLINK_NOT_FOLLOWED"
	// ReasonNotRegularFile marks a pipe, socket or device with a manifest
	// extension met while walking a directory.
	ReasonNotRegularFile Reason = "NOT_REGULAR_FILE"
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

// Workspace is the decoded content of one file (Decode) or of every input
// of an Open call.
type Workspace struct {
	Documents []Document
	Omissions []Omission
	// Auxiliary holds the decoded value of top-level documents that are not
	// Kubernetes-shaped but come from a file named exactly Chart.yaml,
	// kustomization.yaml, kustomization.yml or Kustomization. The same
	// documents are still listed as NOT_KUBERNETES_SHAPED omissions, so every
	// other output is unchanged. A templated document is never retained.
	// Document.Kind is empty when the file carries no kind.
	Auxiliary []Document
	// Encrypted holds the source of every top-level document that is not
	// Kubernetes-shaped but carries a SOPS metadata block. Only the source is
	// kept, never the value; the document is still listed as a
	// NOT_KUBERNETES_SHAPED omission.
	Encrypted []Source
	// Files, Digest and Notices are filled by Open only.
	Files []FileRecord
	// Digest is sha256 over the sorted file digests.
	Digest  string
	Notices []string
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
	workspace, err := decodeFile(display, raw, decodeOptions{})
	if err != nil {
		return Workspace{}, ErrDecode
	}
	return workspace, nil
}

// decodeFile is Decode with caller-chosen document and node budgets. A bound
// that is exceeded is returned as a limitReached error.
func decodeFile(display string, raw []byte, bounds decodeOptions) (Workspace, error) {
	if len(raw) == 0 || !utf8.Valid(raw) {
		return Workspace{}, ErrDecode
	}
	sum := sha256.Sum256(raw)
	digest := "sha256:" + hex.EncodeToString(sum[:])
	bounds.foldKeys, bounds.timestampStrings = true, true
	values, err := decodeDocuments(raw, bounds)
	if err != nil {
		var limit limitReached
		if errors.As(err, &limit) {
			return Workspace{}, err
		}
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
		w.retainAuxiliary(source, object, api, kind, templated)
		if source.Item < 0 && HasSOPSMetadata(object) {
			w.Encrypted = append(w.Encrypted, source)
		}
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

// auxiliaryName reports whether a file base name is on the closed list of
// files whose non-Kubernetes-shaped content is retained.
func auxiliaryName(display string) bool {
	base := display
	if i := strings.LastIndexAny(display, "/\\"); i >= 0 {
		base = display[i+1:]
	}
	switch base {
	case "Chart.yaml", "kustomization.yaml", "kustomization.yml", "Kustomization":
		return true
	}
	return false
}

// retainAuxiliary keeps the value of a top-level object from a listed file.
func (w *Workspace) retainAuxiliary(source Source, object map[string]any, api, kind string, templated bool) {
	if templated || source.Item >= 0 || !auxiliaryName(source.Display) {
		return
	}
	w.Auxiliary = append(w.Auxiliary, Document{Source: source, APIVersion: api, Kind: kind, Value: object})
}

// HasSOPSMetadata reports the metadata block SOPS adds to a file it encrypts:
// a top-level sops object with a mac, version or lastmodified member.
func HasSOPSMetadata(object map[string]any) bool {
	block, ok := object["sops"].(map[string]any)
	if !ok {
		return false
	}
	for _, member := range []string{"mac", "version", "lastmodified"} {
		if _, found := block[member]; found {
			return true
		}
	}
	return false
}
