// SPDX-License-Identifier: AGPL-3.0-only

package targetdraft

import (
	"bytes"
	"errors"
	"io"
	"strings"

	"gopkg.in/yaml.v3"
)

// Kustomize patch fragments (opt-in, Input.SkipPatchFragments).
//
// A kustomize patch under config/crd/patches names the kind
// CustomResourceDefinition but is not a definition: it only edits the metadata
// or the conversion of a definition that lives elsewhere. Read as a
// definition it fails the shape check and ends the run as unreadable-shape.
//
// With the opt-in such a file is set aside as a "patch fragment, not a
// definition" ONLY when its own content proves it. The proof is closed and
// fail-closed: every anomaly leaves the file unreadable-shape.
//
//   - the bytes hold no template syntax and parse as strict YAML (no alias,
//     anchor, merge key, custom tag or repeated key);
//   - every non-empty document is either a strategic-merge fragment (a mapping
//     of the kind CustomResourceDefinition whose keys are only apiVersion,
//     kind, metadata and spec; metadata only name, namespace, labels,
//     annotations, with a name; spec only conversion and preserveUnknownFields)
//     or a JSON-patch list whose every operation touches only /metadata,
//     /spec/conversion or /spec/preserveUnknownFields;
//   - no definition key (spec.group, spec.names, spec.versions, spec.scope or
//     any other spec field) appears; a file with one stays unreadable, a file
//     that is a whole definition is read as a definition by the scanner and
//     never reaches this check.
//
// A set-aside fragment is never an install file, never a ranking candidate and
// is listed in the report. A fragment that a symbolic link reaches is not set
// aside (see scanTreeFragments).

// fragmentTopKeys, fragmentMetaKeys and fragmentSpecKeys are the allowlists of
// a strategic-merge fragment.
var (
	fragmentTopKeys  = map[string]bool{"apiVersion": true, "kind": true, "metadata": true, "spec": true}
	fragmentMetaKeys = map[string]bool{"name": true, "namespace": true, "labels": true, "annotations": true}
	fragmentSpecKeys = map[string]bool{"conversion": true, "preserveUnknownFields": true}
	jsonPatchOps     = map[string]bool{"add": true, "remove": true, "replace": true, "move": true, "copy": true, "test": true}
	jsonPatchKeys    = map[string]bool{"op": true, "path": true, "value": true, "from": true}
)

// isPatchFragment reports whether the bytes are proven to hold only kustomize
// patch fragments (see above). Any doubt is false.
func isPatchFragment(data []byte) bool {
	if bytes.Contains(data, []byte("{{")) || !bytes.Contains(data, []byte("CustomResourceDefinition")) {
		return false
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	docs := 0
	for {
		var node yaml.Node
		err := dec.Decode(&node)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil || node.Kind != yaml.DocumentNode || len(node.Content) != 1 {
			return false
		}
		root := node.Content[0]
		if !strictNode(root) {
			return false
		}
		if root.Kind == yaml.ScalarNode && root.Tag == "!!null" {
			continue // an empty document
		}
		var v any
		if err := root.Decode(&v); err != nil {
			return false
		}
		switch t := v.(type) {
		case map[string]any:
			if !fragmentMap(t) {
				return false
			}
		case []any:
			if !jsonPatchList(t) {
				return false
			}
		default:
			return false
		}
		docs++
	}
	return docs > 0
}

// strictNode rejects anything that can hide or rewrite content: aliases,
// anchors, merge keys and custom tags.
func strictNode(n *yaml.Node) bool {
	if n.Kind == yaml.AliasNode || n.Anchor != "" || n.Alias != nil || n.Tag == "!!merge" || n.Style&yaml.TaggedStyle != 0 {
		return false
	}
	for _, c := range n.Content {
		if !strictNode(c) {
			return false
		}
	}
	return true
}

func onlyKeys(m map[string]any, allowed map[string]bool) bool {
	for k := range m {
		if !allowed[k] {
			return false
		}
	}
	return true
}

func fragmentMap(m map[string]any) bool {
	if !onlyKeys(m, fragmentTopKeys) {
		return false
	}
	if k, ok := m["kind"].(string); !ok || k != "CustomResourceDefinition" {
		return false
	}
	if av, present := m["apiVersion"]; present {
		s, ok := av.(string)
		if !ok || !strings.HasPrefix(s, "apiextensions.k8s.io/") {
			return false
		}
	}
	meta, ok := m["metadata"].(map[string]any)
	if !ok || !onlyKeys(meta, fragmentMetaKeys) {
		return false
	}
	if n, ok := meta["name"].(string); !ok || n == "" {
		return false
	}
	for _, k := range []string{"labels", "annotations"} {
		if v, present := meta[k]; present {
			if _, ok := v.(map[string]any); !ok {
				return false
			}
		}
	}
	if sv, present := m["spec"]; present {
		spec, ok := sv.(map[string]any)
		if !ok || !onlyKeys(spec, fragmentSpecKeys) {
			return false
		}
	}
	return true
}

// patchPathAllowed says that a JSON-pointer touches only the metadata, the
// conversion or preserveUnknownFields of a definition.
func patchPathAllowed(p string) bool {
	switch {
	case strings.HasPrefix(p, "/metadata/") && len(p) > len("/metadata/"):
		return true
	case p == "/spec/conversion" || strings.HasPrefix(p, "/spec/conversion/"):
		return true
	case p == "/spec/preserveUnknownFields":
		return true
	}
	return false
}

func jsonPatchList(l []any) bool {
	if len(l) == 0 {
		return false
	}
	for _, e := range l {
		op, ok := e.(map[string]any)
		if !ok || !onlyKeys(op, jsonPatchKeys) {
			return false
		}
		name, ok := op["op"].(string)
		if !ok || !jsonPatchOps[name] {
			return false
		}
		p, ok := op["path"].(string)
		if !ok || !patchPathAllowed(p) {
			return false
		}
		if src, present := op["from"]; present {
			s, ok := src.(string)
			if !ok || !patchPathAllowed(s) {
				return false
			}
		}
	}
	return true
}
