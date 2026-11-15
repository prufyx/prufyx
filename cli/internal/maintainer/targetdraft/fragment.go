// SPDX-License-Identifier: AGPL-3.0-only

package targetdraft

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path"
	"sort"

	"github.com/prufyx/prufyx/cli/internal/extract/crdversions"
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
// definition" ONLY when its own content proves it, by the extractor's own
// patch-fragment shape (class crd-patch in extract/crdversions, which does not
// export it; the checks below mirror it check for check and a test pins equal
// verdicts over the extractor's own fixtures). The proof is closed and
// fail-closed: every anomaly leaves the file unreadable-shape.
//
//   - no template syntax; at most the extractor's file size; strictly decoded
//     (no alias, anchor, merge key, custom tag, non-string, empty or repeated
//     key; bounded depth, nodes, documents, members and items);
//   - every non-empty document is a mapping of apiVersion
//     apiextensions.k8s.io/v1 or v1beta1 and kind CustomResourceDefinition
//     with only the keys apiVersion, kind, metadata and spec; metadata only
//     name (non-empty, at most 253 bytes), labels and annotations (mappings of
//     strings); spec only preserveUnknownFields (a boolean) and conversion
//     (the extractor's strict conversion shape);
//   - a JSON-patch list is NOT accepted (the extractor does not read one);
//   - the fragment lies below a directory (not the repository root) that
//     holds a kustomization file. The extractor needs the stronger facts that
//     such a kustomization lists a definition file and that the patched name
//     is a listed definition; the generator cannot know them here, so they
//     are left to the extractor, which classes a fragment that fails them as
//     unread (blocking attestation). The generator requires only the weaker
//     necessary condition, and any doubt stays unreadable-shape.
//
// A set-aside fragment is never an install file, never a ranking candidate and
// is listed in the report. A fragment that a symbolic link reaches is not set
// aside (see scanTreeFragments).

// The extractor's strict-decode bounds.
const (
	fragMaxDepth     = 128
	fragMaxNodes     = 4_000_000
	fragMaxDocuments = 1024
	fragMaxMembers   = 8192
	fragMaxItems     = 8192
	fragMaxName      = 253
)

const (
	fragAPIVersionV1      = "apiextensions.k8s.io/v1"
	fragAPIVersionV1beta1 = "apiextensions.k8s.io/v1beta1"
	fragKind              = "CustomResourceDefinition"
)

var errFragStrict = errors.New("not strictly decodable")

// isPatchFragment reports whether the bytes are proven to hold only patch
// fragments by content (see above). It does not look at the location. Any
// doubt is false.
func isPatchFragment(data []byte) bool {
	if len(data) > crdversions.MaxFileBytes || bytes.Contains(data, []byte("{{")) || !bytes.Contains(data, []byte(fragKind)) {
		return false
	}
	values, err := fragDecodeStrict(data)
	if err != nil || len(values) == 0 {
		return false
	}
	for _, v := range values {
		if why := fragmentDoc(v); why != "" {
			return false
		}
	}
	return true
}

// fragDecodeStrict mirrors the extractor's strict decoder: the plain value
// (map[string]any, []any, string, bool, json.Number or nil) of every non-empty
// document. Empty documents and documents holding only null are skipped.
func fragDecodeStrict(data []byte) ([]any, error) {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	budget := fragMaxNodes
	var values []any
	for {
		var node yaml.Node
		err := dec.Decode(&node)
		if errors.Is(err, io.EOF) {
			return values, nil
		}
		if err != nil || node.Kind != yaml.DocumentNode || len(node.Content) > 1 {
			return nil, errFragStrict
		}
		if len(node.Content) == 0 {
			continue
		}
		root := node.Content[0]
		if root.Kind == yaml.ScalarNode && root.ShortTag() == "!!null" && root.Anchor == "" {
			continue
		}
		v, err := fragStrictValue(root, 0, &budget)
		if err != nil {
			return nil, err
		}
		values = append(values, v)
		if len(values) > fragMaxDocuments {
			return nil, errFragStrict
		}
	}
}

func fragStrictValue(node *yaml.Node, depth int, budget *int) (any, error) {
	*budget--
	if *budget < 0 || depth > fragMaxDepth || node == nil || node.Anchor != "" || node.Alias != nil || node.Kind == yaml.AliasNode {
		return nil, errFragStrict
	}
	switch node.Kind {
	case yaml.MappingNode:
		if node.ShortTag() != "!!map" || len(node.Content)%2 != 0 || len(node.Content)/2 > fragMaxMembers {
			return nil, errFragStrict
		}
		obj := make(map[string]any, len(node.Content)/2)
		for i := 0; i < len(node.Content); i += 2 {
			key := node.Content[i]
			if key.Kind != yaml.ScalarNode || key.ShortTag() != "!!str" || key.Anchor != "" || key.Alias != nil || key.Value == "" || key.Value == "<<" {
				return nil, errFragStrict
			}
			if _, dup := obj[key.Value]; dup {
				return nil, errFragStrict
			}
			v, err := fragStrictValue(node.Content[i+1], depth+1, budget)
			if err != nil {
				return nil, err
			}
			obj[key.Value] = v
		}
		return obj, nil
	case yaml.SequenceNode:
		if node.ShortTag() != "!!seq" || len(node.Content) > fragMaxItems {
			return nil, errFragStrict
		}
		items := make([]any, 0, len(node.Content))
		for _, c := range node.Content {
			v, err := fragStrictValue(c, depth+1, budget)
			if err != nil {
				return nil, err
			}
			items = append(items, v)
		}
		return items, nil
	case yaml.ScalarNode:
		switch node.ShortTag() {
		case "!!str", "!!timestamp":
			return node.Value, nil
		case "!!bool":
			switch node.Value {
			case "true", "True", "TRUE":
				return true, nil
			case "false", "False", "FALSE":
				return false, nil
			}
		case "!!int", "!!float":
			return json.Number(node.Value), nil
		case "!!null":
			return nil, nil
		}
	}
	return nil, errFragStrict
}

func fragSortedKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// fragmentDoc checks one document of a patch fragment; "" accepts it, else the
// reason. It mirrors the extractor's check.
func fragmentDoc(v any) string {
	obj, ok := v.(map[string]any)
	if !ok {
		return "not a mapping"
	}
	for _, k := range fragSortedKeys(obj) {
		switch k {
		case "apiVersion", "kind", "metadata", "spec":
		default:
			return fmt.Sprintf("key %q", k)
		}
	}
	if av, _ := obj["apiVersion"].(string); av != fragAPIVersionV1 && av != fragAPIVersionV1beta1 {
		return fmt.Sprintf("apiVersion %q", obj["apiVersion"])
	}
	if k, _ := obj["kind"].(string); k != fragKind {
		return fmt.Sprintf("kind %q", obj["kind"])
	}
	meta, ok := obj["metadata"].(map[string]any)
	if !ok {
		return "no metadata mapping"
	}
	for _, k := range fragSortedKeys(meta) {
		switch k {
		case "name":
		case "annotations", "labels":
			if why := fragStringMap(meta[k]); why != "" {
				return fmt.Sprintf("metadata.%s %s", k, why)
			}
		default:
			return fmt.Sprintf("metadata key %q", k)
		}
	}
	name, _ := meta["name"].(string)
	if name == "" || len(name) > fragMaxName {
		return "metadata.name is not a definition name"
	}
	raw, present := obj["spec"]
	if !present {
		return ""
	}
	spec, ok := raw.(map[string]any)
	if !ok {
		return "spec is not a mapping"
	}
	for _, k := range fragSortedKeys(spec) {
		switch k {
		case "preserveUnknownFields":
			if _, ok := spec[k].(bool); !ok {
				return "spec.preserveUnknownFields is not a boolean"
			}
		case "conversion":
			if why := fragConversionShape(spec[k]); why != "" {
				return "spec.conversion " + why
			}
		default:
			return fmt.Sprintf("spec key %q", k)
		}
	}
	return ""
}

func fragConversionShape(v any) string {
	c, ok := v.(map[string]any)
	if !ok {
		return "is not a mapping"
	}
	for _, k := range fragSortedKeys(c) {
		switch k {
		case "strategy":
			if s, _ := c[k].(string); s != "None" && s != "Webhook" {
				return fmt.Sprintf("strategy %q", c[k])
			}
		case "webhook":
			w, ok := c[k].(map[string]any)
			if !ok {
				return "webhook is not a mapping"
			}
			for _, wk := range fragSortedKeys(w) {
				switch wk {
				case "clientConfig":
					if why := fragClientConfigShape(w[wk]); why != "" {
						return "webhook.clientConfig " + why
					}
				case "conversionReviewVersions":
					if why := fragStringList(w[wk]); why != "" {
						return "webhook.conversionReviewVersions " + why
					}
				default:
					return fmt.Sprintf("webhook key %q", wk)
				}
			}
		case "webhookClientConfig":
			if why := fragClientConfigShape(c[k]); why != "" {
				return "webhookClientConfig " + why
			}
		case "conversionReviewVersions":
			if why := fragStringList(c[k]); why != "" {
				return "conversionReviewVersions " + why
			}
		default:
			return fmt.Sprintf("key %q", k)
		}
	}
	return ""
}

func fragClientConfigShape(v any) string {
	cc, ok := v.(map[string]any)
	if !ok {
		return "is not a mapping"
	}
	for _, k := range fragSortedKeys(cc) {
		switch k {
		case "url", "caBundle":
			if _, ok := cc[k].(string); !ok {
				return k + " is not a string"
			}
		case "service":
			svc, ok := cc[k].(map[string]any)
			if !ok {
				return "service is not a mapping"
			}
			for _, sk := range fragSortedKeys(svc) {
				switch sk {
				case "namespace", "name", "path":
					if _, ok := svc[sk].(string); !ok {
						return "service." + sk + " is not a string"
					}
				case "port":
					if _, ok := svc[sk].(json.Number); !ok {
						return "service.port is not a number"
					}
				default:
					return fmt.Sprintf("service key %q", sk)
				}
			}
		default:
			return fmt.Sprintf("key %q", k)
		}
	}
	return ""
}

func fragStringMap(v any) string {
	m, ok := v.(map[string]any)
	if !ok {
		return "is not a mapping"
	}
	for _, k := range fragSortedKeys(m) {
		if _, ok := m[k].(string); !ok {
			return fmt.Sprintf("value of %q is not a string", k)
		}
	}
	return ""
}

func fragStringList(v any) string {
	l, ok := v.([]any)
	if !ok {
		return "is not a list"
	}
	for _, it := range l {
		if _, ok := it.(string); !ok {
			return "holds a value that is not a string"
		}
	}
	return ""
}

// isKustomizationName is the extractor's list of kustomization file names.
func isKustomizationName(base string) bool {
	return base == "kustomization.yaml" || base == "kustomization.yml" || base == "Kustomization"
}

// kustomizationDirs lists the directories (never the repository root) that
// hold a kustomization file among the entries of a tree.
func kustomizationDirs(entries []Entry) map[string]bool {
	dirs := map[string]bool{}
	for _, e := range entries {
		if e.IsLink || !isKustomizationName(path.Base(e.Path)) {
			continue
		}
		if d := path.Dir(e.Path); d != "." {
			dirs[d] = true
		}
	}
	return dirs
}

// underKustomization says that a file lies below (or in) a directory of the
// set (never the repository root).
func underKustomization(p string, dirs map[string]bool) bool {
	for d := path.Dir(p); d != "." && d != "/" && d != ""; d = path.Dir(d) {
		if dirs[d] {
			return true
		}
	}
	return false
}
