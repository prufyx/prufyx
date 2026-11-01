// SPDX-License-Identifier: AGPL-3.0-only

package crdschema

import (
	"bytes"
	"errors"
	"io"
	"path"
	"strings"

	"gopkg.in/yaml.v3"
)

// kustomizeKeys are the top-level keys of a kustomize file that can only list
// resources or add metadata. Keys that can rewrite other documents (patches,
// replacements, transformers, generators, components, ...) are not in the
// list: such a file is never skipped.
var kustomizeKeys = map[string]bool{
	"apiVersion": true, "kind": true, "metadata": true, "resources": true, "bases": true,
	"namespace": true, "namePrefix": true, "nameSuffix": true,
	"labels": true, "commonLabels": true, "commonAnnotations": true,
}

func kustomizeName(file string) bool {
	b := path.Base(file)
	return b == "kustomization.yaml" || b == "kustomization.yml"
}

// isKustomizeFile reports whether a file of a listed directory is provably a
// kustomize file, which carries no CRD. All of these must hold, anything else
// is not skipped and stays an ordinary (non-CRD) document:
//   - the base name is exactly kustomization.yaml or kustomization.yml;
//   - the bytes do not mention CustomResourceDefinition (any case) anywhere;
//   - they parse as exactly one document that passes the strict YAML checks;
//   - the root is a mapping with only the keys in kustomizeKeys, "resources"
//     and "bases" being lists of strings;
//   - kind is Kustomization or Component, and apiVersion is absent or in the
//     kustomize.config.k8s.io group;
//   - every sibling YAML file of the same listed directory (siblings, base
//     names, the kustomization itself excluded) is named in resources or bases
//     as its base name or ./base name, and every resources or bases entry is
//     such a sibling (nothing else: no .., URL, subdirectory or glob). Otherwise a resources list is not inert:
//     a CRD that one commit lists and the other leaves out of the list is a
//     hidden removal, so the file stays an ordinary (non-CRD) document.
func isKustomizeFile(file string, data []byte, siblings []string, g parseGuards) (ok bool) {
	if !kustomizeName(file) {
		return false
	}
	if !g.kustomizeProof {
		return true
	}
	defer func() {
		if recover() != nil {
			ok = false
		}
	}()
	if g.kustomizeSize && len(data) > maxFileBytes {
		return false
	}
	if g.kustomizeMarker && bytes.Contains(bytes.ToLower(data), []byte("customresourcedefinition")) {
		return false
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	var n yaml.Node
	if err := dec.Decode(&n); err != nil {
		return false
	}
	var extra yaml.Node
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return false // a second document, or garbage after the first
	}
	root := &n
	if n.Kind == yaml.DocumentNode {
		if len(n.Content) != 1 {
			return false
		}
		root = n.Content[0]
	}
	if root.Kind != yaml.MappingNode {
		return false
	}
	if g.kustomizeStrict {
		if err := checkYAML(root, g, data); err != nil {
			return false
		}
	}
	named := map[string]bool{}
	sibSet := map[string]bool{}
	for _, sb := range siblings {
		sibSet[sb] = true
	}
	for i := 0; i+1 < len(root.Content); i += 2 {
		k, v := root.Content[i].Value, root.Content[i+1]
		if !kustomizeKeys[k] {
			return false
		}
		if k == "resources" || k == "bases" {
			if v.Kind != yaml.SequenceNode {
				return false
			}
			for _, e := range v.Content {
				if g.kustomizeEntries && !isStr(e) {
					return false
				}
				if isStr(e) {
					name := strings.TrimPrefix(e.Value, "./")
					// An entry that is not a sibling YAML file (.., /, :, a URL,
					// a subdirectory, a glob) pulls in documents this pass
					// does not read, so the file is not skipped.
					if g.kustomizeCovered && !sibSet[name] {
						return false
					}
					named[name] = true
				}
			}
		}
	}
	kind := mget(root, "kind")
	if !isStr(kind) || (kind.Value != "Kustomization" && kind.Value != "Component") {
		return false
	}
	if av := mget(root, "apiVersion"); av != nil && (!isStr(av) || !strings.HasPrefix(av.Value, "kustomize.config.k8s.io/")) {
		return false
	}
	if g.kustomizeCovered {
		for _, sib := range siblings {
			if !named[sib] {
				return false
			}
		}
	}
	return true
}
