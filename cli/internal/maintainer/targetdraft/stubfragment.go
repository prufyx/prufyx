// SPDX-License-Identifier: AGPL-3.0-only

package targetdraft

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"path"
	"strings"

	"github.com/prufyx/prufyx/cli/internal/extract/crdversions"
	"gopkg.in/yaml.v3"
)

// Patch stubs (opt-in, Input.TolerateStubs; needs Input.SkipPatchFragments).
//
// Some kustomize patches are a CustomResourceDefinition stub that the patch
// fragment proof (fragment.go) rejects: metadata.creationTimestamp: null,
// status: null, an older apiVersion, a $(VAR) reference in a string. The
// stub proof below accepts such a document ONLY when every condition holds,
// and any doubt leaves the file unreadable-shape, exactly as without the
// option:
//
//   - the file is strictly decoded as for a fragment (fragDecodeStrict), has no
//     template syntax and lies below a kustomization directory, and not below
//     a path the generator refuses as a source (test, vendor, docs, fixture or
//     CI metadata directories);
//   - every document is either a #574 fragment document or a stub document;
//   - a stub document has only the keys apiVersion (apiextensions.k8s.io/v1,
//     v1beta1 or v1alpha1), kind CustomResourceDefinition, metadata, spec and
//     status; metadata only name, labels, annotations (string maps) and
//     creationTimestamp (null only); status absent or null-valued all the way
//     down; spec absent (never null) or only conversion, whose only fields are a
//     strategy equal to the full definition's own explicit strategy (Webhook or
//     None) and webhook.clientConfig.service namespace, name, path and port;
//   - metadata.name is <plural>.<group> and names an identity that exactly one
//     definition in the whole tree at this tag defines, and that one is a full
//     definition (scope, names, a versions list and a schema). A second
//     definition of the identity, an identity with none, or any file that
//     mentions a definition and cannot be decoded keeps the stop.
//
// The stub holds no group, names, scope, versions or schema, so it cannot
// redefine, add or remove a definition: the installed definitions are the full
// ones, which the generator reads as before. A set-aside stub is listed like a
// patch fragment (patchFragments, part of the facts digest).

const fragAPIVersionV1alpha1 = "apiextensions.k8s.io/v1alpha1"

// stubDef is one definition found in the tree under an identity.
type stubDef struct {
	full        bool
	strategy    string // spec.conversion.strategy of the definition, "" if absent
	hasStrategy bool
}

// stubIndex holds, per "<plural>.<group>", the definitions of one tree.
type stubIndex struct {
	defs    map[string][]stubDef
	blocked bool // a file mentioning a definition could not be decoded
}

// stubRefusedPath is a path the generator does not read as a source of
// definitions; a stub there is never set aside by this option.
func stubRefusedPath(p string) bool {
	if testLike(p) {
		return true
	}
	segs := strings.Split(p, "/")
	for _, s := range segs[:len(segs)-1] {
		switch s {
		case ".github", ".gitlab", ".circleci":
			return true
		}
	}
	return false
}

func lenientDocs(data []byte) ([]any, error) {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	var out []any
	for {
		var v any
		err := dec.Decode(&v)
		if errors.Is(err, io.EOF) {
			return out, nil
		}
		if err != nil {
			return nil, err
		}
		out = append(out, v)
		if len(out) > fragMaxDocuments {
			return nil, errFragStrict
		}
	}
}

func asMap(v any) (map[string]any, bool) {
	m, ok := v.(map[string]any)
	return m, ok
}

func nonEmptyString(v any) string {
	s, _ := v.(string)
	return s
}

// addDocs records the definition documents of one decoded value; items of a
// list are read to a bounded depth and exhausting the bound blocks every stub.
func (ix *stubIndex) addDocs(v any, depth int) {
	if v == nil {
		return
	}
	m, ok := asMap(v)
	if !ok {
		if _, isAnyMap := v.(map[any]any); isAnyMap {
			ix.blocked = true
		}
		return
	}
	if items, ok := m["items"].([]any); ok && len(items) > 0 {
		if depth >= 3 {
			ix.blocked = true
		} else {
			for _, it := range items {
				ix.addDocs(it, depth+1)
			}
		}
	}
	if m["kind"] != "CustomResourceDefinition" {
		return
	}
	spec, _ := asMap(m["spec"])
	if spec == nil {
		return
	}
	group := nonEmptyString(spec["group"])
	names, _ := asMap(spec["names"])
	plural := nonEmptyString(names["plural"])
	if group == "" || plural == "" {
		// A definition-like document with no identity cannot be counted
		// against a stub; one that names a group or names at all is doubtful.
		if _, g := spec["group"]; g {
			ix.blocked = true
		} else if _, n := spec["names"]; n {
			ix.blocked = true
		}
		return
	}
	id := plural + "." + group
	if meta, ok := asMap(m["metadata"]); ok {
		if n, present := meta["name"]; present && n != id {
			ix.blocked = true
		}
	}
	d := stubDef{}
	if conv, ok := asMap(spec["conversion"]); ok {
		if s, ok := conv["strategy"].(string); ok {
			d.strategy, d.hasStrategy = s, true
		}
	}
	d.full = nonEmptyString(spec["scope"]) != "" && nonEmptyString(names["kind"]) != "" && hasSchemaVersions(spec)
	ix.defs[id] = append(ix.defs[id], d)
}

func hasSchemaVersions(spec map[string]any) bool {
	versions, ok := spec["versions"].([]any)
	if !ok || len(versions) == 0 {
		return false
	}
	schema := false
	for _, v := range versions {
		vm, ok := asMap(v)
		if !ok || nonEmptyString(vm["name"]) == "" {
			return false
		}
		if s, ok := asMap(vm["schema"]); ok {
			if o, ok := asMap(s["openAPIV3Schema"]); ok && len(o) > 0 {
				schema = true
			}
		}
	}
	if !schema {
		if val, ok := asMap(spec["validation"]); ok {
			if o, ok := asMap(val["openAPIV3Schema"]); ok && len(o) > 0 {
				schema = true
			}
		}
	}
	return schema
}

// buildStubIndex reads every candidate file of the tree (each resolved file
// once). Anything it cannot read or decode blocks every stub.
func buildStubIndex(t Tree, isFile map[string]bool, paths []string) *stubIndex {
	ix := &stubIndex{defs: map[string][]stubDef{}}
	for _, p := range paths {
		if !isFile[p] {
			continue
		}
		data, err := t.Read(p)
		if err != nil {
			ix.blocked = true
			continue
		}
		// No raw-byte filter: a kind can be written with escapes, quotes or a
		// tag, so a file is judged by its decoded documents only. A file that
		// cannot be decoded (template, oversize, garbled) may hide a
		// definition and blocks every stub.
		if len(data) > crdversions.MaxFileBytes || bytes.Contains(data, []byte("{{")) {
			ix.blocked = true
			continue
		}
		docs, err := lenientDocs(data)
		if err != nil {
			ix.blocked = true
			continue
		}
		for _, d := range docs {
			ix.addDocs(d, 0)
		}
	}
	return ix
}

// isStubFile reports whether the bytes hold only patch fragment documents and
// stub documents (at least one stub) that the index proves harmless.
func isStubFile(data []byte, ix *stubIndex) bool {
	if ix == nil || ix.blocked || len(data) > crdversions.MaxFileBytes || bytes.Contains(data, []byte("{{")) || !bytes.Contains(data, []byte(fragKind)) {
		return false
	}
	values, err := fragDecodeStrict(data)
	if err != nil || len(values) == 0 {
		return false
	}
	for _, v := range values {
		if fragmentDoc(v) == "" {
			continue
		}
		if !stubDoc(v, ix) {
			return false
		}
	}
	return true
}

func nullish(v any, depth int) bool {
	if v == nil {
		return true
	}
	m, ok := v.(map[string]any)
	if !ok || depth > 8 {
		return false
	}
	for _, x := range m {
		if !nullish(x, depth+1) {
			return false
		}
	}
	return true
}

func stubDoc(v any, ix *stubIndex) bool {
	obj, ok := v.(map[string]any)
	if !ok {
		return false
	}
	for k := range obj {
		switch k {
		case "apiVersion", "kind", "metadata", "spec", "status":
		default:
			return false
		}
	}
	switch obj["apiVersion"] {
	case fragAPIVersionV1, fragAPIVersionV1beta1, fragAPIVersionV1alpha1:
	default:
		return false
	}
	if obj["kind"] != fragKind {
		return false
	}
	meta, ok := obj["metadata"].(map[string]any)
	if !ok {
		return false
	}
	for k, val := range meta {
		switch k {
		case "name":
		case "labels", "annotations":
			if fragStringMap(val) != "" {
				return false
			}
			// A key starting with $ ($patch) is a merge directive that
			// deletes or replaces the definition's own map.
			for lk := range val.(map[string]any) {
				if strings.HasPrefix(lk, "$") {
					return false
				}
			}
		case "creationTimestamp":
			if val != nil {
				return false
			}
		default:
			return false
		}
	}
	name, _ := meta["name"].(string)
	if name == "" || len(name) > fragMaxName {
		return false
	}
	dot := strings.Index(name, ".")
	if dot <= 0 || dot == len(name)-1 {
		return false
	}
	defs := ix.defs[name]
	if len(defs) != 1 || !defs[0].full {
		return false
	}
	if st, present := obj["status"]; present && !nullish(st, 0) {
		return false
	}
	raw, present := obj["spec"]
	if !present {
		return true
	}
	// An explicit null spec (or any null below it) would delete the full
	// definition's field in a merge patch: only absence is harmless. The
	// tolerated nulls are status and metadata.creationTimestamp.
	spec, ok := raw.(map[string]any)
	if !ok {
		return false
	}
	for k, c := range spec {
		if k != "conversion" || !stubConversion(c, defs[0]) {
			return false
		}
	}
	return true
}

func stubConversion(v any, def stubDef) bool {
	c, ok := v.(map[string]any)
	if !ok {
		return false
	}
	for k, val := range c {
		switch k {
		case "strategy":
			s, _ := val.(string)
			if (s != "Webhook" && s != "None") || !def.hasStrategy || s != def.strategy {
				return false
			}
		case "webhook":
			w, ok := val.(map[string]any)
			if !ok {
				return false
			}
			for wk, wv := range w {
				cc, ok := wv.(map[string]any)
				if wk != "clientConfig" || !ok {
					return false
				}
				for ck, cv := range cc {
					svc, ok := cv.(map[string]any)
					if ck != "service" || !ok {
						return false
					}
					for sk, sv := range svc {
						switch sk {
						case "namespace", "name", "path":
							if _, ok := sv.(string); !ok {
								return false
							}
						case "port":
							switch sv.(type) {
							case json.Number, string:
							default:
								return false
							}
						default:
							return false
						}
					}
				}
			}
		default:
			return false
		}
	}
	return true
}

// stubPathOK is the location condition of a stub (see stubRefusedPath and the
// kustomization rule of fragments).
func stubPathOK(p string, kdirs map[string]bool) bool {
	return underKustomization(p, kdirs) && !stubRefusedPath(p) && path.Dir(p) != "."
}
