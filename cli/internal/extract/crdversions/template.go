// SPDX-License-Identifier: AGPL-3.0-only

package crdversions

import (
	"bytes"
	"strings"
)

// Template syntax.
//
// A file the extractor reads must be a rendered manifest: the bytes the API
// server is sent, not a template a renderer turns into them. "{{" is how Go
// templates (Helm) open an action, so a file that holds it is not read as a
// manifest, with one exception that is decided by the structure of the file
// and not by a search for the characters: a CustomResourceDefinition's
// OpenAPI schema documents its fields in "description" strings, and a
// description may quote template syntax (Cluster API's ClusterClass
// documents its variable and patch templates that way). Such text is
// documentation. Nothing the extractor reads (names, group, scope, versions
// and their served and storage flags) depends on it, and a renderer that
// found it in a real template would have to fail on it, so a file whose
// every "{{" lies in description strings of the schema is a rendered
// manifest.
//
// The rule, precisely. A file with "{{" is read as a rendered manifest only
// when all of these hold; otherwise it is template syntax:
//
//  1. the file decodes within the strict YAML subset (decodeStrict);
//  2. the file with every "{{" (non-overlapping, left to right) replaced by
//     "{" and a letter decodes within the strict subset too, to a tree of
//     the same shape: the same mappings with the same keys, the same lists
//     of the same lengths, the same non-string scalars;
//  3. the two trees differ only in strings, and every string that differs
//     is the value of a "description" key of the OpenAPI schema of a
//     CustomResourceDefinition document, reached through schema keywords
//     only (schemaPathAdmitsDescription), and is exactly the other tree's
//     string with its "{{" replaced the same way;
//  4. no string of the decoded file holds "{{" unless it differs in that
//     way (a "{{" produced by an escape sequence, a line continuation or a
//     key is never admitted), and no key holds it;
//  5. the "{{" in those strings are all of the "{{" in the file, counted
//     in the bytes: a "{{" in a comment, or in any text that is not the
//     content of such a string, is one more than they account for.
//
// So a "{{" in a name, a flag, an annotation, a default, an enumeration, a
// validation rule, a key, a comment, a directive line, a flow collection
// or a document that is not a CustomResourceDefinition makes the file a
// template. The replacement changes the file's line structure nowhere, so
// the lines a citation names are the same in both readings.

// templateOutsideDescriptions returns why the file's "{{" is template
// syntax, or "" when the file has none or only the admitted kind. The
// decoded values are those of decodeStrict(data).
func templateOutsideDescriptions(data []byte, values []any) string {
	n := bytes.Count(data, []byte(templateMarker))
	if n == 0 {
		return ""
	}
	// The replacement letter: any letter works, the comparison below does
	// not depend on it being absent from the file.
	const letter = "T"
	replaced := bytes.ReplaceAll(data, []byte(templateMarker), []byte("{"+letter))
	_, other, err := decodeStrict(replaced)
	if err != nil {
		return "a \"{{\" outside the description strings of a schema changes how the file is read"
	}
	if len(other) != len(values) {
		return "a \"{{\" outside the description strings of a schema changes how the file is read"
	}
	accounted := 0
	for i := range values {
		w := templateWalk{replacement: "{" + letter}
		doc, _ := values[i].(map[string]any)
		w.crd = doc != nil && doc["kind"] == crdKind
		if reason := w.compare(values[i], other[i], nil); reason != "" {
			return reason
		}
		accounted += w.accounted
	}
	if accounted != n {
		return "a \"{{\" outside the description strings of a schema (in a comment or other text that is not such a string)"
	}
	return ""
}

type templateWalk struct {
	replacement string
	crd         bool
	accounted   int
}

// compare walks the file's tree a and the replaced file's tree b together.
// path holds the keys (string) and list indices (int) from the document root.
func (w *templateWalk) compare(a, b any, path []any) string {
	const reason = "a \"{{\" outside the description strings of a schema"
	switch x := a.(type) {
	case map[string]any:
		y, ok := b.(map[string]any)
		if !ok || len(x) != len(y) {
			return reason + " changes the file's structure"
		}
		for key, v := range x {
			if strings.Contains(key, templateMarker) {
				return reason + " (in a key)"
			}
			other, ok := y[key]
			if !ok {
				return reason + " changes the file's structure"
			}
			if why := w.compare(v, other, append(path[:len(path):len(path)], key)); why != "" {
				return why
			}
		}
		return ""
	case []any:
		y, ok := b.([]any)
		if !ok || len(x) != len(y) {
			return reason + " changes the file's structure"
		}
		for i := range x {
			if why := w.compare(x[i], y[i], append(path[:len(path):len(path)], i)); why != "" {
				return why
			}
		}
		return ""
	case string:
		y, ok := b.(string)
		if !ok {
			return reason + " changes the file's structure"
		}
		if !strings.Contains(x, templateMarker) {
			if x != y {
				return reason + " changes the file's content"
			}
			return ""
		}
		if !w.crd || !schemaPathAdmitsDescription(path) {
			return reason
		}
		if y != strings.ReplaceAll(x, templateMarker, w.replacement) {
			return reason + " (not written in the file's text)"
		}
		w.accounted += strings.Count(x, templateMarker)
		return ""
	default:
		// Booleans, numbers and null: the replacement cannot change them
		// without changing the file's shape, which is compared above; a
		// scalar that is not a string never holds "{{".
		if a != b {
			return reason + " changes the file's content"
		}
		return ""
	}
}

// schemaPathAdmitsDescription reports whether path names the "description"
// string of an OpenAPI schema of a CustomResourceDefinition:
//
//	spec.versions[i].schema.openAPIV3Schema ( <schema keyword> )* description
//
// where the schema keywords are exactly the ones that lead from a schema to
// a sub-schema: properties and patternProperties (followed by a field
// name), items, additionalProperties, not, and allOf, anyOf and oneOf
// (followed by an index). A field called "description" is a name after
// "properties", never the documentation key; arbitrary data (default,
// example, enum, x-kubernetes-validations) is not reached.
func schemaPathAdmitsDescription(path []any) bool {
	if len(path) < 6 {
		return false
	}
	if k, ok := path[0].(string); !ok || k != "spec" {
		return false
	}
	if k, ok := path[1].(string); !ok || k != "versions" {
		return false
	}
	if _, ok := path[2].(int); !ok {
		return false
	}
	if k, ok := path[3].(string); !ok || k != "schema" {
		return false
	}
	if k, ok := path[4].(string); !ok || k != "openAPIV3Schema" {
		return false
	}
	const (
		inSchema = iota
		inNames
		inList
	)
	state := inSchema
	rest := path[5:]
	for i, element := range rest {
		last := i == len(rest)-1
		switch state {
		case inSchema:
			key, ok := element.(string)
			if !ok {
				return false
			}
			switch key {
			case "description":
				return last
			case "items", "additionalProperties", "not":
				// stays in schema position
			case "properties", "patternProperties":
				state = inNames
			case "allOf", "anyOf", "oneOf":
				state = inList
			default:
				return false
			}
		case inNames:
			if _, ok := element.(string); !ok {
				return false
			}
			state = inSchema
		case inList:
			if _, ok := element.(int); !ok {
				return false
			}
			state = inSchema
		}
	}
	return false
}
