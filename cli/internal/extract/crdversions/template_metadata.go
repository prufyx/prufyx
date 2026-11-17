// SPDX-License-Identifier: AGPL-3.0-only

package crdversions

import (
	"bytes"
	"strings"

	"gopkg.in/yaml.v3"
)

// templateReadMetadata is the FileRecord.TemplateRead value of a file read
// under the metadata-only rule.
const templateReadMetadata = "markers-in-comments-and-metadata-strings"

// Template markers outside the schema.
//
// Some projects ship a CRD file generated for a chart: the markers ("{{" and
// "}}") lie in full-line comments and in quoted label values, and nothing
// the extractor reads depends on them. A file with markers is read as a
// rendered manifest under this rule, and only under it. It holds when all of
// these are true:
//
//  1. the file decodes within the strict YAML subset and is exactly one
//     document, a CustomResourceDefinition;
//  2. every marker lies in a full-line comment (the first non-blank
//     character of its line is "#"), or inside a single- or double-quoted
//     scalar that is the value of metadata.labels.<key> or
//     metadata.annotations.<key>;
//  3. apiVersion, kind, metadata.name and the whole spec subtree hold no
//     marker (no comment line within the lines of spec either), and no key
//     anywhere holds one (checked on the decoded tree);
//  4. the markers are accounted in the bytes: the file with every "{{"
//     replaced decodes to the same tree except in those strings, and the
//     count of each marker in the bytes equals the count in full-line
//     comments plus the count in those strings (a marker in a trailing
//     comment, produced by an escape or a continuation line, or in a block
//     scalar is one more than they account for).
//
//  5. no comment that holds a marker also holds "-}}", "~}}" or "{{~" (a
//     trim marker would swallow the next line in a chart render); "{{-" is
//     not refused.
//
// Trust assumption: the extractor attests the SHIPPED FILE TEXT of the CRD
// file, the bytes at the pinned tag, not a Helm chart render of it. The
// markers admitted here are inert in that text.
//
// Anything else is template syntax with the same refusal as before. The
// decision is recorded on the file's record (FileRecord.TemplateRead).

// templateInMetadata returns why the file does not satisfy the rule, or ""
// when it does. nodes and values are those of decodeStrict(data).
func templateInMetadata(data []byte, nodes []*yaml.Node, values []any) string {
	const no = "markers outside comments and metadata label and annotation strings"
	if len(values) != 1 || len(nodes) != 1 {
		return no + ": not a single document"
	}
	doc, _ := values[0].(map[string]any)
	if doc == nil || doc["kind"] != crdKind {
		return no + ": not a CustomResourceDefinition"
	}
	// Quoted label and annotation values: only these may hold a marker.
	quoted := map[string]bool{}
	if meta, _ := child(nodes[0], "metadata"); meta != nil {
		for _, group := range []string{"labels", "annotations"} {
			m, _ := child(meta, group)
			if m == nil || m.Kind != yaml.MappingNode {
				continue
			}
			for i := 0; i+1 < len(m.Content); i += 2 {
				v := m.Content[i+1]
				if v.Kind == yaml.ScalarNode && v.ShortTag() == "!!str" && v.Style&(yaml.SingleQuotedStyle|yaml.DoubleQuotedStyle) != 0 {
					quoted[group+"\x00"+m.Content[i].Value] = true
				}
			}
		}
	}
	admit := func(path []any) bool {
		if len(path) != 3 {
			return false
		}
		root, _ := path[0].(string)
		group, _ := path[1].(string)
		key, _ := path[2].(string)
		return root == "metadata" && quoted[group+"\x00"+key]
	}
	replaced := bytes.ReplaceAll(data, []byte(templateMarker), []byte("{T"))
	_, other, err := decodeStrict(replaced)
	if err != nil || len(other) != 1 {
		return no + ": changes how the file is read"
	}
	w := templateWalk{replacement: "{T", admit: admit}
	if why := w.compare(values[0], other[0], nil); why != "" {
		return why
	}
	// Markers in full-line comments.
	// None may lie within the lines of spec.
	specFrom, specTo := 0, 0
	if v, k := child(nodes[0], "spec"); v != nil {
		specFrom, specTo = k.Line, maxLine(v)
	}
	openComment, closeComment := 0, 0
	for i, line := range bytes.Split(data, []byte("\n")) {
		if t := bytes.TrimLeft(line, " \t"); len(t) > 0 && t[0] == '#' {
			o, c := bytes.Count(t, []byte(templateMarker)), bytes.Count(t, []byte(templateClose))
			if (o > 0 || c > 0) && (bytes.Contains(t, []byte("-}}")) || bytes.Contains(t, []byte("~}}")) || bytes.Contains(t, []byte("{{~"))) {
				// A right-trim or tilde marker would swallow the next
				// line in a chart render: the comment is not inert.
				return no + ": a trim marker in a comment"
			}
			if (o > 0 || c > 0) && i+1 >= specFrom && i+1 <= specTo {
				return no + ": a comment marker lies within spec"
			}
			openComment += o
			closeComment += c
		}
	}
	if bytes.Count(data, []byte(templateMarker)) != openComment+w.accounted ||
		strings.Count(string(data), templateClose) != closeComment+w.closes {
		return no + ": a marker lies elsewhere"
	}
	return ""
}
