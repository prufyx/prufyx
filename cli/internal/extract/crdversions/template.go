// SPDX-License-Identifier: AGPL-3.0-only

package crdversions

import (
	"bytes"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
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

// Template syntax in comment directives and metadata strings.
//
// A file the description rule refuses is read as a rendered manifest when
// its "{{" sit where Helm can only drop the whole file, drop or add
// metadata lines, or write inside a quoted metadata string (cert-manager's
// deploy/crds from 1.16 to 1.18 are written that way). The rule, precisely.
// A file with "{{" is read only when all of these hold; otherwise it is
// template syntax:
//
//  1. the file decodes within the strict YAML subset and holds no line
//     break other than "\n" (no carriage return, NEL U+0085, line
//     separator U+2028 or paragraph separator U+2029, which the decoder
//     counts as line breaks);
//  2. every string of the decoded file that holds "{{" is the value of a
//     key of metadata.labels or metadata.annotations of a
//     CustomResourceDefinition document, written on one line in single or
//     double quotes whose text is the string itself (no escape, no doubled
//     quote), with nothing but blanks after the closing quote; each action
//     in it is well formed (no brace inside it), trims no whitespace, and
//     is not an if, else, end, range, with, define, block, break or
//     continue, nor a variable assignment. No key holds "{{";
//  3. every other line that holds "{{" is a comment directive: a "#"
//     comment that ends in exactly one action (^\s*#[^{}]*\{\{[^{}]*\}\}\s*$),
//     placed as readTemplate places a directive line: a template comment
//     anywhere; the declared template header (Target.TemplateHeader,
//     matched exactly) once, before the condition around the whole file
//     and any line that is not blank or a comment; an if as the condition
//     around the whole file, before any line that is not blank or a
//     comment, whose end is the last line that is not blank; and if, with,
//     end, and include or toYaml ending in indent or nindent only inside
//     the top-level metadata block of a CustomResourceDefinition document
//     (from its metadata key to the document's next key, located in the
//     decoded nodes), balanced inside it. Anything else (range, else,
//     define, template, block, an assignment, an expression, a directive
//     elsewhere or between documents) is template syntax. A directive that
//     trims the line break after it ("-}}") is accepted only on the last
//     line that is not blank: "{{-" on a comment line trims back to the
//     "#" at most;
//  4. the file with every admitted action replaced by as many spaces (same
//     bytes and lines) decodes to the same tree, except that each admitted
//     string reads with its actions replaced the same way, and the admitted
//     actions are all of the "{{" of the file's bytes.
//
// What the rendering can do with such a file: the condition around the file
// drops every document of it, never one version; a condition in metadata
// drops metadata lines, an include in metadata adds lines indented by at
// least one column inside it; the output of an action inside a quoted
// string stays in that string unless it closes the quote, and then it can
// change spec only through a duplicate key or a new document, which the
// API server refuses or reads as another definition. The file is read as
// it is written (the condition taken as true), like a templated copy.

// commentDirectiveRE is a comment line that ends in exactly one action.
var commentDirectiveRE = regexp.MustCompile(`^\s*#[^{}]*\{\{[^{}]*\}\}\s*$`)

// stringActionWords are the action words refused inside a metadata string.
var stringActionWords = []string{"if", "else", "end", "range", "with", "define", "block", "break", "continue"}

// templateInCommentsAndMetadata returns why the file's "{{" is template
// syntax under the rule above, or "" when the file is read. nodes and
// values are those of decodeStrict(data); header is the action of the
// target's declared template header ("" for none).
func templateInCommentsAndMetadata(data []byte, nodes []*yaml.Node, values []any, header string) string {
	const reason = "a \"{{\" outside comment directives and metadata labels and annotations"
	n := bytes.Count(data, []byte(templateMarker))
	if n == 0 {
		return ""
	}
	// The metadata block is located by the lines of the decoded nodes and
	// applied to the file split at "\n": every other byte sequence the YAML
	// decoder counts as a line break (CR, NEL, LS, PS) would shift one
	// against the other.
	if bytes.IndexByte(data, '\r') >= 0 || len(nodes) != len(values) {
		return reason
	}
	if bytes.Contains(data, []byte("\xc2\x85")) || bytes.Contains(data, []byte("\xe2\x80\xa8")) || bytes.Contains(data, []byte("\xe2\x80\xa9")) {
		return reason
	}
	lines := strings.Split(string(data), "\n")
	s := metadataStrings{lines: lines, spans: map[int][][2]int{}, expected: map[int]map[string]string{}}
	// region marks the lines (0-based) of the top-level metadata block of
	// each CustomResourceDefinition document.
	region := make([]bool, len(lines))
	for d, root := range nodes {
		doc, _ := values[d].(map[string]any)
		crd := doc != nil && doc["kind"] == crdKind
		if why := s.walk(root, nil, crd, d); why != "" {
			return why
		}
		if !crd {
			continue
		}
		meta, key := child(root, "metadata")
		if meta == nil || meta.Kind != yaml.MappingNode || meta.Style != 0 || key.Column != 1 || key.Line < 1 || key.Line > len(lines) || strings.TrimRight(lines[key.Line-1], " \t") != "metadata:" {
			continue
		}
		end := following(root, "metadata")
		if end == 0 {
			end = maxLine(meta) + 1
		}
		for l := key.Line; l < end && l <= len(lines); l++ {
			region[l-1] = true
		}
	}
	first, last := -1, -1
	for i, line := range lines {
		if strings.TrimSpace(line) != "" {
			if first < 0 {
				first = i
			}
			last = i
		}
	}
	replaced := make([]string, len(lines))
	copy(replaced, lines)
	admitted := s.count
	depth, metaDepth := 0, 0
	wrapper, seen, headerUsed, inMeta := false, false, false, false
	for i, line := range lines {
		if region[i] != inMeta {
			if inMeta && depth != metaDepth {
				return reason + " (a condition in metadata does not end inside it)"
			}
			inMeta, metaDepth = region[i], depth
		}
		t := strings.TrimSpace(line)
		if !strings.Contains(line, templateMarker) {
			if t != "" && !strings.HasPrefix(t, "#") {
				seen = true
			}
			continue
		}
		if spans, ok := s.spans[i]; ok {
			// A line with an admitted string: every "{{" on it lies in one.
			for off := 0; ; {
				j := strings.Index(line[off:], templateMarker)
				if j < 0 {
					break
				}
				at := off + j
				inside := false
				for _, sp := range spans {
					inside = inside || (at >= sp[0] && at+len(templateMarker) <= sp[1])
				}
				if !inside {
					return reason
				}
				off = at + len(templateMarker)
			}
			for _, sp := range spans {
				replaced[i] = replaced[i][:sp[0]] + blankActions(replaced[i][sp[0]:sp[1]]) + replaced[i][sp[1]:]
			}
			seen = true
			continue
		}
		if !commentDirectiveRE.MatchString(line) {
			return reason
		}
		loc := templateRE.FindStringIndex(line)
		expr := line[loc[0]:loc[1]]
		replaced[i] = line[:loc[0]] + strings.Repeat(" ", len(expr)) + line[loc[1]:]
		admitted++
		action, after := templateAction(expr)
		if after && i != last {
			return reason + " (a directive trims the line break after it)"
		}
		if templateComment(expr) {
			continue
		}
		if assignRE.MatchString(action) {
			return reason + " (a template variable is assigned)"
		}
		word := ""
		if f := strings.Fields(action); len(f) > 0 {
			word = f[0]
		}
		switch {
		case header != "" && action == header && !headerUsed && !wrapper && !seen:
			headerUsed = true
		case word == "if" && !wrapper && !seen && depth == 0:
			wrapper, depth, seen = true, 1, true
		case word == "end" && wrapper && depth == 1 && !inMeta:
			if i != last {
				return reason + " (the condition around the whole file ends before its last line)"
			}
			depth = 0
		case !inMeta:
			return reason + " (" + directiveWord(word) + " directive outside metadata)"
		case word == "if" || word == "with":
			depth++
		case word == "end":
			if depth <= metaDepth {
				return reason + " (an end in metadata closes a condition opened outside it)"
			}
			depth--
		case word == "include" || word == "toYaml":
			if !indentedRE.MatchString(action) {
				return reason + " (" + directiveWord(word) + " directive whose output does not end in indent or nindent)"
			}
		default:
			return reason + " (" + directiveWord(word) + " directive)"
		}
	}
	if inMeta && depth != metaDepth {
		return reason + " (a condition in metadata does not end inside it)"
	}
	if depth != 0 {
		return reason + " (a condition does not end)"
	}
	if admitted != n {
		return reason
	}
	_, other, err := decodeStrict([]byte(strings.Join(replaced, "\n")))
	if err != nil || len(other) != len(values) {
		return reason + " changes how the file is read"
	}
	for d := range values {
		if !sameExceptAdmitted(values[d], other[d], nil, s.expected[d]) {
			return reason + " changes how the file is read"
		}
	}
	return ""
}

// metadataStrings collects the admitted metadata strings of a file: the
// byte spans of their text per line (0-based), their count of "{{", and per
// document the string each reads with its actions blanked, by
// "labels\x00<key>" or "annotations\x00<key>".
type metadataStrings struct {
	lines    []string
	spans    map[int][][2]int
	count    int
	expected map[int]map[string]string
}

// walk checks every key and string of a document node for "{{".
func (s *metadataStrings) walk(n *yaml.Node, path []any, crd bool, doc int) string {
	const reason = "a \"{{\" outside comment directives and metadata labels and annotations"
	switch n.Kind {
	case yaml.MappingNode:
		for i := 0; i+1 < len(n.Content); i += 2 {
			if strings.Contains(n.Content[i].Value, templateMarker) {
				return reason + " (in a key)"
			}
			if why := s.walk(n.Content[i+1], append(path[:len(path):len(path)], n.Content[i].Value), crd, doc); why != "" {
				return why
			}
		}
	case yaml.SequenceNode:
		for i, c := range n.Content {
			if why := s.walk(c, append(path[:len(path):len(path)], i), crd, doc); why != "" {
				return why
			}
		}
	case yaml.ScalarNode:
		if !strings.Contains(n.Value, templateMarker) {
			return ""
		}
		if !crd || len(path) != 3 || path[0] != "metadata" || (path[1] != "labels" && path[1] != "annotations") {
			return reason
		}
		key, _ := path[2].(string)
		from, to, ok := s.oneLineQuoted(n)
		if !ok {
			return reason + " (a metadata string that is not one quoted line)"
		}
		raw := s.lines[n.Line-1][from:to]
		if strings.Contains(templateRE.ReplaceAllString(raw, ""), "{{") || strings.Contains(templateRE.ReplaceAllString(raw, ""), "}}") {
			return reason + " (a template action is not well formed)"
		}
		for _, expr := range templateRE.FindAllString(raw, -1) {
			if strings.ContainsAny(expr[2:len(expr)-2], "{}") {
				return reason + " (a template action is not well formed)"
			}
			action, after := templateAction(expr)
			if after || strings.HasPrefix(expr, "{{-") {
				return reason + " (a template action in a metadata string trims whitespace)"
			}
			if templateComment(expr) {
				continue
			}
			word := ""
			if f := strings.Fields(action); len(f) > 0 {
				word = f[0]
			}
			if assignRE.MatchString(action) || slicesContains(stringActionWords, word) {
				return reason + " (" + directiveWord(word) + " action in a metadata string)"
			}
		}
		s.spans[n.Line-1] = append(s.spans[n.Line-1], [2]int{from, to})
		s.count += strings.Count(raw, templateMarker)
		if s.expected[doc] == nil {
			s.expected[doc] = map[string]string{}
		}
		s.expected[doc][path[1].(string)+"\x00"+key] = blankActions(n.Value)
	}
	return ""
}

// oneLineQuoted returns the byte span, in its line, of the text of a
// quoted scalar written on one line whose text is its value, followed by
// nothing but blanks.
func (s *metadataStrings) oneLineQuoted(n *yaml.Node) (int, int, bool) {
	if n.Style != yaml.SingleQuotedStyle && n.Style != yaml.DoubleQuotedStyle {
		return 0, 0, false
	}
	if n.Line < 1 || n.Line > len(s.lines) || n.Column < 1 {
		return 0, 0, false
	}
	line := s.lines[n.Line-1]
	col := n.Column - 1
	if col >= len(line) {
		return 0, 0, false
	}
	for i := 0; i < col; i++ {
		if line[i] >= 0x80 {
			return 0, 0, false
		}
	}
	quote := byte('\'')
	if n.Style == yaml.DoubleQuotedStyle {
		quote = '"'
	}
	if line[col] != quote {
		return 0, 0, false
	}
	from := col + 1
	to := strings.IndexByte(line[from:], quote)
	if to < 0 {
		return 0, 0, false
	}
	to += from
	raw := line[from:to]
	if raw != n.Value || strings.ContainsRune(raw, '\\') || strings.TrimSpace(line[to+1:]) != "" {
		return 0, 0, false
	}
	return from, to, true
}

// blankActions replaces every action in s by as many spaces.
func blankActions(s string) string {
	return templateRE.ReplaceAllStringFunc(s, func(m string) string { return strings.Repeat(" ", len(m)) })
}

// sameExceptAdmitted compares the file's tree a with the blanked file's
// tree b: equal, except that an admitted string of b reads as expected.
func sameExceptAdmitted(a, b any, path []any, expected map[string]string) bool {
	switch x := a.(type) {
	case map[string]any:
		y, ok := b.(map[string]any)
		if !ok || len(x) != len(y) {
			return false
		}
		for k, v := range x {
			w, ok := y[k]
			if !ok || !sameExceptAdmitted(v, w, append(path[:len(path):len(path)], k), expected) {
				return false
			}
		}
		return true
	case []any:
		y, ok := b.([]any)
		if !ok || len(x) != len(y) {
			return false
		}
		for i := range x {
			if !sameExceptAdmitted(x[i], y[i], append(path[:len(path):len(path)], i), expected) {
				return false
			}
		}
		return true
	case string:
		y, ok := b.(string)
		if !ok {
			return false
		}
		if len(path) == 3 && path[0] == "metadata" {
			section, _ := path[1].(string)
			key, _ := path[2].(string)
			if want, admitted := expected[section+"\x00"+key]; admitted {
				return y == want
			}
		}
		return x == y
	default:
		return a == b
	}
}
