// SPDX-License-Identifier: AGPL-3.0-only

package fix

import (
	"bytes"
	"encoding/json"
	"strings"
	"unicode/utf8"

	"gopkg.in/yaml.v3"

	"github.com/prufyx/prufyx/cli/internal/intake"
)

// Operation is a structural change a kind declares: what the decoded
// document must look like afterwards. The framework applies the declared
// operation to the decoded document itself and requires the edited bytes to
// decode to exactly that result. The kind's byte edit is only a proposal; it
// is never the source of the expected result.
//
// The operations are RenameKey, RemoveKey, RemoveElement and SetValue. Paths
// are relative to the root of the document the kind was asked to plan and
// use the names and indexes of the original document.
type Operation interface {
	operation()
}

// RenameKey renames the mapping key at Path (a path ending in a key) to
// NewKey. The value stays as it is.
type RenameKey struct {
	Path   Path
	NewKey string
}

// RemoveKey removes the mapping entry (key and whole value) at Path, which
// ends in a key.
type RemoveKey struct {
	Path Path
}

// RemoveElement removes the sequence element at Path, which ends in an index.
type RemoveElement struct {
	Path Path
}

// SetValue replaces the scalar value at Path with Scalar. Scalar is a string,
// a bool, nil (null) or a json.Number holding a plain decimal number.
type SetValue struct {
	Path   Path
	Scalar any
}

func (RenameKey) operation()     {}
func (RemoveKey) operation()     {}
func (RemoveElement) operation() {}
func (SetValue) operation()      {}

// Planned is one declared operation together with the byte edit the kind
// proposes for it.
type Planned struct {
	Op   Operation
	Edit Edit
}

// OperationKind is an optional extension of Kind for structural changes. The
// framework calls PlanOperations after Plan for every selected document; the
// same purity and idempotence rules apply. An operation that is already
// satisfied must not be returned again.
//
// Edit shapes: RenameKey edits exactly the key token; SetValue edits exactly
// the scalar token; RemoveKey and RemoveElement delete whole lines (empty
// replacement) from the start of the entry's first line up to the start of
// the line after its last line. Locator provides RemoveKeyEdit and
// RemoveElementEdit for that span.
type OperationKind interface {
	Kind
	PlanOperations(doc intake.Document, src []byte, parsed any) ([]Planned, error)
}

// opEdit is a planned operation of one document.
type opEdit struct {
	document int
	op       Operation
	edit     Edit
}

func (o opEdit) path() Path {
	switch op := o.op.(type) {
	case RenameKey:
		return op.Path
	case RemoveKey:
		return op.Path
	case RemoveElement:
		return op.Path
	case SetValue:
		return op.Path
	}
	return nil
}

func (o opEdit) removes() bool {
	switch o.op.(type) {
	case RemoveKey, RemoveElement:
		return true
	}
	return false
}

// validateDeclared checks an operation on its own: the path shape, the new
// key, the scalar.
func validateDeclared(op Operation) *Refusal {
	check := func(path Path, wantKey, wantIndex bool) *Refusal {
		if len(path) == 0 || len(path) > MaxPathSegments {
			return refuse(ReasonInvalidEdit, "an operation path is empty or too long")
		}
		last := path[len(path)-1]
		if wantKey && last.isIndex || wantIndex && !last.isIndex {
			return refuse(ReasonInvalidEdit, "an operation path ends in the wrong kind of segment")
		}
		return nil
	}
	switch typed := op.(type) {
	case RenameKey:
		if r := check(typed.Path, true, false); r != nil {
			return r
		}
		if typed.NewKey == "" || typed.NewKey == "<<" || len(typed.NewKey) > MaxReplacementBytes ||
			!utf8.ValidString(typed.NewKey) || hasControl(typed.NewKey) ||
			strings.Contains(typed.NewKey, "{{") || strings.Contains(typed.NewKey, "${") {
			return refuse(ReasonInvalidEdit, "the new key is not a usable single-line key")
		}
	case RemoveKey:
		return check(typed.Path, true, false)
	case RemoveElement:
		return check(typed.Path, false, true)
	case SetValue:
		if r := check(typed.Path, false, false); r != nil {
			return r
		}
		switch scalar := typed.Scalar.(type) {
		case nil, bool:
		case string:
			if !utf8.ValidString(scalar) || hasControl(scalar) || strings.Contains(scalar, "{{") || strings.Contains(scalar, "${") {
				return refuse(ReasonInvalidEdit, "the new value is not a usable single-line text")
			}
		case json.Number:
			if !plainDecimal.MatchString(string(scalar)) {
				return refuse(ReasonInvalidEdit, "the new value is not a plain decimal number")
			}
		default:
			return refuse(ReasonInvalidEdit, "the new value is not a string, number, boolean or null")
		}
	default:
		return refuse(ReasonInvalidEdit, "unknown operation")
	}
	return nil
}

// markerRemoved stands in for a removed entry while the other operations
// still navigate by the original names and indexes.
type markerRemoved struct{}

// applyOperations applies the declared operations to the decoded documents:
// values first, then removals (as markers, so indexes and names stay valid),
// then renames from the deepest path up, then the markers are dropped. A
// mapping or sequence that loses entries must keep at least one.
func applyOperations(expected []any, ops []opEdit, plainKeys []target) *Refusal {
	cannot := refuse(ReasonDecodeMismatch, "the declared operation cannot be applied to the decoded document")
	for _, o := range ops {
		if op, ok := o.op.(SetValue); ok {
			if !substitute(&expected[o.document], op.Path, PartValue, scalarValue(op.Scalar)) {
				return cannot
			}
		}
	}
	for _, o := range ops {
		if o.removes() && !markRemoved(&expected[o.document], o.path()) {
			return cannot
		}
	}
	type rename struct {
		document int
		path     Path
		key      string
	}
	var renames []rename
	for _, o := range ops {
		if op, ok := o.op.(RenameKey); ok {
			renames = append(renames, rename{o.document, op.Path, op.NewKey})
		}
	}
	for _, t := range plainKeys {
		renames = append(renames, rename{t.document, t.path, t.value.(string)})
	}
	// Deepest first, so every step navigates by original names.
	for i := 1; i < len(renames); i++ {
		for j := i; j > 0 && len(renames[j].path) > len(renames[j-1].path); j-- {
			renames[j], renames[j-1] = renames[j-1], renames[j]
		}
	}
	for _, r := range renames {
		if !substitute(&expected[r.document], r.path, PartKey, r.key) {
			return cannot
		}
	}
	for i := range expected {
		var emptied bool
		expected[i], emptied = sweep(expected[i])
		if emptied {
			return refuse(ReasonInvalidEdit, "the removal would leave an empty mapping or sequence")
		}
	}
	return nil
}

func scalarValue(scalar any) any {
	if n, ok := scalar.(json.Number); ok {
		return json.Number(string(n))
	}
	return scalar
}

// markRemoved replaces the entry at path with a marker.
func markRemoved(at *any, path Path) bool {
	segment := path[0]
	switch container := (*at).(type) {
	case map[string]any:
		child, ok := container[segment.key]
		if segment.isIndex || !ok {
			return false
		}
		if len(path) == 1 {
			if _, again := child.(markerRemoved); again {
				return false
			}
			container[segment.key] = markerRemoved{}
			return true
		}
		if !markRemoved(&child, path[1:]) {
			return false
		}
		container[segment.key] = child
		return true
	case []any:
		if !segment.isIndex || segment.index < 0 || segment.index >= len(container) {
			return false
		}
		if len(path) == 1 {
			if _, again := container[segment.index].(markerRemoved); again {
				return false
			}
			container[segment.index] = markerRemoved{}
			return true
		}
		return markRemoved(&container[segment.index], path[1:])
	}
	return false
}

// sweep drops the markers. emptied reports a container that held entries and
// lost all of them.
func sweep(value any) (out any, emptied bool) {
	switch typed := value.(type) {
	case map[string]any:
		had := len(typed)
		for key, child := range typed {
			if _, gone := child.(markerRemoved); gone {
				delete(typed, key)
				continue
			}
			swept, bad := sweep(child)
			if bad {
				return nil, true
			}
			typed[key] = swept
		}
		return typed, had > 0 && len(typed) == 0
	case []any:
		kept := make([]any, 0, len(typed))
		for _, child := range typed {
			if _, gone := child.(markerRemoved); gone {
				continue
			}
			swept, bad := sweep(child)
			if bad {
				return nil, true
			}
			kept = append(kept, swept)
		}
		return kept, len(typed) > 0 && len(kept) == 0
	}
	return value, false
}

// RemoveKeyEdit returns the edit that deletes the mapping entry at path, key
// and whole value, as whole lines; RemoveElementEdit does the same for a
// sequence element. See removalSpan for what is refused.
func (l *Locator) RemoveKeyEdit(file string, document int, path Path) (Edit, error) {
	return l.removal(file, document, path, false)
}

// RemoveElementEdit: see RemoveKeyEdit.
func (l *Locator) RemoveElementEdit(file string, document int, path Path) (Edit, error) {
	return l.removal(file, document, path, true)
}

func (l *Locator) removal(file string, document int, path Path, element bool) (Edit, error) {
	span, r := l.file.removalSpan(document, path, element)
	if r != nil {
		return Edit{}, r
	}
	return Edit{File: file, StartByte: span.Start, EndByte: span.End}, nil
}

// removalSpan computes the whole lines an entry occupies. The entry is the
// mapping key at path (element false) or the sequence element (element
// true). It is refused unless:
//
//   - no flow-style collection holds the entry;
//   - the entry starts its own line: only spaces before a key, only spaces,
//     one dash and spaces before an element (so "- key: v" and "? key" are
//     out);
//   - no tab is used in the indentation of the lines involved;
//   - no other token shares a line with the entry;
//   - its parent keeps at least one entry.
//
// The entry ends with its last line that has content deeper than the entry's
// indentation (a block sequence written at the key's own indentation counts as
// deeper). That includes comment lines indented deeper than the entry that
// follow its value. Blank lines, and comment lines at the entry's own
// indentation or less (the head comment of the next entry), stay. Comment
// lines above the entry stay too.
func (f *parsedFile) removalSpan(document int, path Path, element bool) (Span, *Refusal) {
	if len(path) == 0 || path[len(path)-1].isIndex != element {
		return Span{}, refuse(ReasonPathNotFound, "the path does not end in the kind of segment to remove")
	}
	found, r := f.resolve(document, path, PartValue)
	if r != nil {
		return Span{}, r
	}
	if found.flow || found.parent == nil || found.parent.Style&yaml.FlowStyle != 0 {
		return Span{}, refuse(ReasonSpanNotIsolated, "the entry is inside a flow-style collection")
	}
	entries := len(found.parent.Content)
	if !element {
		entries /= 2
	}
	if entries < 2 {
		return Span{}, refuse(ReasonInvalidEdit, "the removal would leave an empty mapping or sequence")
	}
	first := found.node
	if !element {
		first = found.key
	}
	at, ok := f.offset(first.Line, first.Column)
	if !ok {
		return Span{}, refuse(ReasonSpanNotIsolated, "the entry position is outside the file")
	}
	lineIndex := first.Line - 1
	if lineIndex == 0 && bytes.HasPrefix(f.src, bom) {
		return Span{}, refuse(ReasonSpanNotIsolated, "the entry is on the first line of a file that starts with a byte order mark")
	}
	prefix := f.src[f.lineStarts[lineIndex]:at]
	indent, ok := entryIndent(prefix, element)
	if !ok {
		return Span{}, refuse(ReasonSpanNotIsolated, "the entry does not start its own line")
	}
	zeroSequence := !element && found.node.Kind == yaml.SequenceNode && found.node.Style&yaml.FlowStyle == 0 &&
		len(found.node.Content) > 0 && found.node.Content[0].Line > found.key.Line &&
		f.lineIndent(found.node.Content[0].Line-1) == indent
	last := lineIndex
scan:
	for i := lineIndex + 1; i < len(f.lineStarts); i++ {
		text := f.lineText(i)
		trimmed := bytes.TrimLeft(text, " \t")
		if len(trimmed) == 0 {
			continue
		}
		lead := text[:len(text)-len(trimmed)]
		if bytes.IndexByte(lead, '\t') >= 0 {
			return Span{}, refuse(ReasonSpanNotIsolated, "a tab is used for indentation")
		}
		switch {
		case len(lead) > indent:
		case len(lead) == indent && zeroSequence && trimmed[0] == '-' && (len(trimmed) == 1 || trimmed[1] == ' '):
		default:
			break scan
		}
		last = i
	}
	endLine := last + 1 // the 1-based number of the last line; also the 0-based index of the next line
	// The scan is a guess; these checks keep it honest. Every token of the
	// entry must lie on its lines, and no other token may.
	inside := map[*yaml.Node]bool{}
	var collect func(node *yaml.Node)
	collect = func(node *yaml.Node) {
		inside[node] = true
		for _, child := range node.Content {
			collect(child)
		}
	}
	collect(first)
	if !element {
		collect(found.node)
	}
	for node := range inside {
		if node.Kind != yaml.ScalarNode || node.Value == "" && node.Style == 0 {
			continue // collections, and implicit empty values whose position is not meaningful
		}
		if node.Line < first.Line || node.Line > endLine {
			return Span{}, refuse(ReasonSpanNotIsolated, "a token of the entry lies outside its lines")
		}
		// A plain or quoted scalar that continues on the next line has an end
		// that the scan cannot see (its text may look like indentation or a
		// comment), so it is refused. Block scalars end by indentation and
		// are fine.
		if node.Style&(yaml.LiteralStyle|yaml.FoldedStyle) == 0 {
			at, ok := f.offset(node.Line, node.Column)
			if !ok {
				return Span{}, refuse(ReasonSpanNotIsolated, "the position of a token of the entry is outside the file")
			}
			if _, r := scanToken(f.src, at, node); r != nil {
				return Span{}, r
			}
		}
	}
	// What follows the entry must be a new construct: a token on its own
	// line, a document marker or the end of the file, not a stray piece of a
	// value.
	if r := f.checkEntryEnd(endLine); r != nil {
		return Span{}, r
	}
	for _, doc := range f.docs {
		var foreign bool
		var walk func(node *yaml.Node)
		walk = func(node *yaml.Node) {
			if !inside[node] && node.Kind == yaml.ScalarNode && node.Line >= first.Line && node.Line <= endLine &&
				!(node.Value == "" && node.Style == 0) {
				foreign = true
			}
			for _, child := range node.Content {
				walk(child)
			}
		}
		walk(doc.root)
		if foreign {
			return Span{}, refuse(ReasonSpanNotIsolated, "another token shares a line with the entry")
		}
	}
	start := f.lineStarts[lineIndex]
	end := len(f.src)
	if endLine < len(f.lineStarts) {
		end = f.lineStarts[endLine]
	}
	return Span{Start: start, End: end}, nil
}

// checkEntryEnd requires the first line after the entry, past blank and
// comment lines, to start a token of the document, to be a document marker,
// or not to exist. next is the 0-based index of the line after the entry.
func (f *parsedFile) checkEntryEnd(next int) *Refusal {
	for i := next; i < len(f.lineStarts); i++ {
		text := f.lineText(i)
		trimmed := bytes.TrimLeft(text, " \t")
		if len(trimmed) == 0 || trimmed[0] == '#' {
			continue
		}
		if len(text) >= 3 && (string(text[:3]) == "---" || string(text[:3]) == "...") && (len(text) == 3 || text[3] == ' ' || text[3] == '\t') {
			return nil
		}
		for _, doc := range f.docs {
			var starts bool
			var walk func(node *yaml.Node)
			walk = func(node *yaml.Node) {
				if node.Line == i+1 && !(node.Kind == yaml.ScalarNode && node.Value == "" && node.Style == 0) {
					starts = true
				}
				for _, child := range node.Content {
					walk(child)
				}
			}
			walk(doc.root)
			if starts {
				return nil
			}
		}
		return refuse(ReasonSpanNotIsolated, "what follows the entry is not the start of another entry")
	}
	return nil
}

// entryIndent returns the indentation of an entry from the bytes before its
// first token on the line.
func entryIndent(prefix []byte, element bool) (int, bool) {
	spaces := 0
	for spaces < len(prefix) && prefix[spaces] == ' ' {
		spaces++
	}
	if !element {
		return spaces, spaces == len(prefix)
	}
	rest := prefix[spaces:]
	if len(rest) < 2 || rest[0] != '-' {
		return 0, false
	}
	for _, b := range rest[1:] {
		if b != ' ' {
			return 0, false
		}
	}
	return spaces, true
}

// lineText returns line i (0-based) without its line break.
func (f *parsedFile) lineText(i int) []byte {
	end := len(f.src)
	if i+1 < len(f.lineStarts) {
		end = f.lineStarts[i+1]
	}
	text := f.src[f.lineStarts[i]:end]
	text = bytes.TrimSuffix(text, []byte("\n"))
	return bytes.TrimSuffix(text, []byte("\r"))
}

// lineIndent counts the leading spaces of line i (0-based).
func (f *parsedFile) lineIndent(i int) int {
	text := f.lineText(i)
	return len(text) - len(bytes.TrimLeft(text, " "))
}
