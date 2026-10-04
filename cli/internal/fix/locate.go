// SPDX-License-Identifier: AGPL-3.0-only

package fix

import (
	"bytes"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"
)

// MaxPathSegments bounds a Path.
const MaxPathSegments = 32

// Segment is one step of a Path: a mapping key or a sequence index.
type Segment struct {
	key     string
	index   int
	isIndex bool
}

// Key is a path step into a mapping.
func Key(key string) Segment { return Segment{key: key} }

// Index is a path step into a sequence.
func Index(index int) Segment { return Segment{index: index, isIndex: true} }

// Path addresses one node inside a document from its root. It has no
// wildcards.
type Path []Segment

// Part says which token of the addressed node a span covers.
type Part int

const (
	// PartValue is the scalar value at the path.
	PartValue Part = iota
	// PartKey is the mapping key token of the last path segment.
	PartKey
)

// Span is a byte range [Start, End) of the source.
type Span struct {
	Start, End int
}

// Edit returns the edit that replaces this span of file.
func (s Span) Edit(file, replacement string) Edit {
	return Edit{File: file, StartByte: s.Start, EndByte: s.End, Replacement: replacement}
}

// Locator finds the byte spans of key and scalar tokens in one file.
type Locator struct {
	file *parsedFile
}

var lastLocator struct {
	sync.Mutex
	digest string
	file   *parsedFile
}

// NewLocator decodes src with the file-level checks of this package. The most
// recent decode is reused when the same bytes are located again.
func NewLocator(src []byte) (*Locator, error) {
	digest := digestOf(src)
	lastLocator.Lock()
	if lastLocator.file != nil && lastLocator.digest == digest && bytes.Equal(lastLocator.file.src, src) {
		file := lastLocator.file
		lastLocator.Unlock()
		return &Locator{file: file}, nil
	}
	lastLocator.Unlock()
	file, r := parseFile(bytes.Clone(src))
	if r != nil {
		return nil, r
	}
	lastLocator.Lock()
	lastLocator.digest, lastLocator.file = digest, file
	lastLocator.Unlock()
	return &Locator{file: file}, nil
}

// Locate returns the span of one token; see Locator.Locate.
func Locate(src []byte, document int, path Path, part Part) (Span, error) {
	locator, err := NewLocator(src)
	if err != nil {
		return Span{}, err
	}
	return locator.Locate(document, path, part)
}

// Locate returns the exact byte span of the key token (PartKey) or scalar
// value token (PartValue) at path in the document with the given index
// among the non-empty documents. Quoted spans include their quotes. Block
// scalars, multi-line scalars, tagged or empty scalars, collections and
// tokens whose bytes cannot be isolated are refused.
func (l *Locator) Locate(document int, path Path, part Part) (Span, error) {
	found, r := l.file.resolve(document, path, part)
	if r != nil {
		return Span{}, r
	}
	span, r := l.file.tokenSpan(found.node, part)
	if r != nil {
		return Span{}, r
	}
	return span, nil
}

// resolved is the node a path leads to and the nodes around it.
type resolved struct {
	// node is the key token (PartKey) or the value or item the path ends in.
	node *yaml.Node
	// key is the key node of the last segment, nil for a sequence item.
	key *yaml.Node
	// parent is the mapping or sequence that holds the last segment.
	parent *yaml.Node
	// flow reports a flow-style collection on the way, parent included.
	flow bool
}

// resolve follows path in the document with the given index.
func (f *parsedFile) resolve(document int, path Path, part Part) (resolved, *Refusal) {
	if len(path) > MaxPathSegments {
		return resolved{}, refuse(ReasonLimit, "the path has too many segments")
	}
	if document < 0 || document >= len(f.docs) {
		return resolved{}, refuse(ReasonPathNotFound, "the document does not exist")
	}
	doc := f.docs[document]
	if doc.secret {
		return resolved{}, refuse(ReasonSecretDocument, "Secret documents are never edited")
	}
	if part == PartKey && (len(path) == 0 || path[len(path)-1].isIndex) {
		return resolved{}, refuse(ReasonPathNotFound, "a key target needs a path ending in a key")
	}
	out := resolved{node: doc.root}
	node := doc.root
	for i, segment := range path {
		if node.Style&yaml.FlowStyle != 0 {
			out.flow = true
		}
		out.parent, out.key = node, nil
		switch {
		case node.Kind == yaml.MappingNode && !segment.isIndex:
			var keyNode, valueNode *yaml.Node
			for j := 0; j+1 < len(node.Content); j += 2 {
				if node.Content[j].Value == segment.key {
					keyNode, valueNode = node.Content[j], node.Content[j+1]
					break
				}
			}
			if keyNode == nil {
				return resolved{}, refuse(ReasonPathNotFound, "the path does not exist in the document")
			}
			out.key = keyNode
			if i == len(path)-1 && part == PartKey {
				node = keyNode
			} else {
				node = valueNode
			}
		case node.Kind == yaml.SequenceNode && segment.isIndex:
			if segment.index < 0 || segment.index >= len(node.Content) {
				return resolved{}, refuse(ReasonPathNotFound, "the path does not exist in the document")
			}
			node = node.Content[segment.index]
		default:
			return resolved{}, refuse(ReasonPathNotFound, "the path does not exist in the document")
		}
	}
	out.node = node
	return out, nil
}

// tokenSpan finds the bytes of one scalar token from its decoder position
// and proves them: plain tokens must equal the decoded text, quoted tokens
// must decode on their own to the same text, and the bytes after the token
// must end it.
func (f *parsedFile) tokenSpan(node *yaml.Node, part Part) (Span, *Refusal) {
	if node.Kind != yaml.ScalarNode {
		return Span{}, refuse(ReasonSpanNotIsolated, "the target is a collection, not a scalar")
	}
	if node.Style&(yaml.LiteralStyle|yaml.FoldedStyle) != 0 {
		return Span{}, refuse(ReasonBlockScalar, "the target is a block scalar")
	}
	if node.Style&yaml.TaggedStyle != 0 || node.Anchor != "" {
		return Span{}, refuse(ReasonSpanNotIsolated, "the target carries a tag or anchor")
	}
	start, ok := f.offset(node.Line, node.Column)
	if !ok {
		return Span{}, refuse(ReasonSpanNotIsolated, "the target position is outside the file")
	}
	end, r := scanToken(f.src, start, node)
	if r != nil {
		return Span{}, r
	}
	rest := end
	for rest < len(f.src) && (f.src[rest] == ' ' || f.src[rest] == '\t') {
		rest++
	}
	if part == PartKey {
		if rest >= len(f.src) || f.src[rest] != ':' {
			return Span{}, refuse(ReasonSpanNotIsolated, "the key token is not followed by a colon")
		}
		return Span{Start: start, End: end}, nil
	}
	if end < len(f.src) {
		switch f.src[end] {
		case ' ', '\t', '\r', '\n', ',', ']', '}':
		default:
			return Span{}, refuse(ReasonSpanNotIsolated, "the token end cannot be isolated")
		}
	}
	return Span{Start: start, End: end}, nil
}

// scanToken returns the end of the scalar token that starts at start.
func scanToken(src []byte, start int, node *yaml.Node) (int, *Refusal) {
	if start >= len(src) {
		return 0, refuse(ReasonSpanNotIsolated, "the target position is outside the file")
	}
	switch {
	case node.Style&yaml.DoubleQuotedStyle != 0:
		if src[start] != '"' {
			return 0, refuse(ReasonSpanNotIsolated, "the quoted token does not start at its position")
		}
		for i := start + 1; i < len(src); i++ {
			switch src[i] {
			case '\\':
				if i+1 >= len(src) || src[i+1] == '\n' || src[i+1] == '\r' {
					return 0, refuse(ReasonMultiLineScalar, "the quoted scalar continues on the next line")
				}
				i++
			case '\n', '\r':
				return 0, refuse(ReasonMultiLineScalar, "the quoted scalar continues on the next line")
			case '"':
				return quotedEnd(src, start, i+1, node)
			}
		}
		return 0, refuse(ReasonSpanNotIsolated, "the quoted token is not closed")
	case node.Style&yaml.SingleQuotedStyle != 0:
		if src[start] != '\'' {
			return 0, refuse(ReasonSpanNotIsolated, "the quoted token does not start at its position")
		}
		for i := start + 1; i < len(src); i++ {
			switch src[i] {
			case '\n', '\r':
				return 0, refuse(ReasonMultiLineScalar, "the quoted scalar continues on the next line")
			case '\'':
				if i+1 < len(src) && src[i+1] == '\'' {
					i++
					continue
				}
				return quotedEnd(src, start, i+1, node)
			}
		}
		return 0, refuse(ReasonSpanNotIsolated, "the quoted token is not closed")
	case node.Style&^yaml.FlowStyle != 0:
		return 0, refuse(ReasonSpanNotIsolated, "the scalar style is not supported")
	}
	value := node.Value
	if value == "" {
		return 0, refuse(ReasonSpanNotIsolated, "the target is an implicit empty value")
	}
	if strings.ContainsAny(value, "\n\r") {
		return 0, refuse(ReasonMultiLineScalar, "the plain scalar spans more than one line")
	}
	end := start + len(value)
	if end > len(src) || string(src[start:end]) != value {
		if end <= len(src) && bytes.ContainsAny(src[start:end], "\n\r") {
			return 0, refuse(ReasonMultiLineScalar, "the plain scalar spans more than one line")
		}
		return 0, refuse(ReasonSpanNotIsolated, "the plain token does not match its decoded text")
	}
	return end, nil
}

// quotedEnd proves a quoted token by decoding it on its own.
func quotedEnd(src []byte, start, end int, node *yaml.Node) (int, *Refusal) {
	alone, ok := decodeLoneScalar(src[start:end])
	if !ok || alone.Value != node.Value || alone.Style != node.Style&^yaml.FlowStyle {
		return 0, refuse(ReasonSpanNotIsolated, "the quoted token does not decode to its value")
	}
	return end, nil
}

// decodeLoneScalar decodes token as a whole YAML stream that must hold
// exactly one document with a scalar root and nothing else.
func decodeLoneScalar(token []byte) (*yaml.Node, bool) {
	decoder := yaml.NewDecoder(bytes.NewReader(token))
	var document yaml.Node
	if err := decoder.Decode(&document); err != nil {
		return nil, false
	}
	var extra yaml.Node
	if err := decoder.Decode(&extra); err == nil {
		return nil, false
	}
	if document.Kind != yaml.DocumentNode || len(document.Content) != 1 {
		return nil, false
	}
	root := document.Content[0]
	if root.Kind != yaml.ScalarNode || root.Anchor != "" || root.Style&yaml.TaggedStyle != 0 {
		return nil, false
	}
	return root, true
}
