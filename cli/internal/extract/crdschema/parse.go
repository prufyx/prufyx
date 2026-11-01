// SPDX-License-Identifier: AGPL-3.0-only

package crdschema

import (
	"bytes"
	"errors"
	"io"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/prufyx/prufyx/cli/internal/extract/membercode"
)

// fault is a withheld item before it is attributed to a subject. key is the
// "group\x00Kind" identity when the document got far enough to have one.
type fault struct {
	reason string
	file   string
	key    string
}

type crdDoc struct {
	file     string
	group    string
	kind     string
	webhook  bool
	versions []*verDoc
}

type verDoc struct {
	name   string
	served bool
	tree   *tree // nil when the version has no readable schema
}

func (c *crdDoc) key() string { return c.group + "\x00" + c.kind }

// parseGuards are the strictness switches the mutation tests turn off.
type parseGuards struct {
	strict  bool // duplicate keys, anchors, aliases, merge keys, custom tags
	secret  bool
	nonCRD  bool
	limits  bool
	unmodel bool
	// quotedFlow accepts quoted scalars inside flow collections when the
	// source text proves them simple (see quotedSimple); quotedProof is that
	// proof. With quotedFlow off every quoted flow scalar is refused; with
	// quotedProof off every one is accepted (tests only).
	quotedFlow  bool
	quotedProof bool
	// kustomize skips a provable kustomize file in a listed directory;
	// kustomizeProof is the proof (see isKustomizeFile). With the proof off
	// any file with a kustomize name is skipped (tests only).
	kustomize      bool
	kustomizeProof bool
}

var errUnproven = errors.New("unproven")
var errTooLarge = errors.New("too large")

// parseFile decodes one file into CRD documents. Anything it cannot prove
// withholds the whole file: a later broken document could be anything, so no
// earlier document of the file is trusted either. No decoder error text is
// kept, because it can quote document content.
func parseFile(file string, data []byte, g parseGuards) (docs []*crdDoc, faults []fault) {
	if g.limits && len(data) > maxFileBytes {
		return nil, []fault{{reason: ReasonTooLarge, file: file}}
	}
	defer func() {
		if recover() != nil {
			docs, faults = nil, []fault{{reason: ReasonParseUnproven, file: file}}
		}
	}()
	dec := yaml.NewDecoder(bytes.NewReader(data))
	var roots []*yaml.Node
	for {
		var n yaml.Node
		err := dec.Decode(&n)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, []fault{{reason: ReasonParseUnproven, file: file}}
		}
		if g.limits && len(roots) >= maxDocuments {
			return nil, []fault{{reason: ReasonTooLarge, file: file}}
		}
		root := &n
		if n.Kind == yaml.DocumentNode {
			if len(n.Content) != 1 {
				return nil, []fault{{reason: ReasonParseUnproven, file: file}}
			}
			root = n.Content[0]
		}
		if root.Kind == yaml.ScalarNode && root.Tag == "!!null" {
			continue // an empty document carries nothing
		}
		roots = append(roots, root)
	}
	seen := map[string]bool{}
	for _, root := range roots {
		doc, f := parseDoc(file, root, g, data)
		if f != nil {
			faults = append(faults, *f)
			continue
		}
		if seen[doc.key()] {
			faults = append(faults, fault{reason: ReasonParseUnproven, file: file, key: doc.key()})
			continue
		}
		seen[doc.key()] = true
		docs = append(docs, doc)
	}
	if len(faults) > 0 {
		// One unproven document makes the file's other documents untrusted.
		for i := range faults {
			faults[i].file = file
		}
		return nil, faults
	}
	if len(docs) == 0 {
		return nil, []fault{{reason: ReasonParseUnproven, file: file}}
	}
	return docs, nil
}

func mget(m *yaml.Node, key string) *yaml.Node {
	if m == nil || m.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			return m.Content[i+1]
		}
	}
	return nil
}

func isStr(n *yaml.Node) bool { return n != nil && n.Kind == yaml.ScalarNode && n.Tag == "!!str" }

func boolOf(n *yaml.Node) (v, ok bool) {
	if n == nil || n.Kind != yaml.ScalarNode || n.Tag != "!!bool" {
		return false, false
	}
	switch n.Value {
	case "true":
		return true, true
	case "false":
		return false, true
	}
	return false, false
}

func parseDoc(file string, root *yaml.Node, g parseGuards, src []byte) (*crdDoc, *fault) {
	f := func(reason string) (*crdDoc, *fault) { return nil, &fault{reason: reason, file: file} }
	if root.Kind != yaml.MappingNode {
		if g.nonCRD {
			return f(ReasonNonCRD)
		}
	} else {
		for i := 0; i+1 < len(root.Content); i += 2 {
			if root.Content[i].Value != "kind" || root.Content[i+1].Kind != yaml.ScalarNode {
				continue
			}
			k := root.Content[i+1].Value
			if g.secret && strings.Contains(strings.ToLower(k), "secret") {
				return f(ReasonSecret)
			}
			if g.nonCRD && k != "CustomResourceDefinition" {
				return f(ReasonNonCRD)
			}
		}
		if g.nonCRD && !isStr(mget(root, "kind")) {
			return f(ReasonNonCRD)
		}
	}
	if err := checkYAML(root, g, src); err != nil {
		if errors.Is(err, errTooLarge) {
			return f(ReasonTooLarge)
		}
		return f(ReasonParseUnproven)
	}
	if root.Kind != yaml.MappingNode {
		return f(ReasonParseUnproven)
	}
	if v := mget(root, "apiVersion"); !isStr(v) || v.Value != "apiextensions.k8s.io/v1" {
		return f(ReasonParseUnproven)
	}
	spec := mget(root, "spec")
	group, kind := mget(spec, "group"), mget(mget(spec, "names"), "kind")
	if !isStr(group) || !isStr(kind) {
		return f(ReasonParseUnproven)
	}
	doc := &crdDoc{file: file, group: group.Value, kind: kind.Value}
	fail := func(reason string) (*crdDoc, *fault) {
		return nil, &fault{reason: reason, file: file, key: doc.key()}
	}
	if conv := mget(spec, "conversion"); conv != nil {
		s := mget(conv, "strategy")
		switch {
		case isStr(s) && s.Value == "None":
		case isStr(s) && s.Value == "Webhook":
			doc.webhook = true
		default:
			return fail(ReasonParseUnproven)
		}
	}
	vers := mget(spec, "versions")
	if vers == nil || vers.Kind != yaml.SequenceNode || len(vers.Content) == 0 {
		return fail(ReasonParseUnproven)
	}
	names := map[string]bool{}
	for _, v := range vers.Content {
		name := mget(v, "name")
		served, okServed := boolOf(mget(v, "served"))
		if !isStr(name) || !okServed || names[name.Value] {
			return fail(ReasonParseUnproven)
		}
		names[name.Value] = true
		vd := &verDoc{name: name.Value, served: served}
		schema := mget(mget(v, "schema"), "openAPIV3Schema")
		if served && schema == nil {
			return fail(ReasonParseUnproven)
		}
		if schema != nil {
			t, err := buildTree(schema, g)
			switch {
			case err == nil:
				vd.tree = t
			case served && errors.Is(err, errTooLarge):
				return fail(ReasonTooLarge)
			case served:
				return fail(ReasonParseUnproven)
			}
			// An unserved version that cannot be modelled is never read.
		}
		doc.versions = append(doc.versions, vd)
	}
	return doc, nil
}

// checkYAML refuses any construct whose meaning the extractor cannot fix
// from the bytes alone.
func checkYAML(root *yaml.Node, g parseGuards, src []byte) error {
	count := 0
	var lines [][]byte
	var walk func(n *yaml.Node, depth int, inFlow bool) error
	walk = func(n *yaml.Node, depth int, inFlow bool) error {
		count++
		if g.limits && (count > maxYAMLNodes || depth > maxYAMLDepth) {
			return errTooLarge
		}
		inFlow = inFlow || (n.Kind != yaml.ScalarNode && n.Style&yaml.FlowStyle != 0)
		if g.strict && inFlow && n.Kind == yaml.ScalarNode {
			switch {
			case n.Style&(yaml.LiteralStyle|yaml.FoldedStyle) != 0:
				return errUnproven
			case n.Style&(yaml.DoubleQuotedStyle|yaml.SingleQuotedStyle) != 0:
				// A flow collection holds plain scalars, and quoted ones only
				// when the source text shows a plain string.
				if !g.quotedFlow {
					return errUnproven
				}
				if g.quotedProof {
					if lines == nil {
						lines = bytes.Split(src, []byte("\n"))
					}
					if !quotedSimple(n, lines) {
						return errUnproven
					}
				}
			}
		}
		if g.strict {
			if n.Kind == yaml.AliasNode || n.Anchor != "" || n.Style&yaml.TaggedStyle != 0 {
				return errUnproven
			}
			switch n.Kind {
			case yaml.ScalarNode:
				switch n.Tag {
				case "!!str", "!!int", "!!float", "!!bool", "!!null":
				default:
					return errUnproven
				}
			case yaml.MappingNode:
				if n.Tag != "!!map" || len(n.Content)%2 != 0 {
					return errUnproven
				}
			case yaml.SequenceNode:
				if n.Tag != "!!seq" {
					return errUnproven
				}
			default:
				return errUnproven
			}
		}
		if n.Kind == yaml.MappingNode {
			keys := make(map[string]bool, len(n.Content)/2)
			for i := 0; i+1 < len(n.Content); i += 2 {
				k := n.Content[i]
				if g.strict {
					if k.Kind != yaml.ScalarNode || k.Tag != "!!str" || keys[k.Value] {
						return errUnproven
					}
				}
				keys[k.Value] = true
			}
		}
		for _, c := range n.Content {
			if err := walk(c, depth+1, inFlow); err != nil {
				return err
			}
		}
		return nil
	}
	return walk(root, 0, false)
}

// tree is the flattened schema of one served version.
type tree struct {
	nodes map[string]*pnode
}

type pnode struct {
	segs     []membercode.Seg
	preserve bool // x-kubernetes-preserve-unknown-fields, embedded resource, free-form additionalProperties
	unmodel  bool // a keyword the extractor does not model
	ancP     bool // some strict ancestor preserves
	ancU     bool // some strict ancestor is unmodelled
	enum     enumInfo
}

type enumInfo struct {
	present   bool
	nonString bool
	vals      map[string]bool
	raw       map[string]bool // every entry as tag and scalar text
}

func (n *pnode) chainPreserve() bool { return n.preserve || n.ancP }
func (n *pnode) chainUnmodel() bool  { return n.unmodel || n.ancU }

func segKey(segs []membercode.Seg) string {
	var b strings.Builder
	for _, s := range segs {
		switch s.Kind {
		case membercode.Item:
			b.WriteString("i;")
		case membercode.Any:
			b.WriteString("a;")
		default:
			b.WriteString("p")
			b.WriteString(itoa(len(s.Name)))
			b.WriteString(":")
			b.WriteString(s.Name)
			b.WriteString(";")
		}
	}
	return b.String()
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var d [20]byte
	i := len(d)
	for n > 0 {
		i--
		d[i] = byte('0' + n%10)
		n /= 10
	}
	return string(d[i:])
}

// modelled schema keywords. Every other keyword (allOf, anyOf, oneOf, not,
// $ref, unknown extensions, ...) marks the node and everything below it as
// not decidable.
var modelled = map[string]bool{
	"type": true, "properties": true, "items": true, "additionalProperties": true, "enum": true,
	"required": true, "description": true, "default": true, "format": true, "nullable": true,
	"title": true, "example": true, "pattern": true, "minimum": true, "maximum": true,
	"exclusiveMinimum": true, "exclusiveMaximum": true, "minLength": true, "maxLength": true,
	"minItems": true, "maxItems": true, "minProperties": true, "maxProperties": true,
	"multipleOf": true, "uniqueItems": true,
	"x-kubernetes-list-type": true, "x-kubernetes-list-map-keys": true, "x-kubernetes-map-type": true,
	"x-kubernetes-int-or-string": true, "x-kubernetes-preserve-unknown-fields": true,
	"x-kubernetes-embedded-resource": true, "x-kubernetes-validations": true,
}

func buildTree(schema *yaml.Node, g parseGuards) (*tree, error) {
	t := &tree{nodes: map[string]*pnode{}}
	var walk func(n *yaml.Node, segs []membercode.Seg, ancP, ancU bool) error
	walk = func(n *yaml.Node, segs []membercode.Seg, ancP, ancU bool) error {
		if n.Kind != yaml.MappingNode {
			return errUnproven
		}
		if g.limits && (len(t.nodes) >= maxSchemaNodes || len(segs) > maxSchemaDepth) {
			return errTooLarge
		}
		pn := &pnode{segs: segs, ancP: ancP, ancU: ancU}
		t.nodes[segKey(segs)] = pn
		var props, items, addl *yaml.Node
		for i := 0; i+1 < len(n.Content); i += 2 {
			k, v := n.Content[i].Value, n.Content[i+1]
			if g.unmodel && !modelled[k] {
				pn.unmodel = true
			}
			switch k {
			case "properties":
				if v.Kind != yaml.MappingNode {
					return errUnproven
				}
				props = v
			case "items":
				if v.Kind != yaml.MappingNode {
					return errUnproven // tuple form
				}
				items = v
			case "additionalProperties":
				switch {
				case v.Kind == yaml.MappingNode:
					addl = v
				case v.Kind == yaml.ScalarNode:
					b, ok := boolOf(v)
					if !ok {
						return errUnproven
					}
					if b {
						pn.preserve = true
					}
				default:
					return errUnproven
				}
			case "x-kubernetes-preserve-unknown-fields", "x-kubernetes-embedded-resource":
				b, ok := boolOf(v)
				if !ok {
					return errUnproven
				}
				if b {
					pn.preserve = true
				}
			case "enum":
				if v.Kind != yaml.SequenceNode {
					return errUnproven
				}
				pn.enum = enumInfo{present: true, vals: map[string]bool{}, raw: map[string]bool{}}
				for _, e := range v.Content {
					pn.enum.raw[e.Tag+"\x00"+e.Value] = true
					if !isStr(e) {
						pn.enum.nonString = true
						continue
					}
					pn.enum.vals[e.Value] = true
				}
			}
		}
		cp, cu := ancP || pn.preserve, ancU || pn.unmodel
		child := func(seg membercode.Seg, c *yaml.Node) error {
			next := append(append([]membercode.Seg(nil), segs...), seg)
			return walk(c, next, cp, cu)
		}
		if props != nil {
			for i := 0; i+1 < len(props.Content); i += 2 {
				if err := child(membercode.Seg{Kind: membercode.Prop, Name: props.Content[i].Value}, props.Content[i+1]); err != nil {
					return err
				}
			}
		}
		if items != nil {
			if err := child(membercode.Seg{Kind: membercode.Item}, items); err != nil {
				return err
			}
		}
		if addl != nil {
			if err := child(membercode.Seg{Kind: membercode.Any}, addl); err != nil {
				return err
			}
		}
		return nil
	}
	if err := walk(schema, nil, false, false); err != nil {
		return nil, err
	}
	return t, nil
}

// quotedSimple proves, from the source line, that a quoted scalar is a plain
// one-line string: it is a string without a tag or anchor, the node starts at
// the opening quote, the closing quote is on the same line, no escape sequence
// ("\\" in a double-quoted scalar, a doubled quote in a single-quoted one) is
// used, and the text between the quotes is exactly the decoded value. Quoting
// fixes the type, so a value such as "true", "null" or "1e3" stays a string.
func quotedSimple(n *yaml.Node, lines [][]byte) bool {
	if n.Tag != "!!str" || n.Anchor != "" || n.Style&yaml.TaggedStyle != 0 || n.Line < 1 || n.Line > len(lines) || n.Column < 1 {
		return false
	}
	var q rune
	switch {
	case n.Style&yaml.DoubleQuotedStyle != 0 && n.Style&yaml.SingleQuotedStyle == 0:
		q = '"'
	case n.Style&yaml.SingleQuotedStyle != 0 && n.Style&yaml.DoubleQuotedStyle == 0:
		q = '\''
	default:
		return false
	}
	line := []rune(string(lines[n.Line-1]))
	start := n.Column - 1
	if start >= len(line) || line[start] != q {
		return false
	}
	for j := start + 1; j < len(line); j++ {
		switch {
		case q == '"' && line[j] == '\\':
			return false
		case line[j] == q:
			if q == '\'' && j+1 < len(line) && line[j+1] == '\'' {
				return false
			}
			return string(line[start+1:j]) == n.Value
		}
	}
	return false // no closing quote on the line: a multi-line scalar
}
