// SPDX-License-Identifier: AGPL-3.0-only

package crdversions

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/prufyx/prufyx/cli/internal/constraintengine"
	"github.com/prufyx/prufyx/cli/internal/extract"
	"github.com/prufyx/prufyx/cli/internal/intake"
)

// Bounds. A file, a tag or a CRD beyond them withholds the pair.
const (
	MaxFileBytes       = 4 << 20
	MaxCRDsPerTag      = 512
	MaxVersionsPerCRD  = 64
	crdAPIGroupPrefix  = "apiextensions.k8s.io/"
	crdAPIVersion      = "apiextensions.k8s.io/v1"
	crdKind            = "CustomResourceDefinition"
	templateMarker     = "{{"
	maxNameBytes       = 253
	maxVersionNameByte = 63
)

var (
	groupRE   = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)+$`)
	pluralRE  = regexp.MustCompile(`^[a-z]([-a-z0-9]*[a-z0-9])?$`)
	kindRE    = regexp.MustCompile(`^[A-Z][A-Za-z0-9]{0,62}$`)
	versionRE = regexp.MustCompile(`^[a-z]([-a-z0-9]{0,61}[a-z0-9])?$`)
)

// problem marks a reason to withhold a pair; any other error aborts the run.
type problem struct{ msg string }

func (p problem) Error() string { return p.msg }

func problemf(format string, args ...any) error { return problem{fmt.Sprintf(format, args...)} }

func asProblem(err error) (problem, bool) {
	var p problem
	if errors.As(err, &p) {
		return p, true
	}
	return problem{}, false
}

// CRDVersion is one entry of spec.versions. Lines are 1-based lines of the
// file: StartLine..EndLine is the whole entry, ServedLine and StorageLine the
// lines of its served and storage keys.
type CRDVersion struct {
	Name        string `json:"name"`
	Served      bool   `json:"served"`
	Storage     bool   `json:"storage"`
	StartLine   int    `json:"startLine"`
	EndLine     int    `json:"endLine"`
	ServedLine  int    `json:"servedLine"`
	StorageLine int    `json:"storageLine"`
}

// CRD is one parsed apiextensions.k8s.io/v1 CustomResourceDefinition.
type CRD struct {
	Name           string       `json:"name"`
	Group          string       `json:"group"`
	Kind           string       `json:"kind"`
	Plural         string       `json:"plural"`
	Scope          string       `json:"scope"`
	Path           string       `json:"path"`
	Document       int          `json:"document"`
	StartLine      int          `json:"startLine"`
	VersionsLine   int          `json:"versionsLine"`
	StorageVersion string       `json:"storageVersion"`
	Versions       []CRDVersion `json:"versions"`
}

// version returns the named version entry.
func (c *CRD) version(name string) (CRDVersion, bool) {
	for _, v := range c.Versions {
		if v.Name == name {
			return v, true
		}
	}
	return CRDVersion{}, false
}

// FileRecord is one file the inventory parsed.
type FileRecord struct {
	Path           string `json:"path"`
	SHA256         string `json:"sha256"`
	Size           int    `json:"size"`
	Lines          int    `json:"lines"`
	Documents      int    `json:"documents"`
	CRDs           int    `json:"crds"`
	OtherDocuments int    `json:"otherDocuments"`
}

// parseFile parses every document of one file. CRD documents are returned;
// other documents are counted. Any byte the strict decoder refuses, any
// template syntax and any CRD that is not a complete
// apiextensions.k8s.io/v1 definition is a problem.
func parseFile(path string, data []byte) (FileRecord, []CRD, error) {
	sum := sha256.Sum256(data)
	rec := FileRecord{Path: path, SHA256: "sha256:" + hex.EncodeToString(sum[:]), Size: len(data), Lines: extract.CountLines(data)}
	if len(data) > MaxFileBytes {
		return rec, nil, problemf("%s is %d bytes, over the %d-byte bound", path, len(data), MaxFileBytes)
	}
	if bytes.Contains(data, []byte(templateMarker)) {
		return rec, nil, problemf("%s contains template syntax (%q): it is not a rendered manifest", path, templateMarker)
	}
	values, err := intake.DecodeDocuments(data)
	if err != nil {
		return rec, nil, problemf("%s is not decodable within the strict YAML subset (anchors, aliases, tags, duplicate keys and oversized documents are refused)", path)
	}
	nodes, err := documentNodes(data)
	if err != nil || len(nodes) != len(values) {
		return rec, nil, problemf("%s: the document structure could not be read for line positions", path)
	}
	rec.Documents = len(values)
	lines := splitLines(data)
	var crds []CRD
	for i, v := range values {
		doc := i + 1
		obj, ok := v.(map[string]any)
		if !ok {
			return rec, nil, problemf("%s document %d is not a mapping", path, doc)
		}
		apiVersion, _ := obj["apiVersion"].(string)
		kind, _ := obj["kind"].(string)
		if kind == "List" || strings.HasSuffix(kind, "List") {
			return rec, nil, problemf("%s document %d is a %s: list items are not read", path, doc, kind)
		}
		if kind != crdKind {
			if strings.HasPrefix(apiVersion, crdAPIGroupPrefix) {
				return rec, nil, problemf("%s document %d has apiVersion %s and kind %q", path, doc, apiVersion, kind)
			}
			rec.OtherDocuments++
			continue
		}
		if apiVersion != crdAPIVersion {
			return rec, nil, problemf("%s document %d is a CustomResourceDefinition of apiVersion %q; only %s is read", path, doc, apiVersion, crdAPIVersion)
		}
		next := 0
		if i+1 < len(nodes) {
			next = nodes[i+1].Line
		}
		crd, err := parseCRD(path, doc, obj, nodes[i], next, lines)
		if err != nil {
			return rec, nil, err
		}
		crds = append(crds, crd)
	}
	rec.CRDs = len(crds)
	return rec, crds, nil
}

// documentNodes returns the root node of every non-empty document, skipping
// exactly what intake.DecodeDocuments skips.
func documentNodes(data []byte) ([]*yaml.Node, error) {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	var out []*yaml.Node
	for {
		var node yaml.Node
		err := dec.Decode(&node)
		if err == io.EOF {
			return out, nil
		}
		if err != nil {
			return nil, err
		}
		if node.Kind != yaml.DocumentNode || len(node.Content) != 1 {
			if node.Kind == yaml.DocumentNode && len(node.Content) == 0 {
				continue
			}
			return nil, errors.New("unexpected document")
		}
		root := node.Content[0]
		if root.Kind == yaml.ScalarNode && root.ShortTag() == "!!null" {
			continue
		}
		out = append(out, root)
	}
}

func splitLines(data []byte) []string {
	s := string(data)
	s = strings.TrimSuffix(s, "\n")
	if s == "" {
		return nil
	}
	return strings.Split(s, "\n")
}

func str(m map[string]any, key string) string {
	s, _ := m[key].(string)
	return s
}

func mapping(m map[string]any, key string) map[string]any {
	v, _ := m[key].(map[string]any)
	return v
}

// child returns the value node of key in a mapping node, and the key node.
func child(n *yaml.Node, key string) (*yaml.Node, *yaml.Node) {
	if n == nil || n.Kind != yaml.MappingNode {
		return nil, nil
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		if n.Content[i].Value == key {
			return n.Content[i+1], n.Content[i]
		}
	}
	return nil, nil
}

// following returns the line of the first node after key's value in the
// mapping n (the next key), or 0 when key is the last.
func following(n *yaml.Node, key string) int {
	for i := 0; i+1 < len(n.Content); i += 2 {
		if n.Content[i].Value == key && i+2 < len(n.Content) {
			return n.Content[i+2].Line
		}
	}
	return 0
}

func maxLine(n *yaml.Node) int {
	m := n.Line
	for _, c := range n.Content {
		m = max(m, maxLine(c))
	}
	return m
}

// trimEnd moves end back over blank lines, document markers and comment
// lines indented less than the entry's keys (keyIndent, 0-based), but never
// before floor. Lines indented at or beyond the keys may be the content of a
// block scalar, so they always stay in the span.
func trimEnd(lines []string, end, floor, keyIndent int) int {
	for end > floor && end >= 1 && end <= len(lines) {
		l := lines[end-1]
		t := strings.TrimSpace(l)
		indent := len(l) - len(strings.TrimLeft(l, " \t"))
		switch {
		case t == "":
		case (t == "---" || t == "...") && indent == 0:
		case strings.HasPrefix(t, "#") && indent < keyIndent:
		default:
			return end
		}
		end--
	}
	return end
}

func parseCRD(path string, doc int, obj map[string]any, root *yaml.Node, nextDoc int, lines []string) (CRD, error) {
	where := fmt.Sprintf("%s document %d", path, doc)
	meta, spec := mapping(obj, "metadata"), mapping(obj, "spec")
	if meta == nil || spec == nil {
		return CRD{}, problemf("%s: a CustomResourceDefinition without metadata or spec", where)
	}
	names := mapping(spec, "names")
	c := CRD{Name: str(meta, "name"), Group: str(spec, "group"), Kind: str(names, "kind"), Plural: str(names, "plural"), Scope: str(spec, "scope"), Path: path, Document: doc, StartLine: root.Line}
	switch {
	case len(c.Group) > maxNameBytes || !groupRE.MatchString(c.Group):
		return CRD{}, problemf("%s: spec.group %q is not a valid API group", where, c.Group)
	case !pluralRE.MatchString(c.Plural):
		return CRD{}, problemf("%s: spec.names.plural %q is not valid", where, c.Plural)
	case !kindRE.MatchString(c.Kind):
		return CRD{}, problemf("%s: spec.names.kind %q is not valid", where, c.Kind)
	case c.Name != c.Plural+"."+c.Group:
		return CRD{}, problemf("%s: metadata.name %q is not <plural>.<group>", where, c.Name)
	case c.Scope != "Namespaced" && c.Scope != "Cluster":
		return CRD{}, problemf("%s: spec.scope %q is not Namespaced or Cluster", where, c.Scope)
	}
	items, ok := spec["versions"].([]any)
	if !ok || len(items) == 0 {
		return CRD{}, problemf("%s: CustomResourceDefinition %s has no spec.versions list", where, c.Name)
	}
	if len(items) > MaxVersionsPerCRD {
		return CRD{}, problemf("%s: CustomResourceDefinition %s has %d versions, over the bound of %d", where, c.Name, len(items), MaxVersionsPerCRD)
	}
	specNode, _ := child(root, "spec")
	seqNode, seqKey := child(specNode, "versions")
	if seqNode == nil || seqNode.Kind != yaml.SequenceNode || len(seqNode.Content) != len(items) {
		return CRD{}, problemf("%s: spec.versions could not be located", where)
	}
	c.VersionsLine = seqKey.Line
	// The line after the last entry: the next key of spec, of the document,
	// or the next document.
	after := following(specNode, "versions")
	if after == 0 {
		after = following(root, "spec")
	}
	if after == 0 {
		after = nextDoc
	}
	if after == 0 {
		after = len(lines) + 1
	}
	seen := map[string]bool{}
	storage := 0
	for i, item := range items {
		vm, ok := item.(map[string]any)
		node := seqNode.Content[i]
		if !ok || node.Kind != yaml.MappingNode {
			return CRD{}, problemf("%s: spec.versions[%d] of %s is not a mapping", where, i, c.Name)
		}
		served, sok := vm["served"].(bool)
		stored, tok := vm["storage"].(bool)
		v := CRDVersion{Name: str(vm, "name"), Served: served, Storage: stored, StartLine: node.Line}
		if !versionRE.MatchString(v.Name) || len(v.Name) > maxVersionNameByte {
			return CRD{}, problemf("%s: spec.versions[%d] of %s has name %q, not a valid version name", where, i, c.Name, v.Name)
		}
		if !sok || !tok {
			return CRD{}, problemf("%s: version %s of %s does not state served and storage as booleans", where, v.Name, c.Name)
		}
		if nameNode, _ := child(node, "name"); nameNode == nil || nameNode.Value != v.Name {
			return CRD{}, problemf("%s: version %s of %s could not be located", where, v.Name, c.Name)
		}
		_, sk := child(node, "served")
		_, tk := child(node, "storage")
		v.ServedLine, v.StorageLine = sk.Line, tk.Line
		end := after - 1
		if i+1 < len(seqNode.Content) {
			end = seqNode.Content[i+1].Line - 1
		}
		last := maxLine(node)
		v.EndLine = max(trimEnd(lines, end, last, node.Column-1), last)
		if v.EndLine < v.StartLine || v.EndLine > len(lines) {
			return CRD{}, problemf("%s: version %s of %s spans lines %d-%d of %d", where, v.Name, c.Name, v.StartLine, v.EndLine, len(lines))
		}
		if seen[v.Name] {
			return CRD{}, problemf("%s: version %s of %s is listed twice", where, v.Name, c.Name)
		}
		seen[v.Name] = true
		if v.Storage {
			storage++
			c.StorageVersion = v.Name
		}
		if !constraintengine.ValidSetMember(member(c.Group, v.Name, c.Kind)) {
			return CRD{}, problemf("%s: %s is not representable as a set member", where, member(c.Group, v.Name, c.Kind))
		}
		c.Versions = append(c.Versions, v)
	}
	if storage != 1 {
		return CRD{}, problemf("%s: CustomResourceDefinition %s has %d storage versions, not exactly one", where, c.Name, storage)
	}
	return c, nil
}

// member is the set member naming one served custom-resource version.
func member(group, version, kind string) string { return group + "/" + version + "/" + kind }
