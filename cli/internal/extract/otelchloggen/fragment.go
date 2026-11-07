// SPDX-License-Identifier: AGPL-3.0-only

package otelchloggen

import (
	"bytes"
	"errors"
	"fmt"
	"io"

	"gopkg.in/yaml.v3"
)

// text is one string scalar of a fragment with the line it starts on.
type text struct {
	Value string
	Line  int
	// Block is true for a literal or folded block scalar, whose content
	// starts on the line after the indicator.
	Block bool
	// Literal is true for a literal block scalar: only then is the line
	// span of the value exact.
	Literal bool
}

func (t *text) UnmarshalYAML(n *yaml.Node) error {
	if n.Kind != yaml.ScalarNode || n.Tag != "!!str" {
		return errors.New("expected a string")
	}
	t.Value = n.Value
	t.Line = n.Line
	t.Block = n.Style&(yaml.LiteralStyle|yaml.FoldedStyle) != 0
	t.Literal = n.Style&yaml.LiteralStyle != 0
	return nil
}

// issueRef accepts one integer scalar (an issue or pull request number).
type issueRef struct{}

func (*issueRef) UnmarshalYAML(n *yaml.Node) error {
	if n.Kind != yaml.ScalarNode || n.Tag != "!!int" {
		return errors.New("expected an integer")
	}
	return nil
}

// fragment is the closed shape of a .chloggen entry. Unknown fields fail the
// decode.
type fragment struct {
	ChangeType string     `yaml:"change_type"`
	Component  string     `yaml:"component"`
	Note       text       `yaml:"note"`
	Issues     []issueRef `yaml:"issues"`
	Subtext    text       `yaml:"subtext"`
}

// decodeFragment parses exactly one YAML document strictly: unknown fields,
// duplicate keys, aliases, anchors, merge keys, explicit tags and trailing
// documents are all refused.
func decodeFragment(data []byte) (*fragment, error) {
	var root yaml.Node
	dec := yaml.NewDecoder(bytes.NewReader(data))
	if err := dec.Decode(&root); err != nil {
		return nil, err
	}
	var extra yaml.Node
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, errors.New("more than one document")
	}
	if err := checkNode(&root, 0); err != nil {
		return nil, err
	}
	var f fragment
	d := yaml.NewDecoder(bytes.NewReader(data))
	d.KnownFields(true)
	if err := d.Decode(&f); err != nil {
		return nil, err
	}
	return &f, nil
}

const maxDepth = 8

var allowedTags = map[string]bool{"!!map": true, "!!seq": true, "!!str": true, "!!int": true, "!!null": true, "!!bool": true, "!!float": true}

func checkNode(n *yaml.Node, depth int) error {
	if depth > maxDepth {
		return errors.New("nested too deep")
	}
	if n.Kind == yaml.AliasNode || n.Anchor != "" {
		return errors.New("alias or anchor")
	}
	if n.Kind != yaml.DocumentNode && !allowedTags[n.Tag] {
		return fmt.Errorf("tag %q", n.Tag)
	}
	for _, c := range n.Content {
		if err := checkNode(c, depth+1); err != nil {
			return err
		}
	}
	return nil
}
