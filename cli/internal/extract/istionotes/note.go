// SPDX-License-Identifier: AGPL-3.0-only

package istionotes

import (
	"bytes"
	"errors"
	"fmt"
	"io"

	"gopkg.in/yaml.v3"
)

// text is one string scalar of a note with the line it starts on.
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

// scalar accepts one string or integer scalar (issue references).
type scalar struct{}

func (*scalar) UnmarshalYAML(n *yaml.Node) error {
	if n.Kind != yaml.ScalarNode || (n.Tag != "!!str" && n.Tag != "!!int") {
		return errors.New("expected a string or integer")
	}
	return nil
}

type upgradeNote struct {
	Title   text `yaml:"title"`
	Content text `yaml:"content"`
}

// note is the closed shape of an Istio release note fragment. Unknown
// fields fail the decode.
type note struct {
	APIVersion    string        `yaml:"apiVersion"`
	Kind          string        `yaml:"kind"`
	Area          string        `yaml:"area"`
	Issue         []scalar      `yaml:"issue"`
	ReleaseNotes  []text        `yaml:"releaseNotes"`
	UpgradeNotes  []upgradeNote `yaml:"upgradeNotes"`
	Docs          []text        `yaml:"docs"`
	SecurityNotes []text        `yaml:"securityNotes"`
}

// decodeNote parses exactly one YAML document strictly: unknown fields,
// duplicate keys, aliases, anchors, merge keys, explicit tags and trailing
// documents are all refused.
func decodeNote(data []byte) (*note, error) {
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
	var n note
	d := yaml.NewDecoder(bytes.NewReader(data))
	d.KnownFields(true)
	if err := d.Decode(&n); err != nil {
		return nil, err
	}
	return &n, nil
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
