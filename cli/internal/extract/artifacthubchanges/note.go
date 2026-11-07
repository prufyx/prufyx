// SPDX-License-Identifier: AGPL-3.0-only

package artifacthubchanges

import (
	"bytes"
	"errors"
	"fmt"
	"io"

	"gopkg.in/yaml.v3"
)

// text is one string scalar with the line it starts on.
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

// skipped accepts any value of a Chart.yaml field the reader does not use.
// The node tree has already passed checkNode.
type skipped struct{}

func (*skipped) UnmarshalYAML(*yaml.Node) error { return nil }

// chart is the closed shape of a Chart.yaml (Helm chart API v2). Unknown
// fields fail the decode. Only apiVersion, name, version and annotations are
// read.
type chart struct {
	APIVersion   string          `yaml:"apiVersion"`
	Name         string          `yaml:"name"`
	Version      string          `yaml:"version"`
	KubeVersion  skipped         `yaml:"kubeVersion"`
	Description  skipped         `yaml:"description"`
	Type         skipped         `yaml:"type"`
	Keywords     skipped         `yaml:"keywords"`
	Home         skipped         `yaml:"home"`
	Sources      skipped         `yaml:"sources"`
	Dependencies skipped         `yaml:"dependencies"`
	Maintainers  skipped         `yaml:"maintainers"`
	Icon         skipped         `yaml:"icon"`
	AppVersion   skipped         `yaml:"appVersion"`
	Deprecated   skipped         `yaml:"deprecated"`
	Annotations  map[string]text `yaml:"annotations"`
}

// link is one reference of a change. It is validated for shape and never
// read further.
type link struct {
	Name text `yaml:"name"`
	URL  text `yaml:"url"`
}

// change is the closed shape of one entry of the artifacthub.io/changes
// annotation. Unknown fields fail the decode.
type change struct {
	Kind        text   `yaml:"kind"`
	Description text   `yaml:"description"`
	Links       []link `yaml:"links"`
}

// decodeStrict parses exactly one YAML document into out, strictly: unknown
// fields, duplicate keys, aliases, anchors, merge keys, explicit tags,
// excessive nesting and trailing documents are all refused.
func decodeStrict(data []byte, out any) error {
	var root yaml.Node
	dec := yaml.NewDecoder(bytes.NewReader(data))
	if err := dec.Decode(&root); err != nil {
		return err
	}
	var extra yaml.Node
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return errors.New("more than one document")
	}
	if err := checkNode(&root, 0); err != nil {
		return err
	}
	d := yaml.NewDecoder(bytes.NewReader(data))
	d.KnownFields(true)
	return d.Decode(out)
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
	if n.Style&yaml.TaggedStyle != 0 {
		return errors.New("explicit tag")
	}
	if n.Kind != yaml.DocumentNode && !allowedTags[n.Tag] {
		return fmt.Errorf("tag %q", n.Tag)
	}
	if n.Kind == yaml.MappingNode {
		keys := map[string]bool{}
		for i := 0; i+1 < len(n.Content); i += 2 {
			k := n.Content[i]
			if k.Kind != yaml.ScalarNode {
				return errors.New("non-scalar key")
			}
			if keys[k.Value] {
				return errors.New("duplicate key")
			}
			keys[k.Value] = true
		}
	}
	for _, c := range n.Content {
		if err := checkNode(c, depth+1); err != nil {
			return err
		}
	}
	return nil
}
