// SPDX-License-Identifier: AGPL-3.0-only

package fix

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"unicode/utf8"

	"gopkg.in/yaml.v3"

	"github.com/prufyx/prufyx/cli/internal/intake"
)

// MaxFileBytes bounds one file, as the intake bounds one input file.
const MaxFileBytes = int(intake.DefaultFileBytes)

// parsedFile is one file decoded with node positions. It is never mutated
// after parseFile returns.
type parsedFile struct {
	src []byte
	// lineStarts holds the byte offset of each line; line n (1-based)
	// starts at lineStarts[n-1].
	lineStarts []int
	docs       []parsedDoc
}

type parsedDoc struct {
	root   *yaml.Node
	value  any
	secret bool
}

func digestOf(src []byte) string {
	sum := sha256.Sum256(src)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// parseFile applies every file-level check and decodes the documents the
// way the intake does: documents without content, and documents whose root
// is null, are skipped, so document indexes match intake.Source.Document.
func parseFile(src []byte) (*parsedFile, *Refusal) {
	if len(src) == 0 {
		return nil, refuse(ReasonUnsupportedYAML, "the file is empty")
	}
	if len(src) > MaxFileBytes {
		return nil, refuse(ReasonLimit, "the file is larger than the per-file limit")
	}
	if r := checkEncoding(src); r != nil {
		return nil, r
	}
	if bytes.Contains(src, []byte("{{")) || bytes.Contains(src, []byte("${")) {
		return nil, refuse(ReasonTemplated, "the file contains template syntax; edit the template source instead")
	}
	// The intake decoder is the reference for what is accepted: anything it
	// refuses is refused here too.
	if _, err := intake.Decode("", src); err != nil {
		if errors.Is(err, intake.ErrDecode) {
			return nil, refuse(ReasonUnsupportedYAML, "the file is outside the strict YAML subset")
		}
		return nil, refuse(ReasonLimit, "the file exceeds a decoding bound")
	}
	file := &parsedFile{src: src, lineStarts: lineStarts(src)}
	decoder := yaml.NewDecoder(bytes.NewReader(src))
	for {
		var node yaml.Node
		err := decoder.Decode(&node)
		if err == io.EOF {
			break
		}
		if err != nil || node.Kind != yaml.DocumentNode || len(node.Content) > 1 {
			return nil, refuse(ReasonUnsupportedYAML, "the file is outside the strict YAML subset")
		}
		if len(node.Content) == 0 {
			continue
		}
		root := node.Content[0]
		if root.Kind == yaml.ScalarNode && root.ShortTag() == "!!null" {
			continue
		}
		value, err := strictValue(root, 0)
		if err != nil {
			return nil, refuse(ReasonUnsupportedYAML, "the file is outside the strict YAML subset")
		}
		if len(file.docs) >= intake.MaxDocuments {
			return nil, refuse(ReasonLimit, "the file has too many documents")
		}
		file.docs = append(file.docs, parsedDoc{root: root, value: value, secret: holdsSecret(value)})
	}
	return file, nil
}

func (f *parsedFile) hasSecret() bool {
	for _, doc := range f.docs {
		if doc.secret {
			return true
		}
	}
	return false
}

// checkEncoding accepts valid UTF-8 with LF or CRLF line breaks and at most a
// leading byte order mark. Other line breaks (bare CR, NEL, LS, PS) and inner
// byte order marks change how positions are counted, so they are refused.
func checkEncoding(src []byte) *Refusal {
	if !utf8.Valid(src) {
		return refuse(ReasonUnsupportedEncoding, "the file is not valid UTF-8")
	}
	for i := 0; i < len(src); i++ {
		switch {
		case src[i] == '\r' && (i+1 == len(src) || src[i+1] != '\n'):
			return refuse(ReasonUnsupportedEncoding, "the file has a carriage return that does not end a CRLF line break")
		case src[i] == 0xC2 && i+1 < len(src) && src[i+1] == 0x85,
			src[i] == 0xE2 && i+2 < len(src) && src[i+1] == 0x80 && (src[i+2] == 0xA8 || src[i+2] == 0xA9):
			return refuse(ReasonUnsupportedEncoding, "the file has a Unicode line or paragraph separator")
		case src[i] == 0xEF && i > 0 && i+2 < len(src) && src[i+1] == 0xBB && src[i+2] == 0xBF:
			return refuse(ReasonUnsupportedEncoding, "the file has a byte order mark after its first byte")
		}
	}
	return nil
}

var bom = []byte{0xEF, 0xBB, 0xBF}

// lineStarts returns the byte offset where each line starts. The decoder
// strips a leading byte order mark before it counts columns, so the first
// line starts after it.
func lineStarts(src []byte) []int {
	starts := []int{0}
	if bytes.HasPrefix(src, bom) {
		starts[0] = len(bom)
	}
	for i, b := range src {
		if b == '\n' {
			starts = append(starts, i+1)
		}
	}
	return starts
}

// offset converts a 1-based decoder line and column to a byte offset. The
// decoder counts columns in characters, so the column is walked rune by rune
// and must stay on its line.
func (f *parsedFile) offset(line, column int) (int, bool) {
	if line < 1 || line > len(f.lineStarts) || column < 1 {
		return 0, false
	}
	at := f.lineStarts[line-1]
	for steps := column - 1; steps > 0; steps-- {
		if at >= len(f.src) || f.src[at] == '\n' || f.src[at] == '\r' {
			return 0, false
		}
		_, width := utf8.DecodeRune(f.src[at:])
		at += width
	}
	if at > len(f.src) {
		return 0, false
	}
	return at, true
}

// holdsSecret reports a Secret, a SecretList, or any list with a Secret item.
func holdsSecret(value any) bool {
	object, ok := value.(map[string]any)
	if !ok {
		return false
	}
	if kind, _ := object["kind"].(string); kind == "Secret" || kind == "SecretList" {
		return true
	}
	items, _ := object["items"].([]any)
	for _, item := range items {
		if entry, ok := item.(map[string]any); ok {
			if kind, _ := entry["kind"].(string); kind == "Secret" {
				return true
			}
		}
	}
	return false
}

var errStrict = errors.New("outside the strict YAML subset")

// strictValue converts a node to plain values with the manifest rules of the
// intake decoder: no anchors, aliases, merge keys or custom tags; string keys
// only, unique also when compared without case; untagged timestamps read as
// text; numbers kept as their written text.
func strictValue(node *yaml.Node, depth int) (any, error) {
	if depth > intake.MaxDepth || node == nil || node.Anchor != "" || node.Alias != nil || node.Kind == yaml.AliasNode {
		return nil, errStrict
	}
	switch node.Kind {
	case yaml.MappingNode:
		if node.ShortTag() != "!!map" || len(node.Content)%2 != 0 || len(node.Content)/2 > intake.MaxObjectMembers {
			return nil, errStrict
		}
		object := make(map[string]any, len(node.Content)/2)
		folded := make(map[string]bool, len(node.Content)/2)
		for index := 0; index < len(node.Content); index += 2 {
			key := node.Content[index]
			if key.Kind != yaml.ScalarNode || key.ShortTag() != "!!str" || key.Anchor != "" || key.Alias != nil || key.Value == "" || key.Value == "<<" {
				return nil, errStrict
			}
			lower := strings.ToLower(key.Value)
			if _, duplicate := object[key.Value]; duplicate || folded[lower] {
				return nil, errStrict
			}
			folded[lower] = true
			value, err := strictValue(node.Content[index+1], depth+1)
			if err != nil {
				return nil, err
			}
			object[key.Value] = value
		}
		return object, nil
	case yaml.SequenceNode:
		if node.ShortTag() != "!!seq" || len(node.Content) > intake.MaxArrayItems {
			return nil, errStrict
		}
		items := make([]any, 0, len(node.Content))
		for _, child := range node.Content {
			value, err := strictValue(child, depth+1)
			if err != nil {
				return nil, err
			}
			items = append(items, value)
		}
		return items, nil
	case yaml.ScalarNode:
		return strictScalar(node)
	}
	return nil, errStrict
}

func strictScalar(node *yaml.Node) (any, error) {
	switch node.ShortTag() {
	case "!!str", "!!timestamp":
		return node.Value, nil
	case "!!bool":
		switch node.Value {
		case "true", "True", "TRUE":
			return true, nil
		case "false", "False", "FALSE":
			return false, nil
		}
	case "!!int", "!!float":
		return json.Number(node.Value), nil
	case "!!null":
		return nil, nil
	}
	return nil, errStrict
}

func copyValue(value any) any {
	switch typed := value.(type) {
	case map[string]any:
		out := make(map[string]any, len(typed))
		for key, child := range typed {
			out[key] = copyValue(child)
		}
		return out
	case []any:
		out := make([]any, len(typed))
		for index, child := range typed {
			out[index] = copyValue(child)
		}
		return out
	}
	return value
}
