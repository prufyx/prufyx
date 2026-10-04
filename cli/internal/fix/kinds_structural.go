// SPDX-License-Identifier: AGPL-3.0-only

package fix

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"unicode/utf8"

	"github.com/prufyx/prufyx/cli/internal/intake"
)

// maxKindPathSegments bounds the path parameter of the structural kinds.
const maxKindPathSegments = 12

// maxKindKeyBytes bounds one key of a path parameter and the new key of a
// rename.
const maxKindKeyBytes = 253

// kindPath is the path parameter of a structural kind: a JSON array whose
// strings are mapping keys and whose non-negative integers are sequence
// indexes. Keys are literal; there are no wildcards.
type kindPath Path

func (p *kindPath) UnmarshalJSON(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var segments []any
	if err := decoder.Decode(&segments); err != nil {
		return err
	}
	if len(segments) == 0 || len(segments) > maxKindPathSegments {
		return errors.New("path length")
	}
	out := make(kindPath, 0, len(segments))
	for _, raw := range segments {
		switch segment := raw.(type) {
		case string:
			if !usableKey(segment) {
				return errors.New("path key")
			}
			out = append(out, Key(segment))
		case json.Number:
			index, err := segment.Int64()
			if err != nil || index < 0 || index > 1<<20 || strings.ContainsAny(string(segment), ".eE+-") {
				return errors.New("path index")
			}
			out = append(out, Index(int(index)))
		default:
			return errors.New("path segment")
		}
	}
	*p = out
	return nil
}

// usableKey accepts a non-empty single-line UTF-8 key without template
// syntax that is not the merge key.
func usableKey(key string) bool {
	return key != "" && key != "<<" && len(key) <= maxKindKeyBytes && utf8.ValidString(key) && !hasControl(key) &&
		!strings.Contains(key, "{{") && !strings.Contains(key, "${")
}

// selector says which documents a structural kind edits: documents with
// exactly this apiVersion and kind, or, with valuesFile true and no
// apiVersion or kind, documents that have neither (values files). An empty
// selector is refused, so a rule that forgets the fields does not match every
// YAML file in a tree. A caller that sets valuesFile should also restrict the
// files it offers (for example to a chart directory).
type selector struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	ValuesFile bool   `json:"valuesFile"`
}

func (s selector) validate() error {
	if s.ValuesFile {
		if s.APIVersion != "" || s.Kind != "" {
			return errors.New("valuesFile excludes apiVersion and kind")
		}
		return nil
	}
	if !apiVersionRE.MatchString(s.APIVersion) || !kindNameRE.MatchString(s.Kind) || s.Kind == "Secret" || s.Kind == "List" {
		return errors.New("invalid apiVersion or kind")
	}
	return nil
}

// selects reports whether the document is one the selector names. A List
// that holds a document the selector names is refused: its items are not
// addressed.
func (s selector) selects(doc intake.Document) (bool, error) {
	if doc.Kind == "List" && s.Kind != "" {
		items, _ := doc.Value["items"].([]any)
		for _, item := range items {
			if entry, ok := item.(map[string]any); ok && entry["kind"] == s.Kind && entry["apiVersion"] == s.APIVersion {
				return false, kindRefused("a List holding a matching document is not supported")
			}
		}
		return false, nil
	}
	return doc.APIVersion == s.APIVersion && doc.Kind == s.Kind, nil
}

// parentAndKey returns the mapping that holds the last path key.
func parentAndKey(doc intake.Document, path kindPath) (map[string]any, string, bool) {
	parent, ok := lookupPath(doc.Value, Path(path[:len(path)-1]))
	if !ok {
		return nil, "", false
	}
	mapping, ok := parent.(map[string]any)
	last := path[len(path)-1]
	if !ok || last.isIndex {
		return nil, "", false
	}
	if _, present := mapping[last.key]; !present {
		return nil, "", false
	}
	return mapping, last.key, true
}

// needsQuotes reports a plain spelling that is not read as exactly this
// string by both YAML readings.
func needsQuotes(text string) bool {
	if text == "" || !plainKeyBody(text) {
		return true
	}
	node, ok := decodeLoneScalar([]byte(text))
	if !ok || node.Style != 0 || node.Value != text || node.ShortTag() != "!!str" {
		return true
	}
	return ambiguousPlain(node)
}

// plainKeyBody accepts the characters that are safe in a plain scalar
// anywhere: a word character first, then word characters, dot, dash, slash.
func plainKeyBody(text string) bool {
	for i := 0; i < len(text); i++ {
		c := text[i]
		word := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_'
		if !word && (i == 0 || c != '.' && c != '-' && c != '/') {
			return false
		}
	}
	return true
}

func doubleQuote(text string) string {
	text = strings.ReplaceAll(text, `\`, `\\`)
	return `"` + strings.ReplaceAll(text, `"`, `\"`) + `"`
}

func singleQuote(text string) string {
	return `'` + strings.ReplaceAll(text, `'`, `''`) + `'`
}

// scalarToken writes a string as a token: in the quote style of the token it
// replaces when that is a quote style, else double-quoted. When plain is
// true a safe, unambiguous string may stay plain (used for keys).
func scalarToken(text string, old byte, plain bool) string {
	switch {
	case old == '\'':
		return singleQuote(text)
	case old == '"':
		return doubleQuote(text)
	case plain && !needsQuotes(text):
		return text
	}
	return doubleQuote(text)
}
