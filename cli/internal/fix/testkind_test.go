// SPDX-License-Identifier: AGPL-3.0-only

package fix

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/prufyx/prufyx/cli/internal/intake"
)

// The kinds below exist only in tests. They exercise the framework the way
// compiled kinds will: decode bounded parameters, look at the decoded
// document, locate tokens and return edits.

func init() {
	Register(setKind{})
	Register(rawKind{})
	Register(growKind{})
}

type setParams struct {
	Path []any `json:"path"`
	Part string `json:"part"`
	From string `json:"from"`
	To   string `json:"to"`
}

func decodeParams(params Params, into any) error {
	decoder := json.NewDecoder(bytes.NewReader(params))
	decoder.DisallowUnknownFields()
	decoder.UseNumber()
	return decoder.Decode(into)
}

func (p setParams) path() (Path, error) {
	var path Path
	for _, raw := range p.Path {
		switch segment := raw.(type) {
		case string:
			path = append(path, Key(segment))
		case json.Number:
			index, err := segment.Int64()
			if err != nil {
				return nil, err
			}
			path = append(path, Index(int(index)))
		default:
			return nil, errors.New("bad segment")
		}
	}
	return path, nil
}

// setKind replaces the value at path when it decodes to From, or renames the
// key at path when it exists, with the token To.
type setKind struct{}

func (setKind) ID() string { return "test_set" }

func (setKind) Validate(params Params) error {
	var p setParams
	if err := decodeParams(params, &p); err != nil {
		return err
	}
	if p.Part != "value" && p.Part != "key" || p.To == "" || len(p.Path) > MaxPathSegments {
		return errors.New("invalid")
	}
	_, err := p.path()
	return err
}

func (setKind) Plan(doc intake.Document, src []byte, params Params) ([]Edit, error) {
	var p setParams
	if err := decodeParams(params, &p); err != nil {
		return nil, err
	}
	path, err := p.path()
	if err != nil {
		return nil, err
	}
	locator, err := NewLocator(src)
	if err != nil {
		return nil, err
	}
	part := PartValue
	if p.Part == "key" {
		part = PartKey
	} else {
		current, found := valueAt(doc.Value, path)
		if !found || fmt.Sprint(current) != p.From {
			return nil, nil
		}
	}
	span, err := locator.Locate(doc.Source.Document, path, part)
	if ReasonOf(err) == ReasonPathNotFound {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return []Edit{span.Edit(doc.Source.Display, p.To)}, nil
}

func valueAt(value any, path Path) (any, bool) {
	for _, segment := range path {
		switch typed := value.(type) {
		case map[string]any:
			if segment.isIndex {
				return nil, false
			}
			child, ok := typed[segment.key]
			if !ok {
				return nil, false
			}
			value = child
		case []any:
			if !segment.isIndex || segment.index < 0 || segment.index >= len(typed) {
				return nil, false
			}
			value = typed[segment.index]
		default:
			return nil, false
		}
	}
	return value, true
}

type rawEdit struct {
	Start       int    `json:"start"`
	End         int    `json:"end"`
	Replacement string `json:"replacement"`
}

// rawKind returns the edits in its parameters for the first document only.
type rawKind struct{}

func (rawKind) ID() string { return "test_raw" }

func (rawKind) Validate(params Params) error {
	var edits []rawEdit
	return decodeParams(params, &edits)
}

func (rawKind) Plan(doc intake.Document, _ []byte, params Params) ([]Edit, error) {
	if doc.Source.Document != 0 {
		return nil, nil
	}
	var raw []rawEdit
	if err := decodeParams(params, &raw); err != nil {
		return nil, err
	}
	edits := make([]Edit, len(raw))
	for i, e := range raw {
		edits[i] = Edit{File: doc.Source.Display, StartByte: e.Start, EndByte: e.End, Replacement: e.Replacement}
	}
	return edits, nil
}

// growKind is deliberately not idempotent: it appends to the scalar at path.
type growKind struct{}

func (growKind) ID() string { return "test_grow" }

func (growKind) Validate(params Params) error {
	var p setParams
	return decodeParams(params, &p)
}

func (growKind) Plan(doc intake.Document, src []byte, params Params) ([]Edit, error) {
	var p setParams
	if err := decodeParams(params, &p); err != nil {
		return nil, err
	}
	path, err := p.path()
	if err != nil {
		return nil, err
	}
	span, err := Locate(src, doc.Source.Document, path, PartValue)
	if err != nil {
		return nil, err
	}
	return []Edit{span.Edit(doc.Source.Display, string(src[span.Start:span.End])+"x")}, nil
}

// setRequest builds a request for the set kind.
func setRequest(part, from, to string, path ...any) Request {
	params, err := json.Marshal(setParams{Path: path, Part: part, From: from, To: to})
	if err != nil {
		panic(err)
	}
	return Request{Kind: "test_set", Params: params}
}

func rawRequest(edits ...rawEdit) Request {
	params, err := json.Marshal(edits)
	if err != nil {
		panic(err)
	}
	return Request{Kind: "test_raw", Params: params}
}
