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
	Register(refuseKind{})
	Register(mutateKind{})
	Register(onceKind{})
}

type setParams struct {
	Path []any  `json:"path"`
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

func (setKind) Validate(params Params) (any, error) {
	var p setParams
	if err := decodeParams(params, &p); err != nil {
		return nil, err
	}
	if p.Part != "value" && p.Part != "key" || p.To == "" || len(p.Path) > MaxPathSegments {
		return nil, errors.New("invalid")
	}
	if _, err := p.path(); err != nil {
		return nil, err
	}
	return p, nil
}

func (setKind) Plan(doc intake.Document, src []byte, parsed any) ([]Edit, error) {
	p := parsed.(setParams)
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

func (rawKind) Validate(params Params) (any, error) {
	var edits []rawEdit
	if err := decodeParams(params, &edits); err != nil {
		return nil, err
	}
	return edits, nil
}

func (rawKind) Plan(doc intake.Document, _ []byte, parsed any) ([]Edit, error) {
	if doc.Source.Document != 0 {
		return nil, nil
	}
	raw := parsed.([]rawEdit)
	edits := make([]Edit, len(raw))
	for i, e := range raw {
		edits[i] = Edit{File: doc.Source.Display, StartByte: e.Start, EndByte: e.End, Replacement: e.Replacement}
	}
	return edits, nil
}

// growKind is deliberately not idempotent: it appends to the scalar at path.
type growKind struct{}

func (growKind) ID() string { return "test_grow" }

func (growKind) Validate(params Params) (any, error) {
	var p setParams
	if err := decodeParams(params, &p); err != nil {
		return nil, err
	}
	return p, nil
}

func (growKind) Plan(doc intake.Document, src []byte, parsed any) ([]Edit, error) {
	p := parsed.(setParams)
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

// refuseKind fails Plan in the way its parameters say.
type refuseKind struct{}

type refuseParams struct {
	Mode   string `json:"mode"`
	Reason string `json:"reason"`
	Detail string `json:"detail"`
}

func (refuseKind) ID() string { return "test_refuse" }

func (refuseKind) Validate(params Params) (any, error) {
	var p refuseParams
	if err := decodeParams(params, &p); err != nil {
		return nil, err
	}
	return p, nil
}

func (refuseKind) Plan(_ intake.Document, _ []byte, parsed any) ([]Edit, error) {
	p := parsed.(refuseParams)
	switch p.Mode {
	case "refusal":
		return nil, &Refusal{Reason: Reason(p.Reason), Detail: p.Detail}
	case "wrapped":
		return nil, fmt.Errorf("kind: %w", &Refusal{Reason: Reason(p.Reason), Detail: p.Detail})
	}
	return nil, errors.New(p.Detail)
}

func refuseRequest(mode, reason, detail string) Request {
	params, err := json.Marshal(refuseParams{Mode: mode, Reason: reason, Detail: detail})
	if err != nil {
		panic(err)
	}
	return Request{Kind: "test_refuse", Params: params}
}

// mutateKind writes into the source bytes it is given.
type mutateKind struct{}

func (mutateKind) ID() string { return "test_mutate" }

func (mutateKind) Validate(Params) (any, error) { return nil, nil }

func (mutateKind) Plan(_ intake.Document, src []byte, _ any) ([]Edit, error) {
	src[0] ^= 0x20
	return nil, nil
}

// onceKind counts its calls: Validate must run once per request, and every
// Plan call must get the value Validate returned. It rewrites a: x to a: zz.
type onceKind struct{}

var onceLog struct {
	validated []*onceParams
	planned   []any
}

type onceParams struct{ marker int }

func (onceKind) ID() string { return "test_once" }

func (onceKind) Validate(params Params) (any, error) {
	parsed := &onceParams{marker: len(onceLog.validated)}
	onceLog.validated = append(onceLog.validated, parsed)
	return parsed, nil
}

func (onceKind) Plan(doc intake.Document, src []byte, parsed any) ([]Edit, error) {
	onceLog.planned = append(onceLog.planned, parsed)
	if doc.Value["a"] != "x" {
		return nil, nil
	}
	span, err := Locate(src, doc.Source.Document, Path{Key("a")}, PartValue)
	if err != nil {
		return nil, err
	}
	return []Edit{span.Edit(doc.Source.Display, "zz")}, nil
}
