// SPDX-License-Identifier: AGPL-3.0-only

package fix

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"

	"github.com/prufyx/prufyx/cli/internal/intake"
)

func init() { Register(setValueKind{}) }

type setValueParams struct {
	selector
	Path  kindPath        `json:"path"`
	Value json.RawMessage `json:"value"`
}

type setValueParsed struct {
	selector
	path   kindPath
	scalar any
}

// setValueKind replaces the scalar value at a path in the documents a
// selector names. The value is a string, a plain decimal number, true, false
// or null. Strings are always written quoted (in the quote style of the
// token they replace, double quotes otherwise); numbers, true, false and null
// are written plain. The existing value must be a single-line scalar; a
// missing path is not an error (nothing to do), and a value that already
// equals the requested one (same type) is left alone.
type setValueKind struct{}

func (setValueKind) ID() string { return "set_value" }

func (setValueKind) Validate(params Params) (any, error) {
	var p setValueParams
	if err := decodeKindParams(params, &p); err != nil {
		return nil, err
	}
	if err := p.validate(); err != nil {
		return nil, err
	}
	if len(p.Path) == 0 || len(p.Value) == 0 {
		return nil, errors.New("path and value are required")
	}
	decoder := json.NewDecoder(bytes.NewReader(p.Value))
	decoder.UseNumber()
	var scalar any
	if err := decoder.Decode(&scalar); err != nil || decoder.More() {
		return nil, errors.New("invalid value")
	}
	// Reuse the framework's own rules for declared scalars.
	if r := validateDeclared(SetValue{Path: Path(p.Path), Scalar: scalar}); r != nil {
		return nil, errors.New("invalid value")
	}
	return setValueParsed{selector: p.selector, path: p.Path, scalar: scalar}, nil
}

func (setValueKind) Plan(intake.Document, []byte, any) ([]Edit, error) { return nil, nil }

func (setValueKind) PlanOperations(doc intake.Document, src []byte, parsed any) ([]Planned, error) {
	p := parsed.(setValueParsed)
	if selected, err := p.selects(doc); err != nil || !selected {
		return nil, err
	}
	current, ok := lookupPath(doc.Value, Path(p.path))
	if !ok {
		return nil, nil
	}
	switch current.(type) {
	case map[string]any, []any:
		return nil, kindRefused("the value at the path is not a scalar")
	}
	if sameScalar(current, p.scalar) {
		return nil, nil
	}
	locator, err := NewLocator(src)
	if err != nil {
		return nil, err
	}
	span, err := locator.Locate(doc.Source.Document, Path(p.path), PartValue)
	if err != nil {
		return nil, err
	}
	var replacement string
	switch scalar := p.scalar.(type) {
	case string:
		replacement = scalarToken(scalar, tokenQuote(string(src[span.Start:span.End])), false)
	case json.Number:
		replacement = string(scalar)
	case bool:
		replacement = strings.ToLower(boolText(scalar))
	default:
		replacement = "null"
	}
	return []Planned{{
		Op:   SetValue{Path: Path(p.path), Scalar: p.scalar},
		Edit: span.Edit(doc.Source.Display, replacement),
	}}, nil
}

func boolText(value bool) string {
	if value {
		return "true"
	}
	return "false"
}

// sameScalar compares decoded scalars by type and written text.
func sameScalar(a, b any) bool {
	switch x := a.(type) {
	case nil:
		return b == nil
	case string:
		y, ok := b.(string)
		return ok && x == y
	case bool:
		y, ok := b.(bool)
		return ok && x == y
	case json.Number:
		y, ok := b.(json.Number)
		return ok && x == y
	}
	return false
}
