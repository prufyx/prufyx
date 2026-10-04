// SPDX-License-Identifier: AGPL-3.0-only

package fix

import (
	"errors"

	"github.com/prufyx/prufyx/cli/internal/intake"
)

func init() { Register(removeKeyKind{}) }

type removeKeyParams struct {
	selector
	Path kindPath `json:"path"`
}

// removeKeyKind removes one mapping entry, key and whole value, as whole
// lines, from the documents a selector names. Flow-style containers, entries
// that share a line with other content, tabs in the indentation and a removal
// that would leave the parent empty are refused (see Locator.RemoveKeyEdit).
// A missing key is not an error (nothing to do).
type removeKeyKind struct{}

func (removeKeyKind) ID() string { return "remove_key" }

func (removeKeyKind) Validate(params Params) (any, error) {
	var p removeKeyParams
	if err := decodeKindParams(params, &p); err != nil {
		return nil, err
	}
	if err := p.validate(); err != nil {
		return nil, err
	}
	if len(p.Path) == 0 || p.Path[len(p.Path)-1].isIndex {
		return nil, errors.New("invalid path")
	}
	return p, nil
}

func (removeKeyKind) Plan(intake.Document, []byte, any) ([]Edit, error) { return nil, nil }

func (removeKeyKind) PlanOperations(doc intake.Document, src []byte, parsed any) ([]Planned, error) {
	p := parsed.(removeKeyParams)
	if selected, err := p.selects(doc); err != nil || !selected {
		return nil, err
	}
	if _, _, ok := parentAndKey(doc, p.Path); !ok {
		return nil, nil
	}
	locator, err := NewLocator(src)
	if err != nil {
		return nil, err
	}
	edit, err := locator.RemoveKeyEdit(doc.Source.Display, doc.Source.Document, Path(p.Path))
	if err != nil {
		return nil, err
	}
	return []Planned{{Op: RemoveKey{Path: Path(p.Path)}, Edit: edit}}, nil
}
