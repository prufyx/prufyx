// SPDX-License-Identifier: AGPL-3.0-only

package fix

import (
	"errors"
	"strings"

	"github.com/prufyx/prufyx/cli/internal/intake"
)

func init() { Register(renameKeyKind{}) }

type renameKeyParams struct {
	selector
	Path   kindPath `json:"path"`
	NewKey string   `json:"newKey"`
}

// renameKeyKind renames one mapping key in the documents a selector names.
// The value and everything else on the line stay. A quoted key keeps its quote
// style; a plain key stays plain when the new key is safe as a plain
// scalar, else it is written double-quoted. Renaming onto another key of the
// same mapping, also one that differs only in case, is refused. A missing
// key is not an error (nothing to do).
type renameKeyKind struct{}

func (renameKeyKind) ID() string { return "rename_key" }

func (renameKeyKind) Validate(params Params) (any, error) {
	var p renameKeyParams
	if err := decodeKindParams(params, &p); err != nil {
		return nil, err
	}
	if err := p.validate(); err != nil {
		return nil, err
	}
	if len(p.Path) == 0 || p.Path[len(p.Path)-1].isIndex || !usableKey(p.NewKey) {
		return nil, errors.New("invalid path or new key")
	}
	return p, nil
}

func (renameKeyKind) Plan(intake.Document, []byte, any) ([]Edit, error) { return nil, nil }

func (renameKeyKind) PlanOperations(doc intake.Document, src []byte, parsed any) ([]Planned, error) {
	p := parsed.(renameKeyParams)
	if selected, err := p.selects(doc); err != nil || !selected {
		return nil, err
	}
	mapping, key, ok := parentAndKey(doc, p.Path)
	if !ok || key == p.NewKey {
		return nil, nil
	}
	for other := range mapping {
		if other != key && strings.EqualFold(other, p.NewKey) {
			return nil, kindRefused("the new key is already used by a sibling key")
		}
	}
	locator, err := NewLocator(src)
	if err != nil {
		return nil, err
	}
	span, err := locator.Locate(doc.Source.Document, Path(p.Path), PartKey)
	if err != nil {
		return nil, err
	}
	token := string(src[span.Start:span.End])
	replacement := scalarToken(p.NewKey, tokenQuote(token), true)
	return []Planned{{
		Op:   RenameKey{Path: Path(p.Path), NewKey: p.NewKey},
		Edit: span.Edit(doc.Source.Display, replacement),
	}}, nil
}
