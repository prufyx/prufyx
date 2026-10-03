// SPDX-License-Identifier: AGPL-3.0-only

package fix

import (
	"errors"
	"regexp"

	"github.com/prufyx/prufyx/cli/internal/intake"
)

func init() { Register(setAPIVersionKind{}) }

var (
	apiVersionRE = regexp.MustCompile(`^(?:[a-z0-9](?:[-a-z0-9.]{0,251}[a-z0-9])?/)?v[1-9][0-9]{0,2}(?:(?:alpha|beta)[1-9][0-9]{0,2})?$`)
	kindNameRE   = regexp.MustCompile(`^[A-Z][A-Za-z0-9]{0,62}$`)
)

type setAPIVersionParams struct {
	Old  string `json:"from"`
	New  string `json:"to"`
	Kind string `json:"kind"`
}

// setAPIVersionKind replaces the apiVersion of documents of one exact kind.
// Documents of another kind are skipped, even with the same apiVersion. A List
// holding a matching item is refused (its items are not addressed).
// Whether the migration is safe is a property of the rule that asks for it;
// this kind only does the byte-exact replacement.
type setAPIVersionKind struct{}

func (setAPIVersionKind) ID() string { return "set_api_version" }

func (setAPIVersionKind) Validate(params Params) (any, error) {
	var p setAPIVersionParams
	if err := decodeKindParams(params, &p); err != nil {
		return nil, err
	}
	if !apiVersionRE.MatchString(p.Old) || !apiVersionRE.MatchString(p.New) || p.Old == p.New {
		return nil, errors.New("invalid apiVersion")
	}
	if !kindNameRE.MatchString(p.Kind) || p.Kind == "Secret" || p.Kind == "List" {
		return nil, errors.New("invalid kind")
	}
	return p, nil
}

func (setAPIVersionKind) Plan(doc intake.Document, src []byte, parsed any) ([]Edit, error) {
	p := parsed.(setAPIVersionParams)
	if doc.Kind == "List" {
		items, _ := doc.Value["items"].([]any)
		for _, item := range items {
			if entry, ok := item.(map[string]any); ok && entry["kind"] == p.Kind && entry["apiVersion"] == p.Old {
				return nil, kindRefused("a List holding a matching document is not supported")
			}
		}
		return nil, nil
	}
	if doc.APIVersion != p.Old {
		return nil, nil
	}
	if doc.Kind != p.Kind {
		return nil, nil
	}
	locator, err := NewLocator(src)
	if err != nil {
		return nil, err
	}
	span, err := locator.Locate(doc.Source.Document, Path{Key("apiVersion")}, PartValue)
	if err != nil {
		return nil, err
	}
	quote := tokenQuote(string(src[span.Start:span.End]))
	return []Edit{span.Edit(doc.Source.Display, wrap(quote, p.New))}, nil
}
