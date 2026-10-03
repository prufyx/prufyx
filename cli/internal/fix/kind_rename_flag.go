// SPDX-License-Identifier: AGPL-3.0-only

package fix

import (
	"errors"
	"strings"

	"github.com/prufyx/prufyx/cli/internal/intake"
)

func init() { Register(renameFlagKind{}) }

type renameFlagParams struct {
	Component string `json:"component"`
	Old       string `json:"from"`
	New       string `json:"to"`
}

// renameFlagKind renames a command-line flag in the command and args lists of
// the containers of one component.
type renameFlagKind struct{}

func (renameFlagKind) ID() string { return "rename_flag" }

func (renameFlagKind) Validate(params Params) (any, error) {
	var p renameFlagParams
	if err := decodeKindParams(params, &p); err != nil {
		return nil, err
	}
	if !flagNameRE.MatchString(p.Old) || !flagNameRE.MatchString(p.New) || p.Old == p.New {
		return nil, errors.New("invalid flag")
	}
	if !knownComponent(p.Component) {
		return nil, errors.New("unknown component")
	}
	return p, nil
}

func isFlag(text, flag string) bool {
	return text == flag || strings.HasPrefix(text, flag+"=")
}

func (renameFlagKind) Plan(doc intake.Document, src []byte, parsed any) ([]Edit, error) {
	p := parsed.(renameFlagParams)
	refs, err := containers(doc)
	if err != nil || len(refs) == 0 {
		return nil, err
	}
	var edits []Edit
	for _, ref := range refs {
		match, unknown := classify(ref.image, p.Component)
		if !match && !unknown {
			continue
		}
		var found []argElement
		target := false
		for _, list := range ref.lists {
			for _, element := range list {
				if isFlag(element.value, p.Old) {
					found = append(found, element)
				}
				if isFlag(element.value, p.New) {
					target = true
				}
			}
		}
		if len(found) == 0 {
			continue
		}
		switch {
		case unknown:
			return nil, kindRefused("a container with the flag has an image that is not a known component")
		case len(found) > 1:
			return nil, kindRefused("the flag is present more than once in a container")
		case target:
			return nil, kindRefused("a container has both the old and the new flag")
		}
		locator, err := NewLocator(src)
		if err != nil {
			return nil, err
		}
		span, err := locator.Locate(doc.Source.Document, found[0].path, PartValue)
		if err != nil {
			return nil, err
		}
		raw := string(src[span.Start:span.End])
		quote := tokenQuote(raw)
		body := raw
		if quote != 0 {
			body = raw[1 : len(raw)-1]
		}
		if !strings.HasPrefix(body, p.Old) {
			return nil, kindRefused("the flag token cannot be edited in place")
		}
		edits = append(edits, span.Edit(doc.Source.Display, wrap(quote, p.New+body[len(p.Old):])))
	}
	return edits, nil
}
