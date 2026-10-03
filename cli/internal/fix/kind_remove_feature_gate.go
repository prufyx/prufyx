// SPDX-License-Identifier: AGPL-3.0-only

package fix

import (
	"errors"
	"regexp"
	"strings"

	"github.com/prufyx/prufyx/cli/internal/intake"
)

func init() { Register(removeFeatureGateKind{}) }

type removeFeatureGateParams struct {
	Component string `json:"component"`
	Gate      string `json:"gate"`
}

var (
	gateNameRE  = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9]{0,63}$`)
	gateEntryRE = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9]{0,63}=(?:true|false)$`)
)

// removeFeatureGateKind drops one gate from a --feature-gates list. Removing
// the last entry of a list, or an entry of a featureGates map, deletes a
// whole argument or mapping entry; those structural edits are refused, and so
// is any document in which a featureGates mapping holds the gate.
//
// Limits: only the regular containers of a workload are read (init containers
// are left alone); only the double-dash flag --feature-gates is recognised
// (not -feature-gates); in the two-element form the element after the flag is
// taken as the list, and no per-component flag schema exists to tell a value
// from a flag.
type removeFeatureGateKind struct{}

func (removeFeatureGateKind) ID() string { return "remove_feature_gate" }

func (removeFeatureGateKind) Validate(params Params) (any, error) {
	var p removeFeatureGateParams
	if err := decodeKindParams(params, &p); err != nil {
		return nil, err
	}
	if !gateNameRE.MatchString(p.Gate) {
		return nil, errors.New("invalid gate")
	}
	if !knownComponent(p.Component) {
		return nil, errors.New("unknown component")
	}
	return p, nil
}

const gatesFlag = "--feature-gates"

// gateList is one string that holds a gate list: the value of
// --feature-gates=LIST, or the element after a bare --feature-gates.
type gateList struct {
	element argElement
	prefix  string
}

func gateLists(ref containerRef) []gateList {
	var out []gateList
	for _, list := range ref.lists {
		for i, element := range list {
			switch {
			case strings.HasPrefix(element.value, gatesFlag+"="):
				out = append(out, gateList{element: element, prefix: gatesFlag + "="})
			case element.value == gatesFlag && i+1 < len(list):
				out = append(out, gateList{element: list[i+1]})
			}
		}
	}
	return out
}

func (removeFeatureGateKind) Plan(doc intake.Document, src []byte, parsed any) ([]Edit, error) {
	p := parsed.(removeFeatureGateParams)
	if err := checkGateMap(doc, p); err != nil {
		return nil, err
	}
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
		type hit struct {
			list    gateList
			entries []string
		}
		var hits []hit
		count := 0
		for _, list := range gateLists(ref) {
			value := strings.TrimPrefix(list.element.value, list.prefix)
			if !strings.Contains(value, p.Gate) {
				continue
			}
			entries := strings.Split(value, ",")
			own := 0
			for _, entry := range entries {
				if !gateEntryRE.MatchString(entry) {
					return nil, kindRefused("a feature gate list has an entry that is not Name=true or Name=false")
				}
				if strings.HasPrefix(entry, p.Gate+"=") {
					own++
				}
			}
			if own > 0 {
				count += own
				hits = append(hits, hit{list: list, entries: entries})
			}
		}
		if count == 0 {
			continue
		}
		switch {
		case unknown:
			return nil, kindRefused("a container with the gate has an image that is not a known component")
		case count > 1:
			return nil, kindRefused("the gate is present more than once in a container")
		case len(hits[0].entries) == 1:
			return nil, kindRefused("removing the only gate deletes the argument; structural edits are not supported")
		}
		h := hits[0]
		kept := make([]string, 0, len(h.entries))
		for _, entry := range h.entries {
			if !strings.HasPrefix(entry, p.Gate+"=") {
				kept = append(kept, entry)
			}
		}
		locator, err := NewLocator(src)
		if err != nil {
			return nil, err
		}
		span, err := locator.Locate(doc.Source.Document, h.list.element.path, PartValue)
		if err != nil {
			return nil, err
		}
		quote, ok := plainBody(string(src[span.Start:span.End]), h.list.element.value)
		if !ok {
			return nil, kindRefused("the gate list token cannot be edited in place")
		}
		edits = append(edits, span.Edit(doc.Source.Display, wrap(quote, h.list.prefix+strings.Join(kept, ","))))
	}
	return edits, nil
}

// checkGateMap refuses a document in which any featureGates mapping, at any
// depth, holds the gate as a key: dropping a map entry is a structural edit.
func checkGateMap(doc intake.Document, p removeFeatureGateParams) error {
	if gateInMap(doc.Value, p.Gate, 0) {
		return kindRefused("the gate is a featureGates map entry; removing it is a structural edit")
	}
	return nil
}

func gateInMap(value any, gate string, depth int) bool {
	if depth > 256 {
		return true // too deep to inspect: refuse
	}
	switch typed := value.(type) {
	case map[string]any:
		for key, child := range typed {
			if key == "featureGates" {
				if gates, ok := child.(map[string]any); ok {
					if _, present := gates[gate]; present {
						return true
					}
				}
			}
			if gateInMap(child, gate, depth+1) {
				return true
			}
		}
	case []any:
		for _, child := range typed {
			if gateInMap(child, gate, depth+1) {
				return true
			}
		}
	}
	return false
}
