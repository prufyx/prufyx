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
// the last entry of a list deletes the whole argument (a sequence element
// as whole lines; in the two-element form the flag element goes too), a
// structural operation that the framework proves on the decoded document. It
// is refused when the removal would leave an args or command list empty and
// in flow-style lists. A featureGates map entry is never removed: any such
// mapping holding the gate, anywhere in the file, refuses the file.
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
	// flag is the separate --feature-gates element of the two-element form.
	flag *argElement
}

func gateLists(ref containerRef) []gateList {
	var out []gateList
	for _, list := range ref.lists {
		for i, element := range list {
			switch {
			case strings.HasPrefix(element.value, gatesFlag+"="):
				out = append(out, gateList{element: element, prefix: gatesFlag + "="})
			case element.value == gatesFlag && i+1 < len(list):
				flag := element
				out = append(out, gateList{element: list[i+1], flag: &flag})
			}
		}
	}
	return out
}

// gatePlan is what one document needs: token edits, and structural
// operations for what has to be deleted.
type gatePlan struct {
	edits []Edit
	ops   []Planned
}

func (removeFeatureGateKind) Plan(doc intake.Document, src []byte, parsed any) ([]Edit, error) {
	plan, err := planGate(src, doc, parsed.(removeFeatureGateParams))
	return plan.edits, err
}

func (removeFeatureGateKind) PlanOperations(doc intake.Document, src []byte, parsed any) ([]Planned, error) {
	plan, err := planGate(src, doc, parsed.(removeFeatureGateParams))
	return plan.ops, err
}

func planGate(src []byte, doc intake.Document, p removeFeatureGateParams) (gatePlan, error) {
	var plan gatePlan
	if err := checkGateMap(src, p); err != nil {
		return plan, err
	}
	refs, err := containers(doc)
	if err != nil || len(refs) == 0 {
		return plan, err
	}
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
					return plan, kindRefused("a feature gate list has an entry that is not Name=true or Name=false")
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
			return plan, kindRefused("a container with the gate has an image that is not a known component")
		case count > 1:
			return plan, kindRefused("the gate is present more than once in a container")
		}
		h := hits[0]
		locator, err := NewLocator(src)
		if err != nil {
			return plan, err
		}
		if len(h.entries) == 1 {
			// The gate is the whole list: delete the argument.
			elements := []argElement{h.list.element}
			if h.list.flag != nil {
				elements = []argElement{*h.list.flag, h.list.element}
			}
			for _, element := range elements {
				edit, err := locator.RemoveElementEdit(doc.Source.Display, doc.Source.Document, element.path)
				if err != nil {
					return plan, err
				}
				plan.ops = append(plan.ops, Planned{Op: RemoveElement{Path: element.path}, Edit: edit})
			}
			continue
		}
		kept := make([]string, 0, len(h.entries))
		for _, entry := range h.entries {
			if !strings.HasPrefix(entry, p.Gate+"=") {
				kept = append(kept, entry)
			}
		}
		span, err := locator.Locate(doc.Source.Document, h.list.element.path, PartValue)
		if err != nil {
			return plan, err
		}
		quote, ok := plainBody(string(src[span.Start:span.End]), h.list.element.value)
		if !ok {
			return plan, kindRefused("the gate list token cannot be edited in place")
		}
		plan.edits = append(plan.edits, span.Edit(doc.Source.Display, wrap(quote, h.list.prefix+strings.Join(kept, ","))))
	}
	return plan, nil
}

// checkGateMap refuses the whole file when any featureGates mapping, at any
// depth in any document, holds the gate as a key. Such a mapping says nothing
// about which component it configures, and gate names are shared between
// products, so removing the entry could change another component.
func checkGateMap(src []byte, p removeFeatureGateParams) error {
	locator, err := NewLocator(src)
	if err != nil {
		return err
	}
	for _, doc := range locator.file.docs {
		if gateInMap(doc.value, p.Gate, 0) {
			return kindRefused("the gate is a featureGates map entry; which component it configures cannot be told")
		}
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
