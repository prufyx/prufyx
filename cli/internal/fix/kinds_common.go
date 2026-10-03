// SPDX-License-Identifier: AGPL-3.0-only

package fix

import (
	"bytes"
	"encoding/json"
	"errors"
	"regexp"

	"github.com/prufyx/prufyx/cli/internal/intake"
	"github.com/prufyx/prufyx/cli/internal/localcollector"
)

// decodeKindParams decodes the parameters of a compiled kind: exactly one
// JSON object, no unknown fields. The framework has already bounded them and
// rejected duplicate keys.
func decodeKindParams(params Params, into any) error {
	if len(bytes.TrimSpace(params)) == 0 {
		return errors.New("missing parameters")
	}
	decoder := json.NewDecoder(bytes.NewReader(params))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(into); err != nil {
		return err
	}
	if decoder.More() {
		return errors.New("trailing data")
	}
	return nil
}

func kindRefused(detail string) error { return refuse(ReasonKindRefused, detail) }

// knownComponent reports whether the id is a component of the exact
// component registry.
func knownComponent(id string) bool {
	for _, known := range localcollector.ComponentIDs() {
		if known == id {
			return true
		}
	}
	return false
}

var flagNameRE = regexp.MustCompile(`^--[a-z0-9][a-z0-9._-]{0,62}$`)

// lookupPath follows a path through a decoded document.
func lookupPath(value any, path Path) (any, bool) {
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

// podSpecPath is the location of the pod spec of a workload kind.
var podSpecPath = map[string]Path{
	"Pod":                   {Key("spec")},
	"Deployment":            {Key("spec"), Key("template"), Key("spec")},
	"StatefulSet":           {Key("spec"), Key("template"), Key("spec")},
	"DaemonSet":             {Key("spec"), Key("template"), Key("spec")},
	"ReplicaSet":            {Key("spec"), Key("template"), Key("spec")},
	"ReplicationController": {Key("spec"), Key("template"), Key("spec")},
	"Job":                   {Key("spec"), Key("template"), Key("spec")},
	"CronJob":               {Key("spec"), Key("jobTemplate"), Key("spec"), Key("template"), Key("spec")},
}

// argElement is one string of a container's command or args list.
type argElement struct {
	path  Path
	value string
}

// containerRef is one regular container of a workload document.
type containerRef struct {
	image string
	// args are the strings of command, then args, in order. A separate
	// slice per list keeps "flag, value" pairs inside one list.
	lists [][]argElement
}

// containers returns the regular containers of a workload document, or none
// for any other document. A List that holds workloads is refused: its items
// are not addressed by this package.
func containers(doc intake.Document) ([]containerRef, error) {
	if doc.Kind == "List" {
		items, _ := doc.Value["items"].([]any)
		for _, item := range items {
			if entry, ok := item.(map[string]any); ok {
				kind, _ := entry["kind"].(string)
				if _, workload := podSpecPath[kind]; workload {
					return nil, kindRefused("a List holding workloads is not supported")
				}
			}
		}
		return nil, nil
	}
	base, ok := podSpecPath[doc.Kind]
	if !ok {
		return nil, nil
	}
	list, ok := lookupPath(doc.Value, append(append(Path{}, base...), Key("containers")))
	if !ok {
		return nil, nil
	}
	entries, _ := list.([]any)
	var out []containerRef
	for i, entry := range entries {
		container, ok := entry.(map[string]any)
		if !ok {
			continue
		}
		image, _ := container["image"].(string)
		ref := containerRef{image: image}
		for _, field := range []string{"command", "args"} {
			values, _ := container[field].([]any)
			var elements []argElement
			for j, value := range values {
				if text, ok := value.(string); ok {
					path := append(append(Path{}, base...), Key("containers"), Index(i), Key(field), Index(j))
					elements = append(elements, argElement{path: path, value: text})
				}
			}
			ref.lists = append(ref.lists, elements)
		}
		out = append(out, ref)
	}
	return out, nil
}

// classify says how a container relates to a component: it is the
// component's container (match), the container of another known component
// (neither flag), or an image the registry does not know (unknown).
func classify(image, component string) (match, unknown bool) {
	if image == "" {
		return false, true
	}
	id, known := localcollector.ComponentForImage(image)
	if !known {
		return false, true
	}
	return id == component, false
}

// tokenQuote returns the quote character of a located token, or 0 for a
// plain scalar.
func tokenQuote(raw string) byte {
	if len(raw) >= 2 && (raw[0] == '"' || raw[0] == '\'') {
		return raw[0]
	}
	return 0
}

// plainBody returns the text between the quotes of a quoted token, or the
// token itself, when that text equals the decoded value (no escapes).
func plainBody(raw, decoded string) (quote byte, ok bool) {
	quote = tokenQuote(raw)
	body := raw
	if quote != 0 {
		body = raw[1 : len(raw)-1]
	}
	return quote, body == decoded
}

func wrap(quote byte, text string) string {
	if quote == 0 {
		return text
	}
	return string(quote) + text + string(quote)
}
