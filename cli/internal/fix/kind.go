// SPDX-License-Identifier: AGPL-3.0-only

package fix

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"

	"github.com/prufyx/prufyx/cli/internal/intake"
)

// Params are the parameters of one fix, as JSON. They are at most
// MaxParamsBytes long, valid JSON without duplicate object keys, and are
// parsed once: Validate decodes and bounds them and returns the value that
// Plan then receives.
type Params = json.RawMessage

const (
	// MaxParamsBytes bounds the parameters of one fix.
	MaxParamsBytes = 64 << 10
	// maxParamsDepth bounds the nesting of the parameters.
	maxParamsDepth = 32
)

// Edit replaces the bytes [StartByte, EndByte) of File with Replacement.
// File is the display name the document was decoded under.
type Edit struct {
	File        string
	StartByte   int
	EndByte     int
	Replacement string
}

// Kind is one compiled fix kind.
//
// Validate decodes and bounds the parameters once per request and returns the
// parsed value (any type, nil allowed). Plan receives exactly that value, so
// the parameters that were validated are the parameters that are applied; it
// must treat the value as read-only.
//
// Plan is called once per mapping document of a file. doc carries the decoded
// document, src a private copy of the raw bytes of the whole file (a kind
// that writes into it is refused). A kind returns no edits when the document
// needs no change; it locates its targets with Locator. It must be
// idempotent: planning on its own output returns no edits.
//
// An error returned from Plan is passed on only when it is a *Refusal with a
// reason from the closed list and a Detail that is a fixed printable-ASCII
// string of at most 256 bytes; Detail must never carry file content or
// parameter values. Any other error becomes KIND_REFUSED.
type Kind interface {
	ID() string
	Validate(params Params) (parsed any, err error)
	Plan(doc intake.Document, src []byte, parsed any) ([]Edit, error)
}

// checkParams bounds and pre-validates parameters before a kind sees them:
// size, valid JSON, no duplicate keys (also when compared without case) and a
// bounded depth. Empty parameters are allowed.
func checkParams(params Params) *Refusal {
	if len(params) == 0 {
		return nil
	}
	if len(params) > MaxParamsBytes {
		return refuse(ReasonLimit, "the fix parameters are larger than the limit")
	}
	if !json.Valid(params) {
		return refuse(ReasonInvalidParams, "the fix parameters are not valid JSON")
	}
	type frame struct {
		object    bool
		expectKey bool
		keys      map[string]bool
	}
	var stack []frame
	valueDone := func() {
		if n := len(stack); n > 0 && stack[n-1].object {
			stack[n-1].expectKey = true
		}
	}
	decoder := json.NewDecoder(bytes.NewReader(params))
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return refuse(ReasonInvalidParams, "the fix parameters are not valid JSON")
		}
		if delim, ok := token.(json.Delim); ok {
			switch delim {
			case '{', '[':
				if len(stack) >= maxParamsDepth {
					return refuse(ReasonInvalidParams, "the fix parameters are nested too deeply")
				}
				stack = append(stack, frame{object: delim == '{', expectKey: delim == '{', keys: map[string]bool{}})
			default:
				stack = stack[:len(stack)-1]
				valueDone()
			}
			continue
		}
		if n := len(stack); n > 0 && stack[n-1].object && stack[n-1].expectKey {
			key, _ := token.(string)
			folded := strings.ToLower(key)
			if stack[n-1].keys[folded] {
				return refuse(ReasonInvalidParams, "the fix parameters repeat an object key")
			}
			stack[n-1].keys[folded] = true
			stack[n-1].expectKey = false
			continue
		}
		valueDone()
	}
}

var registry = struct {
	sync.Mutex
	kinds  map[string]Kind
	sealed bool
}{kinds: map[string]Kind{}}

// Register adds a compiled kind. It is meant for package init functions: it
// panics on an invalid or duplicate id, and after the first lookup.
func Register(kind Kind) {
	registry.Lock()
	defer registry.Unlock()
	if registry.sealed {
		panic("fix: Register called after the registry was used")
	}
	if kind == nil {
		panic("fix: Register called with a nil kind")
	}
	id := kind.ID()
	if !validKindID(id) {
		panic(fmt.Sprintf("fix: invalid kind id %q", id))
	}
	if _, duplicate := registry.kinds[id]; duplicate {
		panic(fmt.Sprintf("fix: duplicate kind id %q", id))
	}
	registry.kinds[id] = kind
}

// Lookup returns the kind with the given id. The first call seals the
// registry.
func Lookup(id string) (Kind, bool) {
	registry.Lock()
	defer registry.Unlock()
	registry.sealed = true
	kind, ok := registry.kinds[id]
	return kind, ok
}

// Kinds returns the registered ids in sorted order and seals the registry.
func Kinds() []string {
	registry.Lock()
	defer registry.Unlock()
	registry.sealed = true
	ids := make([]string, 0, len(registry.kinds))
	for id := range registry.kinds {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

func validKindID(id string) bool {
	if len(id) == 0 || len(id) > 64 || id[0] < 'a' || id[0] > 'z' {
		return false
	}
	for i := 0; i < len(id); i++ {
		c := id[i]
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_') {
			return false
		}
	}
	return true
}
