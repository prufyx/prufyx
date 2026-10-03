// SPDX-License-Identifier: AGPL-3.0-only

package fix

import (
	"encoding/json"
	"fmt"
	"sort"
	"sync"

	"github.com/prufyx/prufyx/cli/internal/intake"
)

// Params are the parameters of one fix, as JSON. A kind decodes and bounds
// them itself in Validate.
type Params = json.RawMessage

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
// Plan is called once per mapping document of a file. doc carries the decoded
// document, src the raw bytes of the whole file. A kind returns no edits when
// the document needs no change; it locates its targets with Locator. It must
// be idempotent: planning on its own output returns no edits.
type Kind interface {
	ID() string
	Validate(params Params) error
	Plan(doc intake.Document, src []byte, params Params) ([]Edit, error)
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
