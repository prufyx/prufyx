// SPDX-License-Identifier: AGPL-3.0-only

package knowledgegate

import (
	"bytes"
	"fmt"

	"github.com/prufyx/prufyx/cli/internal/customresources"
	"github.com/prufyx/prufyx/cli/internal/strictjson"
)

// defaultTablePath is the reviewed custom-resource table of the shipped
// layout.
const defaultTablePath = "cli/internal/customresources/table.json"

// tableRead is the custom-resource table of one tree as the gate reads it.
type tableRead struct {
	raw      []byte
	projects []customresources.Project
	reserved []customresources.ReservedGroup
}

// readTableTree reads the table at path of t the one way the gate reads it,
// for the onboarding checks and for the coverage report alike: a bounded read
// that refuses links and special files, strict JSON (one value, no repeated
// or case-folded member names, valid UTF-8), the table loader of the base's
// code (unknown fields, trailing data, schema, validation) and the canonical
// spelling of the loaded table. Any failure is an error; there is no
// fallback to the table embedded in the running program.
func readTableTree(t Tree, path string) (tableRead, error) {
	var tr tableRead
	var err error
	if tr.raw, err = t.Read(path, MaxFileBytes); err != nil {
		return tableRead{}, err
	}
	if err := strictjson.Check(tr.raw); err != nil {
		return tableRead{}, fmt.Errorf("%s: %v", path, err)
	}
	if tr.projects, tr.reserved, err = customresources.LoadTable(tr.raw); err != nil {
		return tableRead{}, fmt.Errorf("the custom-resource table does not load: %v", logSafe(err.Error()))
	}
	if canonical, err := customresources.CanonicalTable(tr.projects, tr.reserved); err != nil || !bytes.Equal(canonical, tr.raw) {
		return tableRead{}, fmt.Errorf("%s is not in its canonical spelling", path)
	}
	return tr, nil
}
