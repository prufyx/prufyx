// SPDX-License-Identifier: AGPL-3.0-only

package knowledgegate

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// SOURCE-PREVIEW.json is typed by hand and has no generator, so it must not
// repeat any figure that the generated support inventory owns: a copy drifts
// (it once said 66 executable projects against 65, with a stale inventory
// digest). It points at the inventory instead.
func TestSourcePreviewJSONHoldsNoInventoryFigures(t *testing.T) {
	t.Parallel()
	read := func(rel string) []byte {
		raw, err := os.ReadFile(filepath.Join(repoRoot, filepath.FromSlash(rel)))
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	var inv struct {
		Counts map[string]json.RawMessage `json:"counts"`
	}
	if err := json.Unmarshal(read(inventoryJSON), &inv); err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Source map[string]json.RawMessage `json:"source"`
	}
	if err := json.Unmarshal(read("SOURCE-PREVIEW.json"), &doc); err != nil {
		t.Fatal(err)
	}
	if _, ok := doc.Source["inventorySha256"]; ok {
		t.Error("SOURCE-PREVIEW.json pins inventorySha256, which goes stale with every inventory change")
	}
	var counts map[string]json.RawMessage
	if err := json.Unmarshal(doc.Source["counts"], &counts); err != nil {
		t.Fatal(err)
	}
	for k := range counts {
		if _, ok := inv.Counts[k]; ok {
			t.Errorf("SOURCE-PREVIEW.json source.counts.%s repeats a generated inventory count", k)
		}
	}
}
