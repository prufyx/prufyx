// SPDX-License-Identifier: AGPL-3.0-only

package projectcheck

import (
	"encoding/json"
	"testing"
)

// TestCommunityPackSchemaStatesRangeUse: the embedded community pack has no
// range and keeps its schema; any rule with a range requires the new schema.
func TestCommunityPackSchemaStatesRangeUse(t *testing.T) {
	b, err := load()
	if err != nil {
		t.Fatal(err)
	}
	if b.pack.Schema != packSchema || !validPackSchema(b.pack) {
		t.Fatalf("embedded community pack schema=%s", b.pack.Schema)
	}
	ranged := b.pack
	ranged.Entries = append([]entry(nil), b.pack.Entries...)
	var rule map[string]json.RawMessage
	if err := json.Unmarshal(ranged.Entries[0].Rule, &rule); err != nil {
		t.Fatal(err)
	}
	rule["range"] = json.RawMessage(`{}`)
	raw, err := json.Marshal(rule)
	if err != nil {
		t.Fatal(err)
	}
	ranged.Entries[0].Rule = raw
	if validPackSchema(ranged) {
		t.Fatal("range accepted under the exact-only community schema")
	}
	ranged.Schema = packSchemaRanged
	if !validPackSchema(ranged) {
		t.Fatal("ranged schema refused for a ranged pack")
	}
	exact := b.pack
	exact.Schema = packSchemaRanged
	if validPackSchema(exact) {
		t.Fatal("exact-only community pack accepted under the ranged schema")
	}
}
