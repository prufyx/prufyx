// SPDX-License-Identifier: AGPL-3.0-only

package cncfcheck

import (
	"encoding/json"
	"os"
	"testing"
)

// PackSchemaLevel orders the schemas by the features that introduced them,
// and RequiredPackSchema agrees with the schema the shipped pack carries.
func TestPackSchemaLevelAndRequired(t *testing.T) {
	prev := -1
	for _, s := range []string{packSchema, packSchemaRanged, packSchemaSet, packSchemaAttested, packSchemaPathPolicies, packSchemaNotice, packSchemaBasis, packSchemaSeverity, packSchemaDistributions, packSchemaServedAPIs, packSchemaCrossing} {
		level, ok := PackSchemaLevel(s)
		if !ok || level <= prev {
			t.Fatalf("%s: level %d ok=%v after %d", s, level, ok, prev)
		}
		prev = level
	}
	if _, ok := PackSchemaLevel("prufyx.io/cncf-source-rule-pack/v99"); ok {
		t.Fatal("an unknown schema has a level")
	}
	raw, err := os.ReadFile("data/rules.json")
	if err != nil {
		t.Fatal(err)
	}
	got, err := RequiredPackSchema(raw)
	if err != nil {
		t.Fatal(err)
	}
	var shipped struct {
		Schema string `json:"schema"`
	}
	if err := json.Unmarshal(raw, &shipped); err != nil {
		t.Fatal(err)
	}
	if got != shipped.Schema {
		t.Fatalf("required %s, shipped %s", got, shipped.Schema)
	}
	if _, err := RequiredPackSchema([]byte(`{"schema":"x","schema":"y"}`)); err == nil {
		t.Fatal("a repeated member was read")
	}
}
