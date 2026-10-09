// SPDX-License-Identifier: AGPL-3.0-only

package cncfcheck

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/constraintengine"
)

// syntheticCrossingEntry is the synthetic removed-gate rule plus a crossing
// object. It is test-only and never published: the embedded pack is unchanged.
func syntheticCrossingEntry(t *testing.T) Entry {
	t.Helper()
	entry := syntheticSetEntry(t)
	crossing := `"crossing":{"change":{"version":"1.37.0","basis":"REMOVED_IN_RELEASE","sourceId":"synthetic-gate-declaration"},"horizon":{"lt":"1.40.0","basis":"REVIEWED_THROUGH_MINOR_LINE","sourceId":"synthetic-gate-declaration"}},`
	entry.Rule = json.RawMessage(strings.Replace(string(entry.Rule), `"evidence":`, crossing+`"evidence":`, 1))
	return entry
}

func TestPackCrossingLevel(t *testing.T) {
	entry := syntheticCrossingEntry(t)
	var extra []constraintengine.FactDefinition
	if _, err := assembleSynthetic(syntheticPack(t, packSchemaCrossing, extra, entry), extra); err != nil {
		t.Fatalf("crossing pack under the crossing level refused: %v", err)
	}
	for _, schema := range []string{packSchema, packSchemaRanged, packSchemaSet, packSchemaAttested, packSchemaPathPolicies, packSchemaNotice, packSchemaBasis, packSchemaSeverity, packSchemaDistributions, packSchemaServedAPIs} {
		if _, err := assembleSynthetic(syntheticPack(t, schema, extra, entry), extra); !errors.Is(err, ErrIntegrity) {
			t.Fatalf("crossing pack under %s accepted: %v", schema, err)
		}
	}
	if _, err := assembleSynthetic(syntheticPack(t, packSchemaCrossing, nil), nil); !errors.Is(err, ErrIntegrity) {
		t.Fatal("crossing level without a crossing rule accepted")
	}
	// A crossing on a non-forbid operator is refused by the engine.
	wrong := entry
	wrong.Rule = json.RawMessage(strings.Replace(string(entry.Rule), `"operator":"forbid_set_member"`, `"operator":"forbid_target_version"`, 1))
	if _, err := assembleSynthetic(syntheticPack(t, packSchemaCrossing, extra, wrong), extra); err == nil {
		t.Fatal("crossing on forbid_target_version accepted")
	}
}
