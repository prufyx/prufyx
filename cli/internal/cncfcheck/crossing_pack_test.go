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
	crossing := `"crossing":{"change":{"version":"1.39.0","basis":"REMOVED_IN_RELEASE","sourceId":"synthetic-gate-declaration"},"horizon":{"lt":"1.42.0","basis":"REVIEWED_THROUGH_MINOR_LINE","sourceId":"synthetic-gate-declaration"}},`
	entry.Rule = json.RawMessage(strings.Replace(string(entry.Rule), `"evidence":`, crossing+`"evidence":`, 1))
	return entry
}

func TestPackCrossingLevel(t *testing.T) {
	t.Parallel()
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

// A removal-crossing rule is carried by the embedded pack only: every
// external envelope derived from a pack leaves it out, at the schema level the
// remaining content requires, while an external pack that holds one is still
// refused and a pack without one keeps its bytes.
func TestExternalEnvelopeLeavesCrossingRulesOut(t *testing.T) {
	t.Parallel()
	entry := syntheticCrossingEntry(t)
	withRaw := syntheticPack(t, packSchemaCrossing, nil, entry)
	with, err := assembleSynthetic(withRaw, nil)
	if err != nil {
		t.Fatalf("crossing pack refused: %v", err)
	}
	kept, err := externalEntries(with.pack.Entries)
	if err != nil || len(kept) != len(with.pack.Entries)-1 {
		t.Fatalf("kept %d of %d entries: %v", len(kept), len(with.pack.Entries), err)
	}
	for _, e := range kept {
		if ruleID(t, e) == ruleID(t, entry) {
			t.Fatal("the crossing rule was kept")
		}
	}
	stripped, err := externalPack(with.pack)
	if err != nil {
		t.Fatal(err)
	}
	if want, _ := requiredPackSchema(stripped); stripped.Schema != want || stripped.Schema == packSchemaCrossing {
		t.Fatalf("schema %s after the crossing rule left, required %s", stripped.Schema, want)
	}
	raw, err := encodeExternalEnvelopeWithRecords(with, "1", "operator_provided", with.pack.Entries, recordSections{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := parseExternalBundle(raw, &with); err != nil {
		t.Fatalf("envelope without the crossing rule refused: %v", err)
	}
	if strings.Contains(string(raw), ruleID(t, entry)) {
		t.Fatal("the envelope carries the crossing rule")
	}
	// The guard stays: an external pack holding the rule is refused.
	held := stripped
	held.Entries = with.pack.Entries
	held.Schema = packSchemaCrossing
	if err := validateExternalPack(with, held, "1", false, false); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("external pack holding a crossing rule: %v", err)
	}
	// A pack without a crossing rule is returned as it is.
	plain := syntheticBase(t)
	same, err := externalEntries(plain.Entries)
	if err != nil || len(same) != len(plain.Entries) || (len(same) > 0 && &same[0] != &plain.Entries[0]) {
		t.Fatalf("a pack without a crossing rule changed: %v", err)
	}
}
