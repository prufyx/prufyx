// SPDX-License-Identifier: AGPL-3.0-only

//go:build prufyx_synthetic_knowledge

package cncfcheck

import (
	"strings"
	"testing"
)

// TestSyntheticKnowledgeCarriesSetRuleThroughExternalBundles: with the
// synthetic set rule installed, the embedded knowledge exports as an external
// bundle that the external parser admits under the set pack schema, and the
// seam restores the packaged knowledge afterwards.
func TestSyntheticKnowledgeCarriesSetRuleThroughExternalBundles(t *testing.T) {
	restore, err := UseSyntheticKnowledge(nil, []Entry{syntheticSetEntry(t)})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := ExportEmbeddedExternalBundle("7")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"schema":"`+packSchemaSet+`"`) || !strings.Contains(string(raw), syntheticRuleID) {
		t.Fatal("exported bundle does not carry the set rule under the set schema")
	}
	if _, err := ParseExternalBundle(raw); err != nil {
		t.Fatalf("external bundle with a set rule refused: %v", err)
	}
	if !RegisteredFact(syntheticSetFact) {
		t.Fatal("the feature-gate set fact is not registered")
	}
	restore()
	// The registry declares the feature-gate set facts, so the exported
	// bundle still parses; the restored packaged knowledge must not carry
	// the synthetic rule.
	embedded, err := ExportEmbeddedExternalBundle("7")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(embedded), syntheticRuleID) || strings.Contains(string(embedded), `"schema":"`+packSchemaSet+`"`) {
		t.Fatal("restore left the synthetic set rule in the packaged knowledge")
	}
	if _, err := UseSyntheticKnowledge(nil, []Entry{unregisteredSetEntry(t)}); err == nil {
		t.Fatal("set rule over an unregistered fact installed")
	}
}
