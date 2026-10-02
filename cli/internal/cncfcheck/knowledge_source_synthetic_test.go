// SPDX-License-Identifier: AGPL-3.0-only

//go:build prufyx_synthetic_knowledge

package cncfcheck

import (
	"errors"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/constraintengine"
)

// TestSyntheticKnowledgeCarriesSetRuleThroughExternalBundles: with the
// synthetic set rule installed, the embedded knowledge exports as an external
// bundle that the external parser admits under the set pack schema, and the
// seam restores the packaged knowledge afterwards.
func TestSyntheticKnowledgeCarriesSetRuleThroughExternalBundles(t *testing.T) {
	restore, err := UseSyntheticKnowledge([]constraintengine.FactDefinition{syntheticSetDefinition()}, []Entry{syntheticSetEntry(t)})
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
		t.Fatal("synthetic set fact not registered")
	}
	restore()
	if RegisteredFact(syntheticSetFact) {
		t.Fatal("restore left the synthetic fact registered")
	}
	// Under the packaged knowledge the same bundle no longer matches the
	// compiled registry and capability.
	if _, err := ParseExternalBundle(raw); !errors.Is(err, ErrIntegrity) && !errors.Is(err, ErrInvalid) {
		t.Fatalf("bundle admitted after restore: %v", err)
	}
	if _, err := UseSyntheticKnowledge(nil, []Entry{syntheticSetEntry(t)}); err == nil {
		t.Fatal("set rule over an unregistered fact installed")
	}
}
