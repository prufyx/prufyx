// SPDX-License-Identifier: AGPL-3.0-only

//go:build prufyx_synthetic_knowledge

package knowledgegate

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/cncfcheck"
	"github.com/prufyx/prufyx/cli/internal/constraintengine"
	"github.com/prufyx/prufyx/cli/internal/extract/crdversions"
)

// The build registers the custom-resource version set, so the engine's
// loader admits the CRD-derived Strimzi rules unchanged, with no extra fact
// definition; registering the definition a second time is refused.
func TestCRDRuleAdmissionUsesTheRegisteredFact(t *testing.T) {
	maps := crdEntries(t, gateNow.Add(-time.Hour))
	var entries []cncfcheck.Entry
	for _, e := range maps {
		raw, err := json.Marshal(e)
		if err != nil {
			t.Fatal(err)
		}
		var entry cncfcheck.Entry
		if err := json.Unmarshal(raw, &entry); err != nil {
			t.Fatal(err)
		}
		entries = append(entries, entry)
	}
	restore, err := cncfcheck.UseSyntheticKnowledge(nil, entries)
	if err != nil {
		t.Fatalf("rules over the registered fact refused: %v", err)
	}
	restore()
	tg, _ := crdversions.TargetFor("strimzi")
	def := []constraintengine.FactDefinition{{ID: tg.FactID(), Component: tg.Component, Type: constraintengine.FactSet}}
	if restore, err := cncfcheck.UseSyntheticKnowledge(def, entries); err == nil {
		restore()
		t.Fatal("a second definition of the registered fact was accepted")
	}
}
