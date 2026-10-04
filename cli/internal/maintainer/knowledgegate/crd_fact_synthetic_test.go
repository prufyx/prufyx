// SPDX-License-Identifier: AGPL-3.0-only

//go:build prufyx_synthetic_knowledge

package knowledgegate

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/cncfcheck"
	"github.com/prufyx/prufyx/cli/internal/constraintengine"
	"github.com/prufyx/prufyx/cli/internal/extract"
	"github.com/prufyx/prufyx/cli/internal/extract/crdversions"
)

// The fact definition is the single switch: the CRD-derived Strimzi rules
// are refused by admission while their fact is unregistered and admitted,
// unchanged, once the definition is in the registry (with the pack's
// registry digest bumped to match), both by the engine's loader and by the
// gate's CNCF admission check.
func TestCRDRuleAdmissionNeedsOnlyTheFact(t *testing.T) {
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
	if restore, err := cncfcheck.UseSyntheticKnowledge(nil, entries); err == nil {
		restore()
		t.Fatal("rules with an unregistered fact were admitted")
	}
	tg, _ := crdversions.TargetFor("strimzi")
	def := []constraintengine.FactDefinition{{ID: tg.FactID(), Component: tg.Component, Type: constraintengine.FactSet}}
	restore, err := cncfcheck.UseSyntheticKnowledge(def, entries)
	if err != nil {
		t.Fatalf("rules with the fact registered: %v", err)
	}
	restore()

	// The gate: register the definition only, and give the head pack the
	// registry digest of the extended registry.
	restore, err = cncfcheck.UseSyntheticKnowledge(def, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer restore()
	raw, err := cncfcheck.ExportEmbeddedExternalBundle("1")
	if err != nil {
		t.Fatal(err)
	}
	var bundle struct {
		Pack struct {
			RegistryDigest string `json:"registryDigest"`
		} `json:"pack"`
	}
	if err := json.Unmarshal(raw, &bundle); err != nil || bundle.Pack.RegistryDigest == "" {
		t.Fatalf("registry digest: %v", err)
	}
	base, head := crdHead(t, maps, bundle.Pack.RegistryDigest)
	r := runGate(t, Options{Base: base, Head: head, Source: extract.FixtureReader{Root: strimziFixture}})
	if c, ok := check(r, "admit/cncf"); !ok || !c.OK {
		t.Fatalf("admission with the fact registered: %+v\n%v", c, failedChecks(r))
	}
}
