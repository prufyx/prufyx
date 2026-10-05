// SPDX-License-Identifier: AGPL-3.0-only

//go:build prufyx_synthetic_knowledge

package extractpack_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/cncfcheck"
	"github.com/prufyx/prufyx/cli/internal/constraintengine"
	"github.com/prufyx/prufyx/cli/internal/extract/extractpack"
)

// With the facts of the whole run registered (synthetic knowledge, as the
// knowledge gate's own tests do), the merged pack is admitted by the real
// engine loader with its attestations: the exact-set check and the pack
// schema included.
func TestSyntheticApplyAdmittedWithAttestations(t *testing.T) {
	for _, c := range []kase{cases[1]} {
		t.Run(c.name, func(t *testing.T) {
			run := runDir(t, c, derivedAt)
			pack := prunedPack(t, "cncf", run)
			base, _ := os.ReadFile(pack)
			known := map[string]bool{}
			var doc struct {
				Entries []struct {
					RequiredFacts []struct {
						ID string `json:"id"`
					} `json:"requiredFacts"`
				} `json:"entries"`
			}
			if err := json.Unmarshal(base, &doc); err != nil {
				t.Fatal(err)
			}
			for _, e := range doc.Entries {
				for _, f := range e.RequiredFacts {
					known[f.ID] = true
				}
			}
			// Also the facts of the pruned-away reviewed rules stay registered.
			full, _ := os.ReadFile("../../cncfcheck/data/rules.json")
			doc.Entries = nil
			if err := json.Unmarshal(full, &doc); err != nil {
				t.Fatal(err)
			}
			for _, e := range doc.Entries {
				for _, f := range e.RequiredFacts {
					known[f.ID] = true
				}
			}
			var cands []struct {
				RequiredFacts []struct {
					ID, Component, Type string
					EnumTokens          []string
				} `json:"requiredFacts"`
			}
			readJSON(t, filepath.Join(run, "candidates.json"), &cands)
			var defs []constraintengine.FactDefinition
			seen := map[string]bool{}
			for _, e := range cands {
				for _, f := range e.RequiredFacts {
					if !known[f.ID] && !cncfcheck.RegisteredFact(f.ID) && !seen[f.ID] {
						seen[f.ID] = true
						defs = append(defs, constraintengine.FactDefinition{ID: f.ID, Component: f.Component, Type: constraintengine.FactType(f.Type), EnumTokens: f.EnumTokens})
					}
				}
			}
			restore, err := cncfcheck.UseSyntheticKnowledge(defs, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer restore()
			bundle, err := cncfcheck.ExportEmbeddedExternalBundle("1")
			if err != nil {
				t.Fatal(err)
			}
			var b struct {
				Pack struct {
					RegistryDigest string `json:"registryDigest"`
				} `json:"pack"`
			}
			if err := json.Unmarshal(bundle, &b); err != nil {
				t.Fatal(err)
			}
			// The base pack carries the extended registry's digest.
			p, _ := extractpack.ParsePack(base)
			p.Members["registryDigest"], _ = json.Marshal(b.Pack.RegistryDigest)
			out, _ := p.Render()
			if err := os.WriteFile(pack, out, 0o644); err != nil {
				t.Fatal(err)
			}
			rep, err := extractpack.Apply(extractpack.Options{PackPath: pack, RunDir: run})
			if err != nil {
				t.Fatal(err)
			}
			if !equalStrings(rep.Added, ruleIDs(t, run)) {
				t.Fatalf("%+v", rep)
			}
			t.Logf("%s: %d rules, %d attestations, schema %s -> %s", c.name, len(rep.Added), len(rep.AttAdded), rep.SchemaFrom, rep.SchemaTo)
			if c.name == "served-apis" && len(rep.AttAdded) == 0 {
				t.Fatal("no attestation merged")
			}
		})
	}
}
