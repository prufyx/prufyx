// SPDX-License-Identifier: AGPL-3.0-only

package knowledgegate

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The first attested update of a pack that still holds an older schema moves
// the pack to the lowest schema its content requires. These tests state every
// condition of that admission (schema.go) and refuse each one's violation.

const (
	schemaRanged       = "prufyx.io/cncf-source-rule-pack/v1alpha2"
	schemaSet          = "prufyx.io/cncf-source-rule-pack/v1alpha3"
	schemaPathPolicies = "prufyx.io/cncf-source-rule-pack/v1alpha5"
)

// schemaTrees returns a base that holds the shipped (v1alpha2, unattested)
// pack and a head that adds the Argo CD CRD rules and their line attestations
// (the synthetic fixture of the CRD extractor) under headSchema. tamper edits
// the head pack further, before it is written. The head's derived files are
// regenerated only when the head pack loads (regen).
func schemaTrees(t *testing.T, headSchema string, tamper func(p *packDoc, atts *[]map[string]any)) (Tree, Tree) {
	t.Helper()
	entries, atts := argoDerivation(t, gateNow.Add(-time.Hour))
	base, head := trees(t)
	p := readPack(t, head, cncfRulesPath)
	p.entries = append(p.entries, entries...)
	p.sortByID()
	if tamper != nil {
		tamper(p, &atts)
	}
	sortRecords(atts)
	raw, err := json.Marshal(atts)
	if err != nil {
		t.Fatal(err)
	}
	p.fields["lineAttestations"] = raw
	p.fields["schema"] = json.RawMessage(`"` + headSchema + `"`)
	p.write(t, head, cncfRulesPath)
	if tamper == nil && headSchema == attestedPackSchema {
		regenerate(t, head)
	}
	return base, head
}

// setSchema writes a pack schema into a tree's pack without regenerating its
// derived files (the pack may not load).
func setSchema(t *testing.T, tr Tree, schema string) {
	t.Helper()
	p := readPack(t, tr, cncfRulesPath)
	p.fields["schema"] = json.RawMessage(`"` + schema + `"`)
	p.write(t, tr, cncfRulesPath)
}

func headPath(tr Tree, rel string) string { return filepath.Join(tr.Root, filepath.FromSlash(rel)) }

func schemaChange(t *testing.T, r *Report) *Change {
	t.Helper()
	for _, c := range r.Changes {
		if c.Member == "schema" {
			return c
		}
	}
	t.Fatalf("no schema change in %+v", r.Changes)
	return nil
}

func gateArgo(t *testing.T, base, head Tree) *Report {
	t.Helper()
	return runGate(t, Options{Base: base, Head: head, Source: argoFixture})
}

// requireSchemaRefused requires the schema change to be refused with want in
// its detail, and the gate to fail.
func requireSchemaRefused(t *testing.T, r *Report, want string) {
	t.Helper()
	c := schemaChange(t, r)
	if c.OK || c.Proof == ProofSchemaLevel || !strings.Contains(c.Detail, want) {
		t.Fatalf("schema change %+v, want a refusal mentioning %q", c, want)
	}
	if r.Passed() {
		t.Fatal("the gate passed with a refused schema change")
	}
}

// The factory's first attested update, at the size of the Argo CD fixture:
// v1alpha2 to v1alpha4 with two mechanical attestations and two mechanical
// rules, all re-derived. The whole gate passes. (The same step with ten
// Strimzi rules and no attestations, v1alpha2 to v1alpha3, is
// TestGateAdmitsCRDRules.)
func TestSchemaBumpAdmittedWithFirstAttestedUpdate(t *testing.T) {
	base, head := schemaTrees(t, attestedPackSchema, nil)
	r := gateArgo(t, base, head)
	if !r.Passed() {
		t.Fatalf("failed:\n%s", strings.Join(failedChecks(r), "\n"))
	}
	c := schemaChange(t, r)
	if !c.OK || c.Proof != ProofSchemaLevel || c.Class != ClassLoosening {
		t.Fatalf("schema change %+v", c)
	}
	rules, records := 0, 0
	for _, ch := range r.Changes {
		switch {
		case ch.Member != "":
		case ch.Section != "":
			records++
			if !ch.OK || ch.Proof != ProofRederived {
				t.Fatalf("record %+v", ch)
			}
		default:
			rules++
			if !ch.OK || ch.Proof != ProofRederived {
				t.Fatalf("rule %+v", ch)
			}
		}
	}
	if rules != 2 || records != 2 {
		t.Fatalf("%d rules, %d records", rules, records)
	}
}

// The first attested update (the schema level moves) is owner-merged: even
// when the gate passes and the automation account authored it, it is not
// eligible for automatic merging, and the reason names the schema level.
func TestSchemaBumpIsNeverAutoMerged(t *testing.T) {
	base, head := schemaTrees(t, attestedPackSchema, nil)
	r := runGate(t, Options{Base: base, Head: head, Source: argoFixture, Author: DefaultBotLogin})
	if !r.Passed() {
		t.Fatalf("failed:\n%s", strings.Join(failedChecks(r), "\n"))
	}
	if c := schemaChange(t, r); !c.OK || c.Proof != ProofSchemaLevel {
		t.Fatalf("schema change %+v", c)
	}
	if r.AutoMerge.Eligible || !strings.Contains(strings.Join(r.AutoMerge.Reasons, " "), "schema level of a pack") {
		t.Fatalf("eligible=%v reasons=%v", r.AutoMerge.Eligible, r.AutoMerge.Reasons)
	}
}

// The schema change is decided last: the gate built from the base decides, so
// a base without this admission refuses it exactly as before (the layout
// without the schema functions).
func TestSchemaBumpNeedsTheSchemaFunctions(t *testing.T) {
	base, head := schemaTrees(t, attestedPackSchema, nil)
	layout := DefaultLayout()
	for i := range layout.Packs {
		layout.Packs[i].RequiredSchema, layout.Packs[i].SchemaLevel = nil, nil
	}
	r := runGate(t, Options{Layout: layout, Base: base, Head: head, Source: argoFixture})
	requireFail(t, r, "only the pack's entries and records may change through this gate; the top-level member schema changed")
	if c := schemaChange(t, r); c.OK {
		t.Fatalf("admitted %+v", c)
	}
}

// Condition 1: the head's schema is exactly the lowest level its content
// requires.
func TestSchemaBumpHigherThanNeededRefused(t *testing.T) {
	base, head := schemaTrees(t, schemaPathPolicies, nil)
	r := gateArgo(t, base, head)
	requireSchemaRefused(t, r, "not the lowest level")
}

// Condition 1: a bump the content does not need (no attestation, no set
// rule) is refused, whichever level it names.
func TestSchemaBumpWithoutContentNeedingItRefused(t *testing.T) {
	for _, schema := range []string{schemaSet, attestedPackSchema} {
		base, head := trees(t)
		setSchema(t, head, schema)
		r := runGate(t, Options{Base: base, Head: head})
		requireSchemaRefused(t, r, "not the lowest level")
	}
	// The content needs the attested level, the head names a lower one.
	base, head := schemaTrees(t, schemaSet, nil)
	requireSchemaRefused(t, gateArgo(t, base, head), "not the lowest level")
}

// Condition 2: never a downgrade, never an unchanged level.
func TestSchemaDowngradeRefused(t *testing.T) {
	base, head := trees(t)
	setSchema(t, base, schemaSet)
	// The head holds the content of the shipped pack under its own level.
	r := runGate(t, Options{Base: base, Head: head})
	requireSchemaRefused(t, r, "not raised")
}

// Condition 2: a base schema the binary does not know is not a base to bump.
func TestSchemaBumpFromUnknownBaseRefused(t *testing.T) {
	base, head := schemaTrees(t, attestedPackSchema, nil)
	setSchema(t, base, "prufyx.io/cncf-source-rule-pack/v9")
	requireSchemaRefused(t, gateArgo(t, base, head), "base's schema is unknown")
}

// Condition 3: no other top-level member changes with the schema.
func TestSchemaBumpWithAnotherTopLevelChangeRefused(t *testing.T) {
	base, head := schemaTrees(t, attestedPackSchema, func(p *packDoc, _ *[]map[string]any) {
		p.fields["registryDigest"] = json.RawMessage(`"sha256:` + strings.Repeat("a", 64) + `"`)
	})
	r := gateArgo(t, base, head)
	requireSchemaRefused(t, r, "changed as well")
	for _, c := range r.Changes {
		if c.Member == "registryDigest" && c.OK {
			t.Fatalf("admitted %+v", c)
		}
	}
}

// Condition 4: every rule and record change is admitted by its own rules.
func TestSchemaBumpWithUnadmittedChangeRefused(t *testing.T) {
	for name, tamper := range map[string]func(p *packDoc, atts *[]map[string]any){
		"rule": func(p *packDoc, _ *[]map[string]any) {
			for _, e := range p.entries {
				if strings.HasPrefix(ruleID(e), "argo") {
					evidenceOf(e)["extractor"].(map[string]any)["version"] = "2.0.0"
					return
				}
			}
			t.Fatal("no argo rule")
		},
		"record": func(_ *packDoc, atts *[]map[string]any) {
			(*atts)[0]["evidence"].(map[string]any)["sources"].([]any)[0].(map[string]any)["endLine"] = json.Number("2")
		},
	} {
		t.Run(name, func(t *testing.T) {
			base, head := schemaTrees(t, attestedPackSchema, tamper)
			requireSchemaRefused(t, gateArgo(t, base, head), "not admitted")
		})
	}
}

// Condition 5: never in combination with trust material or registry files.
func TestSchemaBumpWithTrustOrRegistryChangeRefused(t *testing.T) {
	for name, rel := range map[string]string{
		"trust material": approvalKeys,
		"registry":       "cli/internal/cncfcheck/data/priority-portfolio.json",
	} {
		t.Run(name, func(t *testing.T) {
			base, head := schemaTrees(t, attestedPackSchema, nil)
			writeFile(t, headPath(head, rel), []byte("{}\n"))
			r := gateArgo(t, base, head)
			requireSchemaRefused(t, r, "in the same change")
		})
	}
}

// The community pack has no schema functions: its schema bump stays refused.
func TestCommunitySchemaBumpStaysRefused(t *testing.T) {
	base, head := trees(t)
	editPack(t, head, commRulesPath, func(p *packDoc) {
		p.fields["schema"] = []byte(`"` + communitySeverityPack + `"`)
		p.entries = append(p.entries, communitySupportEntry())
		sortCommunity(p)
	})
	r := runGate(t, Options{Base: base, Head: head})
	requireSchemaRefused(t, r, "no schema levels")
}

// The kill switch stops the schema change like any other loosening change.
func TestSchemaBumpStoppedByKillSwitch(t *testing.T) {
	base, head := schemaTrees(t, attestedPackSchema, nil)
	writeFile(t, headPath(head, "factory/PAUSE"), []byte("stop\n"))
	r := gateArgo(t, base, head)
	if c := schemaChange(t, r); c.OK {
		t.Fatalf("admitted %+v", c)
	}
	if r.Passed() {
		t.Fatal("passed while paused")
	}
}
