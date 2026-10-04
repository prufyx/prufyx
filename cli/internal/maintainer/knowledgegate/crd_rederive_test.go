// SPDX-License-Identifier: AGPL-3.0-only

package knowledgegate

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/cncfcheck"
	"github.com/prufyx/prufyx/cli/internal/constraintengine"
	"github.com/prufyx/prufyx/cli/internal/extract"
	"github.com/prufyx/prufyx/cli/internal/extract/crdversions"
	"github.com/prufyx/prufyx/cli/internal/extract/extractcli"
)

var strimziFixture = filepath.Join("..", "..", "extract", "crdversions", "testdata", "strimzi")

// crdEntries runs the CRD version-removal extractor for Strimzi over its
// frozen fixture, as the factory would over the mirror.
func crdEntries(t *testing.T, at time.Time) []map[string]any {
	t.Helper()
	tg, ok := crdversions.TargetFor("strimzi")
	if !ok {
		t.Fatal("no strimzi target")
	}
	repo, err := extract.ParseRepo(tg.Repo)
	if err != nil {
		t.Fatal(err)
	}
	src := extract.FixtureReader{Root: strimziFixture}
	out, err := extract.Run(context.Background(), crdversions.New(tg), src, src, extract.Options{Repo: repo, DerivedAt: at})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := extract.Canonical(out.Entries)
	if err != nil {
		t.Fatal(err)
	}
	var entries []map[string]any
	if err := json.Unmarshal(raw, &entries); err != nil {
		t.Fatal(err)
	}
	if len(entries) != 10 {
		t.Fatalf("%d entries", len(entries))
	}
	return entries
}

// crdChanges turns entries into new-rule changes of the CNCF pack, read as
// admission reads them.
func crdChanges(t *testing.T, entries []map[string]any) []*Change {
	t.Helper()
	var out []*Change
	for _, e := range entries {
		raw, err := json.Marshal(e)
		if err != nil {
			t.Fatal(err)
		}
		admitted, err := cncfcheck.AdmittedEntry(raw)
		if err != nil {
			t.Fatalf("%s: %v", ruleID(e), err)
		}
		h, err := newEntry(admitted)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, &Change{Pack: "cncf", RuleID: h.RuleID, Project: h.Project, Class: ClassLoosening, Kinds: []string{KindNew}, Basis: constraintengine.BasisMechanical, head: h})
	}
	return out
}

// The gate's re-derivation reproduces every CRD-derived rule from the
// pinned bytes, and refuses each one that does not come out of the
// extractor byte for byte.
func TestGateRederivesCRDRules(t *testing.T) {
	src := extract.FixtureReader{Root: strimziFixture}
	changes := crdChanges(t, crdEntries(t, gateNow.Add(-time.Hour)))
	rederive(context.Background(), src, extractcli.Catalog(), 0, DefaultLayout(), changes)
	for _, c := range changes {
		if !c.OK || c.Proof != ProofRederived {
			t.Fatalf("%s: %+v", c.RuleID, c)
		}
	}

	const kafka = "strimzi.crd-version-removal.kafkas-kafka-strimzi-io.0-51-0-to-1-0-0"
	cases := map[string]struct {
		tamper func(e map[string]any)
		want   string
	}{
		"member dropped": {func(e map[string]any) {
			ruleOf(e)["setCondition"].(map[string]any)["members"] = []any{"kafka.strimzi.io/v1beta1/Kafka"}
		}, "differs from what extractor"},
		"subject moved": {func(e map[string]any) { ruleOf(e)["subject"].(map[string]any)["to"] = "1.1.0" }, "differs from what extractor"},
		"next action":   {func(e map[string]any) { ruleOf(e)["nextAction"] = "nothing to do" }, "differs from what extractor"},
		"cited lines": {func(e map[string]any) {
			s := evidenceOf(e)["sources"].([]any)[1].(map[string]any)
			s["startLine"] = s["endLine"]
		}, "differs from what extractor"},
		"rule id": {func(e map[string]any) { ruleOf(e)["id"] = kafka + "-x" }, "does not derive this rule"},
		"other project's extractor": {func(e map[string]any) {
			evidenceOf(e)["extractor"].(map[string]any)["id"] = "crd.version-removal.istio"
		}, "re-derivation failed"},
		"code digest": {func(e map[string]any) {
			evidenceOf(e)["extractor"].(map[string]any)["codeDigest"] = "sha256:" + strings.Repeat("1", 64)
		}, "this gate runs"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			entries := crdEntries(t, gateNow.Add(-time.Hour))
			for _, e := range entries {
				if ruleID(e) == kafka {
					tc.tamper(e)
				}
			}
			changes := crdChanges(t, entries)
			rederive(context.Background(), src, extractcli.Catalog(), 0, DefaultLayout(), changes)
			tampered := 0
			for _, c := range changes {
				if strings.HasPrefix(c.RuleID, kafka) {
					tampered++
					if c.OK || !strings.Contains(c.Detail, tc.want) {
						t.Fatalf("tampered rule: ok=%v %q, want %q", c.OK, c.Detail, tc.want)
					}
				} else if !c.OK && name != "other project's extractor" {
					t.Fatalf("untampered rule %s failed: %s", c.RuleID, c.Detail)
				}
			}
			if tampered != 1 {
				t.Fatalf("%d tampered changes", tampered)
			}
		})
	}

	// Other upstream bytes (the synthetic Argo CD fixture holds no Strimzi
	// repository) re-derive nothing.
	changes = crdChanges(t, crdEntries(t, gateNow.Add(-time.Hour)))
	rederive(context.Background(), extract.FixtureReader{Root: t.TempDir()}, extractcli.Catalog(), 0, DefaultLayout(), changes)
	for _, c := range changes {
		if c.OK || !strings.Contains(c.Detail, "re-derivation failed") {
			t.Fatalf("%s: %+v", c.RuleID, c)
		}
	}
}

// crdSetPackSchema is the pack level of a pack holding a set rule. The CRD
// rules are the first set rules of the CNCF pack, so the head carries it;
// the registry digest stays the compiled registry's.
const crdSetPackSchema = "prufyx.io/cncf-source-rule-pack/v1alpha3"

// crdHead returns base and head trees where the head adds the CRD-derived
// rules with every pack-level condition of admission met (schema level,
// sorted entries, the current registry digest), so admission can only
// refuse at the fact check.
func crdHead(t *testing.T, entries []map[string]any, registryDigest string) (Tree, Tree) {
	t.Helper()
	base, head := trees(t)
	p := readPack(t, head, cncfRulesPath)
	p.entries = append(p.entries, entries...)
	p.sortByID()
	p.fields["schema"] = json.RawMessage(`"` + crdSetPackSchema + `"`)
	if registryDigest != "" {
		p.fields["registryDigest"] = json.RawMessage(`"` + registryDigest + `"`)
	}
	p.write(t, head, cncfRulesPath)
	return base, head
}

// A CRD-derived rule reads a set fact no adapter declares, and the fact
// registry of this revision lacks it: even a rule the gate re-derives
// exactly cannot enter the CNCF pack. The synthetic-knowledge test
// (crd_fact_synthetic_test.go) shows that registering the fact definition
// alone makes the same rules admissible.
func TestGateRefusesCRDRulesWithoutRegisteredFact(t *testing.T) {
	for _, tg := range crdversions.Targets {
		if cncfcheck.RegisteredFact(tg.FactID()) {
			t.Fatalf("%s is registered: this test no longer shows why the rules stay out of the pack", tg.FactID())
		}
	}
	entries := crdEntries(t, gateNow.Add(-time.Hour))
	base, head := crdHead(t, entries, "")
	r := runGate(t, Options{Base: base, Head: head, Source: extract.FixtureReader{Root: strimziFixture}})
	requireFail(t, r, "admit/cncf: the engine does not admit the pack")
	for _, e := range entries {
		if c := change(t, r, ruleID(e)); !c.OK || c.Proof != ProofRederived {
			t.Fatalf("%s: re-derivation %+v", c.RuleID, c)
		}
	}
}
