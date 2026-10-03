// SPDX-License-Identifier: AGPL-3.0-only

package knowledgegate

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/extract"
	"github.com/prufyx/prufyx/cli/internal/extract/k8sservedapis"
)

var servedFixture = filepath.Join("..", "..", "extract", "k8sservedapis", "testdata", "fixture")

var servedDerivedAt = time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)

// derivedEntries runs the served-API extractor over its frozen fixture, as
// the factory would over the mirror, and returns its pack entries.
func derivedEntries(t *testing.T) []map[string]any {
	t.Helper()
	repo, err := extract.ParseRepo(k8sservedapis.Repo)
	if err != nil {
		t.Fatal(err)
	}
	src := extract.FixtureReader{Root: servedFixture}
	out, err := extract.Run(context.Background(), k8sservedapis.New(0), src, src, extract.Options{Repo: repo, DerivedAt: servedDerivedAt})
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
	if len(entries) == 0 {
		t.Fatal("the extractor derived nothing")
	}
	return entries
}

// mechanicalTrees returns a base and a head where the head adds the rules
// the extractor derives (with tamper applied to the entries first). The
// engine refuses two rules constraining the same fact, so both trees first
// drop the reviewed rules for the derived facts, and derived rules whose
// fact this revision's registry lacks are left out.
func mechanicalTrees(t *testing.T, tamper func(entries []map[string]any)) (Tree, Tree, []map[string]any) {
	t.Helper()
	base, head := trees(t)
	var entries []map[string]any
	facts := map[string]bool{}
	for _, e := range derivedEntries(t) {
		fact := ruleOf(e)["condition"].(map[string]any)["factId"].(string)
		if fact == "component.kubernetes.selfsubjectreview_v1beta1_removed_gvk_present" {
			continue
		}
		facts[fact] = true
		entries = append(entries, e)
	}
	for _, tr := range []Tree{base, head} {
		editPack(t, tr, cncfRulesPath, func(p *packDoc) {
			var kept []map[string]any
			for _, e := range p.entries {
				if c, ok := ruleOf(e)["condition"].(map[string]any); ok && facts[c["factId"].(string)] {
					continue
				}
				kept = append(kept, e)
			}
			p.entries = kept
		})
	}
	if tamper != nil {
		tamper(entries)
	}
	editPack(t, head, cncfRulesPath, func(p *packDoc) {
		p.entries = append(p.entries, entries...)
		p.sortByID()
	})
	return base, head, entries
}

func TestGateMechanicalRederived(t *testing.T) {
	base, head, entries := mechanicalTrees(t, nil)
	r := runGate(t, Options{Base: base, Head: head, Source: extract.FixtureReader{Root: servedFixture}, Author: DefaultBotLogin})
	requirePass(t, r)
	if r.Totals.Loosening != len(entries) {
		t.Fatalf("loosening %d, want %d", r.Totals.Loosening, len(entries))
	}
	for _, c := range r.Changes {
		if c.Proof != ProofRederived || c.Basis != "mechanical" || c.Kinds[0] != KindNew {
			t.Fatalf("%s: %+v", c.RuleID, c)
		}
	}
	if !r.AutoMerge.Eligible {
		t.Fatalf("not eligible: %v", r.AutoMerge.Reasons)
	}
}

// The lease is the factory's choice (it staggers renewals), bounded by the
// engine's review window: the gate re-derives with the rule's own lease. A
// renewal is a re-derivation at a later time.
func TestGateMechanicalLeaseAndRenewal(t *testing.T) {
	base, head, _ := mechanicalTrees(t, func(entries []map[string]any) {
		for _, e := range entries {
			evidenceOf(e)["validUntil"] = shiftTime(t, evidenceOf(e)["validUntil"], -10*24*time.Hour)
		}
	})
	r := runGate(t, Options{Base: base, Head: head, Source: extract.FixtureReader{Root: servedFixture}})
	requirePass(t, r)

	// Renew every derived rule one week later: the head is what the
	// extractor derives at the new time.
	renewed := copyTree(t, head)
	editPack(t, renewed, cncfRulesPath, func(p *packDoc) {
		for _, e := range p.entries {
			ev := evidenceOf(e)
			if ev["basis"] != "mechanical" {
				continue
			}
			for _, k := range []string{"derivedAt", "reviewedAt", "validUntil"} {
				ev[k] = shiftTime(t, ev[k], 7*24*time.Hour)
			}
		}
	})
	r = runGate(t, Options{Base: head, Head: renewed, Source: extract.FixtureReader{Root: servedFixture}})
	requirePass(t, r)
	for _, c := range r.Changes {
		if c.Class != ClassLoosening || c.Kinds[0] != KindRenew || c.Proof != ProofRederived {
			t.Fatalf("%s: %+v", c.RuleID, c)
		}
	}
}

func copyTree(t *testing.T, src Tree) Tree {
	t.Helper()
	dst := t.TempDir()
	err := filepath.WalkDir(src.Root, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel, err := filepath.Rel(src.Root, p)
		if err != nil {
			return err
		}
		raw, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		writeFile(t, filepath.Join(dst, rel), raw)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return Tree{Root: dst}
}

// A mechanical rule that does not come out of the extractor byte for byte
// fails, whatever was changed.
func TestGateMechanicalTamperedFails(t *testing.T) {
	cases := map[string]struct {
		tamper func(e map[string]any)
		want   string
	}{
		"next action": {func(e map[string]any) { ruleOf(e)["nextAction"] = "Upgrade; nothing to do." }, "differs from what extractor"},
		"cited lines": {func(e map[string]any) {
			src := evidenceOf(e)["sources"].([]any)[0].(map[string]any)
			src["endLine"] = src["startLine"]
		}, "differs from what extractor"},
		"source digest": {func(e map[string]any) {
			src := evidenceOf(e)["sources"].([]any)[0].(map[string]any)
			src["contentDigest"] = "sha256:" + strings.Repeat("0", 64)
		}, "differs from what extractor"},
		"derivedAt": {func(e map[string]any) {
			evidenceOf(e)["derivedAt"] = shiftTime(t, evidenceOf(e)["derivedAt"], time.Hour)
		}, "differs from what extractor"},
		"rule id": {func(e map[string]any) { ruleOf(e)["id"] = ruleID(e) + ".x" }, "does not derive this rule"},
		"code digest": {func(e map[string]any) {
			evidenceOf(e)["extractor"].(map[string]any)["codeDigest"] = "sha256:" + strings.Repeat("1", 64)
		}, "this gate runs"},
		"extractor version": {func(e map[string]any) {
			evidenceOf(e)["extractor"].(map[string]any)["version"] = "9.9.9"
		}, "this gate runs"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			var tampered string
			base, head, _ := mechanicalTrees(t, func(entries []map[string]any) {
				tc.tamper(entries[0])
				tampered = ruleID(entries[0])
			})
			r := runGate(t, Options{Base: base, Head: head, Source: extract.FixtureReader{Root: servedFixture}})
			requireFail(t, r, tc.want)
			if c := change(t, r, tampered); c.OK {
				t.Fatal("the tampered rule was admitted")
			}
			for _, c := range r.Changes {
				if c.RuleID != tampered && !c.OK && !strings.Contains(tc.want, "this gate runs") {
					t.Fatalf("untampered rule %s failed: %s", c.RuleID, c.Detail)
				}
			}
		})
	}
}

// Without an upstream source, or with one whose bytes differ, nothing
// mechanical is admitted.
func TestGateMechanicalNeedsUpstream(t *testing.T) {
	base, head, _ := mechanicalTrees(t, nil)
	r := runGate(t, Options{Base: base, Head: head})
	requireFail(t, r, "no upstream source is configured")
	r = runGate(t, Options{Base: base, Head: head, Source: extract.FixtureReader{Root: t.TempDir()}})
	requireFail(t, r, "re-derivation failed")
}

// The scheduled run re-derives every active mechanical rule, changed or
// not.
func TestGateRederiveAll(t *testing.T) {
	_, head, _ := mechanicalTrees(t, nil)
	r := runGate(t, Options{Base: head, Head: head, Source: extract.FixtureReader{Root: servedFixture}, RederiveAll: true})
	requirePass(t, r)
	if c, ok := check(r, "rederive-all"); !ok || !strings.HasPrefix(c.Detail, "5 mechanical rules re-derived, 0 failed") {
		t.Fatalf("rederive-all %+v", c)
	}
	r = runGate(t, Options{Base: head, Head: head, Source: extract.FixtureReader{Root: t.TempDir()}, RederiveAll: true})
	requireFail(t, r, "rederive-all")
}
