// SPDX-License-Identifier: AGPL-3.0-only

package evidencereattest

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// markMechanical turns a test rule's evidence into a mechanically derived one.
func markMechanical(rule map[string]any, derivedAt string) {
	evidence := rule["evidence"].(map[string]any)
	evidence["basis"] = "mechanical"
	evidence["extractor"] = map[string]any{"id": "example.removal", "version": "1.0.0", "codeDigest": "sha256:" + strings.Repeat("ab", 32)}
	evidence["derivedAt"] = derivedAt
}

func TestPrepareRefusesToRenewMechanicalRule(t *testing.T) {
	packPath := "/repo/cli/internal/cncfcheck/data/rules.json"
	reviewed := freshSpec("rule-a", "proj-a", baseNow)
	mechanical := freshSpec("rule-b", "proj-b", baseNow)
	mechanical.mechanical = true
	wl, pack := buildWorklistAndPack(t, packPath, baseNow, []ruleSpec{reviewed, mechanical})

	result, err := Prepare(PrepareOptions{
		WorklistRaw: marshalWorklist(t, wl), PackName: PackCNCF, PackPath: packPath, PackRaw: pack,
		Wave: 1, AttestedAt: baseNow, Now: baseNow, NextRevision: "rev-2", EngineCapabilityDigest: testEngineCapabilityDigest, Chain: &Chain{},
	})
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	if len(result.Statement.Rules) != 1 || result.Statement.Rules[0].RuleID != "rule-a" {
		t.Fatalf("expected only the reviewed rule renewed, got %+v", result.Statement.Rules)
	}
	if len(result.Statement.NotExtended) != 1 || result.Statement.NotExtended[0].RuleID != "rule-b" || result.Statement.NotExtended[0].WorstClass != reasonMechanicalRule {
		t.Fatalf("expected the mechanical rule refused with %s, got %+v", reasonMechanicalRule, result.Statement.NotExtended)
	}
	// The mechanical rule's bytes in the next pack are untouched.
	var next packDocument
	if err := json.Unmarshal(result.NextPack, &next); err != nil {
		t.Fatal(err)
	}
	var before packDocument
	if err := json.Unmarshal(pack, &before); err != nil {
		t.Fatal(err)
	}
	for i := range next.Entries {
		fields, _ := parseRuleFields(next.Entries[i].Rule)
		if fields.ID == "rule-b" && compact(t, next.Entries[i].Rule) != compact(t, before.Entries[i].Rule) {
			t.Fatal("a refused mechanical rule was modified in the next pack")
		}
	}
}

func TestPrepareRefusesMechanicalRuleEvenWhenOnlyRule(t *testing.T) {
	packPath := "/repo/cli/internal/cncfcheck/data/rules.json"
	spec := freshSpec("rule-a", "proj-a", baseNow)
	spec.mechanical = true
	wl, pack := buildWorklistAndPack(t, packPath, baseNow, []ruleSpec{spec})
	result, err := Prepare(PrepareOptions{
		WorklistRaw: marshalWorklist(t, wl), PackName: PackCNCF, PackPath: packPath, PackRaw: pack,
		Wave: 1, AttestedAt: baseNow, Now: baseNow, NextRevision: "rev-2", EngineCapabilityDigest: testEngineCapabilityDigest, Chain: &Chain{},
	})
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	if len(result.Statement.Rules) != 0 || len(result.Statement.NotExtended) != 1 || result.Statement.NotExtended[0].WorstClass != reasonMechanicalRule {
		t.Fatalf("got rules=%+v notExtended=%+v", result.Statement.Rules, result.Statement.NotExtended)
	}
}

func TestParseRuleFieldsRejectsMalformedBasis(t *testing.T) {
	good := testRule("rule-a", "active", "2026-01-01T00:00:00Z", "2026-03-01T00:00:00Z", false)
	for name, mutate := range map[string]func(map[string]any){
		"unknown basis":                func(e map[string]any) { e["basis"] = "automatic" },
		"empty basis":                  func(e map[string]any) { e["basis"] = "" },
		"mechanical without extractor": func(e map[string]any) { e["basis"] = "mechanical" },
		"extractor on reviewed rule": func(e map[string]any) {
			markMechanical(map[string]any{"evidence": e}, "2026-01-01T00:00:00Z")
			e["basis"] = "reviewed"
		},
	} {
		t.Run(name, func(t *testing.T) {
			raw, _ := json.Marshal(good)
			var rule map[string]any
			_ = json.Unmarshal(raw, &rule)
			mutate(rule["evidence"].(map[string]any))
			raw, _ = json.Marshal(rule)
			if _, err := parseRuleFields(raw); !errors.Is(err, ErrRejected) {
				t.Fatalf("expected rejection, got %v", err)
			}
		})
	}
	for _, basis := range []string{"", "reviewed"} {
		rule := testRule("rule-a", "active", "2026-01-01T00:00:00Z", "2026-03-01T00:00:00Z", false)
		if basis != "" {
			rule["evidence"].(map[string]any)["basis"] = basis
		}
		raw, _ := json.Marshal(rule)
		if _, err := parseRuleFields(raw); err != nil {
			t.Fatalf("basis %q rejected: %v", basis, err)
		}
	}
}

func TestCheckV6RejectsMechanicalLeaseChangeEvenWithReviewRecord(t *testing.T) {
	derive := func(reviewedAt, validUntil string) json.RawMessage {
		rule := testRule("rule-a", "active", reviewedAt, validUntil, false)
		markMechanical(rule, reviewedAt)
		raw, _ := json.Marshal(rule)
		return raw
	}
	prior := map[string]json.RawMessage{"rule-a": derive("2026-01-01T00:00:00Z", "2026-03-01T00:00:00Z")}
	next := map[string]json.RawMessage{"rule-a": derive("2026-02-01T00:00:00Z", "2026-04-01T00:00:00Z")}
	fresh := map[string]string{"rule-a": "sha256:" + strings.Repeat("ee", 32)}
	for name, statement := range map[string]Statement{
		"covered by statement": {Rules: []RuleAttestation{{RuleID: "rule-a"}}},
		"covered by record":    {},
	} {
		if err := checkV6(prior, next, statement, fresh); err == nil || !strings.Contains(err.Error(), "mechanical") {
			t.Fatalf("%s: expected a mechanical refusal, got %v", name, err)
		}
	}
	// A pack change that leaves a mechanical rule's lease alone is fine.
	if err := checkV6(prior, prior, Statement{}, nil); err != nil {
		t.Fatalf("unchanged mechanical rule rejected: %v", err)
	}
}

func TestCheckV6RejectsBasisChange(t *testing.T) {
	reviewed := testRule("rule-a", "active", "2026-01-01T00:00:00Z", "2026-03-01T00:00:00Z", false)
	mechanical := testRule("rule-a", "active", "2026-01-01T00:00:00Z", "2026-03-01T00:00:00Z", false)
	markMechanical(mechanical, "2026-01-01T00:00:00Z")
	a, _ := json.Marshal(reviewed)
	b, _ := json.Marshal(mechanical)
	if err := checkV6(map[string]json.RawMessage{"rule-a": a}, map[string]json.RawMessage{"rule-a": b}, Statement{}, nil); err == nil || !strings.Contains(err.Error(), "basis changed") {
		t.Fatalf("expected a basis-change refusal, got %v", err)
	}
}

func compact(t *testing.T, raw json.RawMessage) string {
	t.Helper()
	var out bytes.Buffer
	if err := json.Compact(&out, raw); err != nil {
		t.Fatal(err)
	}
	return out.String()
}
