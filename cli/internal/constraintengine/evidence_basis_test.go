// SPDX-License-Identifier: AGPL-3.0-only

package constraintengine

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

const testCodeDigest = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

func basisDocument(mutate func(evidence map[string]any)) []byte {
	document := testRuleDocument("forbid_target_version", "")
	evidence := document["rules"].([]any)[0].(map[string]any)["evidence"].(map[string]any)
	mutate(evidence)
	raw, _ := json.Marshal(document)
	return raw
}

func mechanical(evidence map[string]any) {
	evidence["basis"] = "mechanical"
	evidence["extractor"] = map[string]any{"id": "example.removal", "version": "1.2.3", "codeDigest": testCodeDigest}
	evidence["derivedAt"] = "2026-01-01T00:00:00Z"
}

func TestEvidenceBasisStrictParse(t *testing.T) {
	registry := testRegistry(t)
	for _, test := range []struct {
		name   string
		mutate func(map[string]any)
		valid  bool
	}{
		{"absent is reviewed", func(map[string]any) {}, true},
		{"explicit reviewed", func(e map[string]any) { e["basis"] = "reviewed" }, true},
		{"mechanical complete", mechanical, true},
		{"unknown basis", func(e map[string]any) { e["basis"] = "automatic" }, false},
		{"uppercase basis", func(e map[string]any) { e["basis"] = "Mechanical" }, false},
		{"empty basis", func(e map[string]any) { e["basis"] = "" }, false},
		{"null basis", func(e map[string]any) { e["basis"] = nil }, false},
		{"mechanical without extractor", func(e map[string]any) { mechanical(e); delete(e, "extractor") }, false},
		{"mechanical without derivedAt", func(e map[string]any) { mechanical(e); delete(e, "derivedAt") }, false},
		{"mechanical with bare extractor", func(e map[string]any) { e["basis"] = "mechanical" }, false},
		{"reviewed with extractor", func(e map[string]any) { mechanical(e); e["basis"] = "reviewed" }, false},
		{"absent basis with extractor", func(e map[string]any) { mechanical(e); delete(e, "basis") }, false},
		{"reviewed with derivedAt", func(e map[string]any) { e["derivedAt"] = "2026-01-01T00:00:00Z" }, false},
		{"extractor unknown key", func(e map[string]any) { mechanical(e); e["extractor"].(map[string]any)["extra"] = "x" }, false},
		{"extractor missing id", func(e map[string]any) { mechanical(e); delete(e["extractor"].(map[string]any), "id") }, false},
		{"extractor bad id", func(e map[string]any) { mechanical(e); e["extractor"].(map[string]any)["id"] = "Bad ID" }, false},
		{"extractor bad version", func(e map[string]any) { mechanical(e); e["extractor"].(map[string]any)["version"] = "1.2" }, false},
		{"extractor leading zero version", func(e map[string]any) { mechanical(e); e["extractor"].(map[string]any)["version"] = "01.2.3" }, false},
		{"extractor short digest", func(e map[string]any) { mechanical(e); e["extractor"].(map[string]any)["codeDigest"] = "sha256:abc" }, false},
		{"extractor uppercase digest", func(e map[string]any) {
			mechanical(e)
			e["extractor"].(map[string]any)["codeDigest"] = "sha256:" + "B" + testCodeDigest[8:]
		}, false},
		{"extractor wrong algorithm", func(e map[string]any) {
			mechanical(e)
			e["extractor"].(map[string]any)["codeDigest"] = "sha512:" + testCodeDigest[7:]
		}, false},
		{"extractor null", func(e map[string]any) { mechanical(e); e["extractor"] = nil }, false},
		{"derivedAt not UTC", func(e map[string]any) { mechanical(e); e["derivedAt"] = "2026-01-01T00:00:00+02:00" }, false},
		{"derivedAt not RFC3339", func(e map[string]any) { mechanical(e); e["derivedAt"] = "2026-01-01" }, false},
		{"derivedAt after validUntil", func(e map[string]any) { mechanical(e); e["derivedAt"] = "2027-06-01T00:00:00Z" }, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := ParseRuleSet(basisDocument(test.mutate), registry)
			if test.valid && err != nil {
				t.Fatalf("rejected a valid rule: %v", err)
			}
			if !test.valid && !errors.Is(err, ErrInvalid) {
				t.Fatalf("accepted an invalid rule: %v", err)
			}
		})
	}
}

// TestEvidenceBasisNeverChangesVerdict evaluates the same rule under every
// admissible basis and requires an identical verdict and requirements; only
// the disclosure fields and the rule digest (which binds the rule's bytes) may
// differ.
func TestEvidenceBasisNeverChangesVerdict(t *testing.T) {
	registry := testRegistry(t)
	input := testInput(t, registry, `{"id":"component.example.feature_enabled","state":"declared","boolValue":false}`, "2.0.0")
	evaluate := func(mutate func(map[string]any)) Claim {
		rules, err := ParseRuleSet(basisDocument(mutate), registry)
		if err != nil {
			t.Fatal(err)
		}
		report, err := Evaluate(input, rules, testNow(t))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := MarshalReport(report); err != nil {
			t.Fatalf("report did not seal: %v", err)
		}
		return report.Claims[0]
	}
	base := evaluate(func(map[string]any) {})
	if base.EvidenceBasis != "" || base.EvidenceExtractor != nil || base.EvidenceDerivedAt != "" {
		t.Fatalf("a rule without a basis must not disclose one: %+v", base)
	}
	for name, mutate := range map[string]func(map[string]any){
		"reviewed":   func(e map[string]any) { e["basis"] = "reviewed" },
		"mechanical": mechanical,
	} {
		claim := evaluate(mutate)
		if claim.Status != base.Status || claim.ReasonCode != base.ReasonCode || claim.EvidenceFreshness != base.EvidenceFreshness || claim.Operator != base.Operator {
			t.Fatalf("%s changed the verdict: %+v vs %+v", name, claim, base)
		}
	}
	claim := evaluate(mechanical)
	if claim.EvidenceBasis != BasisMechanical || claim.EvidenceExtractor == nil || claim.EvidenceExtractor.ID != "example.removal" || claim.EvidenceExtractor.Version != "1.2.3" || claim.EvidenceDerivedAt != "2026-01-01T00:00:00Z" {
		t.Fatalf("mechanical basis not disclosed: %+v", claim)
	}
}

func TestEvidenceWithoutBasisIsByteIdentical(t *testing.T) {
	registry := testRegistry(t)
	raw := basisDocument(func(map[string]any) {})
	rules, err := ParseRuleSet(raw, registry)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{`"basis"`, `"extractor"`, `"derivedAt"`} {
		if strings.Contains(string(mustMarshal(t, rules.document)), key) {
			t.Fatalf("a rule without a basis re-marshals with %s", key)
		}
	}
	input := testInput(t, registry, `{"id":"component.example.feature_enabled","state":"declared","boolValue":false}`, "2.0.0")
	report, err := Evaluate(input, rules, testNow(t))
	if err != nil {
		t.Fatal(err)
	}
	out, err := MarshalReport(report)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"evidenceBasis", "evidenceExtractor", "evidenceDerivedAt"} {
		if strings.Contains(string(out), key) {
			t.Fatalf("a report for a rule without a basis carries %s", key)
		}
	}
}

func TestEffectiveBasisAbsentIsReviewed(t *testing.T) {
	if EffectiveBasis("") != BasisReviewed || EffectiveBasis(BasisMechanical) != BasisMechanical {
		t.Fatal("effective basis")
	}
}

func mustMarshal(t *testing.T, value any) []byte {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// TestEvidenceBasisPresentationGolden pins the exact human line and the exact
// JSON of a mechanical claim's provenance.
func TestEvidenceBasisPresentationGolden(t *testing.T) {
	registry := testRegistry(t)
	input := testInput(t, registry, `{"id":"component.example.feature_enabled","state":"declared","boolValue":false}`, "2.0.0")
	render := func(mutate func(map[string]any)) (Claim, []byte) {
		rules, err := ParseRuleSet(basisDocument(mutate), registry)
		if err != nil {
			t.Fatal(err)
		}
		report, err := Evaluate(input, rules, testNow(t))
		if err != nil {
			t.Fatal(err)
		}
		raw, err := MarshalReport(report)
		if err != nil {
			t.Fatal(err)
		}
		return report.Claims[0], raw
	}

	claim, _ := render(func(map[string]any) {})
	if got := claim.EvidenceBasisLine(); got != "evidence basis: reviewed by maintainer" {
		t.Fatalf("absent basis line = %q", got)
	}
	claim, _ = render(func(e map[string]any) { e["basis"] = "reviewed" })
	if got := claim.EvidenceBasisLine(); got != "evidence basis: reviewed by maintainer" {
		t.Fatalf("reviewed basis line = %q", got)
	}
	claim, raw := render(mechanical)
	if got := claim.EvidenceBasisLine(); got != "evidence basis: derived from source by example.removal v1.2.3" {
		t.Fatalf("mechanical basis line = %q", got)
	}
	want := `"evidenceBasis":"mechanical","evidenceExtractor":{"id":"example.removal","version":"1.2.3","codeDigest":"` + testCodeDigest + `"},"evidenceDerivedAt":"2026-01-01T00:00:00Z"`
	if !strings.Contains(string(raw), want) {
		t.Fatalf("JSON provenance missing or reordered:\n%s", raw)
	}
}
