// SPDX-License-Identifier: AGPL-3.0-only

package cncfcheck

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/constraintengine"
)

// The synthetic-pack tests add one pack feature (a set rule, line
// attestations, path policies, distributions, a basis, a severity, ...) to
// the shipped knowledge and assert the exact schema level and admission of
// the result. They need a base that uses no feature of its own above the
// ranged level, so the level they assert is the level of the feature they
// add. syntheticBase is that base, taken from the shipped pack: the shipped
// rules without the set rules, without the line attestation and served-API list sections, under
// the ranged schema. It is not a copy of an older pack: every other shipped
// rule is in it, byte for byte.
//
// The shipped set rules and line attestations are not dropped from testing:
// TestEmbeddedKnowledgeSetRulesReadCustomResourceSets and
// TestEmbeddedPackLineAttestations hold them, and TestPackSchemaLevels
// holds the shipped pack's own schema, on the shipped bytes.

// syntheticBase is the shipped pack reduced as described above. It fails
// the test when the shipped pack carries a section or a rule feature this
// reduction does not know, so a new shipped feature is never stripped
// silently.
func syntheticBase(t *testing.T) rulePack {
	t.Helper()
	pack := shippedPack(t)
	if len(pack.PathPolicies) != 0 || len(pack.Distributions) != 0 {
		t.Fatal("the shipped pack carries a section syntheticBase does not reduce")
	}
	entries := make([]Entry, 0, len(pack.Entries))
	for _, entry := range pack.Entries {
		if !isSetRule(t, entry) {
			entries = append(entries, entry)
		}
	}
	pack.Entries, pack.LineAttestations, pack.ServedAPIs, pack.Schema = entries, nil, nil, packSchemaRanged
	if schema, err := requiredPackSchema(pack); err != nil || schema != packSchemaRanged {
		t.Fatalf("the reduced shipped pack needs schema %s (%v), not the ranged one: syntheticBase must learn the new feature", schema, err)
	}
	return pack
}

// syntheticBaseRaw is syntheticBase encoded as a pack file.
func syntheticBaseRaw(t *testing.T) []byte {
	t.Helper()
	raw, err := json.Marshal(syntheticBase(t))
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// syntheticBaseBundle is the embedded bundle with its pack replaced by
// syntheticBase, for the tests that mutate a loaded bundle's pack.
func syntheticBaseBundle(t *testing.T) bundle {
	t.Helper()
	b, err := assembleSynthetic(syntheticBaseRaw(t), nil)
	if err != nil {
		t.Fatalf("syntheticBase refused: %v", err)
	}
	return b
}

// shippedPack decodes the embedded pack file strictly.
func shippedPack(t *testing.T) rulePack {
	t.Helper()
	raw, err := packagedFiles.ReadFile("data/rules.json")
	if err != nil {
		t.Fatal(err)
	}
	var pack rulePack
	if err := strictJSON(raw, &pack); err != nil {
		t.Fatal(err)
	}
	return pack
}

// isSetRule reports whether the entry's rule is a set rule, read from the
// rule's operator by the test itself (not through the pack's feature
// table).
func isSetRule(t *testing.T, entry Entry) bool {
	t.Helper()
	var shape struct {
		Operator string `json:"operator"`
	}
	if err := json.Unmarshal(entry.Rule, &shape); err != nil {
		t.Fatal(err)
	}
	return shape.Operator == string(constraintengine.OperatorForbidSetMember)
}

// syntheticBaseExternalBundle is a rules-only external envelope over
// syntheticBase, built the way ExportEmbeddedExternalBundle builds one, for
// the tests that tamper with a rules-only envelope. While the shipped pack
// carries no set rule and no line attestation it is the export byte for
// byte, which it checks.
func syntheticBaseExternalBundle(t *testing.T, revision string) []byte {
	t.Helper()
	capability, err := ExternalCapabilityDigest()
	if err != nil {
		t.Fatal(err)
	}
	pack := syntheticBase(t)
	pack.Revision = revision
	raw, err := json.Marshal(externalFixtureDocument{Schema: externalBundleSchema, Revision: revision, Purpose: "operator_provided", EngineCapabilityDigest: capability, Pack: pack})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseExternalBundle(raw); err != nil {
		t.Fatalf("rules-only envelope over syntheticBase refused: %v", err)
	}
	shipped := shippedPack(t)
	if len(shipped.LineAttestations) == 0 && len(shipped.ServedAPIs) == 0 && len(shipped.Entries) == len(pack.Entries) {
		exported, err := ExportEmbeddedExternalBundle(revision)
		if err != nil || !bytes.Equal(exported, raw) {
			t.Fatalf("the export of a section-free shipped pack differs from the rules-only envelope: %v", err)
		}
	}
	return raw
}

// shippedSchemaLevel is the pack schema the shipped pack must carry, stated
// by the test from what the shipped bytes hold: the served-API level when it
// carries served-API lists, else the line attestation level when it carries
// line attestations, else the set level when it holds a set
// rule, else the ranged level (its Kubernetes removal rules carry ranges).
// Any other section fails the test, so a new shipped feature is stated here
// on purpose.
func shippedSchemaLevel(t *testing.T) string {
	t.Helper()
	pack := shippedPack(t)
	if len(pack.PathPolicies) != 0 || len(pack.Distributions) != 0 {
		t.Fatal("the shipped pack carries a section shippedSchemaLevel does not state")
	}
	if len(pack.ServedAPIs) != 0 {
		return packSchemaServedAPIs
	}
	if len(pack.LineAttestations) != 0 {
		return packSchemaAttested
	}
	for _, entry := range pack.Entries {
		if isSetRule(t, entry) {
			return packSchemaSet
		}
	}
	return packSchemaRanged
}
