// SPDX-License-Identifier: AGPL-3.0-only

package cncfcheck

import (
	"encoding/json"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/constraintengine"
)

// coveredExternal is a one-rule external envelope under the given pack schema.
func coveredExternal(t *testing.T, pack rulePack, schema string) []byte {
	t.Helper()
	var document externalFixtureDocument
	if err := json.Unmarshal(externalFixture(t, pack.Entries), &document); err != nil {
		t.Fatal(err)
	}
	document.Pack.Schema = schema
	raw, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// TestPackBoundaryCoveredIsDeclared: the level is reached only by declaring
// it, needs a ranged rule, and is the one opt-in level.
func TestPackBoundaryCoveredIsDeclared(t *testing.T) {
	t.Parallel()
	pack := syntheticBase(t)
	if schema, err := requiredPackSchema(pack); err != nil || schema != packSchemaRanged {
		t.Fatalf("content alone requires %s (%v)", schema, err)
	}
	pack.Schema = packSchemaBoundaryCovered
	if !validPackSchema(pack) {
		t.Fatal("a ranged pack declaring the level was refused")
	}
	unranged := withoutRanges(t, pack)
	if validPackSchema(unranged) {
		t.Fatal("a pack without a range was admitted at the level")
	}
	for _, feature := range packFeatureLevels {
		if PackSchemaIsOptIn(feature.schema) != (feature.schema == packSchemaBoundaryCovered) {
			t.Fatalf("opt-in answer for %s", feature.schema)
		}
	}
	if PackSchemaIsOptIn(packSchema) || PackSchemaIsOptIn("") || PackSchemaIsOptIn(packSchemaBoundaryCovered+"0") {
		t.Fatal("another schema reported as opt-in")
	}
}

// TestExternalBundleBoundaryCovered: an external bundle carries the contract
// only under the declared level and only with a range.
func TestExternalBundleBoundaryCovered(t *testing.T) {
	t.Parallel()
	pack := withAnchorOnlyRange(t, rulePack{Entries: []Entry{ruleEntry(t, "kubernetes", cronJobRuleID)}}, cronJobRuleID)
	for schema, contract := range map[string]string{
		packSchemaBoundaryCovered: constraintengine.EngineContractDigestBoundaryCovered(),
		packSchemaRanged:          constraintengine.EngineContractDigestRanged(),
	} {
		parsed, err := ParseExternalBundle(coveredExternal(t, pack, schema))
		if err != nil {
			t.Fatalf("%s refused: %v", schema, err)
		}
		report, err := parsed.EvaluateRule("kubernetes", cronJobRuleID, kubernetesInput(t, "1.24.0", "1.25.0", true), rangeReviewClock)
		if err != nil {
			t.Fatal(err)
		}
		if len(report.Check.Claims) != 1 || report.Check.Claims[0].Status != "BLOCKED" || report.Check.EngineContractDigest != contract {
			t.Fatalf("%s: report=%+v", schema, report.Check)
		}
	}
	for name, raw := range map[string][]byte{
		"no range":       coveredExternal(t, withoutRanges(t, pack), packSchemaBoundaryCovered),
		"unknown schema": coveredExternal(t, pack, packSchemaBoundaryCovered+"0"),
		"exact schema":   coveredExternal(t, pack, packSchema),
	} {
		if _, err := ParseExternalBundle(raw); err == nil {
			t.Fatalf("%s admitted", name)
		}
	}
}

// TestSplitTargetsKeepBoundaryCovered: a per-project target keeps the declared
// contract while its rules hold a range, and never gains it otherwise.
func TestSplitTargetsKeepBoundaryCovered(t *testing.T) {
	t.Parallel()
	for _, declared := range []string{packSchemaRanged, packSchemaBoundaryCovered} {
		pack := syntheticBase(t)
		pack.Schema = declared
		raw, err := json.Marshal(pack)
		if err != nil {
			t.Fatal(err)
		}
		_, targets, err := BuildExternalTargetsFromPack(raw, "5")
		if err != nil {
			t.Fatalf("%s: %v", declared, err)
		}
		covered, plain := 0, 0
		for _, target := range targets {
			var document externalFixtureDocument
			if err := json.Unmarshal(target.Bytes, &document); err != nil {
				t.Fatal(err)
			}
			rules := make([]json.RawMessage, 0, len(document.Pack.Entries))
			for _, entry := range document.Pack.Entries {
				rules = append(rules, entry.Rule)
			}
			ranged, err := constraintengine.AnyRanged(rules)
			if err != nil {
				t.Fatal(err)
			}
			want := declared == packSchemaBoundaryCovered && ranged
			if got := document.Pack.Schema == packSchemaBoundaryCovered; got != want {
				t.Fatalf("%s: %s has schema %s (ranged=%v)", declared, target.Path, document.Pack.Schema, ranged)
			}
			if want {
				covered++
			} else {
				plain++
			}
			if target.Path != ProjectTargetPath("kubernetes") {
				continue
			}
			parsed, err := ParseExternalBundle(target.Bytes)
			if err != nil {
				t.Fatal(err)
			}
			report, err := parsed.EvaluateRule("kubernetes", cronJobRuleID, kubernetesInput(t, "1.24.0", "1.25.0", true), rangeReviewClock)
			if err != nil {
				t.Fatal(err)
			}
			contract := constraintengine.EngineContractDigestRanged()
			if want {
				contract = constraintengine.EngineContractDigestBoundaryCovered()
			}
			if report.Check.EngineContractDigest != contract {
				t.Fatalf("%s: kubernetes contract %s", declared, report.Check.EngineContractDigest)
			}
		}
		if plain == 0 || (covered > 0) != (declared == packSchemaBoundaryCovered) {
			t.Fatalf("%s: %d covered, %d plain targets", declared, covered, plain)
		}
	}
}

// TestParseMemoSeparatesTheDeclaredContract: the same rules, revision and
// registry under another declared level are parsed again, in either order.
func TestParseMemoSeparatesTheDeclaredContract(t *testing.T) {
	t.Parallel()
	base, err := load()
	if err != nil {
		t.Fatal(err)
	}
	rules := []json.RawMessage{ruleEntry(t, "kubernetes", cronJobRuleID).Rule}
	covered := constraintengine.EngineContractDigestBoundaryCovered()
	for _, schema := range []string{packSchemaRanged, packSchemaBoundaryCovered, packSchemaRanged, packSchemaBoundaryCovered} {
		b := base
		b.pack.Revision = "memo-contract"
		b.pack.Schema = schema
		parsed, err := b.parseRulesCorpus(rules, nil)
		if err != nil {
			t.Fatal(err)
		}
		input, _, err := parseGuarded(kubernetesInput(t, "1.24.0", "1.25.0", true), b.registry)
		if err != nil {
			t.Fatal(err)
		}
		report, err := constraintengine.Evaluate(input, parsed, rangeReviewClock)
		if err != nil {
			t.Fatal(err)
		}
		if got := report.EngineContractDigest == covered; got != (schema == packSchemaBoundaryCovered) {
			t.Fatalf("%s: contract %s", schema, report.EngineContractDigest)
		}
	}
}
