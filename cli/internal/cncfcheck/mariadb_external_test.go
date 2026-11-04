// SPDX-License-Identifier: AGPL-3.0-only

package cncfcheck

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/projectprepare"
)

func canaryEnvelope(t *testing.T, entry Entry, canary bool) []byte {
	t.Helper()
	base, err := load()
	if err != nil {
		t.Fatal(err)
	}
	p, err := externalProfile(base, canary)
	if err != nil {
		t.Fatal(err)
	}
	pack := rulePack{Schema: packSchemaCommunity, Revision: "7", PolicyID: base.pack.PolicyID, PolicyDigest: base.pack.PolicyDigest, LandscapeFileDigest: base.pack.LandscapeFileDigest, RegistryDigest: p.registry.Digest(), Entries: []Entry{entry}}
	raw, err := json.Marshal(externalFixtureDocument{externalBundleSchema, "7", "synthetic_test_only", p.capability, pack})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestMariaDBExternalProfilesAndFrozenEntry(t *testing.T) {
	entry, err := mariaDBCanaryEntry()
	if err != nil {
		t.Fatal(err)
	}
	legacyBefore, err := ExportEmbeddedExternalBundle("6")
	if err != nil {
		t.Fatal(err)
	}
	legacyRequirements, _ := ExternalProfileRequirements()
	canaryRequirements, err := MariaDBCanaryProfileRequirements()
	if err != nil {
		t.Fatal(err)
	}
	if legacyRequirements.EngineCapabilityDigest == canaryRequirements.EngineCapabilityDigest || legacyRequirements.RegistryDigest == canaryRequirements.RegistryDigest {
		t.Fatal("profiles not distinct")
	}
	canaryRaw := canaryEnvelope(t, entry, true)
	if _, err := ParseExternalBundle(canaryEnvelope(t, entry, false)); err == nil {
		t.Fatal("canary admitted under legacy")
	}
	var doc externalFixtureDocument
	if json.Unmarshal(canaryRaw, &doc) != nil {
		t.Fatal("fixture")
	}
	for _, what := range []string{"registry", "capability"} {
		changed := doc
		if what == "registry" {
			changed.Pack.RegistryDigest = legacyRequirements.RegistryDigest
		} else {
			changed.EngineCapabilityDigest = "sha256:" + strings.Repeat("0", 64)
		}
		raw, _ := json.Marshal(changed)
		if _, err := ParseExternalBundle(raw); err == nil {
			t.Fatal("forged " + what)
		}
	}
	// Change every scalar leaf of the complete reviewed entry, and remove
	// each object member/array item. This tests the frozen entry boundary,
	// including every guard, citation span/digest and evidence date.
	var object any
	raw, _ := json.Marshal(entry)
	_ = json.Unmarshal(raw, &object)
	var visit func(any, string, func(any))
	count := 0
	var envelope map[string]any
	if json.Unmarshal(canaryRaw, &envelope) != nil {
		t.Fatal("fixture envelope")
	}
	check := func() {
		count++
		// Preserve omissions in the actual wire input. Decoding through Entry
		// here would restore an omitted enumTokens as null before admission.
		envelope["pack"].(map[string]any)["entries"] = []any{object}
		raw, _ := json.Marshal(envelope)
		if _, err := ParseExternalBundle(raw); err == nil {
			t.Fatalf("entry mutation %d accepted", count)
		}
	}
	visit = func(value any, path string, replace func(any)) {
		switch node := value.(type) {
		case map[string]any:
			for key, child := range node {
				delete(node, key)
				check()
				node[key] = child
				visit(child, path+"/"+key, func(v any) { node[key] = v })
			}
		case []any:
			for i, child := range node {
				trimmed := append(append([]any{}, node[:i]...), node[i+1:]...)
				replace(trimmed)
				check()
				replace(node)
				visit(child, fmt.Sprintf("%s/%d", path, i), func(v any) { node[i] = v })
			}
		case string:
			replace(node + "-changed")
			check()
			replace(node)
		case bool:
			replace(!node)
			check()
			replace(node)
		case float64:
			replace(node + 1)
			check()
			replace(node)
		}
	}
	visit(object, "", func(v any) { object = v })
	if count < 100 {
		t.Fatalf("insufficient frozen boundary %d", count)
	}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Go(func() {
			for j := 0; j < 3; j++ {
				for _, raw := range [][]byte{legacyBefore, canaryRaw} {
					if _, err := ParseExternalBundle(raw); err != nil {
						t.Error(err)
					}
				}
			}
		})
	}
	wg.Wait()
	legacyAfter, err := ExportEmbeddedExternalBundle("6")
	if err != nil || !bytes.Equal(legacyBefore, legacyAfter) {
		t.Fatal("legacy export mutated")
	}
}

func TestMariaDBExternalSelectedAndAbsentCanary(t *testing.T) {
	entry, _ := mariaDBCanaryEntry()
	raw := canaryEnvelope(t, entry, true)
	b, err := ParseExternalBundle(raw)
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := projectprepare.PrepareMariaDBOperatorResource([]byte(`{"apiVersion":"k8s.mariadb.com/v1alpha1","kind":"MariaDB","spec":{"galera":{"enabled":true},"updateStrategy":{"autoUpdateDataPlane":false}}}`), "26.3.0", "26.6.0", true, true)
	if err != nil {
		t.Fatal(err)
	}
	now, _ := time.Parse(time.RFC3339, "2026-11-04T12:00:00Z")
	report, err := b.EvaluateRule("mariadb-operator", MariaDBCanaryRuleID, prepared.CanonicalInputJSON, now)
	if err != nil || len(report.Check.Claims) != 1 || report.Check.Claims[0].Status != "BLOCKED" {
		t.Fatalf("report=%+v err=%v", report, err)
	}
	expired, _ := time.Parse(time.RFC3339, "2026-12-13T00:00:00Z")
	stale, err := b.EvaluateRule("mariadb-operator", MariaDBCanaryRuleID, prepared.CanonicalInputJSON, expired)
	if err != nil || len(stale.Check.Claims) != 1 || stale.Check.Claims[0].Status != "UNKNOWN" {
		t.Fatalf("expired evidence=%+v err=%v", stale, err)
	}
	admission, _ := b.Admission()
	indexRaw, _ := json.Marshal(externalIndexDocument{Schema: ExternalIndexSchemaCommunity, Revision: "7", Purpose: "synthetic_test_only", EngineCapabilityDigest: admission.EngineCapabilityDigest, Projects: []ExternalIndexEntry{{Project: "mariadb-operator", Catalog: CatalogCommunity, TargetPath: ProjectTargetPath("mariadb-operator"), Revision: "7", Length: int64(len(raw)), Digest: digest(raw), RuleDigest: admission.RuleDigest, EvidenceExpiresAt: admission.EvidenceExpiresAt}}})
	index, err := ParseExternalIndex(indexRaw)
	if err != nil {
		t.Fatal(err)
	}
	empty, err := index.EmptyExternalBundle()
	if err != nil {
		t.Fatal(err)
	}
	ea, _ := empty.Admission()
	if ea.EngineCapabilityDigest != admission.EngineCapabilityDigest {
		t.Fatal("absent profile substituted")
	}
	report, err = empty.EvaluateRule("mariadb-operator", MariaDBCanaryRuleID, prepared.CanonicalInputJSON, now)
	if err != nil || len(report.Check.Claims) != 0 || report.Assessment != "UNKNOWN" {
		t.Fatalf("empty=%+v err=%v", report, err)
	}
	if _, err := (ExternalIndex{}).EmptyExternalBundle(); err == nil {
		t.Fatal("forged index issued empty bundle")
	}
	// Omit only the semantic canary while retaining a CRD rule under the new
	// capability; selecting the canary must not pick that other claim.
	other := communityEntry()
	otherRaw := canaryEnvelope(t, other, true)
	otherBundle, err := ParseExternalBundle(otherRaw)
	if err != nil {
		t.Fatal(err)
	}
	report, err = otherBundle.EvaluateRule("mariadb-operator", MariaDBCanaryRuleID, prepared.CanonicalInputJSON, now)
	if err != nil || len(report.Check.Claims) != 0 {
		t.Fatalf("omitted canary=%+v err=%v", report, err)
	}
	// Signed target binding rejects both profile swap directions even when
	// the index length/hash is recomputed for the replacement target.
	for _, canary := range []bool{false, true} {
		target := canaryEnvelope(t, other, canary)
		targetBundle, err := ParseExternalBundle(target)
		if err != nil {
			t.Fatal(err)
		}
		a, _ := targetBundle.Admission()
		opposite, _ := externalProfile(*index.base, !canary)
		doc := externalIndexDocument{Schema: ExternalIndexSchemaCommunity, Revision: "7", Purpose: "synthetic_test_only", EngineCapabilityDigest: opposite.capability, Projects: []ExternalIndexEntry{{Project: other.Project, Catalog: CatalogCommunity, TargetPath: ProjectTargetPath(other.Project), Revision: "7", Length: int64(len(target)), Digest: digest(target), RuleDigest: a.RuleDigest, EvidenceExpiresAt: a.EvidenceExpiresAt}}}
		encoded, _ := json.Marshal(doc)
		x, err := ParseExternalIndex(encoded)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := AdmitExternalProjectTarget(x, other.Project, target); err == nil {
			t.Fatal("cross-profile target admitted")
		}
	}
}

func TestMariaDBExternalFactsCannotBeTransplanted(t *testing.T) {
	entry, err := mariaDBCanaryEntry()
	if err != nil {
		t.Fatal(err)
	}
	var doc externalFixtureDocument
	if json.Unmarshal(canaryEnvelope(t, entry, true), &doc) != nil {
		t.Fatal("fixture")
	}
	entry.Project = "kyverno"
	var rule map[string]any
	if json.Unmarshal(entry.Rule, &rule) != nil {
		t.Fatal("rule")
	}
	rule["id"] = "kyverno.synthetic-transplanted-canary"
	rule["subject"].(map[string]any)["component"] = "pkg:github/kyverno/kyverno"
	entry.Rule, _ = json.Marshal(rule)
	doc.Pack.Entries = []Entry{entry}
	doc.Pack.Schema, err = requiredPackSchema(doc.Pack)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseExternalBundle(raw); err == nil {
		t.Fatal("CNCF rule acquired the canary-only facts")
	}
}
