// SPDX-License-Identifier: AGPL-3.0-only

package cncfcheck

import (
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/cncfprepare"
	"github.com/prufyx/prufyx/cli/internal/constraintengine"
	"github.com/prufyx/prufyx/cli/internal/extract/supersedeids"
)

// laterRemovalFacts are the removals of the 1.33, 1.34 and 1.37 lines: the
// rendered apply-set adapter derives them and the served-API extractor
// derives rules over them, but no published rule reads them yet.
var laterRemovalFacts = []struct {
	fact, group string
	line        int
	kinds       []string
}{
	{"component.kubernetes.selfsubjectreview_v1beta1_removed_gvk_present", "authentication.k8s.io", 33, []string{"SelfSubjectReview"}},
	{"component.kubernetes.validatingadmissionpolicy_v1beta1_removed_gvk_present", "admissionregistration.k8s.io", 34, []string{"ValidatingAdmissionPolicy", "ValidatingAdmissionPolicyBinding"}},
	{"component.kubernetes.ipaddress_servicecidr_v1beta1_removed_gvk_present", "networking.k8s.io", 37, []string{"IPAddress", "ServiceCIDR"}},
	{"component.kubernetes.volumeattributesclass_v1beta1_removed_gvk_present", "storage.k8s.io", 37, []string{"VolumeAttributesClass"}},
}

func minorVersion(minor int, patch int) string {
	return "1." + strconv.Itoa(minor) + "." + strconv.Itoa(patch)
}

// removalEntry is a test-only rule of the shape the served-API extractor
// derives for one removal: line-wide range, mechanical evidence. It is never
// published.
func removalEntry(fact string, line int) Entry {
	from, to, next := minorVersion(line-1, 0), minorVersion(line, 0), minorVersion(line+1, 0)
	slug := strings.ReplaceAll(from, ".", "-") + "-to-" + strings.ReplaceAll(to, ".", "-")
	id := "kubernetes.synthetic-removal-" + strings.TrimSuffix(strings.TrimPrefix(fact, "component.kubernetes."), "_v1beta1_removed_gvk_present") + "." + slug
	source := func(sourceID string) string {
		return `{"id":"` + sourceID + `","url":"https://github.com/kubernetes/kubernetes/blob/` + syntheticRevision + `/api/openapi-spec/swagger.json","revision":"` + syntheticRevision + `","contentDigest":"sha256:` + strings.Repeat("0", 64) + `","startLine":1,"endLine":2}`
	}
	bound := func(name, basis string) string {
		return `{"bound":"` + name + `","basis":"` + basis + `","sourceId":"lifecycle"}`
	}
	rule := `{"id":"` + id + `","operator":"forbid_predicate_value","subject":{"component":"` + kubernetesComponent + `","from":"` + from + `","to":"` + to + `"},` +
		`"range":{"from":{"gte":"` + from + `","lt":"` + to + `"},"to":{"gte":"` + to + `","lt":"` + next + `"},"bounds":[` +
		bound("from.gte", "PREVIOUS_MINOR_LINE") + `,` + bound("from.lt", "REMOVED_IN_RELEASE") + `,` + bound("to.gte", "REMOVED_IN_RELEASE") + `,` + bound("to.lt", "TARGET_SERIES") + `]},` +
		`"condition":{"side":"proposed","component":"` + kubernetesComponent + `","factId":"` + fact + `","boolValue":true},` +
		`"evidence":{"state":"active","basis":"mechanical","derivedAt":"2026-10-03T00:00:00Z","reviewedAt":"2026-10-03T00:00:00Z","validUntil":"2026-12-19T00:00:00Z",` +
		`"extractor":{"id":"k8s.served-api-removal","version":"1.1.0","codeDigest":"sha256:` + strings.Repeat("1", 64) + `"},"sources":[` + source("lifecycle") + `]},` +
		`"reasonCode":"KUBERNETES_SERVED_API_REMOVED","nextAction":"synthetic test-only action"}`
	return Entry{Project: "kubernetes", Description: "Synthetic test-only served API removal.", RequiredFacts: []Fact{{Side: "proposed", ID: fact, Component: kubernetesComponent, Type: constraintengine.FactBool, Description: "Whether the apply set contains the removed version."}}, Rule: json.RawMessage(rule)}
}

// withoutFact is the compiled registry without one fact.
func withoutFact(fact string) []constraintengine.FactDefinition {
	var out []constraintengine.FactDefinition
	for _, d := range compiledDefinitions() {
		if d.ID != fact {
			out = append(out, d)
		}
	}
	return out
}

// removalPack is the embedded pack plus entries, at its own schema, bound
// to the registry of definitions.
func removalPack(t *testing.T, definitions []constraintengine.FactDefinition, entries ...Entry) []byte {
	t.Helper()
	raw, err := packagedFiles.ReadFile("data/rules.json")
	if err != nil {
		t.Fatal(err)
	}
	var pack rulePack
	if err := strictJSON(raw, &pack); err != nil {
		t.Fatal(err)
	}
	schema := pack.Schema
	encoded := crdPack(t, definitions, entries...)
	if err := strictJSON(encoded, &pack); err != nil {
		t.Fatal(err)
	}
	pack.Schema = schema
	encoded, err = json.Marshal(pack)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

// Every fact the rendered apply-set adapter derives is registered once, as
// a boolean fact of the Kubernetes component: the extractor's fact table is
// pinned to the adapter's by a test in the extractor package, so this covers
// every fact a derived removal rule can read.
func TestKubernetesRemovalFactsRegistered(t *testing.T) {
	count := map[string]int{}
	for _, d := range compiledDefinitions() {
		count[d.ID]++
		if strings.HasSuffix(d.ID, "_removed_gvk_present") && (d.Component != kubernetesComponent || d.Type != constraintengine.FactBool || d.EnumTokens != nil) {
			t.Fatalf("%s: %+v", d.ID, d)
		}
	}
	for _, fact := range cncfprepare.KubernetesRemovedAPIAllFacts() {
		if count[fact] != 1 || !RegisteredFact(fact) {
			t.Fatalf("%s registered %d times", fact, count[fact])
		}
	}
	for _, f := range laterRemovalFacts {
		if count[f.fact] != 1 {
			t.Fatalf("%s registered %d times", f.fact, count[f.fact])
		}
	}
}

// embeddedRemovalRule is the embedded pack's rule over a later removal fact.
func embeddedRemovalRule(t *testing.T, b bundle, fact string, line int) (Entry, string) {
	t.Helper()
	slug := "1-" + strconv.Itoa(line-1) + "-0-to-1-" + strconv.Itoa(line) + "-0"
	var found []Entry
	for _, e := range b.pack.Entries {
		for _, rf := range e.RequiredFacts {
			if rf.ID == fact && strings.HasSuffix(ruleID(t, e), "."+slug) {
				found = append(found, e)
			}
		}
	}
	if len(found) != 1 {
		t.Fatalf("%s: %d embedded rules for line 1.%d", fact, len(found), line)
	}
	return found[0], ruleID(t, found[0])
}

// laterRemovalRule returns a bundle holding a rule over the later removal fact
// and the rule's id: the embedded pack's own mechanical rule once the shipped
// pack holds them, a test-only rule of the same shape before.
func laterRemovalRule(t *testing.T, fact string, line int) (bundle, string) {
	t.Helper()
	if supersedeids.Superseded() {
		b, err := load()
		if err != nil {
			t.Fatal(err)
		}
		_, id := embeddedRemovalRule(t, b, fact, line)
		return b, id
	}
	entry := removalEntry(fact, line)
	b, err := assembleWith(removalPack(t, compiledDefinitions(), entry), compiledDefinitions())
	if err != nil {
		t.Fatal(err)
	}
	return b, ruleID(t, entry)
}

// Registration is what admits a rule over each fact: the same pack is
// refused against the registry without the fact and admitted with it. The
// embedded pack itself reads none of them.
func TestKubernetesRemovalRuleAdmissionNeedsTheRegisteredFact(t *testing.T) {
	if supersedeids.Superseded() {
		// The embedded pack holds a rule over each fact: it is refused
		// against the registry without the fact and admitted with it.
		raw, err := packagedFiles.ReadFile("data/rules.json")
		if err != nil {
			t.Fatal(err)
		}
		b, err := load()
		if err != nil {
			t.Fatal(err)
		}
		for _, f := range laterRemovalFacts {
			embeddedRemovalRule(t, b, f.fact, f.line)
			if _, err := assembleWith(raw, withoutFact(f.fact)); !errors.Is(err, ErrIntegrity) {
				t.Fatalf("%s: rule over the unregistered fact admitted: %v", f.fact, err)
			}
		}
		if _, err := assembleWith(raw, compiledDefinitions()); err != nil {
			t.Fatalf("embedded pack refused against the compiled registry: %v", err)
		}
		return
	}
	for _, f := range laterRemovalFacts {
		entry := removalEntry(f.fact, f.line)
		if _, err := assembleWith(removalPack(t, withoutFact(f.fact), entry), withoutFact(f.fact)); !errors.Is(err, ErrIntegrity) {
			t.Fatalf("%s: rule over the unregistered fact admitted: %v", f.fact, err)
		}
		if _, err := assembleWith(removalPack(t, compiledDefinitions(), entry), compiledDefinitions()); err != nil {
			t.Fatalf("%s: rule over the registered fact refused: %v", f.fact, err)
		}
	}
	b, err := load()
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range b.pack.Entries {
		for _, rf := range e.RequiredFacts {
			for _, f := range laterRemovalFacts {
				if rf.ID == f.fact {
					t.Fatalf("embedded pack reads %s", f.fact)
				}
			}
		}
	}
}

// Each fact decides its rule through the adapter's own input: BLOCKED when
// a removed version is in the apply set (anchor or any patch of either
// line), PASS when only the served version is and the scope is complete,
// UNKNOWN for an unreviewed version, an incomplete scope, or a transition
// outside the rule's lines.
func TestKubernetesRemovalFactsDecideTheirRules(t *testing.T) {
	now := supersedeids.Clock()
	doc := func(api, kind string) string {
		return `{"apiVersion":"` + api + `","kind":"` + kind + `","metadata":{"name":"x"}}`
	}
	list := func(items ...string) []byte {
		return []byte(`{"apiVersion":"v1","kind":"List","items":[` + strings.Join(items, ",") + `]}`)
	}
	for _, f := range laterRemovalFacts {
		b, id := laterRemovalRule(t, f.fact, f.line)
		for _, kind := range f.kinds {
			removed, served, unreviewed := doc(f.group+"/v1beta1", kind), doc(f.group+"/v1", kind), doc(f.group+"/v1alpha1", kind)
			other := doc("v1", "ConfigMap")
			for _, tc := range []struct {
				name, from, to string
				raw            []byte
				complete       bool
				status, reason string
			}{
				{"removed version at the anchor", minorVersion(f.line-1, 0), minorVersion(f.line, 0), list(removed, other), true, "BLOCKED", "KUBERNETES_SERVED_API_REMOVED"},
				{"removed version between patches", minorVersion(f.line-1, 7), minorVersion(f.line, 2), list(other, removed), true, "BLOCKED", "KUBERNETES_SERVED_API_REMOVED"},
				{"served version, complete scope", minorVersion(f.line-1, 0), minorVersion(f.line, 0), list(served, other), true, "PASS", "KUBERNETES_SERVED_API_REMOVED"},
				{"served version between patches", minorVersion(f.line-1, 3), minorVersion(f.line, 1), list(served), true, "PASS", "KUBERNETES_SERVED_API_REMOVED"},
				{"unreviewed version", minorVersion(f.line-1, 0), minorVersion(f.line, 0), list(unreviewed), true, "UNKNOWN", "RULE_FACT_UNAVAILABLE"},
				{"incomplete scope", minorVersion(f.line-1, 0), minorVersion(f.line, 0), list(removed), false, "UNKNOWN", "RULE_FACT_UNAVAILABLE"},
			} {
				t.Run(f.fact+"/"+kind+"/"+tc.name, func(t *testing.T) {
					prepared, err := cncfprepare.PrepareKubernetesRemovedAPIs(tc.raw, tc.from, tc.to, "official_upstream", true, tc.complete)
					if err != nil {
						t.Fatal(err)
					}
					report, err := b.checkFacts("kubernetes", cncfprepare.KubernetesRemovedAPIAllFacts(), prepared.CanonicalInputJSON, now)
					if err != nil {
						t.Fatal(err)
					}
					var found []constraintengine.Claim
					for _, claim := range report.Check.Claims {
						if claim.RuleID == id {
							found = append(found, claim)
						} else if claim.Status == "BLOCKED" || (claim.Status == "PASS" && !supersedeids.Superseded()) {
							// The mechanical rules pass beside this one on a shared hop.
							t.Fatalf("another rule decided: %s %s", claim.RuleID, claim.Status)
						}
					}
					if len(found) != 1 || found[0].Status != tc.status || found[0].ReasonCode != tc.reason {
						t.Fatalf("claims %+v", report.Check.Claims)
					}
				})
			}
		}
		// Outside the rule's lines the fact is not derived and the rule
		// decides nothing.
		prepared, err := cncfprepare.PrepareKubernetesRemovedAPIs(list(doc(f.group+"/v1beta1", f.kinds[0])), minorVersion(f.line, 0), minorVersion(f.line+1, 0), "official_upstream", true, true)
		if err != nil {
			t.Fatal(err)
		}
		report, err := b.checkFacts("kubernetes", cncfprepare.KubernetesRemovedAPIAllFacts(), prepared.CanonicalInputJSON, now)
		if err != nil {
			t.Fatal(err)
		}
		for _, claim := range report.Check.Claims {
			// Before the supersede no claim at all is decided on the next line;
			// the mechanical rules of other lines may pass beside this one, so
			// there only this rule is held to it.
			if (claim.RuleID == id || !supersedeids.Superseded()) && (claim.Status == "PASS" || claim.Status == "BLOCKED") {
				t.Fatalf("%s: %s decided %s on the next line", f.fact, claim.RuleID, claim.Status)
			}
		}
	}
}
