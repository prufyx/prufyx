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
// rendered apply-set adapter derives them, and both generations of the
// published pack hold a ranged rule over each of them.
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

// laterRemovalRule returns the embedded bundle, the id of its rule over the
// later removal fact and that rule's reason code: the reviewed rule, or its
// mechanical replacement once the shipped pack holds those.
func laterRemovalRule(t *testing.T, fact string, line int) (bundle, string, string) {
	t.Helper()
	b, err := load()
	if err != nil {
		t.Fatal(err)
	}
	entry, id := embeddedRemovalRule(t, b, fact, line)
	var rule struct {
		ReasonCode string `json:"reasonCode"`
	}
	if err := json.Unmarshal(entry.Rule, &rule); err != nil || rule.ReasonCode == "" {
		t.Fatalf("%s: reason code: %v", id, err)
	}
	return b, id, rule.ReasonCode
}

// Registration is what admits a rule over each fact: the embedded pack holds
// a rule over each fact, and it is refused against the registry without the
// fact and admitted with it.
func TestKubernetesRemovalRuleAdmissionNeedsTheRegisteredFact(t *testing.T) {
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
		b, id, reason := laterRemovalRule(t, f.fact, f.line)
		for _, kind := range f.kinds {
			removed, served, unreviewed := doc(f.group+"/v1beta1", kind), doc(f.group+"/v1", kind), doc(f.group+"/v1alpha1", kind)
			other := doc("v1", "ConfigMap")
			for _, tc := range []struct {
				name, from, to string
				raw            []byte
				complete       bool
				status, reason string
			}{
				{"removed version at the anchor", minorVersion(f.line-1, 0), minorVersion(f.line, 0), list(removed, other), true, "BLOCKED", reason},
				{"removed version between patches", minorVersion(f.line-1, 7), minorVersion(f.line, 2), list(other, removed), true, "BLOCKED", reason},
				{"served version, complete scope", minorVersion(f.line-1, 0), minorVersion(f.line, 0), list(served, other), true, "PASS", reason},
				{"served version between patches", minorVersion(f.line-1, 3), minorVersion(f.line, 1), list(served), true, "PASS", reason},
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
						} else if claim.Status == "BLOCKED" {
							// Other rules of the line may pass beside this one on a
							// shared hop (1.37 has two), never block.
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
			// The rules of other lines may pass beside this one, so only this
			// rule is held to it.
			if claim.RuleID == id && (claim.Status == "PASS" || claim.Status == "BLOCKED") {
				t.Fatalf("%s: %s decided %s on the next line", f.fact, claim.RuleID, claim.Status)
			}
		}
	}
}
