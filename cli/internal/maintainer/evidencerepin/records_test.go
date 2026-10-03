// SPDX-License-Identifier: AGPL-3.0-only

package evidencerepin

import (
	"encoding/json"
	"regexp"
	"strings"
	"testing"
)

// recordPack is a rule pack with one rule, one line attestation and one
// path-policy record, each citing its own source.
func recordPack(t *testing.T, mutate func(pack map[string]any)) []byte {
	t.Helper()
	digest := "sha256:" + strings.Repeat("cd", 32)
	pack := map[string]any{
		"schema": "prufyx.io/rule-pack/v1", "revision": "test",
		"entries": []map[string]any{ruleEntry("argo-cd", "argo-cd.rule-1", source("argo-cd-src", "argoproj", "argo-cd", commitA, "VERSION", digest, 1, 2))},
		"lineAttestations": []map[string]any{{
			"component": "pkg:github/kubernetes/kubernetes", "line": "1.30", "factFamily": "kubernetes.removed_served_gvk",
			"completeness": "COMPLETE_REVIEWED_RULES_FOR_LINE", "ruleIds": []string{},
			"evidence": map[string]any{
				"basis": "reviewed", "reviewedAt": "2026-09-12T10:00:00Z", "validUntil": "2026-12-11T10:00:00Z",
				"sources": []map[string]any{source("k8s-openapi", "kubernetes", "kubernetes", commitB, "api/openapi-spec/swagger.json", digest, 1, 90000)},
			},
		}},
		"pathPolicies": []map[string]any{{
			"component": "pkg:github/kubernetes/kubernetes", "policy": "sequential_minor",
			"evidence": map[string]any{
				"state": "active", "reviewedAt": "2026-09-12T10:00:00Z", "validUntil": "2026-12-11T10:00:00Z",
				"sources": []map[string]any{source("skew-policy", "kubernetes", "website", commitA, "content/en/releases/version-skew-policy.md", digest, 189, 193)},
			},
		}},
	}
	if mutate != nil {
		mutate(pack)
	}
	raw, err := json.Marshal(pack)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestLoadCitationsIncludesRecordCitations(t *testing.T) {
	citations, err := LoadCitations("rules.json", recordPack(t, nil))
	if err != nil {
		t.Fatalf("LoadCitations: %v", err)
	}
	if len(citations) != 3 {
		t.Fatalf("expected 3 citations (rule, attestation, path policy), got %+v", citations)
	}
	attestationID := LineAttestationRecordID("pkg:github/kubernetes/kubernetes", "kubernetes.removed_served_gvk", "1.30")
	policyID := PathPolicyRecordID("pkg:github/kubernetes/kubernetes")
	want := []Citation{
		{RulePack: "rules.json", RuleID: "argo-cd.rule-1", Project: "argo-cd", SourceID: "argo-cd-src", Owner: "argoproj", Repo: "argo-cd", Path: "VERSION", OldCommit: commitA},
		{RulePack: "rules.json", RuleID: attestationID, Project: RecordProjectLineAttestations, SourceID: "k8s-openapi", Owner: "kubernetes", Repo: "kubernetes", Path: "api/openapi-spec/swagger.json", OldCommit: commitB},
		{RulePack: "rules.json", RuleID: policyID, Project: RecordProjectPathPolicies, SourceID: "skew-policy", Owner: "kubernetes", Repo: "website", Path: "content/en/releases/version-skew-policy.md", OldCommit: commitA},
	}
	for i, w := range want {
		got := citations[i]
		if got.RulePack != w.RulePack || got.RuleID != w.RuleID || got.Project != w.Project || got.SourceID != w.SourceID || got.Owner != w.Owner || got.Repo != w.Repo || got.Path != w.Path || got.OldCommit != w.OldCommit || got.OldDigest == "" || got.StartLine < 1 {
			t.Fatalf("citation %d: got %+v want %+v", i, got, w)
		}
	}
	if citations[1].EndLine != 90000 || citations[2].StartLine != 189 || citations[2].EndLine != 193 {
		t.Fatalf("record spans not carried: %+v", citations[1:])
	}
}

func TestRecordIDsAreRuleShapedAndDistinct(t *testing.T) {
	ruleShaped := regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,127}$`)
	ids := map[string]bool{}
	for _, id := range []string{
		LineAttestationRecordID("pkg:github/kubernetes/kubernetes", "kubernetes.removed_served_gvk", "1.30"),
		LineAttestationRecordID("pkg:github/kubernetes/kubernetes", "kubernetes.removed_served_gvk", "1.31"),
		LineAttestationRecordID("pkg:github/kubernetes/kubernetes", "kubernetes.removed_served_gv", "k1.30"),
		PathPolicyRecordID("pkg:github/kubernetes/kubernetes"),
		PathPolicyRecordID("pkg:github/etcd-io/etcd"),
	} {
		if !ruleShaped.MatchString(id) || ids[id] {
			t.Fatalf("record ID %q is not rule-shaped or not distinct", id)
		}
		ids[id] = true
	}
	if !strings.HasPrefix(PathPolicyRecordID("pkg:github/etcd-io/etcd"), "path-policy.") ||
		!strings.HasPrefix(LineAttestationRecordID("a", "b", "c"), "line-attestation.") {
		t.Fatal("record ID prefixes changed")
	}
}

func TestLoadCitationsRejectsUnreadableRecordSections(t *testing.T) {
	for name, mutate := range map[string]func(map[string]any){
		"case variant of the attestation member": func(p map[string]any) { p["LineAttestations"] = p["lineAttestations"]; delete(p, "lineAttestations") },
		"case variant of the policy member":      func(p map[string]any) { p["PathPolicies"] = p["pathPolicies"]; delete(p, "pathPolicies") },
		"unknown member":                         func(p map[string]any) { p["notices"] = []any{} },
		"empty attestation section":              func(p map[string]any) { p["lineAttestations"] = []any{} },
		"null policy section":                    func(p map[string]any) { p["pathPolicies"] = nil },
		"attestation without basis": func(p map[string]any) {
			delete(p["lineAttestations"].([]map[string]any)[0]["evidence"].(map[string]any), "basis")
		},
		"policy source with mismatched revision": func(p map[string]any) {
			p["pathPolicies"].([]map[string]any)[0]["evidence"].(map[string]any)["sources"].([]map[string]any)[0]["revision"] = commitB
		},
		"rule with a record's ID": func(p map[string]any) {
			p["entries"].([]map[string]any)[0]["rule"].(map[string]any)["id"] = PathPolicyRecordID("pkg:github/kubernetes/kubernetes")
		},
	} {
		t.Run(name, func(t *testing.T) {
			if citations, err := LoadCitations("rules.json", recordPack(t, mutate)); err == nil {
				t.Fatalf("accepted: %+v", citations)
			}
		})
	}
}

func TestLoadCitationsIncludesMechanicalRecordCitations(t *testing.T) {
	raw := recordPack(t, func(p map[string]any) {
		evidence := p["lineAttestations"].([]map[string]any)[0]["evidence"].(map[string]any)
		evidence["basis"] = "mechanical"
		evidence["extractor"] = map[string]any{"id": "k8s.served-api-removal", "version": "1.1.0", "codeDigest": "sha256:" + strings.Repeat("ab", 32)}
		evidence["derivedAt"] = evidence["reviewedAt"]
	})
	citations, err := LoadCitations("rules.json", raw)
	if err != nil || len(citations) != 3 || citations[1].Project != RecordProjectLineAttestations {
		t.Fatalf("citations=%+v err=%v", citations, err)
	}
}
