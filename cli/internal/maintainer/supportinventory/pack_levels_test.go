// SPDX-License-Identifier: AGPL-3.0-only

package supportinventory

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

const (
	levelTestRevision = "0000000000000000000000000000000000000001"
	levelTestSetRule  = "kubernetes.synthetic-removed-gate.1-36-0-to-1-37-0"
)

// levelSetRule is a test-only forbid_set_member rule (it names no real
// gate and is never published).
func levelSetRule() map[string]any {
	var rule map[string]any
	raw := `{"id":"` + levelTestSetRule + `","operator":"forbid_set_member","subject":{"component":"pkg:github/kubernetes/kubernetes","from":"1.36.0","to":"1.37.0"},` +
		`"setCondition":{"side":"proposed","component":"pkg:github/kubernetes/kubernetes","factId":"component.kubernetes.kubelet_feature_gates_set","members":["SyntheticRemovedGate"]},` +
		`"evidence":{"state":"active","reviewedAt":"2026-09-20T00:00:00Z","validUntil":"2026-12-19T00:00:00Z","sources":[{"id":"synthetic-gate-declaration","url":"https://github.com/kubernetes/kubernetes/blob/` + levelTestRevision + `/pkg/features/kube_features.go","revision":"` + levelTestRevision + `","contentDigest":"sha256:` + strings.Repeat("0", 64) + `","startLine":1,"endLine":2}]},` +
		`"reasonCode":"KUBERNETES_FEATURE_GATE_REMOVED","nextAction":"remove SyntheticRemovedGate from every kubelet feature-gate setting before upgrading"}`
	if err := json.Unmarshal([]byte(raw), &rule); err != nil {
		panic(err)
	}
	return rule
}

// levelSeverityRule is a test-only support-range rule.
func levelSeverityRule() map[string]any {
	rule := levelSetRule()
	delete(rule, "setCondition")
	rule["id"] = "kubernetes.synthetic-support-range.1-36-0-to-1-37-0"
	rule["operator"] = "require_component_version"
	rule["severity"] = "unsupported"
	rule["reasonCode"] = "SYNTHETIC_OUTSIDE_SUPPORT_RANGE"
	return rule
}

// levelLeadRule is a test-only rule with a lead basis.
func levelLeadRule() map[string]any {
	rule := levelSetRule()
	rule["id"] = "kubernetes.synthetic-lead.1-36-0-to-1-37-0"
	rule["evidence"].(map[string]any)["basis"] = "lead"
	return rule
}

// levelNoticeRule is a test-only notice_one_way rule.
func levelNoticeRule() map[string]any {
	rule := levelSetRule()
	delete(rule, "setCondition")
	rule["id"] = "kubernetes.synthetic-one-way.1-36-0-to-1-37-0"
	rule["operator"] = "notice_one_way"
	rule["reasonCode"] = "ONE_WAY_TRANSITION"
	rule["nextAction"] = "take an etcd snapshot and verify that it restores before upgrading"
	return rule
}

func levelSource(id, repo, path string, start, end int) map[string]any {
	return map[string]any{
		"id": id, "url": "https://github.com/kubernetes/" + repo + "/blob/" + levelTestRevision + "/" + path,
		"revision": levelTestRevision, "contentDigest": "sha256:" + strings.Repeat("1", 64), "startLine": start, "endLine": end,
	}
}

func levelAttestations() []any {
	return []any{map[string]any{
		"component": "pkg:github/kubernetes/kubernetes", "line": "1.30", "factFamily": "kubernetes.removed_served_gvk",
		"completeness": "COMPLETE_REVIEWED_RULES_FOR_LINE", "ruleIds": []any{},
		"evidence": map[string]any{"basis": "reviewed", "reviewedAt": "2026-09-20T00:00:00Z", "validUntil": "2026-12-19T00:00:00Z",
			"sources": []any{levelSource("k8s-openapi", "kubernetes", "api/openapi-spec/swagger.json", 1, 1000)}},
	}}
}

func levelPolicies() []any {
	return []any{map[string]any{
		"component": "pkg:github/kubernetes/kubernetes", "policy": "sequential_minor",
		"evidence": map[string]any{"state": "active", "reviewedAt": "2026-09-20T00:00:00Z", "validUntil": "2026-12-19T00:00:00Z",
			"sources": []any{levelSource("skew-policy", "website", "content/en/releases/version-skew-policy.md", 189, 193)}},
	}}
}

// levelDistributions is a synthetic distribution section (test data, not
// knowledge).
func levelDistributions() map[string]any {
	evidence := func() map[string]any {
		return map[string]any{"state": "active", "reviewedAt": "2026-09-20T00:00:00Z", "validUntil": "2026-12-19T00:00:00Z",
			"sources": []any{levelSource("versions", "website", "content/en/releases/version-skew-policy.md", 1, 2)}}
	}
	return map[string]any{
		"records":       []any{map[string]any{"distribution": "eks", "controlPlane": "managed", "evidence": evidence()}},
		"applicability": []any{map[string]any{"distribution": "eks", "family": "kubernetes.removed_served_gvk", "status": "applies", "evidence": evidence()}},
	}
}

// levelServedAPIs is a synthetic served-API list section (test data, not
// knowledge).
func levelServedAPIs() []any {
	return []any{map[string]any{
		"component": "pkg:github/kubernetes/kubernetes", "line": "1.30", "completeness": "COMPLETE_SERVED_API_LIST_FOR_LINE",
		"apis": []any{"v1 ConfigMap"},
		"evidence": map[string]any{"basis": "reviewed", "reviewedAt": "2026-09-20T00:00:00Z", "validUntil": "2026-12-19T00:00:00Z",
			"sources": []any{levelSource("deprecation-guide", "website", "content/en/docs/reference/using-api/deprecation-guide.md", 1, 2)}},
	}}
}

// generateWithPack runs Generate over the repository inputs with the CNCF
// pack replaced by the embedded pack after edit.
func generateWithPack(t *testing.T, edit func(pack map[string]any)) (map[string]any, error) {
	t.Helper()
	cfg, root := repositoryConfig(t)
	raw, err := os.ReadFile(filepath.Join(root, "internal/cncfcheck/data/rules.json"))
	if err != nil {
		t.Fatal(err)
	}
	var pack map[string]any
	if err := json.Unmarshal(raw, &pack); err != nil {
		t.Fatal(err)
	}
	edit(pack)
	edited, err := json.Marshal(pack)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Rules = filepath.Join(t.TempDir(), "rules.json")
	if err := os.WriteFile(cfg.Rules, edited, 0o600); err != nil {
		t.Fatal(err)
	}
	out, _, err := Generate(cfg)
	if err != nil {
		return nil, err
	}
	var document map[string]any
	if err := json.Unmarshal(out, &document); err != nil {
		t.Fatal(err)
	}
	delete(document["inputDigests"].(map[string]any), "rules")
	return document, nil
}

// The inventory reads every CNCF pack schema of the loader's feature-level
// table: set rules (v1alpha3), line attestations (v1alpha4) and path
// policies (v1alpha5), notice rules (v1alpha6), consensus and lead rules
// (v1alpha7), support-range rules (v1alpha8) and distribution records
// (v1alpha9) each require exactly their level. Notices, consensus, lead and
// support-range rules, and distribution records, are then refused:
// the inventory does not list them yet. Attestations and
// policies add no capability, so the inventory is otherwise unchanged.
func TestSupportInventory_ReadsEveryPackSchemaLevel(t *testing.T) {
	base, err := generateWithPack(t, func(map[string]any) {})
	if err != nil {
		t.Fatal(err)
	}
	addSetRule := func(p map[string]any) {
		p["entries"] = append(p["entries"].([]any), map[string]any{
			"description": "Synthetic test-only removed kubelet feature gate.", "project": "kubernetes",
			"requiredFacts": []any{map[string]any{"side": "proposed", "id": "component.kubernetes.kubelet_feature_gates_set", "component": "pkg:github/kubernetes/kubernetes", "type": "set", "description": "Feature gates the kubelet sets."}},
			"rule":          levelSetRule(),
		})
	}
	addRule := func(p map[string]any, rule map[string]any) {
		p["entries"] = append(p["entries"].([]any), map[string]any{"description": "d", "project": "kubernetes", "requiredFacts": []any{}, "rule": rule})
	}
	addNoticeRule := func(p map[string]any) {
		p["entries"] = append(p["entries"].([]any), map[string]any{
			"description": "Synthetic test-only one-way transition.", "project": "kubernetes", "requiredFacts": []any{}, "rule": levelNoticeRule(),
		})
	}
	schemas := []string{
		"prufyx.io/cncf-source-rule-pack/v1alpha1", "prufyx.io/cncf-source-rule-pack/v1alpha2", "prufyx.io/cncf-source-rule-pack/v1alpha3",
		"prufyx.io/cncf-source-rule-pack/v1alpha4", "prufyx.io/cncf-source-rule-pack/v1alpha5", "prufyx.io/cncf-source-rule-pack/v1alpha6",
		"prufyx.io/cncf-source-rule-pack/v1alpha7", "prufyx.io/cncf-source-rule-pack/v1alpha8", "prufyx.io/cncf-source-rule-pack/v1alpha9",
		"prufyx.io/cncf-source-rule-pack/v1alpha10", "prufyx.io/cncf-source-rule-pack/v1alpha11", "prufyx.io/cncf-source-rule-pack/v1alpha12",
	}
	for _, tc := range []struct {
		name      string
		edit      func(map[string]any)
		want      string
		unchanged bool
		// refusal is the error the right schema still meets (the
		// inventory does not list notices yet).
		refusal string
	}{
		{name: "ranged (published)", edit: func(map[string]any) {}, want: schemas[1], unchanged: true},
		{name: "set rule", edit: addSetRule, want: schemas[2]},
		{name: "line attestations", edit: func(p map[string]any) { p["lineAttestations"] = levelAttestations() }, want: schemas[3], unchanged: true},
		{name: "path policies", edit: func(p map[string]any) { p["pathPolicies"] = levelPolicies() }, want: schemas[4], unchanged: true},
		{name: "attestations and policies", edit: func(p map[string]any) {
			p["lineAttestations"], p["pathPolicies"] = levelAttestations(), levelPolicies()
		}, want: schemas[4], unchanged: true},
		{name: "set rule and attestations", edit: func(p map[string]any) { addSetRule(p); p["lineAttestations"] = levelAttestations() }, want: schemas[3]},
		{name: "notice rule", edit: addNoticeRule, want: schemas[5], refusal: "does not list notices"},
		{name: "notice rule, set rule, attestations and policies", edit: func(p map[string]any) {
			addNoticeRule(p)
			addSetRule(p)
			p["lineAttestations"], p["pathPolicies"] = levelAttestations(), levelPolicies()
		}, want: schemas[5], refusal: "does not list notices"},
		{name: "lead rule", edit: func(p map[string]any) { addRule(p, levelLeadRule()) }, want: schemas[6], refusal: "does not list consensus or lead rules"},
		{name: "consensus rule", edit: func(p map[string]any) {
			rule := levelLeadRule()
			rule["evidence"].(map[string]any)["basis"] = "consensus"
			addRule(p, rule)
		}, want: schemas[6], refusal: "does not list consensus or lead rules"},
		{name: "support-range rule", edit: func(p map[string]any) { addRule(p, levelSeverityRule()) }, want: schemas[7], refusal: "does not list support-range rules"},
		{name: "support-range rule, notice and attestations", edit: func(p map[string]any) {
			addRule(p, levelSeverityRule())
			addNoticeRule(p)
			p["lineAttestations"] = levelAttestations()
		}, want: schemas[7], refusal: "does not list"},
		{name: "distributions", edit: func(p map[string]any) { p["distributions"] = levelDistributions() }, want: schemas[8], refusal: "does not list distribution records"},
		{name: "distributions, set rule, attestations and policies", edit: func(p map[string]any) {
			addSetRule(p)
			p["distributions"], p["lineAttestations"], p["pathPolicies"] = levelDistributions(), levelAttestations(), levelPolicies()
		}, want: schemas[8], refusal: "does not list distribution records"},
		{name: "served-API lists", edit: func(p map[string]any) { p["servedAPIs"] = levelServedAPIs() }, want: schemas[9], refusal: "does not list served-API lists"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, schema := range schemas {
				document, err := generateWithPack(t, func(p map[string]any) { tc.edit(p); p["schema"] = schema })
				if schema != tc.want {
					if err == nil || !strings.Contains(err.Error(), "invalid rule-pack schema") {
						t.Fatalf("schema %s accepted for a pack whose level is %s: %v", schema, tc.want, err)
					}
					continue
				}
				if tc.refusal != "" {
					if err == nil || !strings.Contains(err.Error(), tc.refusal) {
						t.Fatalf("schema %s: expected %q, got %v", schema, tc.refusal, err)
					}
					continue
				}
				if err != nil {
					t.Fatalf("schema %s: %v", schema, err)
				}
				if tc.unchanged && !reflect.DeepEqual(document, base) {
					t.Fatal("the inventory changed")
				}
				if !tc.unchanged && reflect.DeepEqual(document, base) {
					t.Fatal("the set rule is missing from the inventory")
				}
			}
		})
	}
}

func TestSupportInventory_SetRuleIsListed(t *testing.T) {
	document, err := generateWithPack(t, func(p map[string]any) {
		p["schema"] = "prufyx.io/cncf-source-rule-pack/v1alpha3"
		p["entries"] = append(p["entries"].([]any), map[string]any{"description": "d", "project": "kubernetes", "requiredFacts": []any{}, "rule": levelSetRule()})
	})
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(document)
	if !strings.Contains(string(raw), levelTestSetRule) {
		t.Fatal("the set rule is not listed")
	}
}

// A section under a variant spelling of its member name is refused, never
// skipped.
func TestSupportInventory_RefusesVariantPackMembers(t *testing.T) {
	for _, name := range []string{"LineAttestations", "PATHPOLICIES", "pathPolicieſ", "notices", "Distributions", "distribution"} {
		if _, err := generateWithPack(t, func(p map[string]any) { p[name] = levelPolicies() }); err == nil {
			t.Fatalf("member %q accepted", name)
		}
	}
}

// A notice rule is never listed or counted as an executable rule: the
// inventory refuses a pack with one, under its right schema, until notices
// have their own section.
func TestSupportInventory_RefusesNoticeRules(t *testing.T) {
	_, err := generateWithPack(t, func(p map[string]any) {
		p["schema"] = "prufyx.io/cncf-source-rule-pack/v1alpha6"
		p["entries"] = append(p["entries"].([]any), map[string]any{"description": "d", "project": "kubernetes", "requiredFacts": []any{}, "rule": levelNoticeRule()})
	})
	if err == nil || !strings.Contains(err.Error(), "the inventory does not list notices yet") {
		t.Fatalf("a notice rule was accepted: %v", err)
	}
}

// The community-project table has no set level: a community pack with a set
// rule is refused under the CNCF set level's number (v1alpha3, which the
// community pack uses for notices) and above, because the pack holds no
// notice or support-range rule that would justify the schema. (Its
// v1alpha1-v1alpha4 acceptance mirrors the community pack loader's schema
// check; the engine refuses set rules there.)
func TestSupportInventory_CommunityPackRefusesSetRules(t *testing.T) {
	cfg, root := repositoryConfig(t)
	raw, err := os.ReadFile(filepath.Join(root, "internal/projectcheck/data/rules.json"))
	if err != nil {
		t.Fatal(err)
	}
	var pack map[string]any
	if err := json.Unmarshal(raw, &pack); err != nil {
		t.Fatal(err)
	}
	entries := pack["entries"].([]any)
	first := entries[0].(map[string]any)
	rule := levelSetRule()
	rule["subject"] = first["rule"].(map[string]any)["subject"]
	pack["entries"] = append(entries, map[string]any{"description": "d", "project": first["project"], "requiredFacts": []any{}, "rule": rule})
	for _, schema := range []string{
		"prufyx.io/community-project-source-rule-pack/v1alpha3", "prufyx.io/community-project-source-rule-pack/v1alpha4",
	} {
		pack["schema"] = schema
		edited, err := json.Marshal(pack)
		if err != nil {
			t.Fatal(err)
		}
		cfg.ProjectRules = filepath.Join(t.TempDir(), "rules.json")
		if err := os.WriteFile(cfg.ProjectRules, edited, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, _, err := Generate(cfg); err == nil || !strings.Contains(err.Error(), "invalid community-project source schema") {
			t.Fatalf("schema %s: a community set-rule pack was not refused for its schema: %v", schema, err)
		}
	}
}
