// SPDX-License-Identifier: AGPL-3.0-only

package supportinventory

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/customresources"
)

const communityCatalogSchema = "prufyx.io/cncf-source-rule-pack/v1alpha12"

// communityCatalogEntry is a test-only rule of a community-catalog project
// (never published).
func communityCatalogEntry(project string) map[string]any {
	var p customresources.Project
	for _, q := range customresources.CommunityProjects() {
		if q.Slug == project {
			p = q
		}
	}
	var rule map[string]any
	raw := `{"id":"` + project + `.crd-version-removal.synthetic.1-1-0-to-1-2-0","operator":"forbid_set_member","subject":{"component":"` + p.Component + `","from":"1.1.0","to":"1.2.0"},` +
		`"setCondition":{"side":"proposed","component":"` + p.Component + `","factId":"` + p.FactID() + `","members":["gateway.networking.k8s.io/v1beta1/Gateway"]},` +
		`"evidence":{"state":"active","reviewedAt":"2026-09-20T00:00:00Z","validUntil":"2026-12-19T00:00:00Z","sources":[{"id":"crd-1-2-0","url":"` + p.Upstream.Repository + `/blob/` + levelTestRevision + `/config/crd/gateways.yaml","revision":"` + levelTestRevision + `","contentDigest":"sha256:` + strings.Repeat("0", 64) + `","startLine":1,"endLine":2}]},` +
		`"reasonCode":"CRD_VERSION_NOT_SERVED","nextAction":"change apiVersion before upgrading to 1.2.0"}`
	if err := json.Unmarshal([]byte(raw), &rule); err != nil {
		panic(err)
	}
	return map[string]any{
		"description": "Synthetic test-only custom-resource version removal of a community project.", "project": project,
		"requiredFacts": []any{map[string]any{"side": "proposed", "id": p.FactID(), "component": p.Component, "type": "set", "description": "Custom-resource versions."}},
		"rule":          rule,
	}
}

func addCommunityCatalog(p map[string]any) {
	p["entries"] = append(p["entries"].([]any), communityCatalogEntry("gateway-api"))
	p["schema"] = communityCatalogSchema
}

// A community-catalog rule is listed apart from the CNCF rules, labelled, and
// counted in its own members: the CNCF counts are the same as without it.
func TestSupportInventory_CommunityCatalogRulesAreListedApart(t *testing.T) {
	base, err := generateWithPack(t, func(map[string]any) {})
	if err != nil {
		t.Fatal(err)
	}
	// The generator emits nothing for the community catalog while the pack
	// holds none: the gate regenerates with the base branch's generator.
	for _, key := range []string{"communityCatalogSourceRules", "communityCatalogRuleProjects"} {
		if _, present := base["counts"].(map[string]any)[key]; present {
			t.Fatalf("count %s present without a community-catalog rule", key)
		}
	}
	if _, present := base["scope"].(map[string]any)["communityCatalogRules"]; present {
		t.Fatal("scope member present without a community-catalog rule")
	}
	got, err := generateWithPack(t, addCommunityCatalog)
	if err != nil {
		t.Fatal(err)
	}
	counts, baseCounts := got["counts"].(map[string]any), base["counts"].(map[string]any)
	if counts["communityCatalogSourceRules"] != float64(1) || counts["communityCatalogRuleProjects"] != float64(1) {
		t.Fatalf("counts %v", counts)
	}
	for _, key := range []string{"cncfSourceRules", "cncfRuleProjects", "cncfSourceRulesWithdrawn", "communityProjectSourceRules", "communityProjectRuleProjects"} {
		if counts[key] != baseCounts[key] {
			t.Fatalf("%s moved from %v to %v", key, baseCounts[key], counts[key])
		}
	}
	if counts["executableProjects"] != baseCounts["executableProjects"].(float64)+1 {
		t.Fatalf("executable projects %v, base %v", counts["executableProjects"], baseCounts["executableProjects"])
	}
	var listed map[string]any
	for _, raw := range got["projects"].([]any) {
		if project := raw.(map[string]any); project["projectID"] == "gateway-api" {
			listed = project
		}
	}
	if listed == nil || listed["catalog"] != "community" || listed["catalogLabel"] != customresources.CommunityLabel || listed["supportState"] != "executable" {
		t.Fatalf("listed %v", listed)
	}
	capability := listed["capabilities"].([]any)[0].(map[string]any)
	if capability["kind"] != "embedded_community_catalog_source_rule" || !strings.Contains(capability["limit"].(string), "no CNCF status asserted") {
		t.Fatalf("capability %v", capability)
	}
	command, _ := json.Marshal(capability["command"])
	if !strings.Contains(string(command), "--custom-resources") || capability["localPreparer"] != nil {
		t.Fatalf("command %s, preparer %v", command, capability["localPreparer"])
	}
	// Every other project is exactly as without the rule.
	for _, raw := range base["projects"].([]any) {
		project := raw.(map[string]any)
		var same map[string]any
		for _, other := range got["projects"].([]any) {
			if other.(map[string]any)["projectID"] == project["projectID"] {
				same = other.(map[string]any)
			}
		}
		if !reflect.DeepEqual(project, same) {
			t.Fatalf("%v changed", project["projectID"])
		}
		if project["catalog"] != nil {
			t.Fatalf("%v is labelled", project["projectID"])
		}
	}
}

func TestSupportInventory_CommunityCatalogMarkdown(t *testing.T) {
	cfg, root := repositoryConfig(t)
	raw, err := os.ReadFile(filepath.Join(root, "internal/cncfcheck/data/rules.json"))
	if err != nil {
		t.Fatal(err)
	}
	var pack map[string]any
	if err := json.Unmarshal(raw, &pack); err != nil {
		t.Fatal(err)
	}
	_, baseMarkdown, err := Generate(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(baseMarkdown, "Community-catalog") || strings.Contains(baseMarkdown, "community catalog") {
		t.Fatal("the markdown names the community catalog without a rule of it")
	}
	addCommunityCatalog(pack)
	edited, _ := json.Marshal(pack)
	cfg.Rules = filepath.Join(t.TempDir(), "rules.json")
	if err := os.WriteFile(cfg.Rules, edited, 0o600); err != nil {
		t.Fatal(err)
	}
	_, markdown, err := Generate(cfg)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"- Community-catalog embedded source rules (projects outside the embedded CNCF landscape catalog; no CNCF status asserted; custom-resource versions only): **1** across **1** projects.",
		"(" + customresources.CommunityLabel + ")",
	} {
		if !strings.Contains(markdown, want) {
			t.Fatalf("markdown lacks %q", want)
		}
	}
}

// A community-catalog rule needs its schema, a project of the reviewed table
// that is not in the landscape, and nothing else is accepted for it.
func TestSupportInventory_CommunityCatalogRefusals(t *testing.T) {
	for name, edit := range map[string]func(map[string]any){
		"lower schema": func(p map[string]any) {
			addCommunityCatalog(p)
			p["schema"] = "prufyx.io/cncf-source-rule-pack/v1alpha11"
		},
		"schema without a community entry": func(p map[string]any) { p["schema"] = communityCatalogSchema },
		"unknown project": func(p map[string]any) {
			entry := communityCatalogEntry("gateway-api")
			entry["project"] = "not-a-catalog-project"
			p["entries"] = append(p["entries"].([]any), entry)
			p["schema"] = communityCatalogSchema
		},
		"support-range rule not listed": func(p map[string]any) {
			addCommunityCatalog(p)
			entries := p["entries"].([]any)
			rule := entries[len(entries)-1].(map[string]any)["rule"].(map[string]any)
			rule["severity"] = "unsupported"
		},
	} {
		if _, err := generateWithPack(t, edit); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
}
