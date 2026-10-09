// SPDX-License-Identifier: AGPL-3.0-only

package supportinventory

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const communityTestComponent = "pkg:github/grafana/grafana"

// communityTestRule is a test-only rule on the Grafana identity, never
// published.
func communityTestRule(id, operator, reason, action string, extra map[string]any) map[string]any {
	rule := map[string]any{
		"id": id, "operator": operator,
		"subject": map[string]any{"component": communityTestComponent, "from": "11.0.0", "to": "11.1.0"},
		"evidence": map[string]any{"state": "active", "reviewedAt": "2026-09-20T00:00:00Z", "validUntil": "2026-12-19T00:00:00Z",
			"sources": []any{map[string]any{"id": "synthetic-source", "url": "https://github.com/grafana/grafana/blob/" + levelTestRevision + "/CHANGELOG.md", "revision": levelTestRevision, "contentDigest": "sha256:" + strings.Repeat("0", 64), "startLine": 1, "endLine": 2}}},
		"reasonCode": reason, "nextAction": action,
	}
	for key, value := range extra {
		rule[key] = value
	}
	return rule
}

func communityTestEntries() (support, notice map[string]any) {
	support = map[string]any{"project": "grafana", "description": "d", "requiredFacts": []any{}, "rule": communityTestRule("grafana.synthetic-support", "require_component_version", "ADDON_KUBERNETES_SUPPORT_RANGE", "move to a supported release line", map[string]any{
		"severity": "unsupported", "dependency": map[string]any{"side": "proposed", "component": "pkg:github/kubernetes/kubernetes", "comparison": "gte", "version": "1.38.0"}})}
	notice = map[string]any{"project": "grafana", "description": "d", "requiredFacts": []any{}, "rule": communityTestRule("grafana.synthetic-one-way", "notice_one_way", "ONE_WAY_TRANSITION", "take a backup and verify that it restores before upgrading", nil)}
	return support, notice
}

func generateCommunity(t *testing.T, edit func(pack map[string]any)) (map[string]any, string, error) {
	t.Helper()
	cfg, root := repositoryConfig(t)
	raw, err := os.ReadFile(filepath.Join(root, "internal/projectcheck/data/rules.json"))
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
	cfg.ProjectRules = filepath.Join(t.TempDir(), "rules.json")
	if err := os.WriteFile(cfg.ProjectRules, edited, 0o600); err != nil {
		t.Fatal(err)
	}
	generated, markdown, err := Generate(cfg)
	if err != nil {
		return nil, "", err
	}
	var document map[string]any
	if err := json.Unmarshal(generated, &document); err != nil {
		t.Fatal(err)
	}
	return document, markdown, nil
}

// TestSupportInventory_CommunitySupportRangeAndNoticesAreCountedSeparately:
// a community pack holding a support-range rule and a notice is listed with
// each counted on its own line, never inside the verdict-rule count, with
// wording that does not call either a verdict.
func TestSupportInventory_CommunitySupportRangeAndNoticesAreCountedSeparately(t *testing.T) {
	baseline, _, err := generateCommunity(t, func(map[string]any) {})
	if err != nil {
		t.Fatal(err)
	}
	support, notice := communityTestEntries()
	document, markdown, err := generateCommunity(t, func(pack map[string]any) {
		pack["schema"] = "prufyx.io/community-project-source-rule-pack/v1alpha4"
		pack["entries"] = append(pack["entries"].([]any), support, notice)
	})
	if err != nil {
		t.Fatal(err)
	}
	base, got := baseline["counts"].(map[string]any), document["counts"].(map[string]any)
	if got["communityProjectSourceRules"] != base["communityProjectSourceRules"] || got["communityProjectSupportRangeRules"] != float64(1) || got["communityProjectNotices"] != float64(1) || got["communityProjectRuleProjects"] != base["communityProjectRuleProjects"] {
		t.Fatalf("counts=%v baseline=%v", got, base)
	}
	if _, ok := base["communityProjectSupportRangeRules"]; ok {
		t.Fatalf("baseline counts=%v", base)
	}
	if _, ok := base["communityProjectNotices"]; ok {
		t.Fatalf("baseline counts=%v", base)
	}
	kinds := map[string]string{}
	for _, project := range document["projects"].([]any) {
		p := project.(map[string]any)
		if p["projectID"] != "grafana" {
			continue
		}
		for _, capability := range p["capabilities"].([]any) {
			for _, rule := range capability.(map[string]any)["rules"].([]any) {
				r := rule.(map[string]any)
				if kind, ok := r["ruleKind"].(string); ok {
					kinds[r["ruleID"].(string)] = kind + "|" + r["limit"].(string)
				}
			}
		}
	}
	if !strings.HasPrefix(kinds["grafana.synthetic-support"], "support_range|") || !strings.Contains(kinds["grafana.synthetic-support"], "UNSUPPORTED (not verified, not shown to be broken), never BLOCKED") ||
		!strings.HasPrefix(kinds["grafana.synthetic-one-way"], "one_way_notice|") || !strings.Contains(kinds["grafana.synthetic-one-way"], "not a verdict, never passes or blocks") {
		t.Fatalf("kinds=%v", kinds)
	}
	for _, line := range []string{"Community-project support-range rules (counted separately", "Community-project one-way notices (counted separately; informational, not verdicts, not executable checks): **1**"} {
		if !strings.Contains(markdown, line) {
			t.Fatalf("markdown lacks %q", line)
		}
	}
}

func communityProject(t *testing.T, document map[string]any, id string) map[string]any {
	t.Helper()
	for _, project := range document["projects"].([]any) {
		if p := project.(map[string]any); p["projectID"] == id {
			return p
		}
	}
	return nil
}

func capabilityKinds(project map[string]any) map[string][]string {
	kinds := map[string][]string{}
	for _, capability := range project["capabilities"].([]any) {
		c := capability.(map[string]any)
		command := []string{}
		for _, part := range c["command"].([]any) {
			command = append(command, part.(string))
		}
		kinds[c["kind"].(string)] = command
	}
	return kinds
}

// withoutGrafanaVerdictRules keeps every other project's entries and adds extra.
func withoutGrafanaVerdictRules(pack map[string]any, extra ...any) {
	kept := append([]any{}, extra...)
	for _, entry := range pack["entries"].([]any) {
		if entry.(map[string]any)["project"] != "grafana" {
			kept = append(kept, entry)
		}
	}
	pack["entries"] = kept
}

// TestSupportInventory_CommunityNoticeOnlyProjectIsListedNotExecutable: a
// project whose only rules are notices is counted as a notice, listed under
// its own state and capability kind, and not counted as executable.
func TestSupportInventory_CommunityNoticeOnlyProjectIsListedNotExecutable(t *testing.T) {
	baseline, _, err := generateCommunity(t, func(map[string]any) {})
	if err != nil {
		t.Fatal(err)
	}
	_, notice := communityTestEntries()
	document, markdown, err := generateCommunity(t, func(pack map[string]any) {
		pack["schema"] = "prufyx.io/community-project-source-rule-pack/v1alpha3"
		withoutGrafanaVerdictRules(pack, notice)
	})
	if err != nil {
		t.Fatal(err)
	}
	counts := document["counts"].(map[string]any)
	if counts["communityProjectNotices"] != float64(1) || counts["executableProjects"] != baseline["counts"].(map[string]any)["executableProjects"].(float64)-1 {
		t.Fatalf("counts=%v", counts)
	}
	project := communityProject(t, document, "grafana")
	if project == nil || project["supportState"] != "notice_only" {
		t.Fatalf("a notice-only project is not listed as notice_only: %v", project)
	}
	if kinds := capabilityKinds(project); len(kinds) != 1 || kinds["embedded_community_project_one_way_notice"] == nil {
		t.Fatalf("capabilities=%v", kinds)
	}
	if !strings.Contains(markdown, "Projects with rules that decide no transition on their own") || !strings.Contains(markdown, "grafana.synthetic-one-way") {
		t.Fatalf("markdown does not list the notice-only project")
	}
}

// TestSupportInventory_CommunitySupportRangeIsItsOwnCapability: a support
// range is a capability of its own on the `check batch` route. It never makes
// a project executable by itself and never changes the executable union.
func TestSupportInventory_CommunitySupportRangeIsItsOwnCapability(t *testing.T) {
	baseline, _, err := generateCommunity(t, func(map[string]any) {})
	if err != nil {
		t.Fatal(err)
	}
	union := baseline["counts"].(map[string]any)["executableProjects"].(float64)
	support, notice := communityTestEntries()

	// Next to verdict rules: the union is unchanged, the support range sits
	// on `check batch`, and the verdict capability does not list it.
	document, _, err := generateCommunity(t, func(pack map[string]any) {
		pack["schema"] = "prufyx.io/community-project-source-rule-pack/v1alpha4"
		pack["entries"] = append(pack["entries"].([]any), support, notice)
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := document["counts"].(map[string]any)["executableProjects"]; got != union {
		t.Fatalf("executable union changed: %v -> %v", union, got)
	}
	project := communityProject(t, document, "grafana")
	kinds := capabilityKinds(project)
	if project["supportState"] != "executable" || strings.Join(kinds["embedded_community_project_support_range"], " ") != "check batch" || strings.Join(kinds["embedded_community_project_source_rule"], " ") != "check project --project grafana" {
		t.Fatalf("state=%v kinds=%v", project["supportState"], kinds)
	}
	for _, capability := range project["capabilities"].([]any) {
		c := capability.(map[string]any)
		for _, rule := range c["rules"].([]any) {
			id := rule.(map[string]any)["ruleID"]
			if id == "grafana.synthetic-support" && c["kind"] != "embedded_community_project_support_range" {
				t.Fatalf("the support range is listed under %v", c["kind"])
			}
		}
	}

	// A project holding only a support range is not executable.
	document, markdown, err := generateCommunity(t, func(pack map[string]any) {
		pack["schema"] = "prufyx.io/community-project-source-rule-pack/v1alpha4"
		withoutGrafanaVerdictRules(pack, support)
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := document["counts"].(map[string]any)["executableProjects"]; got != union-1 {
		t.Fatalf("a support-range-only project is counted as executable: %v (was %v)", got, union)
	}
	project = communityProject(t, document, "grafana")
	if project == nil || project["supportState"] != "support_range_only" {
		t.Fatalf("project=%v", project)
	}
	if kinds := capabilityKinds(project); len(kinds) != 1 || strings.Join(kinds["embedded_community_project_support_range"], " ") != "check batch" {
		t.Fatalf("capabilities=%v", kinds)
	}
	if !strings.Contains(markdown, "support_range_only") || !strings.Contains(markdown, "prufyx check batch") {
		t.Fatalf("markdown does not list the support-range-only project")
	}
}

// TestSupportInventory_CommunityPackSchemaMustMatchItsFeatures: the pack
// schema must state the highest feature the pack holds.
func TestSupportInventory_CommunityPackSchemaMustMatchItsFeatures(t *testing.T) {
	support, notice := communityTestEntries()
	for name, tc := range map[string]struct {
		schema  string
		entries []any
		ok      bool
	}{
		"support range under severity": {"prufyx.io/community-project-source-rule-pack/v1alpha4", []any{support}, true},
		"support range under notice":   {"prufyx.io/community-project-source-rule-pack/v1alpha3", []any{support}, false},
		"support range under ranged":   {"prufyx.io/community-project-source-rule-pack/v1alpha2", []any{support}, false},
		"notice under notice":          {"prufyx.io/community-project-source-rule-pack/v1alpha3", []any{notice}, true},
		"notice under severity":        {"prufyx.io/community-project-source-rule-pack/v1alpha4", []any{notice}, false},
		"notice under exact":           {"prufyx.io/community-project-source-rule-pack/v1alpha1", []any{notice}, false},
	} {
		t.Run(name, func(t *testing.T) {
			_, _, err := generateCommunity(t, func(pack map[string]any) {
				pack["schema"] = tc.schema
				pack["entries"] = append(pack["entries"].([]any), tc.entries...)
			})
			if tc.ok != (err == nil) {
				t.Fatalf("err=%v, want ok=%v", err, tc.ok)
			}
		})
	}
}
