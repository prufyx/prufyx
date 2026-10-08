// SPDX-License-Identifier: AGPL-3.0-only

package knowledgegate

import (
	"slices"
	"sort"
	"strings"
	"testing"
)

const (
	communitySeverityPack   = "prufyx.io/community-project-source-rule-pack/v1alpha4"
	communitySupportRuleID  = "grafana.synthetic-support"
	communityNoticeRuleID   = "grafana.synthetic-one-way"
	communityTestRevisionID = "0000000000000000000000000000000000000001"
)

func communityRule(id, operator, reason, action string, extra map[string]any) map[string]any {
	rule := map[string]any{
		"id": id, "operator": operator,
		"subject": map[string]any{"component": "pkg:github/grafana/grafana", "from": "11.0.0", "to": "11.1.0"},
		"evidence": map[string]any{"state": "active", "reviewedAt": "2026-09-20T00:00:00Z", "validUntil": "2026-12-19T00:00:00Z",
			"sources": []any{map[string]any{"id": "synthetic-source", "url": "https://github.com/grafana/grafana/blob/" + communityTestRevisionID + "/CHANGELOG.md", "revision": communityTestRevisionID, "contentDigest": "sha256:" + strings.Repeat("0", 64), "startLine": 1, "endLine": 2}}},
		"reasonCode": reason, "nextAction": action,
	}
	for key, value := range extra {
		rule[key] = value
	}
	return rule
}

// sortCommunity orders entries as the community pack requires: by project,
// then by rule id (sortByID orders by rule id alone, which is the CNCF
// pack's order).
func sortCommunity(p *packDoc) {
	sort.SliceStable(p.entries, func(i, j int) bool {
		if a, b := p.entries[i]["project"].(string), p.entries[j]["project"].(string); a != b {
			return a < b
		}
		return ruleID(p.entries[i]) < ruleID(p.entries[j])
	})
}

func communityEntry(rule map[string]any) map[string]any {
	return map[string]any{"project": "grafana", "description": "d", "requiredFacts": []any{}, "rule": rule}
}

func communitySupportEntry() map[string]any {
	return communityEntry(communityRule(communitySupportRuleID, "require_component_version", "ADDON_KUBERNETES_SUPPORT_RANGE", "move to a supported release line", map[string]any{
		"severity": "unsupported", "dependency": map[string]any{"side": "proposed", "component": "pkg:github/kubernetes/kubernetes", "comparison": "gte", "version": "1.38.0"}}))
}

func communityNoticeEntry() map[string]any {
	return communityEntry(communityRule(communityNoticeRuleID, "notice_one_way", "ONE_WAY_TRANSITION", "take a backup and verify that it restores before upgrading", nil))
}

// TestClassifyCommunitySupportRangeAndNoticeChanges: the knowledge gate
// classifies support-range and notice rules of the community pack exactly as
// it classifies those of the CNCF pack. Adding one is a loosening change
// that needs a proof (as for any new rule), a changed reason code is a
// loosening modification, and withdrawing one is tightening. The pack
// schema stays a pack-member change that the gate never admits on its own.
func TestClassifyCommunitySupportRangeAndNoticeChanges(t *testing.T) {
	withBase := func(p *packDoc) {
		p.fields["schema"] = []byte(`"` + communitySeverityPack + `"`)
		p.entries = append(p.entries, communitySupportEntry())
		sortCommunity(p)
	}
	for name, tc := range map[string]struct {
		head      func(p *packDoc)
		id        string
		class     string
		kinds     []string
		withdrawn bool
	}{
		"add a support-range rule": {func(p *packDoc) {
			e := communityEntry(communityRule("grafana.synthetic-support-b", "require_component_version", "ADDON_KUBERNETES_SUPPORT_RANGE", "move to a supported release line", map[string]any{
				"severity": "unsupported", "dependency": map[string]any{"side": "proposed", "component": "pkg:github/kubernetes/kubernetes", "comparison": "gte", "version": "1.39.0"}}))
			p.entries = append(p.entries, e)
			sortCommunity(p)
		}, "grafana.synthetic-support-b", ClassLoosening, []string{KindNew}, false},
		"add a notice": {func(p *packDoc) {
			p.entries = append(p.entries, communityNoticeEntry())
			sortCommunity(p)
		}, communityNoticeRuleID, ClassLoosening, []string{KindNew}, false},
		"change a support-range reason": {func(p *packDoc) {
			ruleOf(p.find(t, communitySupportRuleID))["reasonCode"] = "REVIEWED_SUPPORT_RANGE"
		}, communitySupportRuleID, ClassLoosening, []string{KindModify}, false},
		"withdraw a support-range rule": {func(p *packDoc) {
			evidenceOf(p.find(t, communitySupportRuleID))["state"] = "withdrawn"
		}, communitySupportRuleID, ClassTightening, []string{KindWithdraw}, true},
		"add a withdrawn notice": {func(p *packDoc) {
			e := communityNoticeEntry()
			evidenceOf(e)["state"] = "withdrawn"
			p.entries = append(p.entries, e)
			sortCommunity(p)
		}, communityNoticeRuleID, ClassTightening, []string{KindAddWithdrawn}, true},
	} {
		t.Run(name, func(t *testing.T) {
			base, head := trees(t)
			editPack(t, base, commRulesPath, withBase)
			editPack(t, head, commRulesPath, withBase)
			if tc.withdrawn {
				// The community support inventory lists active rules only
				// and refuses a withdrawn one (for any rule, not only these),
				// so its regeneration is skipped; the classifier reads packs.
				p := readPack(t, head, commRulesPath)
				tc.head(p)
				p.write(t, head, commRulesPath)
			} else {
				editPack(t, head, commRulesPath, tc.head)
			}
			cls, err := Classify(DefaultLayout(), base, head)
			if err != nil {
				t.Fatal(err)
			}
			var got *Change
			for _, c := range cls.Changes {
				if c.RuleID == tc.id {
					got = c
				} else if c.Member == "" {
					t.Fatalf("unexpected change %+v", c)
				}
			}
			if got == nil || got.Pack != "community" || got.Class != tc.class || !slices.Equal(got.Kinds, tc.kinds) {
				t.Fatalf("change %+v, want %s %v", got, tc.class, tc.kinds)
			}
		})
	}
}

// TestClassifyCommunitySchemaBumpIsAPackMemberChange: the first support-range
// rule of the pack moves the schema to the severity level, which the gate
// reports as a loosening pack-member change it never admits by itself (the
// same as the CNCF pack's schema levels); the rule itself is a new rule.
func TestClassifyCommunitySchemaBumpIsAPackMemberChange(t *testing.T) {
	base, head := trees(t)
	editPack(t, head, commRulesPath, func(p *packDoc) {
		p.fields["schema"] = []byte(`"` + communitySeverityPack + `"`)
		p.entries = append(p.entries, communitySupportEntry())
		sortCommunity(p)
	})
	cls, err := Classify(DefaultLayout(), base, head)
	if err != nil {
		t.Fatal(err)
	}
	var member, rule bool
	for _, c := range cls.Changes {
		switch {
		case c.Member == "schema":
			member = c.Class == ClassLoosening && slices.Equal(c.Kinds, []string{KindPackMember})
		case c.RuleID == communitySupportRuleID:
			rule = c.Class == ClassLoosening && slices.Equal(c.Kinds, []string{KindNew})
		}
	}
	if !member || !rule {
		t.Fatalf("changes=%+v", cls.Changes)
	}
}
