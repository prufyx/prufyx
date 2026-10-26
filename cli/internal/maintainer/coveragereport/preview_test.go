// SPDX-License-Identifier: AGPL-3.0-only

package coveragereport

import "testing"

func TestRenderPreview(t *testing.T) {
	t.Parallel()
	inv := []byte(`{"counts":{"cncfSourceRules":5,"cncfRuleProjects":3,"cncfSourceRulesWithdrawn":1,"communityProjectSourceRules":7,"communityProjectRuleProjects":2}}`)
	intro, err := RenderPreviewIntro(inv)
	if err != nil || intro != "The current embedded preview has 5 active exact rules across 3 rule projects (1 withdrawn, not used).\n" {
		t.Fatalf("%q %v", intro, err)
	}
	pack, err := RenderPreviewPack(inv)
	if err != nil || pack != "The embedded CNCF rule pack has 5 active constraints across 3 rule projects; the separate\ncommunity-project pack has 7 constraints across 2 projects.\n" {
		t.Fatalf("%q %v", pack, err)
	}
	for name, bad := range map[string]string{"not json": `{`, "count missing": `{"counts":{"cncfSourceRules":5}}`} {
		if _, err := RenderPreviewIntro([]byte(bad)); err == nil {
			t.Errorf("%s: intro rendered", name)
		}
		if _, err := RenderPreviewPack([]byte(bad)); err == nil {
			t.Errorf("%s: pack rendered", name)
		}
	}
}
