// SPDX-License-Identifier: AGPL-3.0-only

package evidencereattest

import (
	"encoding/json"
	"strings"
	"testing"
)

// A citation class holds only for the record it was computed from: a source
// edited after the repin run, at the same commit, is not renewed.
func TestPrepareDoesNotRenewAnEditedRecord(t *testing.T) {
	packPath := "/p/rules.json"
	for name, edit := range map[string]func(source map[string]any){
		"unchanged":      func(map[string]any) {},
		"content digest": func(s map[string]any) { s["contentDigest"] = "sha256:" + strings.Repeat("ef", 32) },
		"start and end":  func(s map[string]any) { s["startLine"], s["endLine"] = 2, 2 },
		"end line":       func(s map[string]any) { s["endLine"] = 2 },
		"path":           func(s map[string]any) { s["url"] = s["url"].(string) + ".other" },
		"repository": func(s map[string]any) {
			s["url"] = strings.Replace(s["url"].(string), "repo-rule-a", "repo-other", 1)
		},
		"url shape": func(s map[string]any) { s["url"] = "https://example.invalid/VERSION" },
	} {
		wl, pack := buildWorklistAndPack(t, packPath, baseNow, []ruleSpec{freshSpec("rule-a", "proj-a", baseNow)})
		var doc map[string]any
		if err := json.Unmarshal(pack, &doc); err != nil {
			t.Fatal(err)
		}
		rule := doc["entries"].([]any)[0].(map[string]any)["rule"].(map[string]any)
		source := rule["evidence"].(map[string]any)["sources"].([]any)[0].(map[string]any)
		before, err := json.Marshal(source)
		if err != nil {
			t.Fatal(err)
		}
		edit(source)
		after, err := json.Marshal(source)
		if err != nil {
			t.Fatal(err)
		}
		if (name == "unchanged") != (string(before) == string(after)) {
			t.Fatalf("%s: the fixture edit is wrong: %s", name, after)
		}
		edited, err := json.Marshal(doc)
		if err != nil {
			t.Fatal(err)
		}
		res, err := Prepare(PrepareOptions{
			WorklistRaw: marshalWorklist(t, wl), PackName: PackCNCF, PackPath: packPath, PackRaw: edited,
			Wave: 1, AttestedAt: baseNow, Now: baseNow, NextRevision: "rev-2", EngineCapabilityDigest: testEngineCapabilityDigest, Chain: &Chain{},
		})
		if name == "unchanged" {
			if err != nil || len(res.Statement.Rules) != 1 {
				t.Fatalf("control: %v %+v", err, res.Statement.NotExtended)
			}
			continue
		}
		if err != nil {
			// Only a source that is no citation at all may reject the run.
			if name != "url shape" {
				t.Errorf("%s: Prepare: %v", name, err)
			}
			continue
		}
		if len(res.Statement.Rules) != 0 || len(res.Statement.NotExtended) != 1 || res.Statement.NotExtended[0].WorstClass != "CITATION_DOES_NOT_MATCH_PINNED_SOURCE" {
			t.Errorf("%s: renewed %+v, not extended %+v", name, res.Statement.Rules, res.Statement.NotExtended)
		}
	}
}
