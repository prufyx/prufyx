// SPDX-License-Identifier: AGPL-3.0-only

package coveragereport

import (
	"encoding/json"
	"fmt"
)

// The rule-count sentences of the CNCF source preview: two marker pairs.
const (
	PreviewIntroBegin = "<!-- preview-counts-intro:begin -->"
	PreviewIntroEnd   = "<!-- preview-counts-intro:end -->"
	PreviewPackBegin  = "<!-- preview-counts-pack:begin -->"
	PreviewPackEnd    = "<!-- preview-counts-pack:end -->"
)

func previewCounts(inventoryJSON []byte, keys ...string) (map[string]int, error) {
	var inv struct {
		Counts map[string]int `json:"counts"`
	}
	if err := json.Unmarshal(inventoryJSON, &inv); err != nil {
		return nil, fmt.Errorf("support inventory: %w", err)
	}
	for _, k := range keys {
		if _, ok := inv.Counts[k]; !ok {
			return nil, fmt.Errorf("support inventory: counts.%s is missing", k)
		}
	}
	return inv.Counts, nil
}

// RenderPreviewIntro renders the text between the preview-counts-intro
// markers from the generated support inventory. It ends with one newline.
func RenderPreviewIntro(inventoryJSON []byte) (string, error) {
	c, err := previewCounts(inventoryJSON, "cncfSourceRules", "cncfRuleProjects", "cncfSourceRulesWithdrawn")
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("The current embedded preview has %d active exact rules across %d rule projects (%d withdrawn, not used).\n",
		c["cncfSourceRules"], c["cncfRuleProjects"], c["cncfSourceRulesWithdrawn"]), nil
}

// RenderPreviewPack renders the text between the preview-counts-pack
// markers from the generated support inventory. It ends with one newline.
func RenderPreviewPack(inventoryJSON []byte) (string, error) {
	c, err := previewCounts(inventoryJSON, "cncfSourceRules", "cncfRuleProjects", "communityProjectSourceRules", "communityProjectRuleProjects")
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("The embedded CNCF rule pack has %d active constraints across %d rule projects; the separate\ncommunity-project pack has %d constraints across %d projects.\n",
		c["cncfSourceRules"], c["cncfRuleProjects"], c["communityProjectSourceRules"], c["communityProjectRuleProjects"]), nil
}
