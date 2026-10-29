// SPDX-License-Identifier: AGPL-3.0-only

package projectcheck

import (
	"encoding/json"
	"time"

	"github.com/prufyx/prufyx/cli/internal/knowledgeage"
)

// EmbeddedKnowledgeAge is the end dates of the embedded project pack's active
// rules. A rule whose evidence is not active never counts, as at run time.
func EmbeddedKnowledgeAge() ([]knowledgeage.Source, error) {
	b, err := load()
	if err != nil {
		return nil, err
	}
	var ends []time.Time
	for _, e := range b.pack.Entries {
		var shape struct {
			Evidence struct {
				State      string `json:"state"`
				ValidUntil string `json:"validUntil"`
			} `json:"evidence"`
		}
		if json.Unmarshal(e.Rule, &shape) != nil || shape.Evidence.State != "active" {
			continue
		}
		end, err := time.Parse(time.RFC3339, shape.Evidence.ValidUntil)
		if err != nil {
			return nil, ErrIntegrity
		}
		ends = append(ends, end.UTC())
	}
	return []knowledgeage.Source{{ID: "embedded-projects", Expiries: ends}}, nil
}
