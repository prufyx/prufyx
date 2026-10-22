// SPDX-License-Identifier: AGPL-3.0-only

package extractcli

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/prufyx/prufyx/cli/internal/maintainer/rulecheck"
)

// withoutRenewable returns the published packs a run checks its candidates'
// rule ids against, minus the ids that extract apply --renew-attestations may
// replace: rules the packs hold as active mechanical rules of this extractor.
// A re-run for a project whose rules are already shipped would otherwise fail
// before apply on its own ids. The packs are not edited: the returned files
// are id-only copies in a temporary directory, removed by cleanup. Every other
// check of the run, and the id check for every other rule, stays as it is.
//
// The run's candidate check lives in the extractor framework, whose source is
// part of every extractor's code digest, so the filter sits here instead
// (rulecheck.Options.RenewableIDs does the same for extract apply).
func withoutRenewable(existing []string, extractorID string) (paths []string, cleanup func(), err error) {
	cleanup = func() {}
	if len(existing) == 0 {
		return existing, cleanup, nil
	}
	renewable, err := rulecheck.RenewableIn(existing, extractorID)
	if err != nil {
		return nil, cleanup, err
	}
	if len(renewable) == 0 {
		return existing, cleanup, nil
	}
	dir, err := os.MkdirTemp("", "prufyx-existing-")
	if err != nil {
		return nil, cleanup, err
	}
	cleanup = func() { _ = os.RemoveAll(dir) }
	for i, p := range existing {
		raw, err := os.ReadFile(p)
		if err != nil {
			cleanup()
			return nil, func() {}, fmt.Errorf("read existing rule pack: %w", err)
		}
		var doc struct {
			Entries []struct {
				Rule struct {
					ID string `json:"id"`
				} `json:"rule"`
			} `json:"entries"`
		}
		if err := json.Unmarshal(raw, &doc); err != nil {
			cleanup()
			return nil, func() {}, fmt.Errorf("parse existing rule pack: %w", err)
		}
		type idOnly struct {
			Rule struct {
				ID string `json:"id"`
			} `json:"rule"`
		}
		var keep []idOnly
		for _, e := range doc.Entries {
			if e.Rule.ID != "" && !renewable[e.Rule.ID] {
				var o idOnly
				o.Rule.ID = e.Rule.ID
				keep = append(keep, o)
			}
		}
		out, err := json.Marshal(map[string]any{"entries": keep})
		if err != nil {
			cleanup()
			return nil, func() {}, err
		}
		q := filepath.Join(dir, fmt.Sprintf("pack-%d.json", i))
		if err := os.WriteFile(q, out, 0o600); err != nil {
			cleanup()
			return nil, func() {}, err
		}
		paths = append(paths, q)
	}
	return paths, cleanup, nil
}
