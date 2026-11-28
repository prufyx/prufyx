// SPDX-License-Identifier: AGPL-3.0-only

package evidencereattest

import (
	"testing"

	"github.com/prufyx/prufyx/cli/internal/maintainer/evidencerepin"
)

// bindSources gives every rule citation of wl the repository, path, digest
// and line span its pack source records, as evidence repin does, and
// resolves each cited repository once, copying wl's first resolution.
func bindSources(t *testing.T, wl *evidencerepin.Worklist, packRaw []byte) {
	t.Helper()
	doc, err := loadPack(packRaw)
	if err != nil {
		t.Fatal(err)
	}
	sources := map[string]ruleSourceField{}
	for _, entry := range doc.Entries {
		fields, err := parseRuleFields(entry.Rule)
		if err != nil {
			t.Fatal(err)
		}
		for _, source := range fields.Evidence.Sources {
			sources[fields.ID+"\x00"+source.ID] = source
		}
	}
	template := wl.Repos[0]
	wl.Repos = nil
	seen := map[string]bool{}
	for i := range wl.Citations {
		c := &wl.Citations[i]
		source, ok := sources[c.RuleID+"\x00"+c.SourceID]
		if !ok {
			t.Fatalf("no pack source for %s %s", c.RuleID, c.SourceID)
		}
		owner, repo, _, path, ok := evidencerepin.ParseCitationURL(source.URL)
		if !ok {
			t.Fatalf("unreadable source URL %s", source.URL)
		}
		c.Owner, c.Repo, c.Path = owner, repo, path
		c.OldDigest, c.OldStart, c.OldEnd = source.ContentDigest, source.StartLine, source.EndLine
		if !seen[owner+"/"+repo] {
			seen[owner+"/"+repo] = true
			resolution := template
			resolution.Owner, resolution.Repo, resolution.CurrentCommit = owner, repo, c.OldCommit
			wl.Repos = append(wl.Repos, resolution)
		}
	}
}
