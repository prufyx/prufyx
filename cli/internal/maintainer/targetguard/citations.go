// SPDX-License-Identifier: AGPL-3.0-only

package targetguard

import (
	"fmt"

	"github.com/prufyx/prufyx/cli/internal/maintainer/rulecheck"
)

// PinnedFiles lists every citation that needs the network: each table
// group's source, a community project's licence source, and for a target
// that moves its definitions to another repository the kustomization file at
// each pinned commit. rulecheck.CitationVerifier.VerifyPinnedFiles checks
// them. No file declares a content digest today; when a source gains one,
// it belongs in rulecheck.CitationItem, which compares it.
func PinnedFiles(in Inputs) []rulecheck.PinnedFile {
	var out []rulecheck.PinnedFile
	for _, p := range in.Projects {
		for _, g := range p.Groups {
			out = append(out, rulecheck.PinnedFile{ID: fmt.Sprintf("table %s %s", p.Slug, g.Name), URL: g.Source})
		}
		if p.Community() {
			out = append(out, rulecheck.PinnedFile{ID: "table " + p.Slug + " license", URL: p.Upstream.LicenseSource})
		}
	}
	for _, t := range in.Targets {
		r := t.Remote
		if r == nil {
			continue
		}
		for _, pin := range r.Pins {
			url := "https://" + r.Repo + "/blob/" + pin.Commit + "/" + r.Directory + "/kustomization.yaml"
			out = append(out, rulecheck.PinnedFile{ID: fmt.Sprintf("target %s pin %s", t.Project, pin.Tag), URL: url})
		}
	}
	return out
}
