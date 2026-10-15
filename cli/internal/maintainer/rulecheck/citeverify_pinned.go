// SPDX-License-Identifier: AGPL-3.0-only

package rulecheck

import (
	"context"
	"errors"
	"fmt"

	"github.com/prufyx/prufyx/cli/internal/constraintengine"
)

// PinnedFile is a citation that declares no content digest: a file named by
// a pinned github blob URL (a table row's source, a pinned kustomization).
// ID names it in findings.
type PinnedFile struct {
	ID  string
	URL string
}

// VerifyPinnedFiles runs every check of VerifyItems over files that declare
// no digest: the revision in the URL is a commit object that is a tag commit
// or in the default branch history of the named repository, and the path
// exists at it with at least one line. The file is fetched once to learn its
// digest and the full citation check then runs against that digest, so the
// revision, reachability and fetch checks are exactly the ones a rule's
// citation gets; only the comparison with a declared digest has nothing to
// compare. A fetch that fails is a fetch-failed finding. There is no way to
// skip a check, and an empty list is not a pass.
func (v *CitationVerifier) VerifyPinnedFiles(ctx context.Context, files []PinnedFile) (CitationReport, error) {
	if v.Resolver == nil || v.Fetcher == nil {
		return CitationReport{}, errors.New("citation verification needs both a RevisionResolver and a Fetcher")
	}
	items := make([]CitationItem, 0, len(files))
	var early []CitationFinding
	for _, f := range files {
		owner, repo, revision, ok := githubBlobURL(f.URL)
		if !ok {
			// verifySource reports the malformed URL (citation-url).
			items = append(items, CitationItem{Record: true, ID: f.ID, Sources: []constraintengine.SourceEvidence{{ID: f.ID, URL: f.URL, Revision: "-", StartLine: 1, EndLine: 1}}})
			continue
		}
		rawURL, ok := rawBlobURL(owner, repo, revision, f.URL)
		if !ok {
			items = append(items, CitationItem{Record: true, ID: f.ID, Sources: []constraintengine.SourceEvidence{{ID: f.ID, URL: f.URL, Revision: revision, StartLine: 1, EndLine: 1}}})
			continue
		}
		fctx, cancel := context.WithTimeout(ctx, DefaultCitationTimeout)
		facts, err := v.contentAt(fctx, rawURL)
		cancel()
		if err != nil {
			early = append(early, CitationFinding{RuleID: f.ID, SourceID: f.ID, Check: CheckCitationFetch, Message: fmt.Sprintf("could not fetch %s: %v", rawURL, err)})
			continue
		}
		items = append(items, CitationItem{Record: true, ID: f.ID, Sources: []constraintengine.SourceEvidence{{ID: f.ID, URL: f.URL, Revision: revision, ContentDigest: facts.digest, StartLine: 1, EndLine: 1}}})
	}
	report, err := v.VerifyItems(ctx, items)
	if err != nil {
		return CitationReport{}, err
	}
	for _, f := range early {
		report.Findings = append(report.Findings, f)
		report.FailedRules = append(report.FailedRules, f.RuleID)
		report.RecordsChecked++
		report.SourcesChecked++
	}
	report.Pass = len(report.Findings) == 0 && report.SourcesChecked > 0
	return report, nil
}
