// SPDX-License-Identifier: AGPL-3.0-only

package rulecheck

import (
	"context"
	"errors"
	"fmt"
	"sort"

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
	timeout := v.Timeout
	if timeout <= 0 {
		timeout = DefaultCitationTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
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
		facts, err := v.contentAt(ctx, rawURL)
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
	failed := map[string]bool{}
	for _, id := range report.FailedRules {
		failed[id] = true
	}
	for _, f := range early {
		report.Findings = append(report.Findings, f)
		if !failed[f.RuleID] {
			failed[f.RuleID] = true
			report.FailedRules = append(report.FailedRules, f.RuleID)
		}
		report.RecordsChecked++
		report.SourcesChecked++
	}
	sort.Strings(report.FailedRules)
	sort.SliceStable(report.Findings, func(i, j int) bool {
		a, b := report.Findings[i], report.Findings[j]
		if a.RuleID != b.RuleID {
			return a.RuleID < b.RuleID
		}
		return a.Check < b.Check
	})
	report.Pass = len(report.Findings) == 0 && report.SourcesChecked > 0
	return report, nil
}
