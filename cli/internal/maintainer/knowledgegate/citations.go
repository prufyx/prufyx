// SPDX-License-Identifier: AGPL-3.0-only

package knowledgegate

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/prufyx/prufyx/cli/internal/maintainer/rulecheck"
)

// CheckCitations is the name of the citation check in a gate report.
const CheckCitations = "citations"

// OfflineCitations is the gate's explicit offline mode, installed only by
// `--source fixture:DIR` (the fixtures of tests and local runs): it checks
// nothing, so the citations check FAILS ("not verified (offline fixture)")
// for any change that cites a source, and the change is never eligible for
// automatic merge. A missing proof is not a pass. The workflows use
// `--source github`, which verifies against upstream.
type OfflineCitations struct{}

// isOffline reports whether c is the offline mode, as a value or a pointer.
func isOffline(c CitationChecker) bool {
	switch c.(type) {
	case OfflineCitations, *OfflineCitations:
		return true
	}
	return false
}

// VerifyItems implements CitationChecker; citationCheck never calls it.
func (OfflineCitations) VerifyItems(context.Context, []rulecheck.CitationItem) (rulecheck.CitationReport, error) {
	return rulecheck.CitationReport{}, errors.New("offline mode verifies nothing")
}

// maxCitationFindingsListed bounds how many findings a check detail lists.
const maxCitationFindingsListed = 20

// citationItems lists the source-bearing items of every loosening change
// that leaves a rule or record in the head: an added or changed rule, path
// policy or line attestation. A removal has no head to cite, and a
// tightening change (an earlier validUntil, a withdrawal, a removed
// attestation) changes no source, so neither is checked: a pack may
// withdraw a rule whose citation has rotted.
//
// Coupling: a distribution record is not listed here because a change to a
// distribution section is a pack-member change, which the gate always
// refuses (see the pack-member rule in Verify). If a later gate version
// admits distribution records as a record section, this switch must gain
// that case, or its sources would go unchecked.
func citationItems(cls *Classification) ([]rulecheck.CitationItem, error) {
	var items []rulecheck.CitationItem
	for _, c := range cls.Changes {
		if c.Class != ClassLoosening {
			continue
		}
		switch {
		case c.Section == "" && c.Member == "" && c.head != nil:
			var shape struct {
				Rule json.RawMessage `json:"rule"`
			}
			if err := json.Unmarshal(c.head.Raw, &shape); err != nil {
				return nil, fmt.Errorf("rule %s: %w", c.RuleID, err)
			}
			rule := []json.RawMessage{shape.Rule}
			// Rule decoding is shared with the pack-wide verifier.
			one, err := rulecheck.RuleCitationItems(rule)
			if err != nil {
				return nil, fmt.Errorf("rule %s: %w", c.RuleID, err)
			}
			items = append(items, one...)
		case c.rhead != nil && c.rhead.attestation != nil:
			items = append(items, rulecheck.AttestationCitationItem(*c.rhead.attestation))
		case c.rhead != nil && c.rhead.policy != nil:
			items = append(items, rulecheck.PolicyCitationItem(*c.rhead.policy))
		}
	}
	return items, nil
}

// citationCheck runs, for every added or changed rule, path policy and line
// attestation, the checks of `rule verify-citations`: the revision is a
// commit object that is a tag commit of, or in the default branch history of,
// the cited repository,
// the whole-file sha256 at it equals contentDigest, and the cited lines are
// inside the file. It fails closed: with no verifier
// configured (no upstream source), a fetch error, a rate limit or any
// unresolvable fact, the check fails; there is no skip. A change with no
// such item has nothing to check, so unrelated changes and the unchanged
// pack content never fail on a rotted citation (the scheduled
// citations-nightly workflow covers the whole pack).
func (r *Report) citationCheck(ctx context.Context, cls *Classification, opts Options) {
	items, err := citationItems(cls)
	if err != nil {
		r.add(CheckCitations, false, "could not list the changed sources: %v", err)
		return
	}
	if len(items) == 0 {
		r.add(CheckCitations, true, "no added or changed rule, path policy or line attestation")
		return
	}
	if opts.Citations == nil {
		r.add(CheckCitations, false, "%d changed rules or records cite sources, but no upstream source is configured to verify them (use --source github); a citation that cannot be checked is not a pass", len(items))
		return
	}
	if isOffline(opts.Citations) {
		r.add(CheckCitations, false, "not verified (offline fixture): the sources of %d changed rules and records were not checked against upstream; offline mode (--source fixture:) is never a pass, use --source github", len(items))
		return
	}
	report, err := opts.Citations.VerifyItems(ctx, items)
	if err != nil {
		r.add(CheckCitations, false, "citation verification could not run: %v", err)
		return
	}
	if report.Pass {
		r.add(CheckCitations, true, "%d rules and records, %d sources: each revision is a commit in the upstream history (tag or default branch), each whole-file digest and line span matches upstream", len(items), report.SourcesChecked)
		return
	}
	var lines []string
	for i, f := range report.Findings {
		if i == maxCitationFindingsListed {
			lines = append(lines, fmt.Sprintf("... and %d more", len(report.Findings)-i))
			break
		}
		lines = append(lines, fmt.Sprintf("%s source %s [%s]: %s", logSafe(f.RuleID), logSafe(f.SourceID), f.Check, logSafe(f.Message)))
	}
	detail := fmt.Sprintf("%d findings in %d rules or records", len(report.Findings), len(report.FailedRules))
	if len(report.Findings) == 0 {
		detail = "the changed items cite no source at all"
	}
	r.add(CheckCitations, false, "%s%s", detail, listDetail(lines))
}
