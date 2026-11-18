// SPDX-License-Identifier: AGPL-3.0-only

package evidencerepin

import (
	"fmt"
	"sort"

	"github.com/prufyx/prufyx/cli/internal/constraintengine"
)

// ExitPinnedDrift is the process exit status of "evidence repin
// --pinned-only" when a pinned citation drifted or could not be checked.
const ExitPinnedDrift = 4

// PinnedOnly keeps the citations of the rules that hold a pinned lease. The
// citations of a record (line attestation, path policy) never do.
func PinnedOnly(citations []Citation) []Citation {
	var out []Citation
	for _, citation := range citations {
		if citation.Lease == constraintengine.LeasePinned {
			out = append(out, citation)
		}
	}
	return out
}

// PinnedDrift is the check that stands in for a time lease on a pinned rule.
// It reads a worklist built over the pinned citations only, with the
// release-line baseline, and reports one finding per citation that is not
// proven unchanged on its release line: a class other than NO_NEW_RELEASE,
// FILE_IDENTICAL or SPAN_IDENTICAL, a citation still pending, a baseline that
// is not a release line (release_line, or tag_line derived from git tags) with
// its line and pinned tag, a stale resolution, or a tags-list resolution. It
// also reports a worklist that does not hold exactly one result per expected
// citation, so a missing result is never read as a pass. An empty list means
// no pinned citation drifted.
func PinnedDrift(worklist Worklist, expected int) []string {
	var findings []string
	if len(worklist.Citations) != expected {
		findings = append(findings, fmt.Sprintf("the worklist holds %d citations, %d pinned citations were expected", len(worklist.Citations), expected))
	}
	for _, citation := range worklist.Citations {
		label := fmt.Sprintf("rule %s source %s", citation.RuleID, citation.SourceID)
		switch citation.Class {
		case ClassNoNewRelease, ClassFileIdentical, ClassSpanIdentical:
		default:
			findings = append(findings, fmt.Sprintf("%s: %s", label, citation.Class))
			continue
		}
		switch {
		case citation.Baseline != BaselineReleaseLine && citation.Baseline != BaselineTagLine, citation.BaselineLine == "", citation.PinnedTag == "":
			findings = append(findings, fmt.Sprintf("%s: not compared on a release line", label))
		case citation.Stale:
			findings = append(findings, fmt.Sprintf("%s: stale resolution", label))
		case citation.Resolution == resolutionTagFallback:
			findings = append(findings, fmt.Sprintf("%s: resolved from the tags list only", label))
		}
	}
	sort.Strings(findings)
	return findings
}
