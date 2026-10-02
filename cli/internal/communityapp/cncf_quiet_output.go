// SPDX-License-Identifier: AGPL-3.0-only

package communityapp

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"

	"github.com/prufyx/prufyx/cli/internal/checkroutemetadata"
	"github.com/prufyx/prufyx/cli/internal/constraintengine"
)

// Human output of the native and generic CNCF routes is written for a reader
// who wants the answer first: the claims that decide something, then one
// aggregate, then the sources once. JSON output is never produced here.

const reasonTransitionNotReviewed = "RULE_TRANSITION_NOT_REVIEWED"

// maxReviewedPairsShown bounds the reviewed-pairs list in one line.
const maxReviewedPairsShown = 8

// claimSummary partitions claims for quiet human output.
type claimSummary struct {
	shown         []constraintengine.Claim
	passes        int
	unreviewed    int
	allUnreviewed bool
}

func summarizeClaims(claims []constraintengine.Claim, showPasses bool) claimSummary {
	var summary claimSummary
	for _, claim := range claims {
		switch {
		case claim.Status == "UNKNOWN" && claim.ReasonCode == reasonTransitionNotReviewed:
			summary.unreviewed++
		case claim.Status == "PASS" && !showPasses:
			summary.passes++
		default:
			summary.shown = append(summary.shown, claim)
		}
	}
	summary.allUnreviewed = len(claims) > 0 && summary.unreviewed == len(claims)
	return summary
}

// writeUnreviewedTransition is the whole answer when no claim could be decided
// because the pair is not one a reviewed rule covers.
func writeUnreviewedTransition(out io.Writer, project, from, to string) error {
	subject := project
	if from != "" && to != "" {
		subject = project + " " + from + " -> " + to
	}
	_, err := fmt.Fprintf(out, "UNKNOWN: %s is not a reviewed transition; reviewed pairs: %s; for a multi-minor upgrade, check each reviewed pair in turn\n", subject, reviewedPairs(project))
	return err
}

// reviewedPairs lists the distinct from -> to pairs that embedded rules of the
// project review, in version order, bounded to one line.
func reviewedPairs(project string) string {
	result, err := checkroutemetadata.Discover(project, "", "")
	if err != nil {
		return "unavailable"
	}
	type pair struct{ from, to string }
	seen := map[pair]bool{}
	var pairs []pair
	for _, check := range result.Checks {
		p := pair{check.From, check.To}
		if !seen[p] {
			seen[p] = true
			pairs = append(pairs, p)
		}
	}
	if len(pairs) == 0 {
		return "none"
	}
	sort.Slice(pairs, func(i, j int) bool {
		if c := compareVersions(pairs[i].from, pairs[j].from); c != 0 {
			return c < 0
		}
		return compareVersions(pairs[i].to, pairs[j].to) < 0
	})
	parts := make([]string, 0, maxReviewedPairsShown+1)
	for index, p := range pairs {
		if index == maxReviewedPairsShown {
			parts = append(parts, fmt.Sprintf("and %d more (prufyx catalog checks --project %s)", len(pairs)-index, project))
			break
		}
		parts = append(parts, p.from+" -> "+p.to)
	}
	return strings.Join(parts, ", ")
}

// compareVersions orders dotted numeric versions; anything else sorts after,
// lexically, so the order is total and deterministic.
func compareVersions(a, b string) int {
	as, bs := strings.Split(a, "."), strings.Split(b, ".")
	for index := 0; index < len(as) && index < len(bs); index++ {
		an, aerr := strconv.Atoi(as[index])
		bn, berr := strconv.Atoi(bs[index])
		switch {
		case aerr == nil && berr == nil && an != bn:
			if an < bn {
				return -1
			}
			return 1
		case aerr != nil || berr != nil:
			if c := strings.Compare(as[index], bs[index]); c != 0 {
				return c
			}
		}
	}
	return len(as) - len(bs)
}

// writeCollapsedNotes prints the counts of claims that were not listed.
func writeCollapsedNotes(out io.Writer, summary claimSummary) error {
	if summary.unreviewed > 0 {
		if _, err := fmt.Fprintf(out, "%d rules for other transitions not applicable to this pair\n", summary.unreviewed); err != nil {
			return err
		}
	}
	if summary.passes > 0 {
		if _, err := fmt.Fprintf(out, "%d rules PASS (not listed; use --show-passes)\n", summary.passes); err != nil {
			return err
		}
	}
	return nil
}

// writeSourceFooter prints each distinct pinned source once, in first-seen order.
func writeSourceFooter(out io.Writer, claims []constraintengine.Claim) error {
	seen := map[constraintengine.SourceEvidence]bool{}
	for _, claim := range claims {
		for _, source := range claim.Sources {
			if seen[source] {
				continue
			}
			seen[source] = true
			if _, err := fmt.Fprintf(out, "pinned source: %s lines %d-%d; revision %s; digest %s\n", source.URL, source.StartLine, source.EndLine, source.Revision, source.ContentDigest); err != nil {
				return err
			}
		}
	}
	return nil
}

// canonicalTransition reads the single from and to version of a canonical
// input declaration; ok is false when it does not name exactly one component
// on each side.
func canonicalTransition(input []byte) (from, to string, ok bool) {
	var envelope struct {
		Current  struct{ Components []struct{ Version string } }
		Proposed struct{ Components []struct{ Version string } }
	}
	if json.Unmarshal(input, &envelope) != nil || len(envelope.Current.Components) != 1 || len(envelope.Proposed.Components) != 1 {
		return "", "", false
	}
	return envelope.Current.Components[0].Version, envelope.Proposed.Components[0].Version, true
}
