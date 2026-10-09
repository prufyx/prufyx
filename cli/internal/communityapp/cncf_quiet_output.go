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
	"github.com/prufyx/prufyx/cli/internal/cncfcheck"
	"github.com/prufyx/prufyx/cli/internal/constraintengine"
)

// Human output of the native and generic CNCF routes is written for a reader
// who wants the answer first: the claims that decide something, then one
// aggregate, then the sources once. JSON output is never produced here.

// An unreviewed transition is one the rules do not cover: either a pair
// outside every reviewed subject, or a hop that crosses a ranged rule's
// release boundary outside its range. Quiet output collapses both.
const reasonTransitionNotReviewed = "RULE_TRANSITION_NOT_REVIEWED"

// maxReviewedPairsShown bounds the reviewed-pairs list in one line.
const maxReviewedPairsShown = 8

// claimSummary partitions claims for quiet human output. One-way notices and
// leads are kept apart from every verdict claim: they are never collapsed
// with passes and never counted as unreviewed, blocked or unknown.
type claimSummary struct {
	shown         []constraintengine.Claim
	notices       []constraintengine.Claim
	passes        int
	unreviewed    int
	allUnreviewed bool
	// boundary counts the claims of rules whose release boundary the hop
	// crosses outside their reviewed range. They are unreviewed for this hop
	// but are not "other transitions": they are never counted with
	// unreviewed and never described as not applicable.
	boundary      int
	boundaryRules []string
}

func summarizeClaims(claims []constraintengine.Claim, showPasses bool) claimSummary {
	var summary claimSummary
	verdicts := 0
	for _, claim := range claims {
		if claim.IsVerdictNeutral() {
			summary.notices = append(summary.notices, claim)
			continue
		}
		verdicts++
		switch {
		case claim.Status == "UNKNOWN" && claim.ReasonCode == reasonTransitionNotReviewed:
			summary.unreviewed++
		case claim.Status == "UNKNOWN" && claim.ReasonCode == constraintengine.ReasonReleaseBoundaryNotReviewed:
			summary.boundary++
			summary.boundaryRules = append(summary.boundaryRules, claim.RuleID)
		case claim.Status == "PASS" && !showPasses:
			summary.passes++
		default:
			summary.shown = append(summary.shown, claim)
		}
	}
	summary.allUnreviewed = verdicts > 0 && summary.unreviewed+summary.boundary == verdicts
	return summary
}

// writeNotices prints each one-way notice on its own lines, with its
// reviewed "before you upgrade" text. A notice that does not apply prints
// nothing: its absence is not a statement about rolling back.
func writeNotices(out io.Writer, notices []constraintengine.Claim) error {
	for _, claim := range notices {
		printed, err := writeClaimHeadline(out, claim)
		if err != nil {
			return err
		}
		if !printed {
			continue
		}
		if _, err := fmt.Fprintln(out, claim.EvidenceBasisLine()); err != nil {
			return err
		}
	}
	return nil
}

// writeClaimHeadline prints the first lines of one claim: the rule, status,
// reason and next action of a verdict claim, or the one-way wording of a
// notice. printed is false for a notice that does not apply to the declared
// transition; the caller then prints nothing else for that claim.
func writeClaimHeadline(out io.Writer, claim constraintengine.Claim) (printed bool, err error) {
	if lines, notice := claim.NoticeLines(); notice {
		for _, line := range lines {
			if _, err := fmt.Fprintln(out, line); err != nil {
				return false, err
			}
		}
		return len(lines) > 0, nil
	}
	_, err = fmt.Fprintf(out, "%s: %s (%s)\n%s\n", claim.RuleID, claim.Status, claim.ReasonCode, claimActionLine(claim))
	return err == nil, err
}

// claimActionLine is the line under a claim that says what to do. A claim
// that passed has nothing to fix: its reviewed remediation is shown as what to
// do if the condition it checked ever changes, so it never reads as a required
// fix.
func claimActionLine(claim constraintengine.Claim) string {
	if claim.Status == "PASS" {
		return "if this changes: " + claim.NextAction
	}
	return "next action: " + claim.NextAction
}

// verdictClaims counts the claims that are neither one-way notices nor
// leads.
func verdictClaims(claims []constraintengine.Claim) int {
	verdicts := 0
	for _, claim := range claims {
		if !claim.IsVerdictNeutral() {
			verdicts++
		}
	}
	return verdicts
}

// writeNoVerdictLine states, when a report holds one-way notices or leads
// and nothing else, that no verdict rule decided the transition.
func writeNoVerdictLine(out io.Writer, claims []constraintengine.Claim) error {
	if len(claims) == 0 || verdictClaims(claims) != 0 {
		return nil
	}
	line := noVerdictLine
	for _, claim := range claims {
		if claim.IsLead() {
			line = noVerdictLeadLine
		}
	}
	_, err := fmt.Fprintln(out, line)
	return err
}

// writeCustomResourceScope states, when a claim's rule reads a
// custom-resource version set, why the check cannot exit 0.
func writeCustomResourceScope(out io.Writer, claims []constraintengine.Claim) error {
	for _, claim := range claims {
		if cncfcheck.ReadsCustomResourceVersions(claim) {
			_, err := fmt.Fprintln(out, customResourceScopeLine)
			return err
		}
	}
	return nil
}

const customResourceScopeLine = "scope: a rule over a custom-resource version set never makes this check pass (exit 11 at best): no record yet shows that the published rules name every version the target release stops serving"

const (
	noVerdictLine     = "UNKNOWN: no reviewed rule decided this transition; a one-way notice is not a verdict"
	noVerdictLeadLine = "UNKNOWN: no reviewed rule decided this transition; a notice or unverified lead is not a verdict"
)

// writeUnreviewedTransition is the whole answer when no claim could be decided
// because the pair is not one a reviewed rule covers.
func writeUnreviewedTransition(out io.Writer, summary claimSummary, project, from, to string) error {
	subject := project
	if from != "" && to != "" {
		subject = project + " " + from + " -> " + to
	}
	if _, err := fmt.Fprintf(out, "UNKNOWN: %s is not a reviewed transition; reviewed pairs: %s; for a multi-minor upgrade, check each minor step; a step without a reviewed pair stays UNKNOWN\n", subject, reviewedPairs(project)); err != nil {
		return err
	}
	return writeBoundaryNote(out, summary)
}

// writeBoundaryNote states that the hop crosses release boundaries that rules
// cite and that no reviewed rule covers the hop. It names the boundaries so
// the operator learns the hop skips cited removals; it never calls them not
// applicable.
func writeBoundaryNote(out io.Writer, summary claimSummary) error {
	if summary.boundary == 0 {
		return nil
	}
	boundaries := releaseBoundaries(summary.boundaryRules)
	named := ""
	if len(boundaries) > 0 {
		named = " (" + strings.Join(boundaries, ", ") + ")"
	}
	if summary.boundary == 1 {
		_, err := fmt.Fprintf(out, "1 rule about a release boundary%s this hop crosses is not reviewed for this hop\n", named)
		return err
	}
	_, err := fmt.Fprintf(out, "%d rules about release boundaries%s this hop crosses are not reviewed for this hop\n", summary.boundary, named)
	return err
}

// releaseBoundaries lists, in version order, the distinct release boundaries
// of the embedded rules with the given ids. A rule the embedded catalogue does
// not know (an external bundle) contributes none.
func releaseBoundaries(ruleIDs []string) []string {
	result, err := checkroutemetadata.Discover("", "", "")
	if err != nil {
		return nil
	}
	wanted := map[string]bool{}
	for _, id := range ruleIDs {
		wanted[id] = true
	}
	seen := map[string]bool{}
	var boundaries []string
	for _, check := range result.Checks {
		if !wanted[check.RuleID] {
			continue
		}
		if change, ok := check.Transition().ChangeVersion(); ok && !seen[change] {
			seen[change] = true
			boundaries = append(boundaries, change)
		}
	}
	sort.Slice(boundaries, func(i, j int) bool { return compareVersions(boundaries[i], boundaries[j]) < 0 })
	return boundaries
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
		other := "%d rules for other transitions not applicable to this pair\n"
		if summary.unreviewed == 1 {
			other = "%d rule for another transition not applicable to this pair\n"
		}
		if _, err := fmt.Fprintf(out, other, summary.unreviewed); err != nil {
			return err
		}
	}
	if err := writeBoundaryNote(out, summary); err != nil {
		return err
	}
	if summary.passes > 0 {
		passed := "%d rules PASS (not listed; use --show-passes)\n"
		if summary.passes == 1 {
			passed = "%d rule PASS (not listed; use --show-passes)\n"
		}
		if _, err := fmt.Fprintf(out, passed, summary.passes); err != nil {
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

// writeNativeClaims prints the listed verdict claims, then the one-way
// notices, then the collapsed counts.
func writeNativeClaims(out io.Writer, summary claimSummary, claims []constraintengine.Claim) error {
	for _, claim := range summary.shown {
		if _, err := fmt.Fprintf(out, "%s: %s (%s)\n%s\n", claim.RuleID, claim.Status, claim.ReasonCode, claimActionLine(claim)); err != nil {
			return err
		}
		if _, err := fmt.Fprintln(out, claim.EvidenceBasisLine()); err != nil {
			return err
		}
	}
	if err := writeNotices(out, summary.notices); err != nil {
		return err
	}
	if err := writeNoVerdictLine(out, claims); err != nil {
		return err
	}
	if !summary.allUnreviewed {
		return writeCollapsedNotes(out, summary)
	}
	return nil
}
