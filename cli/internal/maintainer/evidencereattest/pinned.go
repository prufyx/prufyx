// SPDX-License-Identifier: AGPL-3.0-only

package evidencereattest

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/prufyx/prufyx/cli/internal/constraintengine"
	"github.com/prufyx/prufyx/cli/internal/maintainer/evidencerepin"
)

// Pinned-lease renewal. A human statement may carry, per renewed rule, the
// row field lease: "pinned". Such a row moves the rule from the time lease to
// the pinned lease (constraintengine.LeasePinned): reviewedAt becomes the
// statement's attestedAt, validUntil exactly attestedAt plus
// constraintengine.PinnedLeaseYears, and evidence.lease is set. Nothing else
// in the rule changes. A statement pins all of its rows or none.
//
// A rule is pinnable only if the fixed-version predicate holds, recomputed
// here from the prior pack and the retained worklist and never taken from the
// statement (pinnedReasons): the structural clauses of
// constraintengine.PinnedRuleReasons, plus the clause that every citation
// was compared on its release line (release_line, or a tag_line derived from
// git tags) with a pinned tag and a line, the comparison evidence repin
// --pinned-only repeats. Pinning counts as one batch cycle and never resets
// the consecutive-cycle count; a rule at the cap cannot be pinned. Automated
// mode refuses pinning.

const (
	// reasonPinnedNotEligible is the notExtended class of a rule a pinning
	// statement leaves out because the fixed-version predicate fails; the
	// precise reasons follow after a colon.
	reasonPinnedNotEligible = "LEASE_PINNED_NOT_ELIGIBLE"
	// reasonAlreadyPinned excludes a rule that already holds a pinned lease:
	// it has no end to renew, and a renewal would break the pinned window.
	reasonAlreadyPinned = "LEASE_ALREADY_PINNED"
	// reasonPinNothing is the error text of a pinning run that would pin
	// nothing; such a statement could not be recomputed by Verify.
	reasonPinNothing = "no rule is pinnable in this batch"
)

// PinnedStatementText is the exact text a human signs for a statement that
// pins the lease of its rules. Like FixedStatementText it is never free-form.
func PinnedStatementText(generatedAt string) string {
	return "I ran `evidence repin` at `" + generatedAt + "` with no reused state. " +
		"Every listed citation was mechanically classified NO_NEW_RELEASE, FILE_IDENTICAL or SPAN_IDENTICAL " +
		"against the listed upstream commit on its release line. I reviewed the listed upstream releases for " +
		"errata affecting the listed rules and found none. I fully re-reviewed the sampled rules. No rule " +
		"content other than reviewedAt, validUntil and lease changes. This pins the lease of these rules: " +
		"validUntil is ten years after attestedAt, the rules no longer end on time, and they stay current only " +
		"while `evidence repin --pinned-only` finds no drift on their release line. It is not a new compatibility claim."
}

// statementPins reports whether statement pins the lease of its rows: it has
// rows and the first row says so. ParseStatement guarantees that then every
// row does.
func statementPins(statement Statement) bool {
	return len(statement.Rules) > 0 && statement.Rules[0].Lease == constraintengine.LeasePinned
}

// checkRowLeases holds the lease column of a statement's rows to its
// contract. It is part of ParseStatement, so a statement that breaks it never
// parses: a row lease is absent or "pinned", only a human statement has one,
// and all rows agree.
func checkRowLeases(statement Statement, role string) error {
	pinned := 0
	for _, ra := range statement.Rules {
		switch ra.Lease {
		case "":
		case constraintengine.LeasePinned:
			pinned++
		default:
			return fmt.Errorf("%w: row lease", ErrRejected)
		}
	}
	if pinned == 0 {
		return nil
	}
	if role != RoleHuman || statement.Schema != StatementSchema || pinned != len(statement.Rules) {
		return fmt.Errorf("%w: a pinned lease belongs to a human statement and to every row of it", ErrRejected)
	}
	return nil
}

// lineDerivable is the clause "the citation's line is derivable by repin": the
// citation was compared on its release line, with the line and the pinned tag
// that comparison records.
func lineDerivable(baseline, line, pinnedTag string) bool {
	return (baseline == evidencerepin.BaselineReleaseLine || baseline == evidencerepin.BaselineTagLine) && line != "" && pinnedTag != ""
}

// pinnedReasons computes why a rule cannot be pinned, from the prior pack's
// rule and the baseline facts of its citations; empty means it can. A record
// (line attestation, path policy) is never pinnable.
func pinnedReasons(candidate ruleCandidate, citations [][3]string) []string {
	if candidate.Fields.record {
		return []string{"a record has no pinned lease"}
	}
	reasons, err := constraintengine.PinnedRuleReasons(candidate.Raw)
	if err != nil {
		return []string{"unreadable rule"}
	}
	if candidate.Fields.Evidence.Lease == constraintengine.LeasePinned {
		reasons = append(reasons, "already-pinned")
	}
	if len(citations) == 0 {
		reasons = append(reasons, "no-citation")
	}
	for _, citation := range citations {
		if !lineDerivable(citation[0], citation[1], citation[2]) {
			reasons = append(reasons, "citation-line-not-derivable")
			break
		}
	}
	return reasons
}

// pinnedNotExtendedClass is the notExtended class of an unpinnable rule.
func pinnedNotExtendedClass(reasons []string) string {
	sorted := append([]string(nil), reasons...)
	sort.Strings(sorted)
	return reasonPinnedNotEligible + ":" + strings.Join(sorted, ",")
}

// pinBatch is the pinning statement's replacement for the wave's stagger: a
// pinned rule has no end date to spread, so the 15% per ISO week cap does not
// apply to it (checkV7 exempts pinned rules by name). It takes the eligible
// rules whose current lease is due (renewalWindow, as in a human batch) and
// whose new window is later than the current one, soonest-expiring first, and
// caps the batch at maxRules (0 means no cap); the rest are deferred. Every
// pinned rule still counts against the daily loosening limit of the gate.
func pinBatch(candidates []ruleCandidate, eligibleIDs []string, attestedAt time.Time, maxRules int) (chosen, notLater, notDue, deferred []string, err error) {
	pinnedUntil := attestedAt.AddDate(constraintengine.PinnedLeaseYears, 0, 0)
	current := map[string]time.Time{}
	for _, candidate := range candidates {
		validUntil, err := parseUTC(candidate.Fields.Evidence.ValidUntil)
		if err != nil {
			return nil, nil, nil, nil, fmt.Errorf("%w: V7: rule %s validUntil", ErrRejected, candidate.RuleID)
		}
		current[candidate.RuleID] = validUntil
	}
	var ordered []string
	for _, id := range eligibleIDs {
		switch {
		case !pinnedUntil.After(current[id]):
			notLater = append(notLater, id)
		case current[id].Sub(attestedAt) > renewalWindow:
			notDue = append(notDue, id)
		default:
			ordered = append(ordered, id)
		}
	}
	sort.Slice(ordered, func(i, j int) bool {
		if !current[ordered[i]].Equal(current[ordered[j]]) {
			return current[ordered[i]].Before(current[ordered[j]])
		}
		return ordered[i] < ordered[j]
	})
	if maxRules > 0 && len(ordered) > maxRules {
		return ordered[:maxRules], notLater, notDue, ordered[maxRules:], nil
	}
	return ordered, notLater, notDue, nil, nil
}

// pinnedUntilFor is the validUntil a pinned row gives its rule: exactly
// attestedAt plus the pinned lease length.
func pinnedUntilFor(attestedAt string) (string, error) {
	until, err := constraintengine.PinnedValidUntil(attestedAt)
	if err != nil {
		return "", fmt.Errorf("%w: pinned validUntil", ErrRejected)
	}
	return until, nil
}
