// SPDX-License-Identifier: AGPL-3.0-only

package constraintengine

import (
	"encoding/json"
	"time"
)

// Evidence lease values. An absent lease is the time lease: the evidence ends
// at validUntil and a rule past it answers UNKNOWN. A pinned lease is held
// only by a rule whose claim is a fixed from-to transition cited at immutable
// commits (PinnedRuleReasons): such a rule is never stale on time and reports
// the freshness FreshnessPinned. A pinned rule still carries a validUntil,
// fixed by PinnedValidUntil, so a reader that only knows validity windows sees
// a long lease instead of a missing one.
const (
	LeaseTime   = "time"
	LeasePinned = "pinned"
	// FreshnessPinned is the evidence freshness of an active pinned rule.
	FreshnessPinned = "pinned"
	// PinnedLeaseYears is the fixed length of a pinned rule's validUntil
	// window, counted from its reviewedAt.
	PinnedLeaseYears = 10
)

// EffectiveLease resolves an evidence lease token: absent is the time lease.
func EffectiveLease(lease string) string {
	if lease == "" {
		return LeaseTime
	}
	return lease
}

// PinnedValidUntil is the validUntil a pinned rule must carry: its reviewedAt
// plus PinnedLeaseYears calendar years, in the engine's UTC form.
func PinnedValidUntil(reviewedAt string) (string, error) {
	reviewed, err := parseUTC(reviewedAt)
	if err != nil {
		return "", err
	}
	return reviewed.AddDate(PinnedLeaseYears, 0, 0).UTC().Format(time.RFC3339), nil
}

// Reason tokens of the pinned-rule eligibility predicate.
const (
	PinnedReasonState    = "evidence-not-active"
	PinnedReasonBasis    = "basis-not-reviewed"
	PinnedReasonSubject  = "subject-not-an-exact-transition"
	PinnedReasonRange    = "range-present"
	PinnedReasonOperator = "operator-not-admitted"
	PinnedReasonSeverity = "severity-present"
	PinnedReasonSources  = "source-not-pinned-to-a-commit"
	PinnedReasonHost     = "source-host-not-allowed"
)

// pinnedOperator reports whether the lease may be pinned for a rule of this
// operator. require_component_version and forbid_target_version assert the
// absence of something in a release, which a later re-tag can change without
// changing the cited commit; they keep the time lease.
func pinnedOperator(operator string) bool {
	return operator == "forbid_predicate_value" || operator == "require_intermediate_version"
}

// pinnedClauseReasons evaluates the structural clauses of the fixed-version
// predicate on a typed rule. A withdrawn rule is not asked for an active
// state: withdrawing a pinned rule is always allowed.
func pinnedClauseReasons(r rule, allowWithdrawn bool) []string {
	var reasons []string
	if r.Evidence.State != "active" && !(allowWithdrawn && r.Evidence.State == "withdrawn") {
		reasons = append(reasons, PinnedReasonState)
	}
	if EffectiveBasis(r.Evidence.Basis) != BasisReviewed {
		reasons = append(reasons, PinnedReasonBasis)
	}
	if !validVersion(r.Subject.From) || !validVersion(r.Subject.To) || sameVersion(r.Subject.From, r.Subject.To) {
		reasons = append(reasons, PinnedReasonSubject)
	}
	if r.Range != nil {
		reasons = append(reasons, PinnedReasonRange)
	}
	if !pinnedOperator(r.Operator) {
		reasons = append(reasons, PinnedReasonOperator)
	}
	if r.Severity != "" {
		reasons = append(reasons, PinnedReasonSeverity)
	}
	sourcesOK, hostOK := len(r.Evidence.Sources) > 0 && len(r.Evidence.Sources) <= maxSources, true
	for _, source := range r.Evidence.Sources {
		if !gitRevision.MatchString(source.Revision) || !digestRE.MatchString(source.ContentDigest) || source.StartLine < 1 || source.EndLine < source.StartLine {
			sourcesOK = false
		}
		if !immutableGitURL(source.URL, source.Revision) {
			hostOK = false
		}
	}
	if !sourcesOK {
		reasons = append(reasons, PinnedReasonSources)
	}
	if !hostOK {
		reasons = append(reasons, PinnedReasonHost)
	}
	return reasons
}

// PinnedRuleReasons computes, from one rule's exact JSON, why the rule is not
// eligible for a pinned lease; an empty list means every structural clause of
// the fixed-version predicate holds. Eligibility is never declared by the
// rule: it is recomputed here wherever a pinned lease is relied on. The clause
// that the citation's release line is derivable by evidence repin needs the
// retained worklist and is checked by evidence reattest, not here. An
// unreadable rule is an error, never "eligible".
func PinnedRuleReasons(raw []byte) ([]string, error) {
	var r rule
	if err := json.Unmarshal(raw, &r); err != nil {
		return nil, ErrInvalid
	}
	return pinnedClauseReasons(r, false), nil
}

// validateLease holds a rule's lease to its contract: a known token, and for
// a pinned rule the fixed validUntil and every structural clause of the
// fixed-version predicate (a withdrawn pinned rule is allowed).
func validateLease(r rule) error {
	switch r.Evidence.Lease {
	case "":
		return nil
	case LeaseTime:
		return nil
	case LeasePinned:
	default:
		return ErrInvalid
	}
	want, err := PinnedValidUntil(r.Evidence.ReviewedAt)
	if err != nil || r.Evidence.ValidUntil != want {
		return ErrInvalid
	}
	if len(pinnedClauseReasons(r, true)) != 0 {
		return ErrInvalid
	}
	return nil
}
