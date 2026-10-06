// SPDX-License-Identifier: AGPL-3.0-only

package lineattest

import (
	"time"

	"github.com/prufyx/prufyx/cli/internal/constraintengine"
)

// Freshness values, the same tokens a rule claim reports.
const (
	FreshnessCurrent           = "current"
	FreshnessStale             = "stale"
	FreshnessClockBeforeReview = "clock_before_review"
)

// Freshness evaluates the attestation's validity window at now, exactly as
// the engine evaluates a rule's: before reviewedAt it is not yet usable, at
// or after validUntil it is stale. Only a current attestation may be relied
// on; any other state must be treated as if the attestation were absent.
func (a LineAttestation) Freshness(now time.Time) string { return a.Evidence.Freshness(now) }

// Freshness evaluates the evidence's validity window at now (see
// LineAttestation.Freshness).
func (e Evidence) Freshness(now time.Time) string {
	reviewed, err1 := constraintengine.ParseUTC(e.ReviewedAt)
	until, err2 := constraintengine.ParseUTC(e.ValidUntil)
	if err1 != nil || err2 != nil {
		return FreshnessStale
	}
	if now.Before(reviewed) {
		return FreshnessClockBeforeReview
	}
	if !now.Before(until) {
		return FreshnessStale
	}
	return FreshnessCurrent
}

// Status is an attestation together with its freshness at the lookup time.
type Status struct {
	Attestation LineAttestation
	Freshness   string
}

// Current reports whether the attestation may be relied on.
func (s Status) Current() bool { return s.Freshness == FreshnessCurrent }

// Index looks attestations up by scope. Build it only from a validated
// document (Parse or Validate), which guarantees one attestation per scope.
type Index struct {
	byKey map[Key]LineAttestation
}

// NewIndex indexes atts.
func NewIndex(atts []LineAttestation) Index {
	ix := Index{byKey: make(map[Key]LineAttestation, len(atts))}
	for _, a := range atts {
		ix.byKey[a.Key()] = copyOf(a)
	}
	return ix
}

// AttestationsFor returns the attestations for one component, minor line and
// fact family, each with its freshness at now. A validated document holds at
// most one per scope, so the result has zero or one element. An empty result
// means the line is not attested for that family; it never means "no rules".
//
// Contract for a caller that plans or evaluates a hop into the line:
//   - only a current attestation may be relied on; any other freshness is
//     treated as no attestation;
//   - the attestation says which rules exist, not that they decided the hop:
//     every listed rule must be evaluated for the hop's concrete versions,
//     and a listed rule that does not match the hop (constraintengine
//     RuleTransition.Match returns MatchNone), or that does not reach a
//     verdict, makes the hop a gap, never covered.
//
// An admitted pack only holds attestations whose rules match every
// transition into the line (CheckRuleSets, rule-not-line-wide), so the
// second point should not trigger for a hop of the family's shape; it is the
// caller's guard for any hop of another shape (for example one that skips a
// minor line) and for an index built without CheckRuleSets.
func (ix Index) AttestationsFor(component, line, family string, now time.Time) []Status {
	a, ok := ix.byKey[Key{Component: component, Line: line, Family: family}]
	if !ok {
		return nil
	}
	return []Status{{Attestation: copyOf(a), Freshness: a.Freshness(now)}}
}

// Len is the number of indexed attestations.
func (ix Index) Len() int { return len(ix.byKey) }

func copyOf(a LineAttestation) LineAttestation {
	a.RuleIDs = append([]string{}, a.RuleIDs...)
	a.Evidence.Sources = append([]constraintengine.SourceEvidence(nil), a.Evidence.Sources...)
	if a.Evidence.Extractor != nil {
		x := *a.Evidence.Extractor
		a.Evidence.Extractor = &x
	}
	return a
}
