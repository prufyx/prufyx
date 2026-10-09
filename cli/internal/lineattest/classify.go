// SPDX-License-Identifier: AGPL-3.0-only

package lineattest

import (
	"fmt"
	"reflect"
	"sort"
	"time"

	"github.com/prufyx/prufyx/cli/internal/constraintengine"
)

// Change classes. A tightening change can only make fewer answers rely on an
// attestation (a covered line becomes a gap); a loosening change can make an
// answer rely on an attestation it could not rely on before. Anything not
// provably tightening is loosening.
const (
	Tightening = "tightening"
	Loosening  = "loosening"
)

// Change kinds.
const (
	ChangeAdded    = "added"
	ChangeRemoved  = "removed"
	ChangeModified = "modified"
)

// Change is one difference between two attestation sets for one scope.
type Change struct {
	Key   Key
	Kind  string
	Class string
	// Fields names the changed members of a modified attestation, sorted.
	Fields []string
	// Renewal marks a loosening modification that changes only the times
	// and moves all of them forward: reviewedAt later, derivedAt later (when
	// either side has one) and validUntil later, with the same completeness,
	// rules, basis, extractor and sources: a lease renewal. Moving reviewedAt
	// or derivedAt backwards (backdating), or extending validUntil without a
	// later review, is a plain loosening change, never a renewal.
	Renewal bool
	// Basis is the basis of the attestation after the change (before it,
	// for a removal).
	Basis string
}

// Classify compares two attestation sets and returns every change in
// canonical scope order. Unchanged attestations are not reported. Each set
// must hold at most one attestation per scope, as a validated document does;
// a set with a duplicate scope is an error, never collapsed, because keeping
// either copy could hide a change.
//
//   - removed: tightening (the line becomes a gap again);
//   - added: loosening;
//   - modified: tightening only when nothing changed but the validity window
//     shrinking (reviewedAt/derivedAt later, validUntil earlier or equal);
//     every other modification, including a renewal, a changed rule list,
//     changed releases, a changed source, basis or extractor, is loosening.
//
// A loosening change to a mechanical attestation is admissible without a
// person only with a reproducible derivation behind it; a loosening change
// to a reviewed attestation needs a person. Classify does not decide
// admissibility; it tells the caller which rule applies.
func Classify(before, after []LineAttestation) ([]Change, error) {
	old, err := byScope("before", before)
	if err != nil {
		return nil, err
	}
	cur, err := byScope("after", after)
	if err != nil {
		return nil, err
	}
	keys := make([]Key, 0, len(old)+len(cur))
	for k := range old {
		keys = append(keys, k)
	}
	for k := range cur {
		if _, ok := old[k]; !ok {
			keys = append(keys, k)
		}
	}
	sort.Slice(keys, func(i, j int) bool { return keyLess(keys[i], keys[j]) })
	var out []Change
	for _, k := range keys {
		a, hadOld := old[k]
		b, hasNew := cur[k]
		switch {
		case hadOld && !hasNew:
			out = append(out, Change{Key: k, Kind: ChangeRemoved, Class: Tightening, Basis: a.Evidence.Basis})
		case !hadOld && hasNew:
			out = append(out, Change{Key: k, Kind: ChangeAdded, Class: Loosening, Basis: b.Evidence.Basis})
		default:
			if c, changed := classifyModified(a, b); changed {
				out = append(out, c)
			}
		}
	}
	return out, nil
}

func byScope(side string, atts []LineAttestation) (map[Key]LineAttestation, error) {
	out := make(map[Key]LineAttestation, len(atts))
	for _, a := range atts {
		if _, dup := out[a.Key()]; dup {
			return nil, fmt.Errorf("%w: the %s set holds two attestations for %s", ErrInvalid, side, a.Key())
		}
		out[a.Key()] = a
	}
	return out, nil
}

func classifyModified(a, b LineAttestation) (Change, bool) {
	c := Change{Key: a.Key(), Kind: ChangeModified, Basis: b.Evidence.Basis}
	other := false
	if a.Completeness != b.Completeness {
		c.Fields, other = append(c.Fields, "completeness"), true
	}
	if !reflect.DeepEqual(normIDs(a.RuleIDs), normIDs(b.RuleIDs)) {
		c.Fields, other = append(c.Fields, "ruleIds"), true
	}
	if !reflect.DeepEqual(a.Releases, b.Releases) {
		// Naming other releases changes which hops the attestation covers.
		c.Fields, other = append(c.Fields, "releases"), true
	}
	if a.Evidence.Basis != b.Evidence.Basis {
		c.Fields, other = append(c.Fields, "evidence.basis"), true
	}
	if !reflect.DeepEqual(a.Evidence.Extractor, b.Evidence.Extractor) {
		c.Fields, other = append(c.Fields, "evidence.extractor"), true
	}
	if !reflect.DeepEqual(normSources(a.Evidence.Sources), normSources(b.Evidence.Sources)) {
		c.Fields, other = append(c.Fields, "evidence.sources"), true
	}
	startLater, startEarlier := compareTimes(a.Evidence.ReviewedAt, b.Evidence.ReviewedAt)
	endLater, endEarlier := compareTimes(a.Evidence.ValidUntil, b.Evidence.ValidUntil)
	derivedLater, derivedEarlier := compareTimes(a.Evidence.DerivedAt, b.Evidence.DerivedAt)
	if a.Evidence.DerivedAt != b.Evidence.DerivedAt {
		c.Fields = append(c.Fields, "evidence.derivedAt")
	}
	if a.Evidence.ReviewedAt != b.Evidence.ReviewedAt {
		c.Fields = append(c.Fields, "evidence.reviewedAt")
	}
	if a.Evidence.ValidUntil != b.Evidence.ValidUntil {
		c.Fields = append(c.Fields, "evidence.validUntil")
	}
	if len(c.Fields) == 0 {
		return Change{}, false
	}
	sort.Strings(c.Fields)
	timesUnknown := (a.Evidence.ReviewedAt != b.Evidence.ReviewedAt && !startLater && !startEarlier) ||
		(a.Evidence.ValidUntil != b.Evidence.ValidUntil && !endLater && !endEarlier) ||
		(a.Evidence.DerivedAt != b.Evidence.DerivedAt && !derivedLater && !derivedEarlier)
	if !other && !timesUnknown && !startEarlier && !endLater && !derivedEarlier {
		c.Class = Tightening
		return c, true
	}
	c.Class = Loosening
	hasDerived := a.Evidence.DerivedAt != "" || b.Evidence.DerivedAt != ""
	c.Renewal = !other && !timesUnknown && endLater && startLater && (!hasDerived || derivedLater)
	return c, true
}

// compareTimes reports whether b is later or earlier than a. Unparseable or
// absent values compare as neither.
func compareTimes(a, b string) (later, earlier bool) {
	ta, err1 := constraintengine.ParseUTC(a)
	tb, err2 := constraintengine.ParseUTC(b)
	if err1 != nil || err2 != nil {
		return false, false
	}
	return tb.After(ta), tb.Before(ta)
}

func normIDs(ids []string) []string {
	out := append([]string{}, ids...)
	sort.Strings(out)
	return out
}

func normSources(s []constraintengine.SourceEvidence) []constraintengine.SourceEvidence {
	return append([]constraintengine.SourceEvidence{}, s...)
}

// Renewable reports whether a mechanical attestation can be renewed by
// re-derivation at now: it is mechanical and names its extractor. The
// renewal itself is a new extractor run whose output, verified byte for byte
// against the pinned sources, replaces the old attestation; Classify then
// reports it as a loosening Renewal.
func Renewable(a LineAttestation) bool {
	return a.Evidence.Basis == constraintengine.BasisMechanical && a.Evidence.Extractor != nil
}

// ExpiresWithin reports whether the attestation is stale at now+d (or its
// validUntil cannot be read), for listing attestations that need renewal.
func (a LineAttestation) ExpiresWithin(now time.Time, d time.Duration) bool {
	until, err := constraintengine.ParseUTC(a.Evidence.ValidUntil)
	return err != nil || !now.Add(d).Before(until)
}
