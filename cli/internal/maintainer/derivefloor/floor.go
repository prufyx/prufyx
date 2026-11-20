// SPDX-License-Identifier: AGPL-3.0-only

// Package derivefloor derives the two floor numbers of a CRD version target
// from per-pair outcomes. It is one pure function: no network, no clock, no
// project name, no file access. The verify-pr recompute and the oracle both
// call it (Verify), so no second derivation exists.
//
//   - minFrom is the from-line of the lowest pair of the contiguous run of
//     attested pairs that ends at the newest pair. One failing pair cuts the
//     floor above it.
//   - derivedFrom is the from-line of the lowest pair of the contiguous run
//     of pairs below the floor that each carry an outcome: an attestation or
//     a final stop code. A pair with no outcome ends the run.
//
// derivedFrom is never evidence. Nothing here, and nothing that reads this
// package's result, may treat "the line is at or above derivedFrom" as an
// attestation; only a pair's own attestation, rule or stop speaks for it.
package derivefloor

import (
	"errors"
	"fmt"
	"slices"

	"github.com/prufyx/prufyx/cli/internal/hopstop"
)

// Line is a release line (major, minor), the same shape as the target's
// minFrom.
type Line = [2]int

// MaxDepth is the hard bound of Facts.Depth: the number of newest pairs a
// derivation may look at. A constant; no input can raise it.
const MaxDepth = 24

// PairFact is the outcome of one pair of consecutive release lines From to
// To. Attested means an admitted attestation covers the pair. Stop is a
// final stop code (closed set, see FinalStop) or empty. A pair with neither
// has no outcome. Attested together with a stop is a contradiction and
// refuses the whole derivation.
type PairFact struct {
	From, To Line
	Attested bool
	Stop     string
}

// Facts is the input: the pairs in ascending order, each pair's To equal to
// the next pair's From, and the bound on how many of the newest pairs are
// looked at (1..MaxDepth).
type Facts struct {
	Pairs []PairFact
	Depth int
}

// Stop is one recorded final stop of a pair.
type Stop struct {
	From, To Line
	Code     string
}

// Result is the derivation. Floor is false when the newest pair does not
// attest: there is then no minFrom and no derivedFrom, and Stops lists the
// final stops of the contiguous run of pairs with an outcome from the newest
// pair down. With a floor, Stops lists the final stops of the pairs in
// [DerivedFrom, MinFrom), ascending; an attested pair in that range is
// recorded by its attestation, not here.
type Result struct {
	Floor       bool
	MinFrom     Line
	DerivedFrom Line
	Stops       []Stop
}

// FinalStop reports whether code is a final stop code (hopstop.Final).
func FinalStop(code string) bool { return hopstop.Final(code) }

// TransientStop reports whether code is a transient code (hopstop.Transient).
func TransientStop(code string) bool { return hopstop.Transient(code) }

func less(a, b Line) bool { return a[0] < b[0] || (a[0] == b[0] && a[1] < b[1]) }

// Errors.
var (
	ErrFacts = errors.New("derivefloor: facts refused")
)

func (f Facts) validate() error {
	if f.Depth < 1 || f.Depth > MaxDepth {
		return fmt.Errorf("%w: depth %d is outside 1..%d", ErrFacts, f.Depth, MaxDepth)
	}
	if len(f.Pairs) == 0 {
		return fmt.Errorf("%w: no pairs", ErrFacts)
	}
	for i, p := range f.Pairs {
		var prevEnd Line
		if i > 0 {
			prevEnd = f.Pairs[i-1].To
		}
		start := p.From
		switch {
		case p.From[0] < 0 || p.From[1] < 0 || p.To[0] < 0 || p.To[1] < 0:
			return fmt.Errorf("%w: pair %d has a negative line", ErrFacts, i)
		case !less(p.From, p.To):
			return fmt.Errorf("%w: pair %d: lines are not strictly ascending", ErrFacts, i)
		case i > 0 && prevEnd != start:
			return fmt.Errorf("%w: pair %d does not continue pair %d (unsorted, duplicate or missing line)", ErrFacts, i, i-1)
		case p.Attested && p.Stop != "":
			return fmt.Errorf("%w: pair %d is both attested and stopped", ErrFacts, i)
		case p.Stop != "" && !FinalStop(p.Stop) && !TransientStop(p.Stop):
			return fmt.Errorf("%w: pair %d: unknown stop code", ErrFacts, i)
		}
	}
	return nil
}

func hasOutcome(p PairFact) bool { return p.Attested || FinalStop(p.Stop) }

// DeriveFloor derives minFrom, derivedFrom and the stops from the facts. Any
// malformed input is an error and never a partial result.
func DeriveFloor(f Facts) (Result, error) {
	if err := f.validate(); err != nil {
		return Result{}, err
	}
	top := len(f.Pairs) - 1
	lowest := top - f.Depth + 1
	if lowest < 0 {
		lowest = 0
	}
	i := top
	for i >= lowest && f.Pairs[i].Attested {
		i--
	}
	run := i + 1 // lowest attested pair index of the run, == top+1 when none
	var res Result
	end := top // highest index of the pairs the outcome run covers
	if run <= top {
		res.Floor = true
		res.MinFrom = f.Pairs[run].From
		end = run - 1
	}
	j := end
	for j >= lowest && hasOutcome(f.Pairs[j]) {
		j--
	}
	if res.Floor {
		res.DerivedFrom = res.MinFrom
		if j+1 <= end {
			res.DerivedFrom = f.Pairs[j+1].From
		}
	}
	for k := j + 1; k <= end; k++ {
		if p := f.Pairs[k]; FinalStop(p.Stop) {
			res.Stops = append(res.Stops, Stop{From: p.From, To: p.To, Code: p.Stop})
		}
	}
	return res, nil
}

// Claim is what a target and its records carry: the two floor numbers and
// the recorded stops. An absent derivedFrom in a target is passed as the
// minFrom (the default).
type Claim struct {
	MinFrom     Line
	DerivedFrom Line
	Stops       []Stop
}

// Verify is the one check verify-pr and the oracle share. It refuses a claim
// that differs in any way from DeriveFloor(f): a floor above or below the
// derived one, a missing or extra stop, an unattested pair at or above the
// floor, a pair in [derivedFrom, minFrom) with neither attestation nor
// stop, derivedFrom above minFrom. A claim over facts without a floor is
// refused.
func Verify(f Facts, c Claim) error {
	res, err := DeriveFloor(f)
	if err != nil {
		return err
	}
	if less(c.MinFrom, c.DerivedFrom) {
		return fmt.Errorf("derivefloor: derivedFrom %d.%d is above minFrom %d.%d", c.DerivedFrom[0], c.DerivedFrom[1], c.MinFrom[0], c.MinFrom[1])
	}
	if !res.Floor {
		return fmt.Errorf("derivefloor: the newest pair does not attest, no floor can be claimed")
	}
	// Per-pair reasons first, so a refusal says which pair.
	for _, p := range f.Pairs {
		switch {
		case !less(p.From, c.MinFrom) && !p.Attested:
			return fmt.Errorf("derivefloor: pair %d.%d is at or above minFrom %d.%d and is not attested", p.From[0], p.From[1], c.MinFrom[0], c.MinFrom[1])
		case !less(p.From, c.DerivedFrom) && less(p.From, c.MinFrom) && !p.Attested && !FinalStop(p.Stop):
			return fmt.Errorf("derivefloor: pair %d.%d in [derivedFrom, minFrom) has neither an attestation nor a final stop", p.From[0], p.From[1])
		}
	}
	if c.MinFrom != res.MinFrom {
		return fmt.Errorf("derivefloor: minFrom %d.%d differs from the derived %d.%d", c.MinFrom[0], c.MinFrom[1], res.MinFrom[0], res.MinFrom[1])
	}
	if c.DerivedFrom != res.DerivedFrom {
		return fmt.Errorf("derivefloor: derivedFrom %d.%d differs from the derived %d.%d", c.DerivedFrom[0], c.DerivedFrom[1], res.DerivedFrom[0], res.DerivedFrom[1])
	}
	if !slices.Equal(c.Stops, res.Stops) {
		return fmt.Errorf("derivefloor: the recorded stops differ from the derived ones")
	}
	return nil
}
