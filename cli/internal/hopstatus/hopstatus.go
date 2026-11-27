// SPDX-License-Identifier: AGPL-3.0-only

// Package hopstatus resolves the status of every hop (pair of consecutive
// release lines) on the path of a jump, from the evidence of the signed pack
// only: no model, no network, no clock. See cli/docs/hopstatus.md.
//
// Priority per hop, strongest first:
//
//	B rule with a citation          -> BLOCKED
//	admitted attestation            -> PASS
//	cited change list               -> L
//	hop-stop record                 -> G with the stop code
//	nothing                         -> G "not-derived"
//
// PASS needs an attestation and nothing else. The derivedFrom line is
// informational: it only picks the next bounded action of a hop with no
// evidence; it is never evidence and never changes a status.
package hopstatus

import (
	"errors"
	"fmt"

	"github.com/prufyx/prufyx/cli/internal/hopstop"
	"github.com/prufyx/prufyx/cli/internal/lineattest"
)

// Status of a hop.
type Status string

const (
	Blocked Status = "BLOCKED"
	Pass    Status = "PASS"
	// Change is L: a cited change list exists, no decision.
	Change Status = "L"
	// Gap is G: not decided; ReasonCode and NextAction say why and what.
	Gap Status = "G"
)

// Source says which evidence decided the hop.
type Source string

const (
	SourceRule        Source = "rule"
	SourceAttestation Source = "attestation"
	SourceHopStop     Source = "hop-stop"
	SourceRelnotes    Source = "relnotes"
	SourceNone        Source = "none"
)

// Reason codes of a G hop that is not a stop code.
const (
	ReasonNotDerived       = "not-derived"
	ReasonEvidenceConflict = "evidence-conflict"
)

// Next actions of a G hop with no evidence.
const (
	ActionBackfillDepth = "backfill-depth"
	ActionReDerive      = "re-derive"
)

// Block is one BLOCKED rule of a hop. Citation (tag and path of the source)
// is required: a block without one is refused, never downgraded.
type Block struct {
	RuleID   string
	Citation string
}

// Evidence is everything the pack holds for one hop.
type Evidence struct {
	// Blocked are the B rules of the hop (admitted, citation-backed).
	Blocked []Block
	// Attested: an admitted line attestation covers the hop. It is set by
	// the caller from the pack, never from DerivedFrom.
	Attested bool
	// Change is the citation of the cited change list (L); empty: none.
	Change string
	// Stop is the hop-stop record of the hop, nil: none.
	Stop *hopstop.Record
}

// Project is one project's pack view for the jump.
type Project struct {
	// Lines are the project's known release lines, ascending, unique.
	Lines []string
	// Hops holds the evidence by hop, keyed by Key(from, to). A key that is
	// not a hop of Lines is refused.
	Hops map[string]Evidence
	// DerivedFrom is the target's derivedFrom line, "" when unknown. It
	// only chooses NextAction.
	DerivedFrom string
}

// Key is the key of a hop in Project.Hops.
func Key(from, to string) string { return from + "->" + to }

// Hop is the resolved status of one hop.
type Hop struct {
	From       string
	To         string
	Status     Status
	Citation   string
	ReasonCode string
	Source     Source
	NextAction string
}

// ErrRefused marks input the resolver will not answer from.
var ErrRefused = errors.New("hopstatus: refused")

func refuse(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrRefused, fmt.Sprintf(format, args...))
}

func (p Project) check() (index map[string]int, err error) {
	index = map[string]int{}
	for i, l := range p.Lines {
		switch {
		case !lineattest.ValidLine(l):
			return nil, refuse("line %q is not major.minor", l)
		case i > 0 && !lineattest.LineLess(p.Lines[i-1], l):
			return nil, refuse("lines are not strictly ascending at %q", l)
		}
		index[l] = i
	}
	if p.DerivedFrom != "" && !lineattest.ValidLine(p.DerivedFrom) {
		return nil, refuse("derivedFrom is not major.minor")
	}
	hops := map[string]bool{}
	for i := 1; i < len(p.Lines); i++ {
		hops[Key(p.Lines[i-1], p.Lines[i])] = true
	}
	for k, ev := range p.Hops {
		if !hops[k] {
			return nil, refuse("evidence for %q, which is not a hop of the known lines", k)
		}
		for _, b := range ev.Blocked {
			if b.RuleID == "" || b.Citation == "" {
				return nil, refuse("a BLOCKED rule of %s has no rule id or no citation", k)
			}
		}
		if ev.Stop != nil {
			if err := ev.Stop.Validate(); err != nil {
				return nil, refuse("hop-stop of %s: %v", k, err)
			}
			if Key(ev.Stop.FromLine, ev.Stop.ToLine) != k {
				return nil, refuse("hop-stop of another hop under %s", k)
			}
		}
	}
	return index, nil
}

// Resolve returns one Hop per consecutive known line from fromLine up to
// toLine, ascending. Both lines must be known and fromLine before toLine;
// otherwise, and for any inconsistent evidence, it returns an error and no
// hops: an unanswerable path is never a PASS.
func Resolve(p Project, fromLine, toLine string) ([]Hop, error) {
	index, err := p.check()
	if err != nil {
		return nil, err
	}
	i, okFrom := index[fromLine]
	j, okTo := index[toLine]
	if !okFrom || !okTo {
		return nil, refuse("line %q or %q is not known for the project", fromLine, toLine)
	}
	if i >= j {
		return nil, refuse("%s is not before %s", fromLine, toLine)
	}
	out := make([]Hop, 0, j-i)
	for k := i + 1; k <= j; k++ {
		from, to := p.Lines[k-1], p.Lines[k]
		out = append(out, p.resolveHop(from, to, p.Hops[Key(from, to)]))
	}
	return out, nil
}

func (p Project) resolveHop(from, to string, ev Evidence) Hop {
	h := Hop{From: from, To: to}
	switch {
	case len(ev.Blocked) > 0:
		h.Status, h.Source, h.Citation = Blocked, SourceRule, ev.Blocked[0].Citation
		h.ReasonCode = ev.Blocked[0].RuleID
	case ev.Attested && ev.Stop != nil:
		// An attestation and a stop for one hop contradict each other.
		h.Status, h.Source, h.ReasonCode = Gap, SourceNone, ReasonEvidenceConflict
		h.NextAction = ActionReDerive
	case ev.Attested:
		h.Status, h.Source = Pass, SourceAttestation
	case ev.Change != "":
		h.Status, h.Source, h.Citation = Change, SourceRelnotes, ev.Change
	case ev.Stop != nil:
		h.Status, h.Source, h.ReasonCode = Gap, SourceHopStop, ev.Stop.Code
	default:
		h.Status, h.Source, h.ReasonCode = Gap, SourceNone, ReasonNotDerived
		h.NextAction = ActionReDerive
		if p.DerivedFrom == "" || lineattest.LineLess(from, p.DerivedFrom) {
			h.NextAction = ActionBackfillDepth
		}
	}
	return h
}
