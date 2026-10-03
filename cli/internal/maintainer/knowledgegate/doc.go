// SPDX-License-Identifier: AGPL-3.0-only

// Package knowledgegate is the continuous-integration gate for changes to
// the published knowledge: the rule packs, their corpus attestations, the
// generated support inventory and the reattestation records.
//
// The gate compares two checkouts of the repository, the base a change is
// proposed against and the proposed head, and never executes anything from
// the head: it only reads the head's files with the code it was itself
// built from (the base).
//
// Every changed rule is classified from the pack diff, never from anything
// the change declares:
//
//   - tightening: the change can only turn a PASS or BLOCKED answer into
//     UNKNOWN. Exactly two edits qualify: withdrawing an active rule
//     (evidence.state active -> withdrawn) and moving evidence.validUntil
//     earlier. A rule added already withdrawn is also tightening. Everything
//     else in the rule must stay byte-identical (canonical JSON).
//   - loosening: anything else, including a new rule (it also makes PASS
//     reachable for inputs it does not match), a renewal, a re-pin, any
//     range change (narrowing a range can turn a range-matched BLOCKED into
//     a scope-complete PASS when another rule's anchor equals the
//     transition), a text change, and removing a rule.
//
// A tightening change needs only the well-formedness checks. A loosening
// change is admitted only with a proof the gate checks itself:
//
//   - basis mechanical: the named extractor, as compiled into this binary,
//     re-derives the rule from upstream bytes pinned by commit SHA and
//     fetched independently, and the re-derived entry is byte-identical
//     (canonical JSON) to the proposed one;
//   - basis reviewed: the change carries a signed reattestation statement
//     for the pack that passes every reattestation invariant, including the
//     comparison with a worklist the verifying job produced itself, or a
//     signed owner approval for exactly that entry, verified against a
//     pinned approval key;
//   - consensus, empirical or any other basis: not admitted by this
//     version. Consensus evidence may only ever block; until the engine
//     evaluates it as block-only, a consensus rule fails the gate.
//   - removing a rule: never admitted; withdraw it instead.
//
// On top of that the gate checks every head pack (engine admission,
// rulecheck, fact registry and size caps, the stagger cap for renewed
// leases, corpus attestation and support inventory regeneration), enforces a
// per-change cap on loosening changes and a kill switch file that blocks
// all loosening, and reports whether the change would be eligible for
// automatic merging (bot author, every check green, knowledge files only).
// It never merges anything itself.
package knowledgegate
