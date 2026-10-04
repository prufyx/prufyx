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
//   - consensus, empirical, lead or any other basis: not admitted by this
//     version. The engine evaluates consensus as block-only, but this gate
//     has no consensus verifier; empirical evidence may pass and needs a
//     reproduction proof the gate cannot check yet; a lead is never
//     published. Every head pack must also hold only known bases, with
//     consensus evaluated as block-only and leads as verdict-neutral by the
//     engine (the block-only check).
//   - removing a rule: never admitted; withdraw it instead.
//
// A pack's line attestations and upgrade-path policies are diffed record by
// record, keyed by record ID, and classified the same way (removing a line
// attestation is tightening; withdrawing a path policy or moving a record's
// validUntil earlier is tightening; anything else is loosening). A
// loosening record change is admitted only by re-derivation (a mechanical
// line attestation), by a verified automated reattestation statement that
// renews the record and changes nothing but its two dates (a reviewed
// record), or, for a reviewed line attestation, by an owner approval for
// exactly that record plus a cross-check against the attesting extractor's
// own derivation of the line. See records.go.
//
// On top of that the gate checks every head pack (engine admission,
// rulecheck, fact registry and size caps, the stagger cap for renewed
// leases, corpus attestation and support inventory regeneration), enforces a
// per-change cap on loosening changes and a kill switch file that blocks
// all loosening, and reports whether the change would be eligible for
// automatic merging (bot author, every check green, knowledge files only).
// It never merges anything itself.
package knowledgegate
