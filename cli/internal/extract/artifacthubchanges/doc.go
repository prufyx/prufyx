// SPDX-License-Identifier: AGPL-3.0-only

// Package artifacthubchanges reads the artifacthub.io/changes annotation of
// Helm Chart.yaml files at one pinned commit and proposes DRAFT candidates:
// long flags and values keys that a chart's changelog calls removed or
// deprecated.
//
// The annotation is a YAML document held inside a string of the Chart.yaml: a
// list of entries {kind, description, links}. It is structured intent written
// for humans, not a derivation: nothing here can be re-derived by the gate and
// nothing here is a derived fact. Every candidate therefore carries the
// evidence basis "draft" and NeedsReview; it is a lead for a reviewer, never a
// rule, and it can never authorise a pass. The package is inert: it
// registers nothing, writes nothing and is not wired into the extract runner,
// the rule data or the factory.
//
// Method. The Chart.yaml and the annotation document are each decoded with a
// strict, closed YAML shape (unknown fields, duplicate keys, aliases,
// anchors, explicit tags and extra documents are refused) within fixed size,
// count and depth bounds. Only entries of kind "deprecated" or "removed" are
// examined; added, changed, fixed and security entries produce nothing, and a
// kind outside the reviewed list is withheld. A description becomes a
// candidate only when it states the action of its kind in words, carries
// exactly one distinct backticked identifier (a long flag or a dotted values
// key path), and the action verb stands next to that identifier. Anything
// else is a ledger entry and no candidate. A non-empty ledger means the
// result is incomplete.
//
// Modal, planned, conditional, negated or versioned prose ("may be removed",
// "planned for removal", "removal in 2.0"), a named replacement or default,
// mixed actions, and an action that contradicts the entry kind are withheld as
// ambiguous. A flag candidate has Component "unknown": a changelog entry does
// not name its binary.
//
// A values key candidate names a key path as the chart's changelog spells it;
// the reader cannot tell it from a similarly shaped word, so a reviewer must
// confirm it against the chart's values before any use.
package artifacthubchanges
