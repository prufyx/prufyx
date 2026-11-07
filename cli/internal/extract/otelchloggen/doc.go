// SPDX-License-Identifier: AGPL-3.0-only

// Package otelchloggen reads the changelog fragments of OpenTelemetry
// (.chloggen/*.yaml) at one pinned commit and proposes DRAFT candidates:
// command line flags and component config keys that a fragment calls removed
// or deprecated.
//
// A fragment is human prose with a few structured fields (change_type,
// component, note, issues, subtext). It is structured intent, not a
// derivation: nothing here can be re-derived by the gate and nothing here is a
// derived fact. Every candidate therefore carries the evidence basis "draft"
// and NeedsReview; it is a lead for a reviewer, never a rule, and it can never
// authorise a pass. The package is inert: it registers nothing, writes nothing
// and is not wired into the extract runner, the rule data or the factory.
//
// change_logs is accepted from a closed set (user, api) and otherwise ignored.
//
// Method. A fragment is decoded with a strict, closed YAML shape (unknown
// fields, duplicate keys, aliases, anchors, explicit tags and extra documents
// are refused). Only change_type breaking and deprecation can produce
// candidates; the other known types produce nothing and are not withheld. A
// deprecation fragment states "deprecated". A breaking fragment states
// "removed" when its text plainly says so, and otherwise "removed_or_changed":
// the fragment says the change breaks users, not how. The component field must
// be in knownComponents, a hand-written table; any other component is
// withheld. The note and the subtext are read as one text, and the text
// becomes candidates only when every backticked token in it is a long flag or
// a config key and the action verb stands next to each token. Anything else,
// including a text that names a replacement, a default or a feature gate,
// quotes a code block or names nothing, is a ledger entry and no candidate. A
// non-empty ledger means the result is incomplete.
//
// Modal, planned, conditional, negated or versioned prose ("may be removed",
// "planned for removal", "removal in 0.100", "will be removed in the next
// release") is withheld. A flag candidate has Component "unknown": a fragment
// does not name the binary that owns a flag.
//
// knownComponents is hand-written. When this reader is wired into anything, it
// must be cross-checked against the component list of the pinned tree first.
// The tool's own files in the same directory, TEMPLATE.yaml and config.yaml,
// are skipped by name.
//
// Bounds are fixed constants (files, fragment bytes, quote bytes, issues,
// candidates per fragment, candidates, ledger entries, nesting depth) and an
// input over any bound is withheld, never truncated. Output is deterministic:
// candidates and the ledger are sorted and free of duplicates. The ledger
// carries identifiers only, never fragment text. The code digest of an
// extractor built on this reader must cover SourceSet.
package otelchloggen
