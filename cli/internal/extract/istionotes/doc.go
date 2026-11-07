// SPDX-License-Identifier: AGPL-3.0-only

// Package istionotes reads the release note fragments of Istio
// (releasenotes/notes/*.yaml) at one pinned commit and proposes DRAFT
// candidates: flags, CRD fields and CRD kinds that the notes call removed or
// deprecated.
//
// A fragment is human prose with a few structured fields. It is structured
// intent, not a derivation: nothing here can be re-derived by the gate and
// nothing here is mechanical. Every candidate therefore carries the evidence
// basis "draft" and NeedsReview; it is a lead for a reviewer, never a rule,
// and it can never authorise a pass. The package is inert: it registers
// nothing, writes nothing and is not wired into the extract runner, the rule
// data or the factory.
//
// Method. Only the releaseNotes and upgradeNotes fields are read. A fragment
// is decoded with a strict, closed YAML shape (unknown fields, duplicate
// keys, aliases, anchors, explicit tags and extra documents are refused). A
// text becomes candidates only when it carries exactly one action signal
// (removed or deprecated, from its words or from the note kind) and every
// backticked token in it is a long flag, a kind of the reviewed table or a
// field of such a kind. Anything else, including a text that mixes actions,
// names a replacement, quotes a code block or names nothing, is a ledger
// entry and no candidate. A non-empty ledger means the result is incomplete.
//
// Limits are fixed (see the Max constants). There is no network access and
// no execution: bytes come only through extract.PinnedReader.
package istionotes
