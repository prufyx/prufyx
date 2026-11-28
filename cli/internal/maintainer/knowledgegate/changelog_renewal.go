// SPDX-License-Identifier: AGPL-3.0-only

package knowledgegate

import (
	"reflect"
	"time"

	"github.com/prufyx/prufyx/cli/internal/lineattest"
	"github.com/prufyx/prufyx/cli/internal/maintainer/changelogrenew"
)

// changelogRenewalPre refuses a change of an existing listed-entries record
// that re-derivation alone would admit but that is not a new derivation. It
// only ever refuses, and what passes it is still re-derived.
//
//   - the extractor id is the base record's;
//   - derivedAt is later than the base record's (moving validUntil under an
//     old derivation time is a date edit, not a renewal);
//   - at the same extractor build and with the same releases, the change is a
//     time-only renewal (changelogrenew.TimeOnly).
//
// A change of the releases or of the extractor build is new content and is
// decided by re-derivation, as before. changelogrenew.NewBuild is the renewal
// tool's rule and is deliberately not applied here: a real content change at a
// new build comes through this gate too.
func changelogRenewalPre(c *Change) error {
	if c.rbase == nil || c.rhead == nil || c.rhead.attestation == nil ||
		c.rhead.attestation.FactFamily != lineattest.FamilyChangelogListedEntries {
		return nil
	}
	refused := func(code, detail string) error {
		return &changelogrenew.Error{Code: code, Detail: detail}
	}
	b, h := c.rbase, c.rhead
	if b.attestation == nil {
		return refused(changelogrenew.CodeInput, "the base record is not a line attestation")
	}
	if b.Extractor == nil || h.Extractor == nil || b.Extractor.ID != h.Extractor.ID {
		return refused(changelogrenew.CodeOtherExtractor, "the record names another extractor than the base record")
	}
	old, err1 := time.Parse(time.RFC3339, b.DerivedAt)
	next, err2 := time.Parse(time.RFC3339, h.DerivedAt)
	if err1 != nil || err2 != nil || !next.After(old) {
		return refused(changelogrenew.CodeDerivationTime, "derivedAt is not later than the base record's: a date edit is not a renewal")
	}
	if *b.Extractor == *h.Extractor && reflect.DeepEqual(b.attestation.Releases, h.attestation.Releases) {
		return changelogrenew.TimeOnly(b.Canonical, h.Canonical)
	}
	return nil
}
