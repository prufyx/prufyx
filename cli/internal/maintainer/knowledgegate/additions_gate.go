// SPDX-License-Identifier: AGPL-3.0-only

package knowledgegate

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/prufyx/prufyx/cli/internal/maintainer/coveragereport"
)

// maxTagFiles bounds the tag files of one tree.
const maxTagFiles = 4096

// treeAdditions reads and validates the additions file of a tree. present is
// whether the path exists in the tree (an existing empty file is present).
// A path that exists but cannot be read as a regular file is an error.
func treeAdditions(t Tree) (file coveragereport.AdditionsFile, raw []byte, present bool, err error) {
	present = t.Exists(coveragereport.PinnedAdditionsPath)
	if present {
		raw, err = t.Read(coveragereport.PinnedAdditionsPath, MaxFileBytes)
		if err != nil {
			return file, nil, true, err
		}
	}
	file, err = coveragereport.ParseAdditions(raw)
	return file, raw, present, err
}

// additionsAllowedPaths are the paths of the additions mechanism a batch or
// onboarding change may carry: the additions file and, in the head's tags
// directory, the regular files named <slug>.tags. They are never in
// AutoMergePaths and never include the baseline file.
func additionsAllowedPaths(head Tree) map[string]bool {
	out := map[string]bool{coveragereport.PinnedAdditionsPath: true}
	files, err := head.Dir(coveragereport.PinnedTagsDir, MaxFileBytes, maxTagFiles)
	if err != nil {
		return out // unreadable: nothing of the directory is allowed; the floor check fails the change
	}
	for name := range files {
		if slug, ok := strings.CutSuffix(name, ".tags"); ok && coveragereport.ValidSlug(slug) {
			out[coveragereport.PinnedTagsDir+"/"+name] = true
		}
	}
	return out
}

// linesIntegrity holds what the published measure is measured against:
//  1. the pinned snapshot is byte-identical in base and head;
//  2. the additions file only grows: the head file exists when the base file
//     does, every base entry is in the head with a byte-identical value, no key
//     is removed or renamed; a base that has no file is the empty set (the
//     introducing change is a code change that a human reviews);
//  3. every head entry is valid, disjoint from the pinned snapshot and equals
//     the offline reading of its committed tag file, which is regenerated on
//     every run; a tag file that belongs to no entry is refused.
//
// Fail closed: an unreadable base or head file, an unparsable base file or any
// mismatch is an error.
func linesIntegrity(base, head Tree) error {
	baseLines, err := base.Read(coveragereport.PinnedLinesPath, MaxFileBytes)
	if err != nil {
		return fmt.Errorf("the base branch has no readable pinned lines snapshot: %w", err)
	}
	headLines, err := head.Read(coveragereport.PinnedLinesPath, MaxFileBytes)
	if err != nil {
		return fmt.Errorf("the change has no readable pinned lines snapshot: %w", err)
	}
	if !bytes.Equal(baseLines, headLines) {
		return fmt.Errorf("the pinned lines snapshot %s differs from the base branch; moving what is measured is a code change (a new pin), never a data change", coveragereport.PinnedLinesPath)
	}
	pinned, err := coveragereport.ParseLines(headLines)
	if err != nil {
		return fmt.Errorf("the pinned lines snapshot is invalid: %w", err)
	}

	baseAdds, _, basePresent, err := treeAdditions(base)
	if err != nil {
		return fmt.Errorf("the base additions file is unreadable or invalid: %w", err)
	}
	headAdds, _, headPresent, err := treeAdditions(head)
	if err != nil {
		return fmt.Errorf("the change's additions file is unreadable or invalid: %w", err)
	}
	if basePresent && !headPresent {
		return fmt.Errorf("the change removes or renames the additions file %s of the base branch", coveragereport.PinnedAdditionsPath)
	}
	for slug, be := range baseAdds.Additions {
		he, ok := headAdds.Additions[slug]
		if !ok {
			return fmt.Errorf("the change removes or renames the added project %s", logSafe(slug))
		}
		// Semantic identity: both entries are validated and bound by their
		// digest, and compared by their canonical JSON; formatting of the file
		// around an entry may differ, no member of the entry may.
		bb, _ := json.Marshal(be)
		hb, _ := json.Marshal(he)
		if !bytes.Equal(bb, hb) {
			return fmt.Errorf("the change edits the added project %s; an added entry is immutable", logSafe(slug))
		}
	}
	if err := coveragereport.CheckDisjoint(pinned, headAdds); err != nil {
		return err
	}
	tags, err := head.Dir(coveragereport.PinnedTagsDir, MaxFileBytes, maxTagFiles)
	if err != nil {
		return fmt.Errorf("the tag files are unreadable: %w", err)
	}
	slugs := make([]string, 0, len(headAdds.Additions))
	for slug := range headAdds.Additions {
		slugs = append(slugs, slug)
	}
	sort.Strings(slugs)
	for _, slug := range slugs {
		raw, ok := tags[coveragereport.TagFileName(slug)]
		if !ok {
			return fmt.Errorf("the added project %s has no tag file %s/%s", logSafe(slug), coveragereport.PinnedTagsDir, coveragereport.TagFileName(slug))
		}
		if err := coveragereport.VerifyAdditionFromTags(slug, headAdds.Additions[slug], raw); err != nil {
			return err
		}
	}
	for name := range tags {
		slug, ok := strings.CutSuffix(name, ".tags")
		if _, has := headAdds.Additions[slug]; !ok || !has {
			return fmt.Errorf("the tag file %s belongs to no added project", logSafe(name))
		}
	}
	return nil
}

// additionsNotFuture refuses an addition captured after the gate's clock.
func additionsNotFuture(head Tree, now time.Time) error {
	adds, _, _, err := treeAdditions(head)
	if err != nil {
		return fmt.Errorf("the change's additions file is unreadable or invalid: %w", err)
	}
	if now.IsZero() {
		return errors.New("the gate has no clock to bound the additions' capture dates with")
	}
	today := now.UTC().Format("2006-01-02")
	for slug, e := range adds.Additions {
		if e.CapturedOn > today {
			return fmt.Errorf("the added project %s is captured on %s, after the gate's date %s", logSafe(slug), e.CapturedOn, today)
		}
	}
	return nil
}

// attestationsNotFuture refuses a head whose newest line attestation
// (derivedAt or reviewedAt, CNCF or community pack) is later than the gate's
// clock: the evaluation clock of the tree follows its attestations
// (EvaluationClockFromPack), so an attestation stamped in the future must not
// make itself current. The bound has no tolerance: the factory stamps the
// derivation before the gate observes the change. A zero gate clock refuses:
// this bound never falls back to the host's wall clock. Unreadable
// attestations fail.
func attestationsNotFuture(head Tree, now time.Time) error {
	if now.IsZero() {
		return errors.New("the gate has no clock to bound the line attestation times with")
	}
	pack, err := head.Read(cncfRulesPath, MaxFileBytes)
	if err != nil {
		return fmt.Errorf("the change's rule pack is unreadable: %w", err)
	}
	community, err := head.Read(commRulesPath, MaxFileBytes)
	if err != nil {
		return fmt.Errorf("the change's community rule pack is unreadable: %w", err)
	}
	newest, ok, err := coveragereport.NewestAttestationTime(pack, community)
	if err != nil {
		return fmt.Errorf("the change's line attestations are unreadable or invalid: %w", err)
	}
	if ok && newest.After(now) {
		return fmt.Errorf("a line attestation is dated %s, after the gate's clock %s", newest.UTC().Format(time.RFC3339), now.UTC().Format(time.RFC3339))
	}
	return nil
}
