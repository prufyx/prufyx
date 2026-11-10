// SPDX-License-Identifier: AGPL-3.0-only

package knowledgegate

import (
	"bytes"
	"encoding/json"
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

// additionsPaths are the paths of the additions mechanism a change may carry
// under rec: only a v3 record that binds additions admits them, and then only
// the additions file and tags/<slug>.tags of the slugs it binds. A record
// without additions (v1, v2, a plain batch, no record) admits none, so a
// change that touches these paths without a record fails closed. They are
// never in AutoMergePaths and never include the baseline file.
func additionsPaths(rec OnboardingRecord) map[string]bool {
	out := map[string]bool{}
	if len(rec.adds) == 0 {
		return out
	}
	out[coveragereport.PinnedAdditionsPath] = true
	for slug := range rec.adds {
		out[coveragereport.PinnedTagsDir+"/"+coveragereport.TagFileName(slug)] = true
	}
	return out
}

// additionsProblems is the gate's check of the additions a v3 record binds
// (O9), all or nothing with the rest of the batch. For every bound slug (kind
// new only): the head tag file hashes to the record's tagFileSha256 and is a
// new file, the head entry carries the record's entryDigest and is the
// offline reading of that tag file. The entries the head adds to the
// additions file are exactly the bound slugs, and every base entry is
// unchanged. A record without additions has nothing to check here; its
// additions paths are refused by the path allow-list.
func (st *onboardingState) additionsProblems(rec OnboardingRecord) []string {
	if len(rec.adds) == 0 {
		return nil
	}
	var problems []string
	bad := func(format string, args ...any) { problems = append(problems, "O9: "+fmt.Sprintf(format, args...)) }
	baseAdds, _, _, err := treeAdditions(st.baseTree)
	if err != nil {
		bad("the base additions file is unreadable or invalid: %s", logSafe(err.Error()))
		return problems
	}
	headAdds, _, _, err := treeAdditions(st.headTree)
	if err != nil {
		bad("the change's additions file is unreadable or invalid: %s", logSafe(err.Error()))
		return problems
	}
	kinds := map[string]string{}
	for _, p := range rec.Projects {
		kinds[p.Slug] = p.Kind
	}
	slugs := make([]string, 0, len(rec.adds))
	for s := range rec.adds {
		slugs = append(slugs, s)
	}
	sort.Strings(slugs)
	for _, slug := range slugs {
		a := rec.adds[slug]
		if kinds[slug] != OnboardingKindNew || !coveragereport.ValidSlug(slug) {
			bad("%s: additions are bound only for a new project", logSafe(slug))
			continue
		}
		rel := coveragereport.PinnedTagsDir + "/" + coveragereport.TagFileName(slug)
		if st.baseTree.Exists(rel) {
			bad("%s: the tag file %s already exists in the base; a batch adds a new one", logSafe(slug), rel)
			continue
		}
		raw, err := st.headTree.Read(rel, MaxFileBytes)
		if err != nil {
			bad("%s: the tag file %s is unreadable: %s", logSafe(slug), rel, logSafe(err.Error()))
			continue
		}
		if coveragereport.TagFileDigest(raw) != a.TagFileSha256 {
			bad("%s: the tag file is not the one the batch was signed for", logSafe(slug))
			continue
		}
		if _, inBase := baseAdds.Additions[slug]; inBase {
			bad("%s: the project already has an additions entry in the base", logSafe(slug))
			continue
		}
		entry, ok := headAdds.Additions[slug]
		if !ok {
			bad("%s: the additions file has no entry for it", logSafe(slug))
			continue
		}
		if entry.EntryDigest != a.EntryDigest {
			bad("%s: the additions entry is not the one the batch was signed for", logSafe(slug))
			continue
		}
		if err := coveragereport.VerifyAdditionFromTags(slug, entry, raw); err != nil {
			bad("%s: %s", logSafe(slug), logSafe(err.Error()))
		}
	}
	for slug := range headAdds.Additions {
		if _, inBase := baseAdds.Additions[slug]; inBase {
			continue
		}
		if _, bound := rec.adds[slug]; !bound {
			bad("%s: the change adds an additions entry the batch does not bind", logSafe(slug))
		}
	}
	for slug, be := range baseAdds.Additions {
		he, ok := headAdds.Additions[slug]
		if !ok {
			bad("%s: the change removes an added project", logSafe(slug))
			continue
		}
		bb, _ := json.Marshal(be)
		hb, _ := json.Marshal(he)
		if !bytes.Equal(bb, hb) {
			bad("%s: the change edits an added project; an added entry is immutable", logSafe(slug))
		}
	}
	return problems
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
		now = time.Now()
	}
	today := now.UTC().Format("2006-01-02")
	for slug, e := range adds.Additions {
		if e.CapturedOn > today {
			return fmt.Errorf("the added project %s is captured on %s, after the gate's date %s", logSafe(slug), e.CapturedOn, today)
		}
	}
	return nil
}
