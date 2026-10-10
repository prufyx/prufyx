// SPDX-License-Identifier: AGPL-3.0-only

package knowledgegate

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"unicode/utf8"
)

// The review summary of a batch: Markdown rendered from the canonical
// entries, the classification and the sample only (no clock, no model, no
// text the change supplies outside the packs), so the gate can render it
// again and compare its digest with the one the owner signed. Every
// character outside printable ASCII is escaped, so a pack string cannot hide
// text from the reader with control or bidirectional characters.

// batchFlaggedKinds are reviewed edits always shown in full, whether or not
// the sample draws them. KindModify is among them: "anything else in the
// entry changed" (match, message, fix, severity of an existing reviewed rule)
// is the most open-ended kind, and the sample alone may not draw it.
var batchFlaggedKinds = map[string]bool{KindReactivate: true, KindBasis: true, KindWiden: true, KindNarrow: true, KindRangeChange: true, KindModify: true}

// batchOtherRows bounds the rows of the "Other changes" table. Beyond it the
// summary gives counts only (the change-set digest still binds every change),
// so a change padded with tightening or mechanical changes cannot push the
// entries out of the owner's view.
const batchOtherRows = 100

// flaggedChange reports whether a change has a kind always shown in full.
func flaggedChange(c *Change) bool {
	for _, k := range c.Kinds {
		if batchFlaggedKinds[k] {
			return true
		}
	}
	return false
}

// flaggedIndexes are the numbers of the entries of rec the summary shows in
// full because of their kind, whether or not the sample draws them.
func (st *batchState) flaggedIndexes(rec BatchRecord) []int {
	byKey := map[string]*Change{}
	for _, it := range st.items {
		byKey[it.entry.key()] = it.change
	}
	var out []int
	for i, e := range rec.Entries {
		if c := byKey[e.key()]; c != nil && flaggedChange(c) {
			out = append(out, i)
		}
	}
	return out
}

// othersCount is the number of changes the batch does not approve.
func othersCount(st *batchState, rec BatchRecord) int {
	return len(st.others(rec))
}

// others are the changes of the change the batch does not approve:
// tightening and mechanical changes, and pack member changes.
func (st *batchState) others(rec BatchRecord) []*Change {
	inBatch := map[string]bool{}
	for _, e := range rec.Entries {
		inBatch[e.key()] = true
	}
	var out []*Change
	for _, c := range st.cls.Changes {
		if c.Member != "" || !inBatch[batchKey(c.Pack, changeSubject(c), c.RuleID)] {
			out = append(out, c)
		}
	}
	return out
}

// termSafe escapes everything but printable ASCII and line breaks.
func termSafe(s string) string {
	var b strings.Builder
	for i, r := range s {
		switch {
		case r == '\n' || (r >= 0x20 && r < 0x7f):
			b.WriteRune(r)
		case r == utf8.RuneError && !strings.HasPrefix(s[i:], "�"):
			b.WriteString(`\x{invalid}`)
		default:
			fmt.Fprintf(&b, `\u{%04X}`, r)
		}
	}
	return b.String()
}

// cell makes a value safe for one Markdown table cell.
func cell(s string) string {
	s = termSafe(s)
	s = strings.ReplaceAll(s, "|", `\|`)
	return strings.ReplaceAll(s, "\n", " ")
}

func shortDigest(d string) string {
	if strings.HasPrefix(d, "sha256:") && len(d) >= 19 {
		return d[7:19]
	}
	return d
}

// entryJSON is a canonical entry or record as it is read (canonical JSON
// is already indented); nil is "(none)".
func entryJSON(raw []byte) string {
	if raw == nil {
		return "(none)"
	}
	return strings.TrimSuffix(string(raw), "\n")
}

// sourceURLs lists the URLs of an entry's cited sources.
func sourceURLs(c *Change) []string {
	var list []struct {
		URL string `json:"url"`
	}
	if err := json.Unmarshal(itemSources(c), &list); err != nil {
		return nil
	}
	var out []string
	for _, s := range list {
		out = append(out, s.URL)
	}
	return out
}

func sortedKeys(m map[string]int) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// summary renders the review summary of rec (its core and sample) for this
// state.
func (st *batchState) summary(rec BatchRecord) string {
	var b strings.Builder
	w := func(format string, args ...any) { fmt.Fprintf(&b, format, args...) }
	sampled := map[int]bool{}
	for _, i := range rec.Sample {
		sampled[i] = true
	}
	byKey := map[string]*Change{}
	for _, it := range st.items {
		byKey[it.entry.key()] = it.change
	}
	others := st.others(rec)
	w("# Batch approval %s\n\n", cell(rec.BatchID))
	w("Candidate: %s. Entries: %d (at most %d). Sample read in full: %d. Other changes not approved by this batch: %d. Nonce: %s.\n\n", cell(rec.CandidateID), len(rec.Entries), MaxBatchEntries, len(rec.Sample), len(others), cell(rec.Nonce))
	w("Every entry below becomes knowledge with basis reviewed. Read the sampled and flagged entries in full; refuse the batch if any of them is wrong.\n\n")
	w("| Pack | Base file | Head file |\n| --- | --- | --- |\n")
	for _, p := range rec.Packs {
		w("| %s | %s | %s |\n", cell(p.Pack), cell(p.Base), cell(p.Head))
	}
	w("\nChange set: %s. Citations: %s.\n\n", cell(rec.ChangeSetDigest), cell(rec.CitationsDigest))

	kinds := map[string]int{}
	for _, e := range rec.Entries {
		if c := byKey[e.key()]; c != nil {
			for _, k := range c.Kinds {
				kinds[k]++
			}
		}
	}
	w("## Entries (%d)\n\n", len(rec.Entries))
	if len(kinds) > 0 {
		var parts []string
		for _, k := range []string{KindNew, KindRenew, KindRepin, KindReactivate, KindBasis, KindWiden, KindNarrow, KindRangeChange, KindModify} {
			if kinds[k] > 0 {
				parts = append(parts, fmt.Sprintf("%s %d", k, kinds[k]))
			}
		}
		w("By kind: %s.\n\n", strings.Join(parts, ", "))
	}
	w("| # | Pack | Subject | ID | Project | Kinds | Base | Candidate | Sources | Read |\n| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |\n")
	var full []int
	for i, e := range rec.Entries {
		c := byKey[e.key()]
		project, kindList, sources := "", "", ""
		flagged := false
		if c != nil {
			project, kindList = c.Project, strings.Join(c.Kinds, ", ")
			flagged = flaggedChange(c)
			urls := sourceURLs(c)
			if len(urls) > 0 {
				sources = fmt.Sprintf("%d: %s", len(urls), urls[0])
			}
		}
		read := ""
		switch {
		case sampled[i] && flagged:
			read = "sample, flagged"
		case sampled[i]:
			read = "sample"
		case flagged:
			read = "flagged"
		}
		if read != "" {
			full = append(full, i)
		}
		w("| %d | %s | %s | %s | %s | %s | %s | %s | %s | %s |\n", i, cell(e.Pack), cell(e.Subject), cell(e.ID), cell(project), cell(kindList), cell(shortDigest(e.BaseDigest)), cell(shortDigest(e.CandidateDigest)), cell(sources), read)
	}

	w("\n## Other changes in this change (%d)\n\n", len(others))
	if len(others) > 0 {
		counts := map[string]int{}
		for _, c := range others {
			key := c.Class
			if c.Member != "" {
				key = "pack member"
			}
			counts[key]++
		}
		var parts []string
		for _, k := range sortedKeys(counts) {
			parts = append(parts, fmt.Sprintf("%s %d", k, counts[k]))
		}
		w("By class: %s.\n\n", cell(strings.Join(parts, ", ")))
		w("Not approved by this batch: tightening changes need no approval, mechanical changes are re-derived by the gate.\n\n")
		shown := others
		if len(shown) > batchOtherRows {
			shown = shown[:batchOtherRows]
		}
		w("| Pack | Section | ID | Class | Kinds | Basis |\n| --- | --- | --- | --- | --- | --- |\n")
		for _, c := range shown {
			id := c.RuleID
			if c.Member != "" {
				id = "member " + c.Member
			}
			section := c.Section
			if section == "" {
				section = "entries"
			}
			w("| %s | %s | %s | %s | %s | %s |\n", cell(c.Pack), cell(section), cell(id), cell(c.Class), cell(strings.Join(c.Kinds, ", ")), cell(c.Basis))
		}
		if len(others) > len(shown) {
			w("\n%d more changes are not listed (the first %d are); the change-set digest binds all of them.\n", len(others)-len(shown), len(shown))
		}
	}

	w("\n## Entries to read in full (%d)\n", len(full))
	for _, i := range full {
		e := rec.Entries[i]
		c := byKey[e.key()]
		w("\n### #%d %s %s/%s\n\n", i, cell(e.Subject), cell(e.Pack), cell(e.ID))
		if c == nil {
			w("Not changed by this change.\n")
			continue
		}
		base, head := c.canonicalSides()
		w("Kinds: %s. Project: %s.\n\nBase:\n\n```json\n%s\n```\n\nProposed:\n\n```json\n%s\n```\n", cell(strings.Join(c.Kinds, ", ")), cell(c.Project), termSafe(entryJSON(base)), termSafe(entryJSON(head)))
	}
	return b.String()
}
