// SPDX-License-Identifier: AGPL-3.0-only

package knowledgegate

import (
	"encoding/json"
	"fmt"
	"sort"

	"github.com/prufyx/prufyx/cli/internal/maintainer/evidencereattest"
	"github.com/prufyx/prufyx/cli/internal/maintainer/evidencerepin"
)

// movedBlobsDir is the directory under a pack's reattestation directory that
// retains the old and new file of every span move a statement renews, content
// addressed (evidencereattest.LoadMovedBlobs).
const movedBlobsDir = "/moved-blobs"

// movedSourceFields are the members of a source a moved citation changes.
var movedSourceFields = []string{"revision", "url", "contentDigest", "startLine", "endLine"}

func intOf(v any) (int, bool) {
	switch n := v.(type) {
	case json.Number:
		i, err := n.Int64()
		return int(i), err == nil
	case float64:
		return int(n), n == float64(int(n))
	case int:
		return n, true
	}
	return 0, false
}

// movedRenewalProblem is the renewal class of a moved citation: a rule whose
// sources changed is admitted by a verified statement only when every
// differing source is the one a moved row of that statement lists, with the
// old and the new range and both digests the row states, the new commit and
// url the row's commit and path derive, and nothing else in the source
// different; a source with no row stays untouched, and nothing but the
// evidence dates and the sources differs. It returns "" when the rule's
// changes are exactly that (or it has no moved row and its sources are
// unchanged), and the reason otherwise: any other change of a source is a
// loosening that needs an owner approval.
func movedRenewalProblem(c *Change, statement evidencereattest.Statement) string {
	if c.base == nil || c.head == nil {
		return ""
	}
	var row *evidencereattest.RuleAttestation
	for i := range statement.Rules {
		if statement.Rules[i].RuleID == c.RuleID {
			row = &statement.Rules[i]
		}
	}
	moved := map[string]evidencereattest.CitationAttestation{}
	if row != nil {
		for _, citation := range row.Citations {
			if citation.Moved != nil {
				moved[citation.SourceID] = citation
			}
		}
	}
	if len(moved) > 0 && statement.SignerRole != evidencereattest.RoleHuman {
		return "a moved citation is renewed by a human statement only"
	}
	sourcesSame := sameAt(c.base.generic, c.head.generic, "rule", "evidence", "sources")
	if sourcesSame && len(moved) == 0 {
		return ""
	}
	for _, kind := range c.Kinds {
		if kind != KindRenew && kind != KindRepin {
			return fmt.Sprintf("a moved-citation renewal changes nothing but the cited places and the evidence dates (%s)", kind)
		}
	}
	baseRaw, bok := lookup(c.base.generic, "rule", "evidence", "sources")
	headRaw, hok := lookup(c.head.generic, "rule", "evidence", "sources")
	baseSources, bok2 := baseRaw.([]any)
	headSources, hok2 := headRaw.([]any)
	if !bok || !hok || !bok2 || !hok2 || len(baseSources) != len(headSources) {
		return "the sources of the rule changed in number or shape"
	}
	seen := map[string]bool{}
	for i := range baseSources {
		b, bm := baseSources[i].(map[string]any)
		h, hm := headSources[i].(map[string]any)
		if !bm || !hm {
			return "a source of the rule is not an object"
		}
		id, _ := b["id"].(string)
		if hid, _ := h["id"].(string); hid != id || id == "" {
			return "a source of the rule changed its id or order"
		}
		citation, isMoved := moved[id]
		if string(canonicalOf(b)) == string(canonicalOf(h)) {
			if isMoved {
				return fmt.Sprintf("the statement lists a move of source %s, which did not change", id)
			}
			continue
		}
		if !isMoved {
			return fmt.Sprintf("source %s changed but no moved row of the verified statement lists it", id)
		}
		seen[id] = true
		m := citation.Moved
		oldStart, ok1 := intOf(b["startLine"])
		oldEnd, ok2 := intOf(b["endLine"])
		newStart, ok3 := intOf(h["startLine"])
		newEnd, ok4 := intOf(h["endLine"])
		oldURL, _ := b["url"].(string)
		newURL, _ := h["url"].(string)
		owner, repo, _, path, parsed := evidencerepin.ParseCitationURL(oldURL)
		wantURL, urlOK := evidencerepin.MovedURL(oldURL, owner, repo, citation.ComparedCommit, path)
		if !ok1 || !ok2 || !ok3 || !ok4 || !parsed || !urlOK ||
			oldStart != m.OldStartLine || oldEnd != m.OldEndLine || newStart != m.NewStartLine || newEnd != m.NewEndLine ||
			b["contentDigest"] != m.OldContentDigest || h["contentDigest"] != m.NewContentDigest ||
			path != m.Path || h["revision"] != citation.ComparedCommit || newURL != wantURL || oldEnd-oldStart != newEnd-newStart {
			return fmt.Sprintf("source %s does not change the way its moved row states", id)
		}
		rest, restBase := deepCopy(h).(map[string]any), deepCopy(b).(map[string]any)
		for _, field := range movedSourceFields {
			delete(rest, field)
			delete(restBase, field)
		}
		if string(canonicalOf(rest)) != string(canonicalOf(restBase)) {
			return fmt.Sprintf("source %s changed outside the cited place", id)
		}
	}
	if len(seen) != len(moved) {
		ids := make([]string, 0, len(moved))
		for id := range moved {
			if !seen[id] {
				ids = append(ids, id)
			}
		}
		sort.Strings(ids)
		return fmt.Sprintf("the statement lists a move of %v that the pack does not make", ids)
	}
	return ""
}
