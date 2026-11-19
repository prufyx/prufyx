// SPDX-License-Identifier: AGPL-3.0-only

package evidencereattest

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"

	"github.com/prufyx/prufyx/cli/internal/maintainer/evidencerepin"
	"github.com/prufyx/prufyx/cli/internal/maintainer/sourcecorpus"
)

// Moved-citation renewal (E1-moved). A rule whose citations are each
// unchanged, or whose cited bytes only moved to one new, guarded place (see
// evidencerepin.EvaluateMove), is renewed in a human statement without a hand
// re-review. The statement row of a moved citation carries the old and new
// place and both whole-file digests, and the renewed rule differs from the
// prior one in exactly those source fields (commit, lines, digest, url,
// revision) plus reviewedAt and validUntil. Every guard is recomputed by
// Prepare, and so by Verify, from the bytes of the two files. A moved rule is
// always in the review sample and counts against the consecutive-cycle cap
// like any other renewal. Automated mode never renews one.

const (
	reasonMovedNotAutomatable = "MOVED_NOT_AUTOMATABLE"
	reasonMovedNotPinnable    = "MOVED_NOT_PINNABLE"
	reasonMovedUnverified     = "MOVED_UNVERIFIED"

	// MaxMovedBlobBytes bounds one retained file of a move; MaxMovedBlobs
	// bounds how many a run may carry.
	MaxMovedBlobBytes = 8 << 20
	MaxMovedBlobs     = 4096
)

// MovedStatementText is the exact text a human signs for a statement with at
// least one moved citation. Like FixedStatementText it is never free-form.
func MovedStatementText(generatedAt, validUntil string) string {
	return "I ran `evidence repin` at `" + generatedAt + "` with no reused state. " +
		"Every listed citation was mechanically classified NO_NEW_RELEASE, FILE_IDENTICAL, SPAN_IDENTICAL or SPAN_MOVED " +
		"against the listed upstream commit. A SPAN_MOVED citation is listed with its old and new place and both file " +
		"digests: its cited bytes are the single occurrence of the same bytes at the new place of the same file, with " +
		"the same surrounding lines. I reviewed the listed upstream releases for errata affecting the listed rules and " +
		"found none. I fully re-reviewed the sampled rules, which include every rule with a moved citation. No rule " +
		"content other than reviewedAt, validUntil and the listed citation places (commit, lines, digest, url, " +
		"revision) changes. This renews the maintainer review lease for these rules until `" + validUntil + "`. " +
		"It is not a new compatibility claim."
}

// MovedAttestation is the row of a moved citation: where the cited bytes were
// and where they are, with both whole-file digests.
type MovedAttestation struct {
	Path             string `json:"path"`
	OldStartLine     int    `json:"oldStartLine"`
	OldEndLine       int    `json:"oldEndLine"`
	NewStartLine     int    `json:"newStartLine"`
	NewEndLine       int    `json:"newEndLine"`
	OldContentDigest string `json:"oldContentDigest"`
	NewContentDigest string `json:"newContentDigest"`
}

// statementMoves reports whether any row of statement carries a moved citation.
func statementMoves(statement Statement) bool {
	for _, ra := range statement.Rules {
		for _, c := range ra.Citations {
			if c.Moved != nil {
				return true
			}
		}
	}
	return false
}

// checkRowMoves holds the moved column of a statement's citations to its
// contract; it is part of ParseStatement. A moved row exists exactly for a
// SPAN_MOVED citation, only in a human v2 statement that does not pin, on a
// release line baseline, and says a move of one span to a different place.
func checkRowMoves(statement Statement, role string) error {
	moves := false
	for _, ra := range statement.Rules {
		for _, c := range ra.Citations {
			if (c.Class == evidencerepin.ClassSpanMoved) != (c.Moved != nil) {
				return fmt.Errorf("%w: a SPAN_MOVED citation carries exactly one moved row", ErrRejected)
			}
			if c.Moved == nil {
				continue
			}
			moves = true
			m := c.Moved
			if !isLineBaseline(c.Baseline) || c.BaselineLine == "" || c.PinnedTag == "" || c.ComparedCommit == "" || c.ComparedCommit == c.PinnedCommit ||
				m.Path == "" || m.OldStartLine < 1 || m.NewStartLine < 1 || m.OldEndLine < m.OldStartLine || m.NewEndLine < m.NewStartLine ||
				m.OldEndLine-m.OldStartLine != m.NewEndLine-m.NewStartLine || m.OldStartLine == m.NewStartLine ||
				!validDigest(m.OldContentDigest) || !validDigest(m.NewContentDigest) || m.OldContentDigest == m.NewContentDigest ||
				m.OldContentDigest != c.ContentDigest {
				return fmt.Errorf("%w: moved row", ErrRejected)
			}
		}
	}
	if !moves {
		return nil
	}
	if role != RoleHuman || statement.Schema != StatementSchema || statementPins(statement) {
		return fmt.Errorf("%w: a moved citation belongs to a human statement that does not pin", ErrRejected)
	}
	return nil
}

// sourceMove is the new location of one source of a rule.
type sourceMove struct {
	commit, url, digest string
	start, end          int
}

// applySourceMoves rewrites, in a rule's generically decoded evidence, the
// location fields of the listed sources: revision, url, contentDigest,
// startLine and endLine. Every other member of every source is left alone.
func applySourceMoves(evidence map[string]any, moves map[string]sourceMove) error {
	sources, ok := evidence["sources"].([]any)
	if !ok {
		return fmt.Errorf("%w: mutate rule sources", ErrRejected)
	}
	done := map[string]bool{}
	for _, entry := range sources {
		source, ok := entry.(map[string]any)
		if !ok {
			return fmt.Errorf("%w: mutate rule sources", ErrRejected)
		}
		id, _ := source["id"].(string)
		move, moved := moves[id]
		if !moved {
			continue
		}
		source["revision"] = move.commit
		source["url"] = move.url
		source["contentDigest"] = move.digest
		source["startLine"] = json.Number(strconv.Itoa(move.start))
		source["endLine"] = json.Number(strconv.Itoa(move.end))
		done[id] = true
	}
	if len(done) != len(moves) {
		return fmt.Errorf("%w: a moved source is not in the rule", ErrRejected)
	}
	return nil
}

// movedSource finds the source of a rule by ID.
func movedSource(candidate ruleCandidate, sourceID string) (ruleSourceField, bool) {
	for _, source := range candidate.Fields.Evidence.Sources {
		if source.ID == sourceID {
			return source, true
		}
	}
	return ruleSourceField{}, false
}

// movedCitationReason says why a SPAN_MOVED citation does not make its rule
// eligible, or "" when every guard recomputes: the recorded move exists, names
// the compared commit, the citation's own path and the cited length, the
// citation sits on the head of its release line, the order of the rule's cited
// spans of the file is kept, and the move recomputes from the bytes of the old
// file (whose digest the pack records) and of the new file (whose digest the
// worklist records). A citation without a recorded move keeps the plain class
// as its reason, as before.
func movedCitationReason(candidate ruleCandidate, citation evidencerepin.ClassResult, source ruleSourceField, automated, pin bool, blobs map[string][]byte) string {
	moved := citation.MovedTo
	if moved == nil {
		return evidencerepin.ClassSpanMoved
	}
	if automated {
		return reasonMovedNotAutomatable
	}
	if pin {
		return reasonMovedNotPinnable
	}
	owner, repo, _, path, ok := evidencerepin.ParseCitationURL(source.URL)
	if !ok || owner != citation.Owner || repo != citation.Repo || path != citation.Path || moved.Path != path {
		return reasonMovedUnverified
	}
	if citation.OldStart != source.StartLine || citation.OldEnd != source.EndLine ||
		moved.Commit == "" || moved.Commit != citation.NewCommit || moved.StartLine != citation.NewStart || moved.EndLine != citation.NewEnd ||
		moved.EndLine-moved.StartLine != source.EndLine-source.StartLine {
		return reasonMovedUnverified
	}
	if !evidencerepin.MoveBaselineOK(citation) || !evidencerepin.MoveOrderPreserved(candidate.Citations, citation) {
		return reasonMovedUnverified
	}
	oldData, newData := blobs[source.ContentDigest], blobs[moved.ContentDigest]
	if oldData == nil || newData == nil || sourcecorpus.SHA(oldData) != source.ContentDigest || sourcecorpus.SHA(newData) != moved.ContentDigest {
		return reasonMovedUnverified
	}
	if reason := evidencerepin.VerifyMovedTo(oldData, source.StartLine, source.EndLine, newData, citation.NewCommit, path, *moved); reason != "" {
		return reasonMovedUnverified
	}
	return ""
}

// movesFor lists the source moves of a rule's eligible citations.
func movesFor(candidate ruleCandidate, citations []evidencerepin.ClassResult) (map[string]sourceMove, error) {
	moves := map[string]sourceMove{}
	for _, c := range citations {
		if c.Class != evidencerepin.ClassSpanMoved {
			continue
		}
		source, ok := movedSource(candidate, c.SourceID)
		if !ok || c.MovedTo == nil {
			return nil, fmt.Errorf("%w: rule %s moved citation %s", ErrRejected, candidate.RuleID, c.SourceID)
		}
		url, ok := evidencerepin.MovedURL(source.URL, c.Owner, c.Repo, c.MovedTo.Commit, c.MovedTo.Path)
		if !ok {
			return nil, fmt.Errorf("%w: rule %s moved citation %s url", ErrRejected, candidate.RuleID, c.SourceID)
		}
		moves[c.SourceID] = sourceMove{commit: c.MovedTo.Commit, url: url, digest: c.MovedTo.ContentDigest, start: c.MovedTo.StartLine, end: c.MovedTo.EndLine}
	}
	return moves, nil
}

// movedAttestation renders the row of a moved citation.
func movedAttestation(c evidencerepin.ClassResult, oldDigest string) *MovedAttestation {
	if c.Class != evidencerepin.ClassSpanMoved || c.MovedTo == nil {
		return nil
	}
	return &MovedAttestation{
		Path: c.MovedTo.Path, OldStartLine: c.OldStart, OldEndLine: c.OldEnd, NewStartLine: c.MovedTo.StartLine, NewEndLine: c.MovedTo.EndLine,
		OldContentDigest: oldDigest, NewContentDigest: c.MovedTo.ContentDigest,
	}
}

// ruleMoves is the sorted source IDs of a statement row's moved citations.
func ruleMoves(ra RuleAttestation) []string {
	var ids []string
	for _, c := range ra.Citations {
		if c.Moved != nil {
			ids = append(ids, c.SourceID)
		}
	}
	sort.Strings(ids)
	return ids
}

// checkMovedRewrite (V13) holds a moved rule to its contract independently of
// the recomputation: next differs from prior in exactly the location fields
// of the moved sources the row lists (with url and revision derived from the
// compared commit and path) and the evidence dates; every other byte of the
// rule is the same, and a source the row does not list is untouched.
func checkMovedRewrite(ra RuleAttestation, priorRaw, nextRaw json.RawMessage, candidate ruleCandidate) error {
	moves := map[string]sourceMove{}
	for _, c := range ra.Citations {
		if c.Moved == nil {
			continue
		}
		source, ok := movedSource(candidate, c.SourceID)
		if !ok {
			return fmt.Errorf("%w: V13: rule %s moved source %s is not in the prior rule", ErrRejected, ra.RuleID, c.SourceID)
		}
		owner, repo, _, path, ok := evidencerepin.ParseCitationURL(source.URL)
		if !ok || path != c.Moved.Path {
			return fmt.Errorf("%w: V13: rule %s moved source %s changes its path", ErrRejected, ra.RuleID, c.SourceID)
		}
		url, ok := evidencerepin.MovedURL(source.URL, owner, repo, c.ComparedCommit, path)
		if !ok {
			return fmt.Errorf("%w: V13: rule %s moved source %s url", ErrRejected, ra.RuleID, c.SourceID)
		}
		moves[c.SourceID] = sourceMove{commit: c.ComparedCommit, url: url, digest: c.Moved.NewContentDigest, start: c.Moved.NewStartLine, end: c.Moved.NewEndLine}
	}
	nextFields, err := parseRuleFields(nextRaw)
	if err != nil {
		return err
	}
	want, err := mutateRuleEvidenceMoves(priorRaw, nextFields.Evidence.ReviewedAt, nextFields.Evidence.ValidUntil, nextFields.Evidence.Lease, moves)
	if err != nil {
		return err
	}
	a, err := sourcecorpus.DecodeBounded(want, int64(len(want)))
	if err != nil {
		return fmt.Errorf("%w: V13: rule %s", ErrRejected, ra.RuleID)
	}
	b, err := sourcecorpus.DecodeBounded(nextRaw, int64(len(nextRaw)))
	if err != nil {
		return fmt.Errorf("%w: V13: rule %s", ErrRejected, ra.RuleID)
	}
	canonA, errA := sourcecorpus.Canonical(a)
	canonB, errB := sourcecorpus.Canonical(b)
	if errA != nil || errB != nil || string(canonA) != string(canonB) {
		return fmt.Errorf("%w: V13: rule %s changed outside the moved citation fields and the evidence dates", ErrRejected, ra.RuleID)
	}
	return nil
}

// checkMoved (V13) is the statement-level moved checks that need the packs and
// the independent worklist: a moved statement is accepted only with an
// independent worklist, which must carry the same recorded move for every
// moved citation; every rule with a moved row is in the sample; and every
// moved rule's next record is the prior one with only the listed fields
// changed. The per-citation guards themselves are recomputed by the
// recomputation (checkV1AndV3) from the retained files.
func checkMoved(statement Statement, packPath string, priorByID, nextByID map[string]json.RawMessage, priorCandidates map[string]ruleCandidate, independentRaw []byte) error {
	if !statementMoves(statement) {
		return nil
	}
	if len(independentRaw) == 0 {
		return fmt.Errorf("%w: V13: the statement renews moved citations; an independent worklist is required", ErrRejected)
	}
	var wl evidencerepin.Worklist
	if err := json.Unmarshal(independentRaw, &wl); err != nil || wl.Schema != evidencerepin.Schema {
		return fmt.Errorf("%w: V13: independent worklist does not decode", ErrRejected)
	}
	sampled := map[string]bool{}
	for _, entry := range statement.SampledForFullReview {
		sampled[entry.RuleID] = true
	}
	for _, ra := range statement.Rules {
		ids := ruleMoves(ra)
		if len(ids) == 0 {
			continue
		}
		if !sampled[ra.RuleID] {
			return fmt.Errorf("%w: V13: rule %s has a moved citation and is not in the review sample", ErrRejected, ra.RuleID)
		}
		for _, c := range ra.Citations {
			if c.Moved == nil {
				continue
			}
			var got *evidencerepin.ClassResult
			for i := range wl.Citations {
				w := &wl.Citations[i]
				if matchesPack(w.RulePack, packPath) && w.RuleID == ra.RuleID && w.SourceID == c.SourceID {
					if got != nil {
						return fmt.Errorf("%w: V13: rule %s citation %s is listed twice in the independent worklist", ErrRejected, ra.RuleID, c.SourceID)
					}
					got = w
				}
			}
			m := c.Moved
			if got == nil || got.Class != evidencerepin.ClassSpanMoved || got.MovedTo == nil ||
				got.MovedTo.Commit != c.ComparedCommit || got.MovedTo.Path != m.Path || got.MovedTo.StartLine != m.NewStartLine ||
				got.MovedTo.EndLine != m.NewEndLine || got.MovedTo.ContentDigest != m.NewContentDigest ||
				got.OldStart != m.OldStartLine || got.OldEnd != m.OldEndLine || !evidencerepin.MoveBaselineOK(*got) {
				return fmt.Errorf("%w: V13: rule %s moved citation %s is not the move the independent worklist records", ErrRejected, ra.RuleID, c.SourceID)
			}
		}
		prior, next := priorByID[ra.RuleID], nextByID[ra.RuleID]
		candidate, ok := priorCandidates[ra.RuleID]
		if !ok || prior == nil || next == nil {
			return fmt.Errorf("%w: V13: rule %s is not in both packs", ErrRejected, ra.RuleID)
		}
		if err := checkMovedRewrite(ra, prior, next, candidate); err != nil {
			return err
		}
	}
	return nil
}

// LoadMovedBlobs reads a directory of retained files, content-addressed: each
// regular file is keyed by the digest of its own bytes, whatever it is named,
// so a file's name carries no authority.
func LoadMovedBlobs(dir string) (map[string][]byte, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	if len(entries) > MaxMovedBlobs {
		return nil, fmt.Errorf("%w: too many moved blobs", ErrRejected)
	}
	out := map[string][]byte{}
	for _, entry := range entries {
		if !entry.Type().IsRegular() {
			return nil, fmt.Errorf("%w: moved blob %s is not a regular file", ErrRejected, entry.Name())
		}
		raw, err := os.ReadFile(filepath.Join(dir, entry.Name()))
		if err != nil {
			return nil, err
		}
		if len(raw) > MaxMovedBlobBytes {
			return nil, fmt.Errorf("%w: moved blob %s is too large", ErrRejected, entry.Name())
		}
		out[sourcecorpus.SHA(raw)] = raw
	}
	return out, nil
}

// MovedBlobsFromFiles keys files read elsewhere (a tree directory) by the
// digest of their bytes.
func MovedBlobsFromFiles(files map[string][]byte) (map[string][]byte, error) {
	if len(files) > MaxMovedBlobs {
		return nil, fmt.Errorf("%w: too many moved blobs", ErrRejected)
	}
	out := map[string][]byte{}
	for name, raw := range files {
		if len(raw) > MaxMovedBlobBytes {
			return nil, fmt.Errorf("%w: moved blob %s is too large", ErrRejected, name)
		}
		out[sourcecorpus.SHA(raw)] = raw
	}
	return out, nil
}
