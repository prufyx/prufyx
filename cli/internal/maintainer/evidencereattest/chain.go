// SPDX-License-Identifier: AGPL-3.0-only

package evidencereattest

import (
	"bytes"
	"fmt"
	"sort"
	"time"

	"github.com/prufyx/prufyx/cli/internal/maintainer/evidencerepin"
	"github.com/prufyx/prufyx/cli/internal/maintainer/reviewrecord"
	"github.com/prufyx/prufyx/cli/internal/maintainer/sourcecorpus"
)

// ChainEntry is one previously produced statement in a pack's statement
// chain together with its detached signature envelope. Name is only used
// in error messages; it plays no part in ordering the chain or in comparing
// a chain against its base (see checkAppendOnly), which use the exact
// statement and envelope bytes.
type ChainEntry struct {
	Name      string
	Statement []byte
	Envelope  []byte
}

// Chain is one pack's signed, append-only statement log. Every entry must
// carry a valid signature under the pinned trust root (TrustRoot, pinned by
// ExpectedTrustRootDigest); an unsigned or badly signed entry rejects the
// whole chain rather than being skipped. Entries are ordered by their
// previousAttestationDigest links from a single genesis entry (nil
// previous) to a single head, never by name. The trust root pin is only
// required when the chain has at least one entry.
type Chain struct {
	Entries                 []ChainEntry
	TrustRoot               []byte
	ExpectedTrustRootDigest string
}

// chainState is what a verified chain establishes for the next statement:
// which digest the next statement must link to, and, per rule, how many
// batch renewals have happened since that rule's most recent recorded
// individual review.
type chainState struct {
	headDigest     *string
	headAttestedAt time.Time
	// batchSinceReview counts, per rule, the batch renewals recorded since
	// the most recent individual review recorded for it in the chain.
	batchSinceReview map[string]int
	// lastReviewAt is the lastIndividualReviewAt the chain carries for a
	// rule, once the rule has appeared in the chain.
	lastReviewAt map[string]string
	// recordedReviews holds, per rule, every review record digest the chain
	// has already recorded, so a record is never counted as a new review
	// twice.
	recordedReviews map[string]map[string]bool
	// entries holds, keyed by attestedAt (unique, because attestedAt
	// strictly increases along the chain), which rules each chain entry
	// renewed or recorded an individual review for, and the validUntil it
	// renewed them to (see checkPriorPackCovered).
	entries map[string]entryRecord
}

// entryRecord is what one chain entry did, as checkPriorPackCovered needs
// it: the validUntil it renewed each rule to, and the rules it recorded an
// individual review for. It is never modified after apply records it.
type entryRecord struct {
	renewed  map[string]string
	reviewed map[string]bool
}

func newChainState() chainState {
	return chainState{
		batchSinceReview: map[string]int{},
		lastReviewAt:     map[string]string{},
		recordedReviews:  map[string]map[string]bool{},
		entries:          map[string]entryRecord{},
	}
}

func (s chainState) clone() chainState {
	out := newChainState()
	if s.headDigest != nil {
		digest := *s.headDigest
		out.headDigest = &digest
	}
	out.headAttestedAt = s.headAttestedAt
	for k, v := range s.batchSinceReview {
		out.batchSinceReview[k] = v
	}
	for k, v := range s.lastReviewAt {
		out.lastReviewAt[k] = v
	}
	for k, v := range s.recordedReviews {
		set := map[string]bool{}
		for d := range v {
			set[d] = true
		}
		out.recordedReviews[k] = set
	}
	for k, v := range s.entries {
		out.entries[k] = v
	}
	return out
}

// expectedCycles is the consecutiveBatchCycles value a statement must
// record for ruleID when it renews it: 1 when the same statement records a
// new individual review for the rule, otherwise one more than the batch
// renewals the chain has recorded since the rule's last recorded review.
func (s chainState) expectedCycles(ruleID string, reviewedNow bool) int {
	if reviewedNow {
		return 1
	}
	return s.batchSinceReview[ruleID] + 1
}

// expectedLastReview is the lastIndividualReviewAt a statement must record
// for ruleID: its own attestedAt when it records a new individual review
// for the rule, otherwise the value the chain already carries for the
// rule, otherwise (the rule's first appearance in the chain) the rule's
// reviewedAt in the prior pack.
func (s chainState) expectedLastReview(ruleID string, reviewedNow bool, attestedAt, priorReviewedAt string) string {
	if reviewedNow {
		return attestedAt
	}
	if last, ok := s.lastReviewAt[ruleID]; ok {
		return last
	}
	return priorReviewedAt
}

// reviewsFromRecords decides which supplied individual review records are
// new individual reviews, keyed by rule ID, with the digest of the
// record's exact bytes. records maps a rule ID (the record file's name
// without its ".json" extension) to the record's bytes; rules holds every
// rule in the prior pack by ID.
//
// A record whose digest the chain already recorded for that rule is not a
// new review and is skipped. Every other record must be a structurally
// valid review record (maintainer/reviewrecord's format) that names the
// same rule and the same project, is bound to the exact version of the
// rule in the prior pack (its bindings.ruleDigest), and was decided after
// the rule's last individual review recorded in the chain and not after
// attestedAt. A record for a rule not in the pack, or one failing any of
// these checks, rejects the whole statement rather than being skipped:
// copying one rule's record under another rule's name, changing a byte of
// an already counted record, or supplying a record made against an older
// version of the rule never counts as a new review.
func (s chainState) reviewsFromRecords(rules map[string]ruleCandidate, records map[string][]byte, attestedAt time.Time) (map[string]string, error) {
	ids := make([]string, 0, len(records))
	for id := range records {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	out := map[string]string{}
	for _, id := range ids {
		raw := records[id]
		rule, ok := rules[id]
		if !ok {
			return nil, fmt.Errorf("%w: V5: review record %s names no rule in the pack", ErrRejected, id)
		}
		if rule.Fields.record {
			return nil, fmt.Errorf("%w: V5: review record %s names a line attestation or path-policy record; records take no review record", ErrRejected, id)
		}
		if len(raw) == 0 || len(raw) > MaxReviewRecordBytes {
			return nil, fmt.Errorf("%w: V5: review record for rule %s is empty or too large", ErrRejected, id)
		}
		digest := sourcecorpus.SHA(raw)
		if s.recordedReviews[id][digest] {
			continue
		}
		fields, err := reviewrecord.ParseRecordFields(raw)
		if err != nil {
			return nil, fmt.Errorf("%w: V5: review record for rule %s is not a well-formed review record", ErrRejected, id)
		}
		if fields.RuleID != id || fields.Project != rule.Project {
			return nil, fmt.Errorf("%w: V5: review record for rule %s names a different rule or project", ErrRejected, id)
		}
		ruleDigest, _, _, err := ruleDigestAndEvidence(rule.Raw)
		if err != nil || fields.RuleDigest != ruleDigest {
			return nil, fmt.Errorf("%w: V5: review record for rule %s is not bound to the rule's current version in the prior pack", ErrRejected, id)
		}
		if last, ok := s.lastReviewAt[id]; ok {
			lastAt, err := parseUTC(last)
			if err != nil || !fields.DecidedAt.After(lastAt) {
				return nil, fmt.Errorf("%w: V5: review record for rule %s is not later than the rule's last individual review recorded in the chain", ErrRejected, id)
			}
		}
		if fields.DecidedAt.After(attestedAt) {
			return nil, fmt.Errorf("%w: V5: review record for rule %s was decided after attestedAt", ErrRejected, id)
		}
		out[id] = digest
	}
	return out, nil
}

// renewedValidUntil is the validUntil statement gives a rule it renews: the
// rule's own in an automated statement, the statement's in a human one.
func renewedValidUntil(statement Statement, ra RuleAttestation) string {
	if ra.ValidUntil != "" {
		return ra.ValidUntil
	}
	return statement.ValidUntil
}

// apply checks that statement correctly continues the chain described by s
// and advances s past it. It is the single definition of V5 used on every
// chain entry, on the statement being verified (checkV5), and as Prepare's
// self-check, so Prepare can never emit a statement Verify rejects for a
// chain reason.
func (s *chainState) apply(statement Statement) error {
	if s.headDigest == nil {
		if statement.PreviousAttestationDigest != nil {
			return fmt.Errorf("%w: V5: previousAttestationDigest is declared but the pack's statement chain is empty", ErrRejected)
		}
	} else {
		if statement.PreviousAttestationDigest == nil {
			return fmt.Errorf("%w: V5: the pack's statement chain has a head but the statement declares no previousAttestationDigest", ErrRejected)
		}
		if *statement.PreviousAttestationDigest != *s.headDigest {
			return fmt.Errorf("%w: V5: previousAttestationDigest does not match the head of the pack's statement chain", ErrRejected)
		}
	}
	attestedAt, err := parseUTC(statement.AttestedAt)
	if err != nil {
		return fmt.Errorf("%w: V5: attestedAt", ErrRejected)
	}
	if s.headDigest != nil && !attestedAt.After(s.headAttestedAt) {
		return fmt.Errorf("%w: V5: attestedAt is not after the chain head's attestedAt", ErrRejected)
	}

	listed := map[string]bool{}
	for _, ra := range statement.Rules {
		listed[ra.RuleID] = true
	}
	for _, ne := range statement.NotExtended {
		listed[ne.RuleID] = true
	}
	reviewed := map[string]string{}
	previousID := ""
	for i, review := range statement.IndividualReviews {
		if review.RuleID == "" || (i > 0 && review.RuleID <= previousID) {
			return fmt.Errorf("%w: V5: individualReviews must be sorted by unique rule ID", ErrRejected)
		}
		previousID = review.RuleID
		if !listed[review.RuleID] {
			return fmt.Errorf("%w: V5: rule %s has an individual review but is in neither the statement's rules nor its notExtended list", ErrRejected, review.RuleID)
		}
		if evidencerepin.IsRecordID(review.RuleID) {
			return fmt.Errorf("%w: V5: rule %s individual review names a line attestation or path-policy record; records take no review record", ErrRejected, review.RuleID)
		}
		if !validDigest(review.ReviewRecordDigest) {
			return fmt.Errorf("%w: V5: rule %s individual review record digest is malformed", ErrRejected, review.RuleID)
		}
		if s.recordedReviews[review.RuleID][review.ReviewRecordDigest] {
			return fmt.Errorf("%w: V5: rule %s individual review record was already recorded earlier in the chain", ErrRejected, review.RuleID)
		}
		reviewed[review.RuleID] = review.ReviewRecordDigest
	}
	for _, sample := range statement.SampledForFullReview {
		if sample.ReviewRecordDigest != "" && sample.ReviewRecordDigest != reviewed[sample.RuleID] {
			return fmt.Errorf("%w: V5: sampled rule %s review record is not a new individual review recorded by this statement", ErrRejected, sample.RuleID)
		}
	}

	for _, ra := range statement.Rules {
		_, reviewedNow := reviewed[ra.RuleID]
		if ra.ConsecutiveBatchCycles < 1 {
			return fmt.Errorf("%w: V5: rule %s consecutiveBatchCycles %d is below 1", ErrRejected, ra.RuleID, ra.ConsecutiveBatchCycles)
		}
		if ra.ConsecutiveBatchCycles != s.expectedCycles(ra.RuleID, reviewedNow) {
			return fmt.Errorf("%w: V5: rule %s consecutiveBatchCycles does not continue the chain", ErrRejected, ra.RuleID)
		}
		if ra.ConsecutiveBatchCycles > maxConsecutiveBatchCycles {
			return fmt.Errorf("%w: V5: rule %s exceeds the consecutive-batch-cycle cap", ErrRejected, ra.RuleID)
		}
		if ra.LastIndividualReviewAt != s.expectedLastReview(ra.RuleID, reviewedNow, statement.AttestedAt, ra.PriorReviewedAt) {
			return fmt.Errorf("%w: V5: rule %s lastIndividualReviewAt does not carry forward", ErrRejected, ra.RuleID)
		}
	}

	for ruleID, digest := range reviewed {
		s.batchSinceReview[ruleID] = 0
		s.lastReviewAt[ruleID] = statement.AttestedAt
		if s.recordedReviews[ruleID] == nil {
			s.recordedReviews[ruleID] = map[string]bool{}
		}
		s.recordedReviews[ruleID][digest] = true
	}
	record := entryRecord{renewed: map[string]string{}, reviewed: map[string]bool{}}
	for ruleID := range reviewed {
		record.reviewed[ruleID] = true
	}
	for _, ra := range statement.Rules {
		s.batchSinceReview[ra.RuleID] = ra.ConsecutiveBatchCycles
		s.lastReviewAt[ra.RuleID] = ra.LastIndividualReviewAt
		record.renewed[ra.RuleID] = renewedValidUntil(statement, ra)
	}
	s.entries[statement.AttestedAt] = record
	canonical, err := CanonicalStatement(statement)
	if err != nil {
		return fmt.Errorf("%w: V5: statement digest", ErrRejected)
	}
	digest := sourcecorpus.SHA(canonical)
	s.headDigest = &digest
	s.headAttestedAt = attestedAt
	return nil
}

// checkPriorPackCovered ties the prior pack's evidence dates to the chain.
// It rejects a prior pack holding any rule whose reviewedAt is later than
// the chain head's attestedAt unless this statement records a new
// individual review for it: every batch renewal is a chain entry, so such
// a rule was either renewed by a statement missing from the chain (a
// truncated chain) or reviewed individually, and only a supplied review
// record tells the two apart. It also rejects a rule whose reviewedAt
// equals some chain entry's attestedAt unless that entry renewed it (and
// then its validUntil must still be the one that entry set) or recorded an
// individual review for it, or this statement records a new one: a rule's
// dates can never claim a renewal the chain does not record.
//
// With tolerateOutside (an automated statement, which never counts a
// review record) a rule whose reviewedAt is later than the chain head is
// not an error: it is returned in outside so the caller can exclude it
// from the automated renewal and leave it to a human statement. Nothing
// about such a rule is trusted, and nothing in the automated path can
// reset its consecutive-cycle count.
func (s chainState) checkPriorPackCovered(priorRules []ruleFields, fresh map[string]string, tolerateOutside bool) (outside map[string]bool, err error) {
	outside = map[string]bool{}
	if s.headDigest == nil {
		return outside, nil
	}
	for _, rule := range priorRules {
		// A mechanical line attestation or path-policy record is renewed by
		// re-deriving it, which moves its reviewedAt (its derivedAt) outside
		// any statement; no statement ever renews one (V6, V8), so its dates
		// say nothing about the chain.
		if rule.record && rule.isMechanical() {
			continue
		}
		reviewedAt, err := parseUTC(rule.Evidence.ReviewedAt)
		if err != nil {
			return nil, fmt.Errorf("%w: V5: rule %s reviewedAt is malformed", ErrRejected, rule.ID)
		}
		if fresh[rule.ID] != "" {
			continue
		}
		if reviewedAt.After(s.headAttestedAt) {
			if tolerateOutside {
				outside[rule.ID] = true
				continue
			}
			return nil, fmt.Errorf("%w: V5: rule %s was reviewed after the chain head was attested but no new individual review record is supplied for it; the statement chain may be truncated", ErrRejected, rule.ID)
		}
		entry, ok := s.entries[rule.Evidence.ReviewedAt]
		if !ok {
			continue
		}
		if validUntil, renewed := entry.renewed[rule.ID]; renewed {
			if rule.Evidence.ValidUntil != validUntil {
				return nil, fmt.Errorf("%w: V5: rule %s carries the reviewedAt of the chain entry that renewed it but not the validUntil that entry set", ErrRejected, rule.ID)
			}
			continue
		}
		if !entry.reviewed[rule.ID] {
			return nil, fmt.Errorf("%w: V5: rule %s carries a chain entry's attestedAt as its reviewedAt but that entry neither renewed it nor recorded an individual review for it", ErrRejected, rule.ID)
		}
	}
	return outside, nil
}

// checkAppendOnly requires chain, the statement chain supplied with the
// change under verification, to be base, the same pack's statement chain
// on the base branch, with at most one entry added, and that added entry
// to be the statement under verification. Entries are compared by their
// exact statement and envelope bytes, never by name. Removing, replacing,
// re-signing or adding any other entry is rejected, as is an empty chain
// over a non-empty base, and a statement the base chain already records.
//
// With requireAdded the statement under verification must be the one added
// entry: a chain equal to its base is then rejected. Verify requires this
// whenever the statement renews a rule or records an individual review, so
// a renewal that is merged without its signed chain entry can never be
// accepted; only the explicit pre-sign structural mode (VerifyOptions.PreSign)
// runs without it, and that mode never passes the publish gate.
func checkAppendOnly(base, chain *Chain, statementRaw []byte, requireAdded bool) error {
	if base == nil {
		return fmt.Errorf("%w: V5: the base branch's statement chain is required; pass an empty one for a pack with no attestation history on the base branch", ErrRejected)
	}
	if chain == nil {
		return fmt.Errorf("%w: V5: a statement chain is required; pass an empty one for a pack with no attestation history", ErrRejected)
	}
	type key struct{ statement, envelope string }
	present := map[key]int{}
	for _, entry := range chain.Entries {
		present[key{sourcecorpus.SHA(entry.Statement), sourcecorpus.SHA(entry.Envelope)}]++
	}
	for _, entry := range base.Entries {
		k := key{sourcecorpus.SHA(entry.Statement), sourcecorpus.SHA(entry.Envelope)}
		if present[k] == 0 {
			return fmt.Errorf("%w: V5: base chain entry %s is missing or changed in the statement chain; the chain is append-only", ErrRejected, entry.Name)
		}
		present[k]--
	}
	for _, entry := range base.Entries {
		if bytes.Equal(entry.Statement, statementRaw) {
			return fmt.Errorf("%w: V5: the statement is already recorded in the base branch's statement chain", ErrRejected)
		}
	}
	var added []ChainEntry
	for _, entry := range chain.Entries {
		k := key{sourcecorpus.SHA(entry.Statement), sourcecorpus.SHA(entry.Envelope)}
		if present[k] > 0 {
			present[k]--
			added = append(added, entry)
		}
	}
	if len(added) > 1 {
		return fmt.Errorf("%w: V5: the statement chain adds %d entries to the base chain; at most one, the statement under verification, may be added", ErrRejected, len(added))
	}
	if len(added) == 1 && !bytes.Equal(added[0].Statement, statementRaw) {
		return fmt.Errorf("%w: V5: chain entry %s is added to the base chain but is not the statement under verification", ErrRejected, added[0].Name)
	}
	if requireAdded && len(added) != 1 {
		return fmt.Errorf("%w: V5: the statement renews a rule or records an individual review but is not appended to the statement chain; the chain must be the base chain plus exactly this statement", ErrRejected)
	}
	return nil
}

// deriveChainState verifies a pack's statement chain and folds it into a
// chainState. It is the one chain derivation both Prepare and Verify use.
// Every entry must parse, belong to packName, be attested no later than
// now, and carry a valid signature under the pinned trust root at now;
// entries must link by
// previousAttestationDigest from exactly one genesis entry to exactly one
// head with no fork, gap, cycle, or duplicate; and every entry's recorded
// cycle counts must themselves continue the chain (see apply).
//
// selfDigest, when non-empty, is the digest of the statement being
// verified: if the chain's head is that same statement (it was already
// appended), the state before it is returned; if it appears anywhere else
// in the chain, the chain is rejected.
func deriveChainState(chain *Chain, packName string, now time.Time, selfDigest string) (chainState, error) {
	if chain == nil {
		return chainState{}, fmt.Errorf("%w: V5: a statement chain is required; pass an empty one for a pack with no attestation history", ErrRejected)
	}
	if len(chain.Entries) > MaxChainEntries {
		return chainState{}, fmt.Errorf("%w: V5: statement chain has too many entries", ErrRejected)
	}
	state := newChainState()
	if len(chain.Entries) == 0 {
		return state, nil
	}
	if !validDigest(chain.ExpectedTrustRootDigest) || len(chain.TrustRoot) == 0 {
		return chainState{}, fmt.Errorf("%w: V5: a pinned trust root is required to verify the statement chain", ErrRejected)
	}

	type node struct {
		name      string
		statement Statement
	}
	byDigest := map[string]node{}
	children := map[string][]string{}
	var genesis []string
	for _, entry := range chain.Entries {
		statement, err := ParseStatement(entry.Statement)
		if err != nil {
			return chainState{}, fmt.Errorf("%w: V5: chain entry %s does not parse", ErrRejected, entry.Name)
		}
		if statement.Pack.Name != packName {
			return chainState{}, fmt.Errorf("%w: V5: chain entry %s belongs to another pack", ErrRejected, entry.Name)
		}
		if attestedAt, err := parseUTC(statement.AttestedAt); err != nil || attestedAt.After(now) {
			return chainState{}, fmt.Errorf("%w: V5: chain entry %s is attested after the current time", ErrRejected, entry.Name)
		}
		if _, err := VerifySignature(VerifySignatureOptions{
			Statement: entry.Statement, Envelope: entry.Envelope, TrustRoot: chain.TrustRoot,
			ExpectedTrustRootDigest: chain.ExpectedTrustRootDigest, Now: now,
		}); err != nil {
			return chainState{}, fmt.Errorf("%w: V5: chain entry %s has no valid signature under the pinned trust root", ErrRejected, entry.Name)
		}
		digest := sourcecorpus.SHA(entry.Statement)
		if _, dup := byDigest[digest]; dup {
			return chainState{}, fmt.Errorf("%w: V5: chain entry %s duplicates another entry", ErrRejected, entry.Name)
		}
		byDigest[digest] = node{name: entry.Name, statement: statement}
		if statement.PreviousAttestationDigest == nil {
			genesis = append(genesis, digest)
			continue
		}
		previous := *statement.PreviousAttestationDigest
		children[previous] = append(children[previous], digest)
	}
	if len(genesis) != 1 {
		return chainState{}, fmt.Errorf("%w: V5: statement chain must have exactly one genesis entry, found %d", ErrRejected, len(genesis))
	}
	for previous, next := range children {
		if len(next) > 1 {
			sort.Strings(next)
			return chainState{}, fmt.Errorf("%w: V5: statement chain forks after %s", ErrRejected, previous)
		}
	}
	order := make([]string, 0, len(byDigest))
	visited := map[string]bool{}
	for current := genesis[0]; ; {
		if visited[current] {
			return chainState{}, fmt.Errorf("%w: V5: statement chain has a cycle", ErrRejected)
		}
		visited[current] = true
		order = append(order, current)
		next := children[current]
		if len(next) == 0 {
			break
		}
		current = next[0]
	}
	if len(order) != len(byDigest) {
		return chainState{}, fmt.Errorf("%w: V5: statement chain has entries not linked to its genesis entry (a gap)", ErrRejected)
	}
	if selfDigest != "" {
		for i, digest := range order {
			if digest != selfDigest {
				continue
			}
			if i != len(order)-1 {
				return chainState{}, fmt.Errorf("%w: V5: the statement is already recorded in the chain, and not as its head", ErrRejected)
			}
			order = order[:i]
		}
	}
	for _, digest := range order {
		entry := byDigest[digest]
		if err := state.apply(entry.statement); err != nil {
			return chainState{}, fmt.Errorf("%w: V5: chain entry %s: %v", ErrRejected, entry.name, err)
		}
	}
	return state, nil
}
