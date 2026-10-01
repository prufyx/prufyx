// SPDX-License-Identifier: AGPL-3.0-only

package evidencereattest

import (
	"fmt"
	"sort"
	"time"

	"github.com/prufyx/prufyx/cli/internal/maintainer/sourcecorpus"
)

// ChainEntry is one previously produced statement in a pack's statement
// chain together with its detached signature envelope. Name is only used
// in error messages; it plays no part in ordering the chain.
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
}

func newChainState() chainState {
	return chainState{
		batchSinceReview: map[string]int{},
		lastReviewAt:     map[string]string{},
		recordedReviews:  map[string]map[string]bool{},
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

// freshReviews returns, for every rule ID in ruleIDs with a supplied review
// record digest, that digest, unless the chain already recorded the same
// digest for the same rule: a review record already counted once is never
// a new individual review.
func (s chainState) freshReviews(ruleIDs []string, supplied map[string]string) map[string]string {
	out := map[string]string{}
	for _, id := range ruleIDs {
		digest := supplied[id]
		if digest == "" || s.recordedReviews[id][digest] {
			continue
		}
		out[id] = digest
	}
	return out
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

	reviewed := map[string]string{}
	previousID := ""
	for i, review := range statement.IndividualReviews {
		if review.RuleID == "" || (i > 0 && review.RuleID <= previousID) {
			return fmt.Errorf("%w: V5: individualReviews must be sorted by unique rule ID", ErrRejected)
		}
		previousID = review.RuleID
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
	for _, ra := range statement.Rules {
		s.batchSinceReview[ra.RuleID] = ra.ConsecutiveBatchCycles
		s.lastReviewAt[ra.RuleID] = ra.LastIndividualReviewAt
	}
	canonical, err := CanonicalStatement(statement)
	if err != nil {
		return fmt.Errorf("%w: V5: statement digest", ErrRejected)
	}
	digest := sourcecorpus.SHA(canonical)
	s.headDigest = &digest
	s.headAttestedAt = attestedAt
	return nil
}

// checkPriorPackCovered rejects a prior pack holding any rule whose
// reviewedAt is later than the chain head's attestedAt unless this
// statement records a new individual review for it. Every batch renewal is
// a chain entry, so such a rule was either renewed by a statement missing
// from the chain (a truncated chain) or reviewed individually; only a
// supplied review record tells the two apart.
func (s chainState) checkPriorPackCovered(priorRules []ruleFields, fresh map[string]string) error {
	if s.headDigest == nil {
		return nil
	}
	for _, rule := range priorRules {
		reviewedAt, err := parseUTC(rule.Evidence.ReviewedAt)
		if err != nil {
			return fmt.Errorf("%w: V5: rule %s reviewedAt is malformed", ErrRejected, rule.ID)
		}
		if reviewedAt.After(s.headAttestedAt) && fresh[rule.ID] == "" {
			return fmt.Errorf("%w: V5: rule %s was reviewed after the chain head was attested but no new individual review record is supplied for it; the statement chain may be truncated", ErrRejected, rule.ID)
		}
	}
	return nil
}

// deriveChainState verifies a pack's statement chain and folds it into a
// chainState. It is the one chain derivation both Prepare and Verify use.
// Every entry must parse, belong to packName, and carry a valid signature
// under the pinned trust root at now; entries must link by
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
