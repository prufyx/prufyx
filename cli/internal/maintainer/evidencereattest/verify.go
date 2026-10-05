// SPDX-License-Identifier: AGPL-3.0-only

package evidencereattest

import (
	"bytes"
	"encoding/json"
	"fmt"
	"time"

	"github.com/prufyx/prufyx/cli/internal/constraintengine"
	"github.com/prufyx/prufyx/cli/internal/maintainer/evidencerepin"
	"github.com/prufyx/prufyx/cli/internal/maintainer/sourcecorpus"
)

// VerifyOptions names every input the structural verifier needs. It never
// touches a signing key. It checks the statement's own signature only
// through VerifySignature, called separately by the CLI adapter; the trust
// root pin it takes (inside Chain) is used to verify the signatures of the
// pack's earlier statements, which the chain derivation requires.
type VerifyOptions struct {
	StatementRaw []byte
	// PriorPackRaw and NextPackRaw are the exact rules.json bytes on the
	// base branch and in the proposed change, respectively.
	PriorPackRaw, NextPackRaw []byte
	// WorklistRaw is the retained worklist the statement claims to be
	// built from. Required: Verify never runs without it.
	WorklistRaw []byte
	// Chain is this pack's signed statement chain (see Chain and
	// deriveChainState). Required: pass a Chain with no entries for a pack
	// with no attestation history. The statement's
	// previousAttestationDigest must equal the chain's head, and every
	// rule's consecutiveBatchCycles must equal the count the chain
	// derivation assigns it; neither is ever taken from a caller-supplied
	// value.
	Chain *Chain
	// BaseChain is the same pack's statement chain as it is on the base
	// branch the change is proposed against. Required: pass a Chain with no
	// entries when the base branch has no attestation history for the
	// pack. Chain must equal BaseChain exactly, plus at most one added
	// entry that is the statement under verification (see
	// checkAppendOnly), so a change can never remove, replace or reorder
	// the chain it builds on.
	BaseChain *Chain
	// EngineCapabilityDigest, PackName and PackPath mirror Prepare's
	// options: checkV1AndV3 recomputes the whole statement and next pack
	// exactly the way Prepare did and requires an exact byte match.
	PackName               string
	PackPath               string
	EngineCapabilityDigest string
	// AttestedAtNow is this verifier's own clock. Required: a statement
	// whose declared attestedAt is after it is rejected outright, so the
	// review-lease clock is bounded by an honest verifier clock, not only
	// by internally consistent statement fields.
	AttestedAtNow time.Time
	// ReviewRecords supplies individual review records by rule ID (see
	// PrepareOptions.ReviewRecords and the CLI's --review-record-dir). Each
	// is checked structurally and against the prior pack and the chain
	// (chainState.reviewsFromRecords); the ones that are new individual
	// reviews are used to recompute the statement exactly (checkV1AndV3: a
	// statement whose declared individualReviews or reviewRecordDigest does
	// not match the supplied records fails to reproduce) and, via checkV6,
	// as the individually-reviewed alternative for a rule whose dates
	// changed outside this statement's own batch. A sample review record
	// (SampleReviewSchema) is also checked against the statement being
	// recomputed (checkSampleReviews). This package does not re-verify a
	// declared review record against its packet, corpus, vectors and
	// target; that is maintainer/reviewrecord's job.
	ReviewRecords map[string][]byte
	// PreSign selects the explicit pre-sign structural mode: the statement
	// need not yet be appended to Chain, so Chain may equal BaseChain. It
	// exists only to run the structural checks right after Prepare, before
	// anyone has signed. Without it, a statement that renews any rule or
	// records any individual review must be the one entry Chain adds to
	// BaseChain (checkAppendOnly), and checkV6 refuses any evidence-date
	// change that no chain entry records. A PreSign result must never be
	// used as the publish gate; the CLI's --structural-only, the only
	// caller that sets it, always exits non-zero.
	PreSign bool
	// IndependentWorklistRaw, when set, is a worklist produced
	// independently of the signing job (the CI verify job's own "evidence
	// repin" run). Verify then requires, for every citation of every rule
	// the statement renews, exactly one identical citation (class, pinned
	// and compared commits, baseline, line and tags) in that worklist,
	// backed by its own line record, so a statement built from a worklist
	// the signing job could have forged is rejected (see
	// checkIndependentWorklist). WorklistRaw is the signing job's retained
	// worklist and is only as trustworthy as that job.
	IndependentWorklistRaw []byte
}

// VerifyResult reports what Verify established. Every field is filled in
// on success; on failure the returned error names which invariant failed
// and Result is the zero value.
type VerifyResult struct {
	// SignerRole is the role the statement requires of its signature
	// (see VerifySignature, which enforces it).
	SignerRole                                string
	RuleCount, SampledCount, NotExtendedCount int
	// ReviewCount is how many individual reviews the statement records.
	ReviewCount int
}

// Verify recomputes and checks every invariant this package enforces
// against a prepared statement. It is deterministic, makes no network
// access, and returns a non-nil, wrapped error identifying the first
// invariant that failed, prefixed with that invariant's own name (V1, V2,
// ...) so a caller or test can assert on which one fired. It requires no
// signing key or trust root: nothing here decides whether a signature
// exists or where its trust root comes from; that is layered separately
// (see VerifySignature and the CLI adapter, which requires a valid
// signature whenever a statement renews at least one rule).
func Verify(options VerifyOptions) (VerifyResult, error) {
	if len(options.WorklistRaw) == 0 {
		return VerifyResult{}, fmt.Errorf("%w: a retained worklist is required", ErrRejected)
	}
	if options.AttestedAtNow.IsZero() {
		return VerifyResult{}, fmt.Errorf("%w: the verifier's current time is required", ErrRejected)
	}
	statement, err := ParseStatement(options.StatementRaw)
	if err != nil {
		return VerifyResult{}, fmt.Errorf("%w: statement does not parse", ErrRejected)
	}
	attestedAt, err := time.Parse(time.RFC3339, statement.AttestedAt)
	if err != nil || attestedAt.After(options.AttestedAtNow.UTC()) {
		return VerifyResult{}, fmt.Errorf("%w: attestedAt is in the future", ErrRejected)
	}

	if err := checkV2(statement); err != nil {
		return VerifyResult{}, err
	}
	recordsChange := len(statement.Rules) > 0 || len(statement.IndividualReviews) > 0
	if err := checkAppendOnly(options.BaseChain, options.Chain, options.StatementRaw, recordsChange && !options.PreSign); err != nil {
		return VerifyResult{}, err
	}
	state, err := deriveChainState(options.Chain, options.PackName, options.AttestedAtNow.UTC(), sourcecorpus.SHA(options.StatementRaw))
	if err != nil {
		return VerifyResult{}, err
	}

	priorDoc, err := loadPack(options.PriorPackRaw)
	if err != nil {
		return VerifyResult{}, fmt.Errorf("%w: prior pack: %v", ErrRejected, err)
	}
	nextDoc, err := loadPack(options.NextPackRaw)
	if err != nil {
		return VerifyResult{}, fmt.Errorf("%w: next pack: %v", ErrRejected, err)
	}
	priorByID, err := rulesByID(priorDoc)
	if err != nil {
		return VerifyResult{}, err
	}
	nextByID, err := rulesByID(nextDoc)
	if err != nil {
		return VerifyResult{}, err
	}
	role, err := statementRole(statement)
	if err != nil {
		return VerifyResult{}, fmt.Errorf("%w: statement role", ErrRejected)
	}
	fresh, err := checkPriorPackAgainstChain(state, priorDoc, options.ReviewRecords, attestedAt.UTC(), role)
	if err != nil {
		return VerifyResult{}, err
	}
	priorCandidates, _, err := packCandidates(priorDoc)
	if err != nil {
		return VerifyResult{}, err
	}

	if err := checkV1AndV3(statement, options.StatementRaw, options, state); err != nil {
		return VerifyResult{}, err
	}
	if err := checkV4(statement, options.PriorPackRaw, options.NextPackRaw, priorDoc, nextDoc); err != nil {
		return VerifyResult{}, err
	}
	if err := checkV5(statement, state); err != nil {
		return VerifyResult{}, err
	}
	if err := checkV6(priorByID, nextByID, statement, coveringReviews(role, fresh), options.PreSign || chainContains(options.Chain, options.StatementRaw)); err != nil {
		return VerifyResult{}, err
	}
	if err := checkV7(statement, nextByID); err != nil {
		return VerifyResult{}, err
	}
	if err := checkSampleReviewed(statement); err != nil {
		return VerifyResult{}, err
	}
	if err := checkRolePolicy(statement, candidatesByID(priorCandidates)); err != nil {
		return VerifyResult{}, err
	}
	if err := checkV10(priorDoc, nextDoc); err != nil {
		return VerifyResult{}, err
	}
	if len(options.IndependentWorklistRaw) > 0 {
		if err := checkIndependentWorklist(statement, options.PackPath, options.IndependentWorklistRaw); err != nil {
			return VerifyResult{}, err
		}
	}

	return VerifyResult{SignerRole: role, RuleCount: len(statement.Rules), SampledCount: len(statement.SampledForFullReview), NotExtendedCount: len(statement.NotExtended), ReviewCount: len(statement.IndividualReviews)}, nil
}

// checkV2 checks the statement's own declared review-lease dates: the
// lease (validUntil - attestedAt) must be positive and no more than the
// policy-v1 90-day cap; a human statement's validUntil must equal its
// wave's slot date computed from its own attestedAt; an automated
// statement's validUntil must be its latest automated slot, and every rule
// it renews must have a validUntil that is one of its automated slots.
func checkV2(statement Statement) error {
	attestedAt, err := time.Parse(time.RFC3339, statement.AttestedAt)
	if err != nil {
		return fmt.Errorf("%w: V2: attestedAt", ErrRejected)
	}
	validUntil, err := time.Parse(time.RFC3339, statement.ValidUntil)
	if err != nil {
		return fmt.Errorf("%w: V2: validUntil", ErrRejected)
	}
	// The lease bound is checked first and on its own, so it holds even if
	// the slot computation below ever allowed a date past the cap.
	if validUntil.Sub(attestedAt) <= 0 || validUntil.Sub(attestedAt) > maxLease {
		return fmt.Errorf("%w: V2: lease is not positive or exceeds the policy-v1 90-day cap", ErrRejected)
	}
	role, err := statementRole(statement)
	if err != nil {
		return fmt.Errorf("%w: V2: statement role", ErrRejected)
	}
	if role == RoleHuman {
		wantValidUntil, err := SlotDate(statement.Wave, attestedAt)
		if err != nil || !validUntil.Equal(wantValidUntil) {
			return fmt.Errorf("%w: V2: validUntil does not match the wave's slot date", ErrRejected)
		}
		return nil
	}
	horizon, err := automatedHorizon(attestedAt)
	if err != nil || !validUntil.Equal(horizon) {
		return fmt.Errorf("%w: V2: validUntil is not the automated schedule's horizon", ErrRejected)
	}
	slots := map[string]bool{}
	for _, slot := range AutomatedSlots(attestedAt) {
		slots[slot.Format(time.RFC3339)] = true
	}
	for _, ra := range statement.Rules {
		ruleValidUntil, err := parseUTC(ra.ValidUntil)
		if err != nil || ruleValidUntil.Sub(attestedAt) <= 0 || ruleValidUntil.Sub(attestedAt) > maxLease {
			return fmt.Errorf("%w: V2: rule %s lease is not positive or exceeds the policy-v1 90-day cap", ErrRejected, ra.RuleID)
		}
		if !slots[ra.ValidUntil] {
			return fmt.Errorf("%w: V2: rule %s validUntil is not an automated slot", ErrRejected, ra.RuleID)
		}
	}
	return nil
}

// checkV1AndV3 is the core anti-tamper check: it reruns Prepare with
// exactly the inputs the statement claims (same worklist, prior pack,
// wave, attestedAt, next revision, engine capability digest, and review
// record digests) and requires the result to reproduce the supplied
// statement and next pack byte-for-byte.
//
// This single check does the work both V1 and V3 name: V3 because
// eligibility, the sample, and every other computed field are never
// trusted from the statement itself, only ever from a fresh recomputation;
// V1 because a next pack that reproduces exactly under recomputation
// cannot smuggle a content change into a listed rule, an unlisted rule, a
// pack-level field, or the entry count/order/IDs — every one of those is
// part of what buildNextPack renders, so any difference there breaks byte
// equality. A rule present on only one side of prior/next therefore always
// fails here too, not only in checkV6's dedicated scan.
func checkV1AndV3(statement Statement, statementRaw []byte, options VerifyOptions, state chainState) error {
	role, err := statementRole(statement)
	if err != nil {
		return fmt.Errorf("%w: V3: statement role", ErrRejected)
	}
	mode := ModeHuman
	if role == RoleAutomation {
		mode = ModeAutomated
	}
	result, err := prepareWithChain(PrepareOptions{
		Mode:        mode,
		WorklistRaw: options.WorklistRaw, PackName: options.PackName, PackPath: options.PackPath,
		PackRaw: options.PriorPackRaw,
		Wave:    statement.Wave, AttestedAt: mustParse(statement.AttestedAt), NextRevision: statement.Pack.Next.Revision,
		EngineCapabilityDigest: options.EngineCapabilityDigest, ReviewRecords: options.ReviewRecords,
	}, state)
	if err != nil {
		return fmt.Errorf("%w: V3: recomputation failed: %v", ErrRejected, err)
	}
	if !bytes.Equal(result.StatementCanonical, statementRaw) {
		return fmt.Errorf("%w: V3: statement does not match a fresh recomputation byte-for-byte", ErrRejected)
	}
	if !bytes.Equal(result.NextPack, options.NextPackRaw) {
		return fmt.Errorf("%w: V1: next pack does not match a fresh recomputation byte-for-byte; every rule not in this batch must stay byte-identical, in the same order, and no entry may be added or removed", ErrRejected)
	}
	return nil
}

func mustParse(value string) time.Time {
	parsed, _ := time.Parse(time.RFC3339, value)
	return parsed
}

// checkV4 rebinds the statement's declared pack digests to the actual
// supplied pack bytes, the way corpusattest.verifyPackBinding does it.
func checkV4(statement Statement, priorRaw, nextRaw []byte, priorDoc, nextDoc packDocument) error {
	if statement.Pack.Prior.PackDigest != packDigest(priorRaw) || statement.Pack.Prior.Revision != priorDoc.Revision {
		return fmt.Errorf("%w: V4: prior pack binding", ErrRejected)
	}
	if statement.Pack.Next.PackDigest != packDigest(nextRaw) || statement.Pack.Next.Revision != nextDoc.Revision {
		return fmt.Errorf("%w: V4: next pack binding", ErrRejected)
	}
	priorRuleSet, err := ruleSetDigest(priorDoc)
	if err != nil || priorRuleSet != statement.Pack.Prior.RuleSetDigest {
		return fmt.Errorf("%w: V4: prior rule set digest", ErrRejected)
	}
	nextRuleSet, err := ruleSetDigest(nextDoc)
	if err != nil || nextRuleSet != statement.Pack.Next.RuleSetDigest {
		return fmt.Errorf("%w: V4: next rule set digest", ErrRejected)
	}
	if statement.Pack.PolicyDigest != priorDoc.PolicyDigest || statement.Pack.PolicyID != priorDoc.PolicyID || statement.Pack.Schema != priorDoc.Schema {
		return fmt.Errorf("%w: V4: policy/schema binding", ErrRejected)
	}
	return nil
}

// rulesByID maps every rule ID to the rule, and every line attestation or
// path-policy record ID to the record's view (see recordView), so V6 and V7
// cover records exactly as they cover rules.
func rulesByID(doc packDocument) (map[string]json.RawMessage, error) {
	byID := map[string]json.RawMessage{}
	for _, entry := range doc.Entries {
		fields, err := parseRuleFields(entry.Rule)
		if err != nil {
			return nil, err
		}
		byID[fields.ID] = entry.Rule
	}
	for _, record := range doc.records {
		view, err := recordView(record)
		if err != nil {
			return nil, err
		}
		byID[record.ID] = view
	}
	return byID, nil
}

// checkV10 holds a pack's line attestation and path-policy records to what a
// renewal may change, independently of checkV1AndV3's recomputation: the
// prior and next pack carry the same sections, holding the same records in
// the same order, and each record is identical apart from its
// evidence.reviewedAt and evidence.validUntil. Which date changes are
// allowed at all is V6's (records are in rulesByID), and the next pack's
// records were parsed strictly and re-checked against its rules on load
// (loadRecords).
func checkV10(priorDoc, nextDoc packDocument) error {
	if (priorDoc.LineAttestations == nil) != (nextDoc.LineAttestations == nil) || (priorDoc.PathPolicies == nil) != (nextDoc.PathPolicies == nil) {
		return fmt.Errorf("%w: V10: a record section is present in only one of the prior and next packs", ErrRejected)
	}
	if len(priorDoc.records) != len(nextDoc.records) {
		return fmt.Errorf("%w: V10: the prior and next packs hold different numbers of records", ErrRejected)
	}
	for i, prior := range priorDoc.records {
		next := nextDoc.records[i]
		if prior.ID != next.ID || prior.Project != next.Project {
			return fmt.Errorf("%w: V10: record %d is %s in the prior pack but %s in the next", ErrRejected, i, prior.ID, next.ID)
		}
		if !sameOutsideValidity(prior.Raw, next.Raw) {
			return fmt.Errorf("%w: V10: record %s changed outside evidence.reviewedAt and evidence.validUntil", ErrRejected, prior.ID)
		}
	}
	return nil
}

// checkPriorPackAgainstChain decides which supplied review records are
// new individual reviews (chainState.reviewsFromRecords, exactly as
// Prepare does) and applies chainState.checkPriorPackCovered to the
// supplied prior pack, so a bad review record or a truncated chain is
// reported as V5 rather than only as a failed recomputation. It returns
// the new reviews by rule ID. An automated statement counts no review
// record at all and tolerates a rule reviewed outside the chain (it is
// excluded, see reasonReviewedOutsideChain), exactly as Prepare does in
// automated mode.
func checkPriorPackAgainstChain(state chainState, priorDoc packDocument, records map[string][]byte, attestedAt time.Time, role string) (map[string]string, error) {
	candidates, rules, err := packCandidates(priorDoc)
	if err != nil {
		return nil, err
	}
	if role == RoleAutomation {
		records = nil
	}
	fresh, err := state.reviewsFromRecords(candidatesByID(candidates), records, attestedAt)
	if err != nil {
		return nil, err
	}
	if _, err := state.checkPriorPackCovered(rules, fresh, role == RoleAutomation); err != nil {
		return nil, err
	}
	return fresh, nil
}

// checkV5 checks the statement against the pack's verified statement
// chain, independently of checkV1AndV3's recomputation: its
// previousAttestationDigest must be the chain's head, its attestedAt must
// be after the head's, every renewed rule's consecutiveBatchCycles must be
// at least 1, equal the count the chain derivation assigns it, and not
// exceed the cap, and every individual review it records must be new to
// the chain (see chainState.apply).
func checkV5(statement Statement, state chainState) error {
	next := state.clone()
	return next.apply(statement)
}

// coveringReviews is what checkV6 may accept, besides the statement's own
// rules, as accounting for a rule's changed evidence dates: the new
// individual reviews for a human statement, and nothing for an automated
// one, which no person signs.
func coveringReviews(role string, fresh map[string]string) map[string]string {
	if role == RoleAutomation {
		return nil
	}
	return fresh
}

// chainContains reports whether chain has an entry whose statement is
// exactly statementRaw.
func chainContains(chain *Chain, statementRaw []byte) bool {
	if chain == nil {
		return false
	}
	for _, entry := range chain.Entries {
		if bytes.Equal(entry.Statement, statementRaw) {
			return true
		}
	}
	return false
}

// checkV6 is a CI gate over the pack diff, independent of checkV1AndV3:
// every rule whose evidence.reviewedAt or evidence.validUntil changed
// between the prior and next pack must be covered either by this
// statement or by a new individual review record (freshReviews, as
// returned by checkPriorPackAgainstChain), and every rule present in one
// pack must be present in the other. It does not re-verify a review
// record against its packet, corpus, vectors and target; that stays
// maintainer/reviewrecord's job.
//
// Coverage only counts when the statement is a chain entry
// (statementRecorded): a date change accounted for by a statement the
// chain does not record is refused, whatever the statement says, because
// the next run would treat the moved dates as a change outside the chain.
// A rule the statement covers must also carry exactly the dates the
// statement gives it: reviewedAt equal to attestedAt and validUntil equal
// to the statement's (or the rule's own, in an automated statement).
func checkV6(priorByID, nextByID map[string]json.RawMessage, statement Statement, freshReviews map[string]string, statementRecorded bool) error {
	covered := map[string]RuleAttestation{}
	for _, ra := range statement.Rules {
		covered[ra.RuleID] = ra
	}
	allIDs := map[string]bool{}
	for id := range priorByID {
		allIDs[id] = true
	}
	for id := range nextByID {
		allIDs[id] = true
	}
	for ruleID := range allIDs {
		prior, priorOK := priorByID[ruleID]
		next, nextOK := nextByID[ruleID]
		if !priorOK || !nextOK {
			return fmt.Errorf("%w: V6: rule %s is present in only one of the prior and next packs", ErrRejected, ruleID)
		}
		nextFields, err := parseRuleFields(next)
		if err != nil {
			return fmt.Errorf("%w: V6: rule %s", ErrRejected, ruleID)
		}
		priorFields, err := parseRuleFields(prior)
		if err != nil {
			return fmt.Errorf("%w: V6: rule %s", ErrRejected, ruleID)
		}
		if constraintengine.EffectiveBasis(priorFields.Evidence.Basis) != constraintengine.EffectiveBasis(nextFields.Evidence.Basis) {
			return fmt.Errorf("%w: V6: rule %s evidence basis changed; reattestation does not alter provenance", ErrRejected, ruleID)
		}
		if nextFields.Evidence.ReviewedAt == priorFields.Evidence.ReviewedAt && nextFields.Evidence.ValidUntil == priorFields.Evidence.ValidUntil {
			continue
		}
		// Neither a batch attestation nor an individual review record may
		// move the lease of a mechanical rule, or change a rule's basis.
		if priorFields.isMechanical() || nextFields.isMechanical() {
			return fmt.Errorf("%w: V6: rule %s is mechanical; its evidence dates are not renewable by reattestation", ErrRejected, ruleID)
		}
		if !statementRecorded {
			return fmt.Errorf("%w: V6: rule %s evidence dates changed but the statement covering them is not recorded in the statement chain", ErrRejected, ruleID)
		}
		if ra, ok := covered[ruleID]; ok {
			if nextFields.Evidence.ReviewedAt != statement.AttestedAt || nextFields.Evidence.ValidUntil != renewedValidUntil(statement, ra) {
				return fmt.Errorf("%w: V6: rule %s evidence dates are not the ones the statement gives it", ErrRejected, ruleID)
			}
			continue
		}
		if digest, ok := freshReviews[ruleID]; ok && digest != "" {
			continue
		}
		return fmt.Errorf("%w: V6: rule %s evidence dates changed with no covering attestation or review record", ErrRejected, ruleID)
	}
	return nil
}

// checkV7 is the stagger cap. It checks only the ISO weeks this statement
// renews rules into: for each such week, the number of next-pack rules
// whose validUntil falls in it must not exceed staggerCap (15% of the
// pack's rules, rounded down, and never less than one). Weeks this
// statement does not renew any rule into are not checked, so an existing
// cluster elsewhere in the pack never fails an unrelated batch, and a
// batch that moves rules out of a crowded week is allowed.
func checkV7(statement Statement, nextByID map[string]json.RawMessage) error {
	if len(statement.Rules) == 0 {
		return nil
	}
	weeks := map[string]bool{}
	for _, ra := range statement.Rules {
		raw, ok := nextByID[ra.RuleID]
		if !ok {
			return fmt.Errorf("%w: V7: renewed rule %s is missing from the next pack", ErrRejected, ra.RuleID)
		}
		fields, err := parseRuleFields(raw)
		if err != nil {
			return fmt.Errorf("%w: V7: rule %s", ErrRejected, ra.RuleID)
		}
		validUntil, err := parseUTC(fields.Evidence.ValidUntil)
		if err != nil {
			return fmt.Errorf("%w: V7: rule %s validUntil", ErrRejected, ra.RuleID)
		}
		weeks[isoWeek(validUntil)] = true
	}
	counts := map[string]int{}
	for id, raw := range nextByID {
		fields, err := parseRuleFields(raw)
		if err != nil {
			return fmt.Errorf("%w: V7: rule %s", ErrRejected, id)
		}
		validUntil, err := parseUTC(fields.Evidence.ValidUntil)
		if err != nil {
			return fmt.Errorf("%w: V7: rule %s validUntil", ErrRejected, id)
		}
		if week := isoWeek(validUntil); weeks[week] {
			counts[week]++
		}
	}
	total := len(nextByID)
	weekCap := staggerCap(total)
	for week, count := range counts {
		if count > weekCap {
			return fmt.Errorf("%w: V7: ISO week %s holds %d of %d rules, over the cap of %d", ErrRejected, week, count, total, weekCap)
		}
	}
	return nil
}

// checkRolePolicy (V8) checks, independently of checkV1AndV3's
// recomputation, that what the statement renews is within what its signer
// role may renew, from the statement and the prior pack alone:
//
//   - every renewed rule exists in the prior pack, is a reviewed (not
//     mechanical) rule, is active, carries no version range, and is listed
//     with exactly one citation per evidence source, each classified
//     NO_NEW_RELEASE, FILE_IDENTICAL or SPAN_IDENTICAL against the latest
//     release or its own release line, proven from GitHub Releases or
//     derived from git tags (an automated statement: its own release line
//     proven from GitHub Releases only), pinned to the source's own
//     revision;
//   - its consecutiveBatchCycles is within 1..the cap;
//   - a human statement has a wave, no per-rule validUntil, and a non-empty
//     sample whenever it renews anything (the sample's reviews are
//     checkSampleReviewed's job);
//   - an automated statement has no wave, no sample, and a validUntil on
//     every rule.
func checkRolePolicy(statement Statement, prior map[string]ruleCandidate) error {
	role, err := statementRole(statement)
	if err != nil {
		return fmt.Errorf("%w: V8: statement role", ErrRejected)
	}
	switch role {
	case RoleHuman:
		if statement.Wave < minWave || statement.Wave > maxWave {
			return fmt.Errorf("%w: V8: a human statement requires a wave", ErrRejected)
		}
		if len(statement.Rules) > 0 && len(statement.SampledForFullReview) == 0 {
			return fmt.Errorf("%w: V8: a human statement that renews rules requires a sample", ErrRejected)
		}
	case RoleAutomation:
		if statement.Wave != 0 || len(statement.SampledForFullReview) != 0 {
			return fmt.Errorf("%w: V8: an automated statement has no wave and no sample", ErrRejected)
		}
	}
	for _, ra := range statement.Rules {
		if (role == RoleAutomation) == (ra.ValidUntil == "") {
			return fmt.Errorf("%w: V8: rule %s per-rule validUntil does not match the statement's role", ErrRejected, ra.RuleID)
		}
		candidate, ok := prior[ra.RuleID]
		if !ok {
			return fmt.Errorf("%w: V8: renewed rule %s is not in the prior pack", ErrRejected, ra.RuleID)
		}
		if candidate.Fields.isMechanical() || hasRange(candidate.Fields.Range) || candidate.Fields.Evidence.State != "active" {
			return fmt.Errorf("%w: V8: rule %s is not renewable by reattestation", ErrRejected, ra.RuleID)
		}
		if candidate.Fields.record && role != RoleAutomation {
			return fmt.Errorf("%w: V8: record %s is renewed only by an automated statement", ErrRejected, ra.RuleID)
		}
		if ra.ConsecutiveBatchCycles < 1 || ra.ConsecutiveBatchCycles > maxConsecutiveBatchCycles {
			return fmt.Errorf("%w: V8: rule %s consecutiveBatchCycles is outside 1..%d", ErrRejected, ra.RuleID, maxConsecutiveBatchCycles)
		}
		sources := map[string]string{}
		for _, source := range candidate.Fields.Evidence.Sources {
			sources[source.ID] = source.Revision
		}
		if len(sources) == 0 || len(ra.Citations) != len(sources) {
			return fmt.Errorf("%w: V8: rule %s citations do not cover its sources one to one", ErrRejected, ra.RuleID)
		}
		seen := map[string]bool{}
		for _, citation := range ra.Citations {
			revision, known := sources[citation.SourceID]
			if !known || seen[citation.SourceID] || citation.PinnedCommit != revision {
				return fmt.Errorf("%w: V8: rule %s citation %s does not match its source", ErrRejected, ra.RuleID, citation.SourceID)
			}
			seen[citation.SourceID] = true
			switch citation.Class {
			case evidencerepin.ClassNoNewRelease, evidencerepin.ClassFileIdentical, evidencerepin.ClassSpanIdentical:
			default:
				return fmt.Errorf("%w: V8: rule %s citation %s is classified %s", ErrRejected, ra.RuleID, citation.SourceID, citation.Class)
			}
			switch citation.Baseline {
			case "", evidencerepin.BaselineLatest, evidencerepin.BaselineReleaseLine, evidencerepin.BaselineTagLine:
			default:
				return fmt.Errorf("%w: V8: rule %s citation %s has an unknown baseline", ErrRejected, ra.RuleID, citation.SourceID)
			}
			// Owner approval of automated renewal covers byte-identical
			// citations on their release line only.
			if role == RoleAutomation && (citation.Baseline != evidencerepin.BaselineReleaseLine || citation.BaselineLine == "" || citation.PinnedTag == "") {
				return fmt.Errorf("%w: V8: rule %s citation %s is not compared on its release line, which automated renewal requires", ErrRejected, ra.RuleID, citation.SourceID)
			}
		}
	}
	return nil
}

// checkIndependentWorklist compares the statement's citations with a
// worklist produced independently of the signing job. For every citation
// of every rule the statement renews, the independent worklist must hold
// exactly one citation for the same pack path, rule and source with the
// same class, pinned commit, compared commit and, for a line baseline
// (release_line or tag_line), the same baseline, line, pinned tag and
// compared tag, and a resolved line record of the same basis naming that
// tag and commit. Any missing or
// differing citation rejects the statement: the statement's own worklist
// is only as trustworthy as the job that signed it.
func checkIndependentWorklist(statement Statement, packPath string, independentRaw []byte) error {
	if len(independentRaw) > MaxWorklistBytes {
		return fmt.Errorf("%w: V9: independent worklist is too large", ErrRejected)
	}
	var wl evidencerepin.Worklist
	if err := json.Unmarshal(independentRaw, &wl); err != nil || (wl.Schema != evidencerepin.Schema && wl.Schema != evidencerepin.SchemaV1) {
		return fmt.Errorf("%w: V9: independent worklist does not decode", ErrRejected)
	}
	type key struct{ rule, source string }
	found := map[key][]evidencerepin.ClassResult{}
	for _, citation := range wl.Citations {
		if matchesPack(citation.RulePack, packPath) {
			k := key{citation.RuleID, citation.SourceID}
			found[k] = append(found[k], citation)
		}
	}
	for _, ra := range statement.Rules {
		for _, claimed := range ra.Citations {
			matches := found[key{ra.RuleID, claimed.SourceID}]
			if len(matches) != 1 {
				return fmt.Errorf("%w: V9: rule %s citation %s has no single counterpart in the independent worklist", ErrRejected, ra.RuleID, claimed.SourceID)
			}
			got := matches[0]
			if got.Class != claimed.Class || got.OldCommit != claimed.PinnedCommit || got.NewCommit != claimed.ComparedCommit {
				return fmt.Errorf("%w: V9: rule %s citation %s differs from the independent worklist", ErrRejected, ra.RuleID, claimed.SourceID)
			}
			if isLineBaseline(claimed.Baseline) {
				if got.Baseline != claimed.Baseline || got.BaselineLine != claimed.BaselineLine || got.PinnedTag != claimed.PinnedTag || got.BaselineTag != claimed.ComparedTag {
					return fmt.Errorf("%w: V9: rule %s citation %s baseline differs from the independent worklist", ErrRejected, ra.RuleID, claimed.SourceID)
				}
				if !lineBaselineVerified(got, wl.Lines) {
					return fmt.Errorf("%w: V9: rule %s citation %s is not backed by a line record in the independent worklist", ErrRejected, ra.RuleID, claimed.SourceID)
				}
			} else if isLineBaseline(got.Baseline) {
				return fmt.Errorf("%w: V9: rule %s citation %s baseline differs from the independent worklist", ErrRejected, ra.RuleID, claimed.SourceID)
			}
		}
	}
	return nil
}
