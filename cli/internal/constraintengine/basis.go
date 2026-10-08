// SPDX-License-Identifier: AGPL-3.0-only

package constraintengine

import (
	"encoding/json"
	"fmt"
)

// Evidence bases say how a rule was produced, and two of them limit what the
// rule may decide:
//
//   - reviewed, mechanical and empirical rules may block and may pass;
//   - a consensus rule (two independent model readings whose citations were
//     verified) may block but never passes: where it would pass, its claim
//     is NO_KNOWN_ISSUE, and in scope completeness that claim is applicable
//     but not verified, so the aggregate stays UNKNOWN
//     (CONSENSUS_ONLY_SCOPE);
//   - a lead rule (one unverified model reading) never blocks and never
//     passes: where it would block, its claim is NOTICE (LEAD_NOT_VERIFIED);
//     where it would pass, NO_KNOWN_ISSUE. Lead rules are verdict-neutral
//     like one-way notices: counted in leadRules and never part of the
//     applicable set.
//
// Documents holding a consensus or lead rule carry RulesSchemaBasis and are
// evaluated under their own engine and scope contracts, so binaries that
// predate these bases reject them, and every other document keeps its
// schema, digest and replay bytes.

const (
	// BasisEmpirical marks a rule whose behaviour was reproduced with real
	// upstream artefacts. It decides like a reviewed rule.
	BasisEmpirical = "empirical"
	// BasisConsensus marks a rule two independent model readings agree on,
	// with every citation verified. It may block and never passes.
	BasisConsensus = "consensus"
	// BasisLead marks an unverified model reading. It never blocks and never
	// passes.
	BasisLead = "lead"

	// RulesSchemaBasis is carried by, and only by, a rule document holding
	// at least one consensus or lead rule. It also admits every feature of
	// the lower schemas.
	RulesSchemaBasis = "prufyx.io/deterministic-constraint-rules/v1alpha5"

	// StatusNoKnownIssue is the claim status of a consensus or lead rule
	// that would otherwise pass. It is not PASS and never counts as one.
	StatusNoKnownIssue = "NO_KNOWN_ISSUE"
	// ReasonConsensusNoKnownIssue is the reason of a consensus NO_KNOWN_ISSUE
	// claim.
	ReasonConsensusNoKnownIssue = "CONSENSUS_NO_KNOWN_ISSUE"
	// ReasonLeadNotVerified is the reason of a lead NOTICE claim.
	ReasonLeadNotVerified = "LEAD_NOT_VERIFIED"
	// ReasonLeadNoKnownIssue is the reason of a lead NO_KNOWN_ISSUE claim.
	ReasonLeadNoKnownIssue = "LEAD_NO_KNOWN_ISSUE"

	// ScopeContractVersionBasis adds consensus and lead semantics to the
	// notice scope contract.
	ScopeContractVersionBasis = "scope-completeness-contract-v4"

	unresolvedConsensusOnlyScope = "CONSENSUS_ONLY_SCOPE"

	basisSemantics = "basis:" + BasisConsensus + ";may-block;never-pass;pass-becomes:" + StatusNoKnownIssue + ";reason:" + ReasonConsensusNoKnownIssue + ";applicable-not-verified\nbasis:" + BasisLead + ";never-blocks;never-passes;block-becomes:" + StatusNotice + ";reason:" + ReasonLeadNotVerified + ";pass-becomes:" + StatusNoKnownIssue + ";reason:" + ReasonLeadNoKnownIssue + ";verdict-neutral;excluded-from-applicable-set;counted-in:leadRules"
)

// Bases is the closed evidence basis vocabulary, in trust order.
func Bases() []string {
	return []string{BasisReviewed, BasisMechanical, BasisEmpirical, BasisConsensus, BasisLead}
}

// KnownBasis reports whether basis is a token of the closed vocabulary. The
// empty string is not a token; EffectiveBasis resolves it to reviewed.
func KnownBasis(basis string) bool {
	for _, known := range Bases() {
		if basis == known {
			return true
		}
	}
	return false
}

// BasisMayBlock reports whether a rule of this basis can produce BLOCKED.
// Absent means reviewed. An unknown token may do nothing.
func BasisMayBlock(basis string) bool {
	switch EffectiveBasis(basis) {
	case BasisReviewed, BasisMechanical, BasisEmpirical, BasisConsensus:
		return true
	}
	return false
}

// BasisMayPass reports whether a rule of this basis can produce PASS or
// contribute to a scope-complete pass. Absent means reviewed. Only evidence
// that does not depend on a model's reading may pass.
func BasisMayPass(basis string) bool {
	switch EffectiveBasis(basis) {
	case BasisReviewed, BasisMechanical, BasisEmpirical:
		return true
	}
	return false
}

// BasisBlockOnly reports whether a rule of this basis may block but never
// pass (consensus). A change gate uses it to admit such a rule only when it
// tightens.
func BasisBlockOnly(basis string) bool {
	return BasisMayBlock(basis) && !BasisMayPass(basis)
}

// BasisVerdictNeutral reports whether a rule of this basis never takes part
// in any verdict (lead).
func BasisVerdictNeutral(basis string) bool {
	return KnownBasis(EffectiveBasis(basis)) && !BasisMayBlock(basis) && !BasisMayPass(basis)
}

// usesBasisSemantics reports whether a parsed rule needs the basis contract.
func (r rule) usesBasisSemantics() bool {
	return r.Evidence.Basis == BasisConsensus || r.Evidence.Basis == BasisLead
}

// verdictNeutral reports whether a parsed rule is left out of scope
// completeness: a one-way notice or a lead.
func (r rule) verdictNeutral() bool {
	return r.usesNoticeOperator() || r.Evidence.Basis == BasisLead
}

// AnyBasisRule reports whether any raw rule declares a consensus or lead
// basis, which needs RulesSchemaBasis.
func AnyBasisRule(rules []json.RawMessage) (bool, error) {
	for _, raw := range rules {
		basis, err := RawRuleBasis(raw)
		if err != nil {
			return false, err
		}
		if basis == BasisConsensus || basis == BasisLead {
			return true, nil
		}
	}
	return false, nil
}

// RawRuleBasis returns the effective evidence basis of one raw rule: the
// declared token, or reviewed when the rule declares none. It reads the
// field only; ParseRuleSet remains the authority on validity.
func RawRuleBasis(raw json.RawMessage) (string, error) {
	var shape map[string]json.RawMessage
	if err := json.Unmarshal(raw, &shape); err != nil {
		return "", fmt.Errorf("rule shape: %w", ErrInvalid)
	}
	var evidence map[string]json.RawMessage
	if rawEvidence, ok := shape["evidence"]; ok {
		if err := json.Unmarshal(rawEvidence, &evidence); err != nil {
			return "", fmt.Errorf("rule evidence shape: %w", ErrInvalid)
		}
	}
	basis := ""
	if rawBasis, ok := evidence["basis"]; ok {
		if err := json.Unmarshal(rawBasis, &basis); err != nil {
			return "", fmt.Errorf("rule evidence basis: %w", ErrInvalid)
		}
	}
	return EffectiveBasis(basis), nil
}

// RawRuleVerdictNeutral reports whether one raw rule never takes part in a
// verdict: a one-way notice or a lead.
func RawRuleVerdictNeutral(raw json.RawMessage) (bool, error) {
	notice, err := AnyNoticeRule([]json.RawMessage{raw})
	if err != nil || notice {
		return notice, err
	}
	basis, err := RawRuleBasis(raw)
	if err != nil {
		return false, err
	}
	return basis == BasisLead, nil
}

// validateBasisRule refuses the combinations the basis contract does not
// define: a one-way notice is already verdict-neutral and carries no
// consensus or lead basis.
func validateBasisRule(r rule) error {
	if r.usesBasisSemantics() && r.usesNoticeOperator() {
		return fmt.Errorf("a one-way notice cannot carry a consensus or lead basis: %w", ErrInvalid)
	}
	return nil
}

// applyBasisSemantics is the single place where a basis changes a claim. A
// consensus claim never passes; a lead claim never blocks or passes. Every
// other basis, and every UNKNOWN claim, is unchanged.
func applyBasisSemantics(r rule, claim Claim) Claim {
	switch r.Evidence.Basis {
	case BasisConsensus:
		if claim.Status == "PASS" {
			claim.Status, claim.ReasonCode = StatusNoKnownIssue, ReasonConsensusNoKnownIssue
		}
	case BasisLead:
		switch claim.Status {
		case "BLOCKED":
			claim.Status, claim.ReasonCode = StatusNotice, ReasonLeadNotVerified
			// Matched members disclose a BLOCKED set claim only.
			claim.MatchedMembers = nil
		case "PASS":
			claim.Status, claim.ReasonCode = StatusNoKnownIssue, ReasonLeadNoKnownIssue
		}
	}
	return claim
}

// engineContractDigestBasis identifies the contract for rule documents that
// hold a consensus or lead rule. It extends the notice contract with the
// basis semantics and the NO_KNOWN_ISSUE status.
func engineContractDigestBasis() string {
	return digestBytes([]byte(EngineVersion + "\n" + InputSchema + "\n" + RulesSchemaBasis + "\n" + ReportSchema + "\n" + InputAuthority + "\n" + RulesAuthority + "\nappliesWhen\ncomparison:eq\ncomparison:gte\ncomparison:lte\ncomparison:lt\nforbid_predicate_value\nrequire_component_version\nrequire_intermediate_version\nforbid_target_version\n" + OperatorForbidSetMember + "\nfact:" + string(FactSet) + "\nclaim:matchedMembers\nreason:" + reasonSetFactIncomplete + "\n" + setMemberPolicy + "\n" + OperatorNoticeOneWay + "\nclaim:status:" + StatusNotice + "\nreason:" + ReasonOneWayTransition + "\n" + noticeNeutrality + "\nclaim:status:" + StatusNoKnownIssue + "\n" + basisSemantics + "\nsubject:exact\nsubject:range\nclaim:subjectMatch\n" + rangeWidthPolicy + "\n" + basisVocabulary()))
}

// EngineContractDigestBasis exposes the contract identity for rule documents
// that hold a consensus or lead rule.
func EngineContractDigestBasis() string { return engineContractDigestBasis() }

// scopeContractDigestBasis adds the consensus and lead rules to the notice
// scope vocabulary. It is used only with the basis engine contract.
func scopeContractDigestBasis() string {
	return digestBytes([]byte(ScopeContractVersionBasis + "\n" + ScopeDeclaration + "\n" + CorpusAttestation + "\n" + AssessmentUnknown + "\n" + AssessmentBlocked + "\n" + AssessmentScopeCompletePass + "\n" + ApplicabilityApplicable + "\n" + ApplicabilityNotApplicable + "\n" + ApplicabilityUndetermined + "\n" + omissionWholeUpgradeScoped + "\n" + unresolvedTransitionNotAnchor + "\n" + noticeNeutrality + "\n" + basisSemantics + "\nnotEvaluated:" + ApplicabilityApplicable + ":" + ReasonConsensusNoKnownIssue + "\nunresolved:" + unresolvedConsensusOnlyScope))
}

// ScopeContractDigestBasis exposes the basis scope-completeness identity.
func ScopeContractDigestBasis() string { return scopeContractDigestBasis() }

// validBasisClaims binds the basis semantics to the basis contract: a
// consensus or lead claim, and a NO_KNOWN_ISSUE claim, is legal only under
// it; a consensus claim is never PASS or NOTICE; a lead claim is never PASS
// or BLOCKED; NO_KNOWN_ISSUE comes only from a consensus or lead rule with
// current evidence and its fixed reason code.
func validBasisClaims(report Report) bool {
	// The severity contract admits every feature of the basis contract.
	basisContract := report.EngineContractDigest == engineContractDigestBasis() || atLeastSeverityContract(report.EngineContractDigest)
	for _, claim := range report.Claims {
		consensus, lead := claim.EvidenceBasis == BasisConsensus, claim.EvidenceBasis == BasisLead
		if (consensus || lead) && (!basisContract || claim.IsNotice()) {
			return false
		}
		switch {
		case consensus && (claim.Status == "PASS" || claim.Status == StatusNotice):
			return false
		case lead && (claim.Status == "PASS" || claim.Status == "BLOCKED"):
			return false
		case lead && claim.Status == StatusNotice && claim.ReasonCode != ReasonLeadNotVerified:
			return false
		}
		if claim.Status != StatusNoKnownIssue {
			continue
		}
		if !basisContract || claim.EvidenceFreshness != "current" || claim.MatchedMembers != nil {
			return false
		}
		if !(consensus && claim.ReasonCode == ReasonConsensusNoKnownIssue) && !(lead && claim.ReasonCode == ReasonLeadNoKnownIssue) {
			return false
		}
	}
	return true
}

// IsLead reports whether the claim comes from a lead rule.
func (c Claim) IsLead() bool { return c.EvidenceBasis == BasisLead }

// IsVerdictNeutral reports whether the claim never takes part in any
// verdict, whatever its status: a one-way notice or a lead. Exit codes,
// batch outcomes and summaries skip such claims.
func (c Claim) IsVerdictNeutral() bool { return c.IsNotice() || c.IsLead() }

// ReliesOnConsensus reports whether the claim's outcome rests on a
// consensus rule: a consensus BLOCKED or NO_KNOWN_ISSUE claim.
func (c Claim) ReliesOnConsensus() bool {
	return c.EvidenceBasis == BasisConsensus && (c.Status == "BLOCKED" || c.Status == StatusNoKnownIssue)
}

// ConsensusNote is the headline note of a report whose findings rely on
// model consensus. ok is false when none does.
func ConsensusNote(claims []Claim) (note string, ok bool) {
	count := 0
	for _, claim := range claims {
		if claim.ReliesOnConsensus() {
			count++
		}
	}
	switch count {
	case 0:
		return "", false
	case 1:
		return "1 finding relies on model consensus", true
	}
	return fmt.Sprintf("%d findings rely on model consensus", count), true
}

const (
	leadLinePrefix  = "unverified lead (does not block): "
	leadCheckPrefix = "worth checking: "
)

// leadLines is the human statement of a lead claim: a lead that would have
// blocked says so as an unverified lead with its next action; any other
// lead claim prints nothing, because an unverified reading that found
// nothing says nothing.
func (c Claim) leadLines() []string {
	if c.Status != StatusNotice {
		return nil
	}
	return append(prefixedLines(leadLinePrefix, c.RuleID), prefixedLines(leadCheckPrefix, c.NextAction)...)
}
