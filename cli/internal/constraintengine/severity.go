// SPDX-License-Identifier: AGPL-3.0-only

package constraintengine

import (
	"encoding/json"
	"fmt"
	"strings"
)

// A support-range rule is a require_component_version rule that carries
// severity "unsupported". It states that the declared combination is
// outside a documented support range, which is not the same as broken:
//
//   - only a reviewed, mechanical or empirical rule may carry a severity;
//   - when the dependency is present and the comparison holds, the claim is
//     PASS, exactly as without the severity;
//   - when the dependency is present and the comparison fails, the claim is
//     UNSUPPORTED with the rule's own reason code, never BLOCKED;
//   - every other path (missing dependency, stale or withdrawn evidence,
//     subject or applicability not matched) keeps its usual UNKNOWN reason.
//
// In scope completeness an UNSUPPORTED claim is applicable but not
// verified: the aggregate is never SCOPE_COMPLETE_PASS from it and never
// BLOCKED from it (unresolved UNSUPPORTED_COMBINATION). A hard
// incompatibility stays an ordinary blocking rule without a severity; the
// field never changes a rule that does not carry it.
//
// Documents holding a support-range rule carry RulesSchemaSeverity and are
// evaluated under their own engine and scope contracts, so binaries that
// predate the field reject them, and every other document keeps its schema,
// digest and replay bytes.

const (
	// RulesSchemaSeverity is carried by, and only by, a rule document holding
	// at least one rule with a severity. It also admits every feature of the
	// lower schemas.
	RulesSchemaSeverity = "prufyx.io/deterministic-constraint-rules/v1alpha6"

	// SeverityUnsupported is the only rule severity: a failed support-range
	// check is reported as UNSUPPORTED instead of BLOCKED.
	SeverityUnsupported = "unsupported"

	// StatusUnsupported is the claim status of a support-range rule whose
	// dependency is outside the documented range. It is neither PASS nor
	// BLOCKED and never counts as either.
	StatusUnsupported = "UNSUPPORTED"

	// ScopeContractVersionSeverity adds support-range rules to the basis
	// scope contract.
	ScopeContractVersionSeverity = "scope-completeness-contract-v5"

	// UnresolvedUnsupportedCombination is the unresolved scope reason when
	// an applicable claim is UNSUPPORTED.
	UnresolvedUnsupportedCombination = "UNSUPPORTED_COMBINATION"

	severitySemantics = "severity:" + SeverityUnsupported + ";operator:require_component_version;comparison-fails-becomes:" + StatusUnsupported + ";reason:rule;never-pass;never-blocks;applicable-not-verified;unresolved:" + UnresolvedUnsupportedCombination + ";basis:" + BasisLead + ":refused;basis:" + BasisConsensus + ":refused"
)

// reservedSeverityReasons are reason codes the engine itself issues. A
// support-range rule may not carry one, so an UNSUPPORTED claim can never be
// mistaken for an engine outcome and never carries an exclusion reason.
var reservedSeverityReasons = map[string]struct{}{
	ReasonOneWayTransition:           {},
	ReasonConsensusNoKnownIssue:      {},
	ReasonLeadNotVerified:            {},
	ReasonLeadNoKnownIssue:           {},
	reasonSetFactIncomplete:          {},
	unresolvedComponentNotAttested:   {},
	unresolvedApplicability:          {},
	unresolvedNoApplicableRule:       {},
	unresolvedTransitionNotAnchor:    {},
	unresolvedConsensusOnlyScope:     {},
	UnresolvedUnsupportedCombination: {},
}

// reservedSeverityReason reports whether a reason code belongs to the
// engine: every RULE_ code and every named engine reason.
func reservedSeverityReason(reason string) bool {
	if strings.HasPrefix(reason, "RULE_") {
		return true
	}
	_, reserved := reservedSeverityReasons[reason]
	return reserved
}

// usesSeverity reports whether a parsed rule needs the severity contract.
func (r rule) usesSeverity() bool { return r.Severity != "" }

// validateSeverityRule checks the severity of one rule: absent, or
// "unsupported" on a require_component_version rule that is neither a
// consensus nor a lead rule and whose reason code is its own.
func validateSeverityRule(r rule) error {
	if !r.usesSeverity() {
		return nil
	}
	if r.Severity != SeverityUnsupported {
		return fmt.Errorf("severity: %w", ErrInvalid)
	}
	if r.Operator != "require_component_version" {
		return fmt.Errorf("severity is only valid for require_component_version: %w", ErrInvalid)
	}
	// A lead never blocks or passes, and a consensus rule may only block:
	// a severity would remove its only decisive outcome, and an unverified
	// model reading would read as a documented support range. Neither may
	// carry a severity.
	if r.Evidence.Basis == BasisLead || r.Evidence.Basis == BasisConsensus {
		return fmt.Errorf("a consensus or lead rule cannot carry a severity: %w", ErrInvalid)
	}
	if reservedSeverityReason(r.ReasonCode) {
		return fmt.Errorf("a support-range rule needs its own reason code: %w", ErrInvalid)
	}
	return nil
}

// AnySeverityRule reports whether any raw rule declares a severity, which
// needs RulesSchemaSeverity. It reads the key only; ParseRuleSet remains the
// authority on validity.
func AnySeverityRule(rules []json.RawMessage) (bool, error) {
	for _, raw := range rules {
		var shape map[string]json.RawMessage
		if err := json.Unmarshal(raw, &shape); err != nil {
			return false, fmt.Errorf("rule shape: %w", ErrInvalid)
		}
		if _, ok := shape["severity"]; ok {
			return true, nil
		}
	}
	return false, nil
}

// applySeverity turns the BLOCKED claim of a support-range rule into
// UNSUPPORTED. It is called only where require_component_version found the
// dependency outside the reviewed bound.
func applySeverity(r rule, claim Claim) Claim {
	if r.Severity == SeverityUnsupported {
		claim.Status = StatusUnsupported
		return claim
	}
	claim.Status = "BLOCKED"
	return claim
}

// engineContractDigestSeverity identifies the contract for rule documents
// that hold a support-range rule. It extends the basis contract with the
// severity field and the UNSUPPORTED status.
func engineContractDigestSeverity() string {
	return digestBytes([]byte(EngineVersion + "\n" + InputSchema + "\n" + RulesSchemaSeverity + "\n" + ReportSchema + "\n" + InputAuthority + "\n" + RulesAuthority + "\nappliesWhen\ncomparison:eq\ncomparison:gte\ncomparison:lte\ncomparison:lt\nforbid_predicate_value\nrequire_component_version\nrequire_intermediate_version\nforbid_target_version\n" + OperatorForbidSetMember + "\nfact:" + string(FactSet) + "\nclaim:matchedMembers\nreason:" + reasonSetFactIncomplete + "\n" + setMemberPolicy + "\n" + OperatorNoticeOneWay + "\nclaim:status:" + StatusNotice + "\nreason:" + ReasonOneWayTransition + "\n" + noticeNeutrality + "\nclaim:status:" + StatusNoKnownIssue + "\n" + basisSemantics + "\nclaim:status:" + StatusUnsupported + "\nclaim:severity\n" + severitySemantics + "\nsubject:exact\nsubject:range\nclaim:subjectMatch\n" + rangeWidthPolicy + "\n" + basisVocabulary()))
}

// EngineContractDigestSeverity exposes the contract identity for rule
// documents that hold a support-range rule.
func EngineContractDigestSeverity() string { return engineContractDigestSeverity() }

// scopeContractDigestSeverity adds support-range rules to the basis scope
// vocabulary. It is used only with the severity engine contract.
func scopeContractDigestSeverity() string {
	return digestBytes([]byte(ScopeContractVersionSeverity + "\n" + ScopeDeclaration + "\n" + CorpusAttestation + "\n" + AssessmentUnknown + "\n" + AssessmentBlocked + "\n" + AssessmentScopeCompletePass + "\n" + ApplicabilityApplicable + "\n" + ApplicabilityNotApplicable + "\n" + ApplicabilityUndetermined + "\n" + omissionWholeUpgradeScoped + "\n" + unresolvedTransitionNotAnchor + "\n" + noticeNeutrality + "\n" + basisSemantics + "\nnotEvaluated:" + ApplicabilityApplicable + ":" + ReasonConsensusNoKnownIssue + "\nunresolved:" + unresolvedConsensusOnlyScope + "\n" + severitySemantics + "\nnotEvaluated:" + ApplicabilityApplicable + ":claim-reason-of:" + StatusUnsupported + "\nunresolved:" + UnresolvedUnsupportedCombination))
}

// ScopeContractDigestSeverity exposes the severity scope-completeness
// identity.
func ScopeContractDigestSeverity() string { return scopeContractDigestSeverity() }

// validSeverityClaims binds the severity semantics to the severity
// contract: a claim that discloses a severity, and an UNSUPPORTED claim, is
// legal only under it; a severity claim comes from require_component_version
// and is never BLOCKED or NOTICE and never a consensus or lead claim; UNSUPPORTED comes only
// from a severity claim with current evidence and a reason code of its own.
func validSeverityClaims(report Report) bool {
	severityContract := atLeastSeverityContract(report.EngineContractDigest)
	for _, claim := range report.Claims {
		if claim.Severity != "" {
			if !severityContract || claim.Severity != SeverityUnsupported || claim.Operator != "require_component_version" || claim.IsLead() || claim.EvidenceBasis == BasisConsensus || claim.Status == "BLOCKED" || claim.Status == StatusNotice || claim.MatchedMembers != nil {
				return false
			}
		}
		if claim.Status != StatusUnsupported {
			continue
		}
		if !severityContract || claim.Severity != SeverityUnsupported || claim.EvidenceFreshness != "current" || reservedSeverityReason(claim.ReasonCode) {
			return false
		}
	}
	return true
}

// IsUnsupported reports whether the claim found a combination outside its
// documented support range. Such a claim is neither a pass nor a blocker.
func (c Claim) IsUnsupported() bool { return c.Status == StatusUnsupported }

// UnsupportedNote is the headline note of a report holding UNSUPPORTED
// claims. ok is false when none does.
func UnsupportedNote(claims []Claim) (note string, ok bool) {
	count := 0
	for _, claim := range claims {
		if claim.IsUnsupported() && !claim.IsVerdictNeutral() {
			count++
		}
	}
	switch count {
	case 0:
		return "", false
	case 1:
		return "1 component combination is outside its documented support range (not verified, not shown to be broken)", true
	}
	return fmt.Sprintf("%d component combinations are outside their documented support range (not verified, not shown to be broken)", count), true
}
