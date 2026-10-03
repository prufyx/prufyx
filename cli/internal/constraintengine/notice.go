// SPDX-License-Identifier: AGPL-3.0-only

package constraintengine

import (
	"encoding/json"
	"fmt"
	"strings"
)

// A one-way notice states that a reviewed transition cannot be rolled back
// and carries, in its nextAction, the reviewed text of what to do before the
// upgrade. It is not a verdict:
//
//   - the notice_one_way operator yields claim status NOTICE when its subject
//     matched, its evidence is current and its appliesWhen conditions hold;
//     every other path keeps the usual UNKNOWN reasons;
//   - notice rules are left out of scope completeness entirely: they are
//     counted once in noticeRules and never enter the applicable set, so the
//     aggregate is exactly what it would be without them, and a component
//     whose only rules are notices still has no evaluated rule;
//   - the absence of a notice says nothing: no output may present it as a
//     statement that a rollback is possible.
//
// Documents that use the operator carry RulesSchemaNotice and are evaluated
// under their own engine and scope contracts, so binaries that predate the
// operator reject them and every document that does not use it keeps its
// schema, digest and replay bytes.

const (
	// RulesSchemaNotice is carried by, and only by, a rule document holding
	// at least one notice_one_way rule. It may also hold reviewed ranges and
	// forbid_set_member rules.
	RulesSchemaNotice = "prufyx.io/deterministic-constraint-rules/v1alpha4"

	// OperatorNoticeOneWay is the verdict-neutral one-way notice operator.
	OperatorNoticeOneWay = "notice_one_way"
	// StatusNotice is the claim status of a matched, current notice rule.
	StatusNotice = "NOTICE"
	// ReasonOneWayTransition is the only reason code a notice rule may carry.
	ReasonOneWayTransition = "ONE_WAY_TRANSITION"

	// ScopeContractVersionNotice adds the exclusion of notice rules from
	// scope completeness to the ranged scope contract.
	ScopeContractVersionNotice = "scope-completeness-contract-v3"

	noticeNeutrality = "notice:verdict-neutral;excluded-from-applicable-set;counted-in:noticeRules"

	noticeLinePrefix        = "cannot be rolled back: "
	noticeBeforePrefix      = "before you upgrade: "
	noticeUnresolvedPrefix  = "one-way notice not established: "
	noticeUnresolvedActions = "next action: "
)

// usesNoticeOperator reports whether a parsed rule needs the notice contract.
func (r rule) usesNoticeOperator() bool {
	return r.Operator == OperatorNoticeOneWay
}

// validateNoticeRule checks the structure of a notice_one_way rule: no
// constraint of its own, the fixed reason code, and a reviewed nextAction
// that never words the upgrade as safe.
func validateNoticeRule(r rule) error {
	if r.Condition != nil || r.SetCondition != nil || r.Dependency != nil || r.Intermediate != "" {
		return fmt.Errorf("notice structure: %w", ErrInvalid)
	}
	if r.ReasonCode != ReasonOneWayTransition {
		return fmt.Errorf("notice reason code: %w", ErrInvalid)
	}
	// Printable ASCII only, so no look-alike letter, invisible character or
	// direction override can hide a word; then neither the text nor the rule
	// id may contain "safe" in any case.
	if !printableASCII(r.NextAction) || !printableASCII(r.ID) {
		return fmt.Errorf("notice text and id must be printable ASCII: %w", ErrInvalid)
	}
	if strings.Contains(strings.ToLower(r.NextAction), "safe") || strings.Contains(strings.ToLower(r.ID), "safe") {
		return fmt.Errorf("notice text and id must not contain the word safe: %w", ErrInvalid)
	}
	return nil
}

func printableASCII(value string) bool {
	for index := 0; index < len(value); index++ {
		if value[index] < 0x20 || value[index] > 0x7e {
			return false
		}
	}
	return true
}

// AnyNoticeRule reports whether any raw rule uses notice_one_way.
func AnyNoticeRule(rules []json.RawMessage) (bool, error) {
	for _, raw := range rules {
		var shape map[string]json.RawMessage
		if err := json.Unmarshal(raw, &shape); err != nil {
			return false, fmt.Errorf("rule shape: %w", ErrInvalid)
		}
		var operator string
		if raw, ok := shape["operator"]; ok && json.Unmarshal(raw, &operator) == nil && operator == OperatorNoticeOneWay {
			return true, nil
		}
	}
	return false, nil
}

// engineContractDigestNotice identifies the contract for rule documents that
// use notice_one_way. It extends the set contract with the operator, the
// NOTICE status, its reason code and the neutrality rule.
func engineContractDigestNotice() string {
	return digestBytes([]byte(EngineVersion + "\n" + InputSchema + "\n" + RulesSchemaNotice + "\n" + ReportSchema + "\n" + InputAuthority + "\n" + RulesAuthority + "\nappliesWhen\ncomparison:eq\ncomparison:gte\ncomparison:lte\ncomparison:lt\nforbid_predicate_value\nrequire_component_version\nrequire_intermediate_version\nforbid_target_version\n" + OperatorForbidSetMember + "\nfact:" + string(FactSet) + "\nclaim:matchedMembers\nreason:" + reasonSetFactIncomplete + "\n" + setMemberPolicy + "\n" + OperatorNoticeOneWay + "\nclaim:status:" + StatusNotice + "\nreason:" + ReasonOneWayTransition + "\n" + noticeNeutrality + "\nsubject:exact\nsubject:range\nclaim:subjectMatch\n" + rangeWidthPolicy + "\n" + basisVocabulary()))
}

// EngineContractDigestNotice exposes the contract identity for rule
// documents that use notice_one_way.
func EngineContractDigestNotice() string { return engineContractDigestNotice() }

// scopeContractDigestNotice adds the notice exclusion to the ranged scope
// vocabulary. It is used only with the notice engine contract.
func scopeContractDigestNotice() string {
	return digestBytes([]byte(ScopeContractVersionNotice + "\n" + ScopeDeclaration + "\n" + CorpusAttestation + "\n" + AssessmentUnknown + "\n" + AssessmentBlocked + "\n" + AssessmentScopeCompletePass + "\n" + ApplicabilityApplicable + "\n" + ApplicabilityNotApplicable + "\n" + ApplicabilityUndetermined + "\n" + omissionWholeUpgradeScoped + "\n" + unresolvedTransitionNotAnchor + "\n" + noticeNeutrality))
}

// ScopeContractDigestNotice exposes the notice scope-completeness identity.
func ScopeContractDigestNotice() string { return scopeContractDigestNotice() }

// validNoticeClaims binds the NOTICE status to the notice operator and the
// notice contract: a NOTICE claim comes only from a notice_one_way rule with
// current evidence and the fixed reason code, a notice_one_way claim is never
// PASS or BLOCKED, and either is legal only under the notice contract.
func validNoticeClaims(report Report) bool {
	for _, claim := range report.Claims {
		notice := claim.IsNotice()
		if notice && report.EngineContractDigest != engineContractDigestNotice() {
			return false
		}
		if claim.Status == StatusNotice && (!notice || claim.ReasonCode != ReasonOneWayTransition || claim.EvidenceFreshness != "current") {
			return false
		}
		if notice && claim.Status != StatusNotice && claim.Status != "UNKNOWN" {
			return false
		}
	}
	return true
}

// IsNotice reports whether the claim comes from a notice_one_way rule. Such a
// claim is informational whatever its status: it never decides PASS, BLOCKED
// or UNKNOWN of any aggregate.
func (c Claim) IsNotice() bool {
	return c.Operator == OperatorNoticeOneWay
}

// NoticeLines is the human statement of a notice_one_way claim. ok is false
// for every other claim, whose human output is unchanged. A NOTICE claim
// yields the rule and its reviewed "before you upgrade" text; a notice rule
// that does not apply to the declared transition yields no line, because the
// absence of a notice says nothing; any other notice claim says that the
// notice could not be established and why. No line states that a rollback
// is possible. Every line is at most 256 bytes.
func (c Claim) NoticeLines() (lines []string, ok bool) {
	if !c.IsNotice() {
		return nil, false
	}
	if c.Status == StatusNotice {
		return append([]string{noticeLinePrefix + c.RuleID}, prefixedLines(noticeBeforePrefix, c.NextAction)...), true
	}
	if _, excluded := exclusionReasons[c.ReasonCode]; excluded {
		return nil, true
	}
	head := []string{noticeUnresolvedPrefix + c.RuleID + " (" + c.ReasonCode + ")"}
	if len(head[0]) > maxStringBytes {
		head = []string{noticeUnresolvedPrefix + c.RuleID, "reason: " + c.ReasonCode}
	}
	return append(head, prefixedLines(noticeUnresolvedActions, c.NextAction)...), true
}

// prefixedLines keeps prefix and text on one line when that fits in 256
// bytes, and otherwise puts the text on its own line.
func prefixedLines(prefix, text string) []string {
	if len(prefix)+len(text) <= maxStringBytes {
		return []string{prefix + text}
	}
	return []string{strings.TrimSuffix(prefix, " "), text}
}
