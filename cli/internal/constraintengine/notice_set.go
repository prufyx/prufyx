// SPDX-License-Identifier: AGPL-3.0-only

package constraintengine

import (
	"encoding/json"
	"fmt"
	"strings"
)

// A set notice is a verdict-neutral statement about members of a declared
// set fact on a chart hop, for a fact that changes what an upgrade does
// without making Helm refuse it (a values key the later chart no longer
// reads, a default that changed). It is never a verdict:
//
//   - notice_set_member_present yields NOTICE when at least one listed
//     member is present in the declared set, whether or not the set is
//     declared complete (presence is decisive, as for forbid_set_member),
//     disclosing the present members in matchedMembers. With no listed
//     member present it is UNKNOWN: RULE_SET_FACT_INCOMPLETE over an
//     incomplete set, RULE_NOTICE_NOT_APPLICABLE over a complete one;
//   - notice_set_member_absent yields NOTICE only when the set is declared
//     complete and at least one listed member is absent, disclosing the
//     absent members in missingMembers; RULE_NOTICE_NOT_APPLICABLE when the
//     complete set holds every listed member; RULE_SET_FACT_INCOMPLETE over
//     an incomplete set, because absence is never inferred from a partial
//     set;
//   - a missing or undeclared fact is RULE_FACT_UNAVAILABLE for both.
//
// Both are counted in noticeRules exactly like notice_one_way and never
// enter the applicable set, so the aggregate and scope completeness are
// what they would be without them. RULE_NOTICE_NOT_APPLICABLE prints
// nothing: the absence of a notice says nothing.
//
// A set notice has a chart subject, a set condition and the rule's own
// reason code (never one the engine issues); it carries no condition,
// dependency, intermediate, range, crossing, severity, consensus or lead
// basis. Its text and id are printable ASCII and never word the upgrade as
// safe or as a verdict ("block", "refuse", "must").
//
// Documents holding one carry RulesSchemaChartNotice and are evaluated
// under their own engine and scope contracts, so binaries that predate the
// operators reject them, and every other document keeps its schema, digest
// and replay bytes.

const (
	// RulesSchemaChartNotice is carried by, and only by, a rule document
	// holding at least one set notice. It also admits every feature of the
	// lower schemas.
	RulesSchemaChartNotice = "prufyx.io/deterministic-constraint-rules/v1alpha9"

	// OperatorNoticeSetMemberPresent notices listed members present in a
	// declared set.
	OperatorNoticeSetMemberPresent = "notice_set_member_present"
	// OperatorNoticeSetMemberAbsent notices listed members absent from a
	// declared complete set.
	OperatorNoticeSetMemberAbsent = "notice_set_member_absent"

	// ReasonNoticeNotApplicable is the UNKNOWN reason of a set notice whose
	// complete set gives it nothing to say. It prints nothing.
	ReasonNoticeNotApplicable = "RULE_NOTICE_NOT_APPLICABLE"

	// ScopeContractVersionChartNotice adds the set notices to the chart
	// scope contract.
	ScopeContractVersionChartNotice = "scope-completeness-contract-v8"

	chartNoticeSemantics = "set-notice:" + OperatorNoticeSetMemberPresent + ":hit:NOTICE:matchedMembers:any-completeness" +
		":complete-no-hit:UNKNOWN:" + ReasonNoticeNotApplicable + ":incomplete-no-hit:UNKNOWN:" + reasonSetFactIncomplete +
		";" + OperatorNoticeSetMemberAbsent + ":complete-member-absent:NOTICE:missingMembers:complete-all-present:UNKNOWN:" + ReasonNoticeNotApplicable +
		":incomplete:UNKNOWN:" + reasonSetFactIncomplete +
		";fact-unavailable:UNKNOWN:RULE_FACT_UNAVAILABLE" +
		";verdict-neutral:excluded-from-applicable-set:counted-in:noticeRules" +
		";rule:subject.chart-required:anchor-only:no-condition:no-dependency:no-intermediate:no-severity:no-consensus-or-lead" +
		";reason:rule-own-not-engine-reserved;text:printable-ascii:no-safe-block-refuse-must" +
		";" + ReasonNoticeNotApplicable + ":prints-nothing"

	noticeSetLinePrefix       = "notice: "
	noticeSetPresentPrefix    = "listed members present: "
	noticeSetAbsentPrefix     = "listed members not present: "
	noticeSetUnresolvedPrefix = "notice not established: "

	noticeIncompleteAction      = "declared %s/%s %s is not complete; this notice is decided only over a complete set or a listed member present: supply every source and declare it complete, or retain UNKNOWN"
	noticeIncompleteActionShort = "declared set fact is not complete; this notice is decided only over a complete set or a listed member present: supply every source and declare it complete, or retain UNKNOWN"
	// The absent notice is decided only over a complete set: a member
	// missing from an incomplete set may come from a source not read.
	noticeAbsentIncompleteAction      = "declared %s/%s %s is not complete; whether a listed member is absent is decided only over a complete set: supply every source and declare it complete, or retain UNKNOWN"
	noticeAbsentIncompleteActionShort = "declared set fact is not complete; whether a listed member is absent is decided only over a complete set: supply every source and declare it complete, or retain UNKNOWN"
	noticeNotApplicableAction         = "this notice does not apply to the declared set; its absence says nothing else about the upgrade"
)

// noticeForbiddenWords may not appear in a set notice's id or text: a
// notice never words the upgrade as safe, nor itself as a verdict.
var noticeForbiddenWords = []string{"safe", "block", "refuse", "must"}

// IsSetNoticeOperator reports whether operator is one of the two
// verdict-neutral set notice operators.
func IsSetNoticeOperator(operator string) bool {
	return operator == OperatorNoticeSetMemberPresent || operator == OperatorNoticeSetMemberAbsent
}

// IsNoticeOperator reports whether operator is verdict-neutral by
// definition: notice_one_way or a set notice.
func IsNoticeOperator(operator string) bool {
	return operator == OperatorNoticeOneWay || IsSetNoticeOperator(operator)
}

// usesChartNotice reports whether a parsed rule needs the chart notice
// contract.
func (r rule) usesChartNotice() bool { return IsSetNoticeOperator(r.Operator) }

// isNotice reports whether a parsed rule is a notice of any kind: counted
// in noticeRules, never in the applicable set.
func (r rule) isNotice() bool { return IsNoticeOperator(r.Operator) }

// validateSetNoticeRule checks the structure of a set notice.
func validateSetNoticeRule(r rule, registry Registry) error {
	if r.SetCondition == nil || r.Condition != nil || r.Dependency != nil || r.Intermediate != "" || r.Range != nil || r.Crossing != nil || r.Severity != "" || len(r.AppliesWhen) != 0 {
		return fmt.Errorf("set notice structure: %w", ErrInvalid)
	}
	if r.Subject.Chart == nil {
		return fmt.Errorf("a set notice needs a chart subject: %w", ErrInvalid)
	}
	if reservedSeverityReason(r.ReasonCode) {
		return fmt.Errorf("a set notice needs its own reason code: %w", ErrInvalid)
	}
	if err := validateNoticeText(r.ID, r.NextAction); err != nil {
		return err
	}
	return validateSetCondition(*r.SetCondition, registry)
}

// validateNoticeText applies the set notice text rule: printable ASCII,
// and none of the forbidden words in any case.
func validateNoticeText(id, text string) error {
	if !printableASCII(text) || !printableASCII(id) {
		return fmt.Errorf("notice text and id must be printable ASCII: %w", ErrInvalid)
	}
	for _, word := range noticeForbiddenWords {
		if strings.Contains(strings.ToLower(text), word) || strings.Contains(strings.ToLower(id), word) {
			return fmt.Errorf("notice text and id must not contain the word %s: %w", word, ErrInvalid)
		}
	}
	return nil
}

// ValidNoticeText reports whether a set notice's id and text meet the text
// rule. ParseRuleSet remains the authority.
func ValidNoticeText(id, text string) bool { return validateNoticeText(id, text) == nil }

// evaluateNoticeSetRule decides a set notice whose subject matched.
func evaluateNoticeSetRule(input inputDocument, rule rule, claim Claim) Claim {
	condition := *rule.SetCondition
	fact, found := findFact(input, condition.Side, condition.Component, condition.FactID)
	if !found || fact.State != "declared" || fact.SetValue == nil {
		claim.Status, claim.ReasonCode = "UNKNOWN", "RULE_FACT_UNAVAILABLE"
		claim.NextAction = factAction(condition.fact(), true)
		return claim
	}
	incomplete := func(claim Claim) Claim {
		claim.Status, claim.ReasonCode = "UNKNOWN", reasonSetFactIncomplete
		action, short := noticeIncompleteAction, noticeIncompleteActionShort
		if rule.Operator == OperatorNoticeSetMemberAbsent {
			action, short = noticeAbsentIncompleteAction, noticeAbsentIncompleteActionShort
		}
		claim.NextAction = boundedAction(fmt.Sprintf(action, condition.Side, condition.Component, condition.FactID), short)
		return claim
	}
	notApplicable := func(claim Claim) Claim {
		claim.Status, claim.ReasonCode, claim.NextAction = "UNKNOWN", ReasonNoticeNotApplicable, noticeNotApplicableAction
		return claim
	}
	if rule.Operator == OperatorNoticeSetMemberPresent {
		if hits := setMembersHit(fact.SetValue.Members, condition.Members); len(hits) > 0 {
			claim.Status, claim.MatchedMembers = StatusNotice, hits
			return claim
		}
		if !fact.SetValue.Complete {
			return incomplete(claim)
		}
		return notApplicable(claim)
	}
	if !fact.SetValue.Complete {
		return incomplete(claim)
	}
	if missing := setMembersMissing(fact.SetValue.Members, condition.Members); len(missing) > 0 {
		claim.Status, claim.MissingMembers = StatusNotice, missing
		return claim
	}
	return notApplicable(claim)
}

// AnyChartNoticeRule reports whether any raw rule uses a set notice
// operator, which needs RulesSchemaChartNotice. It reads the operator only;
// ParseRuleSet remains the authority on validity.
func AnyChartNoticeRule(rules []json.RawMessage) (bool, error) {
	for _, raw := range rules {
		var shape struct {
			Operator *string `json:"operator"`
		}
		if err := json.Unmarshal(raw, &shape); err != nil {
			return false, fmt.Errorf("rule shape: %w", ErrInvalid)
		}
		if shape.Operator != nil && IsSetNoticeOperator(*shape.Operator) {
			return true, nil
		}
	}
	return false, nil
}

// engineContractDigestChartNotice identifies the contract for rule
// documents that hold a set notice. It extends the chart contract.
func engineContractDigestChartNotice() string {
	return digestBytes([]byte(engineContractDigestChart() + "\n" + RulesSchemaChartNotice + "\n" + OperatorNoticeSetMemberPresent + "\n" + OperatorNoticeSetMemberAbsent + "\nclaim:status:" + StatusNotice + "\nreason:" + ReasonNoticeNotApplicable + "\nclaim:matchedMembers:notice\nclaim:missingMembers:notice\n" + chartNoticeSemantics))
}

// EngineContractDigestChartNotice exposes the contract identity for rule
// documents that hold a set notice.
func EngineContractDigestChartNotice() string { return engineContractDigestChartNotice() }

// scopeContractDigestChartNotice adds the set notices to the chart scope
// vocabulary. It is used only with the chart notice engine contract.
func scopeContractDigestChartNotice() string {
	return digestBytes([]byte(scopeContractDigestChart() + "\n" + ScopeContractVersionChartNotice + "\n" + chartNoticeSemantics + "\n" + noticeNeutrality + ":" + OperatorNoticeSetMemberPresent + ":" + OperatorNoticeSetMemberAbsent))
}

// ScopeContractDigestChartNotice exposes the chart notice
// scope-completeness identity.
func ScopeContractDigestChartNotice() string { return scopeContractDigestChartNotice() }

// atLeastChartContract reports a digest that admits every feature of the
// chart contract: the chart contract itself, the chart notice one or the
// ranged chart one.
func atLeastChartContract(digest string) bool {
	return digest == engineContractDigestChart() || digest == engineContractDigestChartNotice() || digest == engineContractDigestChartRanged()
}

// validNoticeSetClaims binds the set notice semantics to the chart notice
// contract: a set notice claim and RULE_NOTICE_NOT_APPLICABLE appear only
// under it; RULE_NOTICE_NOT_APPLICABLE only on an UNKNOWN set notice claim;
// a set notice claim is NOTICE or UNKNOWN, anchor-only, without severity;
// a NOTICE claim has current evidence and a reason the engine does not
// issue, and discloses exactly its own members (present ones for the
// present operator, absent ones for the absent operator); any other set
// notice claim discloses none.
func validNoticeSetClaims(report Report) bool {
	noticeContract := report.EngineContractDigest == engineContractDigestChartNotice() || report.EngineContractDigest == engineContractDigestChartRanged()
	for _, claim := range report.Claims {
		setNotice := IsSetNoticeOperator(claim.Operator)
		if claim.ReasonCode == ReasonNoticeNotApplicable && (!setNotice || claim.Status != "UNKNOWN") {
			return false
		}
		if !setNotice {
			continue
		}
		if !noticeContract || claim.SubjectMatch != nil || claim.CrossingMatch != nil || claim.Severity != "" {
			return false
		}
		switch claim.Status {
		case StatusNotice:
			if claim.EvidenceFreshness != "current" || reservedSeverityReason(claim.ReasonCode) {
				return false
			}
			disclosed, other := claim.MatchedMembers, claim.MissingMembers
			if claim.Operator == OperatorNoticeSetMemberAbsent {
				disclosed, other = claim.MissingMembers, claim.MatchedMembers
			}
			if !canonicalMembers(disclosed, 1, MaxForbiddenMembers) || other != nil {
				return false
			}
		case "UNKNOWN":
			if claim.MatchedMembers != nil || claim.MissingMembers != nil {
				return false
			}
		default:
			return false
		}
	}
	return true
}

// setNoticeLines is the human statement of a set notice claim; see
// NoticeLines.
func (c Claim) setNoticeLines() []string {
	if c.Status == StatusNotice {
		lines := append([]string{noticeSetLinePrefix + c.RuleID}, prefixedLines(noticeBeforePrefix, c.NextAction)...)
		if c.Operator == OperatorNoticeSetMemberAbsent {
			return append(lines, memberLines(noticeSetAbsentPrefix, c.MissingMembers)...)
		}
		return append(lines, memberLines(noticeSetPresentPrefix, c.MatchedMembers)...)
	}
	if _, excluded := exclusionReasons[c.ReasonCode]; excluded || c.ReasonCode == ReasonNoticeNotApplicable {
		return nil
	}
	head := []string{noticeSetUnresolvedPrefix + c.RuleID + " (" + c.ReasonCode + ")"}
	if len(head[0]) > maxStringBytes {
		head = []string{noticeSetUnresolvedPrefix + c.RuleID, "reason: " + c.ReasonCode}
	}
	return append(head, prefixedLines(noticeUnresolvedActions, c.NextAction)...)
}

// memberLines lists members after prefix, as many per line as fit in 256
// bytes; each further line repeats the prefix. A member is at most 128
// bytes, so every line fits.
func memberLines(prefix string, members []string) []string {
	var lines []string
	line := ""
	for _, member := range members {
		switch {
		case line == "":
			line = prefix + member
		case len(line)+2+len(member) <= maxStringBytes:
			line += ", " + member
		default:
			lines = append(lines, line)
			line = prefix + member
		}
	}
	if line != "" {
		lines = append(lines, line)
	}
	return lines
}
