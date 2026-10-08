// SPDX-License-Identifier: AGPL-3.0-only

package constraintengine

import (
	"github.com/prufyx/prufyx/cli/internal/validation"
)

// exclusionReasons are the only reason codes that can justify excluding a
// reviewed rule from the applicable set. Each rests on a declared version or a
// declared fact value. Absence of evidence is not among them.
var exclusionReasons = map[string]struct{}{
	"RULE_TRANSITION_NOT_REVIEWED":   {},
	"RULE_SUBJECT_COMPONENT_MISSING": {},
	"RULE_APPLICABILITY_NOT_MATCHED": {},
}

// ruleApplicability decides, structurally, whether a reviewed rule belongs to
// the complete applicable set for the declared component scope.
//
// It deliberately does not consult rule evidence freshness. Excluding a rule
// because the operator's declared versions differ from the rule's reviewed
// pair, or because a declared fact value excludes it, rests on the operator's
// own declarations and the rule's own declared subject — not on the rule's
// evidence being current. Without that split, one stale rule anywhere in a
// corpus would destroy every completeness verdict for unrelated components.
//
// Every NOT_APPLICABLE result rests on positive declared evidence. Absence is
// always UNDETERMINED, never an exclusion.
func ruleApplicability(input inputDocument, scope map[string]struct{}, candidate rule) (string, string) {
	if _, inScope := scope[candidate.Subject.Component]; !inScope {
		return applicabilityOutOfScope, ""
	}
	if _, reason := subjectAvailability(input, candidate.transition()); reason != "" {
		// Only a reason that rests on declared evidence excludes a rule;
		// a hop that crosses a cited removal the rule does not cover is
		// undetermined.
		if _, excluded := exclusionReasons[reason]; !excluded {
			return ApplicabilityUndetermined, reason
		}
		return ApplicabilityNotApplicable, reason
	}
	for _, applicability := range candidate.AppliesWhen {
		fact, found := findFact(input, applicability.Side, applicability.Component, applicability.FactID)
		if !found || fact.State != "declared" {
			return ApplicabilityUndetermined, "RULE_APPLICABILITY_FACT_UNAVAILABLE"
		}
		if !matchesCondition(fact, applicability) {
			return ApplicabilityNotApplicable, "RULE_APPLICABILITY_NOT_MATCHED"
		}
	}
	return ApplicabilityApplicable, ""
}

// buildScopeCompleteness partitions the rule document against the declared
// component scope. It returns nil unless the caller declared a scope and the
// rule document attested its own completeness: absent either declaration there
// is no auditable applicable set, and therefore nothing to aggregate over.
//
// claims is positionally aligned with rules.Rules, as issued by Evaluate. It
// returns the block and the aggregate that block supports; with no block the
// aggregate stays UNKNOWN.
func buildScopeCompleteness(input inputDocument, rules ruleDocument, claims []Claim, engineDigest string) (*ScopeCompleteness, string) {
	if input.Scope == nil || rules.Corpus == nil || len(claims) != len(rules.Rules) {
		return nil, AssessmentUnknown
	}
	declared := make(map[string]struct{}, len(input.Scope.Components))
	for _, component := range input.Scope.Components {
		declared[component] = struct{}{}
	}
	attested := make(map[string]struct{}, len(rules.Corpus.Components))
	for _, component := range rules.Corpus.Components {
		attested[component] = struct{}{}
	}
	components := make([]ComponentScope, 0, len(input.Scope.Components))
	index := make(map[string]int, len(input.Scope.Components))
	for _, component := range input.Scope.Components {
		current, currentFound := findComponent(input, "current", component)
		proposed, proposedFound := findComponent(input, "proposed", component)
		if !currentFound || !proposedFound {
			// Unreachable for a parsed input: validateScope requires every
			// scoped component on both sides. Refuse rather than guess.
			return nil, AssessmentUnknown
		}
		_, corpusAttested := attested[component]
		index[component] = len(components)
		components = append(components, ComponentScope{
			Component: component, From: current.Version, To: proposed.Version,
			CorpusAttested: corpusAttested, EvaluatedRuleIDs: []string{}, NotEvaluated: []NotEvaluatedRule{},
		})
	}
	outOfScope, notices, leads := 0, 0, 0
	for position, candidate := range rules.Rules {
		// A notice or lead rule is verdict-neutral: it is counted, never
		// partitioned, so the aggregate is exactly what it would be without
		// it.
		if candidate.usesNoticeOperator() {
			notices++
			continue
		}
		if candidate.verdictNeutral() {
			leads++
			continue
		}
		state, reason := ruleApplicability(input, declared, candidate)
		if state == applicabilityOutOfScope {
			outOfScope++
			continue
		}
		target := &components[index[candidate.Subject.Component]]
		switch state {
		case ApplicabilityApplicable:
			claim := claims[position]
			if claim.Status == "PASS" || claim.Status == "BLOCKED" {
				target.EvaluatedRuleIDs = append(target.EvaluatedRuleIDs, candidate.ID)
				continue
			}
			// A consensus rule that found no issue was applicable but did not
			// verify anything: the scope is not proven.
			// A support-range rule that found the combination outside its
			// documented range was applicable but verified nothing either:
			// the scope is not proven, and nothing is blocked.
			if claim.Status == StatusNoKnownIssue || claim.Status == StatusUnsupported {
				target.NotEvaluated = append(target.NotEvaluated, NotEvaluatedRule{RuleID: candidate.ID, Applicability: ApplicabilityApplicable, ReasonCode: claim.ReasonCode})
				continue
			}
			// Applicable but not decidable: stale or withdrawn evidence, a
			// missing constraint fact, an undeclared dependency component, or
			// an unsupported operator. Carry the claim's own reason code.
			target.NotEvaluated = append(target.NotEvaluated, NotEvaluatedRule{RuleID: candidate.ID, Applicability: ApplicabilityUndetermined, ReasonCode: claim.ReasonCode})
		default:
			target.NotEvaluated = append(target.NotEvaluated, NotEvaluatedRule{RuleID: candidate.ID, Applicability: state, ReasonCode: reason})
		}
	}
	result := &ScopeCompleteness{
		Declaration: ScopeDeclaration, CorpusAttestation: CorpusAttestation,
		ContractDigest: scopeDigestFor(engineDigest), RuleSetRevision: rules.Revision,
		OutOfScopeRules: outOfScope, NoticeRules: notices, LeadRules: leads, Components: components,
	}
	assessment, unresolved, err := deriveAssessment(result, claims)
	if err != nil {
		return nil, AssessmentUnknown
	}
	result.Resolved, result.UnresolvedReason = unresolved == "", unresolved
	return result, assessment
}

// deriveAssessment reduces the enumerated evidence to an aggregate. It reads
// only the ScopeCompleteness block and the claims it references, so the
// integrity gate can recompute it independently of whatever scalar the
// evaluator wrote onto the report.
//
// The precedence itself lives in validation.ReduceDecision, which already
// refuses to turn zero or incomplete relations into a pass.
func deriveAssessment(scope *ScopeCompleteness, claims []Claim) (string, string, error) {
	statuses := make(map[string]string, len(claims))
	rangeMatched := make(map[string]bool, len(claims))
	for _, claim := range claims {
		statuses[claim.RuleID] = claim.Status
		rangeMatched[claim.RuleID] = claim.SubjectMatch != nil || claim.CrossingMatch != nil
	}
	required, verified := 0, 0
	blockers := []validation.VerifiedBlocker{}
	unattested, undetermined, emptyComponent, notAnchorReviewed, consensusOnly, unsupported := false, false, false, false, false, false
	for _, component := range scope.Components {
		// Completeness stays anchor-only: a component's transition must
		// equal the reviewed anchor pair of at least one evaluated rule. A
		// transition reached only through ranges may still be BLOCKED, but it
		// cannot be SCOPE_COMPLETE_PASS, because nobody reviewed that pair.
		anchorReviewed := false
		for _, ruleID := range component.EvaluatedRuleIDs {
			if !rangeMatched[ruleID] {
				anchorReviewed = true
			}
		}
		if len(component.EvaluatedRuleIDs) != 0 && !anchorReviewed {
			notAnchorReviewed = true
		}
		if !component.CorpusAttested {
			unattested = true
		}
		if len(component.EvaluatedRuleIDs) == 0 {
			emptyComponent = true
		}
		for _, ruleID := range component.EvaluatedRuleIDs {
			status, found := statuses[ruleID]
			if !found || (status != "PASS" && status != "BLOCKED") {
				return "", "", ErrIntegrity
			}
			required, verified = required+1, verified+1
			if status == "BLOCKED" {
				blockers = append(blockers, validation.VerifiedBlocker{Verified: true, Applicable: true})
			}
		}
		for _, skipped := range component.NotEvaluated {
			status, found := statuses[skipped.RuleID]
			if !found {
				return "", "", ErrIntegrity
			}
			// NO_KNOWN_ISSUE and UNSUPPORTED are recorded as applicable and
			// not verified, and nothing else is: the two are bound in both
			// directions.
			if (status == StatusNoKnownIssue || status == StatusUnsupported) != (skipped.Applicability == ApplicabilityApplicable) {
				return "", "", ErrIntegrity
			}
			if skipped.Applicability == ApplicabilityApplicable {
				required = required + 1
				if status == StatusUnsupported {
					unsupported = true
				} else {
					consensusOnly = true
				}
				continue
			}
			if skipped.Applicability == ApplicabilityUndetermined {
				// Required because it may be applicable, unverified because it
				// was not evaluated. The gap is counted, never assumed away.
				required, undetermined = required+1, true
			}
		}
	}
	unresolved := ""
	switch {
	case unattested:
		unresolved = unresolvedComponentNotAttested
	case unsupported:
		// A decided finding about the declared combination outranks the
		// gaps below it: it says why the scope cannot pass even if every
		// other rule were decided.
		unresolved = UnresolvedUnsupportedCombination
	case undetermined:
		unresolved = unresolvedApplicability
	case consensusOnly:
		unresolved = unresolvedConsensusOnlyScope
	case emptyComponent:
		unresolved = unresolvedNoApplicableRule
	case notAnchorReviewed:
		unresolved = unresolvedTransitionNotAnchor
	}
	decision, err := validation.ReduceDecision(validation.DecisionInput{
		RequiredEvidence: required, VerifiedEvidence: verified, ApplicableEvidence: verified,
		UnknownEvidence: unresolved != "", Blockers: blockers,
	})
	if err != nil {
		return "", "", ErrIntegrity
	}
	switch decision {
	case validation.DecisionBlocked:
		return AssessmentBlocked, unresolved, nil
	case validation.DecisionSafe:
		// Reported as SCOPE_COMPLETE_PASS, never as SAFE: it states only that
		// every constraint applicable to the declared component set was
		// evaluated and passed.
		return AssessmentScopeCompletePass, unresolved, nil
	default:
		return AssessmentUnknown, unresolved, nil
	}
}

// validScopeBlock checks the structural invariants the integrity gate needs
// before it re-derives an assessment from the block.
func validScopeBlock(scope *ScopeCompleteness, claims []Claim, engineDigest string) bool {
	if scope.Declaration != ScopeDeclaration || scope.CorpusAttestation != CorpusAttestation || scope.ContractDigest == "" || scope.ContractDigest != scopeDigestFor(engineDigest) || !idRE.MatchString(scope.RuleSetRevision) {
		return false
	}
	if scope.Resolved != (scope.UnresolvedReason == "") || (scope.UnresolvedReason != "" && !reasonRE.MatchString(scope.UnresolvedReason)) {
		return false
	}
	if scope.OutOfScopeRules < 0 || scope.NoticeRules < 0 || scope.LeadRules < 0 || len(scope.Components) == 0 || len(scope.Components) > maxComponents {
		return false
	}
	// Notice and lead claims are never referenced by a component: they are
	// only counted, and each count must be exactly theirs.
	known := make(map[string]struct{}, len(claims))
	notices, leads := 0, 0
	for _, claim := range claims {
		if claim.IsNotice() {
			notices++
			continue
		}
		if claim.IsLead() {
			leads++
			continue
		}
		known[claim.RuleID] = struct{}{}
	}
	if scope.NoticeRules != notices || scope.LeadRules != leads {
		return false
	}
	severityScope := scope.ContractDigest == scopeContractDigestSeverity() || scope.ContractDigest == scopeContractDigestCrossing()
	basisScope := scope.ContractDigest == scopeContractDigestBasis() || severityScope
	statuses, reasons := make(map[string]string, len(claims)), make(map[string]string, len(claims))
	for _, claim := range claims {
		statuses[claim.RuleID], reasons[claim.RuleID] = claim.Status, claim.ReasonCode
	}
	referenced := make(map[string]struct{}, len(claims))
	for index, component := range scope.Components {
		if !componentRE.MatchString(component.Component) || (index > 0 && scope.Components[index-1].Component >= component.Component) {
			return false
		}
		if !validVersion(component.From) || !validVersion(component.To) {
			return false
		}
		for position, ruleID := range component.EvaluatedRuleIDs {
			if position > 0 && component.EvaluatedRuleIDs[position-1] >= ruleID {
				return false
			}
			if !claimReference(known, referenced, ruleID) {
				return false
			}
		}
		for position, skipped := range component.NotEvaluated {
			if position > 0 && component.NotEvaluated[position-1].RuleID >= skipped.RuleID {
				return false
			}
			if skipped.Applicability != ApplicabilityNotApplicable && skipped.Applicability != ApplicabilityUndetermined && skipped.Applicability != ApplicabilityApplicable || !reasonRE.MatchString(skipped.ReasonCode) {
				return false
			}
			// APPLICABLE in the not-evaluated list is a consensus rule that
			// found no issue, legal only under the basis scope contract (or
			// the severity one, which admits it), or a support-range rule
			// that found the combination unsupported, legal only under the
			// severity scope contract and only with the claim's own reason.
			if skipped.Applicability == ApplicabilityApplicable {
				consensusEntry := basisScope && skipped.ReasonCode == ReasonConsensusNoKnownIssue && statuses[skipped.RuleID] == StatusNoKnownIssue
				unsupportedEntry := severityScope && statuses[skipped.RuleID] == StatusUnsupported && skipped.ReasonCode == reasons[skipped.RuleID]
				if !consensusEntry && !unsupportedEntry {
					return false
				}
			}
			// NOT_APPLICABLE is legal only under a reason code that actually
			// excludes the rule on declared evidence. Without this, relabelling
			// an unresolved rule as not applicable would make the gate's own
			// recomputation agree with the forgery.
			_, exclusion := exclusionReasons[skipped.ReasonCode]
			if exclusion != (skipped.Applicability == ApplicabilityNotApplicable) {
				return false
			}
			if !claimReference(known, referenced, skipped.RuleID) {
				return false
			}
		}
	}
	// A PASS, BLOCKED, NO_KNOWN_ISSUE or UNSUPPORTED claim matched its
	// subject and its
	// applicability held, and the declared scope is every input component,
	// so its rule is applicable and in scope: it must be enumerated, never
	// counted out of scope. Without this, moving a BLOCKED claim into
	// outOfScopeRules would let the gate re-derive a scope-complete pass.
	for _, claim := range claims {
		decided := claim.Status == "PASS" || claim.Status == "BLOCKED" || claim.Status == StatusNoKnownIssue || claim.Status == StatusUnsupported
		if _, enumerated := referenced[claim.RuleID]; decided && !claim.IsVerdictNeutral() && !enumerated {
			return false
		}
	}
	// Every rule in the evaluated document is either a notice, a lead, out
	// of scope, or accounted for exactly once. Dropping an undetermined rule
	// from the enumeration therefore cannot buy a completeness claim.
	return len(referenced)+scope.OutOfScopeRules+scope.NoticeRules+scope.LeadRules == len(claims)
}

func claimReference(known, referenced map[string]struct{}, ruleID string) bool {
	if _, exists := known[ruleID]; !exists {
		return false
	}
	if _, duplicate := referenced[ruleID]; duplicate {
		return false
	}
	referenced[ruleID] = struct{}{}
	return true
}

// legalAssessment is the condition under which MarshalReport may emit a
// non-UNKNOWN aggregate. It never trusts report.Assessment: it revalidates the
// evidence block and recomputes the aggregate from the enumerated contents.
func legalAssessment(report Report) bool {
	if report.ScopeCompleteness == nil {
		return report.Assessment == AssessmentUnknown
	}
	if !validScopeBlock(report.ScopeCompleteness, report.Claims, report.EngineContractDigest) {
		return false
	}
	assessment, unresolved, err := deriveAssessment(report.ScopeCompleteness, report.Claims)
	if err != nil {
		return false
	}
	return assessment == report.Assessment && unresolved == report.ScopeCompleteness.UnresolvedReason
}

// requiredOmissions binds the disclosed omissions to the aggregate actually
// reported, so a scoped verdict cannot be published under the wording of an
// unevaluated one.
func requiredOmissions(assessment string) []string {
	if assessment == AssessmentUnknown {
		return []string{omissionDeclaredInput, omissionWholeUpgradeNotChecked}
	}
	return []string{omissionDeclaredInput, omissionWholeUpgradeScoped}
}

func sameOmissions(reported, required []string) bool {
	if len(reported) != len(required) {
		return false
	}
	for index, value := range required {
		if reported[index] != value {
			return false
		}
	}
	return true
}
