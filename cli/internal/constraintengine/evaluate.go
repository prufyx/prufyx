// SPDX-License-Identifier: AGPL-3.0-only

package constraintengine

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"time"
)

// Evaluate is a pure reducer over opaque parser-issued capabilities and an
// explicit UTC clock. It neither reads system time nor emits SAFE.
//
// The aggregate stays UNKNOWN unless the caller declared a complete component
// scope and the rule document attested that it holds every reviewed rule for
// those components. With both present, the report enumerates per component
// what was evaluated and what was not, and may report SCOPE_COMPLETE_PASS or
// BLOCKED over the declared scope only.
func Evaluate(input Input, rules RuleSet, now time.Time) (Report, error) {
	if !input.Valid() || !rules.Valid() || input.registryDigest == "" || input.registryDigest != rules.registryDigest || now.IsZero() || now.Location() != time.UTC || now.Nanosecond() != 0 {
		return Report{}, fmt.Errorf("evaluation capability or clock: %w", ErrIntegrity)
	}
	claims := make([]Claim, len(rules.document.Rules))
	for index, rule := range rules.document.Rules {
		claims[index] = evaluateRule(input.document, rule, now)
	}
	inputDigest, _ := input.Digest()
	ruleDigest, _ := rules.Digest()
	scope, assessment := buildScopeCompleteness(input.document, rules.document, claims, rules.engineDigest())
	report := Report{
		Schema: ReportSchema, Assessment: assessment, InputAuthority: InputAuthority, RulesAuthority: RulesAuthority,
		EvaluatedAt: now.UTC().Format(time.RFC3339), InputDigest: inputDigest,
		RuleSetDigest: ruleDigest, PolicyID: rules.document.PolicyID,
		PolicyDigest: rules.document.PolicyDigest, EngineContractDigest: rules.engineDigest(), RegistryDigest: input.registryDigest,
		Claims:            claims,
		Omissions:         requiredOmissions(assessment),
		ScopeCompleteness: scope,
	}
	return issueReport(report), nil
}

func evaluateRule(input inputDocument, rule rule, now time.Time) Claim {
	claim := Claim{RuleID: rule.ID, RuleDigest: digestJSON(rule), Operator: rule.Operator, ReasonCode: rule.ReasonCode, NextAction: rule.NextAction, EvidenceReviewedAt: rule.Evidence.ReviewedAt, EvidenceValidUntil: rule.Evidence.ValidUntil, RequiredFacts: requiredFacts(rule), Sources: append([]SourceEvidence(nil), rule.Evidence.Sources...), EvidenceBasis: rule.Evidence.Basis, EvidenceDerivedAt: rule.Evidence.DerivedAt}
	if rule.Evidence.Extractor != nil {
		extractor := *rule.Evidence.Extractor
		claim.EvidenceExtractor = &extractor
	}
	if rule.Evidence.State == "withdrawn" {
		claim.Status, claim.ReasonCode, claim.EvidenceFreshness = "UNKNOWN", "RULE_EVIDENCE_WITHDRAWN", "withdrawn"
		claim.NextAction = "select later declared rule source references with active evidence"
		return claim
	}
	reviewed, _ := parseUTC(rule.Evidence.ReviewedAt)
	validUntil, _ := parseUTC(rule.Evidence.ValidUntil)
	if now.Before(reviewed) {
		claim.Status, claim.ReasonCode, claim.EvidenceFreshness = "UNKNOWN", "RULE_EVIDENCE_CLOCK_BEFORE_REVIEW", "clock_before_review"
		claim.NextAction = "correct the explicit UTC evaluation time and reassess"
		return claim
	}
	if !now.Before(validUntil) {
		claim.Status, claim.ReasonCode, claim.EvidenceFreshness = "UNKNOWN", "RULE_EVIDENCE_STALE", "stale"
		claim.NextAction = "select later declared rule source references with current evidence"
		return claim
	}
	claim.EvidenceFreshness = "current"
	mode, reason := subjectAvailability(input, rule.transition())
	if reason != "" {
		claim.Status, claim.ReasonCode = "UNKNOWN", reason
		claim.NextAction = subjectAction(rule.Subject)
		if rule.Range != nil {
			claim.NextAction = rangeSubjectAction(rule.transition())
		}
		return claim
	}
	if mode == MatchRange {
		// Every verdict reached through a range discloses it, whatever the
		// status, so a range claim can never be read as an anchor review.
		claim = evaluateMatchedRule(input, rule, claim)
		discloseRangeMatch(&claim, rule)
		return claim
	}
	return evaluateMatchedRule(input, rule, claim)
}

// evaluateMatchedRule decides a rule whose evidence is current and whose
// subject matched the declared transition.
func evaluateMatchedRule(input inputDocument, rule rule, claim Claim) Claim {
	for _, applicability := range rule.AppliesWhen {
		fact, found := findFact(input, applicability.Side, applicability.Component, applicability.FactID)
		if !found || fact.State != "declared" {
			claim.Status, claim.ReasonCode = "UNKNOWN", "RULE_APPLICABILITY_FACT_UNAVAILABLE"
			claim.NextAction = factAction(applicability)
			return claim
		}
		if !matchesCondition(fact, applicability) {
			claim.Status, claim.ReasonCode = "UNKNOWN", "RULE_APPLICABILITY_NOT_MATCHED"
			claim.NextAction = factAction(applicability)
			return claim
		}
	}

	switch rule.Operator {
	case "forbid_predicate_value":
		fact, found := findFact(input, rule.Condition.Side, rule.Condition.Component, rule.Condition.FactID)
		if !found || fact.State != "declared" {
			claim.Status, claim.ReasonCode = "UNKNOWN", "RULE_FACT_UNAVAILABLE"
			claim.NextAction = factAction(*rule.Condition)
			return claim
		}
		if matchesCondition(fact, *rule.Condition) {
			claim.Status = "BLOCKED"
			return claim
		}
		claim.Status = "PASS"
	case "require_component_version":
		component, found := findComponent(input, rule.Dependency.Side, rule.Dependency.Component)
		if !found {
			claim.Status, claim.ReasonCode = "UNKNOWN", "RULE_DEPENDENCY_COMPONENT_MISSING"
			claim.NextAction = dependencyAction(*rule.Dependency)
			return claim
		}
		comparison, comparable := compareVersions(component.Version, rule.Dependency.Version)
		matches := comparable && (rule.Dependency.Comparison == "eq" && comparison == 0 || rule.Dependency.Comparison == "gte" && comparison >= 0 || rule.Dependency.Comparison == "lte" && comparison <= 0 || rule.Dependency.Comparison == "lt" && comparison < 0)
		if !matches {
			claim.Status = "BLOCKED"
			return claim
		}
		// A passing inequality establishes only this cited numeric bound; it
		// does not generalize support to every version satisfying that bound.
		claim.Status = "PASS"
	case "require_intermediate_version":
		// Input describes only current and final proposed identities. A reviewed
		// mandatory intermediate therefore blocks this direct transition; a later
		// planner may issue separate transitions for each hop.
		claim.Status = "BLOCKED"
	case "forbid_target_version":
		claim.Status = "BLOCKED"
	default:
		claim.Status, claim.ReasonCode = "UNKNOWN", "RULE_OPERATOR_UNSUPPORTED"
	}
	return claim
}

// subjectAvailability is the engine's single subject gate. Claims and scope
// applicability both call it, and it decides membership only through the
// shared matcher.
func subjectAvailability(input inputDocument, subject RuleTransition) (MatchMode, string) {
	current, currentFound := findComponent(input, "current", subject.Component)
	proposed, proposedFound := findComponent(input, "proposed", subject.Component)
	if !currentFound || !proposedFound {
		return MatchNone, "RULE_SUBJECT_COMPONENT_MISSING"
	}
	mode := subject.Match(current.Version, proposed.Version)
	if mode == MatchNone {
		return MatchNone, "RULE_TRANSITION_NOT_REVIEWED"
	}
	return mode, ""
}

func rangeSubjectAction(subject RuleTransition) string {
	return boundedAction(fmt.Sprintf(rangeSubjectActionTemplate, subject.Component, subject.Range.From.Gte, subject.Range.From.Lt, subject.Range.To.Gte, subject.Range.To.Lt), "no rule for declared transition; retain actual versions and request reviewed coverage")
}

func subjectAction(subject transition) string {
	return boundedAction(fmt.Sprintf("no rule for declared pair; reviewed scope %s %s -> %s; retain actual versions and request coverage", subject.Component, subject.From, subject.To), "no rule for declared transition; retain actual versions and request reviewed coverage")
}

func discloseRangeMatch(claim *Claim, rule rule) {
	claim.SubjectMatch = &SubjectMatch{Mode: subjectMatchModeRange, AnchorFrom: rule.Subject.From, AnchorTo: rule.Subject.To, From: rule.Range.From, To: rule.Range.To}
	action := boundedAction(claim.NextAction+fmt.Sprintf(rangeNextActionSuffixTemplate, rule.Subject.From, rule.Subject.To), "")
	if action == "" {
		action = boundedAction(claim.NextAction+rangeNextActionSuffixShort, claim.NextAction)
	}
	claim.NextAction = action
}

func factAction(condition factCondition) string {
	return boundedAction(fmt.Sprintf("inspect local %s/%s and declare actual %s or mark missing", condition.Side, condition.Component, condition.FactID), "inspect local rule fact and declare its actual value or mark missing")
}

func dependencyAction(dependency componentCheck) string {
	return boundedAction(fmt.Sprintf("inspect local %s/%s and declare actual version or mark missing; reviewed requirement %s %s", dependency.Side, dependency.Component, dependency.Comparison, dependency.Version), "inspect local rule dependency and declare its actual version or mark missing")
}

func boundedAction(action, fallback string) string {
	if publicText(action) {
		return action
	}
	return fallback
}

func requiredFacts(rule rule) []RequiredFact {
	conditions := append([]factCondition(nil), rule.AppliesWhen...)
	if rule.Condition != nil {
		conditions = append(conditions, *rule.Condition)
	}
	result := make([]RequiredFact, 0, len(conditions))
	seen := make(map[string]struct{}, len(conditions))
	for _, condition := range conditions {
		fact := RequiredFact{Side: condition.Side, Component: condition.Component, FactID: condition.FactID}
		key := fact.Side + "\x00" + fact.Component + "\x00" + fact.FactID
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		result = append(result, fact)
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].Side != result[j].Side {
			return result[i].Side < result[j].Side
		}
		if result[i].Component != result[j].Component {
			return result[i].Component < result[j].Component
		}
		return result[i].FactID < result[j].FactID
	})
	return result
}

func findComponent(input inputDocument, side, componentID string) (inputComponent, bool) {
	components := input.Current.Components
	if side == "proposed" {
		components = input.Proposed.Components
	}
	for _, component := range components {
		if component.Component == componentID {
			return component, true
		}
	}
	return inputComponent{}, false
}

func findFact(input inputDocument, side, componentID, factID string) (inputFact, bool) {
	component, found := findComponent(input, side, componentID)
	if !found {
		return inputFact{}, false
	}
	for _, fact := range component.Facts {
		if fact.ID == factID {
			return fact, true
		}
	}
	return inputFact{}, false
}

func matchesCondition(fact inputFact, condition factCondition) bool {
	if condition.BoolValue != nil {
		return fact.BoolValue != nil && *fact.BoolValue == *condition.BoolValue
	}
	return fact.EnumValue == condition.EnumValue
}

func issueReport(report Report) Report {
	raw, _ := json.Marshal(report)
	report.seal, report.digest = &reportSeal{}, digestBytes(raw)
	return report
}

// MarshalReport seals a report for publication. The aggregate gate is the
// deliberate one: a non-UNKNOWN assessment is legal only when a structurally
// valid scope-completeness block is present whose own enumerated contents
// independently re-derive that same assessment. No block, no verdict —
// however many claims passed. See legalAssessment.
func MarshalReport(report Report) ([]byte, error) {
	if report.seal == nil || report.Schema != ReportSchema || !legalAssessment(report) || report.InputAuthority != InputAuthority || report.RulesAuthority != RulesAuthority || scopeDigestFor(report.EngineContractDigest) == "" || !validClaimMatches(report) || !digestRE.MatchString(report.InputDigest) || !digestRE.MatchString(report.RuleSetDigest) || !digestRE.MatchString(report.PolicyDigest) || !digestRE.MatchString(report.RegistryDigest) || !validClaims(report.Claims) || !sameOmissions(report.Omissions, requiredOmissions(report.Assessment)) {
		return nil, ErrIntegrity
	}
	raw, err := json.Marshal(report)
	if err != nil || digestBytes(raw) != report.digest {
		return nil, ErrIntegrity
	}
	return raw, nil
}

func validClaims(claims []Claim) bool {
	for i, claim := range claims {
		reviewed, reviewedErr := parseUTC(claim.EvidenceReviewedAt)
		validUntil, validUntilErr := parseUTC(claim.EvidenceValidUntil)
		if ValidateBasis(claim.EvidenceBasis, claim.EvidenceExtractor, claim.EvidenceDerivedAt) != nil {
			return false
		}
		if (i > 0 && claims[i-1].RuleID >= claim.RuleID) || !idRE.MatchString(claim.RuleID) || !digestRE.MatchString(claim.RuleDigest) || (claim.Status != "PASS" && claim.Status != "BLOCKED" && claim.Status != "UNKNOWN") || !reasonRE.MatchString(claim.ReasonCode) || !publicText(claim.NextAction) || !validRequiredFacts(claim.RequiredFacts) || reviewedErr != nil || validUntilErr != nil || !validUntil.After(reviewed) || (claim.EvidenceFreshness != "current" && claim.EvidenceFreshness != "stale" && claim.EvidenceFreshness != "withdrawn" && claim.EvidenceFreshness != "clock_before_review") {
			return false
		}
	}
	return true
}

// validClaimMatches binds range disclosures to the engine contract: a report
// under the exact-only contract carries none, and every disclosure present is
// a well-formed range that holds its own anchor.
func validClaimMatches(report Report) bool {
	for _, claim := range report.Claims {
		match := claim.SubjectMatch
		if match == nil {
			continue
		}
		if report.EngineContractDigest != engineContractDigestRanged() || match.Mode != subjectMatchModeRange || claim.Status == "UNKNOWN" && claim.ReasonCode == "RULE_TRANSITION_NOT_REVIEWED" {
			return false
		}
		if !validVersion(match.AnchorFrom) || !validVersion(match.AnchorTo) || !inBound(match.AnchorFrom, match.From) || !inBound(match.AnchorTo, match.To) {
			return false
		}
		if c, ok := compareVersions(match.From.Lt, match.To.Gte); !ok || c > 0 {
			return false
		}
	}
	return true
}

func validRequiredFacts(facts []RequiredFact) bool {
	if len(facts) > 9 {
		return false
	}
	for index, fact := range facts {
		if (index > 0 && requiredFactKey(facts[index-1]) >= requiredFactKey(fact)) || (fact.Side != "current" && fact.Side != "proposed") || !componentRE.MatchString(fact.Component) || !factIDRE.MatchString(fact.FactID) {
			return false
		}
	}
	return true
}

func requiredFactKey(fact RequiredFact) string {
	return fact.Side + "\x00" + fact.Component + "\x00" + fact.FactID
}

// Replay recomputes the report at its explicit original clock and requires
// byte equality. It is local replay, not signature or continuing freshness.
func Replay(input Input, rules RuleSet, now time.Time, expected []byte) (Report, error) {
	report, err := Evaluate(input, rules, now)
	if err != nil {
		return Report{}, err
	}
	raw, err := MarshalReport(report)
	if err != nil || !bytes.Equal(raw, expected) {
		return Report{}, ErrIntegrity
	}
	return report, nil
}
