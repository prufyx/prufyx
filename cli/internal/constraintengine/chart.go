// SPDX-License-Identifier: AGPL-3.0-only

package constraintengine

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

// A chart rule is about a Helm chart's own versions, not about the software
// the chart installs. Its subject carries a chart identity (the normalised
// repository URL users install from and the chart name) next to the
// component, and its from and to are chart versions. A chart hop is declared
// the same way: the input component carries the chart identity, and its
// version is the chart version.
//
// The two kinds never meet:
//
//   - a chart rule decides only an input component that declares the same
//     chart on both sides. A component without a chart (an application
//     version) or with another chart excludes it with
//     RULE_SUBJECT_CHART_NOT_DECLARED: the rule's subject is not in the
//     input, which rests on the input's own declaration;
//   - an application rule never decides a chart hop. Its subject (the
//     application version) is not declared there, so it is UNKNOWN with
//     RULE_APP_VERSION_NOT_DECLARED, undetermined in scope, never excluded:
//     the application changes inside a chart upgrade, and absence of its
//     version is not evidence that nothing changed. The same holds for a
//     require_component_version dependency that names a chart component.
//
// Chart rules carry no crossing and no severity. Under RulesSchemaChart they
// are anchor-only; a range over two chart release lines needs
// RulesSchemaChartRanged and one of its two line shapes (chart_range.go). A
// chart rule may require a version of another component (the Kubernetes
// version a chart's kubeVersion constraint names), never of its own
// component, whose declared version is the chart version.
//
// require_set_member is the negative of forbid_set_member: it requires
// members in a declared set fact. It is PASS only when the set is declared
// complete and every required member is present, BLOCKED only when the set
// is declared complete and a required member is absent, and UNKNOWN
// otherwise. Presence in an incomplete set decides nothing, because a source
// the set did not read may still remove the member.
//
// Documents holding a chart rule or require_set_member carry RulesSchemaChart
// and are evaluated under their own engine and scope contracts, so binaries
// that predate them reject such documents, and every other document keeps
// its schema, digest and replay bytes. An input that declares a chart is
// evaluated only under the chart contract.

const (
	// RulesSchemaChart is carried by, and only by, a rule document holding at
	// least one chart rule or require_set_member rule. It also admits every
	// feature of the lower schemas.
	RulesSchemaChart = "prufyx.io/deterministic-constraint-rules/v1alpha8"

	// OperatorRequireSetMember requires members in a declared set fact.
	OperatorRequireSetMember = "require_set_member"

	// ScopeContractVersionChart adds chart identity to the crossing scope
	// contract.
	ScopeContractVersionChart = "scope-completeness-contract-v7"

	// ReasonSubjectChartNotDeclared excludes a chart rule from an input
	// component that does not declare the rule's chart.
	ReasonSubjectChartNotDeclared = "RULE_SUBJECT_CHART_NOT_DECLARED"
	// ReasonAppVersionNotDeclared is the UNKNOWN reason of an application
	// rule, or of a dependency, whose component is declared as a chart hop.
	ReasonAppVersionNotDeclared = "RULE_APP_VERSION_NOT_DECLARED"

	// MaxChartSourceBytes bounds a chart source URL.
	MaxChartSourceBytes = 256

	chartSemantics = "chart:subject.chart+input.component.chart:source-normalised-https-or-oci:name-id-pattern" +
		";chart-rule:decides-only-equal-chart-on-both-sides;otherwise:" + ReasonSubjectChartNotDeclared + ":not-applicable" +
		";app-rule-on-chart-input:" + ReasonAppVersionNotDeclared + ":undetermined-in-scope" +
		";dependency-on-chart-input:" + ReasonAppVersionNotDeclared + ":undetermined-in-scope" +
		";chart-rule:anchor-only:no-range:no-crossing:no-severity:require_component_version-only-of-another-component" +
		";chart-input:no-distribution:same-chart-on-both-sides:only-under-chart-contract" +
		";" + OperatorRequireSetMember + ":complete-all-present:PASS:complete-member-absent:BLOCKED:missingMembers" +
		":incomplete:UNKNOWN:" + reasonSetFactIncomplete + ":fact-unavailable:UNKNOWN:no-crossing" +
		";set-member-grammar-unchanged:colon-reserved-for-type-tag"

	requireIncompleteAction      = "declared %s/%s %s is not complete; a required member is decided only over a complete set: supply every source and declare it complete, or retain UNKNOWN"
	requireIncompleteActionShort = "declared set fact is not complete; a required member is decided only over a complete set: supply every source and declare it complete, or retain UNKNOWN"
	appVersionNotDeclaredAction  = "this component is declared as a chart hop, so its application version is not declared; check the application upgrade in its own input with the application versions, or retain UNKNOWN"
	chartNotDeclaredAction       = "this rule is about the chart %s %s; the input does not declare that chart for this component; no action is needed for this rule"
	chartNotDeclaredActionShort  = "this rule is about a chart the input does not declare for this component; no action is needed for this rule"
)

var (
	chartHostRE    = regexp.MustCompile(`^[a-z0-9]([a-z0-9.-]*[a-z0-9])?(:[0-9]{1,5})?$`)
	chartSegmentRE = regexp.MustCompile(`^[A-Za-z0-9._~+-]+$`)
)

// ChartRef is a chart identity: the normalised repository URL users install
// the chart from and the chart's name.
type ChartRef struct {
	Source string `json:"source"`
	Name   string `json:"name"`
}

// ValidChartSource reports whether value is a chart repository URL in normal
// form: scheme https or oci, a lower-case host with an optional port, path
// segments over [A-Za-z0-9._~+-] that are neither "." nor "..", no trailing
// "/" and no trailing ".git", no userinfo, query, fragment or escape. It is
// the fixed-point set of chartidentity.NormalizeRepoURL (a test in that
// package holds the two together); the engine never normalises, it refuses.
func ValidChartSource(value string) bool {
	if value == "" || len(value) > MaxChartSourceBytes {
		return false
	}
	scheme, rest, ok := strings.Cut(value, "://")
	if !ok || scheme != "https" && scheme != "oci" {
		return false
	}
	host, path, hasPath := strings.Cut(rest, "/")
	if !chartHostRE.MatchString(host) {
		return false
	}
	if !hasPath {
		return true
	}
	if strings.HasSuffix(path, ".git") {
		return false
	}
	for _, segment := range strings.Split(path, "/") {
		if segment == "." || segment == ".." || !chartSegmentRE.MatchString(segment) {
			return false
		}
	}
	return true
}

// ValidChartRef reports whether a chart identity is in normal form and its
// name is a public identifier.
func ValidChartRef(c ChartRef) bool {
	return ValidChartSource(c.Source) && idRE.MatchString(c.Name)
}

// sameChart reports equal chart identities, both absent counting as equal.
func sameChart(a, b *ChartRef) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return *a == *b
}

// AdmitsChart reports whether a declared chart identity (nil for an
// application version) is the one this subject is about. Every selector that
// matches rules by version numbers checks it first, so a chart rule is never
// selected for an application hop with the same numbers, nor the reverse.
func (t RuleTransition) AdmitsChart(declared *ChartRef) bool { return sameChart(t.Chart, declared) }

// usesChart reports whether a parsed rule needs the chart contract (or the
// chart notice contract above it).
func (r rule) usesChart() bool {
	return r.Subject.Chart != nil || r.Operator == OperatorRequireSetMember || r.usesChartNotice()
}

// validateChartRule checks the chart subject and the require_set_member
// structure of one rule. Every failure is ErrInvalid.
func validateChartRule(r rule, registry Registry) error {
	if r.ReasonCode == ReasonSubjectChartNotDeclared || r.ReasonCode == ReasonAppVersionNotDeclared {
		return fmt.Errorf("reason code %s belongs to the engine: %w", r.ReasonCode, ErrInvalid)
	}
	if chart := r.Subject.Chart; chart != nil {
		if !ValidChartRef(*chart) {
			return fmt.Errorf("subject chart identity: %w", ErrInvalid)
		}
		if r.Crossing != nil {
			return fmt.Errorf("a chart rule never carries a crossing: %w", ErrInvalid)
		}
		// A range is admitted only in the release-line shapes
		// (chart_range.go); the schema check in ParseRuleSet admits it only
		// under RulesSchemaChartRanged.
		if r.Range != nil {
			if err := validateChartRange(r); err != nil {
				return err
			}
		}
		if r.Severity != "" || r.Dependency != nil && r.Dependency.Component == r.Subject.Component {
			return fmt.Errorf("a chart rule cannot carry a severity or require its own component's version: %w", ErrInvalid)
		}
	}
	if r.Operator != OperatorRequireSetMember {
		return nil
	}
	// A range on require_set_member is a ranged chart rule, checked above;
	// without a chart subject it is refused.
	if r.SetCondition == nil || r.Condition != nil || r.Dependency != nil || r.Intermediate != "" || r.Range != nil && r.Subject.Chart == nil || r.Crossing != nil || r.Severity != "" {
		return fmt.Errorf("require set member structure: %w", ErrInvalid)
	}
	return validateSetCondition(*r.SetCondition, registry)
}

// validateChartShape is the exact-key gate for a chart identity object.
func validateChartShape(raw json.RawMessage) error {
	_, err := exactObject(raw, []string{"source", "name"}, nil)
	return err
}

// validateInputCharts checks the chart identities of a parsed input: each is
// in normal form, never sits next to a distribution, and a component
// declared on both sides declares the same chart (or none) on both.
func validateInputCharts(document inputDocument) error {
	for _, side := range []inputSide{document.Current, document.Proposed} {
		for _, component := range side.Components {
			if component.Chart == nil {
				continue
			}
			if !ValidChartRef(*component.Chart) || component.Distribution != "" {
				return fmt.Errorf("input chart identity: %w", ErrInvalid)
			}
		}
	}
	for _, current := range document.Current.Components {
		if proposed, found := findComponent(document, "proposed", current.Component); found && !sameChart(current.Chart, proposed.Chart) {
			return fmt.Errorf("input chart differs between sides: %w", ErrInvalid)
		}
	}
	return nil
}

// declaresChart reports whether any input component declares a chart.
func (d inputDocument) declaresChart() bool {
	for _, side := range []inputSide{d.Current, d.Proposed} {
		for _, component := range side.Components {
			if component.Chart != nil {
				return true
			}
		}
	}
	return false
}

// chartAvailability decides chart identity before any version comparison.
// It returns "" when the subject's chart identity is the one both sides
// declare.
func chartAvailability(subject RuleTransition, current, proposed inputComponent) string {
	if sameChart(subject.Chart, current.Chart) && sameChart(subject.Chart, proposed.Chart) {
		return ""
	}
	if subject.Chart != nil {
		return ReasonSubjectChartNotDeclared
	}
	return ReasonAppVersionNotDeclared
}

func chartSubjectAction(subject transition) string {
	if subject.Chart == nil {
		return boundedAction(appVersionNotDeclaredAction, "this component is declared as a chart hop, so its application version is not declared; retain UNKNOWN")
	}
	return boundedAction(fmt.Sprintf(chartNotDeclaredAction, subject.Chart.Source, subject.Chart.Name), chartNotDeclaredActionShort)
}

// evaluateRequireSetRule decides a require_set_member rule whose subject
// matched.
func evaluateRequireSetRule(input inputDocument, rule rule, claim Claim) Claim {
	condition := *rule.SetCondition
	fact, found := findFact(input, condition.Side, condition.Component, condition.FactID)
	if !found || fact.State != "declared" || fact.SetValue == nil {
		claim.Status, claim.ReasonCode = "UNKNOWN", "RULE_FACT_UNAVAILABLE"
		claim.NextAction = factAction(condition.fact(), true)
		return claim
	}
	if !fact.SetValue.Complete {
		claim.Status, claim.ReasonCode = "UNKNOWN", reasonSetFactIncomplete
		claim.NextAction = boundedAction(fmt.Sprintf(requireIncompleteAction, condition.Side, condition.Component, condition.FactID), requireIncompleteActionShort)
		return claim
	}
	if missing := setMembersMissing(fact.SetValue.Members, condition.Members); len(missing) > 0 {
		claim.Status, claim.MissingMembers = "BLOCKED", missing
		return claim
	}
	claim.Status = "PASS"
	return claim
}

// setMembersMissing returns the required members absent from declared, in
// ascending order. Both lists are canonical.
func setMembersMissing(declared, required []string) []string {
	present := setMembersHit(declared, required)
	missing := make([]string, 0, len(required)-len(present))
	i := 0
	for _, member := range required {
		if i < len(present) && present[i] == member {
			i++
			continue
		}
		missing = append(missing, member)
	}
	return missing
}

// AnyChartRule reports whether any raw rule carries a chart subject or uses
// require_set_member or a set notice operator, which needs RulesSchemaChart
// (or RulesSchemaChartNotice above it). It reads the keys only; ParseRuleSet
// remains the authority on validity.
func AnyChartRule(rules []json.RawMessage) (bool, error) {
	for _, raw := range rules {
		var shape struct {
			Operator *string                    `json:"operator"`
			Subject  map[string]json.RawMessage `json:"subject"`
		}
		if err := json.Unmarshal(raw, &shape); err != nil {
			return false, fmt.Errorf("rule shape: %w", ErrInvalid)
		}
		if _, ok := shape.Subject["chart"]; ok {
			return true, nil
		}
		if shape.Operator != nil && (*shape.Operator == OperatorRequireSetMember || IsSetNoticeOperator(*shape.Operator)) {
			return true, nil
		}
	}
	return false, nil
}

// validateSetContradictions refuses a forbid_set_member and a
// require_set_member rule on the same set fact, for the same subject, whose
// members intersect and whose subjects overlap: together they block every
// hop they both match, whatever the set holds. A set notice is
// verdict-neutral and never contradicts anything.
func validateSetContradictions(rules []rule) error {
	verdictSet := func(r rule) bool {
		return r.Operator == OperatorForbidSetMember || r.Operator == OperatorRequireSetMember
	}
	for i := range rules {
		for j := i + 1; j < len(rules); j++ {
			a, b := rules[i], rules[j]
			if a.SetCondition == nil || b.SetCondition == nil || !verdictSet(a) || !verdictSet(b) || a.Operator == b.Operator || a.Subject.Component != b.Subject.Component || !sameChart(a.Subject.Chart, b.Subject.Chart) {
				continue
			}
			ca, cb := a.SetCondition, b.SetCondition
			if ca.Side != cb.Side || ca.Component != cb.Component || ca.FactID != cb.FactID || len(setMembersHit(ca.Members, cb.Members)) == 0 {
				continue
			}
			if regionsOverlap(a.transition(), b.transition()) {
				return fmt.Errorf("a forbid and a require rule contradict on one set member: %w", ErrInvalid)
			}
		}
	}
	return nil
}

// engineContractDigestChart identifies the contract for rule documents that
// hold a chart rule or require_set_member. It extends the crossing contract.
func engineContractDigestChart() string {
	return digestBytes([]byte(engineContractDigestCrossing() + "\n" + RulesSchemaChart + "\nrule:subject.chart\ninput:component.chart\n" + OperatorRequireSetMember + "\nclaim:missingMembers\nreason:" + ReasonSubjectChartNotDeclared + "\nreason:" + ReasonAppVersionNotDeclared + "\n" + chartSemantics))
}

// EngineContractDigestChart exposes the contract identity for rule documents
// that hold a chart rule or require_set_member.
func EngineContractDigestChart() string { return engineContractDigestChart() }

// scopeContractDigestChart adds chart identity to the crossing scope
// vocabulary. It is used only with the chart engine contract.
func scopeContractDigestChart() string {
	return digestBytes([]byte(scopeContractDigestCrossing() + "\n" + ScopeContractVersionChart + "\n" + chartSemantics + "\ncomponent:chart\nnotApplicable:" + ReasonSubjectChartNotDeclared + "\nnotEvaluated:" + ApplicabilityUndetermined + ":" + ReasonAppVersionNotDeclared))
}

// ScopeContractDigestChart exposes the chart scope-completeness identity.
func ScopeContractDigestChart() string { return scopeContractDigestChart() }

// atLeastCrossingContract reports a digest that admits every feature of the
// crossing contract: the crossing contract itself, the chart one or the
// chart notice one.
func atLeastCrossingContract(digest string) bool {
	return digest == engineContractDigestCrossing() || atLeastChartContract(digest)
}

// validChartClaims binds the chart semantics to the chart contract: the two
// chart reason codes and the missing-member disclosure appear only under it;
// the chart reasons only on an UNKNOWN claim without a match disclosure; a
// require_set_member claim is legal only under it, carries missing members
// exactly when it is BLOCKED, and never carries matched members. A range
// disclosure on a chart-rule claim is legal only under the ranged chart
// contract: a require_set_member claim is always a chart-rule claim, and any
// other claim is one when the scope block lists its rule under a chart hop.
func validChartClaims(report Report) bool {
	chartContract := atLeastChartContract(report.EngineContractDigest)
	ranged := report.EngineContractDigest == engineContractDigestChartRanged()
	chartRules := map[string]bool{}
	if scope := report.ScopeCompleteness; scope != nil {
		for _, component := range scope.Components {
			if component.Chart == nil {
				continue
			}
			for _, id := range component.EvaluatedRuleIDs {
				chartRules[id] = true
			}
			for _, skipped := range component.NotEvaluated {
				chartRules[skipped.RuleID] = true
			}
		}
	}
	for _, claim := range report.Claims {
		if claim.SubjectMatch != nil && !ranged && (claim.Operator == OperatorRequireSetMember || chartRules[claim.RuleID]) {
			return false
		}
		if claim.ReasonCode == ReasonSubjectChartNotDeclared || claim.ReasonCode == ReasonAppVersionNotDeclared {
			if !chartContract || claim.Status != "UNKNOWN" || claim.SubjectMatch != nil || claim.CrossingMatch != nil {
				return false
			}
		}
		require := claim.Operator == OperatorRequireSetMember
		if !require {
			// A notice_set_member_absent claim discloses missing members
			// too; validNoticeSetClaims binds them.
			if claim.MissingMembers != nil && claim.Operator != OperatorNoticeSetMemberAbsent {
				return false
			}
			continue
		}
		// validClaimMatches binds the structure of a range disclosure.
		if !chartContract || claim.MatchedMembers != nil || claim.CrossingMatch != nil {
			return false
		}
		if claim.Status == "BLOCKED" {
			if !canonicalMembers(claim.MissingMembers, 1, MaxForbiddenMembers) {
				return false
			}
		} else if claim.MissingMembers != nil {
			return false
		}
	}
	return true
}

// validScopeCharts binds a scope block's chart identities and chart reasons
// to the chart scope contract.
func validScopeCharts(scope *ScopeCompleteness) bool {
	chartScope := scope.ContractDigest == scopeContractDigestChart() || scope.ContractDigest == scopeContractDigestChartNotice() || scope.ContractDigest == scopeContractDigestChartRanged()
	for _, component := range scope.Components {
		if component.Chart != nil && (!chartScope || !ValidChartRef(*component.Chart)) {
			return false
		}
		for _, skipped := range component.NotEvaluated {
			if (skipped.ReasonCode == ReasonSubjectChartNotDeclared || skipped.ReasonCode == ReasonAppVersionNotDeclared) && !chartScope {
				return false
			}
		}
	}
	return true
}

// MissingMembersLine is the one-line human statement of the required set
// members a BLOCKED require_set_member claim found absent. ok is false for
// every other claim, whose human output is unchanged.
func (c Claim) MissingMembersLine() (line string, ok bool) {
	// A notice's members are printed by NoticeLines, never as required.
	if len(c.MissingMembers) == 0 || c.IsNotice() {
		return "", false
	}
	return "required members absent: " + strings.Join(c.MissingMembers, ", "), true
}
