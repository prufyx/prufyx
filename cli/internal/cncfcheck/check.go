// SPDX-License-Identifier: AGPL-3.0-only

package cncfcheck

import (
	"bytes"
	"encoding/json"
	"strings"
	"time"

	"github.com/prufyx/prufyx/cli/internal/constraintengine"
)

type Report struct {
	Schema              string                  `json:"schema"`
	Project             string                  `json:"project"`
	Assessment          string                  `json:"assessment"`
	KnowledgeOrigin     string                  `json:"knowledgeOrigin"`
	KnowledgeRevision   string                  `json:"knowledgeRevision"`
	KnowledgePackDigest string                  `json:"knowledgePackDigest"`
	CatalogueDigest     string                  `json:"catalogueDigest"`
	InputFileDigest     string                  `json:"inputFileDigest"`
	RequestedRuleID     string                  `json:"requestedRuleId,omitempty"`
	SelectedRuleID      string                  `json:"selectedRuleId,omitempty"`
	SourceAuthority     string                  `json:"sourceAuthority"`
	RuntimeReproduced   int                     `json:"runtimeReproduced"`
	NetworkUsed         bool                    `json:"networkUsed"`
	NextAction          string                  `json:"nextAction"`
	Check               constraintengine.Report `json:"check"`
	// TrustPolicy is present only when the caller's trust policy left out
	// at least one candidate rule, so every report without exclusions keeps
	// its bytes.
	TrustPolicy *TrustPolicyDisclosure `json:"trustPolicy,omitempty"`
	seal        *reportSeal
	digest      string
}
type reportSeal struct{}

// TrustPolicy is the set of evidence bases whose rules a check evaluates.
// Rules of any other basis are left out when the rule document is
// assembled, and the report says how many. The zero value is the default
// policy: reviewed, mechanical, empirical and consensus; lead rules are left
// out unless the caller asks for them.
type TrustPolicy struct {
	required []string
}

// TrustPolicyDisclosure states the trust policy of a report that left out
// rules, and how many candidate rules it left out: ExcludedRules verdict
// rules, and ExcludedLeadRules lead rules, which never take part in a
// verdict.
type TrustPolicyDisclosure struct {
	RequiredBasis     []string `json:"requiredBasis"`
	ExcludedRules     int      `json:"excludedRules"`
	ExcludedLeadRules int      `json:"excludedLeadRules,omitempty"`
}

// DefaultTrustPolicy is the policy of a check that names none.
func DefaultTrustPolicy() TrustPolicy {
	return TrustPolicy{required: []string{constraintengine.BasisReviewed, constraintengine.BasisMechanical, constraintengine.BasisEmpirical, constraintengine.BasisConsensus}}
}

// ParseTrustPolicy reads a comma-separated list of evidence bases. Every
// token must be one of the closed vocabulary, once; an empty list is
// refused.
func ParseTrustPolicy(list string) (TrustPolicy, error) {
	if list == "" || len(list) > 256 {
		return TrustPolicy{}, ErrInvalid
	}
	seen := map[string]bool{}
	for _, token := range strings.Split(list, ",") {
		if !constraintengine.KnownBasis(token) || seen[token] {
			return TrustPolicy{}, ErrInvalid
		}
		seen[token] = true
	}
	policy := TrustPolicy{required: []string{}}
	for _, basis := range constraintengine.Bases() {
		if seen[basis] {
			policy.required = append(policy.required, basis)
		}
	}
	return policy, nil
}

// Bases lists the admitted bases in trust order.
func (p TrustPolicy) Bases() []string {
	if p.required == nil {
		return DefaultTrustPolicy().required
	}
	return append([]string(nil), p.required...)
}

// Admits reports whether a rule of this effective basis is evaluated.
func (p TrustPolicy) Admits(basis string) bool {
	for _, admitted := range p.Bases() {
		if admitted == constraintengine.EffectiveBasis(basis) {
			return true
		}
	}
	return false
}

// String is the policy as the comma-separated list ParseTrustPolicy reads.
func (p TrustPolicy) String() string { return strings.Join(p.Bases(), ",") }

// disclosure is the report field for a selection: nil when the policy left
// out no rule.
func (p TrustPolicy) disclosure(selected selection) *TrustPolicyDisclosure {
	if selected.excluded == 0 && selected.excludedLeads == 0 {
		return nil
	}
	return &TrustPolicyDisclosure{RequiredBasis: p.Bases(), ExcludedRules: selected.excluded, ExcludedLeadRules: selected.excludedLeads}
}

// validTrustPolicyDisclosure checks a report's disclosure: absent, or a
// positive count with a nonempty list of known bases in trust order.
func validTrustPolicyDisclosure(disclosure *TrustPolicyDisclosure) bool {
	if disclosure == nil {
		return true
	}
	if disclosure.ExcludedRules < 0 || disclosure.ExcludedLeadRules < 0 || disclosure.ExcludedRules+disclosure.ExcludedLeadRules == 0 || len(disclosure.RequiredBasis) == 0 {
		return false
	}
	policy, err := ParseTrustPolicy(strings.Join(disclosure.RequiredBasis, ","))
	return err == nil && strings.Join(policy.Bases(), ",") == strings.Join(disclosure.RequiredBasis, ",")
}

// Checker evaluates embedded knowledge under one trust policy. Its zero
// value uses the default policy; the package-level functions are the zero
// Checker's methods.
type Checker struct {
	policy TrustPolicy
}

// WithTrustPolicy returns a Checker that evaluates under policy.
func WithTrustPolicy(policy TrustPolicy) Checker { return Checker{policy: policy} }

// load returns the embedded bundle carrying the checker's trust policy.
func (c Checker) load() (bundle, error) {
	b, err := load()
	if err != nil {
		return bundle{}, err
	}
	b.policy = c.policy
	return b, nil
}

// Check uses only the selected project's embedded rules. Local input is parsed
// against the compiled registry; there is no external rule input or fallback.
func Check(project string, inputRaw []byte, now time.Time) (Report, error) {
	return Checker{}.Check(project, inputRaw, now)
}

// Check is Check under the checker's trust policy.
func (c Checker) Check(project string, inputRaw []byte, now time.Time) (Report, error) {
	b, err := c.load()
	if err != nil {
		return Report{}, err
	}
	return b.check(project, "", inputRaw, now)
}

// ValidateCanonicalInput verifies a prepared input against the compiled CNCF
// registry without evaluating a rule or reading external state.
func ValidateCanonicalInput(project string, inputRaw []byte) error {
	b, err := load()
	if err != nil {
		return err
	}
	if !b.hasProject(project) {
		return ErrInvalid
	}
	if _, err := constraintengine.ParseInput(inputRaw, b.registry); err != nil {
		return ErrInvalid
	}
	return nil
}

// CheckRule evaluates one closed maintainer-selected rule. It is intended for
// native routes whose parser inspected exactly that capability. Callers cannot
// use it to suppress arbitrary unknown claims: the rule must belong to project.
func CheckRule(project, ruleID string, inputRaw []byte, now time.Time) (Report, error) {
	return Checker{}.CheckRule(project, ruleID, inputRaw, now)
}

// CheckRule is CheckRule under the checker's trust policy. A selected rule
// the policy leaves out yields a report without claims.
func (c Checker) CheckRule(project, ruleID string, inputRaw []byte, now time.Time) (Report, error) {
	b, err := c.load()
	if err != nil {
		return Report{}, err
	}
	if ruleID == "" {
		return Report{}, ErrInvalid
	}
	return b.check(project, ruleID, inputRaw, now)
}

func (b bundle) check(project, selectedRuleID string, inputRaw []byte, now time.Time) (Report, error) {
	if !b.hasProject(project) {
		return Report{}, ErrInvalid
	}
	input, err := constraintengine.ParseInput(inputRaw, b.registry)
	if err != nil {
		return Report{}, ErrInvalid
	}
	var selected selection
	if selectedRuleID != "" {
		owned, ownershipErr := b.ownsRuleID(project, selectedRuleID)
		if ownershipErr != nil {
			return Report{}, ErrIntegrity
		}
		if !owned {
			return Report{}, ErrInvalid
		}
		selected, err = b.selectRule(project, selectedRuleID)
	} else {
		selected, err = b.selectForInput(project, inputRaw)
	}
	if err != nil {
		return Report{}, ErrIntegrity
	}
	return b.reportSelection(project, selectedRuleID, false, input, selected, inputRaw, now)
}

// RegisteredFact reports whether the compiled fact registry declares id. A
// native adapter uses it to emit only facts that a published rule can consume.
func RegisteredFact(id string) bool {
	for _, definition := range compiledDefinitions() {
		if definition.ID == id {
			return true
		}
	}
	return false
}

// CheckFacts evaluates the project's embedded rules whose every condition and
// applicability fact is one of facts: exactly the rules a native adapter that
// derives those facts can decide. Rules about other evidence are neither run
// nor reported. When no such rule matches the transition, every rule of that
// family is evaluated, so the claims say why none applies; when the family is
// empty the report has no claims.
func CheckFacts(project string, facts []string, inputRaw []byte, now time.Time) (Report, error) {
	return Checker{}.CheckFacts(project, facts, inputRaw, now)
}

// CheckFacts is CheckFacts under the checker's trust policy.
func (c Checker) CheckFacts(project string, facts []string, inputRaw []byte, now time.Time) (Report, error) {
	b, err := c.load()
	if err != nil {
		return Report{}, err
	}
	if !b.hasProject(project) || len(facts) == 0 {
		return Report{}, ErrInvalid
	}
	input, err := constraintengine.ParseInput(inputRaw, b.registry)
	if err != nil {
		return Report{}, ErrInvalid
	}
	selected, err := b.selectFamily(project, facts, inputRaw)
	if err != nil {
		return Report{}, ErrIntegrity
	}
	return b.reportSelection(project, "", true, input, selected, inputRaw, now)
}

func (b bundle) report(project, selectedRuleID string, family bool, input constraintengine.Input, rules constraintengine.RuleSet, inputRaw []byte, now time.Time) (Report, error) {
	return b.reportSelection(project, selectedRuleID, family, input, selection{rules: rules}, inputRaw, now)
}

func (b bundle) reportSelection(project, selectedRuleID string, family bool, input constraintengine.Input, selected selection, inputRaw []byte, now time.Time) (Report, error) {
	result, err := constraintengine.Evaluate(input, selected.rules, now)
	if err != nil {
		return Report{}, ErrInvalid
	}
	if _, err := constraintengine.MarshalReport(result); err != nil {
		return Report{}, ErrIntegrity
	}
	report := Report{
		Schema: "prufyx.io/cncf-source-check/v1alpha1", Project: project, Assessment: "UNKNOWN",
		KnowledgeOrigin: "embedded", KnowledgeRevision: b.pack.Revision, KnowledgePackDigest: b.packDigest,
		CatalogueDigest: b.catalogueDigest, InputFileDigest: digest(inputRaw),
		RequestedRuleID: selectedRuleID,
		SourceAuthority: "PACKAGED_MAINTAINER_REVIEWED_SOURCE_RULES_NOT_RUNTIME_PROOF",
		NextAction:      "review each scoped claim; whole-upgrade behavior and runtime evidence remain unverified",
		Check:           result,
		TrustPolicy:     b.policy.disclosure(selected),
	}
	if selectedRuleID != "" && len(result.Claims) == 1 && result.Claims[0].RuleID == selectedRuleID {
		report.SelectedRuleID = selectedRuleID
		report.NextAction = "review the selected native-input claim; other project rules, configuration and whole-upgrade behavior remain unassessed"
	}
	if len(result.Claims) == 0 {
		if family {
			report.NextAction = "no reviewed rule for this native input is packaged; the result stays UNKNOWN until a maintainer publishes one for this transition"
		} else if selectedRuleID != "" {
			report.NextAction = "the selected reviewed native-input rule is unavailable; retain UNKNOWN and select knowledge that contains that exact rule"
		} else {
			report.NextAction = "no generic rules are packaged for this project; inspect its existing named checks in the catalogue or contribute an exact transition with primary source evidence"
		}
	}
	report.seal = &reportSeal{}
	raw, err := json.Marshal(report)
	if err != nil {
		return Report{}, ErrIntegrity
	}
	report.digest = digest(raw)
	return report, nil
}

func MarshalReport(report Report) ([]byte, error) {
	if report.seal == nil || report.Assessment != "UNKNOWN" || report.NetworkUsed || report.RuntimeReproduced != 0 || !validTrustPolicyDisclosure(report.TrustPolicy) {
		return nil, ErrIntegrity
	}
	if _, err := constraintengine.MarshalReport(report.Check); err != nil {
		return nil, ErrIntegrity
	}
	raw, err := json.Marshal(report)
	if err != nil || digest(raw) != report.digest {
		return nil, ErrIntegrity
	}
	return raw, nil
}

// Replay checks exact local bytes at the explicitly supplied original clock.
// It does not claim continuing source freshness, non-revocation or a signature.
func Replay(project string, inputRaw []byte, now time.Time, expected []byte) (Report, error) {
	return Checker{}.Replay(project, inputRaw, now, expected)
}

// Replay is Replay under the checker's trust policy, which must be the
// policy the original report was made with.
func (c Checker) Replay(project string, inputRaw []byte, now time.Time, expected []byte) (Report, error) {
	if len(expected) == 0 || len(expected) > 4<<20 {
		return Report{}, ErrInvalid
	}
	report, err := c.Check(project, inputRaw, now)
	if err != nil {
		return Report{}, err
	}
	raw, err := MarshalReport(report)
	if err != nil || !bytes.Equal(append(raw, '\n'), expected) {
		return Report{}, ErrIntegrity
	}
	return report, nil
}

// ClaimExit concerns only the selected nonempty set of source constraints.
// Claims of one-way notice and lead rules are informational and never take
// part: a report holding nothing else exits as one without claims. A
// NO_KNOWN_ISSUE claim is not a pass: it exits as unknown.
func ClaimExit(report Report) int {
	if _, err := MarshalReport(report); err != nil {
		return 3
	}
	// A verdict rule the trust policy left out was not evaluated: the
	// result cannot be a pass.
	decided, unknown := 0, report.TrustPolicy != nil && report.TrustPolicy.ExcludedRules > 0
	for _, claim := range report.Check.Claims {
		if claim.IsVerdictNeutral() {
			continue
		}
		decided++
		if claim.Status == "BLOCKED" {
			return 10
		}
		if claim.Status != "PASS" {
			unknown = true
		}
	}
	if decided == 0 || unknown {
		return 11
	}
	return 0
}
