// SPDX-License-Identifier: AGPL-3.0-only

package cncfcheck

import (
	"bytes"
	"encoding/json"
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
	seal                *reportSeal
	digest              string
}
type reportSeal struct{}

// Check uses only the selected project's embedded rules. Local input is parsed
// against the compiled registry; there is no external rule input or fallback.
func Check(project string, inputRaw []byte, now time.Time) (Report, error) {
	b, err := load()
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
	b, err := load()
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
	var rules constraintengine.RuleSet
	if selectedRuleID != "" {
		owned, ownershipErr := b.ownsRuleID(project, selectedRuleID)
		if ownershipErr != nil {
			return Report{}, ErrIntegrity
		}
		if !owned {
			return Report{}, ErrInvalid
		}
		rules, err = b.selectedRuleSet(project, selectedRuleID)
	} else {
		rules, err = b.rulesForAdmittedInput(project, inputRaw)
	}
	if err != nil {
		return Report{}, ErrIntegrity
	}
	return b.report(project, selectedRuleID, false, input, rules, inputRaw, now)
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
	b, err := load()
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
	rules, err := b.factFamilyRuleSet(project, facts, inputRaw)
	if err != nil {
		return Report{}, ErrIntegrity
	}
	return b.report(project, "", true, input, rules, inputRaw, now)
}

func (b bundle) report(project, selectedRuleID string, family bool, input constraintengine.Input, rules constraintengine.RuleSet, inputRaw []byte, now time.Time) (Report, error) {
	result, err := constraintengine.Evaluate(input, rules, now)
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
	if report.seal == nil || report.Assessment != "UNKNOWN" || report.NetworkUsed || report.RuntimeReproduced != 0 {
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
	if len(expected) == 0 || len(expected) > 4<<20 {
		return Report{}, ErrInvalid
	}
	report, err := Check(project, inputRaw, now)
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
// Claims of one-way notice rules are informational and never take part: a
// report holding nothing else exits as one without claims.
func ClaimExit(report Report) int {
	if _, err := MarshalReport(report); err != nil {
		return 3
	}
	decided, unknown := 0, false
	for _, claim := range report.Check.Claims {
		if claim.IsNotice() {
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
