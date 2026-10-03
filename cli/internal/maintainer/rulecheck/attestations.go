// SPDX-License-Identifier: AGPL-3.0-only

package rulecheck

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/prufyx/prufyx/cli/internal/lineattest"
)

// AttestationResultSchema identifies the line attestation validation report.
const AttestationResultSchema = "prufyx.io/line-attestation-validation/v1alpha1"

// AttestationOptions configures line attestation validation.
type AttestationOptions struct {
	// Now, when set, also reports every attestation that is not current at
	// that time (stale, or reviewed after Now), as a rule's evidence would
	// be reported UNKNOWN at evaluation.
	Now time.Time
}

// Attestation finding checks.
const (
	CheckAttestationSchema      = "attestation-schema"
	CheckAttestationMissingRule = "attestation-missing-rule"
	CheckAttestationExtraRule   = "attestation-extra-rule"
	// CheckAttestationRuleNotLineWide: a listed rule does not match every
	// transition into the attested line (see lineattest.Family.CoversLine).
	CheckAttestationRuleNotLineWide = "attestation-rule-not-line-wide"
	CheckAttestationNotCurrent      = "attestation-not-current"
)

// ValidateLineAttestations checks an attestation document against the rules
// of the pack it belongs to. The document must parse strictly
// (lineattest.Parse), and every attestation's ruleIds must equal exactly the
// pack's rules for that component, line and fact family: a rule the pack
// holds but the attestation leaves out, and a listed rule the pack does not
// hold for that scope, are each one finding. Every listed rule must also
// match every transition into the line (a range covering the whole previous
// minor line on the from side and the whole line on the to side); a rule
// that does not is an attestation-rule-not-line-wide finding. Finding.EntryIndex is the
// attestation's index; Finding.RuleID is the disagreeing rule.
func ValidateLineAttestations(raw []byte, rules []json.RawMessage, opts AttestationOptions) Result {
	result := Result{Schema: AttestationResultSchema}
	atts, err := lineattest.Parse(raw)
	if err != nil {
		result.Findings = append(result.Findings, Finding{Check: CheckAttestationSchema, Message: err.Error()})
		return result
	}
	result.EntryCount = len(atts)
	index := map[lineattest.Key]int{}
	for i, a := range atts {
		index[a.Key()] = i
	}
	problems, err := lineattest.CheckRuleSets(atts, rules)
	if err != nil {
		result.Findings = append(result.Findings, Finding{Check: CheckAttestationSchema, Message: "the pack rules cannot be read: " + err.Error()})
		return result
	}
	for _, p := range problems {
		var check string
		switch p.Kind {
		case lineattest.ProblemMissingRule:
			check = CheckAttestationMissingRule
		case lineattest.ProblemExtraRule:
			check = CheckAttestationExtraRule
		case lineattest.ProblemRuleNotLineWide:
			check = CheckAttestationRuleNotLineWide
		default:
			check = CheckAttestationSchema
		}
		result.Findings = append(result.Findings, Finding{EntryIndex: index[p.Key], RuleID: p.RuleID, Check: check, Message: p.Message})
	}
	if !opts.Now.IsZero() {
		for i, a := range atts {
			if f := a.Freshness(opts.Now); f != lineattest.FreshnessCurrent {
				result.Findings = append(result.Findings, Finding{EntryIndex: i, Check: CheckAttestationNotCurrent, Message: fmt.Sprintf("attestation for %s is %s at %s", a.Key(), f, opts.Now.UTC().Format(time.RFC3339))})
			}
		}
	}
	result.Valid = len(result.Findings) == 0
	return result
}

// ValidatePackAttestations reads a whole pack file and validates its
// lineAttestations section against its own entries. The section is located
// by lineattest.PackSection, the function the pack loader uses, so top-level
// member names are matched exactly and a case or Unicode-folding variant of
// any member is an error rather than a pack "without" the section. A pack
// without the section has nothing to check and is valid.
func ValidatePackAttestations(pack []byte, opts AttestationOptions) (Result, error) {
	section, present, err := lineattest.PackSection(pack)
	if err != nil {
		return Result{}, fmt.Errorf("pack does not decode: %w", err)
	}
	if !present {
		return Result{Schema: AttestationResultSchema, Valid: true}, nil
	}
	var doc struct {
		Entries []struct {
			Rule json.RawMessage `json:"rule"`
		} `json:"entries"`
	}
	if err := json.Unmarshal(pack, &doc); err != nil {
		return Result{}, fmt.Errorf("pack does not decode: %w", err)
	}
	rules := make([]json.RawMessage, 0, len(doc.Entries))
	for _, e := range doc.Entries {
		rules = append(rules, e.Rule)
	}
	return ValidateLineAttestations(section, rules, opts), nil
}
