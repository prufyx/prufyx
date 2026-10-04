// SPDX-License-Identifier: AGPL-3.0-only

package scanrun

import (
	"github.com/prufyx/prufyx/cli/internal/cncfprepare"
	"github.com/prufyx/prufyx/cli/internal/intake"
	"github.com/prufyx/prufyx/cli/internal/scanreport"
	"github.com/prufyx/prufyx/cli/internal/upgradepath"
)

// outcome is what one reason means for a Kubernetes scan: a decided result
// that is not a gap, a gap message, or the declaration gaps (which depend on
// what was declared).
type outcome struct {
	decided      bool
	gap          scanreport.GapKey
	declarations bool
}

var decided = outcome{decided: true}

func gapOutcome(key scanreport.GapKey) outcome { return outcome{gap: key} }

// reasonOutcomes maps every reason a Kubernetes scan can meet to its outcome:
// intake omission reasons, the rendered apply-set preparation reasons, the
// planner gaps and every reason the engine gives an UNKNOWN claim. A reason
// that is not here is never decided: it becomes an undecided rule.
var reasonOutcomes = map[string]outcome{
	// Intake omissions (a configuration document is dropped by the scan
	// before the preparation and is not an intake reason).
	string(intake.ReasonTemplated):           gapOutcome(scanreport.GapDocumentsTemplated),
	string(intake.ReasonUnparseable):         gapOutcome(scanreport.GapDocumentsTemplated),
	string(intake.ReasonNestedList):          gapOutcome(scanreport.GapDocumentsLists),
	string(intake.ReasonListShape):           gapOutcome(scanreport.GapDocumentsLists),
	string(intake.ReasonSymlinkNotFollowed):  gapOutcome(scanreport.GapDocumentsFiles),
	string(intake.ReasonNotRegularFile):      gapOutcome(scanreport.GapDocumentsFiles),
	string(intake.ReasonNotKubernetesShaped): gapOutcome(scanreport.GapDocumentsShape),

	// Rendered apply-set preparation.
	cncfprepare.ReasonKubernetesRemovedGVKPresent:    decided,
	cncfprepare.ReasonKubernetesRemovedGVKAbsent:     decided,
	cncfprepare.ReasonKubernetesRemovedWitness:       decided,
	cncfprepare.ReasonKubernetesSelectedSetClear:     decided,
	cncfprepare.ReasonKubernetesGVKVersionUnreviewed: gapOutcome(scanreport.GapAPIVersionNotReviewed),
	cncfprepare.ReasonKubernetesUnreviewed:           gapOutcome(scanreport.GapAPIVersionNotReviewed),
	cncfprepare.ReasonKubernetesScopeIncomplete:      gapOutcome(scanreport.GapDeclarationScope),
	cncfprepare.ReasonKubernetesPagination:           gapOutcome(scanreport.GapDocumentsPaginated),
	cncfprepare.ReasonKubernetesUnresolved:           gapOutcome(scanreport.GapDocumentsUnresolved),
	cncfprepare.ReasonKubernetesTemplated:            gapOutcome(scanreport.GapDocumentsTemplated),
	cncfprepare.ReasonKubernetesTargetGuard:          {declarations: true},

	// Planner.
	string(upgradepath.GapDowngradeNotReviewed): gapOutcome(scanreport.GapDowngradeNotReviewed),
	string(upgradepath.GapPathNotPlannable):     gapOutcome(scanreport.GapPathNotPlannable),

	// Engine reasons of an UNKNOWN claim.
	"RULE_EVIDENCE_WITHDRAWN":             gapOutcome(scanreport.GapEvidenceExpired),
	"RULE_EVIDENCE_CLOCK_BEFORE_REVIEW":   gapOutcome(scanreport.GapEvidenceExpired),
	"RULE_EVIDENCE_STALE":                 gapOutcome(scanreport.GapEvidenceExpired),
	"RULE_SUBJECT_COMPONENT_MISSING":      gapOutcome(scanreport.GapRuleNotDecided),
	"RULE_TRANSITION_NOT_REVIEWED":        gapOutcome(scanreport.GapRuleNotDecided),
	"RULE_APPLICABILITY_FACT_UNAVAILABLE": {}, // the preparation reason explains it
	"RULE_APPLICABILITY_NOT_MATCHED":      decided,
	"RULE_FACT_UNAVAILABLE":               {}, // the preparation reason explains it
	"RULE_SET_FACT_INCOMPLETE":            {}, // the preparation reason explains it
	"RULE_DEPENDENCY_COMPONENT_MISSING":   gapOutcome(scanreport.GapRuleNotDecided),
	"RULE_OPERATOR_UNSUPPORTED":           gapOutcome(scanreport.GapRuleNotDecided),
}

// decidedClaimReasons are the reasons rules give their PASS and BLOCKED
// claims: decided claims, not gaps. They are never looked up for an UNKNOWN
// claim.
var decidedClaimReasons = map[string]bool{
	"REVIEWED_SOURCE_CONSTRAINT": true,
}

// factReasons are engine reasons whose cause is the prepared input: the
// preparation reason names the gap.
var factReasons = map[string]bool{
	"RULE_APPLICABILITY_FACT_UNAVAILABLE": true,
	"RULE_FACT_UNAVAILABLE":               true,
	"RULE_SET_FACT_INCOMPLETE":            true,
}
