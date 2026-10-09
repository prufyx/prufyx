// SPDX-License-Identifier: AGPL-3.0-only

package scanreport

import (
	"fmt"
	"sort"
	"strings"
	"unicode/utf8"
)

// This file is the only place that holds English text for scan headlines,
// gap details and actions, human labels, standing omissions, notes and usage
// errors. Rule titles and fixes come from rule data. Every string, after its
// arguments are filled in, is at most MaxText bytes.

// MaxText bounds every rendered catalog string.
const MaxText = 256

// Gap reasons: the closed vocabulary. Adding one requires catalog text (a
// key below) and a test.
const (
	ReasonLineNotAttested            = "LINE_NOT_ATTESTED"
	ReasonIntermediateLineNotCovered = "INTERMEDIATE_LINE_NOT_COVERED_BY_RANGE"
	ReasonNoReviewedPathPolicy       = "NO_REVIEWED_PATH_POLICY"
	ReasonPathPolicyNotCurrent       = "PATH_POLICY_NOT_CURRENT"
	ReasonPathNotPlannable           = "PATH_NOT_PLANNABLE"
	ReasonComponentNotCovered        = "COMPONENT_NOT_COVERED"
	ReasonVersionNotDetected         = "VERSION_NOT_DETECTED"
	ReasonVersionConflict            = "VERSION_CONFLICT"
	ReasonDeclarationMissing         = "DECLARATION_MISSING"
	ReasonDistributionNotCovered     = "DISTRIBUTION_NOT_COVERED"
	ReasonDocumentsTemplated         = "DOCUMENTS_TEMPLATED"
	ReasonDocumentsNotEvaluated      = "DOCUMENTS_NOT_EVALUATED"
	ReasonEvidenceExpired            = "EVIDENCE_EXPIRED"
	ReasonDowngradeNotReviewed       = "DOWNGRADE_NOT_REVIEWED"
	ReasonUnsupportedCombination     = "UNSUPPORTED_COMBINATION"
	ReasonAPIVersionNotServed        = "API_VERSION_NOT_SERVED"
	ReasonAPIVersionNotReviewed      = "API_VERSION_NOT_REVIEWED"
	ReasonAlphaAPINotCovered         = "ALPHA_API_NOT_COVERED"
	ReasonRuleNotDecided             = "RULE_NOT_DECIDED"
	ReasonProjectNotInKnowledge      = "PROJECT_NOT_IN_KNOWLEDGE"
)

// GapKey selects one gap message: a reason, or a reason and a variant.
type GapKey string

// Gap message keys. The reason of a key is the part before the first "/".
const (
	GapLineNotAttested         GapKey = ReasonLineNotAttested
	GapLineNotCurrent          GapKey = ReasonLineNotAttested + "/not-current"
	GapLineHopShape            GapKey = ReasonLineNotAttested + "/hop-shape"
	GapLineSameLine            GapKey = ReasonLineNotAttested + "/same-line"
	GapLineListedRule          GapKey = ReasonLineNotAttested + "/listed-rule"
	GapLineUnlistedRule        GapKey = ReasonLineNotAttested + "/unlisted-rule"
	GapLineNoRules             GapKey = ReasonLineNotAttested + "/no-rules"
	GapIntermediateLine        GapKey = ReasonIntermediateLineNotCovered
	GapIntermediateMajor       GapKey = ReasonIntermediateLineNotCovered + "/major-line"
	GapNoReviewedPathPolicy    GapKey = ReasonNoReviewedPathPolicy
	GapPathPolicyNotCurrent    GapKey = ReasonPathPolicyNotCurrent
	GapPathNotPlannable        GapKey = ReasonPathNotPlannable
	GapComponentNotCovered     GapKey = ReasonComponentNotCovered
	GapVersionNotDetected      GapKey = ReasonVersionNotDetected
	GapVersionConflict         GapKey = ReasonVersionConflict
	GapDeclarationScope        GapKey = ReasonDeclarationMissing + "/scope"
	GapDeclarationApply        GapKey = ReasonDeclarationMissing + "/apply"
	GapDeclarationDistribution GapKey = ReasonDeclarationMissing + "/distribution"
	GapDistributionNotCovered  GapKey = ReasonDistributionNotCovered
	GapDocumentsTemplated      GapKey = ReasonDocumentsTemplated
	GapDocumentsLists          GapKey = ReasonDocumentsNotEvaluated + "/lists"
	GapDocumentsFiles          GapKey = ReasonDocumentsNotEvaluated + "/files"
	GapDocumentsShape          GapKey = ReasonDocumentsNotEvaluated + "/shape"
	GapDocumentsUnresolved     GapKey = ReasonDocumentsNotEvaluated + "/unresolved"
	GapDocumentsEmpty          GapKey = ReasonDocumentsNotEvaluated + "/empty"
	GapDocumentsPaginated      GapKey = ReasonDocumentsNotEvaluated + "/paginated"
	GapEvidenceExpired         GapKey = ReasonEvidenceExpired
	GapDowngradeNotReviewed    GapKey = ReasonDowngradeNotReviewed
	GapAPIVersionNotServed     GapKey = ReasonAPIVersionNotServed
	// GapAPIVersionNotServedCrossed: the removal is on a release line the
	// upgrade enters, and no reviewed rule decided the object.
	GapAPIVersionNotServedCrossed GapKey = ReasonAPIVersionNotServed + "/crossed-undecided"
	// GapStepNotDecided: the step that enters a line did not decide an object.
	GapStepNotDecided GapKey = ReasonRuleNotDecided + "/entered-line"
	// GapLineNoScanRules: a line the upgrade enters removed API versions that
	// scan has no removal rules for.
	GapLineNoScanRules         GapKey = ReasonRuleNotDecided + "/no-line-rules"
	GapAPIVersionNotListed     GapKey = ReasonAPIVersionNotReviewed + "/not-listed"
	GapAPIVersionNoServedList  GapKey = ReasonAPIVersionNotReviewed + "/no-served-list"
	GapLineUndecidedFact       GapKey = ReasonLineNotAttested + "/undecided-fact"
	GapAPIVersionNotReviewed   GapKey = ReasonAPIVersionNotReviewed
	GapAlphaAPINotCovered      GapKey = ReasonAlphaAPINotCovered
	GapRuleNotDecided          GapKey = ReasonRuleNotDecided
	GapRuleNeedsOtherEvidence  GapKey = ReasonRuleNotDecided + "/other-evidence"
	GapUnsupportedCombination  GapKey = ReasonUnsupportedCombination
	GapLineTrustPolicy         GapKey = ReasonLineNotAttested + "/trust-policy"
	GapPathPolicyTrustPolicy   GapKey = ReasonNoReviewedPathPolicy + "/trust-policy"
	GapServedListTrustPolicy   GapKey = ReasonAPIVersionNotReviewed + "/trust-policy"
	GapServedListNotCurrent    GapKey = ReasonAPIVersionNotReviewed + "/served-list-not-current"
	GapServedListMismatch      GapKey = ReasonAPIVersionNotReviewed + "/served-list-mismatch"
	GapRuleNoKnownIssue        GapKey = ReasonRuleNotDecided + "/no-known-issue"
	GapRuleTrustPolicy         GapKey = ReasonRuleNotDecided + "/trust-policy"
	GapRuleStatusNotUnderstood GapKey = ReasonRuleNotDecided + "/status"
	GapProjectNotInKnowledge   GapKey = ReasonProjectNotInKnowledge
	// GapCustomResourcesOnly: a project whose custom-resource versions
	// scan checks, and nothing else.
	GapCustomResourcesOnly GapKey = ReasonComponentNotCovered + "/custom-resources-only"
	// GapDocumentsCustomGroup: objects of custom-resource groups no
	// reviewed project owns.
	GapDocumentsCustomGroup GapKey = ReasonDocumentsNotEvaluated + "/custom-resource-group"
	// Line reviews of custom-resource versions that exist for the target
	// line but cannot decide the hop.
	GapCustomResourceLineNotCurrent GapKey = ReasonLineNotAttested + "/custom-resources-not-current"
	GapCustomResourceLineHopShape   GapKey = ReasonLineNotAttested + "/custom-resources-hop-shape"
	GapCustomResourceLineSameLine   GapKey = ReasonLineNotAttested + "/custom-resources-same-line"
	GapCustomResourceLineRelease    GapKey = ReasonLineNotAttested + "/custom-resources-release"
	GapCustomResourceLineTrust      GapKey = ReasonLineNotAttested + "/custom-resources-trust-policy"
)

// Reason is the gap reason of the key.
func (k GapKey) Reason() string {
	reason, _, _ := strings.Cut(string(k), "/")
	return reason
}

// RequestCoverageURL is where a user asks for coverage that does not exist
// yet.
const RequestCoverageURL = "https://github.com/prufyx/prufyx/issues/new?template=project-knowledge.yml"

type gapMessage struct {
	detail, action string
	// args is the number of arguments both templates take (by index).
	args int
}

// gapMessages holds detail and action per key. Arguments are referenced by
// explicit index so detail and action can use them in any order.
var gapMessages = map[GapKey]gapMessage{
	GapLineNotAttested: {"no review confirms that the removed-API rules for %[1]s %[2]s name every API that line removes",
		"check the %[1]s %[2]s release notes for other removed APIs by hand, or request a line review", 2},
	GapLineNotCurrent: {"the review of %[1]s %[2]s for removed APIs is not current (%[3]s)",
		"use knowledge with a current review, or check the %[1]s %[2]s release notes by hand", 3},
	GapLineHopShape: {"the hop %[2]s -> %[3]s does not enter one release line from the line before it, so line reviews do not apply",
		"plan the upgrade one minor line at a time and scan each hop", 3},
	GapLineSameLine: {"upgrades within %[1]s %[2]s are not reviewed for removed APIs",
		"check the patch release notes by hand", 2},
	GapLineListedRule: {"the review of %[1]s %[2]s lists rule %[3]s, which does not decide this hop",
		"check the %[1]s %[2]s release notes by hand, and report the inconsistent review", 3},
	GapLineUnlistedRule: {"rule %[3]s applies to %[1]s %[2]s but the review of that line does not list it",
		"check the %[1]s %[2]s release notes by hand, and report the inconsistent review", 3},
	GapLineNoRules: {"%[1]s removes API versions on the way to %[2]s that no reviewed rule covers yet",
		"check the %[1]s release notes for removed APIs by hand up to %[2]s", 2},
	GapIntermediateLine: {"rule %[1]s applies to only some releases of this hop's release lines",
		"scan the hop with exact versions, or request a rule that covers whole lines: " + RequestCoverageURL, 1},
	GapIntermediateMajor: {"a whole major release line cannot be evaluated",
		"scan each minor upgrade with exact versions", 0},
	GapNoReviewedPathPolicy: {"no reviewed upgrade-path policy for %[1]s, and %[2]s -> %[3]s skips release lines",
		"upgrade one minor line at a time and scan each hop", 3},
	GapPathPolicyNotCurrent: {"the upgrade-path policy for %[1]s is not current (%[2]s)",
		"use knowledge with a current policy; until then upgrade one minor line at a time and scan each hop", 2},
	GapPathNotPlannable: {"no upgrade path can be planned for %[1]s from %[2]s to %[3]s",
		"check the versions, or scan each upgrade step separately", 3},
	GapComponentNotCovered: {"%[1]s is not evaluated by scan yet",
		"run prufyx check cncf --project %[1]s, or verify its upgrade notes by hand", 1},
	GapProjectNotInKnowledge: {"the selected knowledge database has no knowledge for %[1]s, so nothing about it was checked",
		"update the knowledge database to a revision that covers %[1]s, or verify its upgrade notes by hand", 1},
	GapVersionNotDetected: {"the current %[1]s version is not declared; scan never reads it from manifests",
		"declare it with --from %[1]s=VERSION or under current: in prufyx.yaml", 1},
	GapVersionConflict: {"different versions of %[1]s were declared",
		"declare one version", 1},
	GapDeclarationScope: {"the %[1]s manifests are not declared to be the complete set you apply",
		"if they are, add resourceScopeComplete: true to prufyx.yaml or pass --resource-scope-complete", 1},
	GapDeclarationApply: {"it is not declared that these manifests are applied to the target %[1]s API",
		"if they are, add targetApplyRequired: true to prufyx.yaml or pass --target-api-apply-required", 1},
	GapDeclarationDistribution: {"the %[1]s distribution is not declared",
		"for upstream builds, add distribution: official_upstream to prufyx.yaml or pass --distribution official_upstream", 1},
	GapDistributionNotCovered: {"the %[1]s distribution is %[2]s; only official_upstream is evaluated",
		"check your distribution's release notes by hand", 2},
	GapDocumentsTemplated: {"%[1]d document(s) contain unrendered templates",
		"render them (for example with helm template) and scan the output", 1},
	GapDocumentsLists: {"%[1]d document(s) are nested lists or lists that cannot be resolved",
		"flatten the lists, or pass each object as its own document", 1},
	GapDocumentsFiles: {"%[1]d file(s) were not read (symlinks or special files)",
		"pass the files themselves; symlinks are never followed", 1},
	GapDocumentsShape: {"%[1]d document(s) are not Kubernetes objects, so the manifests cannot be read as one apply set",
		"remove them from the inputs, or pass only rendered manifests", 1},
	GapDocumentsUnresolved: {"the manifests cannot be read as one apply set (an apiVersion or kind is not valid, or an object that is not a List holds items)",
		"pass only valid rendered Kubernetes objects", 0},
	GapDocumentsEmpty: {"no Kubernetes manifests were read",
		"pass the rendered manifests to scan", 0},
	GapDocumentsPaginated: {"a list in the inputs is paginated, so the manifests are incomplete",
		"fetch the complete list and scan it", 0},
	GapEvidenceExpired: {"the review of rule %[1]s is not current (%[2]s)",
		"use a Prufyx release with current knowledge, or check this change by hand", 2},
	GapDowngradeNotReviewed: {"downgrades are not evaluated (%[1]s %[2]s -> %[3]s)",
		"Prufyx checks upgrades only; see %[1]s docs on downgrades (the Kubernetes control plane has none), or swap --from and --to", 3},
	GapAPIVersionNotReviewed: {"a manifest uses an API version of a reviewed kind that the reviewed removals do not name",
		"check that API version against the release notes by hand", 0},
	GapAPIVersionNotServed: {"%[1]d manifest(s) use API versions that Kubernetes %[2]s does not serve (removed at or before that release)",
		"migrate them to a served API version before upgrading, then scan again", 2},
	GapStepNotDecided: {"step %[2]s -> %[3]s (enters %[1]s) decided nothing: %[4]s",
		"check the Kubernetes %[1]s release notes for the removed APIs by hand, or scan with knowledge that reviews this line", 4},
	GapLineNoScanRules: {"Kubernetes %[1]s removed API versions that scan has no removal rules for",
		"check the Kubernetes %[1]s release notes for removed APIs by hand", 1},
	GapAPIVersionNotServedCrossed: {"%[1]d manifest(s) use API versions Kubernetes %[2]s does not serve, removed on a line this upgrade enters",
		"no reviewed rule decided them; migrate them to a served API version before upgrading, and the gaps for the step that enters the line say why", 2},
	GapAPIVersionNotListed: {"%[1]d manifest(s) use API versions that the review of Kubernetes %[2]s does not list as served",
		"check those API versions against the Kubernetes %[2]s API reference by hand", 2},
	GapAPIVersionNoServedList: {"no reviewed list of the API versions Kubernetes %[2]s serves; %[1]d manifest(s) cannot be checked",
		"check them against the API reference of that Kubernetes release by hand, or request coverage: " + RequestCoverageURL, 2},
	GapLineUndecidedFact: {"a manifest uses an API version removed on the way to %[1]s %[2]s that no reviewed rule decides",
		"check the %[1]s %[2]s release notes for removed APIs by hand", 2},
	GapAlphaAPINotCovered: {"%[1]d manifest(s) use alpha API versions of Kubernetes API groups, which removed-API reviews do not cover",
		"check alpha APIs against the release notes of every line by hand", 1},
	GapRuleNotDecided: {"rule %[1]s could not be decided (%[2]s)",
		"run the hop with prufyx check cncf to see the rule's next action, or check by hand", 2},
	GapRuleNeedsOtherEvidence: {"rule %[1]s applies to this hop but needs evidence that scan does not collect",
		"run prufyx check cncf --project %[2]s for that rule, or check by hand", 2},
	GapUnsupportedCombination: {"rule %[1]s finds the planned combination outside a documented support range (%[2]s)",
		"see UNSUPPORTED COMBINATIONS for the rule's next action; the answer cannot pass while it stands", 2},
	GapLineTrustPolicy: {"the review of %[1]s %[2]s rests on basis %[3]s, left out by --require-basis",
		"add %[3]s to --require-basis, or check the %[1]s %[2]s release notes by hand", 3},
	GapPathPolicyTrustPolicy: {"the upgrade-path policy for %[1]s rests on evidence basis %[2]s, which --require-basis leaves out",
		"add %[2]s to --require-basis if you accept it, or upgrade one minor line at a time and scan each hop", 2},
	GapServedListTrustPolicy: {"the served list of Kubernetes %[1]s rests on basis %[2]s, left out by --require-basis",
		"add %[2]s to --require-basis, or check API versions against the Kubernetes %[1]s API reference", 2},
	GapServedListNotCurrent: {"the served list of Kubernetes %[1]s is not current (%[2]s)",
		"use a current list, or check API versions against the Kubernetes %[1]s API reference", 2},
	GapServedListMismatch: {"the served list found for Kubernetes %[1]s names another line or component",
		"check API versions against the Kubernetes %[1]s API reference, and report the knowledge", 1},
	GapRuleNoKnownIssue: {"rule %[1]s found no known issue, but its evidence (%[2]s) can block and never pass",
		"check this change by hand, or wait for reviewed or mechanical evidence", 2},
	GapRuleTrustPolicy: {"rule %[1]s applies but its evidence basis (%[2]s) is left out by --require-basis",
		"add %[2]s to --require-basis if you accept that evidence, or check this change by hand", 2},
	GapRuleStatusNotUnderstood: {"rule %[1]s returned a result this version of scan does not understand (%[2]s)",
		"use a newer Prufyx release, or check by hand", 2},
	GapCustomResourcesOnly: {"scan checks %[1]s only for custom-resource versions its target release no longer serves; nothing else about it is evaluated yet",
		"verify the rest of the %[1]s upgrade notes by hand", 1},
	GapDocumentsCustomGroup: {"%[1]d manifest(s) use custom-resource groups that no reviewed project owns, so no custom-resource set is complete",
		"check those custom resources by hand; they are never assigned to a project by guess", 1},
	GapCustomResourceLineNotCurrent: {"the custom-resource review of %[1]s %[2]s is not current (%[3]s)",
		"use current knowledge, or check the %[1]s %[2]s CRDs by hand", 3},
	GapCustomResourceLineHopShape: {"%[1]s %[2]s -> %[3]s is not a next-minor upgrade; CRD line reviews do not apply",
		"scan each minor upgrade of %[1]s separately", 3},
	GapCustomResourceLineSameLine: {"%[1]s %[2]s -> %[3]s stays within one minor line; CRD line reviews do not apply",
		"diff the CRDs of %[1]s %[2]s and %[3]s by hand", 3},
	GapCustomResourceLineRelease: {"the custom-resource review of %[1]s %[2]s did not read release %[3]s",
		"use knowledge reviewed after %[1]s %[3]s, or check its CRDs by hand", 3},
	GapCustomResourceLineTrust: {"the custom-resource review of %[1]s %[2]s rests on basis %[3]s (see --require-basis)",
		"add %[3]s to --require-basis, or check the %[1]s %[2]s CRDs by hand", 3},
}

// GapReasons lists the closed vocabulary in order.
func GapReasons() []string {
	return []string{
		ReasonAlphaAPINotCovered, ReasonAPIVersionNotReviewed, ReasonAPIVersionNotServed, ReasonUnsupportedCombination, ReasonComponentNotCovered, ReasonDeclarationMissing,
		ReasonDistributionNotCovered, ReasonDocumentsNotEvaluated, ReasonDocumentsTemplated, ReasonDowngradeNotReviewed,
		ReasonEvidenceExpired, ReasonIntermediateLineNotCovered, ReasonLineNotAttested, ReasonNoReviewedPathPolicy,
		ReasonPathNotPlannable, ReasonPathPolicyNotCurrent, ReasonProjectNotInKnowledge, ReasonRuleNotDecided, ReasonVersionConflict, ReasonVersionNotDetected,
	}
}

// GapKeys lists every gap message key in order.
func GapKeys() []GapKey {
	keys := make([]GapKey, 0, len(gapMessages))
	for key := range gapMessages {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })
	return keys
}

// GapArgs is the number of arguments a key takes, or -1 for an unknown key.
func GapArgs(key GapKey) int {
	message, ok := gapMessages[key]
	if !ok {
		return -1
	}
	return message.args
}

// NewGap renders a gap from the catalog. A key that is not in the catalog
// renders as an undecided rule, so a programming error never hides a gap.
func NewGap(component string, hop *HopRef, key GapKey, args ...any) Gap {
	message, ok := gapMessages[key]
	if !ok || len(args) != message.args {
		message, key, args = gapMessages[GapRuleNotDecided], GapRuleNotDecided, []any{"unknown", string(key)}
	}
	var ref *HopRef
	if hop != nil {
		copied := *hop
		ref = &copied
	}
	return Gap{Component: component, Hop: ref, Reason: key.Reason(), Detail: bound(fill(message.detail, args)), Action: bound(fill(message.action, args))}
}

// fill replaces every %[n]s and %[n]d in template with argument n (1-based).
// Unlike fmt, a template may leave arguments unused.
func fill(template string, args []any) string {
	var out strings.Builder
	for index := 0; index < len(template); index++ {
		if template[index] == '%' && index+4 < len(template) && template[index+1] == '[' && template[index+3] == ']' && (template[index+4] == 's' || template[index+4] == 'd') {
			if n := int(template[index+2] - '0'); n >= 1 && n <= len(args) {
				out.WriteString(fmt.Sprint(args[n-1]))
				index += 4
				continue
			}
		}
		out.WriteByte(template[index])
	}
	return out.String()
}

// bound cuts a rendered string to MaxText bytes on a character boundary.
func bound(text string) string {
	if len(text) <= MaxText {
		return text
	}
	cut := MaxText
	for cut > 0 && !utf8.RuneStart(text[cut]) {
		cut--
	}
	return text[:cut]
}

// Headlines, the clear-answer contract. An undecided answer always opens
// with the word of its verdict, UNKNOWN, so that a pasted headline cannot be
// read as a pass.
const (
	headlineBlockedOne         = "BLOCKED: 1 problem must be fixed before this upgrade"
	headlineBlockedMany        = "BLOCKED: %d problems must be fixed before this upgrade"
	headlineBlockedGapsOne     = "BLOCKED: 1 problem must be fixed; 1 area was not checked"
	headlineBlockedGapsMany    = "BLOCKED: 1 problem must be fixed; %d areas were not checked"
	headlineBlockedManyGapsOne = "BLOCKED: %d problems must be fixed; 1 area was not checked"
	headlineBlockedManyGaps    = "BLOCKED: %d problems must be fixed; %d areas were not checked"
	headlineUnknownOne         = "UNKNOWN: no blocker in the checks that ran; 1 area was not checked (see NOT CHECKED)"
	headlineUnknownMany        = "UNKNOWN: no blocker in the checks that ran; %d areas were not checked (see NOT CHECKED)"
	headlineUnknownNone        = "UNKNOWN: no blocker in the checks that ran; some areas were not checked"
	// When no hop was checked, or no component has rules, nothing ran: the
	// headline does not claim a blocker-free "checks that ran".
	headlineNothingRanOne  = "UNKNOWN: nothing could be evaluated; 1 area was not checked (see NOT CHECKED)"
	headlineNothingRanMany = "UNKNOWN: nothing could be evaluated; %d areas were not checked (see NOT CHECKED)"
	headlineNothingRanNone = "UNKNOWN: nothing could be evaluated; some areas were not checked"
	// An undecided report that names a manifest the target does not serve
	// never leads with "no blockers": the object fails on the target
	// whatever else was checked.
	// The count is of the other gaps: the unserved manifest was checked.
	headlineNotServedNone = "UNKNOWN: manifests use API versions the target does not serve; migrate them before upgrading"
	headlineNotServedOne  = "UNKNOWN: manifests use API versions the target does not serve; migrate them before upgrading (1 other area was not checked)"
	headlineNotServedMany = "UNKNOWN: manifests use API versions the target does not serve; migrate them before upgrading (%d other areas were not checked)"
	headlinePass          = "PASS FOR THE DECLARED SCOPE"
)

// somethingRan is true when at least one hop was checked against a component
// that has rules. Without that, "the checks that ran" would be empty.
func somethingRan(report Report) bool {
	return report.Summary.Hops > 0 && report.Summary.ComponentsWithRules > 0
}

func headline(report Report) string {
	switch report.Verdict {
	case VerdictBlocked:
		problems, gaps := len(report.Findings), len(report.Gaps)
		switch {
		case gaps == 0 && problems == 1:
			return headlineBlockedOne
		case gaps == 0:
			return fmt.Sprintf(headlineBlockedMany, problems)
		case problems == 1 && gaps == 1:
			return headlineBlockedGapsOne
		case problems == 1:
			return fmt.Sprintf(headlineBlockedGapsMany, gaps)
		case gaps == 1:
			return fmt.Sprintf(headlineBlockedManyGapsOne, problems)
		}
		return fmt.Sprintf(headlineBlockedManyGaps, problems, gaps)
	case VerdictPass:
		return headlinePass
	}
	notServed := 0
	for _, gap := range report.Gaps {
		if gap.Reason == ReasonAPIVersionNotServed {
			notServed++
		}
	}
	if notServed > 0 {
		switch others := len(report.Gaps) - notServed; others {
		case 0:
			return headlineNotServedNone
		case 1:
			return headlineNotServedOne
		default:
			return fmt.Sprintf(headlineNotServedMany, others)
		}
	}
	if !somethingRan(report) {
		switch len(report.Gaps) {
		case 0:
			return headlineNothingRanNone
		case 1:
			return headlineNothingRanOne
		}
		return fmt.Sprintf(headlineNothingRanMany, len(report.Gaps))
	}
	switch len(report.Gaps) {
	case 0:
		return headlineUnknownNone
	case 1:
		return headlineUnknownOne
	}
	return fmt.Sprintf(headlineUnknownMany, len(report.Gaps))
}

// Standing omissions.
const (
	// OmissionNodeSkew is stated on every Kubernetes path.
	OmissionNodeSkew = "node and kubelet version skew not evaluated"
	// OmissionKubernetesScope says what the Kubernetes evaluation reads.
	OmissionKubernetesScope = "Kubernetes: only API versions in the supplied manifests are evaluated; live cluster objects, CRDs, stored versions, admission and component configuration are not"
)

// PermissionNote is the notice for files other users can read.
func PermissionNote(files int) string {
	if files == 1 {
		return "note: 1 input file is readable by other users; use --input-permissions strict to refuse them"
	}
	return fmt.Sprintf("note: %d input files are readable by other users; use --input-permissions strict to refuse them", files)
}

// Human labels.
const (
	labelPath                   = "%s %s -> %s: %s"
	labelHops                   = "%d hops"
	labelHopOne                 = "1 hop"
	labelPolicy                 = "%s (path policy %s)"
	labelNoPolicy               = "%s (no reviewed path policy)"
	labelNoPath                 = "no path (%s)"
	labelWholeUpgrade           = "whole upgrade"
	labelMore                   = "... and %d more"
	labelFix                    = "fix: %s"
	labelEvidenceReviewed       = "evidence: reviewed"
	labelEvidenceMech           = "evidence: mechanical (%s)"
	labelSource                 = "source: %s lines %d-%d; revision %s; digest %s"
	labelSharedSources          = "Sources cited by several findings:"
	labelNotChecked             = "NOT CHECKED (%d)"
	labelOnlyBlocked            = "Hidden by --only-blocked: %d not-checked gap(s), %d other item(s) (notices, unsupported, leads). Run without the flag or use --format json to see them."
	labelPassed                 = "PASSED (%d)"
	labelChecked                = "Read %s over %s; %s."
	labelComponentsRulesOne     = "%d of 1 component has rules"
	labelComponentsRulesMany    = "%d of %d components have rules"
	labelPartiallyEvaluated     = " (partially evaluated)"
	labelNothingEvaluated       = " (nothing evaluated)"
	labelPassCount              = " %d checks passed (--show-passes)."
	labelPassCountOne           = " 1 check passed (--show-passes)."
	labelNotEvaluated           = "Scope limits: %s."
	labelEvidence               = "Evidence: every finding cites pinned upstream source (--verbose). No network used."
	labelProvenance             = "evaluated at %s; input %s; knowledge %s %s %s"
	labelKnowledgeStore         = "knowledge database %s; layout %s; target %s; trust receipt %s"
	labelKnowledgeProject       = "knowledge for %s: target %s revision %s digest %s"
	labelKnowledgeProjectAbsent = "knowledge for %s: absent from the selected index"
	labelHopStatus              = "  hop %d %s -> %s: %s"
	labelDocuments              = "%d documents"
	labelDocumentOne            = "1 document"
	labelNoName                 = "(no name)"
	labelNotices                = "ONE-WAY CHANGES (%d)"
	labelNoticeRule             = "cannot be rolled back: %s"
	labelNoticeBefore           = "before you upgrade: %s"
	labelNoticeUnresolved       = "one-way notice not established: %s (%s)"
	labelNoticeNext             = "next action: %s"
	labelLeads                  = "UNVERIFIED LEADS (%d)"
	labelUnsupported            = "UNSUPPORTED COMBINATIONS (%d)"
	labelUnsupportedRule        = "outside a documented support range: %s (%s)"
	labelLeadRule               = "unverified lead (does not block): %s"
	labelLeadCheck              = "worth checking: %s"
	labelTrustExcluded          = "trust policy: evidence basis %s only; %d rule(s) that apply were left out, so the result cannot pass"
	labelTrustLeads             = "trust policy: %d unverified lead(s) not shown; add lead to --require-basis to list them"
	labelConsensus              = "%d finding(s) rely on model consensus"
	labelGapLine                = "%s - %s"
	labelFamilyPass             = "  %s %s -> %s: PASS within %s only (line %s attested complete, %s evidence): no manifest uses a version that %s %s stops serving"
	labelFamilyBlocked          = "  %s %s -> %s: BLOCKED within %s (line %s attested complete, %s evidence): see the problems above"
	labelFamilyScope            = "    scope: %s; nothing else about %s is checked"
)

// SARIF and Markdown labels.
const (
	labelResultMessage         = "%s \u2014 fix: %s"
	labelNoticeMessage         = "This is a one-way change that cannot be rolled back. Before you upgrade: %s"
	labelNoticeNotEstab        = "A one-way change was not established (%s). Next action: %s"
	labelLeadMessage           = "Unverified lead; it does not block. Worth checking: %s"
	labelUnsupportedMsg        = "Outside a documented support range: %s. Fix: %s"
	labelSarifGapRule          = "Area not checked: %s"
	labelSarifGapHelp          = "Prufyx could not decide this area (%s), so the scan is UNKNOWN for it. It is not a blocker and not a pass. The result message says what to do."
	labelSarifGapHelpNotServed = "A manifest uses an API version the target does not serve (%s). Migrate it to a served API version before you upgrade. The Prufyx GitHub Action fails the step on this."
	labelSarifTruncated        = "SARIF output is limited to %d results; %d more are in the JSON report"
	labelMDProblems            = "PROBLEMS TO FIX (%d)"
	labelMDScoped              = "SCOPED RESULTS (%d)"
	labelMDPath                = "%s %s -> %s"
	labelMDHopHeader           = "Hop"
	labelMDProblemHeader       = "Problem"
	labelMDWhereHeader         = "Where"
	labelMDFixHeader           = "Fix"
	labelMDAreaHeader          = "Area"
	labelMDDetailHeader        = "What"
	labelMDActionHeader        = "Next step"
	labelMDRuleHeader          = "Rule"
	labelMDRulesHeader         = "Rules"
	labelMDSourceHeader        = "Source"
	labelMDLinesHeader         = "Lines"
	labelMDRevisionHeader      = "Revision"
	labelMDStatusHeader        = "Status"
	labelMDSources             = "SOURCES"
	labelMDHops                = "HOPS"
	labelMDDetails             = "Evidence and provenance"
	labelMDEvaluatedAt         = "evaluated at: %s"
	labelMDInput               = "input: %s"
	labelMDConfig              = "config: %s"
	labelMDKnowledge           = "knowledge: %s %s %s"
	labelMDEngine              = "engine contract: %s"
	labelMDBuild               = "build: %s"
	labelMDNoNetwork           = "network used: no"
	labelMDNetwork             = "network used: yes"
	labelMDMore                = "... and %d more"
)

// Usage and input errors. The command prints them after "prufyx: ".
const (
	UsageInputNotAccepted = "INPUT NOT ACCEPTED: %s"
	UsageIntegrity        = "KNOWLEDGE INTEGRITY FAILURE"
	UsageUnknownFlag      = "unknown flag %s; use prufyx scan --help"
	UsageFlagValue        = "flag %s needs a value; use prufyx scan --help"
	UsageBadValue         = "invalid value for %s; use prufyx scan --help"
	UsageRepeated         = "%s given more than once"
	UsageComponentVersion = "%s takes COMPONENT=VERSION, for example kubernetes=1.30.4"
	UsageVersion          = "version %s of %s is not X.Y.Z"
	UsageUnknownComponent = "unknown component %s; closest: %s"
	// UsageUnknownComponentNoMatch is the same refusal when no known
	// component is near the name.
	UsageUnknownComponentNoMatch = "unknown component %s; list the known projects with `prufyx catalog cncf`"
	UsageConflict                = "%s is given two different versions for %s"
	UsageNoTarget                = "at least one target is required: --to COMPONENT=VERSION or target: in prufyx.yaml"
	UsageKnowledgeDBNow          = "--now cannot be used with --knowledge-db: a knowledge database is verified and evaluated at the current time"
	UsageKnowledgeEmbeddedDB     = "--knowledge=embedded cannot be used with --knowledge-db"
	UsageKnowledgeDBFailed       = "KNOWLEDGE INTEGRITY FAILURE: the knowledge database could not be verified (%s); nothing was evaluated and the embedded knowledge was not used"
	UsageNow                     = "--now must be canonical UTC with whole seconds, for example 2026-10-04T00:00:00Z"
	UsageStdinTwice              = "standard input (-) can be read only once"
	UsageConfig                  = "configuration file: %s"
	UsageConfigNotAccepted       = "configuration file is not accepted"
	UsagePermissions             = "an input file's permissions are refused by --input-permissions %s; run chmod go-rwx on it, or use --input-permissions refuse-writable"
	UsagePermissionsWrite        = "an input file is writable by other users; run chmod go-w on it"
	UsageInputUnreadable         = "an input path cannot be read"
	UsageInputLimit              = "the inputs exceed a size limit"
	UsageInputWindows            = "file and directory input is not supported on Windows; pipe the manifest on standard input (use -)"
	UsageInputDecode             = "an input file is not valid YAML or JSON within the supported subset"
	UsageInputDetail             = "%s (%s)"
	UsageConfigInputs            = "inputs in prufyx.yaml are relative to its directory and must stay inside it"
	UsageUnsupportedVersion      = "%s %s is not a version scan can plan"
	UsageRequireBasis            = "--require-basis takes a comma-separated list of reviewed, mechanical, empirical, consensus, lead"
)

// Knowledge database failure reasons, shown in UsageKnowledgeDBFailed.
const (
	KnowledgeDBPinMismatch   = "its trust root is not the root pinned in this build"
	KnowledgeDBNotPrivate    = "the database directory must be private to its owner (mode 0700) and not a symbolic link"
	KnowledgeDBNotAStore     = "the directory is not a knowledge database (no profile or selection file); run prufyx db update or db import first"
	KnowledgeDBMissing       = "no knowledge database directory at that path"
	KnowledgeDBNoSelection   = "no verified revision is selected; run prufyx db update or db import first"
	KnowledgeDBLayout        = "the database layout does not match its profile marker"
	KnowledgeDBRollback      = "rollback or clock rollback rejected"
	KnowledgeDBExpired       = "trust metadata expired"
	KnowledgeDBTrustAdvanced = "trust state advanced beyond the selection; run prufyx db update again"
	KnowledgeDBRecovery      = "an interrupted import needs recovery"
	KnowledgeDBInvalid       = "the database path or contents are not accepted"
	KnowledgeDBIntegrity     = "integrity check failed"
)

// Usage is the help text of the scan command.
const Usage = `Usage: prufyx scan [PATH ...] [-] --to COMPONENT=VERSION [--from COMPONENT=VERSION ...] [flags]

Checks rendered manifests against an upgrade: the planned hops, every blocker
with where it is and how to fix it, and every area that was not checked.

  PATH                      files or directories of rendered manifests; - reads standard input.
                            Default: inputs in prufyx.yaml, else the current directory.
  --to C=V                  target version of component C (repeatable; at least one)
  --from C=V                current version of component C (repeatable; never read from manifests)
  --config FILE             prufyx.yaml to read; default: prufyx.yaml next to the first PATH
  --distribution D          official_upstream or custom_build (Kubernetes)
  --resource-scope-complete[=true|false]   the inputs are every manifest you apply
  --target-api-apply-required[=true|false] the inputs are applied to the target API
  --format human|json|sarif|markdown|csv   output format (default human); sarif is SARIF 2.1.0 for
                            code scanning, markdown is for pull request comments and tickets,
                            csv is one row per finding location and gap for spreadsheets
  --show-passes             list passed checks (human, markdown)
  --only-blocked            list only BLOCKED findings and unserved-API gaps (human, markdown) and
                            count what is hidden; json and sarif stay complete
  --fail-on blocked|unknown|none   which verdicts give a failing exit code (default unknown:
                            10 blocked, 11 unknown); blocked exits 0 for unknown; none always
                            exits 0; usage (2) and integrity (3) errors and unserved API versions are never suppressed
  --verbose                 show hop status and cited sources (human, markdown)
  --redact                  print digests instead of file paths, names and namespaces
                            (plain digests: short names can be recovered by guessing)
  --input-permissions strict|refuse-writable   default refuse-writable
  --require-basis LIST      evidence bases to evaluate (default reviewed,mechanical,empirical,consensus);
                            a rule left out that applies keeps the answer from passing
  --knowledge-db DIR        read the knowledge from this verified local knowledge database
                            (prufyx db update or db import) instead of the embedded knowledge;
                            any verification failure exits 3, never falls back to embedded knowledge
  --knowledge auto|embedded without --knowledge-db and --now, auto (default) uses the verified database that
                            prufyx db update installed in the default store location, else the embedded
                            knowledge; a default store that is present but invalid or expired is refused
                            (exit 3); embedded forces the embedded knowledge
  --now RFC3339             evaluation instant, for exact replay (default: now, UTC;
                            not with --knowledge-db, which always evaluates at the current time)

Exit status: 0 PASS FOR THE DECLARED SCOPE, 10 BLOCKED, 11 not every area checked,
2 input not accepted, 3 knowledge integrity failure.`

// Text renders a usage or input message from this catalog, bounded.
func Text(format string, args ...any) string {
	return bound(fmt.Sprintf(format, sanitizeArgs(args)...))
}
