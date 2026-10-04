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
	ReasonAPIVersionNotServed        = "API_VERSION_NOT_SERVED"
	ReasonAPIVersionNotReviewed      = "API_VERSION_NOT_REVIEWED"
	ReasonAlphaAPINotCovered         = "ALPHA_API_NOT_COVERED"
	ReasonRuleNotDecided             = "RULE_NOT_DECIDED"
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
	GapAPIVersionNotListed     GapKey = ReasonAPIVersionNotReviewed + "/not-listed"
	GapAPIVersionNoServedList  GapKey = ReasonAPIVersionNotReviewed + "/no-served-list"
	GapLineUndecidedFact       GapKey = ReasonLineNotAttested + "/undecided-fact"
	GapAPIVersionNotReviewed   GapKey = ReasonAPIVersionNotReviewed
	GapAlphaAPINotCovered      GapKey = ReasonAlphaAPINotCovered
	GapRuleNotDecided          GapKey = ReasonRuleNotDecided
	GapRuleNeedsOtherEvidence  GapKey = ReasonRuleNotDecided + "/other-evidence"
	GapRuleStatusNotUnderstood GapKey = ReasonRuleNotDecided + "/status"
)

// Reason is the gap reason of the key.
func (k GapKey) Reason() string {
	reason, _, _ := strings.Cut(string(k), "/")
	return reason
}

type gapMessage struct {
	detail, action string
	// args is the number of arguments both templates take (by index).
	args int
}

// gapMessages holds detail and action per key. Arguments are referenced by
// explicit index so detail and action can use them in any order.
var gapMessages = map[GapKey]gapMessage{
	GapLineNotAttested: {"%[1]s %[2]s has not been reviewed for removed APIs",
		"check the %[1]s %[2]s release notes for removed APIs by hand, or request coverage", 2},
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
		"scan the hop with exact versions, or request a rule that covers whole lines", 1},
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
	GapDocumentsUnresolved: {"the manifests cannot be read as one apply set (an apiVersion or kind is not valid)",
		"pass only valid rendered Kubernetes objects", 0},
	GapDocumentsEmpty: {"no Kubernetes manifests were read",
		"pass the rendered manifests to scan", 0},
	GapDocumentsPaginated: {"a list in the inputs is paginated, so the manifests are incomplete",
		"fetch the complete list and scan it", 0},
	GapEvidenceExpired: {"the review of rule %[1]s is not current (%[2]s)",
		"use a Prufyx release with current knowledge, or check this change by hand", 2},
	GapDowngradeNotReviewed: {"downgrades are not evaluated (%[1]s %[2]s -> %[3]s)",
		"none", 3},
	GapAPIVersionNotReviewed: {"a manifest uses an API version of a reviewed kind that the reviewed removals do not name",
		"check that API version against the release notes by hand", 0},
	GapAPIVersionNotServed: {"%[1]d manifest(s) use API versions Kubernetes %[2]s no longer serves, removed before the evaluated hops",
		"migrate them to a served API version, then scan again", 2},
	GapAPIVersionNotListed: {"%[1]d manifest(s) use API versions that the review of Kubernetes %[2]s does not list as served",
		"check those API versions against the Kubernetes %[2]s API reference by hand", 2},
	GapAPIVersionNoServedList: {"no reviewed list of the API versions Kubernetes %[2]s serves; %[1]d manifest(s) cannot be checked",
		"check them against the Kubernetes %[2]s API reference by hand, or request coverage", 2},
	GapLineUndecidedFact: {"a manifest uses an API version removed on the way to %[1]s %[2]s that no reviewed rule decides",
		"check the %[1]s %[2]s release notes for removed APIs by hand", 2},
	GapAlphaAPINotCovered: {"%[1]d manifest(s) use alpha API versions of Kubernetes API groups, which removed-API reviews do not cover",
		"check alpha APIs against the release notes of every line by hand", 1},
	GapRuleNotDecided: {"rule %[1]s could not be decided (%[2]s)",
		"run the hop with prufyx check cncf to see the rule's next action, or check by hand", 2},
	GapRuleNeedsOtherEvidence: {"rule %[1]s applies to this hop but needs evidence that scan does not collect",
		"run prufyx check cncf --project %[2]s for that rule, or check by hand", 2},
	GapRuleStatusNotUnderstood: {"rule %[1]s returned a result this version of scan does not understand (%[2]s)",
		"use a newer Prufyx release, or check by hand", 2},
}

// GapReasons lists the closed vocabulary in order.
func GapReasons() []string {
	return []string{
		ReasonAlphaAPINotCovered, ReasonAPIVersionNotReviewed, ReasonAPIVersionNotServed, ReasonComponentNotCovered, ReasonDeclarationMissing,
		ReasonDistributionNotCovered, ReasonDocumentsNotEvaluated, ReasonDocumentsTemplated, ReasonDowngradeNotReviewed,
		ReasonEvidenceExpired, ReasonIntermediateLineNotCovered, ReasonLineNotAttested, ReasonNoReviewedPathPolicy,
		ReasonPathNotPlannable, ReasonPathPolicyNotCurrent, ReasonRuleNotDecided, ReasonVersionConflict, ReasonVersionNotDetected,
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

// Headlines, the clear-answer contract.
const (
	headlineBlockedOne  = "BLOCKED: 1 problem must be fixed before this upgrade"
	headlineBlockedMany = "BLOCKED: %d problems must be fixed before this upgrade"
	headlineUnknownOne  = "NO BLOCKERS FOUND IN COVERED CHECKS: 1 area was not checked"
	headlineUnknownMany = "NO BLOCKERS FOUND IN COVERED CHECKS: %d areas were not checked"
	headlineUnknownNone = "NO BLOCKERS FOUND IN COVERED CHECKS: some areas were not checked"
	headlinePass        = "PASS FOR THE DECLARED SCOPE"
)

func headline(report Report) string {
	switch report.Verdict {
	case VerdictBlocked:
		if len(report.Findings) == 1 {
			return headlineBlockedOne
		}
		return fmt.Sprintf(headlineBlockedMany, len(report.Findings))
	case VerdictPass:
		return headlinePass
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
	labelPath             = "%s %s -> %s: %s"
	labelHops             = "%d hops"
	labelHopOne           = "1 hop"
	labelPolicy           = "%s (path policy %s)"
	labelNoPolicy         = "%s (no reviewed path policy)"
	labelNoPath           = "no path (%s)"
	labelWholeUpgrade     = "whole upgrade"
	labelMore             = "... and %d more"
	labelFix              = "fix: %s"
	labelEvidenceReviewed = "evidence: reviewed"
	labelEvidenceMech     = "evidence: mechanical (%s)"
	labelSource           = "source: %s lines %d-%d; revision %s; digest %s"
	labelSharedSources    = "Sources cited by several findings:"
	labelNotChecked       = "NOT CHECKED (%d)"
	labelPassed           = "PASSED (%d)"
	labelChecked          = "Checked %s, %s, %s (%d covered)."
	labelPassCount        = " %d checks passed (--show-passes)."
	labelPassCountOne     = " 1 check passed (--show-passes)."
	labelNotEvaluated     = "Scope limits: %s."
	labelEvidence         = "Evidence: every finding cites pinned upstream source (--verbose). No network used."
	labelProvenance       = "evaluated at %s; input %s; knowledge %s %s %s"
	labelHopStatus        = "  hop %d %s -> %s: %s"
	labelDocuments        = "%d documents"
	labelDocumentOne      = "1 document"
	labelComponents       = "%d components"
	labelComponentOne     = "1 component"
	labelNoName           = "(no name)"
	labelNotices          = "ONE-WAY CHANGES (%d)"
	labelNoticeRule       = "cannot be rolled back: %s"
	labelNoticeBefore     = "before you upgrade: %s"
	labelNoticeUnresolved = "one-way notice not established: %s (%s)"
	labelNoticeNext       = "next action: %s"
)

// Usage and input errors. The command prints them after "prufyx: ".
const (
	UsageInputNotAccepted   = "INPUT NOT ACCEPTED: %s"
	UsageIntegrity          = "KNOWLEDGE INTEGRITY FAILURE"
	UsageUnknownFlag        = "unknown flag %s; use prufyx scan --help"
	UsageFlagValue          = "flag %s needs a value; use prufyx scan --help"
	UsageBadValue           = "invalid value for %s; use prufyx scan --help"
	UsageRepeated           = "%s given more than once"
	UsageComponentVersion   = "%s takes COMPONENT=VERSION, for example kubernetes=1.30.4"
	UsageVersion            = "version %s of %s is not X.Y.Z"
	UsageUnknownComponent   = "unknown component %s; closest: %s"
	UsageConflict           = "%s is given two different versions for %s"
	UsageNoTarget           = "at least one target is required: --to COMPONENT=VERSION or target: in prufyx.yaml"
	UsageKnowledgeDB        = "--knowledge-db is not supported by scan yet: external knowledge carries no line reviews or path policies, so no line could be checked; scan uses the embedded knowledge"
	UsageNow                = "--now must be canonical UTC with whole seconds, for example 2026-10-04T00:00:00Z"
	UsageStdinTwice         = "standard input (-) can be read only once"
	UsageConfig             = "configuration file: %s"
	UsageConfigNotAccepted  = "configuration file is not accepted"
	UsagePermissions        = "an input file's permissions are refused by --input-permissions %s; run chmod go-rwx on it, or use --input-permissions refuse-writable"
	UsagePermissionsWrite   = "an input file is writable by other users; run chmod go-w on it"
	UsageInputUnreadable    = "an input path cannot be read"
	UsageInputLimit         = "the inputs exceed a size limit"
	UsageInputDecode        = "an input file is not valid YAML or JSON within the supported subset"
	UsageInputDetail        = "%s (%s)"
	UsageConfigInputs       = "inputs in prufyx.yaml are relative to its directory and must stay inside it"
	UsageUnsupportedVersion = "%s %s is not a version scan can plan"
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
  --format human|json       output format (default human)
  --show-passes             list passed checks (human)
  --verbose                 show hop status and cited sources (human)
  --redact                  print digests instead of file paths, names and namespaces
                            (plain digests: short names can be recovered by guessing)
  --input-permissions strict|refuse-writable   default refuse-writable
  --now RFC3339             evaluation instant, for exact replay (default: now, UTC)

Exit status: 0 PASS FOR THE DECLARED SCOPE, 10 BLOCKED, 11 not every area checked,
2 input not accepted, 3 knowledge integrity failure.`

// Text renders a usage or input message from this catalog, bounded.
func Text(format string, args ...any) string {
	return bound(fmt.Sprintf(format, args...))
}
