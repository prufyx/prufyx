// SPDX-License-Identifier: AGPL-3.0-only

package scanrun

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"time"

	"github.com/prufyx/prufyx/cli/internal/cncfcheck"
	"github.com/prufyx/prufyx/cli/internal/cncfprepare"
	"github.com/prufyx/prufyx/cli/internal/constraintengine"
	"github.com/prufyx/prufyx/cli/internal/intake"
	"github.com/prufyx/prufyx/cli/internal/scanreport"
	"github.com/prufyx/prufyx/cli/internal/upgradepath"
)

// customResourceRun evaluates the upgrade of a project that has a
// custom-resource version set: the rules over that set alone, on one direct
// hop. No line review covers these rules yet, so the component is never
// covered: a removed version is a finding, and everything else is a gap.
type customResourceRun struct {
	knowledge    Knowledge
	now          time.Time
	report       *scanreport.Report
	workspace    intake.Workspace
	slug         string
	component    string
	fact         string
	declarations declarations
	policy       cncfcheck.TrustPolicy

	// rules are the project's rules whose every fact is the set.
	rules    []cncfcheck.ScanRule
	byID     map[string]cncfcheck.ScanRule
	findings map[string]int
	passes   map[string]bool
	excluded map[string]bool
	// rootGaps are the component-level gaps, by key.
	rootGaps map[scanreport.GapKey]scanreport.Gap
}

// newCustomResourceRun returns the run of a targeted slug that has a
// custom-resource version set, or false.
func newCustomResourceRun(knowledge Knowledge, now time.Time, report *scanreport.Report, workspace intake.Workspace, slug, component string, declared declarations, policy cncfcheck.TrustPolicy) (*customResourceRun, bool) {
	fact, ok := cncfprepare.CustomResourceVersionsFact(slug)
	if !ok {
		return nil, false
	}
	return &customResourceRun{knowledge: knowledge, now: now, report: report, workspace: workspace, slug: slug, component: component, fact: fact, declarations: declared, policy: policy}, true
}

func (r *customResourceRun) evaluate(from, to string) error {
	r.byID = map[string]cncfcheck.ScanRule{}
	for _, rule := range r.knowledge.Rules(r.slug) {
		if _, dup := r.byID[rule.Scope.ID]; dup {
			return ErrIntegrity
		}
		r.byID[rule.Scope.ID] = rule
		if len(rule.Facts) > 0 && allEqual(rule.Facts, r.fact) {
			r.rules = append(r.rules, rule)
		}
	}
	r.findings, r.passes, r.excluded = map[string]int{}, map[string]bool{}, map[string]bool{}
	r.rootGaps = map[scanreport.GapKey]scanreport.Gap{}
	r.componentGaps()
	r.unresolvedSetGap(cncfprepare.KubernetesApplySetReason(r.workspace))

	path := scanreport.Path{Component: r.slug, From: from, To: to}
	defer func() {
		r.report.Paths = append(r.report.Paths, path)
		if len(r.excluded) > 0 {
			if r.report.TrustPolicy == nil {
				r.report.TrustPolicy = &scanreport.TrustPolicy{RequiredBasis: r.policy.Bases()}
			}
			r.report.TrustPolicy.ExcludedRules += len(r.excluded)
		}
	}()
	if from == "" {
		path.Gap = scanreport.ReasonVersionNotDetected
		r.gap(nil, scanreport.GapVersionNotDetected, r.slug)
		return nil
	}
	plan := upgradepath.PlanPath(r.component, from, to, nil)
	if plan.Gap != upgradepath.GapNone {
		outcome := reasonOutcomes[string(plan.Gap)]
		if outcome.gap == "" {
			outcome.gap = scanreport.GapPathNotPlannable
		}
		path.Gap = outcome.gap.Reason()
		r.gap(nil, outcome.gap, r.slug, from, to)
		return nil
	}
	if plan.Component != r.component || len(plan.Hops) != 1 {
		return ErrIntegrity
	}
	hop, err := r.hop(plan.Hops[0])
	if err != nil {
		return err
	}
	path.Hops = append(path.Hops, hop)
	return nil
}

// componentGaps are the gaps that hold whatever the rules say: the
// component is only partly evaluated, the scope declaration, the documents
// that were not read and the objects no project owns.
func (r *customResourceRun) componentGaps() {
	r.rootGap(scanreport.GapCustomResourcesOnly, r.slug)
	if !r.declarations.scopeComplete {
		r.rootGap(scanreport.GapDeclarationScope, r.slug)
	}
	counts := map[scanreport.GapKey]int{}
	for _, omission := range r.workspace.Omissions {
		outcome, known := reasonOutcomes[string(omission.Reason)]
		if !known || outcome.gap == "" {
			outcome.gap = scanreport.GapDocumentsShape
		}
		counts[outcome.gap]++
	}
	for _, key := range []scanreport.GapKey{scanreport.GapDocumentsTemplated, scanreport.GapDocumentsLists, scanreport.GapDocumentsFiles, scanreport.GapDocumentsShape} {
		if counts[key] > 0 {
			r.rootGap(key, counts[key])
		}
	}
	if len(r.workspace.Documents) == 0 && len(r.workspace.Omissions) == 0 {
		r.rootGap(scanreport.GapDocumentsEmpty)
	}
}

// hop evaluates the direct hop.
func (r *customResourceRun) hop(hop upgradepath.Hop) (scanreport.Hop, error) {
	ref := scanreport.HopRef{Index: hop.Index, From: hop.From.String(), To: hop.To.String()}
	result := scanreport.Hop{
		Index: hop.Index,
		From:  scanreport.Endpoint{Version: hop.From.Version, Line: hop.From.Line},
		To:    scanreport.Endpoint{Version: hop.To.Version, Line: hop.To.Line},
	}
	fromVersion, fromOK := hop.From.EngineVersion()
	toVersion, toOK := hop.To.EngineVersion()
	if !fromOK || !toOK {
		return scanreport.Hop{}, ErrIntegrity
	}
	prepared, err := cncfprepare.PrepareCustomResourceVersions(r.workspace, r.slug, fromVersion, toVersion, r.declarations.scopeComplete)
	if err != nil {
		return scanreport.Hop{}, ErrIntegrity
	}
	sum := sha256.Sum256(prepared.Prepared.CanonicalInputJSON)
	if prepared.Prepared.InputDigest != "sha256:"+hex.EncodeToString(sum[:]) || prepared.Fact != r.fact {
		return scanreport.Hop{}, ErrIntegrity
	}
	result.InputDigest = prepared.Prepared.InputDigest
	if len(prepared.Unattributed) > 0 {
		r.rootGap(scanreport.GapDocumentsCustomGroup, len(prepared.Unattributed))
	}
	evaluation, err := r.knowledge.Evaluate(r.policy, r.slug, []string{r.fact}, prepared.Prepared.CanonicalInputJSON, r.now)
	if errors.Is(err, ErrRefused) {
		result.Status = scanreport.HopNoData
		result.Reasons = []string{r.rootGaps[scanreport.GapCustomResourcesOnly].Reason}
		return result, nil
	}
	if err != nil {
		return scanreport.Hop{}, ErrIntegrity
	}
	result.EngineContractDigest = evaluation.EngineContractDigest
	if r.report.Provenance.EngineContractDigest == "" {
		r.report.Provenance.EngineContractDigest = evaluation.EngineContractDigest
	}
	claims := map[string]constraintengine.Claim{}
	for _, claim := range evaluation.Claims {
		rule, known := r.byID[claim.RuleID]
		if _, dup := claims[claim.RuleID]; dup || !known || !customResourceClaimValid(rule, claim, r.policy) {
			return scanreport.Hop{}, ErrIntegrity
		}
		claims[claim.RuleID] = claim
	}

	blocked, applicable := false, 0
	overlapping := map[string]bool{}
	for _, rule := range r.rules {
		if rule.Scope.Component != r.component || !hop.Overlaps(rule.Scope.Transition) {
			continue
		}
		overlapping[rule.Scope.ID] = true
		if rule.Notice || rule.Basis == constraintengine.BasisLead {
			// Verdict-neutral rules never decide a custom-resource hop.
			continue
		}
		applicable++
		switch {
		case !hop.CoveredBy(rule.Scope.Transition):
			result.Reasons = append(result.Reasons, r.gap(&ref, scanreport.GapIntermediateLine, rule.Scope.ID))
			continue
		case !r.policy.Admits(rule.Basis):
			r.excluded[rule.Scope.ID] = true
			result.Reasons = append(result.Reasons, r.gap(&ref, scanreport.GapRuleTrustPolicy, rule.Scope.ID, rule.Basis))
			continue
		}
		claim, found := claims[rule.Scope.ID]
		if !found {
			result.Reasons = append(result.Reasons, r.gap(&ref, scanreport.GapRuleNeedsOtherEvidence, rule.Scope.ID, r.slug))
			continue
		}
		switch claim.Status {
		case "BLOCKED":
			blocked = true
			r.finding(rule, claim, prepared, ref)
		case "PASS":
			key := rule.Scope.ID + "\x00" + ref.From + "\x00" + ref.To
			if !r.passes[key] {
				r.passes[key] = true
				r.report.Passes = append(r.report.Passes, scanreport.Pass{RuleID: rule.Scope.ID, Component: r.slug, Hop: ref})
			}
		case "UNKNOWN":
			result.Reasons = append(result.Reasons, r.unknown(rule, claim, prepared, ref)...)
		case constraintengine.StatusNoKnownIssue:
			result.Reasons = append(result.Reasons, r.gap(&ref, scanreport.GapRuleNoKnownIssue, rule.Scope.ID, rule.Basis))
		default:
			result.Reasons = append(result.Reasons, r.gap(&ref, scanreport.GapRuleStatusNotUnderstood, rule.Scope.ID, quote(claim.Status)))
		}
	}
	for id, claim := range claims {
		if (claim.Status == "PASS" || claim.Status == "BLOCKED") && !overlapping[id] {
			return scanreport.Hop{}, ErrIntegrity
		}
	}
	// Nothing covers this hop: the component is only partly evaluated.
	result.Reasons = append(result.Reasons, r.rootGaps[scanreport.GapCustomResourcesOnly].Reason)
	switch {
	case blocked:
		result.Status = scanreport.HopBlocked
	case applicable == 0:
		result.Status = scanreport.HopNoData
	default:
		result.Status = scanreport.HopPartial
	}
	result.Reasons = uniqueStrings(result.Reasons)
	return result, nil
}

// unknown explains an UNKNOWN claim: by the preparation's reason when the
// set is missing or partial, otherwise by the engine's reason.
func (r *customResourceRun) unknown(rule cncfcheck.ScanRule, claim constraintengine.Claim, prepared cncfprepare.CustomResourceScan, ref scanreport.HopRef) []string {
	if factReasons[claim.ReasonCode] {
		var reasons []string
		switch prepared.Prepared.Reason {
		case cncfprepare.ReasonCustomResourcesScopeIncomplete:
			reasons = append(reasons, r.rootGap(scanreport.GapDeclarationScope, r.slug))
		case cncfprepare.ReasonCustomResourcesUnattributed:
			reasons = append(reasons, r.rootGap(scanreport.GapDocumentsCustomGroup, len(prepared.Unattributed)))
		case cncfprepare.ReasonCustomResourcesPaginated:
			reasons = append(reasons, r.rootGap(scanreport.GapDocumentsPaginated))
		case cncfprepare.ReasonCustomResourcesRendering:
			if gap, found := r.rootGaps[scanreport.GapDocumentsTemplated]; found {
				reasons = append(reasons, gap.Reason)
			}
		case cncfprepare.ReasonCustomResourcesUnresolved:
			for _, key := range []scanreport.GapKey{scanreport.GapDocumentsLists, scanreport.GapDocumentsFiles, scanreport.GapDocumentsShape, scanreport.GapDocumentsEmpty} {
				if gap, found := r.rootGaps[key]; found {
					reasons = append(reasons, gap.Reason)
				}
			}
			if len(reasons) == 0 {
				reasons = append(reasons, r.rootGap(scanreport.GapDocumentsUnresolved))
			}
		}
		if len(reasons) > 0 {
			return reasons
		}
		return []string{r.gap(&ref, scanreport.GapRuleNotDecided, rule.Scope.ID, prepared.Prepared.Reason)}
	}
	outcome, known := reasonOutcomes[claim.ReasonCode]
	switch {
	case known && outcome.decided:
		return nil
	case known && outcome.gap == scanreport.GapEvidenceExpired:
		return []string{r.gap(&ref, scanreport.GapEvidenceExpired, rule.Scope.ID, claim.EvidenceFreshness)}
	}
	return []string{r.gap(&ref, scanreport.GapRuleNotDecided, rule.Scope.ID, claim.ReasonCode)}
}

// finding records a BLOCKED claim once, located at the documents that
// carry the forbidden versions.
func (r *customResourceRun) finding(rule cncfcheck.ScanRule, claim constraintengine.Claim, prepared cncfprepare.CustomResourceScan, ref scanreport.HopRef) {
	if _, found := r.findings[rule.Scope.ID]; found {
		return
	}
	finding := scanreport.Finding{
		RuleID: rule.Scope.ID, Component: r.slug, Hop: ref, Title: title(rule.Description), Fix: rule.NextAction, Match: "anchor",
		Basis: constraintengine.EffectiveBasis(claim.EvidenceBasis), Citations: append([]constraintengine.SourceEvidence{}, claim.Sources...),
		RuleDigest: claim.RuleDigest, Locations: []scanreport.Location{},
	}
	if claim.SubjectMatch != nil {
		finding.Match = claim.SubjectMatch.Mode
	}
	markCrossing(&finding, rule, claim, false)
	if claim.EvidenceExtractor != nil {
		finding.Extractor = claim.EvidenceExtractor.ID + "@" + claim.EvidenceExtractor.Version
	}
	seen := map[intake.Source]bool{}
	for _, member := range claim.MatchedMembers {
		for _, source := range prepared.Members[member] {
			if seen[source] {
				continue
			}
			seen[source] = true
			location := scanreport.Location{File: source.Display, Document: source.Document, Item: source.Item, Line: source.Line}
			for _, document := range r.workspace.Documents {
				if document.Source == source {
					location.Kind, location.Namespace, location.Name = document.Kind, document.Namespace, document.Name
					break
				}
			}
			finding.Locations = append(finding.Locations, location)
		}
	}
	r.findings[rule.Scope.ID] = len(r.report.Findings)
	r.report.Findings = append(r.report.Findings, finding)
}

func (r *customResourceRun) gap(hop *scanreport.HopRef, key scanreport.GapKey, args ...any) string {
	gap := scanreport.NewGap(r.slug, hop, key, args...)
	r.report.Gaps = append(r.report.Gaps, gap)
	return gap.Reason
}

// unresolvedSetGap names an apply set the preparation could not resolve as
// a gap whatever the rules decide, as the Kubernetes run does: a document
// that was read but could not be placed is never an omission.
func (r *customResourceRun) unresolvedSetGap(reason cncfprepare.Reason) {
	if reason != cncfprepare.ReasonKubernetesUnresolved && reason != cncfprepare.ReasonKubernetesTemplated {
		return
	}
	for _, key := range documentGaps {
		if _, found := r.rootGaps[key]; found {
			return
		}
	}
	r.rootGap(scanreport.GapDocumentsUnresolved)
}

// rootGap adds a component-level gap once and returns its reason.
func (r *customResourceRun) rootGap(key scanreport.GapKey, args ...any) string {
	if gap, found := r.rootGaps[key]; found {
		return gap.Reason
	}
	gap := scanreport.NewGap(r.slug, nil, key, args...)
	r.rootGaps[key] = gap
	r.report.Gaps = append(r.report.Gaps, gap)
	return gap.Reason
}

// customResourceClaimValid holds a claim to its rule: neutral rules never
// pass or block and only they give NOTICE; NO_KNOWN_ISSUE comes only from
// consensus or lead evidence; a rule the trust policy leaves out has no
// claim; UNSUPPORTED comes only from a support-range rule.
func customResourceClaimValid(rule cncfcheck.ScanRule, claim constraintengine.Claim, policy cncfcheck.TrustPolicy) bool {
	neutral := rule.Notice || rule.Basis == constraintengine.BasisLead
	switch {
	case claim.IsNotice() != rule.Notice, claim.IsLead() != (rule.Basis == constraintengine.BasisLead):
		return false
	case neutral && (claim.Status == "PASS" || claim.Status == "BLOCKED"):
		return false
	case !neutral && claim.Status == constraintengine.StatusNotice:
		return false
	case claim.Status == constraintengine.StatusNoKnownIssue && rule.Basis != constraintengine.BasisConsensus && rule.Basis != constraintengine.BasisLead:
		return false
	case !policy.Admits(rule.Basis):
		return false
	case claim.Status == constraintengine.StatusUnsupported:
		return false
	}
	return true
}

func allEqual(values []string, want string) bool {
	for _, v := range values {
		if v != want {
			return false
		}
	}
	return true
}

func uniqueStrings(values []string) []string {
	seen := map[string]bool{}
	out := values[:0]
	for _, v := range values {
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	return out
}
