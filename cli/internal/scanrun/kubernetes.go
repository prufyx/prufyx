// SPDX-License-Identifier: AGPL-3.0-only

package scanrun

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/prufyx/prufyx/cli/internal/cncfcheck"
	"github.com/prufyx/prufyx/cli/internal/cncfprepare"
	"github.com/prufyx/prufyx/cli/internal/constraintengine"
	"github.com/prufyx/prufyx/cli/internal/intake"
	"github.com/prufyx/prufyx/cli/internal/lineattest"
	"github.com/prufyx/prufyx/cli/internal/scanreport"
	"github.com/prufyx/prufyx/cli/internal/upgradepath"
)

const (
	kubernetesSlug = "kubernetes"
	familyID       = lineattest.FamilyKubernetesRemovedServedGVK
)

// kubernetesRun evaluates the planned upgrade of Kubernetes for the removed
// served API versions of the manifests.
type kubernetesRun struct {
	knowledge    Knowledge
	now          time.Time
	report       *scanreport.Report
	workspace    intake.Workspace
	component    string
	declarations declarations
	policy       cncfcheck.TrustPolicy

	rules    []cncfcheck.ScanRule
	byID     map[string]cncfcheck.ScanRule
	findings map[string]int // rule id -> index in report.Findings
	passes   map[string]bool
	// rootGaps are the component-level gaps (declarations, documents)
	// that keep a claim from being decided, keyed by their message.
	rootGaps map[scanreport.GapKey]scanreport.Gap
	// excluded and excludedLeads are the rules that apply to the upgrade
	// but that the trust policy left out.
	excluded, excludedLeads map[string]bool
	// blocked are the objects a BLOCKED finding names: a reviewed rule
	// decided them.
	blocked map[intake.Source]bool
}

func (r *kubernetesRun) evaluate(from, to string) error {
	r.rules = r.knowledge.Rules(kubernetesSlug)
	r.byID = make(map[string]cncfcheck.ScanRule, len(r.rules))
	for _, rule := range r.rules {
		if _, dup := r.byID[rule.Scope.ID]; dup {
			return ErrIntegrity
		}
		r.byID[rule.Scope.ID] = rule
	}
	r.findings, r.passes = map[string]int{}, map[string]bool{}
	r.excluded, r.excludedLeads = map[string]bool{}, map[string]bool{}
	r.blocked = map[intake.Source]bool{}
	r.rootGaps = r.componentGaps()
	for _, gap := range r.rootGaps {
		r.report.Gaps = append(r.report.Gaps, gap)
	}
	r.unresolvedSetGap(cncfprepare.KubernetesApplySetReason(r.workspace))

	path := scanreport.Path{Component: kubernetesSlug, From: from, To: to}
	// entered are the release lines the planned upgrade enters; it stays
	// empty when no upgrade can be planned.
	entered := map[string]bool{}
	defer func() {
		path.ServedList = r.apiVersionGaps(to, entered)
		r.report.Paths = append(r.report.Paths, path)
		if len(r.excluded)+len(r.excludedLeads) > 0 {
			r.report.TrustPolicy = &scanreport.TrustPolicy{RequiredBasis: r.policy.Bases(), ExcludedRules: len(r.excluded), ExcludedLeadRules: len(r.excludedLeads)}
		}
	}()
	if from == "" {
		path.Gap = scanreport.ReasonVersionNotDetected
		r.gap(nil, scanreport.GapVersionNotDetected, kubernetesSlug)
		return nil
	}
	status := r.knowledge.PathPolicyFor(r.component, r.now)
	if status.RecordNotCurrent() {
		path.Gap = scanreport.ReasonPathPolicyNotCurrent
		r.gap(nil, scanreport.GapPathPolicyNotCurrent, kubernetesSlug, status.Freshness)
		return nil
	}
	if status.Policy() != nil && !r.policy.Admits(status.Record.Evidence.Basis) {
		// A current policy whose evidence basis the trust policy leaves out
		// is not used, and no direct hop stands in for it.
		path.Gap = scanreport.ReasonNoReviewedPathPolicy
		r.gap(nil, scanreport.GapPathPolicyTrustPolicy, kubernetesSlug, constraintengine.EffectiveBasis(status.Record.Evidence.Basis))
		return nil
	}
	policy := status.Policy()
	plan := upgradepath.PlanPath(r.component, from, to, policy)
	if plan.Gap != upgradepath.GapNone {
		outcome := reasonOutcomes[string(plan.Gap)]
		if outcome.gap == "" {
			outcome.gap = scanreport.GapPathNotPlannable
		}
		path.Gap = outcome.gap.Reason()
		r.gap(nil, outcome.gap, kubernetesSlug, from, to)
		return nil
	}
	if plan.Component != r.component || len(plan.Hops) == 0 {
		return ErrIntegrity
	}
	if policy != nil {
		path.Policy = policy.Policy
	}
	unplanned := policy == nil && skipsLines(from, to)
	if unplanned {
		r.gap(nil, scanreport.GapNoReviewedPathPolicy, kubernetesSlug, from, to)
	}
	for _, line := range enteredLines(from, to) {
		entered[line] = true
	}
	for _, hop := range plan.Hops {
		evaluated, err := r.hop(hop, unplanned)
		if err != nil {
			return err
		}
		path.Hops = append(path.Hops, evaluated)
	}
	if len(plan.Hops) > 1 {
		if err := r.wholeUpgrade(from, to, plan); err != nil {
			return err
		}
	}
	return nil
}

// componentGaps are the gaps that hold for every hop: declarations, the
// documents that were not evaluated, and alpha API versions.
func (r *kubernetesRun) componentGaps() map[scanreport.GapKey]scanreport.Gap {
	gaps := map[scanreport.GapKey]scanreport.Gap{}
	add := func(key scanreport.GapKey, args ...any) {
		gaps[key] = scanreport.NewGap(kubernetesSlug, nil, key, args...)
	}
	for _, key := range r.declarationGaps() {
		if key == scanreport.GapDistributionNotCovered {
			add(key, kubernetesSlug, r.declarations.distribution)
		} else {
			add(key, kubernetesSlug)
		}
	}
	counts := map[scanreport.GapKey]int{}
	for _, omission := range r.workspace.Omissions {
		outcome, known := reasonOutcomes[string(omission.Reason)]
		if !known || outcome.gap == "" {
			outcome.gap = scanreport.GapDocumentsShape
		}
		counts[outcome.gap]++
	}
	for key, n := range counts {
		add(key, n)
	}
	if len(r.workspace.Documents) == 0 && len(r.workspace.Omissions) == 0 {
		add(scanreport.GapDocumentsEmpty)
	}
	alpha, items := 0, false
	for _, document := range r.workspace.Documents {
		if alphaKubernetesAPI(document.APIVersion) {
			alpha++
		}
		// An object that is not a List but holds an items array is not
		// flattened, so the objects in it are never read.
		if _, isList := document.Value["items"].([]any); isList {
			items = true
		}
	}
	if items {
		add(scanreport.GapDocumentsUnresolved)
	}
	if alpha > 0 {
		add(scanreport.GapAlphaAPINotCovered, alpha)
	}
	return gaps
}

// declarationGaps lists the declaration gaps: every precondition of a pass
// that the operator did not declare.
func (r *kubernetesRun) declarationGaps() []scanreport.GapKey {
	var keys []scanreport.GapKey
	if !r.declarations.scopeComplete {
		keys = append(keys, scanreport.GapDeclarationScope)
	}
	if !r.declarations.applyRequired {
		keys = append(keys, scanreport.GapDeclarationApply)
	}
	switch {
	case !r.declarations.distributionSet:
		keys = append(keys, scanreport.GapDeclarationDistribution)
	case r.declarations.distribution != "official_upstream":
		keys = append(keys, scanreport.GapDistributionNotCovered)
	}
	return keys
}

// enteredLines are the minor lines an upgrade from one exact version to
// another enters, in order: every line above the line of from up to the line
// of to, within one major version. A downgrade, a patch upgrade or a major
// change enters none.
func enteredLines(from, to string) []string {
	fromMajor, fromMinor, ok1 := majorMinor(from)
	toMajor, toMinor, ok2 := majorMinor(to)
	if !ok1 || !ok2 || fromMajor != toMajor {
		return nil
	}
	var lines []string
	for minor := fromMinor + 1; minor <= toMinor; minor++ {
		lines = append(lines, strconv.FormatUint(fromMajor, 10)+"."+strconv.FormatUint(minor, 10))
	}
	return lines
}

// apiVersionGaps checks every manifest against the target line: an object
// at a version removed on a line at or below the target is not served unless
// a reviewed rule decided it (a BLOCKED finding names it), and an object of
// a Kubernetes API group must be at a version the review of the target line
// lists as served. An object removed on a line the upgrade enters is named
// apart from one removed before it, because there a rule could have decided.
// It returns the served list the check relied on, nil when none was
// consulted.
func (r *kubernetesRun) apiVersionGaps(to string, entered map[string]bool) *scanreport.ServedList {
	targetLine, ok := lineattest.LineOf(to)
	if !ok {
		return nil
	}
	removed := cncfprepare.KubernetesRemovedVersions()
	status := r.knowledge.ServedAPIs(r.component, targetLine, r.now)
	usable := status.Found && status.Freshness == lineattest.FreshnessCurrent && status.List.Line == targetLine &&
		status.List.Component == r.component && r.policy.Admits(status.List.Basis)
	notServed, notServedEntered, notListed, builtIn := 0, 0, 0, 0
	for _, document := range r.workspace.Documents {
		group, version, found := strings.Cut(document.APIVersion, "/")
		if !found {
			group, version = "", document.APIVersion
		}
		for _, removal := range removed {
			if removal.Group != group || removal.Version != version || !containsString(removal.Kinds, document.Kind) ||
				lineattest.LineLess(targetLine, removal.Line) {
				continue
			}
			switch {
			case r.blocked[document.Source]:
			case entered[removal.Line]:
				notServedEntered++
			default:
				notServed++
			}
			break
		}
		if !kubernetesGroupRE.MatchString(group) || alphaVersionRE.MatchString(version) {
			continue
		}
		builtIn++
		if usable && !status.List.APIs[document.APIVersion+" "+document.Kind] {
			notListed++
		}
	}
	if notServed > 0 {
		r.rootGap(scanreport.GapAPIVersionNotServed, notServed, targetLine)
	}
	if notServedEntered > 0 {
		r.rootGap(scanreport.GapAPIVersionNotServedCrossed, notServedEntered, targetLine)
	}
	if builtIn == 0 {
		return nil
	}
	switch {
	case !status.Found:
		r.rootGap(scanreport.GapAPIVersionNoServedList, builtIn, targetLine)
	case status.List.Line != targetLine || status.List.Component != r.component:
		r.rootGap(scanreport.GapServedListMismatch, targetLine)
	case status.Freshness != lineattest.FreshnessCurrent:
		r.rootGap(scanreport.GapServedListNotCurrent, targetLine, status.Freshness)
	case !r.policy.Admits(status.List.Basis):
		r.rootGap(scanreport.GapServedListTrustPolicy, targetLine, constraintengine.EffectiveBasis(status.List.Basis))
	case notListed > 0:
		r.rootGap(scanreport.GapAPIVersionNotListed, notListed, targetLine)
	}
	if !usable {
		return nil
	}
	return &scanreport.ServedList{
		Line: status.List.Line, Basis: constraintengine.EffectiveBasis(status.List.Basis), Freshness: status.Freshness,
		ValidUntil: status.List.ValidUntil, Digest: servedListDigest(status.List.APIs),
	}
}

// servedListDigest is "sha256:" over the list's sorted pairs, one per line.
func servedListDigest(apis map[string]bool) string {
	pairs := make([]string, 0, len(apis))
	for pair := range apis {
		pairs = append(pairs, pair)
	}
	sort.Strings(pairs)
	sum := sha256.Sum256([]byte(strings.Join(pairs, "\n") + "\n"))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func containsString(values []string, value string) bool {
	for _, candidate := range values {
		if candidate == value {
			return true
		}
	}
	return false
}

// kubernetesGroupRE matches the API groups Kubernetes itself serves: the core
// group, every group without a dot (a custom resource group must contain
// one) and every *.k8s.io group. Their objects must be on the served list of
// the target, and their alpha versions are outside every removed-API review.
var kubernetesGroupRE = regexp.MustCompile(`^([a-z0-9-]*|[a-z0-9.-]+\.k8s\.io)$`)

var alphaVersionRE = regexp.MustCompile(`^v[0-9]+alpha[0-9]*$`)

func alphaKubernetesAPI(apiVersion string) bool {
	group, version, found := strings.Cut(apiVersion, "/")
	if !found {
		group, version = "", apiVersion
	}
	return alphaVersionRE.MatchString(version) && kubernetesGroupRE.MatchString(group)
}

// skipsLines reports whether a direct upgrade from one version to the other
// crosses more than one minor line.
func skipsLines(from, to string) bool {
	fromMajor, fromMinor, ok1 := majorMinor(from)
	toMajor, toMinor, ok2 := majorMinor(to)
	return !ok1 || !ok2 || fromMajor != toMajor || toMinor > fromMinor+1
}

func majorMinor(version string) (uint64, uint64, bool) {
	parts := strings.Split(version, ".")
	if len(parts) < 2 {
		return 0, 0, false
	}
	major, err1 := strconv.ParseUint(parts[0], 10, 64)
	minor, err2 := strconv.ParseUint(parts[1], 10, 64)
	return major, minor, err1 == nil && err2 == nil
}

// gap adds one gap and returns its reason.
func (r *kubernetesRun) gap(hop *scanreport.HopRef, key scanreport.GapKey, args ...any) string {
	gap := scanreport.NewGap(kubernetesSlug, hop, key, args...)
	r.report.Gaps = append(r.report.Gaps, gap)
	return gap.Reason
}

// evaluation is what the engine said for one transition.
type evaluation struct {
	scan     cncfprepare.KubernetesScan
	contract string
	claims   map[string]constraintengine.Claim
	// refused is true when the knowledge cannot evaluate the input: it
	// has no fact for a removal the preparation derives.
	refused bool
}

// readsAnyRemoval reports whether some rule of the knowledge reads one of
// the removal facts the preparation derives for the transition. It is true
// when the transition crosses no line with removals.
func (r *kubernetesRun) readsAnyRemoval(from, to string) bool {
	facts := cncfprepare.KubernetesRemovedAPIFacts(from, to)
	if len(facts) == 0 {
		return true
	}
	for _, rule := range r.rules {
		for _, fact := range rule.Facts {
			if containsFact(facts, fact) {
				return true
			}
		}
	}
	return false
}

func containsFact(facts []string, fact string) bool {
	for _, candidate := range facts {
		if candidate == fact {
			return true
		}
	}
	return false
}

// evaluateTransition prepares the engine input for one concrete transition
// exactly as the single-file route does and evaluates it.
func (r *kubernetesRun) evaluateTransition(from, to string) (evaluation, error) {
	scan, err := cncfprepare.PrepareKubernetesScan(r.workspace, from, to, r.declarations.distribution, r.declarations.applyRequired, r.declarations.scopeComplete)
	if err != nil {
		return evaluation{}, ErrIntegrity
	}
	sum := sha256.Sum256(scan.Prepared.CanonicalInputJSON)
	if scan.Prepared.InputDigest != "sha256:"+hex.EncodeToString(sum[:]) {
		return evaluation{}, ErrIntegrity
	}
	if !r.readsAnyRemoval(from, to) {
		// The knowledge knows the line's removal facts but publishes no
		// rule over any of them: as when it lacks the facts, no review of
		// the line can stand for a decision.
		return evaluation{scan: scan, refused: true}, nil
	}
	result, err := r.knowledge.Evaluate(r.policy, kubernetesSlug, cncfprepare.KubernetesRemovedAPIAllFacts(), scan.Prepared.CanonicalInputJSON, r.now)
	if errors.Is(err, ErrRefused) {
		// The knowledge has no fact for a removal the preparation knows
		// about on this line: no reviewed rule can decide it.
		return evaluation{scan: scan, refused: true}, nil
	}
	if err != nil {
		return evaluation{}, ErrIntegrity
	}
	if r.report.Provenance.EngineContractDigest == "" {
		r.report.Provenance.EngineContractDigest = result.EngineContractDigest
	}
	claims := make(map[string]constraintengine.Claim, len(result.Claims))
	for _, claim := range result.Claims {
		if _, dup := claims[claim.RuleID]; dup {
			return evaluation{}, ErrIntegrity
		}
		rule, known := r.byID[claim.RuleID]
		if !known {
			return evaluation{}, ErrIntegrity
		}
		// A notice comes only from a notice rule and is never a verdict;
		// a verdict rule never returns NOTICE.
		// A notice or a lead is never a verdict; NOTICE comes only from
		// them; NO_KNOWN_ISSUE only from consensus or lead evidence; a rule
		// the trust policy leaves out has no claim.
		notice, lead := claim.IsNotice(), claim.IsLead()
		neutral := rule.Notice || rule.Basis == constraintengine.BasisLead
		switch {
		case notice != rule.Notice:
			return evaluation{}, ErrIntegrity
		case lead != (rule.Basis == constraintengine.BasisLead):
			return evaluation{}, ErrIntegrity
		case neutral && (claim.Status == "PASS" || claim.Status == "BLOCKED"):
			return evaluation{}, ErrIntegrity
		case !neutral && claim.Status == constraintengine.StatusNotice:
			return evaluation{}, ErrIntegrity
		case claim.Status == constraintengine.StatusNoKnownIssue && rule.Basis != constraintengine.BasisConsensus && rule.Basis != constraintengine.BasisLead:
			return evaluation{}, ErrIntegrity
		case !r.policy.Admits(rule.Basis):
			return evaluation{}, ErrIntegrity
		case (claim.Status == constraintengine.StatusUnsupported) && rule.Severity != constraintengine.SeverityUnsupported:
			return evaluation{}, ErrIntegrity
		case rule.Severity != "" && (neutral || claim.Status == "BLOCKED"):
			return evaluation{}, ErrIntegrity
		case claim.CrossingMatch != nil && claim.Status == "BLOCKED" && r.declarations.distribution != "official_upstream":
			// The engine input carries plain versions with no distribution,
			// which a crossing reads as upstream. Only a declared upstream
			// build makes that true; any other declaration prepares no fact
			// a crossing could block on, so a crossing BLOCK here is a fault.
			return evaluation{}, ErrIntegrity
		}
		claims[claim.RuleID] = claim
	}
	return evaluation{scan: scan, claims: claims, contract: result.EngineContractDigest}, nil
}

// judgement is the result of one applicable rule.
type judgement struct {
	decided, blocked bool
	reasons          []string
	// facts are the facts a PASS or BLOCKED claim judged.
	facts []string
}

// judge decides one rule that covers the transition from its claim, or whose
// removal crossing does (viaCrossing, BLOCKED only). A rule
// without a claim needs evidence the scan does not collect. Only PASS,
// BLOCKED and an UNKNOWN that the engine reports for a rule that does not
// apply are decided; every other result is a gap.
func (r *kubernetesRun) judge(rule cncfcheck.ScanRule, eval evaluation, ref scanreport.HopRef, viaCrossing bool) judgement {
	claim, found := eval.claims[rule.Scope.ID]
	if !found {
		return judgement{reasons: []string{r.gap(&ref, scanreport.GapRuleNeedsOtherEvidence, rule.Scope.ID, kubernetesSlug)}}
	}
	switch claim.Status {
	case "BLOCKED":
		r.finding(rule, claim, eval, ref, viaCrossing)
		return judgement{decided: true, blocked: true, facts: claimFacts(claim)}
	case "PASS":
		key := rule.Scope.ID + "\x00" + ref.From + "\x00" + ref.To + "\x00" + strconv.FormatBool(ref.WholeUpgrade)
		if !r.passes[key] {
			r.passes[key] = true
			r.report.Passes = append(r.report.Passes, scanreport.Pass{RuleID: rule.Scope.ID, Component: kubernetesSlug, Hop: ref})
		}
		return judgement{decided: true, facts: claimFacts(claim)}
	case constraintengine.StatusUnsupported:
		r.unsupported(rule, claim, ref)
		return judgement{reasons: []string{r.gap(&ref, scanreport.GapUnsupportedCombination, rule.Scope.ID, claim.ReasonCode)}}
	case constraintengine.StatusNoKnownIssue:
		return judgement{reasons: []string{r.gap(&ref, scanreport.GapRuleNoKnownIssue, rule.Scope.ID, rule.Basis)}}
	case "UNKNOWN":
	default:
		return judgement{reasons: []string{r.gap(&ref, scanreport.GapRuleStatusNotUnderstood, rule.Scope.ID, quote(claim.Status))}}
	}
	if factReasons[claim.ReasonCode] {
		return judgement{reasons: r.preparationGaps(eval.scan.Prepared, rule.Scope.ID, claim.ReasonCode, ref)}
	}
	outcome, known := reasonOutcomes[claim.ReasonCode]
	switch {
	case known && outcome.decided:
		return judgement{decided: true}
	case known && outcome.gap == scanreport.GapEvidenceExpired:
		return judgement{reasons: []string{r.gap(&ref, scanreport.GapEvidenceExpired, rule.Scope.ID, claim.EvidenceFreshness)}}
	}
	return judgement{reasons: []string{r.gap(&ref, scanreport.GapRuleNotDecided, rule.Scope.ID, claim.ReasonCode)}}
}

// preparationGaps explains a claim whose fact the preparation left
// unsupported, by the preparation's reason. Component-level causes are
// already gaps of their own; the hop records their reasons.
func (r *kubernetesRun) preparationGaps(prepared cncfprepare.Prepared, ruleID, claimReason string, ref scanreport.HopRef) []string {
	outcome, known := reasonOutcomes[prepared.Reason]
	switch {
	case known && outcome.declarations:
		var reasons []string
		for _, key := range r.declarationGaps() {
			reasons = append(reasons, key.Reason())
		}
		if len(reasons) > 0 {
			return reasons
		}
	case known && outcome.decided && prepared.Reason == cncfprepare.ReasonKubernetesRemovedGVKPresent:
		// A present removed version is reported while another fact of the
		// same set stays unsupported: a document uses a version the reviews
		// do not name.
		return []string{r.rootGap(scanreport.GapAPIVersionNotReviewed)}
	case known && outcome.gap == scanreport.GapDocumentsUnresolved && (len(r.workspace.Omissions) > 0 || len(r.workspace.Documents) == 0):
		// The omitted documents (or the empty input) are the cause; they
		// are component-level gaps already.
		var reasons []string
		for _, omission := range r.workspace.Omissions {
			if documentGap, found := reasonOutcomes[string(omission.Reason)]; found {
				reasons = append(reasons, documentGap.gap.Reason())
			}
		}
		if len(r.workspace.Documents) == 0 && len(r.workspace.Omissions) == 0 {
			reasons = append(reasons, r.rootGap(scanreport.GapDocumentsEmpty))
		}
		if len(reasons) > 0 {
			return reasons
		}
	case known && !outcome.decided && outcome.gap != "":
		if gap, found := r.rootGaps[outcome.gap]; found {
			return []string{gap.Reason}
		}
		switch outcome.gap {
		case scanreport.GapDocumentsTemplated:
			return []string{r.rootGap(outcome.gap, len(r.workspace.Omissions))}
		case scanreport.GapDocumentsUnresolved, scanreport.GapDocumentsPaginated, scanreport.GapAPIVersionNotReviewed:
			return []string{r.rootGap(outcome.gap)}
		case scanreport.GapDeclarationScope:
			return []string{r.rootGap(outcome.gap, kubernetesSlug)}
		}
	}
	return []string{r.gap(&ref, scanreport.GapRuleNotDecided, ruleID, claimReason)}
}

// documentGaps are the component-level gaps that name documents the apply
// set could not read or place.
var documentGaps = []scanreport.GapKey{
	scanreport.GapDocumentsTemplated, scanreport.GapDocumentsLists, scanreport.GapDocumentsFiles,
	scanreport.GapDocumentsShape, scanreport.GapDocumentsUnresolved, scanreport.GapDocumentsEmpty,
}

// unresolvedSetGap makes an apply set that cannot be read as a whole a gap
// whatever the declarations and the rules decide: the documents that were
// read can show a removed version present, never that nothing else is
// there. Omitted documents are gaps already; a document that was read but
// cannot be placed (an invalid apiVersion or kind, a list with invalid
// metadata) is named here.
func (r *kubernetesRun) unresolvedSetGap(reason cncfprepare.Reason) {
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
func (r *kubernetesRun) rootGap(key scanreport.GapKey, args ...any) string {
	if gap, found := r.rootGaps[key]; found {
		return gap.Reason
	}
	gap := scanreport.NewGap(kubernetesSlug, nil, key, args...)
	r.rootGaps[key] = gap
	r.report.Gaps = append(r.report.Gaps, gap)
	return gap.Reason
}

// hop evaluates one planned hop.
func (r *kubernetesRun) hop(hop upgradepath.Hop, unplanned bool) (scanreport.Hop, error) {
	ref := scanreport.HopRef{Index: hop.Index, From: hop.From.String(), To: hop.To.String()}
	result := scanreport.Hop{
		Index: hop.Index,
		From:  scanreport.Endpoint{Version: hop.From.Version, Line: hop.From.Line},
		To:    scanreport.Endpoint{Version: hop.To.Version, Line: hop.To.Line},
	}
	fromVersion, fromOK := hop.From.EngineVersion()
	toVersion, toOK := hop.To.EngineVersion()
	if !fromOK || !toOK {
		result.Status = scanreport.HopNoData
		result.Reasons = []string{r.gap(&ref, scanreport.GapIntermediateMajor)}
		return result, nil
	}
	eval, err := r.evaluateTransition(fromVersion, toVersion)
	if err != nil {
		return scanreport.Hop{}, err
	}
	result.InputDigest, result.EngineContractDigest = eval.scan.Prepared.InputDigest, eval.contract
	if eval.refused {
		_, toLine, _ := hopLines(hop)
		result.Status = scanreport.HopNoData
		result.Reasons = []string{r.gap(&ref, scanreport.GapLineNoRules, kubernetesSlug, toLine)}
		blocked, err := r.enteredLineBlockers(hop, ref)
		if err != nil {
			return scanreport.Hop{}, err
		}
		if blocked {
			result.Status = scanreport.HopBlocked
		}
		return result, nil
	}

	// Every claim that decided something must belong to a rule that
	// overlaps the hop: a decided claim matched the engine input, which
	// lies inside the hop.
	// One-way notice rules never take part in the verdict: they are kept
	// out of the applicable set and only reported as notices.
	overlapping := map[string]bool{}
	var applicable []cncfcheck.ScanRule
	for _, rule := range r.rules {
		if rule.Scope.Component != r.component || !hop.Overlaps(rule.Scope.Transition) {
			continue
		}
		overlapping[rule.Scope.ID] = true
		if r.neutral(rule, eval, ref, hop.CoveredBy(rule.Scope.Transition)) {
			continue
		}
		applicable = append(applicable, rule)
	}
	for id, claim := range eval.claims {
		if (claim.Status == "PASS" || claim.Status == "BLOCKED" || claim.Status == constraintengine.StatusNotice) && !overlapping[id] {
			return scanreport.Hop{}, ErrIntegrity
		}
	}

	decidedAll, blocked := true, false
	decidedRules := map[string]bool{}
	verdictFacts := map[string]bool{}
	for _, rule := range applicable {
		viaCrossing := false
		if !hop.CoveredBy(rule.Scope.Transition) {
			// A removal crossing covers the whole hop even when no reviewed
			// range does: its BLOCKED claim holds for every release the hop
			// stands for (a crossing only blocks, never passes), so the
			// blocker is kept. Anything else it said at the engine input is
			// downgraded, as for any rule that covers only part of the hop.
			claim, found := eval.claims[rule.Scope.ID]
			if !found || claim.Status != "BLOCKED" || !hop.CrossingCovers(rule.Scope.Transition) {
				// The rule applies to some releases of the hop and not to
				// others; whatever it said at the engine input is downgraded.
				decidedAll = false
				result.Reasons = append(result.Reasons, r.gap(&ref, scanreport.GapIntermediateLine, rule.Scope.ID))
				continue
			}
			viaCrossing = true
		}
		if !r.policy.Admits(rule.Basis) {
			// The trust policy left the rule out: it was not evaluated.
			r.excluded[rule.Scope.ID] = true
			decidedAll = false
			result.Reasons = append(result.Reasons, r.gap(&ref, scanreport.GapRuleTrustPolicy, rule.Scope.ID, rule.Basis))
			continue
		}
		judged := r.judge(rule, eval, ref, viaCrossing)
		for _, fact := range judged.facts {
			verdictFacts[fact] = true
		}
		result.Reasons = append(result.Reasons, judged.reasons...)
		if judged.blocked {
			blocked = true
		}
		if judged.decided {
			decidedRules[rule.Scope.ID] = true
		} else {
			decidedAll = false
		}
	}

	// A hop that skips release lines prepares no removal fact of the lines
	// it skips; the step of the hop that enters each of them is evaluated
	// on its own, and a reviewed rule that blocks it blocks the hop.
	enteredBlocked, err := r.enteredLineBlockers(hop, ref)
	if err != nil {
		return scanreport.Hop{}, err
	}
	blocked = blocked || enteredBlocked

	attested, attestationCurrent := r.attestation(hop, ref, unplanned, applicable, decidedRules, &result)
	if attested {
		// A fact the preparation found true must have been judged by a PASS
		// or BLOCKED claim on this hop; otherwise no review can cover it.
		for fact := range eval.scan.Sources {
			if !verdictFacts[fact] {
				_, toLine, _ := hopLines(hop)
				attested = false
				result.Reasons = append(result.Reasons, r.gap(&ref, scanreport.GapLineUndecidedFact, kubernetesSlug, toLine))
				break
			}
		}
	}

	switch {
	case blocked:
		result.Status = scanreport.HopBlocked
	case decidedAll && attested:
		result.Status = scanreport.HopCovered
		result.Reasons = nil
	case len(applicable) == 0 && !attestationCurrent:
		result.Status = scanreport.HopNoData
	default:
		result.Status = scanreport.HopPartial
	}
	return result, nil
}

// enteredLineBlockers evaluates, for a hop that skips release lines, the
// step of the hop that enters each skipped or target line with known
// removals: from the hop's own start (or the whole line before) to the whole
// entered line (or the hop's own end). Every upgrade over the hop takes such
// a step, because Kubernetes upgrades one minor line at a time, so a
// reviewed rule that covers the whole step (its range, or its removal
// crossing) and blocks it blocks the hop; the finding names the step. It
// only blocks: anything else such a step says is not used, since it decides
// one step and not the hop, which keeps its own gaps. A hop that enters at
// most one line has nothing to add: its own evaluation prepared the facts.
func (r *kubernetesRun) enteredLineBlockers(hop upgradepath.Hop, ref scanreport.HopRef) (bool, error) {
	fromLine, toLine, ok := hopLines(hop)
	if !ok || previousLine(toLine) == fromLine || !lineattest.LineLess(fromLine, toLine) {
		return false, nil
	}
	removalLines := map[string]bool{}
	for _, removal := range cncfprepare.KubernetesRemovedVersions() {
		removalLines[removal.Line] = true
	}
	blocked := false
	for _, line := range enteredLines(fromLine+".0", toLine+".0") {
		if !removalLines[line] {
			continue
		}
		step := upgradepath.Hop{Index: hop.Index, From: upgradepath.Endpoint{Line: previousLine(line)}, To: upgradepath.Endpoint{Line: line}}
		if step.From.Line == fromLine {
			step.From = hop.From
		}
		if line == toLine {
			step.To = hop.To
		}
		fromVersion, fromOK := step.From.EngineVersion()
		toVersion, toOK := step.To.EngineVersion()
		if !fromOK || !toOK {
			continue
		}
		eval, err := r.evaluateTransition(fromVersion, toVersion)
		if err != nil {
			return false, err
		}
		if eval.refused {
			continue
		}
		for _, rule := range r.rules {
			claim, found := eval.claims[rule.Scope.ID]
			if !found || claim.Status != "BLOCKED" {
				continue
			}
			if rule.Scope.Component != r.component || !step.Overlaps(rule.Scope.Transition) {
				// A decided claim matched the step's engine input, which lies
				// inside the step.
				return false, ErrIntegrity
			}
			viaCrossing := false
			if !step.CoveredBy(rule.Scope.Transition) {
				if !step.CrossingCovers(rule.Scope.Transition) {
					continue
				}
				viaCrossing = true
			}
			if rule.Notice || rule.Basis == constraintengine.BasisLead || !r.policy.Admits(rule.Basis) {
				continue
			}
			if finding := r.finding(rule, claim, eval, ref, viaCrossing); finding != nil {
				finding.CrossedLine = &scanreport.CrossedLine{Line: line, From: step.From.String(), To: step.To.String()}
				finding.Fix = crossedLineFix(finding.Fix, *finding.CrossedLine)
			}
			blocked = true
		}
	}
	return blocked, nil
}

// crossedLineFix appends the step disclosure to a rule's fix.
func crossedLineFix(fix string, step scanreport.CrossedLine) string {
	disclosure := "decided on the step " + step.From + " -> " + step.To + ", which this upgrade takes to enter Kubernetes " + step.Line
	if strings.HasSuffix(fix, ".") {
		return fix + " " + strings.ToUpper(disclosure[:1]) + disclosure[1:] + "."
	}
	return fix + "; " + disclosure
}

// attestation checks the line review the hop needs: the hop must enter one
// release line from the line before it, the line's review must be current,
// every rule it lists must have decided this hop, and every family rule of
// the line that overlaps the hop must be listed. It returns whether the hop
// is attested and whether a current review exists.
func (r *kubernetesRun) attestation(hop upgradepath.Hop, ref scanreport.HopRef, unplanned bool, applicable []cncfcheck.ScanRule, decidedRules map[string]bool, result *scanreport.Hop) (bool, bool) {
	fromLine, toLine, ok := hopLines(hop)
	if !ok {
		result.Reasons = append(result.Reasons, r.gap(&ref, scanreport.GapIntermediateMajor))
		return false, false
	}
	if fromLine == toLine {
		result.Reasons = append(result.Reasons, r.gap(&ref, scanreport.GapLineSameLine, kubernetesSlug, toLine))
		return false, false
	}
	if previousLine(toLine) != fromLine {
		if unplanned {
			result.Reasons = append(result.Reasons, scanreport.ReasonNoReviewedPathPolicy)
		} else {
			result.Reasons = append(result.Reasons, r.gap(&ref, scanreport.GapLineHopShape, kubernetesSlug, ref.From, ref.To))
		}
		return false, false
	}
	statuses := r.knowledge.AttestationsFor(r.component, toLine, familyID, r.now)
	if len(statuses) != 1 {
		result.Reasons = append(result.Reasons, r.gap(&ref, scanreport.GapLineNotAttested, kubernetesSlug, toLine))
		return false, false
	}
	status := statuses[0]
	result.Attestation = &scanreport.Attestation{
		Line: status.Attestation.Line, Family: status.Attestation.FactFamily, Basis: status.Attestation.Evidence.Basis,
		Freshness: status.Freshness, ValidUntil: status.Attestation.Evidence.ValidUntil,
	}
	if !status.Current() || status.Attestation.Line != toLine || status.Attestation.FactFamily != familyID || status.Attestation.Component != r.component {
		result.Reasons = append(result.Reasons, r.gap(&ref, scanreport.GapLineNotCurrent, kubernetesSlug, toLine, status.Freshness))
		return false, false
	}
	if !r.policy.Admits(status.Attestation.Evidence.Basis) {
		// The trust policy also selects the evidence a review rests on.
		result.Reasons = append(result.Reasons, r.gap(&ref, scanreport.GapLineTrustPolicy, kubernetesSlug, toLine, constraintengine.EffectiveBasis(status.Attestation.Evidence.Basis)))
		return false, false
	}
	attested := true
	listed := map[string]bool{}
	applicableIDs := map[string]bool{}
	for _, rule := range applicable {
		applicableIDs[rule.Scope.ID] = true
	}
	for _, id := range status.Attestation.RuleIDs {
		listed[id] = true
		if rule, known := r.byID[id]; known && (rule.Notice || rule.Basis == constraintengine.BasisLead) {
			// A one-way notice or a lead never supports a review.
			continue
		}
		if !applicableIDs[id] {
			attested = false
			result.Reasons = append(result.Reasons, r.gap(&ref, scanreport.GapLineListedRule, kubernetesSlug, toLine, id))
		} else if !decidedRules[id] {
			attested = false
		}
	}
	for _, rule := range applicable {
		if rule.Scope.Line == toLine && containsFamily(rule.Scope.Families) && !listed[rule.Scope.ID] {
			attested = false
			result.Reasons = append(result.Reasons, r.gap(&ref, scanreport.GapLineUnlistedRule, kubernetesSlug, toLine, rule.Scope.ID))
		}
	}
	return attested, true
}

// claimFacts are the facts a claim names as required.
func claimFacts(claim constraintengine.Claim) []string {
	facts := make([]string, 0, len(claim.RequiredFacts))
	for _, fact := range claim.RequiredFacts {
		facts = append(facts, fact.FactID)
	}
	return facts
}

func containsFamily(families []string) bool {
	for _, family := range families {
		if family == familyID {
			return true
		}
	}
	return false
}

// hopLines returns the minor lines of the hop's ends.
func hopLines(hop upgradepath.Hop) (string, string, bool) {
	line := func(end upgradepath.Endpoint) (string, bool) {
		if end.MinorLine() {
			return end.Line, true
		}
		if end.Exact() {
			return lineattest.LineOf(end.Version)
		}
		return "", false
	}
	from, ok1 := line(hop.From)
	to, ok2 := line(hop.To)
	return from, to, ok1 && ok2
}

// previousLine is M.(m-1) for M.m, empty for M.0.
func previousLine(line string) string {
	major, minor, ok := majorMinor(line + ".0")
	if !ok || minor == 0 {
		return ""
	}
	return strconv.FormatUint(major, 10) + "." + strconv.FormatUint(minor-1, 10)
}

// wholeUpgrade evaluates the end-to-end transition for rules that span
// several lines and so match no single hop. A rule that matches it is judged
// like a rule of a hop; a blocker there is never lost.
//
// A rule that matches it only by removal crossing is not judged again when a
// planned hop already examined its crossing (the hop overlapped the rule and
// both ends are evaluable): the hop that enters the removal line is where the
// removed-API facts are prepared, so the whole-upgrade input would only read
// them as unavailable and add a gap the hop already decided or reported. A
// crossing that no planned hop examines (for example under a major-line plan)
// is judged here, and a BLOCKED claim is always judged.
func (r *kubernetesRun) wholeUpgrade(from, to string, plan upgradepath.Plan) error {
	eval, err := r.evaluateTransition(from, to)
	if err != nil {
		return err
	}
	ref := scanreport.HopRef{From: from, To: to, WholeUpgrade: true}
	if eval.refused {
		r.gap(&ref, scanreport.GapLineNoRules, kubernetesSlug, to)
		return nil
	}
	for id, claim := range eval.claims {
		rule := r.byID[id]
		if (claim.Status == "PASS" || claim.Status == "BLOCKED" || claim.Status == constraintengine.StatusNotice) && rule.Scope.Transition.Match(from, to) == constraintengine.MatchNone {
			return ErrIntegrity
		}
	}
	for _, rule := range r.rules {
		mode := rule.Scope.Transition.Match(from, to)
		if rule.Scope.Component != r.component || mode == constraintengine.MatchNone {
			continue
		}
		if mode == constraintengine.MatchCrossing && eval.claims[rule.Scope.ID].Status != "BLOCKED" && examinedByAHop(plan, rule) {
			continue
		}
		if r.neutral(rule, eval, ref, true) {
			continue
		}
		if !r.policy.Admits(rule.Basis) {
			r.excluded[rule.Scope.ID] = true
			r.gap(&ref, scanreport.GapRuleTrustPolicy, rule.Scope.ID, rule.Basis)
			continue
		}
		r.judge(rule, eval, ref, false)
	}
	return nil
}

// examinedByAHop reports whether some planned hop with evaluable ends
// overlaps the rule's subject, so the hop-level evaluation already examined
// it.
func examinedByAHop(plan upgradepath.Plan, rule cncfcheck.ScanRule) bool {
	for _, hop := range plan.Hops {
		_, fromOK := hop.From.EngineVersion()
		_, toOK := hop.To.EngineVersion()
		if fromOK && toOK && hop.Overlaps(rule.Scope.Transition) {
			return true
		}
	}
	return false
}

// finding records a BLOCKED claim: once per rule, at the first hop where it
// blocks, with the later hops in AlsoAt.
func (r *kubernetesRun) finding(rule cncfcheck.ScanRule, claim constraintengine.Claim, eval evaluation, ref scanreport.HopRef, viaCrossing bool) *scanreport.Finding {
	for _, fact := range claim.RequiredFacts {
		for _, source := range eval.scan.Sources[fact.FactID] {
			r.blocked[source] = true
		}
	}
	if index, found := r.findings[rule.Scope.ID]; found {
		finding := &r.report.Findings[index]
		if finding.Hop != ref {
			for _, also := range finding.AlsoAt {
				if also == ref {
					return nil
				}
			}
			finding.AlsoAt = append(finding.AlsoAt, ref)
		}
		return nil
	}
	finding := scanreport.Finding{
		RuleID: rule.Scope.ID, Component: kubernetesSlug, Hop: ref, Title: title(rule.Description), Fix: rule.NextAction, Match: "anchor",
		Basis: constraintengine.EffectiveBasis(claim.EvidenceBasis), Citations: append([]constraintengine.SourceEvidence{}, claim.Sources...),
		RuleDigest: claim.RuleDigest, Locations: []scanreport.Location{},
	}
	if claim.SubjectMatch != nil {
		finding.Match = claim.SubjectMatch.Mode
	}
	markCrossing(&finding, rule, claim, viaCrossing)
	if claim.EvidenceExtractor != nil {
		finding.Extractor = claim.EvidenceExtractor.ID + "@" + claim.EvidenceExtractor.Version
	}
	seen := map[intake.Source]bool{}
	for _, fact := range claim.RequiredFacts {
		for _, source := range eval.scan.Sources[fact.FactID] {
			if seen[source] {
				continue
			}
			seen[source] = true
			finding.Locations = append(finding.Locations, r.location(source))
		}
	}
	r.findings[rule.Scope.ID] = len(r.report.Findings)
	r.report.Findings = append(r.report.Findings, finding)
	return &r.report.Findings[len(r.report.Findings)-1]
}

func (r *kubernetesRun) location(source intake.Source) scanreport.Location {
	location := scanreport.Location{File: source.Display, Document: source.Document, Item: source.Item, Line: source.Line}
	for _, document := range r.workspace.Documents {
		if document.Source == source {
			location.Kind, location.Namespace, location.Name = document.Kind, document.Namespace, document.Name
			break
		}
	}
	return location
}

// title is the first sentence of a rule description, bounded.
func title(description string) string {
	text := description
	if index := strings.Index(text, ". "); index >= 0 {
		text = text[:index]
	}
	text = strings.TrimSuffix(text, ".")
	if len(text) > scanreport.MaxText {
		text = scanreport.Text("%s", text)
	}
	return text
}

// noticeExclusions are the reasons a notice rule does not apply: its
// absence says nothing, so they give no entry.
var noticeExclusions = map[string]bool{
	"RULE_TRANSITION_NOT_REVIEWED":   true,
	"RULE_SUBJECT_COMPONENT_MISSING": true,
	"RULE_APPLICABILITY_NOT_MATCHED": true,
}

// notice records a one-way notice rule that applies to ref. It never adds a
// gap, a finding, a pass or a hop reason.
func (r *kubernetesRun) notice(rule cncfcheck.ScanRule, eval evaluation, ref scanreport.HopRef, covers bool) {
	entry := scanreport.Notice{RuleID: rule.Scope.ID, Component: kubernetesSlug, Hop: ref, Text: rule.NextAction, Basis: "reviewed", Citations: []constraintengine.SourceEvidence{}}
	claim, found := eval.claims[rule.Scope.ID]
	if found {
		entry.Basis = constraintengine.EffectiveBasis(claim.EvidenceBasis)
		entry.Citations = append(entry.Citations, claim.Sources...)
	}
	switch {
	case !covers:
		entry.Reason = scanreport.ReasonIntermediateLineNotCovered
	case !found:
		return
	case claim.Status == constraintengine.StatusNotice:
		entry.Established = true
	case noticeExclusions[claim.ReasonCode]:
		return
	default:
		entry.Reason = claim.ReasonCode
	}
	for index := range r.report.Notices {
		existing := &r.report.Notices[index]
		if existing.RuleID == entry.RuleID && existing.Established == entry.Established && existing.Reason == entry.Reason {
			if existing.Hop != ref {
				for _, also := range existing.AlsoAt {
					if also == ref {
						return
					}
				}
				existing.AlsoAt = append(existing.AlsoAt, ref)
			}
			return
		}
	}
	r.report.Notices = append(r.report.Notices, entry)
}

// neutral handles a verdict-neutral rule (a one-way notice or a lead) that
// applies to ref and reports whether the rule was one. Neutral rules never
// add a gap, a finding, a pass or a hop reason.
func (r *kubernetesRun) neutral(rule cncfcheck.ScanRule, eval evaluation, ref scanreport.HopRef, covers bool) bool {
	switch {
	case rule.Notice:
		if r.policy.Admits(rule.Basis) {
			r.notice(rule, eval, ref, covers)
		}
		return true
	case rule.Basis == constraintengine.BasisLead:
		if !r.policy.Admits(rule.Basis) {
			r.excludedLeads[rule.Scope.ID] = true
			return true
		}
		r.lead(rule, eval, ref, covers)
		return true
	}
	return false
}

// lead lists a lead rule that would block on ref. A lead that finds
// nothing, or that cannot be evaluated, says nothing and is not listed.
func (r *kubernetesRun) lead(rule cncfcheck.ScanRule, eval evaluation, ref scanreport.HopRef, covers bool) {
	claim, found := eval.claims[rule.Scope.ID]
	if !covers || !found || claim.Status != constraintengine.StatusNotice {
		return
	}
	for index := range r.report.Leads {
		existing := &r.report.Leads[index]
		if existing.RuleID == rule.Scope.ID {
			if existing.Hop != ref {
				for _, also := range existing.AlsoAt {
					if also == ref {
						return
					}
				}
				existing.AlsoAt = append(existing.AlsoAt, ref)
			}
			return
		}
	}
	r.report.Leads = append(r.report.Leads, scanreport.Lead{RuleID: rule.Scope.ID, Component: kubernetesSlug, Hop: ref, Text: rule.NextAction, Citations: append([]constraintengine.SourceEvidence{}, claim.Sources...)})
}

// unsupported lists a support-range rule that finds the combination outside
// its documented range on ref.
func (r *kubernetesRun) unsupported(rule cncfcheck.ScanRule, claim constraintengine.Claim, ref scanreport.HopRef) {
	for index := range r.report.Unsupported {
		existing := &r.report.Unsupported[index]
		if existing.RuleID == rule.Scope.ID {
			if existing.Hop != ref {
				for _, also := range existing.AlsoAt {
					if also == ref {
						return
					}
				}
				existing.AlsoAt = append(existing.AlsoAt, ref)
			}
			return
		}
	}
	r.report.Unsupported = append(r.report.Unsupported, scanreport.Unsupported{RuleID: rule.Scope.ID, Component: kubernetesSlug, Hop: ref, Reason: claim.ReasonCode, Fix: rule.NextAction,
		Basis: constraintengine.EffectiveBasis(claim.EvidenceBasis), Citations: append([]constraintengine.SourceEvidence{}, claim.Sources...)})
}

// markCrossing makes a finding a crossing finding when the claim matched by
// removal crossing, or when only the crossing covers the whole hop
// (viaCrossing): its match is "crossing", it carries the disclosure and the
// next action names the crossing. Otherwise it leaves the finding alone.
func markCrossing(finding *scanreport.Finding, rule cncfcheck.ScanRule, claim constraintengine.Claim, viaCrossing bool) {
	switch {
	case claim.CrossingMatch != nil:
		match := *claim.CrossingMatch
		finding.Match, finding.Crossing, finding.Fix = claim.CrossingMatch.Mode, &match, claim.NextAction
	case viaCrossing:
		finding.Match, finding.Crossing = "crossing", constraintengine.NewCrossingMatch(rule.Scope.Transition)
		finding.Fix = constraintengine.CrossingNextAction(rule.NextAction, rule.Scope.Transition)
	}
}
