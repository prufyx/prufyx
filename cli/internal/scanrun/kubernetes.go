// SPDX-License-Identifier: AGPL-3.0-only

package scanrun

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"regexp"
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

	rules    []cncfcheck.ScanRule
	byID     map[string]cncfcheck.ScanRule
	findings map[string]int // rule id -> index in report.Findings
	passes   map[string]bool
	// rootGaps are the component-level gaps (declarations, documents)
	// that keep a claim from being decided, keyed by their message.
	rootGaps map[scanreport.GapKey]scanreport.Gap
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
	r.rootGaps = r.componentGaps()
	for _, gap := range r.rootGaps {
		r.report.Gaps = append(r.report.Gaps, gap)
	}

	path := scanreport.Path{Component: kubernetesSlug, From: from, To: to}
	crossed := map[string]bool{}
	defer func() {
		r.report.Paths = append(r.report.Paths, path)
		r.apiVersionGaps(to, crossed)
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
	for line := range crossedLines(plan) {
		crossed[line] = true
	}
	for _, hop := range plan.Hops {
		evaluated, err := r.hop(hop, unplanned)
		if err != nil {
			return err
		}
		path.Hops = append(path.Hops, evaluated)
	}
	if len(plan.Hops) > 1 {
		if err := r.wholeUpgrade(from, to); err != nil {
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
	alpha := 0
	for _, document := range r.workspace.Documents {
		if alphaKubernetesAPI(document.APIVersion) {
			alpha++
		}
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

// crossedLines are the minor lines whose removals a hop of the plan
// evaluates: the line of every hop that enters it from the line before.
func crossedLines(plan upgradepath.Plan) map[string]bool {
	crossed := map[string]bool{}
	for _, hop := range plan.Hops {
		fromLine, toLine, ok := hopLines(hop)
		if !ok {
			continue
		}
		fromMajor, fromMinor, ok1 := majorMinor(fromLine + ".0")
		toMajor, toMinor, ok2 := majorMinor(toLine + ".0")
		// Only a hop that enters one line from the line before evaluates
		// that line's removals; a hop that skips lines crosses nothing here.
		if ok1 && ok2 && fromMajor == toMajor && toMinor == fromMinor+1 {
			crossed[toLine] = true
		}
	}
	return crossed
}

// apiVersionGaps checks every manifest against the target line: an object
// at a version removed on a line at or below the target that no hop crosses
// is not served, and an object of a Kubernetes API group must be at a
// version the review of the target line lists as served.
func (r *kubernetesRun) apiVersionGaps(to string, crossed map[string]bool) {
	targetLine, ok := lineattest.LineOf(to)
	if !ok {
		return
	}
	removed := cncfprepare.KubernetesRemovedVersions()
	served, listed := r.knowledge.ServedAPIs(r.component, targetLine)
	notServed, notListed, builtIn := 0, 0, 0
	for _, document := range r.workspace.Documents {
		group, version, found := strings.Cut(document.APIVersion, "/")
		if !found {
			group, version = "", document.APIVersion
		}
		for _, removal := range removed {
			if removal.Group == group && removal.Version == version && containsString(removal.Kinds, document.Kind) &&
				!lineattest.LineLess(targetLine, removal.Line) && !crossed[removal.Line] {
				notServed++
				break
			}
		}
		if !kubernetesGroupRE.MatchString(group) || alphaVersionRE.MatchString(version) {
			continue
		}
		builtIn++
		if listed && !served[document.APIVersion+" "+document.Kind] {
			notListed++
		}
	}
	if notServed > 0 {
		r.rootGap(scanreport.GapAPIVersionNotServed, notServed, targetLine)
	}
	switch {
	case !listed && builtIn > 0:
		r.rootGap(scanreport.GapAPIVersionNoServedList, builtIn, targetLine)
	case notListed > 0:
		r.rootGap(scanreport.GapAPIVersionNotListed, notListed, targetLine)
	}
}

func containsString(values []string, value string) bool {
	for _, candidate := range values {
		if candidate == value {
			return true
		}
	}
	return false
}

// kubernetesGroupRE matches the API groups Kubernetes itself serves (and any
// other *.k8s.io group): an alpha version there is outside every removed-API
// review.
var kubernetesGroupRE = regexp.MustCompile(`^(|apps|batch|autoscaling|policy|extensions|k8s\.io|[a-z0-9.-]+\.k8s\.io)$`)

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
	scan   cncfprepare.KubernetesScan
	claims map[string]constraintengine.Claim
	// refused is true when the knowledge cannot evaluate the input: it
	// has no fact for a removal the preparation derives.
	refused bool
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
	result, err := r.knowledge.Evaluate(kubernetesSlug, cncfprepare.KubernetesRemovedAPIAllFacts(), scan.Prepared.CanonicalInputJSON, r.now)
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
		notice := claim.IsNotice()
		switch {
		case notice != rule.Notice:
			return evaluation{}, ErrIntegrity
		case notice && (claim.Status == "PASS" || claim.Status == "BLOCKED"):
			return evaluation{}, ErrIntegrity
		case !notice && claim.Status == constraintengine.StatusNotice:
			return evaluation{}, ErrIntegrity
		}
		claims[claim.RuleID] = claim
	}
	return evaluation{scan: scan, claims: claims}, nil
}

// judgement is the result of one applicable rule.
type judgement struct {
	decided, blocked bool
	reasons          []string
}

// judge decides one rule that covers the transition from its claim. A rule
// without a claim needs evidence the scan does not collect. Only PASS,
// BLOCKED and an UNKNOWN that the engine reports for a rule that does not
// apply are decided; every other result is a gap.
func (r *kubernetesRun) judge(rule cncfcheck.ScanRule, eval evaluation, ref scanreport.HopRef) judgement {
	claim, found := eval.claims[rule.Scope.ID]
	if !found {
		return judgement{reasons: []string{r.gap(&ref, scanreport.GapRuleNeedsOtherEvidence, rule.Scope.ID, kubernetesSlug)}}
	}
	switch claim.Status {
	case "BLOCKED":
		r.finding(rule, claim, eval, ref)
		return judgement{decided: true, blocked: true}
	case "PASS":
		key := rule.Scope.ID + "\x00" + ref.From + "\x00" + ref.To + "\x00" + strconv.FormatBool(ref.WholeUpgrade)
		if !r.passes[key] {
			r.passes[key] = true
			r.report.Passes = append(r.report.Passes, scanreport.Pass{RuleID: rule.Scope.ID, Component: kubernetesSlug, Hop: ref})
		}
		return judgement{decided: true}
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
	result.InputDigest = eval.scan.Prepared.InputDigest
	if eval.refused {
		_, toLine, _ := hopLines(hop)
		result.Status = scanreport.HopNoData
		result.Reasons = []string{r.gap(&ref, scanreport.GapLineNoRules, kubernetesSlug, toLine)}
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
		if rule.Notice {
			r.notice(rule, eval, ref, hop.CoveredBy(rule.Scope.Transition))
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
	for _, rule := range applicable {
		if !hop.CoveredBy(rule.Scope.Transition) {
			// The rule applies to some releases of the hop and not to
			// others; whatever it said at the engine input is downgraded.
			decidedAll = false
			result.Reasons = append(result.Reasons, r.gap(&ref, scanreport.GapIntermediateLine, rule.Scope.ID))
			continue
		}
		judged := r.judge(rule, eval, ref)
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

	attested, attestationCurrent := r.attestation(hop, ref, unplanned, applicable, decidedRules, &result)
	if attested {
		// A fact the preparation found true must be read by a rule that
		// decided this hop; otherwise no review can cover the hop.
		for fact := range eval.scan.Sources {
			if !readByDecidedRule(fact, applicable, decidedRules) {
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
	attested := true
	listed := map[string]bool{}
	applicableIDs := map[string]bool{}
	for _, rule := range applicable {
		applicableIDs[rule.Scope.ID] = true
	}
	for _, id := range status.Attestation.RuleIDs {
		listed[id] = true
		if rule, known := r.byID[id]; known && rule.Notice {
			// A one-way notice never supports a review.
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

func readByDecidedRule(fact string, applicable []cncfcheck.ScanRule, decidedRules map[string]bool) bool {
	for _, rule := range applicable {
		if !decidedRules[rule.Scope.ID] {
			continue
		}
		for _, read := range rule.Facts {
			if read == fact {
				return true
			}
		}
	}
	return false
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
func (r *kubernetesRun) wholeUpgrade(from, to string) error {
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
		if rule.Scope.Component != r.component || rule.Scope.Transition.Match(from, to) == constraintengine.MatchNone {
			continue
		}
		if rule.Notice {
			r.notice(rule, eval, ref, true)
			continue
		}
		r.judge(rule, eval, ref)
	}
	return nil
}

// finding records a BLOCKED claim: once per rule, at the first hop where it
// blocks, with the later hops in AlsoAt.
func (r *kubernetesRun) finding(rule cncfcheck.ScanRule, claim constraintengine.Claim, eval evaluation, ref scanreport.HopRef) {
	if index, found := r.findings[rule.Scope.ID]; found {
		finding := &r.report.Findings[index]
		if finding.Hop != ref {
			for _, also := range finding.AlsoAt {
				if also == ref {
					return
				}
			}
			finding.AlsoAt = append(finding.AlsoAt, ref)
		}
		return
	}
	finding := scanreport.Finding{
		RuleID: rule.Scope.ID, Component: kubernetesSlug, Hop: ref, Title: title(rule.Description), Fix: rule.NextAction, Match: "anchor",
		Basis: constraintengine.EffectiveBasis(claim.EvidenceBasis), Citations: append([]constraintengine.SourceEvidence{}, claim.Sources...),
		RuleDigest: claim.RuleDigest, Locations: []scanreport.Location{},
	}
	if claim.SubjectMatch != nil {
		finding.Match = claim.SubjectMatch.Mode
	}
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
