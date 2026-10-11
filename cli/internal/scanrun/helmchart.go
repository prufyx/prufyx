// SPDX-License-Identifier: AGPL-3.0-only

package scanrun

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/prufyx/prufyx/cli/internal/chartidentity"
	"github.com/prufyx/prufyx/cli/internal/cncfcheck"
	"github.com/prufyx/prufyx/cli/internal/cncfprepare"
	"github.com/prufyx/prufyx/cli/internal/constraintengine"
	"github.com/prufyx/prufyx/cli/internal/helmvaluespath"
	"github.com/prufyx/prufyx/cli/internal/intake"
	"github.com/prufyx/prufyx/cli/internal/scanconfig"
	"github.com/prufyx/prufyx/cli/internal/scanreport"
	"github.com/prufyx/prufyx/cli/internal/upgradepath"
)

// chartDeclaration is one declared chart hop, resolved and read: the
// chart identity from the reviewed chart-source table, the merged values,
// whether they were declared complete, and their provenance.
type chartDeclaration struct {
	slug       string
	chart      constraintengine.ChartRef
	values     map[string]any
	complete   bool
	provenance scanreport.HelmValues
}

// helmFlags assigns the command line's chart flags to projects. Each
// --chart names its project; the values flags belong to the one project
// that the command line and the configuration file declare as a chart hop.
func helmFlags(request Request, config scanconfig.Config) (map[string]scanconfig.HelmFlags, error) {
	valueFlags := request.HelmValues != nil || request.HelmSet != nil || request.HelmValuesComplete != nil
	if len(request.Charts) == 0 && !valueFlags {
		return nil, nil
	}
	out := map[string]scanconfig.HelmFlags{}
	for slug, chart := range request.Charts {
		out[slug] = scanconfig.HelmFlags{Chart: chart}
	}
	if !valueFlags {
		return out, nil
	}
	projects := map[string]bool{}
	for slug := range request.Charts {
		projects[slug] = true
	}
	for slug := range config.Declarations.Helm {
		projects[slug] = true
	}
	if len(projects) != 1 {
		return nil, usage(scanreport.UsageHelmNoChart)
	}
	for slug := range projects {
		flags := out[slug]
		flags.Values, flags.Set, flags.Complete = request.HelmValues, request.HelmSet, request.HelmValuesComplete
		out[slug] = flags
	}
	return out, nil
}

// checkCharts refuses a chart declaration of a project that is not a
// target or that is Kubernetes. The project names were checked against
// the catalog with the other components.
func checkCharts(effective scanconfig.Effective) error {
	slugs := make([]string, 0, len(effective.Helm))
	for slug := range effective.Helm {
		slugs = append(slugs, slug)
	}
	sort.Strings(slugs)
	for _, slug := range slugs {
		if slug == kubernetesSlug {
			return usage(scanreport.UsageChartKubernetes)
		}
		if _, targeted := effective.Target[slug]; !targeted {
			return usage(scanreport.UsageChartNoTarget, quote(slug), slug)
		}
	}
	return nil
}

// resolveCharts resolves every declared chart through the reviewed
// chart-source table at now and reads its values. Anything that cannot be
// resolved or read exactly is a usage error: nothing is guessed and no
// partial set is declared.
func resolveCharts(effective scanconfig.Effective, configDir string, request Request, now time.Time) (map[string]*chartDeclaration, error) {
	if len(effective.Helm) == 0 {
		return nil, nil
	}
	slugs := make([]string, 0, len(effective.Helm))
	for slug := range effective.Helm {
		slugs = append(slugs, slug)
	}
	sort.Strings(slugs)
	out := map[string]*chartDeclaration{}
	for _, slug := range slugs {
		declared := effective.Helm[slug]
		chart, err := resolveChart(slug, declared.Chart.Value, now)
		if err != nil {
			return nil, err
		}
		decl := &chartDeclaration{slug: slug, chart: chart, complete: declared.Complete.Set && declared.Complete.Value}
		paths := declared.Values.Value
		if declared.Values.Set && declared.Values.Source == scanconfig.FromFile {
			paths = make([]string, 0, len(declared.Values.Value))
			for _, file := range declared.Values.Value {
				joined := filepath.Join(configDir, file)
				if rel, err := filepath.Rel(configDir, joined); err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
					return nil, usage(scanreport.UsageInputNotAccepted, scanreport.UsageHelmValuesPaths)
				}
				paths = append(paths, joined)
			}
		}
		var files []map[string]any
		var lines []string
		decl.provenance = scanreport.HelmValues{Component: slug, Chart: chart.Name, Source: chart.Source, Files: []scanreport.HelmValuesFile{}, Declared: decl.complete}
		for _, path := range paths {
			record, raw, err := intake.ReadFile(path, intake.Options{Permissions: request.Permissions})
			if err != nil {
				return nil, inputError(err, request)
			}
			values, err := cncfprepare.DecodeHelmValues(raw)
			if err != nil {
				return nil, helmValuesFileError(record.Display, request)
			}
			files = append(files, values)
			lines = append(lines, "file "+record.Digest)
			decl.provenance.Files = append(decl.provenance.Files, scanreport.HelmValuesFile{File: record.Display, Digest: record.Digest})
		}
		var sets []cncfprepare.HelmSet
		for index, text := range declared.Set.Value {
			// An assignment is named by its position: its value is never
			// printed, not even in a refusal.
			set, err := cncfprepare.ParseHelmSet(text)
			if err != nil {
				return nil, usage(scanreport.UsageHelmSet, index+1)
			}
			sets = append(sets, set)
			sum := sha256.Sum256([]byte(text))
			lines = append(lines, "set sha256:"+hex.EncodeToString(sum[:]))
		}
		decl.provenance.Sets = len(sets)
		sum := sha256.Sum256([]byte(strings.Join(append(lines, ""), "\n")))
		decl.provenance.Digest = "sha256:" + hex.EncodeToString(sum[:])
		decl.values, err = cncfprepare.MergeHelmValues(files, sets)
		var conflict cncfprepare.HelmSetPathError
		if errors.As(err, &conflict) && conflict.Index < len(declared.Set.Value) {
			return nil, usage(scanreport.UsageInputNotAccepted, scanreport.Text(scanreport.UsageHelmSetPath, conflict.Index+1))
		}
		if err != nil {
			return nil, ErrIntegrity
		}
		out[slug] = decl
	}
	return out, nil
}

// helmValuesFileError is the refusal of a values file outside the strict
// subset. The file is named unless paths are redacted.
func helmValuesFileError(display string, request Request) error {
	name := quote(display)
	if request.Redact {
		name = "(redacted)"
	}
	return usage(scanreport.UsageInputNotAccepted, scanreport.Text(scanreport.UsageHelmValuesFile, name, scanreport.UsageHelmValuesNotMapping))
}

// resolveChart finds the one usable reviewed chart-source row of the
// project's chart: NAME alone needs exactly one, NAME@SOURCE names it.
func resolveChart(slug, spec string, now time.Time) (constraintengine.ChartRef, error) {
	name, source, withSource := strings.Cut(spec, "@")
	if name == "" || withSource && source == "" {
		return constraintengine.ChartRef{}, usage(scanreport.UsageChartFlag)
	}
	found, err := chartidentity.LookupProjectChart(slug, name, now)
	if err != nil {
		return constraintengine.ChartRef{}, ErrIntegrity
	}
	rows := found.Usable
	if withSource {
		normal, err := chartidentity.NormalizeRepoURL(source)
		if err != nil {
			return constraintengine.ChartRef{}, usage(scanreport.UsageChartSource, quote(source), quote(slug), quote(name))
		}
		var kept []chartidentity.SourceRecord
		for _, row := range rows {
			if row.RepoURL == normal {
				kept = append(kept, row)
			}
		}
		if len(kept) == 0 && len(rows) > 0 {
			return constraintengine.ChartRef{}, usage(scanreport.UsageChartSource, quote(source), quote(slug), quote(name))
		}
		rows = kept
	}
	switch {
	case len(rows) == 1:
		chart := constraintengine.ChartRef{Source: rows[0].RepoURL, Name: rows[0].Chart}
		if !constraintengine.ValidChartRef(chart) {
			return constraintengine.ChartRef{}, ErrIntegrity
		}
		return chart, nil
	case len(rows) > 1:
		return constraintengine.ChartRef{}, usage(scanreport.UsageChartAmbiguous, quote(slug), quote(name), slug, name)
	case found.Unusable > 0:
		return constraintengine.ChartRef{}, usage(scanreport.UsageChartUnusable, quote(slug), quote(name))
	case len(found.Charts) > 0:
		return constraintengine.ChartRef{}, usage(scanreport.UsageChartUnknown, quote(slug), quote(name), strings.Join(found.Charts, ", "))
	}
	return constraintengine.ChartRef{}, usage(scanreport.UsageChartUnknownNone, quote(slug), quote(name), quote(slug))
}

// valuesFactSuffix ends the id of every chart values-path set fact.
const valuesFactSuffix = "_values_paths_set"

// helmChartRun evaluates one declared chart hop: the chart rules of the
// declared chart over the values-path set fact of the supplied values (and
// the declared Kubernetes version), on one direct hop between two chart
// versions. The component is never covered: scan checks nothing else
// about the chart or the application it installs.
type helmChartRun struct {
	knowledge Knowledge
	now       time.Time
	report    *scanreport.Report
	slug      string
	component string
	decl      *chartDeclaration
	// kubernetes is the Kubernetes component and its declared versions.
	kubernetes, kubernetesFrom, kubernetesTo string
	policy                                   cncfcheck.TrustPolicy

	rules []cncfcheck.ScanRule
	byID  map[string]cncfcheck.ScanRule
	fact  string
	// ambiguous: the chart's rules read more than one values-path set
	// fact, so none is declared and every rule reading one is undecided.
	ambiguous bool
	universe  cncfprepare.HelmUniverse
	excluded  map[string]bool
	rootGaps  map[scanreport.GapKey]scanreport.Gap
}

// valuesFact returns the values-path set fact of the declared chart: the
// one the chart's rules read. It is "" when no rule of the chart reads one:
// no id is invented, so the chart rules that read no fact still decide. ok
// is false when the chart's rules read more than one.
func (r *helmChartRun) valuesFact() (string, bool) {
	found := map[string]bool{}
	for _, rule := range r.rules {
		if rule.Chart == nil || *rule.Chart != r.decl.chart {
			continue
		}
		for _, fact := range rule.Facts {
			if strings.HasPrefix(fact, "component.") && strings.HasSuffix(fact, valuesFactSuffix) {
				found[fact] = true
			}
		}
	}
	switch len(found) {
	case 0:
		return "", true
	case 1:
		for fact := range found {
			return fact, true
		}
	}
	return "", false
}

// universeOf collects the members named by every rule of the project that
// reads fact, whatever the trust policy: an input built from it never
// depends on --require-basis. A rule that reads the fact other than as its
// set condition leaves the universe unresolved.
func universeOf(rules []cncfcheck.ScanRule, fact string) cncfprepare.HelmUniverse {
	members := map[string]bool{}
	resolved := true
	for _, rule := range rules {
		reads := 0
		for _, f := range rule.Facts {
			if f == fact {
				reads++
			}
		}
		if reads == 0 {
			continue
		}
		if reads != 1 || rule.SetFact != fact {
			resolved = false
			continue
		}
		for _, member := range rule.SetMembers {
			members[member] = true
		}
	}
	out := cncfprepare.HelmUniverse{Members: make([]string, 0, len(members)), Resolved: resolved}
	for member := range members {
		out.Members = append(out.Members, member)
	}
	sort.Strings(out.Members)
	return out
}

func (r *helmChartRun) evaluate(from, to string) error {
	r.rules = r.knowledge.Rules(r.slug)
	r.byID = map[string]cncfcheck.ScanRule{}
	for _, rule := range r.rules {
		if _, dup := r.byID[rule.Scope.ID]; dup {
			return ErrIntegrity
		}
		r.byID[rule.Scope.ID] = rule
	}
	r.excluded = map[string]bool{}
	r.rootGaps = map[scanreport.GapKey]scanreport.Gap{}
	fact, single := r.valuesFact()
	r.fact, r.ambiguous = fact, !single
	r.universe = universeOf(r.rules, fact)
	r.rootGap(scanreport.GapChartValuesOnly, r.slug, r.decl.chart.Name)

	path := scanreport.Path{Component: r.slug, From: from, To: to, Chart: &scanreport.PathChart{Name: r.decl.chart.Name, Source: r.decl.chart.Source}}
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
	if plan.Component != r.component || len(plan.Hops) != 1 || !plan.Hops[0].From.Exact() || !plan.Hops[0].To.Exact() {
		return ErrIntegrity
	}
	hop, err := r.hop(plan.Hops[0], path.Chart)
	if err != nil {
		return err
	}
	path.Hops = append(path.Hops, hop)
	return nil
}

// hop evaluates the direct chart hop.
func (r *helmChartRun) hop(hop upgradepath.Hop, chart *scanreport.PathChart) (scanreport.Hop, error) {
	ref := scanreport.HopRef{Index: hop.Index, From: hop.From.String(), To: hop.To.String(), Chart: r.decl.chart.Name}
	result := scanreport.Hop{
		Index: hop.Index,
		From:  scanreport.Endpoint{Version: hop.From.Version},
		To:    scanreport.Endpoint{Version: hop.To.Version},
	}
	fromVersion, fromOK := hop.From.EngineVersion()
	toVersion, toOK := hop.To.EngineVersion()
	if !fromOK || !toOK {
		return scanreport.Hop{}, ErrIntegrity
	}
	input := cncfprepare.HelmChartHop{
		Component: r.component, Chart: r.decl.chart, From: fromVersion, To: toVersion,
		Kubernetes: r.kubernetes, KubernetesFrom: r.kubernetesFrom, KubernetesTo: r.kubernetesTo,
	}
	prepared, err := cncfprepare.PrepareHelmValues(input, r.fact, r.decl.values, r.universe, r.decl.complete)
	if err != nil {
		return scanreport.Hop{}, ErrIntegrity
	}
	sum := sha256.Sum256(prepared.Prepared.CanonicalInputJSON)
	if prepared.Prepared.InputDigest != "sha256:"+hex.EncodeToString(sum[:]) || prepared.Fact != r.fact {
		return scanreport.Hop{}, ErrIntegrity
	}
	result.InputDigest = prepared.Prepared.InputDigest
	chart.PathsRead, chart.Unnamed, chart.UniverseSize, chart.Members = prepared.PathsRead, prepared.Unnamed, prepared.UniverseSize, len(prepared.Members)
	chart.Complete = prepared.Prepared.Reason == cncfprepare.ReasonHelmValuesComplete
	onlyReason := r.rootGaps[scanreport.GapChartValuesOnly].Reason
	var facts []string
	if r.fact != "" {
		facts = []string{r.fact}
	}
	evaluation, err := r.knowledge.Evaluate(r.policy, r.slug, facts, prepared.Prepared.CanonicalInputJSON, r.now)
	switch {
	case errors.Is(err, ErrRefused):
		// The knowledge evaluates nothing for this input: no chart rule of
		// this chart is selected (none exists, or the trust policy leaves
		// every one out), or the fact is not registered. Every rule that
		// applies is still named below, undecided.
		evaluation = Evaluation{}
	case err != nil:
		return scanreport.Hop{}, ErrIntegrity
	default:
		result.EngineContractDigest = evaluation.EngineContractDigest
		if r.report.Provenance.EngineContractDigest == "" {
			r.report.Provenance.EngineContractDigest = evaluation.EngineContractDigest
		}
	}
	claims := map[string]constraintengine.Claim{}
	for _, claim := range evaluation.Claims {
		rule, known := r.byID[claim.RuleID]
		if _, dup := claims[claim.RuleID]; dup || !known || !customResourceClaimValid(rule, claim, r.policy) {
			return scanreport.Hop{}, ErrIntegrity
		}
		switch {
		case rule.Chart == nil:
			// A chart version never decides an application rule.
			if claim.Status != "UNKNOWN" || claim.ReasonCode != constraintengine.ReasonAppVersionNotDeclared {
				return scanreport.Hop{}, ErrIntegrity
			}
			result.Reasons = append(result.Reasons, r.gap(&ref, scanreport.GapRuleNotDecided, rule.Scope.ID, claim.ReasonCode))
		case *rule.Chart != r.decl.chart:
			// Never selected; a rule about another chart cannot decide.
			if claim.Status != "UNKNOWN" || claim.ReasonCode != constraintengine.ReasonSubjectChartNotDeclared {
				return scanreport.Hop{}, ErrIntegrity
			}
		}
		claims[claim.RuleID] = claim
	}

	blocked, applicable := false, 0
	overlapping := map[string]bool{}
	for _, rule := range r.rules {
		if rule.Chart == nil || *rule.Chart != r.decl.chart || rule.Scope.Component != r.component || !hop.Overlaps(rule.Scope.Transition) {
			continue
		}
		overlapping[rule.Scope.ID] = true
		if rule.Notice || rule.Basis == constraintengine.BasisLead {
			continue
		}
		applicable++
		switch {
		case !inChartFamily(rule, r.fact) && r.ambiguous:
			// The chart's rules read several values-path set facts.
			result.Reasons = append(result.Reasons, r.rootGap(scanreport.GapHelmValuesUniverseUnresolved, r.slug, r.decl.chart.Name))
			continue
		case !inChartFamily(rule, r.fact):
			// A chart rule about evidence scan does not collect.
			result.Reasons = append(result.Reasons, r.gap(&ref, scanreport.GapRuleNeedsOtherEvidence, rule.Scope.ID, r.slug))
			continue
		}
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
			r.finding(rule, claim, ref)
		case "PASS":
			r.report.Passes = append(r.report.Passes, scanreport.Pass{RuleID: rule.Scope.ID, Component: r.slug, Hop: ref})
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
	// Nothing covers this hop: only the chart's values and Kubernetes
	// version were checked.
	result.Reasons = append(result.Reasons, onlyReason)
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

// inChartFamily reports a rule the chart selection can evaluate: one that
// reads no fact, or only the values-path set fact.
func inChartFamily(rule cncfcheck.ScanRule, fact string) bool {
	for _, f := range rule.Facts {
		if f != fact {
			return false
		}
	}
	return true
}

// unknown explains an UNKNOWN claim of a chart rule: by why the values set
// is not complete or not supported, by the missing Kubernetes version, or
// by the engine's reason.
func (r *helmChartRun) unknown(rule cncfcheck.ScanRule, claim constraintengine.Claim, prepared cncfprepare.HelmValuesScan, ref scanreport.HopRef) []string {
	if factReasons[claim.ReasonCode] {
		var reasons []string
		switch prepared.Prepared.Reason {
		case cncfprepare.ReasonHelmValuesUniverseUnresolved:
			reasons = append(reasons, r.rootGap(scanreport.GapHelmValuesUniverseUnresolved, r.slug, r.decl.chart.Name))
		case cncfprepare.ReasonHelmValuesUniverseTooLarge:
			reasons = append(reasons, r.rootGap(scanreport.GapHelmValuesUniverse, r.slug, r.decl.chart.Name, prepared.UniverseSize))
		default:
			if !r.decl.complete {
				reasons = append(reasons, r.rootGap(scanreport.GapHelmValuesNotComplete, r.slug, r.decl.chart.Name))
			}
			if len(prepared.NullPaths) > 0 {
				reasons = append(reasons, r.rootGap(scanreport.GapHelmValuesNull, r.slug, r.decl.chart.Name, quote(helmvaluespath.DisplayPath(prepared.NullPaths[0]))))
			}
		}
		if len(reasons) > 0 {
			return reasons
		}
		return []string{r.gap(&ref, scanreport.GapRuleNotDecided, rule.Scope.ID, prepared.Prepared.Reason)}
	}
	outcome, known := reasonOutcomes[claim.ReasonCode]
	switch {
	case claim.ReasonCode == "RULE_DEPENDENCY_COMPONENT_MISSING":
		return []string{r.gap(&ref, scanreport.GapChartKubernetesVersion, rule.Scope.ID)}
	case known && outcome.decided:
		return nil
	case known && outcome.gap == scanreport.GapEvidenceExpired:
		return []string{r.gap(&ref, scanreport.GapEvidenceExpired, rule.Scope.ID, claim.EvidenceFreshness)}
	}
	return []string{r.gap(&ref, scanreport.GapRuleNotDecided, rule.Scope.ID, claim.ReasonCode)}
}

// finding records a BLOCKED claim once, with the values keys it is about.
func (r *helmChartRun) finding(rule cncfcheck.ScanRule, claim constraintengine.Claim, ref scanreport.HopRef) {
	for _, existing := range r.report.Findings {
		if existing.RuleID == rule.Scope.ID && existing.Component == r.slug {
			return
		}
	}
	finding := scanreport.Finding{
		RuleID: rule.Scope.ID, Component: r.slug, Hop: ref, Title: title(rule.Description), Fix: rule.NextAction, Match: "anchor",
		Basis: constraintengine.EffectiveBasis(claim.EvidenceBasis), Citations: append([]constraintengine.SourceEvidence{}, claim.Sources...),
		RuleDigest: claim.RuleDigest, Locations: []scanreport.Location{},
	}
	if claim.SubjectMatch != nil {
		finding.Match = claim.SubjectMatch.Mode
	}
	if claim.EvidenceExtractor != nil {
		finding.Extractor = claim.EvidenceExtractor.ID + "@" + claim.EvidenceExtractor.Version
	}
	keys := append(append([]string{}, claim.MissingMembers...), claim.MatchedMembers...)
	if len(keys) > 0 {
		finding.Keys = keys
	}
	r.report.Findings = append(r.report.Findings, finding)
}

func (r *helmChartRun) gap(hop *scanreport.HopRef, key scanreport.GapKey, args ...any) string {
	gap := scanreport.NewGap(r.slug, hop, key, args...)
	r.report.Gaps = append(r.report.Gaps, gap)
	return gap.Reason
}

// rootGap adds a component-level gap once and returns its reason.
func (r *helmChartRun) rootGap(key scanreport.GapKey, args ...any) string {
	if gap, found := r.rootGaps[key]; found {
		return gap.Reason
	}
	gap := scanreport.NewGap(r.slug, nil, key, args...)
	r.rootGaps[key] = gap
	r.report.Gaps = append(r.report.Gaps, gap)
	return gap.Reason
}
