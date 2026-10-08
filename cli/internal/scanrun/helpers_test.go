// SPDX-License-Identifier: AGPL-3.0-only

package scanrun

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/buildidentity"
	"github.com/prufyx/prufyx/cli/internal/cncfcheck"
	"github.com/prufyx/prufyx/cli/internal/constraintengine"
	"github.com/prufyx/prufyx/cli/internal/extract/supersedeids"
	"github.com/prufyx/prufyx/cli/internal/lineattest"
	"github.com/prufyx/prufyx/cli/internal/scanreport"
	"github.com/prufyx/prufyx/cli/internal/upgradepath"
)

var update = flag.Bool("update", false, "rewrite the golden files")

// testdata is the package's testdata directory, fixed before any test
// changes the working directory.
var testdata = func() string {
	dir, err := os.Getwd()
	if err != nil {
		panic(err)
	}
	return filepath.Join(dir, "testdata")
}()

// testNow is the shared test clock, derived from the embedded pack.
var testNow = supersedeids.ClockString()

const kubernetesKey = "pkg:github/kubernetes/kubernetes"

// kubernetesRuleBases returns the evidence basis of the shipped Kubernetes
// API-removal rules ("reviewed" before the served-API supersede, "mechanical"
// after it) and the other one.
func kubernetesRuleBases() (rule, other string) {
	if supersedeids.Superseded() {
		return "mechanical", "reviewed"
	}
	return "reviewed", "mechanical"
}

// testBuild is a fixed build identity so goldens do not depend on the
// toolchain that runs the tests.
var testBuild = buildidentity.Identity{
	Version: "development", ReleaseState: "development", SourceRevision: "development", SourceTreeDigest: "development",
	AllowlistDigest: "development", BuildProfile: "development", BuildEpoch: "development", GoVersion: "test", TrustRootDigest: "unpinned",
}

// testKnowledge is the embedded knowledge with line reviews, an upgrade path
// policy, served lists and synthetic rules added for tests. Published rules
// and their evaluation are unchanged; synthetic rules are evaluated by the
// unchanged engine on the same prepared input and their claims added.
type testKnowledge struct {
	Knowledge
	attestations    lineattest.Index
	policies        upgradepath.Index
	served          map[string]bool
	servedLines     map[string]bool
	servedOverride  ServedList
	servedFreshness string
	synthetic       []cncfcheck.ScanRule
	syntheticRaw    []json.RawMessage
}

func (k testKnowledge) AttestationsFor(component, line, family string, now time.Time) []lineattest.Status {
	return k.attestations.AttestationsFor(component, line, family, now)
}

func (k testKnowledge) PathPolicyFor(component string, now time.Time) upgradepath.Status {
	return k.policies.Lookup(component, now)
}

func (k testKnowledge) ServedAPIs(component, line string, now time.Time) ServedStatus {
	if k.served == nil || !k.servedLines[line] {
		return ServedStatus{}
	}
	list := ServedList{Component: component, Line: line, Basis: "reviewed", APIs: k.served}
	if k.servedOverride.Component != "" {
		list.Component = k.servedOverride.Component
	}
	if k.servedOverride.Line != "" {
		list.Line = k.servedOverride.Line
	}
	if k.servedOverride.Basis != "" {
		list.Basis = k.servedOverride.Basis
	}
	freshness := "current"
	if k.servedFreshness != "" {
		freshness = k.servedFreshness
	}
	return ServedStatus{Found: true, List: list, Freshness: freshness}
}

func (k testKnowledge) Rules(project string) []cncfcheck.ScanRule {
	rules := k.Knowledge.Rules(project)
	if project == "kubernetes" {
		rules = append(rules, k.synthetic...)
		sort.Slice(rules, func(i, j int) bool { return rules[i].Scope.ID < rules[j].Scope.ID })
	}
	return rules
}

func (k testKnowledge) Evaluate(policy cncfcheck.TrustPolicy, project string, facts []string, inputRaw []byte, now time.Time) (Evaluation, error) {
	evaluation, err := k.Knowledge.Evaluate(policy, project, facts, inputRaw, now)
	if err != nil {
		return evaluation, err
	}
	// The trust policy leaves synthetic rules out exactly as it leaves out
	// published ones.
	var admitted []json.RawMessage
	for index, rule := range k.synthetic {
		if policy.Admits(rule.Basis) {
			admitted = append(admitted, k.syntheticRaw[index])
		}
	}
	if len(admitted) == 0 {
		return evaluation, nil
	}
	claims, err := evaluateSynthetic(admitted, inputRaw, now)
	if err != nil {
		return Evaluation{}, err
	}
	evaluation.Claims = append(evaluation.Claims, claims...)
	return evaluation, nil
}

// evaluateSynthetic evaluates synthetic rules with the engine over a
// registry of every fact the input and the rules name.
func evaluateSynthetic(rules []json.RawMessage, inputRaw []byte, now time.Time) ([]constraintengine.Claim, error) {
	var input struct {
		Proposed struct {
			Components []struct {
				Facts []struct {
					ID string `json:"id"`
				} `json:"facts"`
			} `json:"components"`
		} `json:"proposed"`
	}
	if err := json.Unmarshal(inputRaw, &input); err != nil {
		return nil, err
	}
	ids := map[string]bool{}
	for _, component := range input.Proposed.Components {
		for _, fact := range component.Facts {
			ids[fact.ID] = true
		}
	}
	ordered := map[string]json.RawMessage{}
	var order []string
	for _, raw := range rules {
		rule, err := cncfcheck.NewScanRule("kubernetes", "", raw)
		if err != nil {
			return nil, err
		}
		for _, fact := range rule.Facts {
			ids[fact] = true
		}
		ordered[rule.Scope.ID] = raw
		order = append(order, rule.Scope.ID)
	}
	sort.Strings(order)
	rules = nil
	for _, id := range order {
		rules = append(rules, ordered[id])
	}
	var definitions []constraintengine.FactDefinition
	for id := range ids {
		definitions = append(definitions, constraintengine.FactDefinition{ID: id, Component: kubernetesKey, Type: constraintengine.FactBool})
	}
	sort.Slice(definitions, func(i, j int) bool { return definitions[i].ID < definitions[j].ID })
	registry, err := constraintengine.NewCompiledRegistry(definitions)
	if err != nil {
		return nil, err
	}
	parsed, err := constraintengine.ParseInput(inputRaw, registry)
	if err != nil {
		return nil, err
	}
	schema, err := constraintengine.RulesSchemaFor(rules)
	if err != nil {
		return nil, err
	}
	document, err := json.Marshal(map[string]any{"schema": schema, "revision": "synthetic-test", "policyId": "synthetic-test", "policyDigest": "sha256:" + strings.Repeat("0", 64), "rules": rules})
	if err != nil {
		return nil, err
	}
	ruleSet, err := constraintengine.ParseRuleSet(document, registry)
	if err != nil {
		return nil, err
	}
	report, err := constraintengine.Evaluate(parsed, ruleSet, now)
	if err != nil {
		return nil, err
	}
	if _, err := constraintengine.MarshalReport(report); err != nil {
		return nil, err
	}
	return report.Claims, nil
}

// testServed is the served list the tests' reviews carry for every line.
var testServed = map[string]bool{}

func init() {
	for _, pair := range []string{
		"v1 ConfigMap", "v1 Secret", "v1 Service", "v1 Pod", "v1 Namespace", "batch/v1 CronJob", "batch/v1 Job",
		"apps/v1 Deployment", "apps/v1 DaemonSet", "apps/v1 StatefulSet", "autoscaling/v2 HorizontalPodAutoscaler",
		"policy/v1 PodDisruptionBudget", "networking.k8s.io/v1 Ingress", "flowcontrol.apiserver.k8s.io/v1 FlowSchema",
		"flowcontrol.apiserver.k8s.io/v1 PriorityLevelConfiguration",
	} {
		testServed[pair] = true
	}
}

// knowledgeOptions select the added reviews.
type knowledgeOptions struct {
	// lines are attested current; stale lines are attested with an expired
	// review.
	lines, stale []string
	// policy is "" (no record), "current" or "stale" sequential_minor, or
	// "direct" (a current direct policy).
	policy string
	// unchecked skips the admission check of the attestations, to model an
	// index built without it.
	unchecked bool
	// extraRuleIDs lists rule ids to add to a line's review regardless of
	// the pack.
	extraRuleIDs map[string][]string
	// dropRuleIDs lists rule ids to leave out of a line's review.
	dropRuleIDs map[string][]string
	// recordBasis is the evidence basis of the line reviews, the path
	// policy and the served lists: "" (reviewed) or "mechanical".
	recordBasis string
	// reviewBasis and policyBasis override recordBasis for one kind.
	reviewBasis, policyBasis string
	// servedExtra adds "apiVersion kind" pairs to every served list.
	servedExtra []string
	// noServedList leaves out the reviewed served lists; servedOverride
	// replaces the record's own component, line or basis; servedFreshness
	// replaces "current".
	noServedList    bool
	servedOverride  ServedList
	servedFreshness string
	// synthetic are rules added to the published ones (raw rule JSON).
	synthetic []string
	// base is the knowledge the reviews are added to; nil is the embedded
	// knowledge.
	base Knowledge
}

const testSource = `{"id":"kubernetes-website-v125-cronjob-v1beta1","url":"https://github.com/kubernetes/website/blob/9f1af2971c32124bff0a1f42255ba5a2f3c8a16f/content/en/docs/reference/using-api/deprecation-guide.md","revision":"9f1af2971c32124bff0a1f42255ba5a2f3c8a16f","contentDigest":"sha256:96f34a49cbdd7bd53008cc7b7cc8aff58c373ad323e64eef0155cbbc44494f61","startLine":87,"endLine":93}`

func newKnowledge(t testing.TB, options knowledgeOptions) Knowledge {
	t.Helper()
	base := options.base
	if base == nil {
		embedded, err := LoadEmbedded()
		if err != nil {
			t.Fatal(err)
		}
		base = embedded
	}
	var synthetic []cncfcheck.ScanRule
	var syntheticRaw []json.RawMessage
	for _, raw := range options.synthetic {
		rule, err := cncfcheck.NewScanRule("kubernetes", "Synthetic test-only rule. Never published.", json.RawMessage(raw))
		if err != nil {
			t.Fatal(err)
		}
		synthetic, syntheticRaw = append(synthetic, rule), append(syntheticRaw, json.RawMessage(raw))
	}
	rules := append(packRules(t), syntheticRaw...)
	byScope, _, err := lineattest.RulesByScope(rules)
	if err != nil {
		t.Fatal(err)
	}
	type entry struct {
		line   string
		window [2]string
	}
	var entries []entry
	for _, line := range options.lines {
		entries = append(entries, entry{line, [2]string{"2026-09-23T00:00:00Z", "2026-12-20T00:00:00Z"}})
	}
	for _, line := range options.stale {
		entries = append(entries, entry{line, [2]string{"2026-06-01T00:00:00Z", "2026-08-01T00:00:00Z"}})
	}
	sort.Slice(entries, func(i, j int) bool { return lineattest.LineLess(entries[i].line, entries[j].line) })
	var docs []string
	for _, e := range entries {
		ids := byScope[lineattest.Key{Component: kubernetesKey, Line: e.line, Family: lineattest.FamilyKubernetesRemovedServedGVK}]
		ids = append(append([]string{}, ids...), options.extraRuleIDs[e.line]...)
		for _, drop := range options.dropRuleIDs[e.line] {
			for i, id := range ids {
				if id == drop {
					ids = append(ids[:i], ids[i+1:]...)
					break
				}
			}
		}
		sort.Strings(ids)
		encoded, _ := json.Marshal(ids)
		if ids == nil {
			encoded = []byte("[]")
		}
		docs = append(docs, fmt.Sprintf(`{"component":%q,"line":%q,"factFamily":%q,"completeness":"COMPLETE_REVIEWED_RULES_FOR_LINE","ruleIds":%s,"evidence":{%s,"reviewedAt":%q,"validUntil":%q,"sources":[%s]}}`,
			kubernetesKey, e.line, lineattest.FamilyKubernetesRemovedServedGVK, encoded, basisFields(pick(options.reviewBasis, options.recordBasis), e.window[0]), e.window[0], e.window[1], testSource))
	}
	index := lineattest.NewIndex(nil)
	if len(docs) > 0 {
		atts, err := lineattest.Parse([]byte("[" + strings.Join(docs, ",") + "]"))
		if err != nil {
			t.Fatal(err)
		}
		if !options.unchecked {
			problems, err := lineattest.CheckRuleSets(atts, rules)
			if err != nil || len(problems) > 0 {
				t.Fatalf("test attestations are not admissible: %v %+v", err, problems)
			}
		}
		index = lineattest.NewIndex(atts)
	}
	policies := upgradepath.NewIndex(nil)
	if options.policy != "" {
		window := [2]string{"2026-09-23T00:00:00Z", "2026-12-20T00:00:00Z"}
		if options.policy == "stale" {
			window = [2]string{"2026-06-01T00:00:00Z", "2026-08-01T00:00:00Z"}
		}
		policy := "sequential_minor"
		if options.policy == "direct" {
			policy = "direct"
		}
		records, err := upgradepath.Parse([]byte(fmt.Sprintf(`[{"component":%q,"policy":%q,"evidence":{"state":"active",%s,"reviewedAt":%q,"validUntil":%q,"sources":[%s]}}]`, kubernetesKey, policy, basisFields(pick(options.policyBasis, options.recordBasis), window[0]), window[0], window[1], testSource)))
		if err != nil {
			t.Fatal(err)
		}
		policies = upgradepath.NewIndex(records)
	}
	served := testServed
	if len(options.servedExtra) > 0 {
		served = map[string]bool{}
		for pair := range testServed {
			served[pair] = true
		}
		for _, pair := range options.servedExtra {
			served[pair] = true
		}
	}
	if options.noServedList {
		served = nil
	}
	servedLines := map[string]bool{}
	for minor := 20; minor <= 40; minor++ {
		servedLines[fmt.Sprintf("1.%d", minor)] = true
	}
	if options.recordBasis != "" && options.servedOverride.Basis == "" {
		options.servedOverride.Basis = options.recordBasis
	}
	return testKnowledge{Knowledge: base, attestations: index, policies: policies, served: served, servedLines: servedLines,
		servedOverride: options.servedOverride, servedFreshness: options.servedFreshness, synthetic: synthetic, syntheticRaw: syntheticRaw}
}

// packRules are the raw rules of the embedded pack.
func packRules(t testing.TB) []json.RawMessage {
	t.Helper()
	catalogue, err := cncfcheck.Catalog(false, "")
	if err != nil {
		t.Fatal(err)
	}
	var rules []json.RawMessage
	for _, project := range catalogue.Projects {
		for _, entry := range project.Checks {
			rules = append(rules, entry.Rule)
		}
	}
	return rules
}

// allLines attests every line from 1.25 to 1.30.
var allLines = []string{"1.25", "1.26", "1.27", "1.28", "1.29", "1.30"}

func without(lines []string, drop ...string) []string {
	var out []string
	for _, line := range lines {
		keep := true
		for _, d := range drop {
			keep = keep && line != d
		}
		if keep {
			out = append(out, line)
		}
	}
	return out
}

// scan parses args and runs a scan.
func scan(t testing.TB, knowledge Knowledge, args ...string) (Result, error) {
	t.Helper()
	request, err := ParseArgs(args)
	if err != nil {
		return Result{}, err
	}
	return Run(request, Options{Knowledge: knowledge, Build: &testBuild})
}

// mustScan runs a scan that must be accepted.
func mustScan(t testing.TB, knowledge Knowledge, args ...string) Result {
	t.Helper()
	result, err := scan(t, knowledge, args...)
	if err != nil {
		t.Fatalf("scan %q: %v", args, err)
	}
	checkInvariants(t, result.Report)
	return result
}

// checkInvariants holds for every report: an undecided hop names its gaps,
// PASS has no gap and every hop COVERED, every catalog string is bounded.
func checkInvariants(t testing.TB, report scanreport.Report) {
	t.Helper()
	for _, path := range report.Paths {
		for _, hop := range path.Hops {
			if (hop.Status == scanreport.HopPartial || hop.Status == scanreport.HopNoData) && len(hop.Reasons) == 0 {
				t.Fatalf("hop %d %s is undecided without a named gap", hop.Index, hop.Status)
			}
			if hop.Status == scanreport.HopCovered && len(hop.Reasons) != 0 {
				t.Fatalf("covered hop %d has reasons %v", hop.Index, hop.Reasons)
			}
		}
	}
	if report.Verdict == scanreport.VerdictPass {
		if len(report.Gaps) != 0 || len(report.Findings) != 0 || len(report.Paths) == 0 {
			t.Fatal("PASS with gaps, findings or no path")
		}
	}
	if report.Verdict != scanreport.VerdictBlocked && len(report.Findings) != 0 {
		t.Fatal("findings without BLOCKED")
	}
	for _, gap := range report.Gaps {
		if len(gap.Detail) > scanreport.MaxText || len(gap.Action) > scanreport.MaxText || gap.Detail == "" || gap.Action == "" || strings.Contains(gap.Detail+gap.Action, "%") {
			t.Fatalf("gap text %+v", gap)
		}
	}
}

// files writes manifests into a fresh directory with mode 0600 and returns
// their paths.
func files(t testing.TB, contents map[string]string) (string, []string) {
	t.Helper()
	dir := t.TempDir()
	var paths []string
	for name, content := range contents {
		path := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		paths = append(paths, path)
	}
	sort.Strings(paths)
	return dir, paths
}

// inDir runs f with the working directory set to dir, so display paths are
// relative and goldens do not depend on the temporary directory.
func inDir(t testing.TB, dir string, f func()) {
	t.Helper()
	previous, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := os.Chdir(previous); err != nil {
			t.Fatal(err)
		}
	}()
	f()
}

// golden compares output with testdata/name, rewriting it with -update.
func golden(t testing.TB, name string, got []byte) {
	t.Helper()
	path := filepath.Join(testdata, name)
	if *update {
		if err := os.MkdirAll(testdata, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("%s differs from the golden file:\n%s", name, got)
	}
}

func jsonOf(t testing.TB, report scanreport.Report) []byte {
	t.Helper()
	raw, err := scanreport.MarshalJSON(report)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func isUsage(err error) bool {
	var usageErr *UsageError
	return errors.As(err, &usageErr)
}

func gapReasons(report scanreport.Report) []string {
	var out []string
	for _, gap := range report.Gaps {
		hop := ""
		if gap.Hop != nil {
			hop = " " + gap.Hop.From + "->" + gap.Hop.To
		}
		out = append(out, gap.Reason+hop)
	}
	return out
}

// declared are the complete Kubernetes declarations.
var declared = []string{"--distribution", "official_upstream", "--resource-scope-complete", "--target-api-apply-required"}

func args(paths []string, extra ...string) []string {
	return append(append(append([]string{}, paths...), declared...), append([]string{"--now", testNow}, extra...)...)
}

const (
	cronjobV1beta1 = "apiVersion: batch/v1beta1\nkind: CronJob\nmetadata:\n  name: nightly-report\n  namespace: default\nspec:\n  schedule: \"0 2 * * *\"\n---\napiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: report-settings\n  namespace: default\ndata:\n  mode: nightly\n"
	cronjobV1      = "apiVersion: batch/v1\nkind: CronJob\nmetadata:\n  name: nightly-report\n  namespace: default\nspec:\n  schedule: \"0 2 * * *\"\n---\napiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: report-settings\n  namespace: default\ndata:\n  mode: nightly\n"
)

// basisFields are the evidence members of a record of the given basis.
func basisFields(basis, reviewedAt string) string {
	if basis == "mechanical" {
		return `"basis":"mechanical","extractor":{"id":"k8s.served-api-removal","version":"1.1.0","codeDigest":"sha256:` + strings.Repeat("1", 64) + `"},"derivedAt":"` + reviewedAt + `"`
	}
	return `"basis":"reviewed"`
}

func pick(value, fallback string) string {
	if value != "" {
		return value
	}
	return fallback
}
