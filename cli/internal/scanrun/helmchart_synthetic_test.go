// SPDX-License-Identifier: AGPL-3.0-only

//go:build prufyx_synthetic_knowledge

package scanrun

// Run with: go test -tags prufyx_synthetic_knowledge ./internal/scanrun/

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/cncfcheck"
	"github.com/prufyx/prufyx/cli/internal/constraintengine"
	"github.com/prufyx/prufyx/cli/internal/scanreport"
)

// Synthetic chart rules for the keda chart (never published). The chart
// identity is the reviewed chart-source row of keda; the fact follows the
// helm.values naming.
const (
	kedaSlug      = "keda"
	kedaComponent = "pkg:github/kedacore/keda"
	kedaFact      = "component.keda.chart_keda_values_paths_set"
	kedaChartJSON = `{"source":"https://kedacore.github.io/charts","name":"keda"}`
	kedaRevision  = "8b3a8837a62fa9e726f01b95990de3ec9a19a8f2"

	chartRequireID = "keda.helm-values.keda.required-values.2-15-0-to-2-16-0"
	chartForbidID  = "keda.helm-values.keda.removed-values.2-15-0-to-2-16-0"
	chartKubeID    = "keda.helm-values.keda.kube-version.2-15-0-to-2-16-0"
	chartAppID     = "keda.synthetic-app-rule-reading-values.2-15-0-to-2-16-0"
	chartOtherID   = "keda.helm-values.other-chart.required-values.2-15-0-to-2-16-0"
)

func kedaSource(id string) string {
	return `{"id":"` + id + `","url":"https://github.com/kedacore/charts/blob/` + kedaRevision + `/keda/values.schema.json","revision":"` + kedaRevision + `","contentDigest":"sha256:` + strings.Repeat("0", 64) + `","startLine":1,"endLine":2}`
}

func kedaFactDef() cncfcheck.Fact {
	return cncfcheck.Fact{Side: "proposed", ID: kedaFact, Component: kedaComponent, Type: constraintengine.FactSet, Description: "Synthetic."}
}

// chartEntry is one synthetic rule. subject is the subject JSON without
// braces' closing; body is the operator-specific part.
func chartEntry(id, operator, subject, body, basis string, facts ...cncfcheck.Fact) cncfcheck.Entry {
	evidence := `"evidence":{"state":"active",` + currentWindow + `,"sources":[` + kedaSource("s-"+id[len(id)-6:]) + `]`
	if basis != "" {
		evidence += `,"basis":"` + basis + `"`
		if basis == "mechanical" {
			evidence += `,"derivedAt":"` + currentReviewed + `","extractor":{"id":"helm.values.keda.keda","version":"1.1.0","codeDigest":"sha256:` + strings.Repeat("1", 64) + `"}`
		}
	}
	evidence += `}`
	rule := `{"id":"` + id + `","operator":"` + operator + `","subject":` + subject + `,` + body + `,` + evidence + `,"reasonCode":"HELM_VALUES_SYNTHETIC","nextAction":"synthetic chart rule ` + id + `"}`
	if facts == nil {
		facts = []cncfcheck.Fact{}
	}
	return cncfcheck.Entry{Project: kedaSlug, Description: "Synthetic test-only chart rule " + id + ". Never published.", RequiredFacts: facts, Rule: json.RawMessage(rule)}
}

func kedaChartSubject(from, to string) string {
	return `{"component":"` + kedaComponent + `","chart":` + kedaChartJSON + `,"from":"` + from + `","to":"` + to + `"}`
}

func setBody(members ...string) string {
	quoted, _ := json.Marshal(members)
	return `"setCondition":{"side":"proposed","component":"` + kedaComponent + `","factId":"` + kedaFact + `","members":` + string(quoted) + `}`
}

// baseChartEntries: a required-values rule, a refused-values rule, a
// Kubernetes minimum, an application rule that reads the values set (so a
// chart hop must never decide it), and a rule of another chart of keda.
func baseChartEntries(basis string) []cncfcheck.Entry {
	return []cncfcheck.Entry{
		chartEntry(chartRequireID, constraintengine.OperatorRequireSetMember, kedaChartSubject("2.15.0", "2.16.0"), setBody("auth.token", "k..a_2Eb"), basis, kedaFactDef()),
		chartEntry(chartForbidID, constraintengine.OperatorForbidSetMember, kedaChartSubject("2.15.0", "2.16.0"), setBody("legacy.key"), basis, kedaFactDef()),
		chartEntry(chartKubeID, "require_component_version", kedaChartSubject("2.15.0", "2.16.0"),
			`"dependency":{"side":"proposed","component":"pkg:github/kubernetes/kubernetes","comparison":"gte","version":"1.30.0"}`, basis),
		chartEntry(chartAppID, constraintengine.OperatorRequireSetMember, `{"component":"`+kedaComponent+`","from":"2.15.0","to":"2.16.0"}`, setBody("app.only"), basis, kedaFactDef()),
		chartEntry(chartOtherID, constraintengine.OperatorRequireSetMember,
			`{"component":"`+kedaComponent+`","chart":{"source":"https://example.com/charts","name":"keda-other"},"from":"2.15.0","to":"2.16.0"}`,
			`"setCondition":{"side":"proposed","component":"`+kedaComponent+`","factId":"component.keda.chart_keda-other_values_paths_set","members":["other.key"]}`, basis,
			cncfcheck.Fact{Side: "proposed", ID: "component.keda.chart_keda-other_values_paths_set", Component: kedaComponent, Type: constraintengine.FactSet, Description: "Synthetic."}),
	}
}

// chartDefinitions are the synthetic facts the registry does not hold; the
// registry itself defines kedaFact.
func chartDefinitions() []constraintengine.FactDefinition {
	return []constraintengine.FactDefinition{
		{ID: "component.keda.chart_keda-other_values_paths_set", Component: kedaComponent, Type: constraintengine.FactSet},
	}
}

func installCharts(t *testing.T, entries []cncfcheck.Entry) Knowledge {
	t.Helper()
	restore, err := cncfcheck.UseSyntheticKnowledge(chartDefinitions(), entries)
	if err != nil {
		t.Fatalf("synthetic chart knowledge refused: %v", err)
	}
	t.Cleanup(restore)
	embedded, err := LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	return embedded
}

// chartScan writes the values files into a fresh directory (with a
// manifest) and scans the keda chart hop 2.15.0 -> 2.16.0.
func chartScan(t *testing.T, knowledge Knowledge, values []string, extra ...string) Result {
	t.Helper()
	dir := t.TempDir()
	write := func(name, content string) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	argv := []string{write("manifest.yaml", "apiVersion: v1\nkind: ConfigMap\nmetadata: {name: a, namespace: default}\n"),
		"--now", testNow, "--chart", "keda=keda", "--from", "keda=2.15.0", "--to", "keda=2.16.0"}
	for index, content := range values {
		argv = append(argv, "--helm-values", write(fmt.Sprintf("values-%d.yaml", index), content))
	}
	return mustScan(t, knowledge, append(argv, extra...)...)
}

func passIDs(report scanreport.Report) []string {
	var out []string
	for _, pass := range report.Passes {
		out = append(out, pass.RuleID)
	}
	return out
}

func findingOf(report scanreport.Report, id string) *scanreport.Finding {
	for i := range report.Findings {
		if report.Findings[i].RuleID == id {
			return &report.Findings[i]
		}
	}
	return nil
}

func gapWith(report scanreport.Report, text string) bool {
	for _, gap := range report.Gaps {
		if strings.Contains(gap.Detail, text) {
			return true
		}
	}
	return false
}

// neverDecidesAppOrOtherChart: the application rule and the other chart's
// rule are never a pass or a finding of a chart hop.
func neverDecidesAppOrOtherChart(t *testing.T, report scanreport.Report) {
	t.Helper()
	for _, id := range []string{chartAppID, chartOtherID} {
		if slices.Contains(passIDs(report), id) || findingOf(report, id) != nil {
			t.Fatalf("chart hop decided %s: %+v %+v", id, report.Passes, report.Findings)
		}
	}
	if !gapWith(report, "rule "+chartAppID+" could not be decided ("+constraintengine.ReasonAppVersionNotDeclared+")") {
		t.Fatalf("application rule not reported undetermined: %+v", report.Gaps)
	}
	for _, gap := range report.Gaps {
		if strings.Contains(gap.Detail, chartOtherID) {
			t.Fatalf("another chart's rule surfaced: %+v", gap)
		}
	}
}

// TestChartHopWithoutCompleteDeclaration: without --helm-values-complete no
// required key is confirmed (UNKNOWN), a refused key that is set still
// blocks, and nothing passes over the set.
func TestChartHopWithoutCompleteDeclaration(t *testing.T) {
	knowledge := installCharts(t, baseChartEntries(""))
	result := chartScan(t, knowledge, []string{"auth:\n  token: x\nlegacy:\n  key: 1\n"}, "--helm-set", `a\.b=1`)
	report := result.Report
	if report.Verdict != scanreport.VerdictBlocked || result.Exit != scanreport.ExitBlocked {
		t.Fatalf("verdict %s exit %d", report.Verdict, result.Exit)
	}
	forbid := findingOf(report, chartForbidID)
	if forbid == nil || !reflect.DeepEqual(forbid.Keys, []string{"legacy.key"}) || forbid.Hop.Chart != "keda" {
		t.Fatalf("refused key not found: %+v", report.Findings)
	}
	if findingOf(report, chartRequireID) != nil || len(passIDs(report)) != 0 {
		t.Fatalf("decided over an incomplete set: %+v %+v", report.Findings, report.Passes)
	}
	if !gapWith(report, "the supplied values are not declared complete") {
		t.Fatalf("no completeness gap: %+v", report.Gaps)
	}
	if !gapWith(report, "rule "+chartKubeID+" needs the Kubernetes version") {
		t.Fatalf("no Kubernetes version gap: %+v", report.Gaps)
	}
	neverDecidesAppOrOtherChart(t, report)
	path := report.Paths[0]
	if path.Chart == nil || path.Chart.Name != "keda" || path.Chart.Complete || path.Chart.UniverseSize != 4 || path.Chart.Members != 3 {
		t.Fatalf("path chart %+v", path.Chart)
	}
	if report.Inventory[0].Chart != "keda" || report.Inventory[0].Covered {
		t.Fatalf("inventory %+v", report.Inventory)
	}
	human := string(scanreport.Human(report, scanreport.HumanOptions{}))
	if !strings.Contains(human, "keda chart keda 2.15.0 -> 2.16.0: 1 hop") || !strings.Contains(human, "keys: legacy.key") || !strings.Contains(human, "chart keda 2.15.0 -> 2.16.0") {
		t.Fatalf("human output:\n%s", human)
	}
}

// TestChartHopDecided: with the values declared complete and the
// Kubernetes target given, every chart rule decides; the hop is still never
// covered and the application rule stays undetermined.
func TestChartHopDecided(t *testing.T) {
	knowledge := installCharts(t, baseChartEntries(""))
	result := chartScan(t, knowledge, []string{"auth:\n  token: x\n"}, "--helm-set", `a\.b=1`, "--helm-values-complete", "--to", "kubernetes=1.31.0")
	report := result.Report
	passes := passIDs(report)
	for _, id := range []string{chartRequireID, chartForbidID, chartKubeID} {
		if !slices.Contains(passes, id) {
			t.Fatalf("%s did not pass: %v %+v", id, passes, report.Gaps)
		}
	}
	if len(report.Findings) != 0 || report.Verdict != scanreport.VerdictUnknown {
		t.Fatalf("verdict %s findings %+v", report.Verdict, report.Findings)
	}
	neverDecidesAppOrOtherChart(t, report)
	if !report.Paths[slices.IndexFunc(report.Paths, func(p scanreport.Path) bool { return p.Component == kedaSlug })].Chart.Complete {
		t.Fatal("complete set not disclosed")
	}

	missing := chartScan(t, knowledge, []string{"auth:\n  other: x\n"}, "--helm-values-complete", "--to", "kubernetes=1.29.0").Report
	require := findingOf(missing, chartRequireID)
	if require == nil || !reflect.DeepEqual(require.Keys, []string{"auth.token", "k..a_2Eb"}) {
		t.Fatalf("missing required keys not blocked: %+v", missing.Findings)
	}
	if findingOf(missing, chartKubeID) == nil {
		t.Fatalf("Kubernetes minimum not blocked: %+v", missing.Findings)
	}
}

// TestChartHopNullOverride: Helm keeps a null through the merge of the
// supplied values and then removes the key with any chart default under
// it, so a null left in the merged values makes the set incomplete, even
// when it removes a key an earlier file set. A null that a later source
// replaces is forgotten.
func TestChartHopNullOverride(t *testing.T) {
	knowledge := installCharts(t, baseChartEntries(""))
	nulled := chartScan(t, knowledge, []string{"auth:\n  token: x\na.b: 1\nresources:\n  limits: {cpu: 1}\n", "resources: null\n"}, "--helm-values-complete", "--to", "kubernetes=1.31.0").Report
	if slices.Contains(passIDs(nulled), chartRequireID) || slices.Contains(passIDs(nulled), chartForbidID) {
		t.Fatalf("passed with a null override: %v", passIDs(nulled))
	}
	if !gapWith(nulled, `set "resources" to null`) {
		t.Fatalf("no null gap: %+v", nulled.Gaps)
	}
	replaced := chartScan(t, knowledge, []string{"resources: null\n", "auth:\n  token: x\nresources:\n  limits: {cpu: 1}\n"}, "--helm-set", `a\.b=1`, "--helm-values-complete", "--to", "kubernetes=1.31.0").Report
	if !slices.Contains(passIDs(replaced), chartRequireID) || gapWith(replaced, "to null") {
		t.Fatalf("a replaced null was not forgotten: %v %+v", passIDs(replaced), replaced.Gaps)
	}
	setNull := chartScan(t, knowledge, []string{"auth:\n  token: x\n"}, "--helm-set", `a\.b=1`, "--helm-set", "auth.token=NULL", "--helm-values-complete").Report
	if slices.Contains(passIDs(setNull), chartRequireID) || findingOf(setNull, chartRequireID) != nil || !gapWith(setNull, `set "auth.token" to null`) {
		t.Fatalf("--helm-set null: %v %+v %+v", passIDs(setNull), setNull.Findings, setNull.Gaps)
	}
}

// TestChartHopOrderAndDeterminism: the files are merged in the order given
// (a later file wins), and the same inputs give the same bytes.
func TestChartHopOrderAndDeterminism(t *testing.T) {
	knowledge := installCharts(t, baseChartEntries(""))
	first, second := "legacy:\n  key: 1\nauth: {token: x}\n", "legacy: {other: 1}\nauth: {token: y}\n"
	scanJSON := func(values []string) ([]byte, scanreport.Report) {
		report := chartScan(t, knowledge, values, "--helm-values-complete", "--helm-set", `a\.b=1`).Report
		// The values files live in a fresh directory each time: compare
		// with their paths redacted away.
		report.Provenance.HelmValues[0].Files = nil
		return jsonOf(t, report), report
	}
	a1, ra := scanJSON([]string{first, second})
	a2, _ := scanJSON([]string{first, second})
	if !bytes.Equal(a1, a2) {
		t.Fatal("same inputs gave different reports")
	}
	if findingOf(ra, chartForbidID) == nil {
		t.Fatalf("legacy.key merged away: %+v", ra.Findings)
	}
	_, rb := scanJSON([]string{"legacy: null\n", first})
	if findingOf(rb, chartForbidID) == nil {
		t.Fatal("order: a later file must win")
	}
	_, rc := scanJSON([]string{first, "legacy: 5\n"})
	if findingOf(rc, chartForbidID) != nil || !slices.Contains(passIDs(rc), chartForbidID) {
		t.Fatalf("a later scalar must replace the mapping: %+v %v", rc.Findings, passIDs(rc))
	}
}

// TestChartUniverse: the set holds only the members the rules name, so a
// values file with far more than 256 paths still decides; when the rules
// name more than 256 members the set is unsupported and nothing decides.
// The universe comes from every rule that reads the fact, whatever
// --require-basis leaves out, so the engine input never depends on it.
func TestChartUniverse(t *testing.T) {
	knowledge := installCharts(t, baseChartEntries("mechanical"))
	var big strings.Builder
	big.WriteString("auth:\n  token: x\nbig:\n")
	for i := 0; i < 400; i++ {
		fmt.Fprintf(&big, "  k%03d: {a: 1}\n", i)
	}
	result := chartScan(t, knowledge, []string{big.String()}, "--helm-set", `a\.b=1`, "--helm-values-complete")
	if !slices.Contains(passIDs(result.Report), chartRequireID) || result.Report.Paths[0].Chart.PathsRead < 800 {
		t.Fatalf("large values not decided: %v %+v", passIDs(result.Report), result.Report.Paths[0].Chart)
	}
	excluded := chartScan(t, knowledge, []string{big.String()}, "--helm-set", `a\.b=1`, "--helm-values-complete", "--require-basis", "reviewed")
	if len(passIDs(excluded.Report)) != 0 || excluded.Report.TrustPolicy == nil || excluded.Report.TrustPolicy.ExcludedRules == 0 {
		t.Fatalf("trust policy: %v %+v", passIDs(excluded.Report), excluded.Report.TrustPolicy)
	}
	if got, want := excluded.Report.Paths[0].Hops[0].InputDigest, result.Report.Paths[0].Hops[0].InputDigest; got != want {
		t.Fatalf("the engine input depends on --require-basis: %s != %s", got, want)
	}
}

func TestChartUniverseTooLarge(t *testing.T) {
	entries := baseChartEntries("")
	// Five more rules of other chart releases, 52 distinct members each:
	// 260 + 4 members in all.
	for r := 0; r < 5; r++ {
		var members []string
		for m := 0; m < 52; m++ {
			members = append(members, fmt.Sprintf("u%d.m%02d", r, m))
		}
		from, to := fmt.Sprintf("2.%d.0", r+5), fmt.Sprintf("2.%d.0", r+6)
		entries = append(entries, chartEntry(fmt.Sprintf("keda.helm-values.keda.removed-values.2-%d-0-to-2-%d-0", r+5, r+6), constraintengine.OperatorForbidSetMember, kedaChartSubject(from, to), setBody(members...), "", kedaFactDef()))
	}
	knowledge := installCharts(t, entries)
	report := chartScan(t, knowledge, []string{"auth:\n  token: x\nlegacy: {key: 1}\n"}, "--helm-set", `a\.b=1`, "--helm-values-complete").Report
	if len(passIDs(report)) != 0 || len(report.Findings) != 0 {
		t.Fatalf("decided over an unsupported set: %v %+v", passIDs(report), report.Findings)
	}
	if !gapWith(report, "name 264 values keys, more than a set holds") {
		t.Fatalf("no universe gap: %+v", report.Gaps)
	}
}

// TestApplicationHopNeverSelectsChartRules: the same versions without
// --chart are an application hop; adding chart rules to the knowledge
// changes no gap, finding or pass of it.
func TestApplicationHopNeverSelectsChartRules(t *testing.T) {
	run := func(knowledge Knowledge) []string {
		_, paths := files(t, map[string]string{"applyset.yaml": "apiVersion: keda.sh/v1alpha1\nkind: ScaledObject\nmetadata: {name: a, namespace: default}\n"})
		report := mustScan(t, knowledge, args(paths, "--from", "keda=2.15.0", "--to", "keda=2.16.0")...).Report
		out := gapReasons(report)
		for _, f := range report.Findings {
			out = append(out, "finding "+f.RuleID)
		}
		for _, p := range report.Passes {
			out = append(out, "pass "+p.RuleID)
		}
		return out
	}
	embedded, err := LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	plain := run(embedded)
	with := run(installCharts(t, baseChartEntries("")))
	if !reflect.DeepEqual(plain, with) {
		t.Fatalf("chart rules changed an application hop:\n%v\n%v", plain, with)
	}
}

// TestChartKubeMinimumWithoutValuesRule: when no rule of the chart reads a
// values-path set, no fact is declared (none is invented), and a
// Kubernetes minimum still decides: below the minimum it blocks; at the
// minimum it passes, and the hop stays undecided through the chart gap.
func TestChartKubeMinimumWithoutValuesRule(t *testing.T) {
	kube := chartEntry(chartKubeID, "require_component_version", kedaChartSubject("2.15.0", "2.16.0"),
		`"dependency":{"side":"proposed","component":"pkg:github/kubernetes/kubernetes","comparison":"gte","version":"1.30.0"}`, "")
	knowledge := installCharts(t, []cncfcheck.Entry{kube})
	values := []string{"auth:\n  token: x\n"}

	below := chartScan(t, knowledge, values, "--helm-values-complete", "--from", "kubernetes=1.29.0", "--to", "kubernetes=1.29.4")
	if below.Report.Verdict != scanreport.VerdictBlocked || below.Exit != scanreport.ExitBlocked || findingOf(below.Report, chartKubeID) == nil {
		t.Fatalf("below the minimum: %s %+v %+v", below.Report.Verdict, below.Report.Findings, below.Report.Gaps)
	}
	if strings.Contains(string(jsonOf(t, below.Report)), "values_paths_set") {
		t.Fatal("a values fact was declared without a rule that reads one")
	}

	at := chartScan(t, knowledge, values, "--helm-values-complete", "--to", "kubernetes=1.30.0").Report
	if !slices.Contains(passIDs(at), chartKubeID) || len(at.Findings) != 0 || at.Verdict != scanreport.VerdictUnknown {
		t.Fatalf("at the minimum: %s %v %+v", at.Verdict, passIDs(at), at.Findings)
	}
	if !gapWith(at, "keda chart keda: only its values and Kubernetes-version rules are checked") {
		t.Fatalf("no chart gap: %+v", at.Gaps)
	}
	if path := at.Paths[slices.IndexFunc(at.Paths, func(p scanreport.Path) bool { return p.Component == kedaSlug })]; path.Chart.Complete || path.Chart.Members != 0 || path.Chart.UniverseSize != 0 {
		t.Fatalf("path chart %+v", path.Chart)
	}

	unset := chartScan(t, knowledge, values).Report
	if len(unset.Findings) != 0 || len(unset.Passes) != 0 || !gapWith(unset, "rule "+chartKubeID+" needs the Kubernetes version") {
		t.Fatalf("without --to kubernetes: %+v %+v %+v", unset.Findings, unset.Passes, unset.Gaps)
	}
}
