// SPDX-License-Identifier: AGPL-3.0-only

package scanrun

import (
	"fmt"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/scanreport"
)

// Documents that cannot be read as Kubernetes objects. None of them is
// related to the removed CronJob.
const (
	templatedConfigMap  = "apiVersion: v1\nkind: ConfigMap\nmetadata: {name: '{{ .Release.Name }}-settings'}\ndata: {mode: nightly}\n"
	unparseableTemplate = "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: {{ .Release.Name }}\n"
	valuesFile          = "replicas: 2\nimage: report:1.0\n"
	nestedList          = "apiVersion: v1\nkind: List\nitems:\n- {apiVersion: v1, kind: List, items: [{apiVersion: v1, kind: Service, metadata: {name: s}}]}\n"
	removedCronJobOnly  = "apiVersion: batch/v1beta1\nkind: CronJob\nmetadata:\n  name: nightly-report\n  namespace: default\nspec:\n  schedule: \"0 2 * * *\"\n"
)

// unreadable are the inputs added beside the apply set, with the gap each
// one must leave and whether intake lists it as omitted.
var unreadable = map[string]struct {
	files   map[string]string
	gap     string
	omitted int
}{
	"templated document":         {map[string]string{"chart.yaml": templatedConfigMap}, "DOCUMENTS_TEMPLATED", 1},
	"unparseable template":       {map[string]string{"chart.yaml": unparseableTemplate}, "DOCUMENTS_TEMPLATED", 1},
	"values file":                {map[string]string{"values.yaml": valuesFile}, "DOCUMENTS_NOT_EVALUATED", 1},
	"nested list":                {map[string]string{"list.yaml": nestedList}, "DOCUMENTS_NOT_EVALUATED", 1},
	"several templated":          {map[string]string{"chart/a.yaml": templatedConfigMap, "chart/b.yaml": unparseableTemplate, "chart/c.yaml": templatedConfigMap}, "DOCUMENTS_TEMPLATED", 3},
	"templated and values files": {map[string]string{"chart.yaml": templatedConfigMap, "values.yaml": valuesFile}, "DOCUMENTS_TEMPLATED", 2},
	// Read, but not placed as a Kubernetes object: never omitted.
	"invalid apiVersion":         {map[string]string{"odd.yaml": "apiVersion: Batch/V1\nkind: Widget\nmetadata: {name: w}\n"}, "DOCUMENTS_NOT_EVALUATED", 0},
	"list with invalid metadata": {map[string]string{"odd.yaml": "apiVersion: v1\nkind: List\nmetadata: {continue: 1}\nitems:\n- {apiVersion: example.io/v1, kind: Widget, metadata: {name: s}}\n"}, "DOCUMENTS_NOT_EVALUATED", 0},
}

func withFiles(base map[string]string, extra map[string]string) map[string]string {
	out := map[string]string{}
	for name, content := range base {
		out[name] = content
	}
	for name, content := range extra {
		out[name] = content
	}
	return out
}

func gapNamed(report scanreport.Report, reason string) bool {
	for _, gap := range report.Gaps {
		if gap.Reason == reason {
			return true
		}
	}
	return false
}

// TestScanBlockerNotHiddenByUnrelatedInput reproduces the report: a
// directory with a batch/v1beta1 CronJob is BLOCKED with one finding, and
// adding one unrelated templated ConfigMap made it UNKNOWN with no finding.
// The finding now stays, identical, beside a gap and the omitted document,
// for every kind of unreadable input, with and without line reviews.
func TestScanBlockerNotHiddenByUnrelatedInput(t *testing.T) {
	embedded, err := LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	// The embedded knowledge has no path policy, so only a one-line upgrade
	// is planned with it.
	cases := []struct {
		name      string
		knowledge Knowledge
		to        string
	}{
		{"embedded knowledge", embedded, "1.25.5"},
		{"reviewed lines", newKnowledge(t, knowledgeOptions{lines: allLines, policy: "current"}), "1.25.5"},
		{"reviewed lines", newKnowledge(t, knowledgeOptions{lines: allLines, policy: "current"}), "1.30.4"},
	}
	for _, tc := range cases {
		knowledgeName, knowledge, to := tc.name, tc.knowledge, tc.to
		{
			base := map[string]string{"cronjob.yaml": removedCronJobOnly}
			run := func(contents map[string]string) Result {
				var result Result
				dir, _ := files(t, contents)
				inDir(t, dir, func() {
					result = mustScan(t, knowledge, args([]string{"."}, "--from", "kubernetes=1.24.17", "--to", "kubernetes="+to)...)
				})
				return result
			}
			alone := run(base)
			if alone.Exit != scanreport.ExitBlocked || len(alone.Report.Findings) != 1 || alone.Report.Findings[0].RuleID != cronjobRuleID {
				t.Fatalf("%s %s alone: exit %d findings %+v", knowledgeName, to, alone.Exit, alone.Report.Findings)
			}
			for name, extra := range unreadable {
				t.Run(knowledgeName+"/"+to+"/"+name, func(t *testing.T) {
					result := run(withFiles(base, extra.files))
					report := result.Report
					if result.Exit != scanreport.ExitBlocked || report.Verdict != scanreport.VerdictBlocked {
						t.Fatalf("exit %d verdict %s gaps %v", result.Exit, report.Verdict, gapReasons(report))
					}
					if !reflect.DeepEqual(report.Findings, alone.Report.Findings) {
						t.Fatalf("findings changed:\n%+v\n%+v", report.Findings, alone.Report.Findings)
					}
					if !gapNamed(report, extra.gap) || len(report.Omitted) != extra.omitted || report.Summary.DocumentsOmitted != extra.omitted {
						t.Fatalf("gaps %v omitted %+v", gapReasons(report), report.Omitted)
					}
					if report.Paths[0].Hops[0].Status != scanreport.HopBlocked {
						t.Fatalf("hop %+v", report.Paths[0].Hops[0])
					}
					// Every gap of the CronJob alone is still there.
					for _, gap := range gapReasons(alone.Report) {
						found := false
						for _, other := range gapReasons(report) {
							found = found || other == gap
						}
						if !found {
							t.Fatalf("gap %s lost: %v", gap, gapReasons(report))
						}
					}
				})
			}
		}
	}
}

// TestScanBlockerBesideTemplatedDocumentsFormats: a blocker beside several
// unrelated templated documents is BLOCKED in every format, and every
// format shows the finding and the gap. The human and JSON output is kept
// as a golden file; SARIF and Markdown are in TestScanFormatGoldens.
func TestScanBlockerBesideTemplatedDocumentsFormats(t *testing.T) {
	run := formatRunNamed(t, "blocked-templated")
	for _, format := range scanreport.Formats() {
		result := run.result(format)
		out, err := scanreport.Render(result.Report, format, scanreport.RenderOptions{})
		if err != nil {
			t.Fatal(err)
		}
		if result.Exit != scanreport.ExitBlocked || len(result.Report.Findings) != 1 || !gapNamed(result.Report, "DOCUMENTS_TEMPLATED") || len(result.Report.Omitted) != 2 {
			t.Fatalf("%s: exit %d findings %d gaps %v omitted %d", format, result.Exit, len(result.Report.Findings), gapReasons(result.Report), len(result.Report.Omitted))
		}
		text := string(out)
		for _, want := range []string{"batch/v1beta1", "unrendered templates"} {
			if !strings.Contains(text, want) {
				t.Errorf("%s output does not show %q:\n%s", format, want, text)
			}
		}
	}
	report := run.result("json").Report
	golden(t, "blocked-templated.txt", scanreport.Human(report, scanreport.HumanOptions{}))
	golden(t, "blocked-templated.json", jsonOf(t, report))
}

func formatRunNamed(t *testing.T, name string) formatRun {
	t.Helper()
	for _, run := range formatRuns(t) {
		if run.name == name {
			return run
		}
	}
	t.Fatalf("no format run %s", name)
	return formatRun{}
}

// TestScanBlockerNeedingUnreadableDocumentStaysUnknown: a blocker is shown
// only when the documents that were read establish it. When its evidence
// needs the unreadable document, the answer stays UNKNOWN with no finding.
func TestScanBlockerNeedingUnreadableDocumentStaysUnknown(t *testing.T) {
	knowledge := newKnowledge(t, knowledgeOptions{lines: allLines, policy: "current"})
	scanDir := func(t *testing.T, k Knowledge, contents map[string]string, to string) Result {
		dir, _ := files(t, contents)
		return mustScan(t, k, args([]string{dir}, "--from", "kubernetes=1.24.17", "--to", "kubernetes="+to)...)
	}

	// The removed version is only in the templated document.
	for name, chart := range map[string]string{
		"templated name":        "apiVersion: batch/v1beta1\nkind: CronJob\nmetadata: {name: '{{ .Release.Name }}'}\n",
		"unparseable template":  "apiVersion: batch/v1beta1\nkind: CronJob\nmetadata:\n  name: {{ .Release.Name }}\n",
		"templated api version": "apiVersion: '{{ .Values.cronjobAPI }}'\nkind: CronJob\nmetadata: {name: nightly}\n",
	} {
		t.Run(name, func(t *testing.T) {
			result := scanDir(t, knowledge, map[string]string{"applyset.yaml": cronjobV1, "chart.yaml": chart}, "1.30.4")
			hop := result.Report.Paths[0].Hops[0]
			if result.Exit != scanreport.ExitUnknown || len(result.Report.Findings) != 0 || !gapNamed(result.Report, "DOCUMENTS_TEMPLATED") || hop.Status != scanreport.HopPartial {
				t.Fatalf("exit %d findings %+v gaps %v hop %+v", result.Exit, result.Report.Findings, gapReasons(result.Report), hop)
			}
		})
	}

	// A rule that blocks the readable CronJob only when no PodSecurityPolicy
	// at a removed version is present needs every document: the absence is
	// never established while one cannot be read.
	const id = "kubernetes.synthetic-guarded.1-24-0-to-1-25-0"
	guard := `"appliesWhen":[{"side":"proposed","component":"pkg:github/kubernetes/kubernetes","factId":"component.kubernetes.psp_v1beta1_removed_gvk_present","boolValue":false}],`
	base := newKnowledge(t, knowledgeOptions{lines: allLines, policy: "current", unchecked: true,
		synthetic: []string{rangedRule(id, cronjobFact, true, guard)}, dropRuleIDs: map[string][]string{"1.25": {cronjobRuleID}}})
	guarded := hiddenRules{Knowledge: base, hidden: map[string]bool{cronjobRuleID: true}}
	readable := scanDir(t, guarded, map[string]string{"cronjob.yaml": removedCronJobOnly}, "1.25.5")
	if readable.Exit != scanreport.ExitBlocked || len(readable.Report.Findings) != 1 || readable.Report.Findings[0].RuleID != id {
		t.Fatalf("guarded rule alone: exit %d findings %+v gaps %v", readable.Exit, readable.Report.Findings, gapReasons(readable.Report))
	}
	for name, extra := range unreadable {
		t.Run("guarded/"+name, func(t *testing.T) {
			result := scanDir(t, guarded, withFiles(map[string]string{"cronjob.yaml": removedCronJobOnly}, extra.files), "1.25.5")
			hop := result.Report.Paths[0].Hops[0]
			if result.Exit != scanreport.ExitUnknown || len(result.Report.Findings) != 0 || hop.Status != scanreport.HopPartial || !gapNamed(result.Report, extra.gap) {
				t.Fatalf("exit %d findings %+v hop %+v gaps %v", result.Exit, result.Report.Findings, hop, gapReasons(result.Report))
			}
			found := false
			for _, reason := range hop.Reasons {
				found = found || reason == extra.gap
			}
			if !found {
				t.Fatalf("hop reasons %v do not name %s", hop.Reasons, extra.gap)
			}
		})
	}
}

// TestScanFlowControlBlockerNotHidden: the 1.32 flow-control removal follows
// the same rule.
func TestScanFlowControlBlockerNotHidden(t *testing.T) {
	knowledge := newKnowledge(t, knowledgeOptions{lines: allLines, policy: "current"})
	flowSchema := "apiVersion: flowcontrol.apiserver.k8s.io/v1beta3\nkind: FlowSchema\nmetadata: {name: exempt}\n"
	run := func(contents map[string]string) Result {
		var result Result
		dir, _ := files(t, contents)
		inDir(t, dir, func() {
			result = mustScan(t, knowledge, args([]string{"."}, "--from", "kubernetes=1.31.0", "--to", "kubernetes=1.32.0")...)
		})
		return result
	}
	alone := run(map[string]string{"flow.yaml": flowSchema})
	if alone.Exit != scanreport.ExitBlocked || len(alone.Report.Findings) != 1 {
		t.Fatalf("alone: exit %d findings %+v gaps %v", alone.Exit, alone.Report.Findings, gapReasons(alone.Report))
	}
	with := run(map[string]string{"flow.yaml": flowSchema, "chart.yaml": templatedConfigMap})
	if with.Exit != scanreport.ExitBlocked || !reflect.DeepEqual(with.Report.Findings, alone.Report.Findings) || !gapNamed(with.Report, "DOCUMENTS_TEMPLATED") {
		t.Fatalf("with a template: exit %d findings %+v gaps %v", with.Exit, with.Report.Findings, gapReasons(with.Report))
	}
	only := run(map[string]string{"flow.yaml": "apiVersion: flowcontrol.apiserver.k8s.io/v1\nkind: FlowSchema\nmetadata: {name: exempt}\n", "chart.yaml": "apiVersion: flowcontrol.apiserver.k8s.io/v1beta3\nkind: FlowSchema\nmetadata: {name: '{{ x }}'}\n"})
	if only.Exit != scanreport.ExitUnknown || len(only.Report.Findings) != 0 {
		t.Fatalf("removed version only in the template: exit %d findings %+v", only.Exit, only.Report.Findings)
	}
}

// TestScanCustomResourceBlockerNotHidden: a removed custom-resource version
// in a readable document blocks beside a templated document; one only in
// the templated document does not, and a served version never passes.
func TestScanCustomResourceBlockerNotHidden(t *testing.T) {
	knowledge := newCRDKnowledge(t)
	run := func(contents map[string]string) Result {
		var result Result
		dir, _ := files(t, contents)
		inDir(t, dir, func() {
			result = mustScan(t, knowledge, ".", "--now", testNow, "--from", "strimzi=0.51.0", "--to", "strimzi=1.0.0", "--resource-scope-complete")
		})
		return result
	}
	alone := run(map[string]string{"kafka.yaml": kafkaV1beta2Doc})
	with := run(map[string]string{"kafka.yaml": kafkaV1beta2Doc, "chart.yaml": templatedConfigMap})
	if with.Exit != scanreport.ExitBlocked || len(with.Report.Findings) != 1 || !reflect.DeepEqual(with.Report.Findings, alone.Report.Findings) || !hasComponentGap(with.Report, "strimzi", scanreport.ReasonDocumentsTemplated, "unrendered templates") {
		t.Fatalf("exit %d findings %+v gaps %v", with.Exit, with.Report.Findings, gapReasons(with.Report))
	}
	if hop := strimziHop(t, with.Report); hop.Status != scanreport.HopBlocked {
		t.Fatalf("hop %+v", hop)
	}
	// A document that was read but cannot be placed is named as a gap while
	// the rule blocks.
	unplaced := run(map[string]string{"kafka.yaml": kafkaV1beta2Doc, "odd.yaml": "apiVersion: Batch/V1\nkind: Widget\nmetadata: {name: w}\n"})
	if unplaced.Exit != scanreport.ExitBlocked || len(unplaced.Report.Findings) != 1 || !hasComponentGap(unplaced.Report, "strimzi", scanreport.ReasonDocumentsNotEvaluated, "cannot be read as one apply set") {
		t.Fatalf("unplaced: exit %d findings %d gaps %v", unplaced.Exit, len(unplaced.Report.Findings), gapReasons(unplaced.Report))
	}
	served := run(map[string]string{"kafka.yaml": kafkaV1Doc, "chart.yaml": templatedConfigMap})
	if served.Exit != scanreport.ExitUnknown || len(served.Report.Findings) != 0 || len(served.Report.Passes) != 0 || !hasComponentGap(served.Report, "strimzi", scanreport.ReasonDocumentsTemplated, "unrendered templates") {
		t.Fatalf("served: exit %d passes %+v gaps %v", served.Exit, served.Report.Passes, gapReasons(served.Report))
	}
	hidden := run(map[string]string{"kafka.yaml": kafkaV1Doc, "chart.yaml": "apiVersion: kafka.strimzi.io/v1beta2\nkind: Kafka\nmetadata: {name: '{{ x }}'}\n"})
	if hidden.Exit != scanreport.ExitUnknown || len(hidden.Report.Findings) != 0 || len(hidden.Report.Passes) != 0 {
		t.Fatalf("only in the template: exit %d findings %+v passes %+v", hidden.Exit, hidden.Report.Findings, hidden.Report.Passes)
	}
}

// TestScanNeverPassesWithAGap: over combinations of readable documents
// (including an unreviewed sibling version, a paginated list, a witness
// inside a List and an object with items under a non-List kind), unreadable
// inputs, declarations (complete, open scope, no target apply, a custom
// build), and paths through removal lines and quiet lines (a line with no
// removal, where no rule is left undecided to name the gap):
//   - unreadable input is always a named gap, and a scan with any gap or
//     omitted document is never PASS;
//   - adding unrelated unreadable input never adds a finding, never removes
//     one, and never turns an answer into PASS.
//
// The same holds for a project checked for custom-resource versions.
func TestScanNeverPassesWithAGap(t *testing.T) {
	knowledge := newKnowledge(t, knowledgeOptions{lines: allLines, policy: "current"})
	pool := []string{
		cronjobV1,
		removedCronJobOnly,
		"apiVersion: policy/v1\nkind: PodDisruptionBudget\nmetadata: {name: pdb}\n",
		"apiVersion: flowcontrol.apiserver.k8s.io/v1beta3\nkind: FlowSchema\nmetadata: {name: exempt}\n",
		"apiVersion: batch/v2alpha1\nkind: CronJob\nmetadata: {name: sibling}\n",
		"apiVersion: v1\nkind: List\nmetadata: {continue: next}\nitems:\n- {apiVersion: batch/v1beta1, kind: CronJob, metadata: {name: paged}}\n",
		"apiVersion: v1\nkind: List\nitems:\n- {apiVersion: batch/v1beta1, kind: CronJob, metadata: {name: listed}}\n- {apiVersion: v1, kind: ConfigMap, metadata: {name: c}}\n",
		"apiVersion: example.io/v1\nkind: Bundle\nmetadata: {name: b}\nitems: []\n",
	}
	names := make([]string, 0, len(unreadable))
	for name := range unreadable {
		names = append(names, name)
	}
	sort.Strings(names)
	type variant struct {
		declarations []string
		pairs        [][2]string
		maxDocs      int
	}
	allPairs := [][2]string{{"1.24.17", "1.30.4"}, {"1.27.3", "1.28.1"}, {"1.29.6", "1.30.4"}, {"1.31.0", "1.32.0"}}
	somePairs := [][2]string{{"1.24.17", "1.25.5"}, {"1.29.6", "1.30.4"}}
	variants := map[string]variant{
		"complete":     {declared, allPairs, 2},
		"open scope":   {[]string{"--distribution", "official_upstream", "--target-api-apply-required"}, somePairs, 1},
		"no apply":     {[]string{"--distribution", "official_upstream", "--resource-scope-complete"}, somePairs, 1},
		"custom build": {[]string{"--distribution", "custom_build", "--resource-scope-complete", "--target-api-apply-required"}, somePairs, 1},
	}
	ruleIDs := func(report scanreport.Report) []string {
		var ids []string
		for _, finding := range report.Findings {
			ids = append(ids, finding.RuleID)
		}
		return ids
	}
	checked := 0
	for variantName, v := range variants {
		for mask := 1; mask < 1<<len(pool); mask++ {
			contents := map[string]string{}
			for index, doc := range pool {
				if mask&(1<<index) != 0 {
					contents[fmt.Sprintf("doc%d.yaml", index)] = doc
				}
			}
			if len(contents) > v.maxDocs {
				continue
			}
			for _, pair := range v.pairs {
				scanOf := func(input map[string]string) Result {
					dir, _ := files(t, input)
					command := append(append([]string{dir}, v.declarations...), "--now", testNow, "--from", "kubernetes="+pair[0], "--to", "kubernetes="+pair[1])
					return mustScan(t, knowledge, command...)
				}
				readable := scanOf(contents)
				for _, name := range names {
					result := scanOf(withFiles(contents, unreadable[name].files))
					report := result.Report
					checked++
					label := fmt.Sprintf("%s mask %b %s->%s %s", variantName, mask, pair[0], pair[1], name)
					if len(report.Gaps) == 0 || len(report.Omitted) != unreadable[name].omitted || !gapNamed(report, unreadable[name].gap) {
						t.Fatalf("%s: gap or omission missing: %v", label, gapReasons(report))
					}
					if report.Verdict == scanreport.VerdictPass || result.Exit == scanreport.ExitPass {
						t.Fatalf("%s: PASS with gaps %v", label, gapReasons(report))
					}
					if !reflect.DeepEqual(ruleIDs(report), ruleIDs(readable.Report)) {
						t.Fatalf("%s: findings %v, readable documents alone %v", label, ruleIDs(report), ruleIDs(readable.Report))
					}
					if (readable.Exit == scanreport.ExitBlocked) != (result.Exit == scanreport.ExitBlocked) {
						t.Fatalf("%s: exit %d, readable documents alone %d", label, result.Exit, readable.Exit)
					}
				}
			}
		}
	}

	// A project checked for custom-resource versions.
	crd := newCRDKnowledge(t)
	crPool := []string{kafkaV1Doc, kafkaV1beta2Doc, certificateDoc, settingsDoc}
	for _, scope := range [][]string{{"--resource-scope-complete"}, nil} {
		for mask := 1; mask < 1<<len(crPool); mask++ {
			contents := map[string]string{}
			for index, doc := range crPool {
				if mask&(1<<index) != 0 {
					contents[fmt.Sprintf("doc%d.yaml", index)] = doc
				}
			}
			scanOf := func(input map[string]string) Result {
				dir, _ := files(t, input)
				return mustScan(t, crd, append([]string{dir, "--now", testNow, "--from", "strimzi=0.51.0", "--to", "strimzi=1.0.0"}, scope...)...)
			}
			readable := scanOf(contents)
			for _, name := range names {
				result := scanOf(withFiles(contents, unreadable[name].files))
				checked++
				label := fmt.Sprintf("strimzi %v mask %b %s", scope, mask, name)
				if result.Exit == scanreport.ExitPass || !gapNamed(result.Report, unreadable[name].gap) || len(result.Report.Passes) != 0 {
					t.Fatalf("%s: exit %d passes %d gaps %v", label, result.Exit, len(result.Report.Passes), gapReasons(result.Report))
				}
				if !reflect.DeepEqual(ruleIDs(result.Report), ruleIDs(readable.Report)) {
					t.Fatalf("%s: findings %v, readable documents alone %v", label, ruleIDs(result.Report), ruleIDs(readable.Report))
				}
			}
		}
	}
	if checked == 0 {
		t.Fatal("nothing checked")
	}
}

// TestScanWitnessMustBeRenderedUnconditionally: a readable document is a
// witness only when it is applied as written whatever the unreadable input
// holds. A document that a template action of another document in its file
// may enclose, a document of a conditional subchart of a raw chart, a test
// template and a test hook are not witnesses: the answer stays UNKNOWN.
// Documents that are rendered unconditionally still block.
func TestScanWitnessMustBeRenderedUnconditionally(t *testing.T) {
	knowledge := newKnowledge(t, knowledgeOptions{lines: allLines, policy: "current"})
	cron := "apiVersion: batch/v1beta1\nkind: CronJob\nmetadata: {name: legacy}\n"
	templated := "apiVersion: v1\nkind: ConfigMap\nmetadata: {name: '{{ .Release.Name }}'}\n"
	cases := map[string]struct {
		files   map[string]string
		blocked bool
	}{
		"if and end in string scalars of the documents around it":   {map[string]string{"chart.yaml": "apiVersion: v1\nkind: ConfigMap\nmetadata: {name: a}\ndata: {x: \"{{- if .Values.legacy }}\"}\n---\n" + cron + "---\napiVersion: v1\nkind: ConfigMap\nmetadata: {name: b}\ndata: {y: \"{{- end }}\"}\n"}, false},
		"range and end in block scalars of the documents around it": {map[string]string{"chart.yaml": "apiVersion: v1\nkind: ConfigMap\nmetadata: {name: a}\ndata:\n  x: |\n    {{- range .Values.jobs }}\n---\n" + cron + "---\napiVersion: v1\nkind: ConfigMap\nmetadata: {name: b}\ndata:\n  y: |\n    {{- end }}\n"}, false},
		"open action in a document that is not Kubernetes shaped":   {map[string]string{"chart.yaml": "x: \"{{- with .Values.legacy }}\"\n---\n" + cron + "---\ny: \"{{- end }}\"\n"}, false},
		"else of an action opened elsewhere":                        {map[string]string{"chart.yaml": cron + "---\napiVersion: v1\nkind: ConfigMap\nmetadata: {name: a}\ndata: {x: \"{{- else }}\"}\n"}, false},
		"conditional subchart": {map[string]string{
			"Chart.yaml":                           "apiVersion: v2\nname: app\nversion: 1.0.0\ndependencies:\n- name: legacy\n  version: 1.0.0\n  condition: legacy.enabled\n",
			"values.yaml":                          "legacy:\n  enabled: false\n",
			"charts/legacy/Chart.yaml":             "apiVersion: v2\nname: legacy\nversion: 1.0.0\n",
			"charts/legacy/templates/cronjob.yaml": cron,
			"templates/configmap.yaml":             templated,
		}, false},
		"subchart gated by tags": {map[string]string{
			"Chart.yaml":                           "apiVersion: v2\nname: app\nversion: 1.0.0\ndependencies:\n- name: legacy\n  version: 1.0.0\n  tags: [old]\n",
			"charts/legacy/templates/cronjob.yaml": cron,
		}, false},
		"subchart not listed": {map[string]string{
			"Chart.yaml":                           "apiVersion: v2\nname: app\nversion: 1.0.0\n",
			"charts/legacy/templates/cronjob.yaml": cron,
		}, false},
		"test template":  {map[string]string{"Chart.yaml": "apiVersion: v2\nname: app\nversion: 1.0.0\n", "templates/tests/cronjob.yaml": cron}, false},
		"test hook":      {map[string]string{"cron.yaml": "apiVersion: batch/v1beta1\nkind: CronJob\nmetadata:\n  name: legacy\n  annotations: {helm.sh/hook: test}\n", "chart.yaml": templated}, false},
		"test hook list": {map[string]string{"cron.yaml": "apiVersion: batch/v1beta1\nkind: CronJob\nmetadata:\n  name: legacy\n  annotations: {helm.sh/hook: 'pre-install,test-success'}\n", "chart.yaml": templated}, false},
		// Rendered unconditionally: still a blocker.
		"action closed within the templated document": {map[string]string{"chart.yaml": cron + "---\napiVersion: v1\nkind: ConfigMap\nmetadata: {name: a}\ndata:\n  x: |\n    {{- if .Values.on }}on{{- else }}off{{- end }}\n"}, true},
		"open action in another file":                 {map[string]string{"cron.yaml": cron, "chart.yaml": "apiVersion: v1\nkind: ConfigMap\nmetadata: {name: a}\ndata: {x: \"{{- if .Values.legacy }}\"}\n"}, true},
		"template of the chart itself":                {map[string]string{"Chart.yaml": "apiVersion: v2\nname: app\nversion: 1.0.0\n", "templates/cronjob.yaml": cron}, true},
		"unconditional subchart": {map[string]string{
			"Chart.yaml":                           "apiVersion: v2\nname: app\nversion: 1.0.0\ndependencies:\n- name: legacy\n  version: 1.0.0\n",
			"charts/legacy/templates/cronjob.yaml": cron,
		}, true},
		"other hook": {map[string]string{"cron.yaml": "apiVersion: batch/v1beta1\nkind: CronJob\nmetadata:\n  name: legacy\n  annotations: {helm.sh/hook: pre-install}\n", "chart.yaml": templated}, true},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			dir, _ := files(t, tc.files)
			result := mustScan(t, knowledge, args([]string{dir}, "--from", "kubernetes=1.24.17", "--to", "kubernetes=1.25.5")...)
			report := result.Report
			if len(report.Gaps) == 0 || report.Verdict == scanreport.VerdictPass {
				t.Fatalf("no gap: %v", gapReasons(report))
			}
			if tc.blocked != (result.Exit == scanreport.ExitBlocked) || tc.blocked != (len(report.Findings) == 1) {
				t.Fatalf("exit %d findings %d gaps %v, want blocked %v", result.Exit, len(report.Findings), gapReasons(report), tc.blocked)
			}
			if !tc.blocked && result.Exit != scanreport.ExitUnknown {
				t.Fatalf("exit %d", result.Exit)
			}
		})
	}
}
