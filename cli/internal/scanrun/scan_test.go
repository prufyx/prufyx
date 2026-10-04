// SPDX-License-Identifier: AGPL-3.0-only

package scanrun

import (
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/cncfcheck"
	"github.com/prufyx/prufyx/cli/internal/cncfprepare"
	"github.com/prufyx/prufyx/cli/internal/constraintengine"
	"github.com/prufyx/prufyx/cli/internal/lineattest"
	"github.com/prufyx/prufyx/cli/internal/scanreport"
)

// TestScanQuickstartBlocked: the quickstart CronJob at batch/v1beta1 blocks
// the upgrade 1.24.17 -> 1.30.4 at the hop into 1.25, located at its file,
// document, kind and name; every other hop is covered.
func TestScanQuickstartBlocked(t *testing.T) {
	knowledge := newKnowledge(t, knowledgeOptions{lines: allLines, policy: "current"})
	dir, _ := files(t, map[string]string{"applyset.yaml": cronjobV1beta1})
	inDir(t, dir, func() {
		result := mustScan(t, knowledge, args([]string{"applyset.yaml"}, "--from", "kubernetes=1.24.17", "--to", "kubernetes=1.30.4")...)
		report := result.Report
		if result.Exit != scanreport.ExitBlocked || report.Verdict != scanreport.VerdictBlocked || len(report.Findings) != 1 {
			t.Fatalf("exit %d verdict %s findings %d", result.Exit, report.Verdict, len(report.Findings))
		}
		finding := report.Findings[0]
		if finding.RuleID != "kubernetes.cronjob-v1beta1-removed.1-24-0-to-1-25-0" || finding.Hop != (scanreport.HopRef{Index: 1, From: "1.24.17", To: "1.25"}) || len(finding.AlsoAt) != 0 {
			t.Fatalf("finding %+v", finding)
		}
		want := []scanreport.Location{{File: "applyset.yaml", Document: 0, Item: -1, Line: 1, Kind: "CronJob", Namespace: "default", Name: "nightly-report"}}
		if !reflect.DeepEqual(finding.Locations, want) {
			t.Fatalf("locations %+v", finding.Locations)
		}
		statuses := []string{}
		for _, hop := range report.Paths[0].Hops {
			statuses = append(statuses, hop.Status)
		}
		// The removed CronJob is also not on the served list of 1.30.
		if !reflect.DeepEqual(statuses, []string{"BLOCKED", "COVERED", "COVERED", "COVERED", "COVERED", "COVERED"}) || !reflect.DeepEqual(gapReasons(report), []string{"API_VERSION_NOT_REVIEWED"}) {
			t.Fatalf("hops %v gaps %v", statuses, gapReasons(report))
		}
		golden(t, "quickstart-blocked.txt", scanreport.Human(report, scanreport.HumanOptions{}))
		golden(t, "quickstart-blocked-verbose.txt", scanreport.Human(report, scanreport.HumanOptions{Verbose: true, ShowPasses: true}))
		golden(t, "quickstart-blocked.json", jsonOf(t, report))
	})
}

// TestScanQuickstartMigrated: with the CronJob at batch/v1 the answer is
// PASS FOR THE DECLARED SCOPE only when every line has a current review, and
// otherwise names exactly the lines that are not reviewed.
func TestScanQuickstartMigrated(t *testing.T) {
	dir, _ := files(t, map[string]string{"applyset.yaml": cronjobV1})
	run := func(knowledge Knowledge) Result {
		var result Result
		inDir(t, dir, func() {
			result = mustScan(t, knowledge, args([]string{"applyset.yaml"}, "--from", "kubernetes=1.24.17", "--to", "kubernetes=1.30.4")...)
		})
		return result
	}
	pass := run(newKnowledge(t, knowledgeOptions{lines: allLines, policy: "current"}))
	if pass.Exit != scanreport.ExitPass || pass.Report.Verdict != scanreport.VerdictPass || pass.Report.Headline != "PASS FOR THE DECLARED SCOPE" {
		t.Fatalf("all lines reviewed: exit %d gaps %v", pass.Exit, gapReasons(pass.Report))
	}
	golden(t, "quickstart-migrated-pass.txt", scanreport.Human(pass.Report, scanreport.HumanOptions{}))
	golden(t, "quickstart-migrated-pass.json", jsonOf(t, pass.Report))

	unknown := run(newKnowledge(t, knowledgeOptions{lines: without(allLines, "1.28", "1.30"), policy: "current"}))
	if unknown.Exit != scanreport.ExitUnknown || !reflect.DeepEqual(gapReasons(unknown.Report), []string{"LINE_NOT_ATTESTED 1.27->1.28", "LINE_NOT_ATTESTED 1.29->1.30.4"}) {
		t.Fatalf("unreviewed lines: exit %d gaps %v", unknown.Exit, gapReasons(unknown.Report))
	}
	if !strings.HasPrefix(unknown.Report.Headline, "NO BLOCKERS FOUND IN COVERED CHECKS: 2 areas") {
		t.Fatal(unknown.Report.Headline)
	}
	golden(t, "quickstart-migrated-unknown.txt", scanreport.Human(unknown.Report, scanreport.HumanOptions{}))

	embedded := run(nil)
	if embedded.Exit != scanreport.ExitUnknown || !reflect.DeepEqual(gapReasons(embedded.Report), []string{"API_VERSION_NOT_REVIEWED", "NO_REVIEWED_PATH_POLICY"}) {
		t.Fatalf("embedded knowledge: exit %d gaps %v", embedded.Exit, gapReasons(embedded.Report))
	}
}

// TestScanIntermediateLineCoverage: the only rule for 1.32 is reviewed for
// the exact pair 1.31.0 -> 1.32.0. On a hop whose ends are whole lines it
// cannot decide, whatever it says at 1.31.0 -> 1.32.0: its claim is
// downgraded, never a blocker and never a pass, even when a (malformed) line
// review lists it.
func TestScanIntermediateLineCoverage(t *testing.T) {
	removed := "apiVersion: flowcontrol.apiserver.k8s.io/v1beta3\nkind: FlowSchema\nmetadata: {name: limits}\n"
	served := "apiVersion: flowcontrol.apiserver.k8s.io/v1\nkind: FlowSchema\nmetadata: {name: limits}\n"
	lines := []string{"1.31", "1.32", "1.33"}
	// The review of 1.32 lists the anchor-only rule; the pack admission
	// would refuse it (the rule is not line-wide), so it is built unchecked.
	knowledge := newKnowledge(t, knowledgeOptions{lines: lines, policy: "current", unchecked: true})
	for name, manifest := range map[string]string{"removed": removed, "served": served} {
		t.Run(name, func(t *testing.T) {
			dir, _ := files(t, map[string]string{"apf.yaml": manifest})
			inDir(t, dir, func() {
				result := mustScan(t, knowledge, args([]string{"apf.yaml"}, "--from", "kubernetes=1.30.2", "--to", "kubernetes=1.33.1")...)
				report := result.Report
				if result.Exit != scanreport.ExitUnknown || len(report.Findings) != 0 {
					t.Fatalf("exit %d findings %d", result.Exit, len(report.Findings))
				}
				hop := report.Paths[0].Hops[1]
				if hop.From.Line != "1.31" || hop.To.Line != "1.32" || hop.Status != scanreport.HopPartial || !reflect.DeepEqual(hop.Reasons, []string{scanreport.ReasonIntermediateLineNotCovered}) {
					t.Fatalf("hop %+v", hop)
				}
				found := false
				for _, gap := range report.Gaps {
					found = found || gap.Reason == scanreport.ReasonIntermediateLineNotCovered && strings.Contains(gap.Detail, "flowcontrol-v1beta3-removed")
				}
				if !found {
					t.Fatalf("gaps %v", gapReasons(report))
				}
			})
		})
	}
	// The same rule decides the exact pair it was reviewed for.
	dir, _ := files(t, map[string]string{"apf.yaml": removed})
	inDir(t, dir, func() {
		result := mustScan(t, knowledge, args([]string{"apf.yaml"}, "--from", "kubernetes=1.31.0", "--to", "kubernetes=1.32.0")...)
		if result.Exit != scanreport.ExitBlocked {
			t.Fatalf("exact pair: exit %d", result.Exit)
		}
	})
}

// TestScanDowngrade: a downgrade is not planned and is a named gap.
func TestScanDowngrade(t *testing.T) {
	knowledge := newKnowledge(t, knowledgeOptions{lines: allLines, policy: "current"})
	_, paths := files(t, map[string]string{"applyset.yaml": cronjobV1})
	result := mustScan(t, knowledge, args(paths, "--from", "kubernetes=1.30.4", "--to", "kubernetes=1.29.1")...)
	if result.Exit != scanreport.ExitUnknown || !reflect.DeepEqual(gapReasons(result.Report), []string{"DOWNGRADE_NOT_REVIEWED"}) || result.Report.Paths[0].Gap != "DOWNGRADE_NOT_REVIEWED" || len(result.Report.Paths[0].Hops) != 0 {
		t.Fatalf("exit %d gaps %v", result.Exit, gapReasons(result.Report))
	}
}

// TestScanPassPreconditions: from a scan that passes, taking away any one
// precondition of a pass leaves the answer UNKNOWN, on a path with rules and
// on a path whose only line has none.
func TestScanPassPreconditions(t *testing.T) {
	type variant struct {
		knowledge knowledgeOptions
		files     map[string]string
		args      []string
		gap       string
	}
	bases := map[string]struct{ from, to string }{"rules on the path": {"1.24.17", "1.30.4"}, "quiet line only": {"1.29.6", "1.30.4"}}
	for baseName, base := range bases {
		full := knowledgeOptions{lines: allLines, policy: "current"}
		variants := map[string]variant{
			"baseline":                {full, nil, declared, ""},
			"scope not complete":      {full, nil, []string{"--distribution", "official_upstream", "--target-api-apply-required"}, "DECLARATION_MISSING"},
			"scope declared false":    {full, nil, []string{"--distribution", "official_upstream", "--resource-scope-complete=false", "--target-api-apply-required"}, "DECLARATION_MISSING"},
			"apply not required":      {full, nil, []string{"--distribution", "official_upstream", "--resource-scope-complete"}, "DECLARATION_MISSING"},
			"distribution not set":    {full, nil, []string{"--resource-scope-complete", "--target-api-apply-required"}, "DECLARATION_MISSING"},
			"custom build":            {full, nil, []string{"--distribution", "custom_build", "--resource-scope-complete", "--target-api-apply-required"}, "DISTRIBUTION_NOT_COVERED"},
			"one templated document":  {full, map[string]string{"chart.yaml": "apiVersion: v1\nkind: ConfigMap\nmetadata: {name: '{{ .Release.Name }}'}\n"}, declared, "DOCUMENTS_TEMPLATED"},
			"one unparseable file":    {full, map[string]string{"chart.yaml": "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: {{ .Release.Name }}\n"}, declared, "DOCUMENTS_TEMPLATED"},
			"one nested list":         {full, map[string]string{"list.yaml": "apiVersion: v1\nkind: List\nitems:\n- {apiVersion: v1, kind: List, items: [{apiVersion: batch/v1, kind: Job}]}\n"}, declared, "DOCUMENTS_NOT_EVALUATED"},
			"one unresolved list":     {full, map[string]string{"list.yaml": "apiVersion: v1\nkind: List\nitems: []\n"}, declared, "DOCUMENTS_NOT_EVALUATED"},
			"one values file":         {full, map[string]string{"values.yaml": "replicas: 2\n"}, declared, "DOCUMENTS_NOT_EVALUATED"},
			"one alpha API":           {full, map[string]string{"alpha.yaml": "apiVersion: resource.k8s.io/v1alpha3\nkind: DeviceClass\nmetadata: {name: gpu}\n"}, declared, "ALPHA_API_NOT_COVERED"},
			"stale line review":       {knowledgeOptions{lines: without(allLines, "1.30"), stale: []string{"1.30"}, policy: "current"}, nil, declared, "LINE_NOT_ATTESTED"},
			"missing line review":     {knowledgeOptions{lines: without(allLines, "1.30"), policy: "current"}, nil, declared, "LINE_NOT_ATTESTED"},
			"stale path policy":       {knowledgeOptions{lines: allLines, policy: "stale"}, nil, declared, "PATH_POLICY_NOT_CURRENT"},
			"no path policy":          {knowledgeOptions{lines: allLines}, nil, declared, "NO_REVIEWED_PATH_POLICY"},
			"another target":          {full, nil, append([]string{"--to", "etcd=3.6.0"}, declared...), "COMPONENT_NOT_COVERED"},
			"current version unknown": {full, nil, declared, "VERSION_NOT_DETECTED"},
		}
		if baseName == "quiet line only" {
			delete(variants, "no path policy") // one line: no policy is needed
		}
		for name, v := range variants {
			t.Run(baseName+"/"+name, func(t *testing.T) {
				contents := map[string]string{"applyset.yaml": cronjobV1}
				for file, content := range v.files {
					contents[file] = content
				}
				dir, _ := files(t, contents)
				command := append([]string{dir, "--now", testNow, "--to", "kubernetes=" + base.to}, v.args...)
				if name != "current version unknown" {
					command = append(command, "--from", "kubernetes="+base.from)
				}
				result := mustScan(t, newKnowledge(t, v.knowledge), command...)
				if v.gap == "" {
					if result.Exit != scanreport.ExitPass {
						t.Fatalf("baseline exit %d gaps %v", result.Exit, gapReasons(result.Report))
					}
					return
				}
				if result.Exit != scanreport.ExitUnknown || result.Report.Verdict != scanreport.VerdictUnknown {
					t.Fatalf("exit %d with %s removed", result.Exit, name)
				}
				found := false
				for _, gap := range result.Report.Gaps {
					found = found || gap.Reason == v.gap
				}
				if !found {
					t.Fatalf("gap %s not reported: %v", v.gap, gapReasons(result.Report))
				}
			})
		}
	}
}

// TestScanEngineInputDigestUnchanged: every hop evaluates exactly the engine
// input that the single-file preparation produces for the same documents at
// the hop's concrete versions, even when the documents come from several
// files.
func TestScanEngineInputDigestUnchanged(t *testing.T) {
	knowledge := newKnowledge(t, knowledgeOptions{lines: allLines, policy: "current"})
	first := "apiVersion: batch/v1beta1\nkind: CronJob\nmetadata: {name: a}\n"
	second := "apiVersion: autoscaling/v2beta2\nkind: HorizontalPodAutoscaler\nmetadata: {name: b}\n---\napiVersion: v1\nkind: ConfigMap\nmetadata: {name: c}\n"
	_, paths := files(t, map[string]string{"a.yaml": first, "b.yaml": second})
	single := []byte(first + "---\n" + second)
	for _, decl := range [][]string{declared, {"--distribution", "custom_build"}, {"--distribution", "official_upstream", "--target-api-apply-required"}} {
		command := append(append(append([]string{}, paths...), decl...), "--now", testNow, "--from", "kubernetes=1.24.17", "--to", "kubernetes=1.30.4")
		result := mustScan(t, knowledge, command...)
		hops := result.Report.Paths[0].Hops
		if len(hops) != 6 {
			t.Fatalf("hops %d", len(hops))
		}
		distribution, apply, complete := "", false, false
		for i, a := range decl {
			switch a {
			case "--distribution":
				distribution = decl[i+1]
			case "--target-api-apply-required":
				apply = true
			case "--resource-scope-complete":
				complete = true
			}
		}
		for _, hop := range hops {
			from, to := hop.From.Version, hop.To.Version
			if from == "" {
				from = hop.From.Line + ".0"
			}
			if to == "" {
				to = hop.To.Line + ".0"
			}
			prepared, err := cncfprepare.PrepareKubernetesRemovedAPIs(single, from, to, distribution, apply, complete)
			if err != nil {
				t.Fatal(err)
			}
			if hop.InputDigest != prepared.InputDigest {
				t.Fatalf("hop %d %s -> %s: scan %s, single file %s", hop.Index, from, to, hop.InputDigest, prepared.InputDigest)
			}
		}
	}
}

// TestScanLocations: the locations of a finding are exactly the documents
// at the removed version: two files, one of them a List item; a document at
// a served version is not listed.
func TestScanLocations(t *testing.T) {
	knowledge := newKnowledge(t, knowledgeOptions{lines: allLines, policy: "current"})
	dir, _ := files(t, map[string]string{
		"jobs/a.yaml": "apiVersion: batch/v1\nkind: CronJob\nmetadata: {name: served}\n---\napiVersion: batch/v1beta1\nkind: CronJob\nmetadata:\n  name: first\n  namespace: ops\n",
		"jobs/b.json": `{"apiVersion":"v1","kind":"List","items":[{"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":"c"}},` + "\n" + `{"apiVersion":"batch/v1beta1","kind":"CronJob","metadata":{"name":"second"}}]}`,
	})
	inDir(t, dir, func() {
		result := mustScan(t, knowledge, args([]string{"jobs"}, "--from", "kubernetes=1.24.17", "--to", "kubernetes=1.25.3")...)
		if len(result.Report.Findings) != 1 {
			t.Fatalf("findings %+v", result.Report.Findings)
		}
		want := []scanreport.Location{
			{File: "jobs/a.yaml", Document: 1, Item: -1, Line: 5, Kind: "CronJob", Namespace: "ops", Name: "first"},
			{File: "jobs/b.json", Document: 0, Item: 1, Line: 2, Kind: "CronJob", Name: "second"},
		}
		if got := result.Report.Findings[0].Locations; !reflect.DeepEqual(got, want) {
			t.Fatalf("locations %+v", got)
		}
	})
}

// TestScanRedact: with --redact no display path, object name or namespace
// appears anywhere in the human or JSON output.
func TestScanRedact(t *testing.T) {
	knowledge := newKnowledge(t, knowledgeOptions{lines: allLines, policy: "current"})
	private := strings.ReplaceAll(strings.ReplaceAll(cronjobV1beta1, "nightly-report", "zz-private-name"), "default", "zz-private-ns")
	secrets := []string{"secret-dir", "reports.yaml", "chart.yaml", "zz-private-name", "zz-private-ns"}
	check := func(result Result) {
		t.Helper()
		for _, output := range [][]byte{jsonOf(t, result.Report), scanreport.Human(result.Report, scanreport.HumanOptions{Verbose: true, ShowPasses: true})} {
			for _, secret := range secrets {
				if strings.Contains(string(output), secret) {
					t.Fatalf("redacted output contains %q:\n%s", secret, output)
				}
			}
		}
	}
	dir, _ := files(t, map[string]string{"secret-dir/reports.yaml": private})
	inDir(t, dir, func() {
		result := mustScan(t, knowledge, args([]string{"secret-dir"}, "--from", "kubernetes=1.24.17", "--to", "kubernetes=1.30.4", "--redact")...)
		if result.Exit != scanreport.ExitBlocked || len(result.Report.Findings[0].Locations) != 1 {
			t.Fatalf("exit %d", result.Exit)
		}
		check(result)
		location := result.Report.Findings[0].Locations[0]
		if location.File != scanreport.RedactValue("secret-dir/reports.yaml") || location.Name != scanreport.RedactValue("zz-private-name") || location.Namespace != scanreport.RedactValue("zz-private-ns") {
			t.Fatalf("location %+v", location)
		}
		human := string(scanreport.Human(result.Report, scanreport.HumanOptions{}))
		if !strings.Contains(human, location.File[:19]+":1  CronJob "+location.Namespace[:19]+"/"+location.Name[:19]) {
			t.Fatalf("human output does not show digest prefixes:\n%s", human)
		}
	})
	// Omitted files are redacted too.
	dir, _ = files(t, map[string]string{"secret-dir/reports.yaml": private, "secret-dir/chart.yaml": "apiVersion: v1\nkind: ConfigMap\nmetadata: {name: '{{ x }}'}\n"})
	inDir(t, dir, func() {
		result := mustScan(t, knowledge, args([]string{"secret-dir"}, "--from", "kubernetes=1.24.17", "--to", "kubernetes=1.30.4", "--redact")...)
		if len(result.Report.Omitted) != 1 || result.Report.Omitted[0].File != scanreport.RedactValue("secret-dir/chart.yaml") {
			t.Fatalf("omitted %+v", result.Report.Omitted)
		}
		check(result)
		// A refused input names no path under --redact.
		if err := os.Chmod("secret-dir/reports.yaml", 0o664); err != nil {
			t.Fatal(err)
		}
		_, err := scan(t, knowledge, args([]string{"secret-dir"}, "--from", "kubernetes=1.24.17", "--to", "kubernetes=1.30.4", "--redact")...)
		if !isUsage(err) {
			t.Fatalf("error %v", err)
		}
		for _, secret := range secrets {
			if strings.Contains(err.Error(), secret) {
				t.Fatalf("error names %q: %v", secret, err)
			}
		}
	})
}

// TestScanDeterministic: two runs are byte-identical, and the order of the
// paths on the command line does not change the output.
func TestScanDeterministic(t *testing.T) {
	knowledge := newKnowledge(t, knowledgeOptions{lines: without(allLines, "1.28"), policy: "current"})
	dir, _ := files(t, map[string]string{
		"b.yaml": cronjobV1beta1,
		"a.yaml": "apiVersion: autoscaling/v2beta2\nkind: HorizontalPodAutoscaler\nmetadata: {name: web}\n",
		"c.yaml": "apiVersion: policy/v1beta1\nkind: PodDisruptionBudget\nmetadata: {name: pdb}\n",
	})
	inDir(t, dir, func() {
		var outputs []string
		for _, order := range [][]string{{"a.yaml", "b.yaml", "c.yaml"}, {"c.yaml", "a.yaml", "b.yaml"}, {"b.yaml", "c.yaml", "a.yaml"}, {"a.yaml", "b.yaml", "c.yaml"}} {
			result := mustScan(t, knowledge, args(order, "--from", "kubernetes=1.24.17", "--to", "kubernetes=1.30.4")...)
			outputs = append(outputs, string(jsonOf(t, result.Report))+string(scanreport.Human(result.Report, scanreport.HumanOptions{Verbose: true, ShowPasses: true})))
		}
		for _, output := range outputs[1:] {
			if output != outputs[0] {
				t.Fatalf("output differs:\n%s\n---\n%s", outputs[0], output)
			}
		}
		result := mustScan(t, knowledge, args([]string{"a.yaml", "b.yaml", "c.yaml"}, "--from", "kubernetes=1.24.17", "--to", "kubernetes=1.30.4")...)
		var order []string
		for _, finding := range result.Report.Findings {
			order = append(order, finding.Hop.To+" "+finding.RuleID)
		}
		want := []string{
			"1.25 kubernetes.cronjob-v1beta1-removed.1-24-0-to-1-25-0",
			"1.25 kubernetes.pdb-v1beta1-removed.1-24-0-to-1-25-0",
			"1.26 kubernetes.hpa-v2beta2-removed.1-25-0-to-1-26-0",
		}
		if !reflect.DeepEqual(order, want) {
			t.Fatalf("findings out of order: %q", order)
		}
	})
}

// TestScanPermissions: by default a file other users can read is accepted
// with a notice and one they can write is refused; strict refuses both.
func TestScanPermissions(t *testing.T) {
	knowledge := newKnowledge(t, knowledgeOptions{lines: allLines, policy: "current"})
	dir, paths := files(t, map[string]string{"applyset.yaml": cronjobV1})
	command := args(paths, "--from", "kubernetes=1.24.17", "--to", "kubernetes=1.30.4")
	if err := os.Chmod(paths[0], 0o644); err != nil {
		t.Fatal(err)
	}
	result := mustScan(t, knowledge, command...)
	if result.Exit != scanreport.ExitPass || !reflect.DeepEqual(result.Report.Notes, []string{"note: 1 input file is readable by other users; use --input-permissions strict to refuse them"}) {
		t.Fatalf("0644: exit %d notes %v", result.Exit, result.Report.Notes)
	}
	if _, err := scan(t, knowledge, append(command, "--input-permissions", "strict")...); !isUsage(err) || !strings.Contains(err.Error(), "INPUT NOT ACCEPTED") {
		t.Fatalf("strict 0644: %v", err)
	}
	if err := os.Chmod(paths[0], 0o664); err != nil {
		t.Fatal(err)
	}
	if _, err := scan(t, knowledge, command...); !isUsage(err) || !strings.Contains(err.Error(), "writable") {
		t.Fatalf("0664: %v", err)
	}
	if err := os.Chmod(paths[0], 0o600); err != nil {
		t.Fatal(err)
	}
	result = mustScan(t, knowledge, append(command, "--input-permissions", "strict")...)
	if result.Exit != scanreport.ExitPass || len(result.Report.Notes) != 0 {
		t.Fatalf("strict 0600: exit %d notes %v", result.Exit, result.Report.Notes)
	}
	// Standard input has no mode: the policy does not apply to it.
	request, err := ParseArgs(append([]string{"-"}, args(nil, "--from", "kubernetes=1.24.17", "--to", "kubernetes=1.30.4", "--input-permissions", "strict")...))
	if err != nil {
		t.Fatal(err)
	}
	inDir(t, dir, func() {
		stdin, err := Run(request, Options{Knowledge: knowledge, Build: &testBuild, Stdin: strings.NewReader(cronjobV1)})
		if err != nil || stdin.Exit != scanreport.ExitPass {
			t.Fatalf("stdin: %v %d", err, stdin.Exit)
		}
	})
}

// TestScanSlugs: an unknown component is refused with at most three
// suggestions; a known component scan does not evaluate is a named gap.
func TestScanSlugs(t *testing.T) {
	knowledge := newKnowledge(t, knowledgeOptions{lines: allLines, policy: "current"})
	_, paths := files(t, map[string]string{"applyset.yaml": cronjobV1})
	_, err := scan(t, knowledge, args(paths, "--from", "kubernetes=1.24.17", "--to", "kubernets=1.30.4")...)
	if !isUsage(err) {
		t.Fatalf("unknown slug: %v", err)
	}
	message := err.Error()
	_, list, _ := strings.Cut(message, "closest: ")
	suggestions := strings.Split(list, ", ")
	if len(suggestions) == 0 || len(suggestions) > 3 || suggestions[0] != "kubernetes" {
		t.Fatalf("suggestions %q", message)
	}
	if _, err2 := scan(t, knowledge, args(paths, "--to", "kubernets=1.30.4")...); err2 == nil || err2.Error() != message {
		t.Fatalf("suggestions are not deterministic: %v", err2)
	}
	result := mustScan(t, knowledge, args(paths, "--from", "etcd=3.5.17", "--to", "etcd=3.6.0")...)
	if result.Exit != scanreport.ExitUnknown || !reflect.DeepEqual(gapReasons(result.Report), []string{"COMPONENT_NOT_COVERED"}) || !strings.Contains(result.Report.Gaps[0].Action, "check cncf --project etcd") {
		t.Fatalf("other component: exit %d gaps %+v", result.Exit, result.Report.Gaps)
	}
	if _, err := scan(t, knowledge, args(paths, "--from", "kubernetes=1.24.17")...); !isUsage(err) {
		t.Fatalf("no target: %v", err)
	}
	if _, err := scan(t, knowledge, args(paths, "--to", "kubernetes=v1.30.4")...); !isUsage(err) {
		t.Fatalf("bad version: %v", err)
	}
}

// TestScanConfigFile: prufyx.yaml supplies inputs, versions and
// declarations; it is not evaluated as a manifest; flags override it.
func TestScanConfigFile(t *testing.T) {
	knowledge := newKnowledge(t, knowledgeOptions{lines: allLines, policy: "current"})
	config := "apiVersion: prufyx.io/v1alpha1\nkind: ScanConfig\ninputs: [rendered/]\ncurrent: {kubernetes: 1.24.17}\ntarget: {kubernetes: 1.30.4}\ndeclarations:\n  kubernetes:\n    distribution: official_upstream\n    resourceScopeComplete: true\n    targetApplyRequired: true\n"
	dir, _ := files(t, map[string]string{"prufyx.yaml": config, "rendered/applyset.yaml": cronjobV1, "rendered/prufyx.yaml": config})
	inDir(t, dir, func() {
		result := mustScan(t, knowledge, "--now", testNow)
		if result.Exit != scanreport.ExitPass || result.Report.Provenance.ConfigDigest == "" {
			t.Fatalf("config: exit %d gaps %v", result.Exit, gapReasons(result.Report))
		}
		if len(result.Report.Omitted) != 1 || result.Report.Omitted[0].Reason != "CONFIG_DOCUMENT" || result.Report.Summary.DocumentsRead != 2 {
			t.Fatalf("omitted %+v read %d", result.Report.Omitted, result.Report.Summary.DocumentsRead)
		}
		if result.Report.Inventory[0].TargetSource != "file" {
			t.Fatalf("inventory %+v", result.Report.Inventory)
		}
		flagged := mustScan(t, knowledge, "--now", testNow, "--resource-scope-complete=false")
		if flagged.Exit != scanreport.ExitUnknown {
			t.Fatalf("flag override: exit %d", flagged.Exit)
		}
		other := mustScan(t, knowledge, "--now", testNow, "--config", "prufyx.yaml", "--to", "kubernetes=1.25.3")
		if other.Report.Paths[0].To != "1.25.3" || other.Report.Inventory[0].TargetSource != "flag" {
			t.Fatalf("flag target: %+v", other.Report.Paths)
		}
	})
}

// TestScanUsage: malformed command lines are refused before anything is read.
func TestScanUsage(t *testing.T) {
	for _, command := range [][]string{
		{"--to"}, {"--to", "kubernetes"}, {"--to", "=1.2.3"}, {"--format", "sarif"}, {"--now", "2026-10-04T00:00:00+02:00"},
		{"--now", "2026-10-04T00:00:00.5Z"}, {"--input-permissions", "loose"}, {"--distribution", "eks"}, {"--bogus"},
		{"--knowledge-db", "dir"}, {"-", "-"}, {"--to", "kubernetes=1.2.3", "--to", "kubernetes=1.2.4"}, {"--redact=maybe"},
		{"--format", "json", "--format", "human"},
	} {
		if _, err := ParseArgs(command); !isUsage(err) {
			t.Fatalf("%q accepted: %v", command, err)
		}
	}
	request, err := ParseArgs([]string{"a", "--to=kubernetes=1.30.4", "b", "--", "--c", "-"})
	if err != nil || !reflect.DeepEqual(request.Paths, []string{"a", "b", "--c", "-"}) || request.To["kubernetes"] != "1.30.4" || request.Format != "human" {
		t.Fatalf("request %+v %v", request, err)
	}
	if _, err := ParseArgs([]string{"--knowledge-db", "x"}); err == nil || !strings.Contains(err.Error(), "embedded") {
		t.Fatalf("knowledge-db: %v", err)
	}
}

// TestScanDefaultNow: without --now the scan uses the clock, truncated to
// the second, and prints it as the evaluation instant.
func TestScanDefaultNow(t *testing.T) {
	knowledge := newKnowledge(t, knowledgeOptions{lines: allLines, policy: "current"})
	_, paths := files(t, map[string]string{"applyset.yaml": cronjobV1})
	request, err := ParseArgs(append(append([]string{}, paths...), append(declared, "--from", "kubernetes=1.24.17", "--to", "kubernetes=1.30.4")...))
	if err != nil {
		t.Fatal(err)
	}
	clock := func() time.Time { return time.Date(2026, 10, 4, 12, 30, 15, 999, time.UTC) }
	result, err := Run(request, Options{Knowledge: knowledge, Build: &testBuild, Clock: clock})
	if err != nil || result.Report.Provenance.EvaluatedAt != "2026-10-04T12:30:15Z" || !strings.Contains(string(scanreport.Human(result.Report, scanreport.HumanOptions{})), "evaluated at 2026-10-04T12:30:15Z") {
		t.Fatalf("%v %+v", err, result.Report.Provenance)
	}
}

// TestScanOmissionsExplainHops: when an omitted document leaves the apply set
// unresolved, the hops name the omission's gap, and no other cause is
// invented.
func TestScanOmissionsExplainHops(t *testing.T) {
	knowledge := newKnowledge(t, knowledgeOptions{lines: allLines, policy: "current"})
	dir, _ := files(t, map[string]string{"applyset.yaml": cronjobV1beta1, "values.yaml": "replicas: 2\n"})
	result := mustScan(t, knowledge, args([]string{dir}, "--from", "kubernetes=1.24.17", "--to", "kubernetes=1.30.4")...)
	if result.Exit != scanreport.ExitUnknown || !reflect.DeepEqual(gapReasons(result.Report), []string{"API_VERSION_NOT_REVIEWED", "DOCUMENTS_NOT_EVALUATED"}) {
		t.Fatalf("exit %d gaps %v", result.Exit, gapReasons(result.Report))
	}
	if !strings.Contains(result.Report.Gaps[1].Detail, "1 document(s) are not Kubernetes objects") {
		t.Fatalf("detail %q", result.Report.Gaps[1].Detail)
	}
	hop := result.Report.Paths[0].Hops[0]
	if hop.Status != scanreport.HopPartial || !reflect.DeepEqual(hop.Reasons, []string{"DOCUMENTS_NOT_EVALUATED"}) {
		t.Fatalf("hop %+v", hop)
	}
}

// TestFindingAttribution: a rule that blocks at several hops is reported
// once, at the first, with the later hops (and the whole upgrade) in alsoAt.
func TestFindingAttribution(t *testing.T) {
	report := &scanreport.Report{}
	run := &kubernetesRun{report: report, findings: map[string]int{}}
	rule := cncfcheck.ScanRule{Scope: lineattest.RuleScope{ID: "r"}, Description: "Title. More.", NextAction: "fix"}
	first, second := scanreport.HopRef{Index: 1, From: "1.24.0", To: "1.25"}, scanreport.HopRef{Index: 3, From: "1.26", To: "1.27"}
	whole := scanreport.HopRef{From: "1.24.0", To: "1.30.0", WholeUpgrade: true}
	for _, ref := range []scanreport.HopRef{first, second, second, whole} {
		run.finding(rule, constraintengine.Claim{RuleID: "r"}, evaluation{}, ref)
	}
	if len(report.Findings) != 1 || report.Findings[0].Hop != first || !reflect.DeepEqual(report.Findings[0].AlsoAt, []scanreport.HopRef{second, whole}) || report.Findings[0].Title != "Title" {
		t.Fatalf("findings %+v", report.Findings)
	}
}

// TestScanInconsistentLineReview: a line review that lists a rule which does
// not apply to the hop, or leaves out a rule of the line that does, never
// covers the hop.
func TestScanInconsistentLineReview(t *testing.T) {
	_, paths := files(t, map[string]string{"applyset.yaml": cronjobV1})
	extra := newKnowledge(t, knowledgeOptions{lines: allLines, policy: "current", unchecked: true,
		extraRuleIDs: map[string][]string{"1.30": {"kubernetes.cronjob-v1beta1-removed.1-24-0-to-1-25-0"}}})
	result := mustScan(t, extra, args(paths, "--from", "kubernetes=1.29.6", "--to", "kubernetes=1.30.4")...)
	if result.Exit != scanreport.ExitUnknown || result.Report.Paths[0].Hops[0].Status != scanreport.HopPartial || !reflect.DeepEqual(gapReasons(result.Report), []string{"LINE_NOT_ATTESTED 1.29.6->1.30.4"}) || !strings.Contains(result.Report.Gaps[0].Detail, "lists rule") {
		t.Fatalf("listed rule: exit %d gaps %+v", result.Exit, result.Report.Gaps)
	}
	dropped := newKnowledge(t, knowledgeOptions{lines: allLines, policy: "current", unchecked: true,
		dropRuleIDs: map[string][]string{"1.25": {"kubernetes.cronjob-v1beta1-removed.1-24-0-to-1-25-0"}}})
	result = mustScan(t, dropped, args(paths, "--from", "kubernetes=1.24.17", "--to", "kubernetes=1.25.3")...)
	if result.Exit != scanreport.ExitUnknown || result.Report.Paths[0].Hops[0].Status != scanreport.HopPartial || !reflect.DeepEqual(gapReasons(result.Report), []string{"LINE_NOT_ATTESTED 1.24.17->1.25.3"}) || !strings.Contains(result.Report.Gaps[0].Detail, "does not list it") {
		t.Fatalf("unlisted rule: exit %d gaps %+v", result.Exit, result.Report.Gaps)
	}
}

// TestScanHopShape: line reviews cover a hop from the line before; a direct
// hop that skips lines, or a patch upgrade within one line, is not covered by
// them, whatever policy planned it.
func TestScanHopShape(t *testing.T) {
	_, paths := files(t, map[string]string{"applyset.yaml": cronjobV1})
	direct := newKnowledge(t, knowledgeOptions{lines: allLines, policy: "direct"})
	result := mustScan(t, direct, args(paths, "--from", "kubernetes=1.24.17", "--to", "kubernetes=1.30.4")...)
	if result.Exit != scanreport.ExitUnknown || !reflect.DeepEqual(gapReasons(result.Report), []string{"LINE_NOT_ATTESTED 1.24.17->1.30.4"}) || result.Report.Paths[0].Policy != "direct" {
		t.Fatalf("direct policy: exit %d gaps %v", result.Exit, gapReasons(result.Report))
	}
	sequential := newKnowledge(t, knowledgeOptions{lines: allLines, policy: "current"})
	result = mustScan(t, sequential, args(paths, "--from", "kubernetes=1.30.1", "--to", "kubernetes=1.30.4")...)
	if result.Exit != scanreport.ExitUnknown || !reflect.DeepEqual(gapReasons(result.Report), []string{"LINE_NOT_ATTESTED 1.30.1->1.30.4"}) || !strings.Contains(result.Report.Gaps[0].Detail, "within kubernetes 1.30") {
		t.Fatalf("same line: exit %d gaps %+v", result.Exit, result.Report.Gaps)
	}
}

// TestScanRuleNeedsOtherEvidence: a rule that applies to a hop but reads
// evidence scan does not collect (the 1.24 dockershim rule) leaves the hop
// undecided even when the line review lists no removed-API rule.
func TestScanRuleNeedsOtherEvidence(t *testing.T) {
	_, paths := files(t, map[string]string{"applyset.yaml": cronjobV1})
	knowledge := newKnowledge(t, knowledgeOptions{lines: []string{"1.24"}, policy: "current"})
	result := mustScan(t, knowledge, args(paths, "--from", "kubernetes=1.23.17", "--to", "kubernetes=1.24.0")...)
	if result.Exit != scanreport.ExitUnknown || !reflect.DeepEqual(gapReasons(result.Report), []string{"RULE_NOT_DECIDED 1.23.17->1.24.0"}) || !strings.Contains(result.Report.Gaps[0].Detail, "dockershim") {
		t.Fatalf("exit %d gaps %+v", result.Exit, result.Report.Gaps)
	}
}

// TestScanUnreviewedAPIVersion: a version of a reviewed kind that no
// reviewed removal names keeps the hop's rule undecided.
func TestScanUnreviewedAPIVersion(t *testing.T) {
	_, paths := files(t, map[string]string{"applyset.yaml": "apiVersion: autoscaling/v2beta3\nkind: HorizontalPodAutoscaler\nmetadata: {name: web}\n"})
	knowledge := newKnowledge(t, knowledgeOptions{lines: allLines, policy: "current"})
	result := mustScan(t, knowledge, args(paths, "--from", "kubernetes=1.24.17", "--to", "kubernetes=1.25.3")...)
	if result.Exit != scanreport.ExitUnknown || !reflect.DeepEqual(gapReasons(result.Report), []string{"API_VERSION_NOT_REVIEWED", "API_VERSION_NOT_REVIEWED"}) {
		t.Fatalf("exit %d gaps %v", result.Exit, gapReasons(result.Report))
	}
	hop := result.Report.Paths[0].Hops[0]
	if hop.Status != scanreport.HopPartial || !reflect.DeepEqual(hop.Reasons, []string{"API_VERSION_NOT_REVIEWED"}) {
		t.Fatalf("hop %+v", hop)
	}
}

// TestScanEmptyInput: no manifest at all is never a pass, even on a line
// with no rule.
func TestScanEmptyInput(t *testing.T) {
	knowledge := newKnowledge(t, knowledgeOptions{lines: allLines, policy: "current"})
	for _, from := range []string{"1.29.6", "1.24.17"} {
		_, paths := files(t, map[string]string{"empty.yaml": "# nothing rendered\n---\n"})
		result := mustScan(t, knowledge, args(paths, "--from", "kubernetes="+from, "--to", "kubernetes=1.30.4")...)
		if result.Exit != scanreport.ExitUnknown || !reflect.DeepEqual(gapReasons(result.Report), []string{"DOCUMENTS_NOT_EVALUATED"}) || !strings.Contains(result.Report.Gaps[0].Detail, "no Kubernetes manifests") {
			t.Fatalf("from %s: exit %d gaps %+v", from, result.Exit, result.Report.Gaps)
		}
	}
}

// TestJudgeClaims: every claim result other than PASS, BLOCKED and a rule
// that does not apply leaves the rule undecided with a named gap.
func TestJudgeClaims(t *testing.T) {
	rule := cncfcheck.ScanRule{Scope: lineattest.RuleScope{ID: "r"}, Description: "Title.", NextAction: "fix"}
	ref := scanreport.HopRef{Index: 1, From: "1.24.0", To: "1.25"}
	cases := []struct {
		status, reason, freshness string
		decided                   bool
		gap                       string
	}{
		{"PASS", "REVIEWED_SOURCE_CONSTRAINT", "current", true, ""},
		{"BLOCKED", "REVIEWED_SOURCE_CONSTRAINT", "current", true, ""},
		{"UNKNOWN", "RULE_APPLICABILITY_NOT_MATCHED", "current", true, ""},
		{"UNKNOWN", "RULE_EVIDENCE_STALE", "stale", false, "EVIDENCE_EXPIRED"},
		{"UNKNOWN", "RULE_EVIDENCE_WITHDRAWN", "withdrawn", false, "EVIDENCE_EXPIRED"},
		{"UNKNOWN", "RULE_EVIDENCE_CLOCK_BEFORE_REVIEW", "clock_before_review", false, "EVIDENCE_EXPIRED"},
		{"UNKNOWN", "RULE_OPERATOR_UNSUPPORTED", "current", false, "RULE_NOT_DECIDED"},
		{"UNKNOWN", "RULE_DEPENDENCY_COMPONENT_MISSING", "current", false, "RULE_NOT_DECIDED"},
		{"UNKNOWN", "SOMETHING_NEW", "current", false, "RULE_NOT_DECIDED"},
		{"UNKNOWN", "REVIEWED_SOURCE_CONSTRAINT", "current", false, "RULE_NOT_DECIDED"},
		{"NOTICE", "REVIEWED_SOURCE_CONSTRAINT", "current", false, "RULE_NOT_DECIDED"},
	}
	for _, tc := range cases {
		report := &scanreport.Report{}
		run := &kubernetesRun{report: report, findings: map[string]int{}, passes: map[string]bool{}}
		claim := constraintengine.Claim{RuleID: "r", Status: tc.status, ReasonCode: tc.reason, EvidenceFreshness: tc.freshness}
		judged := run.judge(rule, evaluation{claims: map[string]constraintengine.Claim{"r": claim}}, ref)
		gap := ""
		if len(report.Gaps) == 1 {
			gap = report.Gaps[0].Reason
		}
		if judged.decided != tc.decided || gap != tc.gap || len(report.Gaps) > 1 || (tc.gap != "" && !reflect.DeepEqual(judged.reasons, []string{tc.gap})) {
			t.Errorf("%s %s: decided %t gaps %+v", tc.status, tc.reason, judged.decided, report.Gaps)
		}
	}
}
