// SPDX-License-Identifier: AGPL-3.0-only

package scanreport

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/constraintengine"
	"github.com/prufyx/prufyx/cli/internal/goldenfile"
)

var update = flag.Bool("update", false, "rewrite the golden files")

// scanrunData holds the JSON reports that the scan command tests pin; the
// renderers must work from the JSON alone.
const scanrunData = "../scanrun/testdata"

func loadReport(t testing.TB, name string) Report {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(scanrunData, name))
	if err != nil {
		t.Fatal(err)
	}
	report, err := DecodeJSON(raw)
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return report
}

func citation(id string, start int) constraintengine.SourceEvidence {
	return constraintengine.SourceEvidence{
		ID: id, URL: "https://example.test/blob/0123456789abcdef0123456789abcdef01234567/doc.md",
		Revision: "0123456789abcdef0123456789abcdef01234567", ContentDigest: "sha256:" + strings.Repeat("a", 64),
		StartLine: start, EndLine: start + 3,
	}
}

// fullReport has every part of the report: several kinds of finding with a
// shared source and more than five locations, gaps, an established and an
// unestablished notice, a lead, an unsupported combination and a trust policy.
func fullReport() Report {
	hop1 := HopRef{Index: 1, From: "1.24.17", To: "1.25"}
	hop2 := HopRef{Index: 2, From: "1.25", To: "1.26"}
	whole := HopRef{From: "1.24.17", To: "1.30.4", WholeUpgrade: true}
	var many []Location
	for i := 0; i < 7; i++ {
		many = append(many, Location{File: "deploy/app " + strconv.Itoa(i) + ".yaml", Document: i, Item: -1, Line: 1 + i, Kind: "CronJob", Namespace: "prod", Name: "job-" + strconv.Itoa(i)})
	}
	report := Report{
		Inventory: []Component{{Name: "kubernetes", Component: "pkg:github/kubernetes/kubernetes", Current: "1.24.17", Target: "1.30.4", Covered: true}},
		Paths: []Path{{Component: "kubernetes", From: "1.24.17", To: "1.30.4", Policy: "sequential_minor", Hops: []Hop{
			{Index: 1, From: Endpoint{Version: "1.24.17"}, To: Endpoint{Line: "1.25"}, Status: HopBlocked},
			{Index: 2, From: Endpoint{Line: "1.25"}, To: Endpoint{Line: "1.26"}, Status: HopPartial, Reasons: []string{"RULE_NOT_DECIDED"}},
		}}},
		Findings: []Finding{
			{RuleID: "kubernetes.cronjob-removed", Component: "kubernetes", Hop: hop1, AlsoAt: []HopRef{hop2}, Title: "Kubernetes 1.25 stops serving CronJob through batch/v1beta1",
				Fix: "Migrate the manifest to batch/v1.", Match: "anchor", Locations: many, Basis: "mechanical", Extractor: "x.y",
				Citations: []constraintengine.SourceEvidence{citation("a", 87), citation("shared", 189)}, RuleDigest: "sha256:" + strings.Repeat("b", 64)},
			{RuleID: "kubernetes.psp-removed", Component: "kubernetes", Hop: hop1, Title: "PodSecurityPolicy | is removed", Fix: "Use Pod Security Admission.", Match: "range",
				Locations: []Location{{File: "psp.yaml", Document: 0, Item: 2, Kind: "PodSecurityPolicy", Name: "restricted"}},
				Basis:     "consensus", Citations: []constraintengine.SourceEvidence{citation("shared", 189)}, RuleDigest: "sha256:" + strings.Repeat("c", 64)},
			{RuleID: "kubernetes.whole", Component: "kubernetes", Hop: whole, Title: "Whole upgrade rule", Fix: "Do the thing.", Match: "anchor",
				Locations: []Location{{File: "w.yaml", Document: 0, Item: -1, Line: 3, Kind: "Thing", Name: ""}}, Basis: "reviewed", Citations: []constraintengine.SourceEvidence{citation("w", 5)}, RuleDigest: "sha256:" + strings.Repeat("d", 64)},
		},
		Gaps: []Gap{
			NewGap("kubernetes", nil, GapDeclarationScope, "kubernetes"),
			NewGap("kubernetes", &hop2, GapRuleNotDecided, "kubernetes.x", "STALE"),
			NewGap("etcd", nil, GapComponentNotCovered, "etcd"),
		},
		Notices: []Notice{
			{RuleID: "kubernetes.notice-a", Component: "kubernetes", Hop: hop2, Established: true, Text: "Back up etcd first.", Basis: "reviewed", Citations: []constraintengine.SourceEvidence{citation("n", 9)}},
			{RuleID: "kubernetes.notice-b", Component: "kubernetes", Hop: hop2, Established: false, Reason: "NO_DATA", Text: "Run the check by hand.", Basis: "reviewed", Citations: []constraintengine.SourceEvidence{}},
		},
		Leads:       []Lead{{RuleID: "kubernetes.lead-a", Component: "kubernetes", Hop: hop1, Text: "Look at the ingress class.", Citations: []constraintengine.SourceEvidence{citation("l", 1)}}},
		Unsupported: []Unsupported{{RuleID: "kubernetes.support-a", Component: "kubernetes", Hop: hop2, Reason: "node skew over 3 minor versions", Fix: "Upgrade nodes first.", Basis: "reviewed", Citations: []constraintengine.SourceEvidence{citation("s", 40)}}},
		TrustPolicy: &TrustPolicy{RequiredBasis: []string{"reviewed", "mechanical"}, ExcludedRules: 2, ExcludedLeadRules: 1},
		Omitted:     []Omitted{{File: "t.yaml", Document: 0, Item: -1, Reason: "TEMPLATED"}},
		Omissions:   []string{OmissionNodeSkew},
		Notes:       []string{PermissionNote(1)},
		Passes:      []Pass{{RuleID: "kubernetes.ok", Component: "kubernetes", Hop: hop2}},
		Provenance: Provenance{
			EvaluatedAt: "2026-10-04T00:00:00Z", InputDigest: "sha256:" + strings.Repeat("1", 64), ConfigDigest: "sha256:" + strings.Repeat("2", 64),
			KnowledgeOrigin: "embedded", KnowledgeRevision: "rev-1", KnowledgeDigest: "sha256:" + strings.Repeat("3", 64),
			EngineContractDigest: "sha256:" + strings.Repeat("4", 64),
		},
	}
	report.Provenance.Build.Version = "1.2.3"
	report.Summary.DocumentsRead = 9
	Finalize(&report)
	return report
}

type fixture struct {
	name   string
	report Report
}

func fixtures(t testing.TB) []fixture {
	return []fixture{
		{"blocked", loadReport(t, "quickstart-blocked.json")},
		{"unknown", loadReport(t, "rich-unknown.json")},
		{"pass", loadReport(t, "quickstart-migrated-pass.json")},
		{"full", fullReport()},
	}
}

func golden(t *testing.T, name string, got []byte) {
	t.Helper()
	goldenfile.Check(t, filepath.Join("testdata", name), got, *update, " (run with -update to rewrite it)")
}

func must(t testing.TB, raw []byte, err error) []byte {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// TestSARIFGolden: SARIF for the blocked, unknown, pass and full reports.
func TestSARIFGolden(t *testing.T) {
	for _, f := range fixtures(t) {
		raw, err := SARIF(f.report)
		golden(t, "sarif-"+f.name+".json", must(t, raw, err))
	}
}

// TestMarkdownGolden: Markdown for the same reports, plain and with the
// optional sections.
func TestMarkdownGolden(t *testing.T) {
	for _, f := range fixtures(t) {
		golden(t, "markdown-"+f.name+".md", Markdown(f.report, MarkdownOptions{}))
	}
	golden(t, "markdown-full-verbose.md", Markdown(fullReport(), MarkdownOptions{ShowPasses: true, Verbose: true}))
}

// TestRenderPureFunctionOfJSON: a report decoded from its own JSON renders
// to the same bytes in every format, and rendering never changes the report.
func TestRenderPureFunctionOfJSON(t *testing.T) {
	for _, f := range fixtures(t) {
		raw, err := MarshalJSON(f.report)
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := DecodeJSON(raw)
		if err != nil {
			t.Fatal(err)
		}
		for _, format := range Formats() {
			options := RenderOptions{ShowPasses: true, Verbose: true}
			a, err := Render(f.report, format, options)
			if err != nil {
				t.Fatal(err)
			}
			b, _ := Render(decoded, format, options)
			c, _ := Render(f.report, format, options)
			if !bytes.Equal(a, b) || !bytes.Equal(a, c) {
				t.Errorf("%s/%s: not a pure function of the JSON report", f.name, format)
			}
			if len(a) == 0 || a[len(a)-1] != '\n' {
				t.Errorf("%s/%s: no trailing newline", f.name, format)
			}
		}
		after, _ := MarshalJSON(f.report)
		if !bytes.Equal(raw, after) {
			t.Errorf("%s: rendering changed the report", f.name)
		}
	}
}

// TestRenderersKeepVerdict: SARIF carries the verdict and exit code of the
// report, and no part of any rendering says error about a neutral item.
func TestRenderersKeepVerdict(t *testing.T) {
	for _, f := range fixtures(t) {
		raw, err := SARIF(f.report)
		var log struct {
			Runs []struct {
				Invocations []struct {
					ExecutionSuccessful bool `json:"executionSuccessful"`
					ExitCode            int  `json:"exitCode"`
				} `json:"invocations"`
				Results []struct {
					Level string `json:"level"`
				} `json:"results"`
				Properties struct {
					Verdict string `json:"verdict"`
				} `json:"properties"`
			} `json:"runs"`
		}
		if err != nil || json.Unmarshal(raw, &log) != nil {
			t.Fatal(err)
		}
		run := log.Runs[0]
		if run.Properties.Verdict != f.report.Verdict || run.Invocations[0].ExitCode != Exit(f.report) || !run.Invocations[0].ExecutionSuccessful {
			t.Errorf("%s: verdict %q exit %d", f.name, run.Properties.Verdict, run.Invocations[0].ExitCode)
		}
		if len(run.Results) == 0 && bytes.Contains(raw, []byte(`"level": "error"`)) && f.name != "full" {
			t.Errorf("%s: error level without a finding", f.name)
		}
	}
}

// TestNeutralItemsAreNeverErrors: a report with only gaps, notices, leads
// and unsupported combinations has no error level at all. Its only results
// are the warnings for the gaps, so that code scanning does not show an
// undecided scan as "no alerts".
func TestNeutralItemsAreNeverErrors(t *testing.T) {
	report := fullReport()
	report.Findings, report.Passes = nil, nil
	Finalize(&report)
	raw, err := SARIF(report)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateSARIF(raw); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte(`"error"`)) {
		t.Fatalf("error level for neutral items:\n%s", raw)
	}
	var log struct {
		Runs []struct {
			Results     []any `json:"results"`
			Invocations []struct {
				Notifications []struct {
					Level      string `json:"level"`
					Properties struct {
						Kind string `json:"kind"`
					} `json:"properties"`
				} `json:"toolExecutionNotifications"`
			} `json:"invocations"`
		} `json:"runs"`
	}
	_ = json.Unmarshal(raw, &log)
	if len(log.Runs[0].Results) != len(report.Gaps) {
		t.Fatalf("%d results for %d gaps", len(log.Runs[0].Results), len(report.Gaps))
	}
	want := map[string]string{kindGap: "warning", kindUnsupported: "warning", kindNotice: "note", kindLead: "note"}
	seen := map[string]int{}
	for _, n := range log.Runs[0].Invocations[0].Notifications {
		if n.Level != want[n.Properties.Kind] {
			t.Errorf("%s notification has level %s", n.Properties.Kind, n.Level)
		}
		seen[n.Properties.Kind]++
	}
	if seen[kindGap] != 3 || seen[kindNotice] != 2 || seen[kindLead] != 1 || seen[kindUnsupported] != 1 {
		t.Fatalf("notifications %v", seen)
	}
}

// TestSARIFCounts: one result per (finding, location); one notification per
// gap, notice, lead and unsupported combination; one rule per distinct id;
// the run properties repeat the report's summary.
func TestSARIFCounts(t *testing.T) {
	for _, f := range fixtures(t) {
		raw, err := SARIF(f.report)
		if err != nil {
			t.Fatal(err)
		}
		var log struct {
			Runs []struct {
				Tool struct {
					Driver struct {
						Rules []struct{ ID string } `json:"rules"`
					} `json:"driver"`
				} `json:"tool"`
				Results     []struct{ RuleID string } `json:"results"`
				Invocations []struct {
					Notifications []any `json:"toolExecutionNotifications"`
				} `json:"invocations"`
				Properties struct {
					Summary Summary `json:"summary"`
				} `json:"properties"`
			} `json:"runs"`
		}
		if err := json.Unmarshal(raw, &log); err != nil {
			t.Fatal(err)
		}
		run := log.Runs[0]
		results, ids := 0, map[string]bool{}
		for _, finding := range f.report.Findings {
			results += len(finding.Locations)
			ids[finding.RuleID] = true
		}
		for _, n := range f.report.Notices {
			ids[n.RuleID] = true
		}
		for _, l := range f.report.Leads {
			ids[l.RuleID] = true
		}
		for _, u := range f.report.Unsupported {
			ids[u.RuleID] = true
		}
		for _, g := range f.report.Gaps {
			// One warning result per gap, under one rule per gap reason.
			results++
			ids[gapRuleID(g)] = true
		}
		notifications := len(f.report.Gaps) + len(f.report.Notices) + len(f.report.Leads) + len(f.report.Unsupported)
		if len(run.Results) != results || len(run.Invocations[0].Notifications) != notifications || len(run.Tool.Driver.Rules) != len(ids) {
			t.Errorf("%s: results %d/%d notifications %d/%d rules %d/%d", f.name, len(run.Results), results, len(run.Invocations[0].Notifications), notifications, len(run.Tool.Driver.Rules), len(ids))
		}
		if run.Properties.Summary != f.report.Summary {
			t.Errorf("%s: summary %+v", f.name, run.Properties.Summary)
		}
	}
}

// TestSARIFOrder: results by hop, rule id, file, document, item; rules by
// id; the whole upgrade after every hop.
func TestSARIFOrder(t *testing.T) {
	raw, err := SARIF(fullReport())
	if err != nil {
		t.Fatal(err)
	}
	var log struct {
		Runs []struct {
			Results []struct {
				RuleID     string `json:"ruleId"`
				Properties struct {
					Hop string `json:"hop"`
				} `json:"properties"`
				Locations []struct {
					PhysicalLocation struct {
						ArtifactLocation struct{ URI string } `json:"artifactLocation"`
					} `json:"physicalLocation"`
				} `json:"locations"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(raw, &log); err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, r := range log.Runs[0].Results {
		uri := "-"
		if len(r.Locations) > 0 {
			uri = r.Locations[0].PhysicalLocation.ArtifactLocation.URI
		}
		got = append(got, r.RuleID+" "+uri)
	}
	want := []string{
		"kubernetes.cronjob-removed deploy/app%200.yaml", "kubernetes.cronjob-removed deploy/app%201.yaml", "kubernetes.cronjob-removed deploy/app%202.yaml",
		"kubernetes.cronjob-removed deploy/app%203.yaml", "kubernetes.cronjob-removed deploy/app%204.yaml", "kubernetes.cronjob-removed deploy/app%205.yaml",
		"kubernetes.cronjob-removed deploy/app%206.yaml", "kubernetes.psp-removed psp.yaml", "kubernetes.whole w.yaml",
		// The gaps follow the findings, in report order, at the fallback
		// location (a report decoded from JSON has no input anchor).
		"prufyx/gap/COMPONENT_NOT_COVERED prufyx.yaml", "prufyx/gap/DECLARATION_MISSING prufyx.yaml", "prufyx/gap/RULE_NOT_DECIDED prufyx.yaml",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("order:\n%s", strings.Join(got, "\n"))
	}
}

// TestSARIFURI: artifact URIs are relative, forward-slash, encoded, and
// never absolute or climbing out of the root.
func TestSARIFURI(t *testing.T) {
	cases := map[string]string{
		"a/b.yaml":                          "a/b.yaml",
		"./a/b.yaml":                        "a/b.yaml",
		"a\\b.yaml":                         "a/b.yaml",
		"/etc/x.yaml":                       "etc/x.yaml",
		"../../x.yaml":                      "x.yaml",
		"a/../../x.yaml":                    "x.yaml",
		"my dir/a#b?.yaml":                  "my%20dir/a%23b%3F.yaml",
		"c:/x.yaml":                         "c%3A/x.yaml",
		"./-":                               "-",
		"":                                  "",
		".":                                 "",
		"..":                                "",
		"sha256:" + strings.Repeat("e", 64): "redacted/" + strings.Repeat("e", 12),
	}
	for in, want := range cases {
		if got := sarifURI(in); got != want {
			t.Errorf("sarifURI(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestSARIFFingerprintStable: the fingerprint ignores the line.
func TestSARIFFingerprintStable(t *testing.T) {
	a, b := fullReport(), fullReport()
	b.Findings[0].Locations[0].Line += 10
	ra, _ := SARIF(a)
	rb, _ := SARIF(b)
	fa, fb := fingerprints(t, ra), fingerprints(t, rb)
	if len(fa) == 0 || strings.Join(fa, ",") != strings.Join(fb, ",") {
		t.Fatalf("fingerprints depend on the line:\n%v\n%v", fa, fb)
	}
	seen := map[string]bool{}
	for _, f := range fa {
		if seen[f] {
			t.Fatalf("duplicate fingerprint %s", f)
		}
		seen[f] = true
	}
}

func fingerprints(t *testing.T, raw []byte) []string {
	var log struct {
		Runs []struct {
			Results []struct {
				PartialFingerprints map[string]string `json:"partialFingerprints"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(raw, &log); err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, r := range log.Runs[0].Results {
		out = append(out, r.PartialFingerprints[fingerprintKey])
	}
	return out
}

// TestSARIFLimits: GitHub code scanning limits: messages at most 1024
// bytes, results at most SARIFMaxResults with a notification for the rest.
func TestSARIFLimits(t *testing.T) {
	report := fullReport()
	report.Findings = []Finding{{RuleID: "r", Component: "kubernetes", Hop: HopRef{Index: 1, From: "1.24.0", To: "1.25"},
		Title: strings.Repeat("t", 800), Fix: strings.Repeat("é", 600), Match: "anchor", Basis: "reviewed"}}
	for i := 0; i < SARIFMaxResults+5; i++ {
		report.Findings[0].Locations = append(report.Findings[0].Locations, Location{File: "f.yaml", Document: i, Item: -1, Kind: "K", Name: "n"})
	}
	Finalize(&report)
	raw, err := SARIF(report)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateSARIF(raw); err != nil {
		t.Fatal(err)
	}
	var log struct {
		Runs []struct {
			Results []struct {
				Message struct{ Text string } `json:"message"`
			} `json:"results"`
			Invocations []struct {
				Notifications []struct {
					Descriptor struct{ ID string }   `json:"descriptor"`
					Message    struct{ Text string } `json:"message"`
				} `json:"toolExecutionNotifications"`
			} `json:"invocations"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(raw, &log); err != nil {
		t.Fatal(err)
	}
	run := log.Runs[0]
	if len(run.Results) != SARIFMaxResults || len(run.Results[0].Message.Text) > 1024 || strings.ContainsRune(run.Results[0].Message.Text, '\uFFFD') {
		t.Fatalf("results %d, message %d bytes", len(run.Results), len(run.Results[0].Message.Text))
	}
	last := run.Invocations[0].Notifications[len(run.Invocations[0].Notifications)-1]
	// Findings come first, so the gap warnings are what the limit drops: the 5
	// findings over the limit and every gap are counted as "more".
	if last.Descriptor.ID != truncatedID || !strings.Contains(last.Message.Text, strconv.Itoa(5+len(report.Gaps))+" more") {
		t.Fatalf("no truncation notification: %+v", last)
	}
}

// TestRenderVocabulary: renderings contain no internal vocabulary.
func TestRenderVocabulary(t *testing.T) {
	banned := []string{"RFC-", "ADR-", "wave ", "SCAN4", "SCAN5", "orchestrat", "design doc"}
	for _, f := range fixtures(t) {
		for _, format := range Formats() {
			out, err := Render(f.report, format, RenderOptions{ShowPasses: true, Verbose: true})
			if err != nil {
				t.Fatal(err)
			}
			for _, word := range banned {
				if bytes.Contains(bytes.ToLower(out), bytes.ToLower([]byte(word))) {
					t.Errorf("%s/%s contains %q", f.name, format, word)
				}
			}
		}
	}
}

// hostileReport carries canaries in every user-derived field.
func hostileReport() Report {
	report := fullReport()
	report.Findings[1].Locations = []Location{
		{File: "secret-dir/canary-file.yaml", Document: 1, Item: 0, Line: 4, Kind: "Secret", Namespace: "canary-ns", Name: "canary-name"},
		{File: "secret-dir/canary-file.yaml", Document: 2, Item: -1, Kind: "Secret", Namespace: "canary-ns", Name: "canary-name-2"},
	}
	report.Findings[0].Locations = report.Findings[0].Locations[:1]
	report.Findings[0].Locations[0].File = "secret-dir/canary-file.yaml"
	report.Findings[0].Locations[0].Name = "canary-name-3"
	report.Findings[0].Locations[0].Namespace = "canary-ns"
	report.Omitted = []Omitted{{File: "secret-dir/canary-omitted.yaml", Document: 0, Item: -1, Reason: "TEMPLATED"}}
	Finalize(&report)
	return report
}

// TestRedactedRenderingsLeakNothing: after Redact, SARIF and Markdown hold
// none of the file paths, names or namespaces, in locations, logical
// locations, fingerprints or anywhere else.
func TestRedactedRenderingsLeakNothing(t *testing.T) {
	report := hostileReport()
	plain, _ := SARIF(report)
	if !bytes.Contains(plain, []byte("canary-name-3")) {
		t.Fatal("canary missing from the unredacted rendering")
	}
	Redact(&report)
	for _, format := range []string{"sarif", "markdown", "human", "json"} {
		out, err := Render(report, format, RenderOptions{ShowPasses: true, Verbose: true})
		if err != nil {
			t.Fatal(err)
		}
		for _, canary := range []string{"canary", "secret-dir", "job-0", "app 0", "psp.yaml", "restricted", "w.yaml", "t.yaml"} {
			if bytes.Contains(out, []byte(canary)) {
				t.Errorf("%s leaks %q", format, canary)
			}
		}
	}
	// Like the human output, Markdown shows a redacted value as a digest prefix.
	md := string(Markdown(report, MarkdownOptions{}))
	if !strings.Contains(md, RedactValue("canary-name-3")[:19]+"`") || strings.Contains(md, RedactValue("canary-name-3")) || strings.Contains(md, RedactValue("canary-ns")) {
		t.Errorf("redacted names are not shown as a digest prefix:\n%s", md)
	}
	raw, _ := SARIF(report)
	if err := validateSARIF(raw); err != nil {
		t.Fatal(err)
	}
	var log struct {
		Runs []struct {
			Results []struct {
				Locations []struct {
					PhysicalLocation struct {
						ArtifactLocation struct{ URI string } `json:"artifactLocation"`
					} `json:"physicalLocation"`
				} `json:"locations"`
			} `json:"results"`
		} `json:"runs"`
	}
	_ = json.Unmarshal(raw, &log)
	for _, r := range log.Runs[0].Results {
		for _, l := range r.Locations {
			if uri := l.PhysicalLocation.ArtifactLocation.URI; !strings.HasPrefix(uri, "redacted/") && uri != gapFallbackURI {
				t.Errorf("uri %q is not a redacted name", l.PhysicalLocation.ArtifactLocation.URI)
			}
		}
	}
}

// cells splits a Markdown table row on pipes that are not escaped.
func cells(row string) []string {
	var out []string
	var cell strings.Builder
	runes := []rune(row)
	for i := 0; i < len(runes); i++ {
		switch {
		case runes[i] == '\\' && i+1 < len(runes):
			cell.WriteRune(runes[i])
			cell.WriteRune(runes[i+1])
			i++
		case runes[i] == '|':
			out = append(out, cell.String())
			cell.Reset()
		default:
			cell.WriteRune(runes[i])
		}
	}
	return out
}

// TestMarkdownEscaping: a rule title with a pipe, a heading and mentions,
// and an object name with backticks, newlines and links cannot break the
// table, open a heading or list, mention a user, or close a code span.
func TestMarkdownEscaping(t *testing.T) {
	report := fullReport()
	report.Findings = []Finding{{
		RuleID: "r.x", Component: "kubernetes", Hop: HopRef{Index: 1, From: "1.24.17", To: "1.25"},
		Title: "# Title | with *pipe* and @mention [link](http://evil.test) <b>html</b> _x_", Fix: "- fix | now\n1. numbered", Match: "anchor", Basis: "reviewed",
		Locations: []Location{{File: "a`b.yaml", Document: 0, Item: -1, Line: 2, Kind: "Kind|X", Namespace: "n`s", Name: "na``me`\n# not a heading | x"}},
		Citations: []constraintengine.SourceEvidence{citation("c", 1)},
	}}
	Finalize(&report)
	md := string(Markdown(report, MarkdownOptions{}))
	var row string
	for _, line := range strings.Split(md, "\n") {
		if strings.HasPrefix(line, "| 1.24.17 -> 1.25") {
			row = line
		}
	}
	if row == "" {
		t.Fatalf("no finding row:\n%s", md)
	}
	if got := len(cells(row)); got != 5 { // a leading empty piece and four cells
		t.Fatalf("%d cells in %q", got, row)
	}
	for _, bad := range []string{"# Title", "@mention", "[link]", "<b>", "\n# not", "- fix", "\n1. numbered"} {
		if i := strings.Index(md, bad); i >= 0 && (i == 0 || md[i-1] != '\\') {
			t.Errorf("unescaped %q in:\n%s", bad, md)
		}
	}
	for _, line := range strings.Split(md, "\n") {
		if strings.HasPrefix(line, "#") && !strings.HasPrefix(line, "# ") && !strings.HasPrefix(line, "## ") && !strings.HasPrefix(line, "### ") {
			t.Errorf("stray heading %q", line)
		}
	}
	// The name has a run of two backticks, so its code span uses three, and
	// the escaped pipe stays inside the cell.
	if !strings.Contains(md, "```Kind\\|X n`s/na``me` # not a heading \\| x```") || !strings.Contains(md, "``a`b.yaml:2``") {
		t.Errorf("code spans:\n%s", row)
	}
	if !strings.Contains(md, "&#64;mention") || !strings.Contains(md, "\\| with") {
		t.Errorf("escapes missing:\n%s", row)
	}
	for _, c := range []string{"a|b", "`", "``", "a`b", " `x` ", ""} {
		span := mdCode(c)
		if strings.Count(span, "|") != strings.Count(span, "\\|") {
			t.Errorf("mdCode(%q) = %q has a bare pipe", c, span)
		}
	}
}

// TestMdTextLeading: text that would start a block is escaped.
func TestMdTextLeading(t *testing.T) {
	cases := map[string]string{
		"# a": "\\# a", "- a": "\\- a", "+ a": "\\+ a", "> a": "\\> a", "1. a": "1\\. a", "12) a": "12\\) a", "a - b": "a - b",
		"a|b": "a\\|b", "a\nb": "a b", "x@y": "x&#64;y", "a_b*c": "a\\_b\\*c", "": "",
	}
	for in, want := range cases {
		if got := mdText(in); got != want {
			t.Errorf("mdText(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestFormatsDeterministic: two renderings of the same report are identical
// in every format (also with the optional sections).
func TestFormatsDeterministic(t *testing.T) {
	for _, f := range fixtures(t) {
		for _, format := range Formats() {
			for _, options := range []RenderOptions{{}, {ShowPasses: true, Verbose: true}} {
				a, _ := Render(f.report, format, options)
				b, _ := Render(f.report, format, options)
				if !bytes.Equal(a, b) {
					t.Errorf("%s/%s differs between renderings", f.name, format)
				}
			}
		}
	}
}

func readGolden(name string) ([]byte, error) { return os.ReadFile(filepath.Join("testdata", name)) }
