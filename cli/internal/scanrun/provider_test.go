// SPDX-License-Identifier: AGPL-3.0-only

package scanrun

import (
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/constraintengine"
	"github.com/prufyx/prufyx/cli/internal/distribution"
	"github.com/prufyx/prufyx/cli/internal/providerfacts"
	"github.com/prufyx/prufyx/cli/internal/scanreport"
)

// withProviders gives a test knowledge a distribution record set. Rows and
// dates are synthetic.
type withProviders struct {
	Knowledge
	index distribution.Index
}

func (w withProviders) DistributionRecord(id string, now time.Time) (distribution.Record, string, bool) {
	return w.index.Record(id, now)
}

func providerIndex(t testing.TB) distribution.Index {
	t.Helper()
	now, err := time.Parse(time.RFC3339, testNow)
	if err != nil {
		t.Fatal(err)
	}
	rev := "0123456789abcdef0123456789abcdef01234567"
	section := distribution.Section{Records: []distribution.Record{{
		Distribution: "eks", ControlPlane: distribution.ControlPlaneManaged,
		Lifecycle: []distribution.Lifecycle{
			{Line: "1.29", StandardEnd: now.AddDate(0, 0, -200).Format("2006-01-02"), Precision: distribution.PrecisionDay},
			{Line: "1.30", StandardEnd: now.AddDate(0, 0, 400).Format("2006-01-02"), Precision: distribution.PrecisionDay},
		},
		Evidence: distribution.Evidence{State: distribution.StateActive, ReviewedAt: now.AddDate(0, 0, -1).Format(time.RFC3339), ValidUntil: now.AddDate(0, 0, 60).Format(time.RFC3339),
			Sources: []constraintengine.SourceEvidence{{ID: "t", URL: "https://github.com/example/docs/blob/" + rev + "/e.md", Revision: rev, ContentDigest: "sha256:" + strings.Repeat("0", 64), StartLine: 1, EndLine: 2}}},
	}}, Applicability: []distribution.Applicability{}}
	if err := distribution.Validate(section); err != nil {
		t.Fatal(err)
	}
	return distribution.NewIndex(section)
}

func providerScan(t *testing.T, knowledge Knowledge, distributionArgs ...string) Result {
	t.Helper()
	dir, _ := files(t, map[string]string{"applyset.yaml": cronjobV1})
	command := append([]string{dir, "--now", testNow, "--from", "kubernetes=1.29.6", "--to", "kubernetes=1.30.4", "--resource-scope-complete", "--target-api-apply-required"}, distributionArgs...)
	return mustScan(t, knowledge, command...)
}

// verdictOf is everything a provider fact must never change.
func verdictOf(r Result) []any {
	rep := r.Report
	return []any{r.Exit, rep.Verdict, rep.Headline, rep.Summary, rep.Findings, rep.Gaps, rep.Passes, rep.Paths, rep.Unsupported, rep.Notices}
}

func TestProviderFactsNeverChangeAVerdict(t *testing.T) {
	base := newKnowledge(t, knowledgeOptions{lines: allLines, policy: "current"})
	withRecords := withProviders{base, providerIndex(t)}

	pass := providerScan(t, base, "--distribution", "official_upstream")
	if pass.Exit != scanreport.ExitPass || pass.Report.Provider != nil {
		t.Fatalf("upstream baseline: exit %d provider %v", pass.Exit, pass.Report.Provider)
	}
	if got := providerScan(t, withRecords, "--distribution", "official_upstream"); !reflect.DeepEqual(verdictOf(got), verdictOf(pass)) || got.Report.Provider != nil {
		t.Fatal("provider records changed an upstream scan")
	}

	for _, provider := range []string{"eks", "gke", "aks", "k3s"} {
		without := providerScan(t, base, "--distribution", provider)
		with := providerScan(t, withRecords, "--distribution", provider)
		custom := providerScan(t, base, "--distribution", "custom_build")
		if without.Report.Provider == nil || with.Report.Provider == nil || custom.Report.Provider != nil {
			t.Fatalf("%s: provider section without/with/custom: %v %v %v", provider, without.Report.Provider != nil, with.Report.Provider != nil, custom.Report.Provider != nil)
		}
		// Adding records changes nothing a verdict reads.
		if !reflect.DeepEqual(verdictOf(with), verdictOf(without)) {
			t.Fatalf("%s: records changed the verdict", provider)
		}
		// A provider is never upstream: never better than custom_build, and
		// never a PASS.
		if without.Exit != scanreport.ExitUnknown || with.Exit != scanreport.ExitUnknown || without.Exit != custom.Exit {
			t.Fatalf("%s: exit %d/%d (custom %d)", provider, without.Exit, with.Exit, custom.Exit)
		}
		if !reflect.DeepEqual(gapReasons(without.Report), gapReasons(custom.Report)) {
			t.Fatalf("%s: gaps %v vs %v", provider, gapReasons(without.Report), gapReasons(custom.Report))
		}
	}

	// The section for eks with records: ended 1.29, in-support 1.30 (target),
	// with the knowledge revision and the source reference.
	section := providerScan(t, withRecords, "--distribution", "eks").Report.Provider
	if section.KnowledgeRevision == "" || len(section.Lines) != 2 {
		t.Fatalf("section %+v", section)
	}
	if f := section.Lines[0].Findings[0]; f.Rule != providerfacts.RuleSupportEnded || len(f.Sources) != 1 || f.KnowledgeRevision != section.KnowledgeRevision {
		t.Fatalf("1.29 finding %+v", f)
	}
	if f := section.Lines[1].Findings[0]; f.Rule != providerfacts.RuleSupportCurrent || f.Severity != providerfacts.SeverityInfo {
		t.Fatalf("1.30 finding %+v", f)
	}
	// Without a record the same declaration says UNKNOWN, never silence.
	absent := providerScan(t, base, "--distribution", "eks").Report.Provider
	if absent.Lines[0].Findings[0].Rule != providerfacts.RuleRecordAbsent || absent.Lines[0].Findings[0].Severity != providerfacts.SeverityUnknown {
		t.Fatalf("absent %+v", absent.Lines[0].Findings[0])
	}
}

func TestProviderDistributionTokensFailClosed(t *testing.T) {
	for _, token := range []string{"openshift", "talos", "kubeadm", "EKS", "eks ", "", "mystery"} {
		_, err := ParseArgs([]string{"--distribution", token, "--to", "kubernetes=1.30.0"})
		if !isUsage(err) {
			t.Errorf("--distribution %q: err %v", token, err)
		}
	}
	for _, token := range []string{"eks", "gke", "aks", "k3s", "official_upstream", "custom_build"} {
		if _, err := ParseArgs([]string{"--distribution", token, "--to", "kubernetes=1.30.0"}); err != nil {
			t.Errorf("--distribution %q: %v", token, err)
		}
	}
}

func TestProviderSectionRendersAdvisory(t *testing.T) {
	base := newKnowledge(t, knowledgeOptions{lines: allLines, policy: "current"})
	result := providerScan(t, withProviders{base, providerIndex(t)}, "--distribution", "eks")
	human := string(scanreport.Human(result.Report, scanreport.HumanOptions{Verbose: true}))
	for _, want := range []string{"PROVIDER FACTS (advisory", "provider_support_ended", "never make a scan SAFE", "Extended support is paid"} {
		if !strings.Contains(human, want) {
			t.Errorf("human output lacks %q", want)
		}
	}
	if md := string(scanreport.Markdown(result.Report, scanreport.MarkdownOptions{})); !strings.Contains(md, "PROVIDER FACTS") {
		t.Error("markdown output lacks the provider section")
	}
	golden(t, "provider-eks.json", jsonOf(t, result.Report))
	// An upstream scan prints nothing of it.
	if strings.Contains(string(scanreport.Human(providerScan(t, base, "--distribution", "official_upstream").Report, scanreport.HumanOptions{})), "PROVIDER FACTS") {
		t.Error("upstream scan printed provider facts")
	}
}
