// SPDX-License-Identifier: AGPL-3.0-only

package scanrun

import (
	"errors"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/scanreport"
)

const (
	skewRule36 = "kubernetes.kubelet-version-skew.1-35-0-to-1-36-0"
	skewRule37 = "kubernetes.kubelet-version-skew.1-36-0-to-1-37-0"
)

func kubeletKnowledge(t *testing.T) Knowledge {
	t.Helper()
	return newKnowledge(t, knowledgeOptions{policy: "current"})
}

// kubeletArgs scans 1.35.2 -> 1.37.0 with complete upstream declarations
// plus the given extra flags.
func kubeletArgs(paths []string, extra ...string) []string {
	return args(paths, append([]string{"--from", "kubernetes=1.35.2", "--to", "kubernetes=1.37.0", "--show-passes"}, extra...)...)
}

func kubeletManifest(t *testing.T) []string {
	t.Helper()
	_, paths := files(t, map[string]string{"cm.yaml": "apiVersion: v1\nkind: ConfigMap\nmetadata: {name: c}\n"})
	return paths
}

func skewPass(report scanreport.Report, rule string) (scanreport.Pass, bool) {
	for _, pass := range report.Passes {
		if pass.RuleID == rule {
			return pass, true
		}
	}
	return scanreport.Pass{}, false
}

func skewFinding(report scanreport.Report, rule string) (scanreport.Finding, bool) {
	for _, finding := range report.Findings {
		if finding.RuleID == rule {
			return finding, true
		}
	}
	return scanreport.Finding{}, false
}

func hasDetail(report scanreport.Report, text string) bool {
	for _, gap := range report.Gaps {
		if strings.Contains(gap.Detail, text) {
			return true
		}
	}
	return false
}

// TestScanKubeletUndeclared: without a declaration the skew rules apply to
// the hop and name the missing declaration; no skew result is ever produced.
func TestScanKubeletUndeclared(t *testing.T) {
	t.Parallel()
	result := mustScan(t, kubeletKnowledge(t), kubeletArgs(kubeletManifest(t))...)
	if result.Exit != scanreport.ExitUnknown {
		t.Fatalf("exit %d, want %d", result.Exit, scanreport.ExitUnknown)
	}
	if !hasDetail(result.Report, "the lowest kubelet version is not declared") {
		t.Fatalf("no kubelet declaration gap: %v", gapReasons(result.Report))
	}
	for _, rule := range []string{skewRule36, skewRule37} {
		if _, ok := skewPass(result.Report, rule); ok {
			t.Fatalf("%s passed without a declaration", rule)
		}
		if _, ok := skewFinding(result.Report, rule); ok {
			t.Fatalf("%s blocked without a declaration", rule)
		}
	}
	if result.Report.Provenance.KubeletVersions != nil {
		t.Fatal("provenance names kubelet versions that were not declared")
	}
	for _, omission := range result.Report.Omissions {
		if omission == scanreport.OmissionNodeSkewDeclared {
			t.Fatal("omission says declared versions without a declaration")
		}
	}
}

func TestScanKubeletInvalidDeclarationIsUsageError(t *testing.T) {
	t.Parallel()
	paths := kubeletManifest(t)
	cases := map[string][]string{
		"v prefix":        {"--kubelet-version-min", "v1.33.0"},
		"build suffix":    {"--kubelet-version-min", "1.33.0-eks"},
		"minor only":      {"--kubelet-version-min", "1.33"},
		"leading zero":    {"--kubelet-version-min", "1.033.0"},
		"empty":           {"--kubelet-version-min="},
		"max below min":   {"--kubelet-version-min", "1.34.0", "--kubelet-version-max", "1.33.0"},
		"max without min": {"--kubelet-version-max", "1.34.0"},
		"max not x.y.z":   {"--kubelet-version-min", "1.33.0", "--kubelet-version-max", "1.34"},
		"empty max":       {"--kubelet-version-min", "1.33.0", "--kubelet-version-max="},
	}
	for name, extra := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			_, err := scan(t, kubeletKnowledge(t), kubeletArgs(paths, extra...)...)
			var usageErr *UsageError
			if !errors.As(err, &usageErr) {
				t.Fatalf("error %v, want a usage error", err)
			}
		})
	}
}

func TestScanKubeletRepeatedFlagRefused(t *testing.T) {
	t.Parallel()
	_, err := ParseArgs([]string{"--kubelet-version-min", "1.33.0", "--kubelet-version-min", "1.34.0"})
	var usageErr *UsageError
	if !errors.As(err, &usageErr) {
		t.Fatalf("error %v, want a usage error", err)
	}
}

// TestScanKubeletDeclaredBlocksOnlyTheHopItFails: min 1.33.0 is inside the
// window of 1.36 and outside the window of 1.37.
func TestScanKubeletDeclaredBlocksOnlyTheHopItFails(t *testing.T) {
	t.Parallel()
	result := mustScan(t, kubeletKnowledge(t), kubeletArgs(kubeletManifest(t), "--kubelet-version-min", "1.33.0")...)
	if result.Exit != scanreport.ExitBlocked {
		t.Fatalf("exit %d gaps %v", result.Exit, gapReasons(result.Report))
	}
	finding, ok := skewFinding(result.Report, skewRule37)
	if !ok {
		t.Fatalf("no finding for %s: %+v", skewRule37, result.Report.Findings)
	}
	if len(finding.Locations) != 0 || finding.DeclaredEvidence != scanreport.DeclaredEvidenceKubelet {
		t.Fatalf("finding %+v: want no locations and the declared label", finding)
	}
	if _, blocked := skewFinding(result.Report, skewRule36); blocked {
		t.Fatal("hop 1.36 blocked for a kubelet inside the window")
	}
	pass, ok := skewPass(result.Report, skewRule36)
	if !ok || pass.DeclaredEvidence != scanreport.DeclaredEvidenceKubelet {
		t.Fatalf("pass %+v ok %v: want a labelled pass for 1.36", pass, ok)
	}
	versions := result.Report.Provenance.KubeletVersions
	if versions == nil || versions.Minimum != "1.33.0" || versions.Maximum != "" || versions.Source != "flag" || versions.Observed {
		t.Fatalf("provenance %+v", versions)
	}
	if result.Report.Provenance.NetworkUsed {
		t.Fatal("network used")
	}
	var omitted bool
	for _, omission := range result.Report.Omissions {
		omitted = omitted || omission == scanreport.OmissionNodeSkewDeclared
		if omission == scanreport.OmissionNodeSkew {
			t.Fatal("the not-evaluated omission stays with declared versions")
		}
	}
	if !omitted {
		t.Fatalf("omissions %v", result.Report.Omissions)
	}
}

func TestScanKubeletDeclaredInsideTheWindowPassesTheSkewRules(t *testing.T) {
	t.Parallel()
	result := mustScan(t, kubeletKnowledge(t), kubeletArgs(kubeletManifest(t), "--kubelet-version-min", "1.34.0")...)
	for _, rule := range []string{skewRule36, skewRule37} {
		pass, ok := skewPass(result.Report, rule)
		if !ok || pass.DeclaredEvidence != scanreport.DeclaredEvidenceKubelet {
			t.Fatalf("%s: pass %+v ok %v", rule, pass, ok)
		}
		if _, blocked := skewFinding(result.Report, rule); blocked {
			t.Fatalf("%s blocked", rule)
		}
	}
	if hasDetail(result.Report, "kubelet version is not declared") {
		t.Fatal("a declared kubelet is reported as undeclared")
	}
}

// TestScanKubeletMaximumNewerThanTargetBlocks: a kubelet newer than the
// control plane is outside the window whatever the minimum says.
func TestScanKubeletMaximumNewerThanTargetBlocks(t *testing.T) {
	t.Parallel()
	result := mustScan(t, kubeletKnowledge(t), kubeletArgs(kubeletManifest(t), "--kubelet-version-min", "1.35.0", "--kubelet-version-max", "1.37.0")...)
	if _, ok := skewFinding(result.Report, skewRule36); !ok {
		t.Fatalf("no finding for %s; exit %d", skewRule36, result.Exit)
	}
	if _, blocked := skewFinding(result.Report, skewRule37); blocked {
		t.Fatal("1.37 kubelet blocked against a 1.37 target")
	}
}

// TestScanKubeletOtherMajorIsNeverAPass: a declaration that cannot be
// compared with the target leaves the rule undecided.
func TestScanKubeletOtherMajorIsNeverAPass(t *testing.T) {
	t.Parallel()
	result := mustScan(t, kubeletKnowledge(t), kubeletArgs(kubeletManifest(t), "--kubelet-version-min", "2.0.0")...)
	if result.Exit != scanreport.ExitUnknown {
		t.Fatalf("exit %d, want unknown", result.Exit)
	}
	for _, rule := range []string{skewRule36, skewRule37} {
		if _, ok := skewPass(result.Report, rule); ok {
			t.Fatalf("%s passed for another major", rule)
		}
		if _, ok := skewFinding(result.Report, rule); ok {
			t.Fatalf("%s blocked for another major", rule)
		}
	}
}

// TestScanKubeletCustomBuildProducesNoSkewClaim: the declared fact follows
// the distribution declaration exactly as the check route does.
func TestScanKubeletCustomBuildProducesNoSkewClaim(t *testing.T) {
	t.Parallel()
	paths := kubeletManifest(t)
	command := append(append([]string{}, paths...), "--distribution", "custom_build", "--resource-scope-complete", "--target-api-apply-required",
		"--now", testNow, "--from", "kubernetes=1.35.2", "--to", "kubernetes=1.37.0", "--show-passes", "--kubelet-version-min", "1.30.0")
	result := mustScan(t, kubeletKnowledge(t), command...)
	if result.Exit == scanreport.ExitPass {
		t.Fatal("PASS on a custom build")
	}
	for _, rule := range []string{skewRule36, skewRule37} {
		if _, ok := skewPass(result.Report, rule); ok {
			t.Fatalf("%s passed on a custom build", rule)
		}
		if _, ok := skewFinding(result.Report, rule); ok {
			t.Fatalf("%s blocked on a custom build", rule)
		}
	}
}

// TestScanKubeletDeterministicDigest: the declaration is part of the input
// digest, and the same declaration gives the same digest.
func TestScanKubeletDeterministicDigest(t *testing.T) {
	t.Parallel()
	paths := kubeletManifest(t)
	digest := func(extra ...string) string {
		result := mustScan(t, kubeletKnowledge(t), kubeletArgs(paths, extra...)...)
		return result.Report.Paths[0].Hops[1].InputDigest
	}
	first, second := digest("--kubelet-version-min", "1.33.0"), digest("--kubelet-version-min", "1.33.0")
	if first == "" || first != second {
		t.Fatalf("digests %q %q", first, second)
	}
	if other := digest("--kubelet-version-min", "1.34.0"); other == first {
		t.Fatal("a different declared result left the input digest unchanged")
	}
	if none := digest(); none == first {
		t.Fatal("a declaration left the input digest unchanged")
	}
}

func TestScanKubeletFileKeysAndFlagPrecedence(t *testing.T) {
	t.Parallel()
	config := "apiVersion: prufyx.io/v1alpha1\nkind: ScanConfig\ndeclarations:\n  kubernetes:\n    minimumKubeletVersion: 1.30.0\n    maximumKubeletVersion: 1.31.0\n"
	dir, _ := files(t, map[string]string{"prufyx.yaml": config, "cm.yaml": "apiVersion: v1\nkind: ConfigMap\nmetadata: {name: c}\n"})
	command := func(extra ...string) []string {
		return args([]string{dir}, append([]string{"--from", "kubernetes=1.35.2", "--to", "kubernetes=1.37.0"}, extra...)...)
	}
	fromFile := mustScan(t, kubeletKnowledge(t), command()...)
	versions := fromFile.Report.Provenance.KubeletVersions
	if versions == nil || versions.Minimum != "1.30.0" || versions.Maximum != "1.31.0" || versions.Source != "file" {
		t.Fatalf("provenance %+v", versions)
	}
	if _, ok := skewFinding(fromFile.Report, skewRule36); !ok {
		t.Fatal("a 1.30.0 kubelet is outside the window of 1.36")
	}
	overridden := mustScan(t, kubeletKnowledge(t), command("--kubelet-version-min", "1.34.0", "--kubelet-version-max", "1.35.0")...)
	versions = overridden.Report.Provenance.KubeletVersions
	if versions == nil || versions.Minimum != "1.34.0" || versions.Maximum != "1.35.0" || versions.Source != "flag" {
		t.Fatalf("provenance %+v", versions)
	}
	if len(overridden.Report.Findings) != 0 {
		t.Fatalf("findings %+v", overridden.Report.Findings)
	}
	// A flag minimum above the file's maximum is refused as a whole.
	if _, err := scan(t, kubeletKnowledge(t), command("--kubelet-version-min", "1.35.0")...); err == nil {
		t.Fatal("a flag minimum above the file maximum was accepted")
	}
}

// mismatchGaps are the gaps that name a declared kubelet version that cannot
// be compared, by rule.
func mismatchGaps(report scanreport.Report) map[string]scanreport.Gap {
	found := map[string]scanreport.Gap{}
	for _, gap := range report.Gaps {
		if gap.Reason != scanreport.ReasonDeclarationMismatch {
			continue
		}
		for _, rule := range []string{skewRule36, skewRule37} {
			if strings.Contains(gap.Detail, rule) {
				found[rule] = gap
			}
		}
	}
	return found
}

// TestScanKubeletUncomparableNamesTheCause: a declared kubelet version that
// cannot be compared is named as such, never explained by the manifests'
// preparation reason, and never passes.
func TestScanKubeletUncomparableNamesTheCause(t *testing.T) {
	t.Parallel()
	_, removed := files(t, map[string]string{"cronjob.yaml": removedCronJobOnly})
	custom := []string{"--distribution", "custom_build", "--kubelet-version-min", "1.30.0"}
	cases := map[string]struct {
		paths []string
		extra []string
		want  string
	}{
		"other major":                {kubeletManifest(t), []string{"--kubelet-version-min", "2.0.0"}, "other major"},
		"other major, removed GVK":   {removed, []string{"--kubelet-version-min", "2.0.0"}, "other major"},
		"other major in the maximum": {kubeletManifest(t), []string{"--kubelet-version-min", "1.33.0", "--kubelet-version-max", "2.0.0"}, "other major"},
		"custom build":               {kubeletManifest(t), custom, "only official_upstream"},
		"custom build, removed GVK":  {removed, custom, "only official_upstream"},
	}
	for name, test := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			command := kubeletArgs(test.paths, test.extra...)
			if strings.Contains(strings.Join(test.extra, " "), "custom_build") {
				command = append(append([]string{}, test.paths...), "--resource-scope-complete", "--target-api-apply-required",
					"--now", testNow, "--from", "kubernetes=1.35.2", "--to", "kubernetes=1.37.0", "--show-passes")
				command = append(command, test.extra...)
			}
			result := mustScan(t, kubeletKnowledge(t), command...)
			if result.Exit != scanreport.ExitUnknown && result.Exit != scanreport.ExitBlocked {
				t.Fatalf("exit %d, want unknown or blocked, never pass", result.Exit)
			}
			gaps := mismatchGaps(result.Report)
			for _, rule := range []string{skewRule36, skewRule37} {
				gap, ok := gaps[rule]
				if !ok || !strings.Contains(gap.Detail, test.want) {
					t.Fatalf("%s: no %q gap: %+v", rule, test.want, gaps)
				}
				if _, ok := skewPass(result.Report, rule); ok {
					t.Fatalf("%s passed", rule)
				}
			}
		})
	}
}
