// SPDX-License-Identifier: AGPL-3.0-only

package communityapp

import (
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/extract/supersedeids"
)

const quietCronJobJSON = `{"apiVersion":"v1","kind":"List","items":[{"apiVersion":"batch/v1beta1","kind":"CronJob","metadata":{"name":"nightly-report","namespace":"default"}}]}`

const quietCronJobYAML = `apiVersion: batch/v1beta1
kind: CronJob
metadata:
  name: nightly-report
  namespace: default
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: settings
`

func quietArgs(path, from, to string, extra ...string) []string {
	args := []string{"check", "cncf", "--project", "kubernetes", "--native-resource", path, "--from", from, "--to", to, "--distribution", "official_upstream", "--target-api-apply-required", "--resource-scope-complete", "--now", supersedeids.ClockString()}
	return append(args, extra...)
}

func nonEmptyLines(text string) []string {
	return strings.Split(strings.TrimRight(text, "\n"), "\n")
}

func TestQuietHumanUnreviewedTransitionsPrintAtMostSevenLines(t *testing.T) {
	t.Parallel()
	path := writeCNCFFile(t, "kubernetes.json", []byte(quietCronJobJSON), 0o600)
	for _, pair := range [][2]string{{"1.21.0", "1.25.0"}, {"1.28.0", "1.30.0"}, {"1.25.0", "1.24.0"}} {
		code, human, stderr := runCNCFCLI(t, quietArgs(path, pair[0], pair[1], "--format", "human")...)
		lines := nonEmptyLines(human)
		if code != ExitUnknown || stderr != "" || len(lines) > 7 {
			t.Fatalf("%v: code=%d lines=%d stderr=%q\n%s", pair, code, len(lines), stderr, human)
		}
		for _, want := range []string{"UNKNOWN: kubernetes " + pair[0] + " -> " + pair[1] + " is not a reviewed transition", "reviewed pairs:", "1.24.0 -> 1.25.0", "check each minor step; a step without a reviewed pair stays UNKNOWN", "scoped result: UNKNOWN\naggregate: UNKNOWN"} {
			if !strings.Contains(human, want) {
				t.Errorf("%v: missing %q in\n%s", pair, want, human)
			}
		}
		// F3: a hop that crosses release boundaries names them and never calls
		// the claims not applicable; a hop that crosses none says nothing.
		boundaryLine := "20 rules about release boundaries (1.22.0, 1.25.0) this hop crosses are not reviewed for this hop"
		if has := strings.Contains(human, boundaryLine); has != (pair[0] == "1.21.0") {
			t.Errorf("%v: boundary line present=%v\n%s", pair, has, human)
		}
		if strings.Contains(human, "not applicable") {
			t.Errorf("%v: unreviewed claims described as not applicable\n%s", pair, human)
		}
		if strings.Contains(human, RuleTransitionNotReviewedText) || strings.Contains(human, "(RULE_RELEASE_BOUNDARY_NOT_REVIEWED)") {
			t.Errorf("per-rule lines were not collapsed:\n%s", human)
		}
		jsonCode, jsonOut, _ := runCNCFCLI(t, quietArgs(path, pair[0], pair[1], "--format", "json")...)
		if jsonCode != code || strings.Count(jsonOut, "RULE_TRANSITION_NOT_REVIEWED")+strings.Count(jsonOut, "RULE_RELEASE_BOUNDARY_NOT_REVIEWED") < 20 {
			t.Errorf("%v: JSON must still carry every claim (code %d)", pair, jsonCode)
		}
		// 1.21.0 -> 1.25.0 crosses the 1.22.0 removals outside their ranges:
		// the JSON carries them as boundary-unreviewed, never as excluded.
		if pair[0] == "1.21.0" && !strings.Contains(jsonOut, "RULE_RELEASE_BOUNDARY_NOT_REVIEWED") {
			t.Errorf("%v: JSON lacks the release-boundary claims", pair)
		}
	}
}

// RuleTransitionNotReviewedText is the reason code the collapsed output must
// not repeat per rule.
const RuleTransitionNotReviewedText = "(RULE_TRANSITION_NOT_REVIEWED)"

func TestQuietHumanReviewedPairCollapsesPassesAndSharesSources(t *testing.T) {
	t.Parallel()
	path := writeCNCFFile(t, "kubernetes.json", []byte(quietCronJobJSON), 0o600)
	code, human, stderr := runCNCFCLI(t, quietArgs(path, "1.24.0", "1.25.0", "--format", "human")...)
	lines := nonEmptyLines(human)
	// The mechanical rules cite one more pinned source than the reviewed ones.
	maxLines, sources := 11, 2
	if supersedeids.Superseded() {
		maxLines, sources = 12, 3
	}
	if code != ExitBlocked || stderr != "" || len(lines) > maxLines {
		t.Fatalf("code=%d lines=%d\n%s", code, len(lines), human)
	}
	if strings.Count(human, "pinned source:") != sources || strings.Contains(human, ": PASS (") || !strings.Contains(human, "6 rules PASS (not listed; use --show-passes)") {
		t.Fatalf("unexpected quiet output:\n%s", human)
	}
	if !strings.Contains(human, "BLOCKED ("+servedReason()+")") || !strings.Contains(human, "scoped result: BLOCKED\naggregate: UNKNOWN") {
		t.Fatalf("decisive claim missing:\n%s", human)
	}
	aggregate, claim := strings.Index(human, "aggregate: UNKNOWN"), strings.Index(human, "BLOCKED (")
	if aggregate < claim {
		t.Fatalf("aggregate must follow the claims:\n%s", human)
	}

	code, withPasses, _ := runCNCFCLI(t, quietArgs(path, "1.24.0", "1.25.0", "--format", "human", "--show-passes")...)
	if code != ExitBlocked || strings.Count(withPasses, ": PASS (") != 6 || hasDuplicateLines(withPasses) || !strings.Contains(withPasses, "pinned source:") || strings.Contains(withPasses, "--show-passes") {
		t.Fatalf("--show-passes output:\n%s", withPasses)
	}
}

func TestQuietHumanLeavesJSONUntouched(t *testing.T) {
	t.Parallel()
	path := writeCNCFFile(t, "kubernetes.json", []byte(quietCronJobJSON), 0o600)
	_, plain, _ := runCNCFCLI(t, quietArgs(path, "1.24.0", "1.25.0", "--format", "json")...)
	_, shown, _ := runCNCFCLI(t, quietArgs(path, "1.24.0", "1.25.0", "--format", "json", "--show-passes")...)
	if plain != shown || strings.Count(plain, `"status":"PASS"`) != 6 {
		t.Fatalf("JSON differs with --show-passes or lost claims")
	}
}

func TestKubernetesNativeAcceptsYAMLWithSameVerdicts(t *testing.T) {
	t.Parallel()
	jsonPath := writeCNCFFile(t, "a.json", []byte(quietCronJobJSON), 0o600)
	yamlPath := writeCNCFFile(t, "a.yaml", []byte(quietCronJobYAML), 0o600)
	jsonCode, jsonHuman, _ := runCNCFCLI(t, quietArgs(jsonPath, "1.24.0", "1.25.0", "--format", "human")...)
	yamlCode, yamlHuman, stderr := runCNCFCLI(t, quietArgs(yamlPath, "1.24.0", "1.25.0", "--format", "human")...)
	if yamlCode != ExitBlocked || jsonCode != yamlCode || stderr != "" {
		t.Fatalf("yaml code=%d json code=%d stderr=%q\n%s", yamlCode, jsonCode, stderr, yamlHuman)
	}
	// Only the raw input digest line may differ.
	strip := func(text string) string {
		var kept []string
		for _, line := range strings.Split(text, "\n") {
			if !strings.HasPrefix(line, "raw input digests:") {
				kept = append(kept, line)
			}
		}
		return strings.Join(kept, "\n")
	}
	if strip(jsonHuman) != strip(yamlHuman) {
		t.Fatalf("verdict output differs:\n%s\n---\n%s", jsonHuman, yamlHuman)
	}
}

func TestKubernetesNativeYAMLTemplatedAndMalformed(t *testing.T) {
	t.Parallel()
	templated := writeCNCFFile(t, "t.yaml", []byte("apiVersion: batch/v1\nkind: CronJob\nmetadata:\n  name: \"{{ .Values.name }}\"\n"), 0o600)
	code, out, stderr := runCNCFCLI(t, quietArgs(templated, "1.24.0", "1.25.0", "--format", "json")...)
	if code != ExitUnknown || stderr != "" || !strings.Contains(out, "RULE_FACT_UNAVAILABLE") {
		t.Fatalf("templated: code=%d out=%q stderr=%q", code, out, stderr)
	}
	bad := writeCNCFFile(t, "bad.yaml", []byte("a: &x 1\nb: *x\n"), 0o600)
	code, out, _ = runCNCFCLI(t, quietArgs(bad, "1.24.0", "1.25.0", "--format", "json")...)
	if code != ExitUsage || out != "" {
		t.Fatalf("alias accepted: code=%d out=%q", code, out)
	}
}

func hasDuplicateLines(text string) bool {
	seen := map[string]bool{}
	for _, line := range strings.Split(text, "\n") {
		if strings.HasPrefix(line, "pinned source:") {
			if seen[line] {
				return true
			}
			seen[line] = true
		}
	}
	return false
}

func TestGenericPreviewQuietHumanOutput(t *testing.T) {
	t.Parallel()
	run := func(raw string, extra ...string) (int, string) {
		path := writeCNCFFile(t, "vector.json", []byte(raw), 0o600)
		code, stdout, stderr := runCNCFCLI(t, append(cncfArgs(path), extra...)...)
		if stderr != "" {
			t.Fatalf("stderr=%q", stderr)
		}
		return code, stdout
	}
	// A reviewed pair with a PASS claim: counted, listed on request, aggregate after the claims.
	code, quiet := run(syntheticHelmInput, "--format", "human")
	if code != ExitOK || strings.Contains(quiet, ": PASS (") || !strings.Contains(quiet, "1 rule PASS (not listed; use --show-passes)") || strings.Index(quiet, "aggregate: UNKNOWN") < strings.Index(quiet, "rules PASS") {
		t.Fatalf("code=%d\n%s", code, quiet)
	}
	code, listed := run(syntheticHelmInput, "--format", "human", "--show-passes")
	if code != ExitOK || !strings.Contains(listed, ": PASS (") || strings.Contains(listed, "--show-passes") {
		t.Fatalf("code=%d\n%s", code, listed)
	}
	// A pair outside every reviewed transition collapses to one line.
	outside := strings.Replace(syntheticHelmInput, `"version":"4.0.0"`, `"version":"3.14.4"`, 1)
	code, unreviewed := run(outside, "--format", "human")
	if code != ExitUnknown || strings.Contains(unreviewed, "(RULE_TRANSITION_NOT_REVIEWED)") || !strings.Contains(unreviewed, "UNKNOWN: helm ") || !strings.Contains(unreviewed, "is not a reviewed transition") || !strings.Contains(unreviewed, "check each minor step; a step without a reviewed pair stays UNKNOWN") {
		t.Fatalf("code=%d\n%s", code, unreviewed)
	}
	// JSON carries the claims as before.
	if code, out := run(outside, "--format", "json"); code != ExitUnknown || !strings.Contains(out, "RULE_TRANSITION_NOT_REVIEWED") {
		t.Fatalf("json code=%d", code)
	}
}

func TestCompareVersionsOrdersNumerically(t *testing.T) {
	t.Parallel()
	if compareVersions("1.9.0", "1.10.0") >= 0 || compareVersions("1.23.17", "1.24.0") >= 0 || compareVersions("1.24.0", "1.24.0") != 0 {
		t.Fatal("numeric order broken")
	}
}
