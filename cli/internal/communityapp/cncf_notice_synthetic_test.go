// SPDX-License-Identifier: AGPL-3.0-only

//go:build prufyx_synthetic_knowledge

package communityapp

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/cncfcheck"
	"github.com/prufyx/prufyx/cli/internal/constraintengine"
	"github.com/prufyx/prufyx/cli/internal/extract/supersedeids"
)

// Run with: go test -tags prufyx_synthetic_knowledge ./internal/communityapp/
//
// The generic check route runs end to end against synthetic, never published
// knowledge: a one-way notice and, optionally, a passing rule for the same
// Kubernetes transition.

// syntheticReviewed and syntheticUntil are the evidence window of the
// synthetic rules: current at the shared test clock, which follows the
// embedded pack.
var syntheticReviewed, syntheticUntil = supersedeids.Window(61, 29)

func syntheticKubernetesEntry(id, operator, reason, nextAction, extra string) cncfcheck.Entry {
	revision := "0000000000000000000000000000000000000001"
	rule := `{"id":"` + id + `","operator":"` + operator + `","subject":{"component":"pkg:github/kubernetes/kubernetes","from":"1.35.0","to":"1.36.0"}` + extra + `,` +
		`"evidence":{"state":"active","reviewedAt":"` + syntheticReviewed + `","validUntil":"` + syntheticUntil + `","sources":[{"id":"synthetic-source","url":"https://github.com/kubernetes/kubernetes/blob/` + revision + `/CHANGELOG.md","revision":"` + revision + `","contentDigest":"sha256:` + strings.Repeat("0", 64) + `","startLine":1,"endLine":2}]},` +
		`"reasonCode":"` + reason + `","nextAction":"` + nextAction + `"}`
	return cncfcheck.Entry{Project: "kubernetes", Description: "Synthetic test-only rule.", RequiredFacts: []cncfcheck.Fact{}, Rule: json.RawMessage(rule)}
}

func TestSyntheticNoticeThroughTheCommandRoute(t *testing.T) {
	notice := syntheticKubernetesEntry("kubernetes.synthetic-one-way.1-35-0-to-1-36-0", constraintengine.OperatorNoticeOneWay, constraintengine.ReasonOneWayTransition, noticeBeforeText, "")
	pass := syntheticKubernetesEntry("kubernetes.synthetic-pass.1-35-0-to-1-36-0", "require_component_version", "REVIEWED_SOURCE_CONSTRAINT", "keep the reviewed version", `,"dependency":{"side":"proposed","component":"pkg:github/kubernetes/kubernetes","comparison":"gte","version":"1.36.0"}`)
	input := []byte(`{"schema":"` + constraintengine.InputSchema + `","authority":"` + constraintengine.InputAuthority + `","current":{"components":[{"component":"pkg:github/kubernetes/kubernetes","version":"1.35.0","facts":[]}]},"proposed":{"components":[{"component":"pkg:github/kubernetes/kubernetes","version":"1.36.0","facts":[]}]}}`)
	for _, tc := range []struct {
		name       string
		entries    []cncfcheck.Entry
		exit       int
		unreviewed bool
		claims     int
	}{
		// No verdict rule reviews 1.35.0 -> 1.36.0: every Kubernetes rule is
		// still reported as not reviewed, exactly as without the notice.
		{"a notice for an unreviewed pair keeps the unreviewed answer", []cncfcheck.Entry{notice}, ExitUnknown, true, 27 + kubernetesRuleExtra()},
		{"a notice beside a pass keeps the pass", []cncfcheck.Entry{notice, pass}, 0, false, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			restore, err := cncfcheck.UseSyntheticKnowledge(nil, tc.entries)
			if err != nil {
				t.Fatal(err)
			}
			defer restore()
			path := writeCNCFFile(t, "input.json", input, 0o600)
			code, stdout, stderr := runCNCFCLI(t, "check", "cncf", "--project", "kubernetes", "--input", path, "--now", supersedeids.ClockString())
			if code != tc.exit || stderr != "" {
				t.Fatalf("code=%d stderr=%s stdout=%s", code, stderr, stdout)
			}
			if tc.unreviewed != strings.Contains(stdout, "UNKNOWN: kubernetes 1.35.0 -> 1.36.0 is not a reviewed transition") {
				t.Fatalf("unreviewed line:\n%s", stdout)
			}
			if !strings.Contains(stdout, "cannot be rolled back: kubernetes.synthetic-one-way.1-35-0-to-1-36-0\nbefore you upgrade: "+noticeBeforeText+"\n") || strings.Contains(strings.ToLower(stdout), "safe") || strings.Contains(stdout, "NOTICE (") {
				t.Fatalf("stdout:\n%s", stdout)
			}
			code, report, _ := runCNCFCLI(t, "check", "cncf", "--project", "kubernetes", "--input", path, "--now", supersedeids.ClockString(), "--format", "json")
			if code != tc.exit || strings.Count(report, `"ruleId":`) != tc.claims || !strings.Contains(report, `"status":"NOTICE"`) || !strings.Contains(report, `"engineContractDigest":"`+constraintengine.EngineContractDigestNotice()+`"`) {
				t.Fatalf("code=%d report=%s", code, report)
			}
		})
	}
}

// TestSyntheticNoticeOnlyProjectSaysNoRuleDecided: for a project whose only
// rule is a notice, the generic route says that no rule decided the pair.
func TestSyntheticNoticeOnlyProjectSaysNoRuleDecided(t *testing.T) {
	const component = "pkg:github/aeraki-mesh/aeraki"
	entry := syntheticKubernetesEntry("aeraki-mesh.synthetic-one-way.1-35-0-to-1-36-0", constraintengine.OperatorNoticeOneWay, constraintengine.ReasonOneWayTransition, noticeBeforeText, "")
	entry.Project = "aeraki-mesh"
	entry.Rule = json.RawMessage(strings.Replace(string(entry.Rule), "pkg:github/kubernetes/kubernetes", component, 1))
	restore, err := cncfcheck.UseSyntheticKnowledge(nil, []cncfcheck.Entry{entry})
	if err != nil {
		t.Fatal(err)
	}
	defer restore()
	input := []byte(`{"schema":"` + constraintengine.InputSchema + `","authority":"` + constraintengine.InputAuthority + `","current":{"components":[{"component":"` + component + `","version":"1.35.0","facts":[]}]},"proposed":{"components":[{"component":"` + component + `","version":"1.36.0","facts":[]}]}}`)
	path := writeCNCFFile(t, "input.json", input, 0o600)
	code, stdout, stderr := runCNCFCLI(t, "check", "cncf", "--project", "aeraki-mesh", "--input", path, "--now", supersedeids.ClockString())
	if code != ExitUnknown || stderr != "" || !strings.Contains(stdout, noVerdictLine+"\n") || !strings.Contains(stdout, "cannot be rolled back: aeraki-mesh.synthetic-one-way") {
		t.Fatalf("code=%d stderr=%s stdout:\n%s", code, stderr, stdout)
	}
}
