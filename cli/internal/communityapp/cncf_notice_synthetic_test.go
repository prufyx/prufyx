// SPDX-License-Identifier: AGPL-3.0-only

//go:build prufyx_synthetic_knowledge

package communityapp

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/cncfcheck"
	"github.com/prufyx/prufyx/cli/internal/constraintengine"
)

// Run with: go test -tags prufyx_synthetic_knowledge ./internal/communityapp/
//
// The generic check route runs end to end against synthetic, never published
// knowledge: a one-way notice and, optionally, a passing rule for the same
// Kubernetes transition.

func syntheticKubernetesEntry(id, operator, reason, nextAction, extra string) cncfcheck.Entry {
	revision := "0000000000000000000000000000000000000001"
	rule := `{"id":"` + id + `","operator":"` + operator + `","subject":{"component":"pkg:github/kubernetes/kubernetes","from":"1.36.0","to":"1.37.0"}` + extra + `,` +
		`"evidence":{"state":"active","reviewedAt":"2026-09-20T00:00:00Z","validUntil":"2026-12-19T00:00:00Z","sources":[{"id":"synthetic-source","url":"https://github.com/kubernetes/kubernetes/blob/` + revision + `/CHANGELOG.md","revision":"` + revision + `","contentDigest":"sha256:` + strings.Repeat("0", 64) + `","startLine":1,"endLine":2}]},` +
		`"reasonCode":"` + reason + `","nextAction":"` + nextAction + `"}`
	return cncfcheck.Entry{Project: "kubernetes", Description: "Synthetic test-only rule.", RequiredFacts: []cncfcheck.Fact{}, Rule: json.RawMessage(rule)}
}

func TestSyntheticNoticeThroughTheCommandRoute(t *testing.T) {
	notice := syntheticKubernetesEntry("kubernetes.synthetic-one-way.1-36-0-to-1-37-0", constraintengine.OperatorNoticeOneWay, constraintengine.ReasonOneWayTransition, noticeBeforeText, "")
	pass := syntheticKubernetesEntry("kubernetes.synthetic-pass.1-36-0-to-1-37-0", "require_component_version", "REVIEWED_SOURCE_CONSTRAINT", "keep the reviewed version", `,"dependency":{"side":"proposed","component":"pkg:github/kubernetes/kubernetes","comparison":"gte","version":"1.37.0"}`)
	input := []byte(`{"schema":"` + constraintengine.InputSchema + `","authority":"` + constraintengine.InputAuthority + `","current":{"components":[{"component":"pkg:github/kubernetes/kubernetes","version":"1.36.0","facts":[]}]},"proposed":{"components":[{"component":"pkg:github/kubernetes/kubernetes","version":"1.37.0","facts":[]}]}}`)
	for _, tc := range []struct {
		name    string
		entries []cncfcheck.Entry
		exit    int
	}{
		{"only a notice stays unknown", []cncfcheck.Entry{notice}, ExitUnknown},
		{"a notice beside a pass keeps the pass", []cncfcheck.Entry{notice, pass}, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			restore, err := cncfcheck.UseSyntheticKnowledge(nil, tc.entries)
			if err != nil {
				t.Fatal(err)
			}
			defer restore()
			path := writeCNCFFile(t, "input.json", input, 0o600)
			code, stdout, stderr := runCNCFCLI(t, "check", "cncf", "--project", "kubernetes", "--input", path, "--now", "2026-10-01T00:00:00Z")
			if code != tc.exit || stderr != "" {
				t.Fatalf("code=%d stderr=%s stdout=%s", code, stderr, stdout)
			}
			if !strings.Contains(stdout, "cannot be rolled back: kubernetes.synthetic-one-way.1-36-0-to-1-37-0\nbefore you upgrade: "+noticeBeforeText+"\n") || strings.Contains(strings.ToLower(stdout), "safe") || strings.Contains(stdout, "NOTICE (") {
				t.Fatalf("stdout:\n%s", stdout)
			}
			code, report, _ := runCNCFCLI(t, "check", "cncf", "--project", "kubernetes", "--input", path, "--now", "2026-10-01T00:00:00Z", "--format", "json")
			if code != tc.exit || !strings.Contains(report, `"status":"NOTICE"`) || !strings.Contains(report, `"engineContractDigest":"`+constraintengine.EngineContractDigestNotice()+`"`) {
				t.Fatalf("code=%d report=%s", code, report)
			}
		})
	}
}
