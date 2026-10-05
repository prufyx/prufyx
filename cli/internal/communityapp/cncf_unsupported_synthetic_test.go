// SPDX-License-Identifier: AGPL-3.0-only

//go:build prufyx_synthetic_knowledge

package communityapp

import (
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/cncfcheck"
	"github.com/prufyx/prufyx/cli/internal/constraintengine"
)

// TestSyntheticUnsupportedThroughTheCommandRoute: the generic check route,
// end to end against synthetic knowledge: a passing rule plus a support-range
// rule whose documented range excludes the target exits 11 with the
// headline line; inside the range it passes; beside a blocker it exits 10.
func TestSyntheticUnsupportedThroughTheCommandRoute(t *testing.T) {
	const supportAction = "move to a release line whose documented support range includes the target"
	support := func(minimum string) cncfcheck.Entry {
		return syntheticKubernetesEntry("kubernetes.synthetic-support.1-35-0-to-1-36-0", "require_component_version", "ADDON_KUBERNETES_SUPPORT_RANGE", supportAction, `,"dependency":{"side":"proposed","component":"pkg:github/kubernetes/kubernetes","comparison":"gte","version":"`+minimum+`"},"severity":"unsupported"`)
	}
	pass := syntheticKubernetesEntry("kubernetes.synthetic-pass.1-35-0-to-1-36-0", "require_component_version", "REVIEWED_SOURCE_CONSTRAINT", "keep the reviewed version", `,"dependency":{"side":"proposed","component":"pkg:github/kubernetes/kubernetes","comparison":"gte","version":"1.36.0"}`)
	blocker := syntheticKubernetesEntry("kubernetes.synthetic-blocked.1-35-0-to-1-36-0", "forbid_target_version", "REVIEWED_SOURCE_CONSTRAINT", "plan a reviewed route", "")
	input := []byte(`{"schema":"` + constraintengine.InputSchema + `","authority":"` + constraintengine.InputAuthority + `","current":{"components":[{"component":"pkg:github/kubernetes/kubernetes","version":"1.35.0","facts":[]}]},"proposed":{"components":[{"component":"pkg:github/kubernetes/kubernetes","version":"1.36.0","facts":[]}]}}`)
	const headline = "1 component combination is outside its documented support range"
	for _, tc := range []struct {
		name     string
		entries  []cncfcheck.Entry
		exit     int
		headline bool
	}{
		{"pass and UNSUPPORTED", []cncfcheck.Entry{pass, support("1.37.0")}, ExitUnknown, true},
		{"pass inside the support range", []cncfcheck.Entry{pass, support("1.36.0")}, 0, false},
		{"blocker and UNSUPPORTED", []cncfcheck.Entry{blocker, pass, support("1.37.0")}, 10, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			restore, err := cncfcheck.UseSyntheticKnowledge(nil, tc.entries)
			if err != nil {
				t.Fatal(err)
			}
			defer restore()
			path := writeCNCFFile(t, "input.json", input, 0o600)
			code, stdout, stderr := runCNCFCLI(t, "check", "cncf", "--project", "kubernetes", "--input", path, "--now", "2026-11-20T00:00:00Z")
			if code != tc.exit || stderr != "" {
				t.Fatalf("code=%d stderr=%s stdout=%s", code, stderr, stdout)
			}
			if tc.headline != strings.Contains(stdout, headline) {
				t.Fatalf("headline:\n%s", stdout)
			}
			if tc.headline && !strings.Contains(stdout, "kubernetes.synthetic-support.1-35-0-to-1-36-0: UNSUPPORTED (ADDON_KUBERNETES_SUPPORT_RANGE)\nnext action: "+supportAction+"\n") {
				t.Fatalf("claim line:\n%s", stdout)
			}
			code, report, _ := runCNCFCLI(t, "check", "cncf", "--project", "kubernetes", "--input", path, "--now", "2026-11-20T00:00:00Z", "--format", "json")
			if code != tc.exit || !strings.Contains(report, `"engineContractDigest":"`+constraintengine.EngineContractDigestSeverity()+`"`) || tc.headline != strings.Contains(report, `"status":"UNSUPPORTED"`) {
				t.Fatalf("code=%d report=%s", code, report)
			}
		})
	}
}
