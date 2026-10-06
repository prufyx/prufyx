// SPDX-License-Identifier: AGPL-3.0-only

package communityapp

import (
	"fmt"
	"strings"
	"testing"
)

func TestRookLatestCLIExactEndpointsAndKubernetesMinimum(t *testing.T) {
	t.Parallel()
	input := func(from, to, kubernetes string) []byte {
		dependency := ""
		if kubernetes != "" {
			dependency = fmt.Sprintf(`{"component":"pkg:github/kubernetes/kubernetes","version":%q,"facts":[]},`, kubernetes)
		}
		return []byte(fmt.Sprintf(`{"schema":"prufyx.io/operator-declared-constraint-input/v1alpha1","authority":"OPERATOR_DECLARED_MINIMIZED","current":{"components":[{"component":"pkg:github/rook/rook","version":%q,"facts":[]}]},"proposed":{"components":[%s{"component":"pkg:github/rook/rook","version":%q,"facts":[]}]}}`, from, dependency, to))
	}
	for _, from := range []string{"1.15.9", "1.16.9", "1.17.9", "1.18.11", "1.19.11"} {
		// Rook documents only adjacent supported minor upgrade paths, so every
		// non-adjacent origin carries a reviewed BLOCKED direct-minor-skip claim
		// regardless of the declared Kubernetes version. Only the adjacent
		// 1.19.11 origin still exercises the Kubernetes-minimum matrix alone.
		directMinorSkip := from != "1.19.11"
		for _, tc := range []struct {
			name, kubernetes, status string
			code                     int
		}{
			{"below-minimum", "1.30.9", "BLOCKED", ExitBlocked},
			{"at-minimum", "1.31.0", "PASS", ExitOK},
			{"missing", "", "UNKNOWN", ExitUnknown},
		} {
			t.Run(from+"/"+tc.name, func(t *testing.T) {
				expectedCode, expectedStatus := tc.code, tc.status
				if directMinorSkip {
					expectedCode, expectedStatus = ExitBlocked, "BLOCKED"
				}
				raw := input(from, "1.20.7", tc.kubernetes)
				path := writeCNCFFile(t, "rook-latest.json", raw, 0o600)
				code, output, stderr := runCNCFCLI(t, "check", "cncf", "--project", "rook", "--input", path, "--input-digest", cncfDigest(raw), "--now", "2026-09-12T08:32:00Z", "--format", "json")
				if code != expectedCode || stderr != "" || !strings.Contains(output, `"assessment":"UNKNOWN"`) {
					t.Fatalf("code=%d stderr=%q output=%s", code, stderr, output)
				}
				if expectedStatus != "UNKNOWN" && !strings.Contains(output, `"status":"`+expectedStatus+`"`) {
					t.Fatalf("missing %s claim: %s", expectedStatus, output)
				}
				if directMinorSkip && !strings.Contains(output, `"ruleId":"rook.direct-minor-skip.`) {
					t.Fatalf("missing reviewed direct-minor-skip claim: %s", output)
				}
			})
		}
	}
	for _, tc := range []struct{ from, to string }{{"1.19.10", "1.20.7"}, {"1.19.11", "1.20.6"}} {
		t.Run("wrong-"+tc.from+"-"+tc.to, func(t *testing.T) {
			raw := input(tc.from, tc.to, "1.30.9")
			path := writeCNCFFile(t, "rook-latest-wrong.json", raw, 0o600)
			code, output, stderr := runCNCFCLI(t, "check", "cncf", "--project", "rook", "--input", path, "--input-digest", cncfDigest(raw), "--now", "2026-09-12T08:32:00Z", "--format", "json")
			if code != ExitUnknown || stderr != "" || !strings.Contains(output, `"assessment":"UNKNOWN"`) || strings.Contains(output, `"status":"BLOCKED"`) {
				t.Fatalf("code=%d stderr=%q output=%s", code, stderr, output)
			}
		})
	}
}

func TestRookPreviousExactRoutesRemainAvailable(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		raw    []byte
		code   int
		status string
	}{
		{[]byte(`{"schema":"prufyx.io/operator-declared-constraint-input/v1alpha1","authority":"OPERATOR_DECLARED_MINIMIZED","current":{"components":[{"component":"pkg:github/rook/rook","version":"1.19.4","facts":[]}]},"proposed":{"components":[{"component":"pkg:github/rook/rook","version":"1.20.0","facts":[{"id":"component.rook.deployment_mode","state":"declared","enumValue":"helm"}]}]}}`), ExitBlocked, "BLOCKED"},
		{[]byte(`{"schema":"prufyx.io/operator-declared-constraint-input/v1alpha1","authority":"OPERATOR_DECLARED_MINIMIZED","current":{"components":[{"component":"pkg:github/rook/rook","version":"1.19.5","facts":[]}]},"proposed":{"components":[{"component":"pkg:github/kubernetes/kubernetes","version":"1.31.0","facts":[]},{"component":"pkg:github/rook/rook","version":"1.20.0","facts":[]}]}}`), ExitOK, "PASS"},
	} {
		path := writeCNCFFile(t, "rook-previous.json", tc.raw, 0o600)
		code, output, stderr := runCNCFCLI(t, "check", "cncf", "--project", "rook", "--input", path, "--input-digest", cncfDigest(tc.raw), "--now", "2026-09-10T00:00:00Z", "--format", "json")
		if code != tc.code || stderr != "" || !strings.Contains(output, `"status":"`+tc.status+`"`) {
			t.Fatalf("code=%d stderr=%q output=%s", code, stderr, output)
		}
	}
}
