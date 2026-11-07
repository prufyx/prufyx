// SPDX-License-Identifier: AGPL-3.0-only

package communityapp

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/projectcheck"
)

const mariadbCRDResourceFmt = `{"apiVersion":"k8s.mariadb.com/v1alpha1","kind":"MariaDB","metadata":{"name":"PRIVATE_OPERATOR_CRD"},"spec":%s}`

func writeMariaDBCRDResource(t *testing.T, spec string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "resource.json")
	raw := strings.Replace(mariadbCRDResourceFmt, "%s", spec, 1)
	if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestMariaDBOperatorCRDPairRouteOutcomes(t *testing.T) {
	for _, tc := range []struct {
		name, from, to, spec string
		complete             bool
		wantExit             int
		wantBlocked          string
	}{
		{"blocked-removed-field", "25.8.4", "25.10.4", `{"galera":{"primary":{"automaticFailover":true}}}`, true, ExitBlocked, "mariadb-operator.removed-field-galera-primary-automatic-failover.25-8-4-to-25-10-4"},
		{"blocked-embedded-maxscale", "25.8.4", "25.10.4", `{"maxScale":{}}`, true, ExitBlocked, "mariadb-operator.removed-field-embedded-max-scale.25-8-4-to-25-10-4"},
		{"blocked-retyped", "0.38.1", "25.0.0", `{"replication":{"syncBinlog":false}}`, true, ExitBlocked, "mariadb-operator.sync-binlog-retyped-integer.0-38-1-to-25-0-0"},
		{"scoped-pass-replaced-field", "25.8.4", "25.10.4", `{"galera":{"primary":{"autoFailover":true}}}`, true, ExitOK, ""},
		{"scoped-pass-integer", "0.38.1", "25.0.0", `{"replication":{"syncBinlog":1}}`, true, ExitOK, ""},
		{"incomplete-present", "25.8.4", "25.10.4", `{"maxScale":{}}`, false, ExitUnknown, ""},
		{"incomplete-absent", "0.38.1", "25.0.0", `{}`, false, ExitUnknown, ""},
		{"ambiguous-case", "25.8.4", "25.10.4", `{"MaxScale":{}}`, true, ExitUnknown, ""},
		{"ambiguous-type", "0.38.1", "25.0.0", `{"replication":{"syncBinlog":"1"}}`, true, ExitUnknown, ""},
		{"duplicate-key", "25.8.4", "25.10.4", `{"maxScale":{},"maxScale":{}}`, true, ExitUsage, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := writeMariaDBCRDResource(t, tc.spec)
			args := []string{"check", "project", "--project", "mariadb-operator", "--mariadb-resource", path, "--from", tc.from, "--to", tc.to, "--now", "2026-11-10T09:00:00Z", "--format", "json"}
			if tc.complete {
				args = append(args, "--resource-complete")
			}
			var out, stderr bytes.Buffer
			exit := Run(t.Context(), args, &out, &stderr, "test")
			if exit != tc.wantExit || strings.Contains(out.String(), "PRIVATE_OPERATOR_CRD") || strings.Contains(stderr.String(), "PRIVATE_OPERATOR_CRD") {
				t.Fatalf("exit=%d want=%d stdout=%s stderr=%s", exit, tc.wantExit, out.String(), stderr.String())
			}
			if tc.wantExit == ExitUsage {
				return
			}
			var report projectcheck.Report
			if err := json.Unmarshal(out.Bytes(), &report); err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(out.String(), "WHOLE_UPGRADE_COMPATIBILITY_NOT_EVALUATED") || !strings.Contains(out.String(), "HELM_VALUES_FLAGS_DATA_PLANE_AND_REPLICATION_MIGRATION_STEPS_NOT_EVALUATED") {
				t.Fatalf("scope limits missing from the report: %s", out.String())
			}
			for _, claim := range report.Check.Claims {
				want := "PASS"
				if tc.wantExit == ExitUnknown {
					want = "UNKNOWN"
				}
				if claim.RuleID == tc.wantBlocked {
					want = "BLOCKED"
				} else if tc.wantExit == ExitBlocked {
					want = "PASS"
				}
				if claim.Status != want || len(claim.Sources) == 0 {
					t.Fatalf("claim %s = %s want %s", claim.RuleID, claim.Status, want)
				}
			}
			if len(report.Check.Claims) == 0 {
				t.Fatalf("no claims: %s", out.String())
			}
			// A present, mismatching source assertion is an integrity error.
			out.Reset()
			stderr.Reset()
			bad := append(append([]string{}, args...), "--mariadb-resource-digest", "sha256:"+strings.Repeat("0", 64))
			if code := Run(t.Context(), bad, &out, &stderr, "test"); code != ExitIntegrity {
				t.Fatalf("digest mismatch exit %d", code)
			}
		})
	}
}

func TestMariaDBOperatorCRDPairRouteRefusesWrongFlagsAndPairs(t *testing.T) {
	path := writeMariaDBCRDResource(t, `{"maxScale":{}}`)
	base := []string{"check", "project", "--project", "mariadb-operator", "--mariadb-resource", path, "--resource-complete", "--format", "json"}
	for _, tc := range []struct {
		name string
		args []string
		want int
	}{
		{"pre-operator-update-flag", append(append([]string{}, base...), "--from", "25.8.4", "--to", "25.10.4", "--pre-operator-update", "--now", "2026-11-10T09:00:00Z"), ExitUsage},
		{"knowledge-db", append(append([]string{}, base...), "--from", "25.8.4", "--to", "25.10.4", "--knowledge-db", t.TempDir()), ExitUsage},
		{"now-missing", append(append([]string{}, base...), "--from", "25.8.4", "--to", "25.10.4"), ExitUsage},
		{"spanning-pair", append(append([]string{}, base...), "--from", "0.38.1", "--to", "25.10.4", "--now", "2026-11-10T09:00:00Z"), ExitUnknown},
		{"patch-neighbour", append(append([]string{}, base...), "--from", "25.8.3", "--to", "25.10.4", "--now", "2026-11-10T09:00:00Z"), ExitUnknown},
		{"leading-zero-line", append(append([]string{}, base...), "--from", "25.08.0", "--to", "25.10.4", "--now", "2026-11-10T09:00:00Z"), -1},
		{"uncovered-pair", append(append([]string{}, base...), "--from", "25.0.0", "--to", "25.8.4", "--now", "2026-11-10T09:00:00Z"), ExitUnknown},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var out, stderr bytes.Buffer
			exit := Run(t.Context(), tc.args, &out, &stderr, "test")
			if tc.want == -1 {
				if exit == ExitOK || exit == ExitBlocked {
					t.Fatalf("exit=%d stdout=%s", exit, out.String())
				}
				return
			}
			if exit != tc.want {
				t.Fatalf("exit=%d want=%d stdout=%s stderr=%s", exit, tc.want, out.String(), stderr.String())
			}
			if exit == ExitUnknown {
				var report projectcheck.Report
				if err := json.Unmarshal(out.Bytes(), &report); err != nil {
					t.Fatal(err)
				}
				for _, claim := range report.Check.Claims {
					if claim.Status == "PASS" || claim.Status == "BLOCKED" {
						t.Fatalf("pair outside the reviewed set was decided: %+v", claim)
					}
				}
			}
		})
	}
}

func TestMariaDBOperatorCRDPairRoutesDoNotChangeTheGaleraRoute(t *testing.T) {
	// The Galera prerequisite route still refuses a CRD-pair declaration shape
	// and still accepts its own flags for its own pair.
	path := writeMariaDBCRDResource(t, `{"galera":{"enabled":true},"updateStrategy":{"autoUpdateDataPlane":true}}`)
	args := []string{"check", "project", "--project", "mariadb-operator", "--mariadb-resource", path, "--from", "26.3.0", "--to", "26.6.0", "--resource-complete", "--pre-operator-update", "--now", "2026-09-13T09:00:00Z", "--format", "json"}
	var out, stderr bytes.Buffer
	if exit := Run(t.Context(), args, &out, &stderr, "test"); exit != ExitOK || stderr.Len() != 0 {
		t.Fatalf("exit=%d stdout=%s stderr=%s", exit, out.String(), stderr.String())
	}
	var report projectcheck.Report
	if err := json.Unmarshal(out.Bytes(), &report); err != nil || len(report.Check.Claims) != 1 || report.Check.Claims[0].RuleID != "mariadb-operator.upgrade-26-6.requires-dataplane-prerequisite" {
		t.Fatalf("galera route changed: %v %s", err, out.String())
	}
}
