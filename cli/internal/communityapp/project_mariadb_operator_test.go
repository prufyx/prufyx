// SPDX-License-Identifier: AGPL-3.0-only

package communityapp

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/projectcheck"
	"github.com/prufyx/prufyx/cli/internal/projectprepare"
)

const mariadbOperatorTestResource = `{"apiVersion":"k8s.mariadb.com/v1alpha1","kind":"MariaDB","metadata":{"name":"PRIVATE_OPERATOR_NATIVE"},"spec":{"galera":{"enabled":true},"updateStrategy":{"autoUpdateDataPlane":true}}}`

func TestMariaDBOperatorPartialFactsReachActualCheck(t *testing.T) {
	base := mariadbOperatorTestResource
	for _, tc := range []struct {
		name, raw string
		want      int
	}{
		{"missing-auto", strings.Replace(base, `"autoUpdateDataPlane":true`, ``, 1), ExitUnknown},
		{"true", base, ExitOK},
		{"false", strings.Replace(base, `"autoUpdateDataPlane":true`, `"autoUpdateDataPlane":false`, 1), ExitBlocked},
		{"null-auto", strings.Replace(base, `"autoUpdateDataPlane":true`, `"autoUpdateDataPlane":null`, 1), ExitUnknown},
		{"string-auto", strings.Replace(base, `"autoUpdateDataPlane":true`, `"autoUpdateDataPlane":"false"`, 1), ExitUnknown},
		{"case-auto", strings.Replace(base, `"autoUpdateDataPlane":true`, `"AutoUpdateDataPlane":true`, 1), ExitUnknown},
		{"ambiguous-auto", strings.Replace(base, `"autoUpdateDataPlane":true`, `"autoUpdateDataPlane":false,"AutoUpdateDataPlane":true`, 1), ExitUnknown},
		{"duplicate-auto", strings.Replace(base, `"autoUpdateDataPlane":true`, `"autoUpdateDataPlane":true,"autoUpdateDataPlane":false`, 1), ExitUsage},
		{"invalid-galera", strings.Replace(base, `"enabled":true`, `"enabled":"true"`, 1), ExitUnknown},
		{"standalone", strings.Replace(base, `"enabled":true`, `"enabled":false`, 1), ExitUnknown},
		{"replication", strings.Replace(base, `"galera":`, `"replication":{"enabled":true},"galera":`, 1), ExitUnknown},
		{"invalid-replication", strings.Replace(base, `"galera":`, `"replication":{"enabled":null},"galera":`, 1), ExitUnknown},
		{"case-replication", strings.Replace(base, `"galera":`, `"Replication":{"enabled":false},"galera":`, 1), ExitUnknown},
		{"api", strings.Replace(base, "k8s.mariadb.com/v1alpha1", "other/v1", 1), ExitUnknown},
		{"kind", strings.Replace(base, `"kind":"MariaDB"`, `"kind":"Other"`, 1), ExitUnknown},
		{"spec", strings.Replace(base, `"spec":`, `"Spec":`, 1), ExitUnknown},
		{"pair", base, ExitUnknown},
		{"phase", base, ExitUnknown},
		{"complete", base, ExitUnknown},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "resource.json")
			if err := os.WriteFile(path, []byte(tc.raw), 0o600); err != nil {
				t.Fatal(err)
			}
			from := "26.3.0"
			if tc.name == "pair" {
				from = "26.2.0"
			}
			args := []string{"check", "project", "--project", "mariadb-operator", "--mariadb-resource", path, "--from", from, "--to", "26.6.0", "--now", "2026-09-13T09:00:00Z", "--format", "json"}
			complete, phase := tc.name != "complete", tc.name != "phase"
			if complete {
				args = append(args, "--resource-complete")
			}
			if phase {
				args = append(args, "--pre-operator-update")
			}
			var out, stderr bytes.Buffer
			exit := Run(t.Context(), args, &out, &stderr, "test")
			if exit != tc.want || strings.Contains(out.String(), "PRIVATE_OPERATOR_NATIVE") {
				t.Fatalf("exit=%d want=%d stdout=%s stderr=%s", exit, tc.want, out.String(), stderr.String())
			}
			if tc.want == ExitUsage {
				return
			}
			if stderr.Len() != 0 {
				t.Fatal(stderr.String())
			}
			var report projectcheck.Report
			if err := json.Unmarshal(out.Bytes(), &report); err != nil {
				t.Fatal(err)
			}
			if tc.name == "pair" {
				if len(report.Check.Claims) != 0 || !strings.Contains(report.NextAction, "no reviewed rule matches") {
					t.Fatalf("unsupported pair invented a claim: %s", out.String())
				}
			} else {
				if len(report.Check.Claims) != 1 || report.Check.Claims[0].RuleID != "mariadb-operator.upgrade-26-6.requires-dataplane-prerequisite" {
					t.Fatalf("wrong claim %s", out.String())
				}
				claim := report.Check.Claims[0]
				want := "UNKNOWN"
				if tc.want == ExitOK {
					want = "PASS"
				}
				if tc.want == ExitBlocked {
					want = "BLOCKED"
				}
				if claim.Status != want || len(claim.Sources) == 0 {
					t.Fatalf("claim %+v", claim)
				}
				if tc.name == "missing-auto" {
					if claim.ReasonCode != "RULE_FACT_UNAVAILABLE" || !strings.Contains(claim.NextAction, projectprepare.MariaDBOperatorAutoUpdateFact) || strings.Contains(claim.NextAction, projectprepare.MariaDBOperatorGaleraFact) {
						t.Fatalf("missing setting was not identified: %+v", claim)
					}
					found := false
					for _, f := range claim.RequiredFacts {
						if f.FactID == projectprepare.MariaDBOperatorAutoUpdateFact {
							found = true
						}
					}
					if !found {
						t.Fatal("missing auto-update fact not named")
					}
				}
			}
			prepared, err := projectprepare.PrepareMariaDBOperatorResource([]byte(tc.raw), from, "26.6.0", complete, phase)
			if err != nil {
				t.Fatal(err)
			}
			if report.InputFileDigest != prepared.InputDigest || prepared.SourceDigest != fmt.Sprintf("sha256:%x", sha256.Sum256([]byte(tc.raw))) {
				t.Fatal("digest binding mismatch")
			}
			// A present mismatched source assertion must be an integrity error.
			out.Reset()
			stderr.Reset()
			bad := append(append([]string{}, args...), "--mariadb-resource-digest", "sha256:"+strings.Repeat("0", 64))
			if code := Run(t.Context(), bad, &out, &stderr, "test"); code != ExitIntegrity {
				t.Fatalf("digest mismatch exit%d", code)
			}
		})
	}
}

func TestMariaDBOperatorNativeGuardsRemainUnknownWhenOmitted(t *testing.T) {
	t.Parallel()
	resourcePath := filepath.Join(t.TempDir(), "resource.json")
	if err := os.WriteFile(resourcePath, []byte(mariadbOperatorTestResource), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{"check", "project", "--project", "mariadb-operator", "--mariadb-resource", resourcePath, "--from", "26.3.0", "--to", "26.6.0", "--resource-complete", "--now", "2026-09-13T09:00:00Z", "--format", "json"},
		{"check", "project", "--project", "mariadb-operator", "--mariadb-resource", resourcePath, "--from", "26.3.0", "--to", "26.6.0", "--pre-operator-update", "--now", "2026-09-13T09:00:00Z", "--format", "json"},
		{"check", "project", "--project", "mariadb-operator", "--mariadb-resource", resourcePath, "--from", "26.3.0", "--to", "26.6.0", "--now", "2026-09-13T09:00:00Z", "--format", "json"},
	} {
		var stdout, stderr bytes.Buffer
		if exit := Run(t.Context(), args, &stdout, &stderr, "test"); exit != ExitUnknown || stderr.Len() != 0 || !strings.Contains(stdout.String(), `"assessment":"UNKNOWN"`) || strings.Contains(stdout.String(), "PRIVATE_OPERATOR_NATIVE") {
			t.Fatalf("omitted guard accepted: args=%v exit=%d stdout=%s stderr=%s", args, exit, stdout.String(), stderr.String())
		}
	}
}

func TestMariaDBOperatorPreparedGuardsPropagateThroughBatch(t *testing.T) {
	t.Parallel()
	resourcePath := filepath.Join(t.TempDir(), "resource.json")
	if err := os.WriteFile(resourcePath, []byte(mariadbOperatorTestResource), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name                   string
		complete, phase        bool
		wantPrepare, wantBatch int
		wantOutcome            string
	}{
		{"both-declared", true, true, ExitOK, ExitOK, "PASS"},
		{"missing-phase", true, false, ExitUnknown, ExitUnknown, "UNKNOWN"},
		{"missing-completeness", false, true, ExitUnknown, ExitUnknown, "UNKNOWN"},
		{"both-missing", false, false, ExitUnknown, ExitUnknown, "UNKNOWN"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			prepareArgs := []string{"prepare", "project", "--project", "mariadb-operator", "--mariadb-resource", resourcePath, "--from", "26.3.0", "--to", "26.6.0", "--format", "input"}
			if tc.complete {
				prepareArgs = append(prepareArgs, "--resource-complete")
			}
			if tc.phase {
				prepareArgs = append(prepareArgs, "--pre-operator-update")
			}
			var prepareOut, prepareErr bytes.Buffer
			if exit := Run(t.Context(), prepareArgs, &prepareOut, &prepareErr, "test"); exit != tc.wantPrepare || prepareErr.Len() != 0 {
				t.Fatalf("prepare exit=%d want=%d stdout=%s stderr=%s", exit, tc.wantPrepare, prepareOut.String(), prepareErr.String())
			}
			if strings.Contains(prepareOut.String(), "PRIVATE_OPERATOR_NATIVE") || !strings.Contains(prepareOut.String(), `"id":"component.mariadb_operator.pre_operator_update"`) || !strings.Contains(prepareOut.String(), `"id":"component.mariadb_operator.resource_complete"`) {
				t.Fatalf("canonical guard/privacy contract failed: %s", prepareOut.String())
			}
			root := t.TempDir()
			if err := os.WriteFile(filepath.Join(root, "input.json"), prepareOut.Bytes(), 0o600); err != nil {
				t.Fatal(err)
			}
			plan := map[string]any{
				"schema": "prufyx.io/batch-check-plan/v1alpha1", "authority": "OPERATOR_DECLARED_LOCAL_CANONICAL_INPUTS",
				"knowledge": map[string]any{"mode": "embedded_only"},
				"items":     []any{map[string]any{"id": tc.name, "kind": "community_project", "project": "mariadb-operator", "from": "26.3.0", "to": "26.6.0", "inputPath": "input.json"}},
			}
			planRaw, err := json.Marshal(plan)
			if err != nil {
				t.Fatal(err)
			}
			planPath := filepath.Join(root, "plan.json")
			if err := os.WriteFile(planPath, planRaw, 0o600); err != nil {
				t.Fatal(err)
			}
			var batchOut, batchErr bytes.Buffer
			batchExit := Run(t.Context(), []string{"check", "batch", "--plan", planPath, "--root", root, "--now", "2026-09-13T09:00:00Z", "--format", "json"}, &batchOut, &batchErr, "test")
			if batchExit != tc.wantBatch || batchErr.Len() != 0 || !strings.Contains(batchOut.String(), `"outcome":"`+tc.wantOutcome+`"`) || strings.Contains(batchOut.String(), "PRIVATE_OPERATOR_NATIVE") {
				t.Fatalf("batch exit=%d want=%d stdout=%s stderr=%s", batchExit, tc.wantBatch, batchOut.String(), batchErr.String())
			}
		})
	}
}
