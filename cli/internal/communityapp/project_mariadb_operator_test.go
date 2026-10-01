// SPDX-License-Identifier: AGPL-3.0-only

package communityapp

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const mariadbOperatorTestResource = `{"apiVersion":"k8s.mariadb.com/v1alpha1","kind":"MariaDB","metadata":{"name":"PRIVATE_OPERATOR_NATIVE"},"spec":{"galera":{"enabled":true},"updateStrategy":{"autoUpdateDataPlane":true}}}`

func TestMariaDBOperatorNativeGuardsRemainUnknownWhenOmitted(t *testing.T) {
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
