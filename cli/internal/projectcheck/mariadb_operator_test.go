// SPDX-License-Identifier: AGPL-3.0-only

package projectcheck

import (
	"bytes"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/projectprepare"
)

func TestMariaDBOperatorScopedOutcomesAndPrivacy(t *testing.T) {
	now := time.Date(2026, 9, 13, 9, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name, raw            string
		wantExit, wantStatus int
	}{
		{"pass", `{"apiVersion":"k8s.mariadb.com/v1alpha1","kind":"MariaDB","metadata":{"name":"PRIVATE_OPERATOR"},"spec":{"galera":{"enabled":true},"updateStrategy":{"autoUpdateDataPlane":true}}}`, 0, 0},
		{"blocked", `{"apiVersion":"k8s.mariadb.com/v1alpha1","kind":"MariaDB","spec":{"galera":{"enabled":true},"updateStrategy":{"autoUpdateDataPlane":false}}}`, 10, 10},
		{"replication-conflict", `{"apiVersion":"k8s.mariadb.com/v1alpha1","kind":"MariaDB","spec":{"galera":{"enabled":true},"replication":{"enabled":true},"updateStrategy":{"autoUpdateDataPlane":false}}}`, 11, 11},
		{"galera-disabled", `{"apiVersion":"k8s.mariadb.com/v1alpha1","kind":"MariaDB","spec":{"galera":{"enabled":false},"updateStrategy":{"autoUpdateDataPlane":false}}}`, 11, 11},
		{"missing-phase-declaration", `{"apiVersion":"k8s.mariadb.com/v1alpha1","kind":"MariaDB","spec":{"galera":{"enabled":true},"updateStrategy":{"autoUpdateDataPlane":false}}}`, 11, 11},
	} {
		t.Run(tc.name, func(t *testing.T) {
			complete, phase := true, true
			if tc.name == "missing-phase-declaration" {
				complete, phase = false, false
			}
			prepared, err := projectprepare.PrepareMariaDBOperatorResource([]byte(tc.raw), projectprepare.MariaDBOperatorFrom, projectprepare.MariaDBOperatorTo, complete, phase)
			if err != nil {
				t.Fatal(err)
			}
			report, err := CheckRule(projectprepare.MariaDBOperatorProject, prepared.CanonicalInputJSON, now, "mariadb-operator.upgrade-26-6.requires-dataplane-prerequisite")
			if err != nil {
				t.Fatal(err)
			}
			if got := ClaimExit(report); got != tc.wantExit {
				t.Fatalf("exit=%d want=%d report=%+v", got, tc.wantExit, report)
			}
			if len(report.Check.Claims) != 1 {
				t.Fatalf("claims=%d", len(report.Check.Claims))
			}
			if got := map[string]int{"PASS": 0, "BLOCKED": 10, "UNKNOWN": 11}[report.Check.Claims[0].Status]; got != tc.wantStatus {
				t.Fatalf("status=%s", report.Check.Claims[0].Status)
			}
			encoded, err := MarshalReport(report)
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Contains(encoded, []byte("PRIVATE_OPERATOR")) {
				t.Fatalf("private resource leaked: %s", encoded)
			}
		})
	}
}

func TestMariaDBOperatorUnknownForWrongPairOrPhase(t *testing.T) {
	raw := []byte(`{"apiVersion":"k8s.mariadb.com/v1alpha1","kind":"MariaDB","spec":{"galera":{"enabled":true},"updateStrategy":{"autoUpdateDataPlane":true}}}`)
	for _, tc := range []struct {
		from, to        string
		complete, phase bool
		claims          int
	}{
		{"26.3.0", "26.6.1", true, true, 0},
		{"26.3.0", "26.6.0", true, false, 1},
		{"26.3.0", "26.6.0", false, true, 1},
	} {
		prepared, err := projectprepare.PrepareMariaDBOperatorResource(raw, tc.from, tc.to, tc.complete, tc.phase)
		if err != nil {
			t.Fatal(err)
		}
		report, err := CheckRule(projectprepare.MariaDBOperatorProject, prepared.CanonicalInputJSON, time.Date(2026, 9, 13, 9, 0, 0, 0, time.UTC), "mariadb-operator.upgrade-26-6.requires-dataplane-prerequisite")
		if err != nil || ClaimExit(report) != 11 || len(report.Check.Claims) != tc.claims {
			t.Fatalf("report=%+v err=%v", report, err)
		}
		if tc.claims == 1 && report.Check.Claims[0].Status != "UNKNOWN" {
			t.Fatalf("report=%+v", report)
		}
	}
}
