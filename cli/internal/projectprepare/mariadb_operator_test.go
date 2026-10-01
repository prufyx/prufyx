// SPDX-License-Identifier: AGPL-3.0-only

package projectprepare

import (
	"bytes"
	"fmt"
	"testing"
)

func TestPrepareMariaDBOperatorResourceTriStateInputs(t *testing.T) {
	base := `{"apiVersion":"k8s.mariadb.com/v1alpha1","kind":"MariaDB","metadata":{"name":"PRIVATE_CANARY"},"spec":{"galera":{"enabled":true},"updateStrategy":{"autoUpdateDataPlane":%s}}}`
	for _, tc := range []struct {
		name, raw       string
		complete, phase bool
		wantState       string
	}{
		{"pass", base + "", true, true, "PREPARED"},
		{"blocked", base + "", true, true, "PREPARED"},
		{"incomplete", base + "", false, true, "UNKNOWN"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			value := "true"
			if tc.name == "blocked" {
				value = "false"
			}
			prepared, err := PrepareMariaDBOperatorResource([]byte(fmt.Sprintf(tc.raw, value)), MariaDBOperatorFrom, MariaDBOperatorTo, tc.complete, tc.phase)
			if err != nil || prepared.State != tc.wantState {
				t.Fatalf("state=%q err=%v", prepared.State, err)
			}
			if bytes.Contains(prepared.CanonicalInputJSON, []byte("PRIVATE_CANARY")) {
				t.Fatal("private metadata leaked")
			}
			if !bytes.Contains(prepared.CanonicalInputJSON, []byte(`"id":"component.mariadb_operator.auto_update_data_plane"`)) {
				t.Fatal("auto-update fact missing")
			}
			if !bytes.Contains(prepared.CanonicalInputJSON, []byte(`"id":"component.mariadb_operator.pre_operator_update"`)) || !bytes.Contains(prepared.CanonicalInputJSON, []byte(`"id":"component.mariadb_operator.resource_complete"`)) {
				t.Fatal("guard facts missing")
			}
		})
	}
}

func TestPrepareMariaDBOperatorResourceRejectsMalformedAndAmbiguousShape(t *testing.T) {
	for _, raw := range []string{
		`{"apiVersion":"k8s.mariadb.com/v1alpha1","kind":"MariaDB","spec":{"galera":{"enabled":true},"updateStrategy":{"autoUpdateDataPlane":true},"updateStrategy":{"autoUpdateDataPlane":false}}}`,
	} {
		if _, err := PrepareMariaDBOperatorResource([]byte(raw), MariaDBOperatorFrom, MariaDBOperatorTo, true, true); err == nil {
			t.Fatalf("accepted ambiguous resource: %s", raw)
		}
	}
	validButUnsupported := `{"apiVersion":"k8s.mariadb.com/v1alpha1","kind":"MariaDB","spec":{"galera":{"enabled":"true"},"updateStrategy":{"autoUpdateDataPlane":true}}}`
	prepared, err := PrepareMariaDBOperatorResource([]byte(validButUnsupported), MariaDBOperatorFrom, MariaDBOperatorTo, true, true)
	if err != nil || prepared.State != "UNKNOWN" {
		t.Fatalf("typed ambiguity should remain UNKNOWN: state=%s err=%v", prepared.State, err)
	}
	nullReplication := `{"apiVersion":"k8s.mariadb.com/v1alpha1","kind":"MariaDB","spec":{"galera":{"enabled":true},"replication":{"enabled":null},"updateStrategy":{"autoUpdateDataPlane":true}}}`
	prepared, err = PrepareMariaDBOperatorResource([]byte(nullReplication), MariaDBOperatorFrom, MariaDBOperatorTo, true, true)
	if err != nil || prepared.State != "UNKNOWN" {
		t.Fatalf("null replication should remain UNKNOWN: state=%s err=%v", prepared.State, err)
	}
}
