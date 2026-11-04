// SPDX-License-Identifier: AGPL-3.0-only

package projectprepare

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
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

func TestMariaDBOperatorPreservesIndependentFacts(t *testing.T) {
	for _, tc := range []struct {
		name, spec                string
		galera, replication, auto *bool
	}{
		{"missing-auto", `"galera":{"enabled":true},"updateStrategy":{}`, operatorBoolPointer(true), operatorBoolPointer(false), nil},
		{"null-auto", `"galera":{"enabled":true},"updateStrategy":{"autoUpdateDataPlane":null}`, operatorBoolPointer(true), operatorBoolPointer(false), nil},
		{"string-auto", `"galera":{"enabled":true},"updateStrategy":{"autoUpdateDataPlane":"false"}`, operatorBoolPointer(true), operatorBoolPointer(false), nil},
		{"case-auto", `"galera":{"enabled":true},"updateStrategy":{"autoUpdateDataPlane":false,"AutoUpdateDataPlane":true}`, operatorBoolPointer(true), operatorBoolPointer(false), nil},
		{"invalid-galera", `"galera":{"enabled":"true"},"updateStrategy":{"autoUpdateDataPlane":true}`, nil, operatorBoolPointer(false), operatorBoolPointer(true)},
		{"invalid-replication", `"galera":{"enabled":true},"replication":{"enabled":null},"updateStrategy":{"autoUpdateDataPlane":false}`, operatorBoolPointer(true), nil, operatorBoolPointer(false)},
		{"case-replication", `"galera":{"enabled":true},"Replication":{"enabled":false},"updateStrategy":{"autoUpdateDataPlane":true}`, operatorBoolPointer(true), nil, operatorBoolPointer(true)},
		{"case-strategy", `"galera":{"enabled":true},"UpdateStrategy":{"autoUpdateDataPlane":true}`, operatorBoolPointer(true), operatorBoolPointer(false), nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := []byte(`{"apiVersion":"k8s.mariadb.com/v1alpha1","kind":"MariaDB","metadata":{"name":"PRIVATE_PARTIAL_RESOURCE"},"spec":{` + tc.spec + `}}`)
			p, err := PrepareMariaDBOperatorResource(raw, MariaDBOperatorFrom, MariaDBOperatorTo, true, true)
			if err != nil || p.State != "UNKNOWN" {
				t.Fatalf("preparation %+v %v", p, err)
			}
			var doc struct {
				Proposed struct{ Components []struct{ Facts []inputFact } }
			}
			if err := json.Unmarshal(p.CanonicalInputJSON, &doc); err != nil {
				t.Fatal(err)
			}
			facts := doc.Proposed.Components[0].Facts
			for i, want := range []*bool{tc.auto, tc.galera, operatorBoolPointer(true), tc.replication, operatorBoolPointer(true)} {
				f := facts[i]
				if want == nil {
					if f.State != "unsupported" || f.BoolValue != nil {
						t.Fatalf("unknown became Boolean %+v", f)
					}
				} else if f.State != "declared" || f.BoolValue == nil || *f.BoolValue != *want {
					t.Fatalf("independent fact lost %+v", f)
				}
			}
			if p.SourceDigest != digest(raw) || p.InputDigest != digest(p.CanonicalInputJSON) || bytes.Contains(p.CanonicalInputJSON, []byte("PRIVATE_PARTIAL_RESOURCE")) {
				t.Fatal("digest/privacy contract")
			}
		})
	}
}

func TestMariaDBOperatorIdentityFailureDiscardsAllFacts(t *testing.T) {
	base := `{"apiVersion":"k8s.mariadb.com/v1alpha1","kind":"MariaDB","spec":{"galera":{"enabled":true},"updateStrategy":{"autoUpdateDataPlane":true}}}`
	for _, tc := range []struct{ name, raw, from string }{
		{"pair", base, "26.2.0"},
		{"api", strings.Replace(base, "k8s.mariadb.com/v1alpha1", "other/v1", 1), MariaDBOperatorFrom},
		{"kind", strings.Replace(base, `"kind":"MariaDB"`, `"kind":"Other"`, 1), MariaDBOperatorFrom},
		{"spec-type", `{"apiVersion":"k8s.mariadb.com/v1alpha1","kind":"MariaDB","spec":[]}`, MariaDBOperatorFrom},
		{"api-case", strings.Replace(base, `"apiVersion":`, `"ApiVersion":`, 1), MariaDBOperatorFrom},
		{"spec-case", strings.Replace(base, `"spec":`, `"Spec":`, 1), MariaDBOperatorFrom},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, err := PrepareMariaDBOperatorResource([]byte(tc.raw), tc.from, MariaDBOperatorTo, true, true)
			if err != nil || p.State != "UNKNOWN" {
				t.Fatalf("%+v %v", p, err)
			}
			if bytes.Contains(p.CanonicalInputJSON, []byte(`"state":"declared"`)) || bytes.Contains(p.CanonicalInputJSON, []byte(`"boolValue"`)) {
				t.Fatalf("identity bypass %s", p.CanonicalInputJSON)
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
