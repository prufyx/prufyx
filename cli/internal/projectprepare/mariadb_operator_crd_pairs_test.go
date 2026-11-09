// SPDX-License-Identifier: AGPL-3.0-only

package projectprepare

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

const crdPairResource = `{"apiVersion":"k8s.mariadb.com/v1alpha1","kind":"MariaDB","metadata":{"name":"PRIVATE_CRD_PAIR"},"spec":%s}`

// factValues decodes the prepared input into fact id -> (state, bool).
func factValues(t *testing.T, canonical []byte) map[string]string {
	t.Helper()
	var doc struct {
		Proposed struct {
			Components []struct {
				Facts []struct {
					ID        string `json:"id"`
					State     string `json:"state"`
					BoolValue *bool  `json:"boolValue"`
				} `json:"facts"`
			} `json:"components"`
		} `json:"proposed"`
	}
	if err := json.Unmarshal(canonical, &doc); err != nil || len(doc.Proposed.Components) != 1 {
		t.Fatalf("decode: %v", err)
	}
	out := map[string]string{}
	for _, f := range doc.Proposed.Components[0].Facts {
		switch {
		case f.State != "declared":
			out[f.ID] = f.State
		case f.BoolValue == nil:
			out[f.ID] = "declared-nil"
		default:
			out[f.ID] = fmt.Sprint(*f.BoolValue)
		}
	}
	return out
}

func TestMariaDBOperatorCRDPairsAreExactAndClosed(t *testing.T) {
	for _, tc := range []struct {
		from, to string
		want     bool
	}{
		{"0.38.1", "25.0.0", true},
		{"25.8.4", "25.10.4", true},
		{"25.0.0", "25.8.4", false},
		{"25.10.4", "26.3.0", false},
		{"26.3.0", "26.6.0", false}, // the Galera prerequisite pair keeps its own route
		{"26.6.0", "26.10.2", false},
		{"0.38.1", "25.10.4", false}, // spans both pairs: not accepted as either
		{"25.8.3", "25.10.4", false},
		{"25.8.4", "25.10.3", false},
		{"25.08.0", "25.10.4", false},
		{"25.10.4", "25.8.4", false}, // downgrade
		{"", "", false},
	} {
		if got := IsMariaDBOperatorCRDPair(tc.from, tc.to); got != tc.want {
			t.Errorf("%s->%s: got %v want %v", tc.from, tc.to, got, tc.want)
		}
	}
	if MariaDBOperatorCRDFacts("26.3.0", "26.6.0") != nil {
		t.Fatal("a non-CRD pair declared CRD facts")
	}
}

func TestMariaDBOperatorCRDPairFieldFacts(t *testing.T) {
	for _, pair := range mariaDBOperatorCRDPairs {
		for _, field := range pair.Fields {
			field := field
			t.Run(pair.From+"-"+pair.To+"/"+field.Fact, func(t *testing.T) {
				present := nestedSpec(field.Path, `true`)
				if !field.BooleanType {
					present = nestedSpec(field.Path, `"x"`)
				}
				for _, tc := range []struct {
					name, spec string
					complete   bool
					wantState  string
					wantThis   string
				}{
					{"present", present, true, "PREPARED", "true"},
					{"absent", `{"replication":{"enabled":false}}`, true, "PREPARED", "false"},
					{"incomplete", present, false, "UNKNOWN", "unsupported"},
				} {
					prepared, err := PrepareMariaDBOperatorResource([]byte(fmt.Sprintf(crdPairResource, tc.spec)), pair.From, pair.To, tc.complete, false)
					if err != nil || prepared.State != tc.wantState {
						t.Fatalf("%s: state=%q reason=%q err=%v", tc.name, prepared.State, prepared.Reason, err)
					}
					facts := factValues(t, prepared.CanonicalInputJSON)
					if facts[field.Fact] != tc.wantThis {
						t.Fatalf("%s: fact %s = %q want %q", tc.name, field.Fact, facts[field.Fact], tc.wantThis)
					}
					if facts[MariaDBOperatorResourceCompleteFact] != fmt.Sprint(tc.complete) {
						t.Fatalf("%s: completeness not carried: %v", tc.name, facts)
					}
					if len(facts) != len(pair.Fields)+1 {
						t.Fatalf("%s: unexpected fact set %v", tc.name, facts)
					}
					for _, other := range pair.Fields {
						if other.Fact != field.Fact && tc.name == "present" && facts[other.Fact] != "false" {
							t.Fatalf("%s: unrelated fact %s = %q", tc.name, other.Fact, facts[other.Fact])
						}
					}
					if bytes.Contains(prepared.CanonicalInputJSON, []byte("PRIVATE_CRD_PAIR")) {
						t.Fatal("private metadata leaked into the prepared input")
					}
				}
			})
		}
	}
}

// nestedSpec builds {"a":{"b":{"c":VALUE}}} for path [a b c].
func nestedSpec(path []string, value string) string {
	out := value
	for i := len(path) - 1; i >= 0; i-- {
		out = fmt.Sprintf(`{%q:%s}`, path[i], out)
	}
	return out
}

func TestMariaDBOperatorCRDPairNullValueCountsAsPresent(t *testing.T) {
	prepared, err := PrepareMariaDBOperatorResource([]byte(fmt.Sprintf(crdPairResource, `{"maxScale":null}`)), "25.8.4", "25.10.4", true, false)
	if err != nil || prepared.State != "PREPARED" || factValues(t, prepared.CanonicalInputJSON)[MariaDBOperatorEmbeddedMaxScaleFact] != "true" {
		t.Fatalf("null key must still block: %+v err=%v", prepared, err)
	}
}

func TestMariaDBOperatorSyncBinlogTypeIsReadNotTheValue(t *testing.T) {
	for _, tc := range []struct {
		name, value, want string
		state             string
	}{
		{"true", `true`, "true", "PREPARED"},
		{"false", `false`, "true", "PREPARED"},
		{"integer", `1`, "false", "PREPARED"},
		{"zero", `0`, "false", "PREPARED"},
		{"large", `1000000`, "false", "PREPARED"},
		{"string", `"true"`, "unsupported", "UNKNOWN"},
		{"null", `null`, "unsupported", "UNKNOWN"},
		{"object", `{}`, "unsupported", "UNKNOWN"},
		{"array", `[]`, "unsupported", "UNKNOWN"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			spec := fmt.Sprintf(`{"replication":{"syncBinlog":%s}}`, tc.value)
			prepared, err := PrepareMariaDBOperatorResource([]byte(fmt.Sprintf(crdPairResource, spec)), "0.38.1", "25.0.0", true, false)
			if err != nil || prepared.State != tc.state {
				t.Fatalf("state=%q reason=%q err=%v", prepared.State, prepared.Reason, err)
			}
			if got := factValues(t, prepared.CanonicalInputJSON)[MariaDBOperatorSyncBinlogBooleanFact]; got != tc.want {
				t.Fatalf("fact=%q want %q", got, tc.want)
			}
		})
	}
}

func TestMariaDBOperatorCRDPairAmbiguousShapesFailClosed(t *testing.T) {
	for _, tc := range []struct {
		name, from, to, raw string
	}{
		{"case-variant-leaf", "25.8.4", "25.10.4", fmt.Sprintf(crdPairResource, `{"galera":{"primary":{"AutomaticFailover":true}}}`)},
		{"case-variant-parent", "25.8.4", "25.10.4", fmt.Sprintf(crdPairResource, `{"Replication":{"probesEnabled":true}}`)},
		{"case-variant-and-exact", "25.8.4", "25.10.4", fmt.Sprintf(crdPairResource, `{"maxScale":{},"MaxScale":{}}`)},
		{"parent-not-object", "25.8.4", "25.10.4", fmt.Sprintf(crdPairResource, `{"galera":"enabled"}`)},
		{"parent-null", "25.8.4", "25.10.4", fmt.Sprintf(crdPairResource, `{"replication":null}`)},
		{"parent-array", "25.8.4", "25.10.4", fmt.Sprintf(crdPairResource, `{"replication":{"replica":[]}}`)},
		{"sync-binlog-parent-not-object", "0.38.1", "25.0.0", fmt.Sprintf(crdPairResource, `{"replication":true}`)},
		{"sync-binlog-case-variant", "0.38.1", "25.0.0", fmt.Sprintf(crdPairResource, `{"replication":{"SyncBinlog":true}}`)},
		{"wrong-api", "25.8.4", "25.10.4", `{"apiVersion":"k8s.mariadb.com/v1beta1","kind":"MariaDB","spec":{}}`},
		{"wrong-kind", "25.8.4", "25.10.4", `{"apiVersion":"k8s.mariadb.com/v1alpha1","kind":"Backup","spec":{}}`},
		{"kind-case", "25.8.4", "25.10.4", `{"apiVersion":"k8s.mariadb.com/v1alpha1","kind":"mariadb","spec":{}}`},
		{"no-spec", "25.8.4", "25.10.4", `{"apiVersion":"k8s.mariadb.com/v1alpha1","kind":"MariaDB"}`},
		{"spec-case", "25.8.4", "25.10.4", `{"apiVersion":"k8s.mariadb.com/v1alpha1","kind":"MariaDB","Spec":{"maxScale":{}}}`},
		{"spec-not-object", "25.8.4", "25.10.4", `{"apiVersion":"k8s.mariadb.com/v1alpha1","kind":"MariaDB","spec":[]}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			prepared, err := PrepareMariaDBOperatorResource([]byte(tc.raw), tc.from, tc.to, true, false)
			if err != nil || prepared.State != "UNKNOWN" || prepared.Reason != "MARIADB_OPERATOR_RESOURCE_SHAPE_UNSUPPORTED" {
				t.Fatalf("state=%q reason=%q err=%v", prepared.State, prepared.Reason, err)
			}
			for id, state := range factValues(t, prepared.CanonicalInputJSON) {
				if id != MariaDBOperatorResourceCompleteFact && state != "unsupported" {
					t.Fatalf("fact %s = %q on an ambiguous shape", id, state)
				}
			}
		})
	}
}

func TestMariaDBOperatorCRDPairInvalidInputsAreErrors(t *testing.T) {
	for name, raw := range map[string]string{
		"empty":        ``,
		"not-json":     `spec: {}`,
		"duplicate":    `{"apiVersion":"k8s.mariadb.com/v1alpha1","kind":"MariaDB","spec":{"maxScale":{},"maxScale":null}}`,
		"trailing":     `{"apiVersion":"k8s.mariadb.com/v1alpha1","kind":"MariaDB","spec":{}} {}`,
		"top-array":    `[]`,
		"top-scalar":   `1`,
		"oversize-ish": `{"apiVersion":"k8s.mariadb.com/v1alpha1","kind":"MariaDB","spec":{"x":"` + strings.Repeat("a", maxInputBytes) + `"}}`,
	} {
		if _, err := PrepareMariaDBOperatorResource([]byte(raw), "25.8.4", "25.10.4", true, false); err != ErrInvalid {
			t.Errorf("%s: err=%v", name, err)
		}
	}
}

func TestMariaDBOperatorCRDPairRefusesPreOperatorUpdateDeclaration(t *testing.T) {
	for _, pair := range mariaDBOperatorCRDPairs {
		if _, err := PrepareMariaDBOperatorResource([]byte(fmt.Sprintf(crdPairResource, `{}`)), pair.From, pair.To, true, true); err != ErrInvalid {
			t.Fatalf("%s->%s accepted a pre-operator-update declaration: %v", pair.From, pair.To, err)
		}
	}
}

func TestMariaDBOperatorOtherPairsKeepTheGaleraRoute(t *testing.T) {
	// A pair that is not a CRD pair still reaches the original preparer and is
	// refused as an unsupported pair, never answered with CRD facts.
	for _, tc := range [][2]string{{"25.0.0", "25.8.4"}, {"25.10.4", "26.3.0"}, {"26.6.0", "26.10.2"}, {"0.38.1", "25.10.4"}} {
		prepared, err := PrepareMariaDBOperatorResource([]byte(fmt.Sprintf(crdPairResource, `{"galera":{"enabled":true},"updateStrategy":{"autoUpdateDataPlane":false}}`)), tc[0], tc[1], true, true)
		if err != nil || prepared.State != "UNKNOWN" || prepared.Reason != "UNSUPPORTED_VERSION_PAIR" {
			t.Fatalf("%v: state=%q reason=%q err=%v", tc, prepared.State, prepared.Reason, err)
		}
	}
}

func TestMariaDBOperatorCRDPairFactIDsAreUniqueAndScoped(t *testing.T) {
	seen := map[string]string{}
	for _, pair := range mariaDBOperatorCRDPairs {
		for _, id := range MariaDBOperatorCRDFacts(pair.From, pair.To) {
			if !strings.HasPrefix(id, "component.mariadb_operator.") || seen[id] != "" {
				t.Fatalf("fact id %q is unscoped or shared between pairs", id)
			}
			seen[id] = pair.From + "-" + pair.To
		}
	}
}
