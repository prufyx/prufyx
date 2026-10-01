// SPDX-License-Identifier: AGPL-3.0-only

package cncfprepare

import "testing"

func TestPrepareCloudNativePGRequiresMatchingNamespacedIdentity(t *testing.T) {
	current := `{"apiVersion":"postgresql.cnpg.io/v1","kind":"Database","metadata":{"namespace":"payments","name":"ledger","resourceVersion":"17","uid":"2f8a","labels":{"team":"billing"},"managedFields":[{"manager":"kubectl"}]},"spec":{"cluster":{"name":"pg-a","foo":"ignored"},"instances":3},"status":{"phase":"Ready","instances":3}}`
	proposed := `{"apiVersion":"postgresql.cnpg.io/v1","kind":"Database","metadata":{"namespace":"payments","name":"ledger","resourceVersion":"18","uid":"2f8a","annotations":{"change":"planned"},"creationTimestamp":"2026-09-11T10:00:00Z"},"spec":{"cluster":{"name":"pg-b","foo":"changed-but-ignored"},"instances":5},"status":{"phase":"Pending","instances":5}}`
	prepared, err := PrepareCloudNativePG([]byte(`{"current":`+current+`,"proposed":`+proposed+`}`), CloudNativePGFrom, CloudNativePGTo)
	if err != nil || prepared.State != StatePrepared || prepared.Reason != ReasonCloudNativePGChanged {
		t.Fatalf("changed reference = %#v, %v", prepared, err)
	}
	if !containsBytes(prepared.CanonicalInputJSON, `"boolValue":true`) {
		t.Fatalf("changed fact missing: %s", prepared.CanonicalInputJSON)
	}

	proposedSame := `{"apiVersion":"postgresql.cnpg.io/v1","kind":"Database","metadata":{"namespace":"payments","name":"ledger"},"spec":{"cluster":{"name":"pg-a"}}}`
	prepared, err = PrepareCloudNativePG([]byte(`{"current":`+current+`,"proposed":`+proposedSame+`}`), CloudNativePGFrom, CloudNativePGTo)
	if err != nil || prepared.State != StatePrepared || prepared.Reason != ReasonCloudNativePGStable {
		t.Fatalf("unchanged reference = %#v, %v", prepared, err)
	}
}

func TestPrepareCloudNativePGIgnoresUnrelatedNativeFields(t *testing.T) {
	current := `{"apiVersion":"postgresql.cnpg.io/v1","kind":"Database","metadata":{"namespace":"payments","name":"ledger","resourceVersion":"17","labels":{"team":"billing"}},"spec":{"cluster":{"name":"pg-a"},"instances":3},"status":{"phase":"Ready"}}`
	proposed := `{"apiVersion":"postgresql.cnpg.io/v1","kind":"Database","metadata":{"namespace":"payments","name":"ledger","resourceVersion":"18","labels":{"team":"platform"},"annotations":{"note":"unrelated"}},"spec":{"cluster":{"name":"pg-a"},"instances":5},"status":{"phase":"Pending","message":"different"}}`
	prepared, err := PrepareCloudNativePG([]byte(`{"current":`+current+`,"proposed":`+proposed+`}`), CloudNativePGFrom, CloudNativePGTo)
	if err != nil || prepared.State != StatePrepared || prepared.Reason != ReasonCloudNativePGStable {
		t.Fatalf("native object with unrelated fields = %#v, %v", prepared, err)
	}
	if !containsBytes(prepared.CanonicalInputJSON, `"boolValue":false`) {
		t.Fatalf("unchanged fact missing: %s", prepared.CanonicalInputJSON)
	}

	minimal := `{"current":{"apiVersion":"postgresql.cnpg.io/v1","kind":"Database","metadata":{"namespace":"payments","name":"ledger"},"spec":{"cluster":{"name":"pg-a"}}},"proposed":{"apiVersion":"postgresql.cnpg.io/v1","kind":"Database","metadata":{"namespace":"payments","name":"ledger"},"spec":{"cluster":{"name":"pg-a"}}}}`
	minimalPrepared, err := PrepareCloudNativePG([]byte(minimal), CloudNativePGFrom, CloudNativePGTo)
	if err != nil || string(prepared.CanonicalInputJSON) != string(minimalPrepared.CanonicalInputJSON) {
		t.Fatalf("unrelated fields changed canonical result: rich=%s minimal=%s err=%v", prepared.CanonicalInputJSON, minimalPrepared.CanonicalInputJSON, err)
	}
}

func TestPrepareCloudNativePGUnknownForIdentityOrShapeGaps(t *testing.T) {
	base := `{"apiVersion":"postgresql.cnpg.io/v1","kind":"Database","metadata":{"namespace":"payments","name":"ledger"},"spec":{"cluster":{"name":"pg-a"}}}`
	otherNamespace := `{"apiVersion":"postgresql.cnpg.io/v1","kind":"Database","metadata":{"namespace":"other","name":"ledger"},"spec":{"cluster":{"name":"pg-b"}}}`
	for name, raw := range map[string]string{
		"identity mismatch": `{"current":` + base + `,"proposed":` + otherNamespace + `}`,
		"one object":        `{"proposed":` + base + `}`,
		"unsupported kind":  `{"current":` + base + `,"proposed":{"apiVersion":"postgresql.cnpg.io/v1","kind":"Cluster","metadata":{"namespace":"payments","name":"ledger"},"spec":{"cluster":{"name":"pg-b"}}}}`,
		"missing namespace": `{"current":` + base + `,"proposed":{"apiVersion":"postgresql.cnpg.io/v1","kind":"Database","metadata":{"name":"ledger"},"spec":{"cluster":{"name":"pg-b"}}}}`,
	} {
		t.Run(name, func(t *testing.T) {
			prepared, err := PrepareCloudNativePG([]byte(raw), CloudNativePGFrom, CloudNativePGTo)
			if err != nil || prepared.State != StateUnknown || prepared.Reason != ReasonCloudNativePGUnsupported {
				t.Fatalf("unknown case = %#v, %v", prepared, err)
			}
		})
	}
}

func containsBytes(haystack []byte, needle string) bool {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if string(haystack[i:i+len(needle)]) == needle {
			return true
		}
	}
	return false
}
