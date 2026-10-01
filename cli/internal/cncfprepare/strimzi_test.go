// SPDX-License-Identifier: AGPL-3.0-only

package cncfprepare

import (
	"strings"
	"testing"
)

const strimziRemovedKafka = `{"apiVersion":"kafka.strimzi.io/v1beta2","kind":"Kafka","metadata":{"name":"private-cluster","namespace":"private-ns"},"spec":{"kafka":{"replicas":3}}}`
const strimziTargetKafka = `{"apiVersion":"kafka.strimzi.io/v1","kind":"Kafka","metadata":{"name":"private-cluster","namespace":"private-ns"},"spec":{"kafka":{"replicas":3}}}`

func TestPrepareStrimziKafkaResource_BoundedSelectedResources(t *testing.T) {
	tests := []struct {
		name, raw, reason string
		state             State
	}{
		{"removed api present", strimziRemovedKafka, string(ReasonStrimziV1Beta2Present), StatePrepared},
		{"target api only", strimziTargetKafka, string(ReasonStrimziV1Beta2Absent), StatePrepared},
		{"mixed list keeps removed witness", `{"apiVersion":"v1","kind":"List","items":[` + strimziTargetKafka + `,` + strimziRemovedKafka + `]}`, string(ReasonStrimziV1Beta2Present), StatePrepared},
		{"clear list", `{"apiVersion":"v1","kind":"List","items":[` + strimziTargetKafka + `]}`, string(ReasonStrimziV1Beta2Absent), StatePrepared},
		{"other kind in group", `{"apiVersion":"kafka.strimzi.io/v1beta2","kind":"KafkaTopic","metadata":{"name":"private-topic","namespace":"private-ns"}}`, string(ReasonStrimziSurfaceOther), StateUnknown},
		{"unrelated group", `{"apiVersion":"example.test/v1","kind":"Kafka","metadata":{"name":"private-cluster","namespace":"private-ns"}}`, string(ReasonStrimziSurfaceOther), StateUnknown},
		{"other kind inside list", `{"apiVersion":"v1","kind":"List","items":[` + strimziRemovedKafka + `,{"apiVersion":"v1","kind":"Service","metadata":{"name":"private-service","namespace":"private-ns"}}]}`, string(ReasonStrimziSurfaceOther), StateUnknown},
		{"unreviewed served version", `{"apiVersion":"kafka.strimzi.io/v1beta1","kind":"Kafka","metadata":{"name":"private-cluster","namespace":"private-ns"}}`, string(ReasonStrimziUnreviewedAPI), StateUnknown},
		{"missing namespace", `{"apiVersion":"kafka.strimzi.io/v1beta2","kind":"Kafka","metadata":{"name":"private-cluster"}}`, string(ReasonStrimziInputUnsupported), StateUnknown},
		{"missing name", `{"apiVersion":"kafka.strimzi.io/v1beta2","kind":"Kafka","metadata":{"namespace":"private-ns"}}`, string(ReasonStrimziInputUnsupported), StateUnknown},
		{"empty list", `{"apiVersion":"v1","kind":"List","items":[]}`, string(ReasonStrimziInputUnsupported), StateUnknown},
		{"typed list", `{"apiVersion":"kafka.strimzi.io/v1","kind":"KafkaList","items":[]}`, string(ReasonStrimziInputUnsupported), StateUnknown},
		{"nested list", `{"apiVersion":"v1","kind":"List","items":[{"apiVersion":"v1","kind":"List","items":[]}]}`, string(ReasonStrimziInputUnsupported), StateUnknown},
		{"non-v1 list", `{"apiVersion":"kafka.strimzi.io/v1","kind":"List","items":[` + strimziTargetKafka + `]}`, string(ReasonStrimziInputUnsupported), StateUnknown},
		{"bad list metadata", `{"apiVersion":"v1","kind":"List","metadata":{"continue":1},"items":[` + strimziTargetKafka + `]}`, string(ReasonStrimziInputUnsupported), StateUnknown},
		{"pagination", `{"apiVersion":"v1","kind":"List","metadata":{"remainingItemCount":1},"items":[` + strimziTargetKafka + `]}`, string(ReasonStrimziPagination), StateUnknown},
		{"template", `{"apiVersion":"kafka.strimzi.io/{{ .Values.api }}","kind":"Kafka"}`, string(ReasonStrimziTemplated), StateUnknown},
		{"shell substitution", `{"apiVersion":"kafka.strimzi.io/${API}","kind":"Kafka"}`, string(ReasonStrimziTemplated), StateUnknown},
		{"scalar root", `"kafka"`, string(ReasonStrimziInputUnsupported), StateUnknown},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			prepared, err := PrepareStrimziKafkaResource([]byte(test.raw), StrimziFrom, StrimziTo, StrimziDistributionOfficial, true)
			if err != nil || prepared.Reason != Reason(test.reason) || prepared.State != test.state {
				t.Fatalf("prepared=%+v err=%v", prepared, err)
			}
			if strings.Contains(string(prepared.CanonicalInputJSON), "private-") {
				t.Fatalf("canonical input retained private names: %s", prepared.CanonicalInputJSON)
			}
		})
	}
}

func TestPrepareStrimziKafkaResource_GuardsPrecedeResourceClassification(t *testing.T) {
	tests := []struct {
		name, from, to, distribution, reason string
	}{
		{"unreviewed pair", "0.50.0", "1.0.0", StrimziDistributionOfficial, string(ReasonStrimziPairUnsupported)},
		{"unreviewed target", StrimziFrom, "1.1.0", StrimziDistributionOfficial, string(ReasonStrimziPairUnsupported)},
		{"missing distribution", StrimziFrom, StrimziTo, "", string(ReasonStrimziGuardUnresolved)},
		{"unknown distribution token", StrimziFrom, StrimziTo, "vendor_build", string(ReasonStrimziGuardUnresolved)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			prepared, err := PrepareStrimziKafkaResource([]byte(strimziRemovedKafka), test.from, test.to, test.distribution, true)
			if err != nil || prepared.State != StateUnknown || prepared.Reason != Reason(test.reason) {
				t.Fatalf("prepared=%+v err=%v", prepared, err)
			}
		})
	}
}

// A custom build is a declared fact, not a guard failure: the adapter still
// derives the API fact and lets the rule's own applicability keep the claim
// UNKNOWN. This must never become a PASS route for unreviewed builds.
func TestPrepareStrimziKafkaResource_CustomBuildStaysDeclaredNotOfficial(t *testing.T) {
	prepared, err := PrepareStrimziKafkaResource([]byte(strimziTargetKafka), StrimziFrom, StrimziTo, StrimziDistributionCustom, true)
	if err != nil || prepared.State != StatePrepared || prepared.Reason != ReasonStrimziV1Beta2Absent {
		t.Fatalf("prepared=%+v err=%v", prepared, err)
	}
	canonical := string(prepared.CanonicalInputJSON)
	if !strings.Contains(canonical, `"enumValue":"`+StrimziDistributionCustom+`"`) {
		t.Fatalf("custom build not declared: %s", canonical)
	}
}

func TestPrepareStrimziKafkaResource_RecordsDeclaredAdmissionIntent(t *testing.T) {
	for _, required := range []bool{true, false} {
		prepared, err := PrepareStrimziKafkaResource([]byte(strimziRemovedKafka), StrimziFrom, StrimziTo, StrimziDistributionOfficial, required)
		if err != nil {
			t.Fatalf("required=%v err=%v", required, err)
		}
		canonical := string(prepared.CanonicalInputJSON)
		want := `{"id":"` + StrimziTargetCRDAdmissionFact + `","state":"declared","boolValue":`
		if !strings.Contains(canonical, want+boolText(required)) {
			t.Fatalf("required=%v canonical=%s", required, canonical)
		}
	}
}

func TestPrepareStrimziKafkaResource_RejectsRawBoundsAndMalformedJSON(t *testing.T) {
	for _, raw := range [][]byte{
		nil,
		{0xff},
		make([]byte, maxInputBytes+1),
	} {
		if _, err := PrepareStrimziKafkaResource(raw, StrimziFrom, StrimziTo, StrimziDistributionOfficial, true); err == nil {
			t.Fatalf("accepted raw input of %d bytes", len(raw))
		}
	}
	for _, from := range []string{"", "0.51", "v0.51.0", StrimziTo} {
		if _, err := PrepareStrimziKafkaResource([]byte(strimziTargetKafka), from, StrimziTo, StrimziDistributionOfficial, true); err == nil {
			t.Fatalf("accepted from version %q", from)
		}
	}
	for _, raw := range []string{
		`{"apiVersion":"kafka.strimzi.io/v1beta2","apiVersion":"kafka.strimzi.io/v1","kind":"Kafka"}`,
		`{"apiVersion":`,
	} {
		prepared, err := PrepareStrimziKafkaResource([]byte(raw), StrimziFrom, StrimziTo, StrimziDistributionOfficial, true)
		if err != nil || prepared.State != StateUnknown || prepared.Reason != ReasonStrimziInputUnsupported {
			t.Fatalf("raw=%q prepared=%+v err=%v", raw, prepared, err)
		}
	}
}

func TestPrepareStrimziKafkaResource_DigestsAndOmissionsAreStable(t *testing.T) {
	first, err := PrepareStrimziKafkaResource([]byte(strimziRemovedKafka), StrimziFrom, StrimziTo, StrimziDistributionOfficial, true)
	if err != nil {
		t.Fatal(err)
	}
	second, err := PrepareStrimziKafkaResource([]byte(strimziRemovedKafka), StrimziFrom, StrimziTo, StrimziDistributionOfficial, true)
	if err != nil {
		t.Fatal(err)
	}
	if first.SourceDigest != second.SourceDigest || first.InputDigest != second.InputDigest {
		t.Fatalf("unstable digests %+v %+v", first, second)
	}
	if first.SourceDigest != digestBytes([]byte(strimziRemovedKafka)) || first.InputDigest != digestBytes(first.CanonicalInputJSON) {
		t.Fatalf("digest bindings %+v", first)
	}
	if len(first.Omissions) != 3 || first.Omissions[2] != OmissionNoWholeUpgrade {
		t.Fatalf("omissions = %v", first.Omissions)
	}
}
