// SPDX-License-Identifier: AGPL-3.0-only

package cncfprepare

import "testing"

func TestPrepareKubernetesFlowControl_BoundedRenderedSet(t *testing.T) {
	tests := []struct {
		name, raw, reason string
		complete          bool
		state             State
	}{
		{"removed complete", `{"apiVersion":"flowcontrol.apiserver.k8s.io/v1beta3","kind":"FlowSchema"}`, string(ReasonKubernetesRemovedWitness), true, StatePrepared},
		{"clear complete list", `{"apiVersion":"v1","kind":"List","items":[{"apiVersion":"flowcontrol.apiserver.k8s.io/v1","kind":"FlowSchema"},{"apiVersion":"v1","kind":"Service"}]}`, string(ReasonKubernetesSelectedSetClear), true, StatePrepared},
		{"incomplete removed", `{"apiVersion":"flowcontrol.apiserver.k8s.io/v1beta3","kind":"FlowSchema"}`, string(ReasonKubernetesScopeIncomplete), false, StateUnknown},
		{"empty list", `{"apiVersion":"v1","kind":"List","items":[]}`, string(ReasonKubernetesUnresolved), true, StateUnknown},
		{"typed list", `{"apiVersion":"flowcontrol.apiserver.k8s.io/v1","kind":"FlowSchemaList","items":[]}`, string(ReasonKubernetesUnresolved), true, StateUnknown},
		{"nested list", `{"apiVersion":"v1","kind":"List","items":[{"apiVersion":"v1","kind":"List","items":[]}]}`, string(ReasonKubernetesUnresolved), true, StateUnknown},
		{"bad list metadata", `{"apiVersion":"v1","kind":"List","metadata":{"continue":1},"items":[{"apiVersion":"v1","kind":"Service"}]}`, string(ReasonKubernetesUnresolved), true, StateUnknown},
		{"pagination", `{"apiVersion":"v1","kind":"List","metadata":{"remainingItemCount":1},"items":[{"apiVersion":"v1","kind":"Service"}]}`, string(ReasonKubernetesPagination), true, StateUnknown},
		{"unreviewed flowcontrol version", `{"apiVersion":"flowcontrol.apiserver.k8s.io/v9","kind":"PriorityLevelConfiguration"}`, string(ReasonKubernetesUnreviewed), true, StateUnknown},
		{"ordinary unrelated matching kind", `{"apiVersion":"example.test/v1","kind":"FlowSchema"}`, string(ReasonKubernetesSelectedSetClear), true, StatePrepared},
		{"malformed api version", `{"apiVersion":"flowcontrol.apiserver.k8s.io/v1 beta3","kind":"FlowSchema"}`, string(ReasonKubernetesUnresolved), true, StateUnknown},
		{"template", `{{ .Values.flow }}`, string(ReasonKubernetesTemplated), true, StateUnknown},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			prepared, err := PrepareKubernetesFlowControl([]byte(test.raw), "1.31.0", "1.32.0", "official_upstream", true, test.complete)
			if err != nil || prepared.Reason != Reason(test.reason) || prepared.State != test.state {
				t.Fatalf("prepared=%+v err=%v", prepared, err)
			}
		})
	}
}

func TestPrepareKubernetesFlowControl_ValidatesRawBoundsBeforeTargetGuards(t *testing.T) {
	if _, err := PrepareKubernetesFlowControl([]byte{0xff}, "1.31.0", "1.32.0", "custom_build", false, false); err == nil {
		t.Fatal("invalid UTF-8 bypassed target guard")
	}
}

func TestPrepareKubernetesFlowControl_RejectsDuplicateAndInvalidJSON(t *testing.T) {
	for _, raw := range []string{
		`{"apiVersion":"flowcontrol.apiserver.k8s.io/v1beta3","apiVersion":"flowcontrol.apiserver.k8s.io/v1","kind":"FlowSchema"}`,
		`{"apiVersion":`,
	} {
		if _, err := PrepareKubernetesFlowControl([]byte(raw), "1.31.0", "1.32.0", "official_upstream", true, true); err == nil {
			t.Fatalf("accepted invalid raw input %q", raw)
		}
	}
}
