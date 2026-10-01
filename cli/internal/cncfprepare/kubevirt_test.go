// SPDX-License-Identifier: AGPL-3.0-only

package cncfprepare

import "testing"

func TestPrepareKubeVirtRequiresExactlyOneInterfaceBinding(t *testing.T) {
	tests := []struct {
		name, raw, reason string
		invalid           bool
	}{
		{"one method", `{"apiVersion":"kubevirt.io/v1","kind":"VirtualMachineInstance","metadata":{"namespace":"compute","name":"vm-a"},"spec":{"domain":{"devices":{"interfaces":[{"name":"default","masquerade":{}}]}}}}`, string(ReasonKubeVirtBindingValid), false},
		{"no binding", `{"apiVersion":"kubevirt.io/v1","kind":"VirtualMachineInstance","metadata":{"namespace":"compute","name":"vm-a"},"spec":{"domain":{"devices":{"interfaces":[{"name":"default"}]}}}}`, string(ReasonKubeVirtBindingInvalid), true},
		{"two methods", `{"apiVersion":"kubevirt.io/v1","kind":"VirtualMachineInstance","metadata":{"namespace":"compute","name":"vm-a"},"spec":{"domain":{"devices":{"interfaces":[{"name":"default","masquerade":{},"bridge":{}}]}}}}`, string(ReasonKubeVirtBindingInvalid), true},
		{"plugin and method", `{"apiVersion":"kubevirt.io/v1","kind":"VirtualMachineInstance","metadata":{"namespace":"compute","name":"vm-a"},"spec":{"domain":{"devices":{"interfaces":[{"name":"default","binding":{"name":"plug"},"masquerade":{}}]}}}}`, string(ReasonKubeVirtBindingInvalid), true},
		{"VM template", `{"apiVersion":"kubevirt.io/v1","kind":"VirtualMachine","metadata":{"namespace":"compute","name":"vm-a"},"spec":{"running":false,"template":{"metadata":{"labels":{"app":"vm"}},"spec":{"domain":{"devices":{"interfaces":[{"name":"default","bridge":{}}]}}}}}}`, string(ReasonKubeVirtBindingValid), false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			prepared, err := PrepareKubeVirt([]byte(test.raw), KubeVirtFrom, KubeVirtTo)
			if err != nil || prepared.State != StatePrepared || string(prepared.Reason) != test.reason {
				t.Fatalf("PrepareKubeVirt() = %#v, %v", prepared, err)
			}
			if !containsBytes(prepared.CanonicalInputJSON, `"boolValue":`+map[bool]string{true: "true", false: "false"}[test.invalid]) {
				t.Fatalf("fact mismatch: %s", prepared.CanonicalInputJSON)
			}
		})
	}
}

func TestPrepareKubeVirtIgnoresUnrelatedNativeFields(t *testing.T) {
	rich := `{"apiVersion":"kubevirt.io/v1","kind":"VirtualMachineInstance","metadata":{"namespace":"compute","name":"vm-a","uid":"u1","resourceVersion":"9","labels":{"team":"platform"}},"spec":{"domain":{"devices":{"interfaces":[{"name":"default","masquerade":{},"macAddress":"02:00:00:00:00:01"}],"disks":[{"name":"root"}]},"resources":{"requests":{"memory":"1Gi"}}}},"status":{"phase":"Running","interfaces":[{"name":"default"}]}}`
	minimal := `{"apiVersion":"kubevirt.io/v1","kind":"VirtualMachineInstance","metadata":{"namespace":"compute","name":"vm-a"},"spec":{"domain":{"devices":{"interfaces":[{"name":"default","masquerade":{}}]}}}}`
	richPrepared, err := PrepareKubeVirt([]byte(rich), KubeVirtFrom, KubeVirtTo)
	if err != nil || richPrepared.State != StatePrepared || richPrepared.Reason != ReasonKubeVirtBindingValid {
		t.Fatalf("rich native resource = %#v, %v", richPrepared, err)
	}
	minimalPrepared, err := PrepareKubeVirt([]byte(minimal), KubeVirtFrom, KubeVirtTo)
	if err != nil || string(richPrepared.CanonicalInputJSON) != string(minimalPrepared.CanonicalInputJSON) {
		t.Fatalf("unrelated native fields changed canonical result: rich=%s minimal=%s err=%v", richPrepared.CanonicalInputJSON, minimalPrepared.CanonicalInputJSON, err)
	}
}

func TestPrepareKubeVirtUnknownForUnsupportedNativeShapes(t *testing.T) {
	base := `{"apiVersion":"kubevirt.io/v1","kind":"VirtualMachineInstance","metadata":{"namespace":"compute","name":"vm-a"},"spec":{"domain":{"devices":{"interfaces":[{"name":"default","masquerade":{}}]}}}}`
	for name, raw := range map[string]string{
		"missing interfaces": `{"apiVersion":"kubevirt.io/v1","kind":"VirtualMachineInstance","metadata":{"namespace":"compute","name":"vm-a"},"spec":{"domain":{"devices":{}}}}`,
		"wrong api":          `{"apiVersion":"kubevirt.io/v1beta1","kind":"VirtualMachineInstance","metadata":{"namespace":"compute","name":"vm-a"},"spec":{"domain":{"devices":{"interfaces":[]}}}}`,
		"wrong binding type": `{"apiVersion":"kubevirt.io/v1","kind":"VirtualMachineInstance","metadata":{"namespace":"compute","name":"vm-a"},"spec":{"domain":{"devices":{"interfaces":[{"name":"default","binding":"plugin"}]}}}}`,
		"missing namespace":  `{"apiVersion":"kubevirt.io/v1","kind":"VirtualMachineInstance","metadata":{"name":"vm-a"},"spec":{"domain":{"devices":{"interfaces":[]}}}}`,
		"bad json":           base[:len(base)-1],
	} {
		t.Run(name, func(t *testing.T) {
			prepared, err := PrepareKubeVirt([]byte(raw), KubeVirtFrom, KubeVirtTo)
			if name == "bad json" {
				if err == nil {
					t.Fatal("expected malformed JSON error")
				}
				return
			}
			if err != nil || prepared.State != StateUnknown || prepared.Reason != ReasonKubeVirtUnsupported {
				t.Fatalf("unknown case = %#v, %v", prepared, err)
			}
		})
	}
}
