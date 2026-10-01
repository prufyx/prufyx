// SPDX-License-Identifier: AGPL-3.0-only

package cncfprepare

import "testing"

func TestPrepareNativeMigration(t *testing.T) {
	tests := []struct {
		name, project, raw, from, to, reason string
		state                                State
	}{
		{"metallb configmap", "metallb", `{"apiVersion":"v1","kind":"ConfigMap","metadata":{"namespace":"metallb-system","name":"config"},"data":{"config":"address-pools: []"}}`, MetalLBFrom, MetalLBTo, string(ReasonMetalLBConfigMap), StatePrepared},
		{"metallb cr", "metallb", `{"apiVersion":"metallb.io/v1beta1","kind":"IPAddressPool","metadata":{"namespace":"metallb-system","name":"pool"},"spec":{}}`, MetalLBFrom, MetalLBTo, string(ReasonMetalLBCR), StatePrepared},
		{"contour alpha", "contour", `{"apiVersion":"networking.x-k8s.io/v1alpha1","kind":"Gateway","metadata":{"namespace":"contour","name":"gw"},"spec":{}}`, ContourFrom, ContourTo, string(ReasonContourGatewayAlpha), StatePrepared},
		{"contour target", "contour", `{"apiVersion":"gateway.networking.k8s.io/v1alpha2","kind":"Gateway","metadata":{"namespace":"contour","name":"gw"},"spec":{}}`, ContourFrom, ContourTo, string(ReasonContourGatewayTarget), StatePrepared},
		{"contour gatewayclass", "contour", `{"apiVersion":"networking.x-k8s.io/v1alpha1","kind":"GatewayClass","metadata":{"name":"contour"},"spec":{}}`, ContourFrom, ContourTo, string(ReasonContourGatewayAlpha), StatePrepared},
		{"unsupported kind", "contour", `{"apiVersion":"gateway.networking.k8s.io/v1alpha2","kind":"TCPRoute","metadata":{"namespace":"contour","name":"route"}}`, ContourFrom, ContourTo, string(ReasonNativeMigrationUnsupported), StateUnknown},
		{"unsupported shape", "metallb", `{"apiVersion":"v1","kind":"ConfigMap","metadata":{"namespace":"other","name":"config"},"data":{"other":"x"}}`, MetalLBFrom, MetalLBTo, string(ReasonNativeMigrationUnsupported), StateUnknown},
		{"contour missing namespace", "contour", `{"apiVersion":"gateway.networking.k8s.io/v1alpha2","kind":"Gateway","metadata":{"name":"gw"},"spec":{}}`, ContourFrom, ContourTo, string(ReasonNativeMigrationUnsupported), StateUnknown},
		{"contour namespace on class", "contour", `{"apiVersion":"networking.x-k8s.io/v1alpha1","kind":"GatewayClass","metadata":{"namespace":"contour","name":"class"},"spec":{}}`, ContourFrom, ContourTo, string(ReasonNativeMigrationUnsupported), StateUnknown},
		{"metallb unsupported crd kind", "metallb", `{"apiVersion":"metallb.io/v1beta1","kind":"NodeSelector","metadata":{"namespace":"metallb-system","name":"selector"},"spec":{}}`, MetalLBFrom, MetalLBTo, string(ReasonNativeMigrationUnsupported), StateUnknown},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			prepared, err := PrepareNativeMigration([]byte(test.raw), test.project, test.from, test.to)
			if err != nil || prepared.State != test.state || string(prepared.Reason) != test.reason {
				t.Fatalf("PrepareNativeMigration() = %#v, %v", prepared, err)
			}
			if len(prepared.CanonicalInputJSON) == 0 || prepared.InputDigest == prepared.SourceDigest {
				t.Fatalf("prepared declaration lacks independent canonical digest: %#v", prepared)
			}
		})
	}
}

func TestPrepareNativeMigrationRejectsDuplicateJSON(t *testing.T) {
	if _, err := PrepareNativeMigration([]byte(`{"apiVersion":"v1","kind":"ConfigMap","kind":"ConfigMap","metadata":{"namespace":"metallb-system","name":"config"},"data":{"config":"x"}}`), "metallb", MetalLBFrom, MetalLBTo); err == nil {
		t.Fatal("expected duplicate JSON member rejection")
	}
}
