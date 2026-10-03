// SPDX-License-Identifier: AGPL-3.0-only

package localcollector

import "testing"

func TestComponentForImage(t *testing.T) {
	for image, want := range map[string]string{
		"prom/prometheus:v3.1.0":                        "pkg:oci/prometheus/prometheus",
		"docker.io/prom/prometheus@sha256:" + zeros():   "pkg:oci/prometheus/prometheus",
		"quay.io/jetstack/cert-manager-webhook:v1.16.2": "pkg:oci/cert-manager/cert-manager",
		"quay.io/cilium/cilium:v1.16.0":                 "pkg:oci/cilium/cilium",
		"quay.io/jetstack/cert-manager-controller":      "pkg:oci/cert-manager/cert-manager",
		"quay.io/argoproj/argocd:v2.13.0":               "pkg:oci/argoproj/argo-cd",
		"docker.io/argoproj/workflow-controller:v3.6.0": "pkg:oci/argoproj/argo-workflows",
	} {
		if got, ok := ComponentForImage(image); !ok || got != want {
			t.Errorf("%s: got %q %v", image, got, ok)
		}
	}
	for _, image := range []string{"", "nginx", "example.com/prom/prometheus:v1", "prom/prometheus-extra:v1", "cilium/cilium-operator"} {
		if got, ok := ComponentForImage(image); ok {
			t.Errorf("%q matched %q", image, got)
		}
	}
	ids := ComponentIDs()
	if len(ids) < 4 || ids[0] > ids[1] {
		t.Fatalf("ids %v", ids)
	}
}

func zeros() string {
	out := make([]byte, 64)
	for i := range out {
		out[i] = '0'
	}
	return string(out)
}
