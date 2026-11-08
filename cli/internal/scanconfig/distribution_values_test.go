// SPDX-License-Identifier: AGPL-3.0-only

package scanconfig

import "testing"

func TestDistributionValuesInConfig(t *testing.T) {
	for _, v := range []string{"official_upstream", "custom_build", "eks", "gke", "aks", "k3s"} {
		cfg, err := Parse([]byte(head + "declarations: {kubernetes: {distribution: " + v + "}}\n"))
		if err != nil || cfg.Declarations.Kubernetes == nil || cfg.Declarations.Kubernetes.Distribution == nil || *cfg.Declarations.Kubernetes.Distribution != v {
			t.Errorf("%s: %v", v, err)
		}
	}
	// Anything else, including a recognised distribution this version does
	// not evaluate and case or space variants, is refused.
	for _, v := range []string{"openshift", "talos", "kubeadm", "rke2", "EKS", "'eks '", "''", "mystery"} {
		if _, err := Parse([]byte(head + "declarations: {kubernetes: {distribution: " + v + "}}\n")); err == nil {
			t.Errorf("%s accepted", v)
		}
	}
}
