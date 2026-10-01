// SPDX-License-Identifier: AGPL-3.0-only

package cncfprepare

import (
	"bytes"
	"testing"
)

func TestPrepareCiliumClusterName(t *testing.T) {
	config := func(name, cluster string) []byte {
		return []byte("apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: " + name + "\ndata:\n  cluster-name: '" + cluster + "'\n  private: hidden\n")
	}
	for _, tc := range []struct {
		name, cluster string
		blocked       bool
	}{
		{"valid after target trim", "  mesh-1  ", false},
		{"uppercase", "Mesh", true},
		{"empty after target trim", "   ", true},
		{"leading dash", "-mesh", true},
		{"over length", "abcdefghijklmnopqrstuvwxyz1234567", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			prepared, err := PrepareCiliumClusterName(config("cilium-config", tc.cluster), "1.16.19", "1.17.18", "official_upstream", true, true)
			if err != nil || prepared.State != StatePrepared || bytes.Contains(prepared.CanonicalInputJSON, []byte("hidden")) {
				t.Fatalf("prepared=%+v err=%v", prepared, err)
			}
			fact := preparedFacts(t, prepared)[CiliumInvalidEffectiveClusterNameFact]
			if fact["boolValue"] != tc.blocked {
				t.Fatalf("fact=%v, want %v", fact, tc.blocked)
			}
		})
	}
}

func TestPrepareCiliumClusterNameUnknownBoundaries(t *testing.T) {
	valid := []byte("apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: cilium-config\ndata:\n  cluster-name: mesh\n")
	for _, tc := range []struct {
		name                 string
		raw                  []byte
		dist                 string
		complete, precedence bool
	}{
		{"incomplete", valid, "official_upstream", false, true},
		{"precedence unresolved", valid, "official_upstream", true, false},
		{"custom distribution", valid, "custom_build", true, true},
		{"missing name", []byte("apiVersion: v1\nkind: ConfigMap\nmetadata: {}\ndata:\n  cluster-name: mesh\n"), "official_upstream", true, true},
		{"missing cluster name", []byte("apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: cilium-config\ndata: {}\n"), "official_upstream", true, true},
		{"typed value", []byte("apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: cilium-config\ndata:\n  cluster-name: 7\n"), "official_upstream", true, true},
		{"alias", []byte("apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: cilium-config\ndata:\n  cluster-name: &name mesh\n"), "official_upstream", true, true},
		{"template", []byte("apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: cilium-config\ndata:\n  cluster-name: '{{ name }}'\n"), "official_upstream", true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			prepared, err := PrepareCiliumClusterName(tc.raw, "1.16.19", "1.17.18", tc.dist, tc.complete, tc.precedence)
			if err != nil || prepared.State != StateUnknown {
				t.Fatalf("prepared=%+v err=%v", prepared, err)
			}
		})
	}
	if _, err := PrepareCiliumClusterName([]byte{0xff}, "1.16.19", "1.17.18", "custom_build", false, false); err == nil {
		t.Fatal("invalid bytes accepted")
	}
}

func TestPrepareCiliumClusterNameAdmitsOrdinaryMetadataButNotBinaryOverlap(t *testing.T) {
	realistic := []byte("apiVersion: v1\nkind: ConfigMap\nimmutable: false\nmetadata:\n  name: cilium-config\n  creationTimestamp: null\n  generation: 4\ndata:\n  cluster-name: mesh-1\n")
	prepared, err := PrepareCiliumClusterName(realistic, "1.16.19", "1.17.18", "official_upstream", true, true)
	if err != nil || prepared.State != StatePrepared || prepared.Reason != ReasonCiliumClusterNameValid {
		t.Fatalf("prepared=%+v err=%v", prepared, err)
	}
	overlap := []byte("apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: cilium-config\ndata:\n  cluster-name: mesh-1\nbinaryData:\n  cluster-name: bWVzaC0y\n")
	prepared, err = PrepareCiliumClusterName(overlap, "1.16.19", "1.17.18", "official_upstream", true, true)
	if err != nil || prepared.State != StateUnknown {
		t.Fatalf("overlap prepared=%+v err=%v", prepared, err)
	}
}
