// SPDX-License-Identifier: AGPL-3.0-only

package cncfprepare

import (
	"encoding/json"
	"strings"
	"testing"
)

const argoCDV3Default = `[{"apiGroups":["","discovery.k8s.io"],"kinds":["Endpoints","EndpointSlice"]},{"apiGroups":["coordination.k8s.io"],"kinds":["Lease"]},{"apiGroups":["authentication.k8s.io","authorization.k8s.io"],"kinds":["SelfSubjectReview","TokenReview","LocalSubjectAccessReview","SelfSubjectAccessReview","SelfSubjectRulesReview","SubjectAccessReview"]},{"apiGroups":["certificates.k8s.io"],"kinds":["CertificateSigningRequest"]},{"apiGroups":["cert-manager.io"],"kinds":["CertificateRequest"]},{"apiGroups":["cilium.io"],"kinds":["CiliumIdentity","CiliumEndpoint","CiliumEndpointSlice"]},{"apiGroups":["kyverno.io","reports.kyverno.io","wgpolicyk8s.io"],"kinds":["PolicyReport","ClusterPolicyReport","EphemeralReport","ClusterEphemeralReport","AdmissionReport","ClusterAdmissionReport","BackgroundScanReport","ClusterBackgroundScanReport","UpdateRequest"]}]`

func argoExclusionsConfig(data string) []byte {
	return []byte("apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: argocd-cm\ndata:\n  resource.exclusions: '" + data + "'\n  private.example: hidden\n")
}
func TestPrepareArgoCDResourceExclusionsFiniteModes(t *testing.T) {
	yes := true
	cases := []struct {
		name   string
		raw    []byte
		want   bool
		reason Reason
	}{{"source default", argoExclusionsConfig(argoCDV3Default), true, ReasonArgoCDResourceExclusionsDefault}, {"empty", argoExclusionsConfig("[]"), false, ReasonArgoCDResourceExclusionsEmpty}, {"absent", []byte("apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: argocd-cm\ndata:\n  private.example: hidden\n"), false, ReasonArgoCDResourceExclusionsAbsent}}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p, e := PrepareArgoCDResourceExclusions(tc.raw, ArgoCDFrom, ArgoCDTo, true, true, &yes)
			if e != nil || p.State != StatePrepared || p.Reason != tc.reason {
				t.Fatalf("%#v %v", p, e)
			}
			if strings.Contains(string(p.CanonicalInputJSON), "hidden") {
				t.Fatal("private value escaped")
			}
			var d struct {
				Proposed struct {
					Components []struct {
						Facts []struct {
							ID        string
							BoolValue *bool
						}
					}
				}
			}
			json.Unmarshal(p.CanonicalInputJSON, &d)
			found := false
			for _, fact := range d.Proposed.Components[0].Facts {
				if fact.ID == ArgoCDResourceExclusionsFact {
					found = fact.BoolValue != nil && *fact.BoolValue == tc.want
				}
			}
			if !found {
				t.Fatalf("source-default fact missing or wrong: %#v", d)
			}
		})
	}
}
func TestPrepareArgoCDResourceExclusionsUnknownBoundaries(t *testing.T) {
	yes := true
	for _, raw := range [][]byte{argoExclusionsConfig(`[{"apiGroups":["x"],"kinds":["y"]}]`), []byte("apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: argocd-cm\ndata:\n  'resource.exclusions ': '[]'\n"), []byte("apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: argocd-cm\ndata:\n  resource.exclusions: []\n"), []byte("apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: argocd-cm\ndata:\n  resource.exclusions: '{{ secret }}'\n"), []byte("apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: argocd-cm\ndata:\n  resource.exclusions: '[]'\n  other: [not-a-string]\n"), []byte("apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: argocd-cm\ndata:\n  resource.exclusions: '[]'\n  'resource.exclusions ': '[]'\n")} {
		p, e := PrepareArgoCDResourceExclusions(raw, ArgoCDFrom, ArgoCDTo, true, true, &yes)
		if e != nil || p.State != StateUnknown || p.Reason != ReasonArgoCDResourceExclusionsUnsupported {
			t.Fatalf("%#v %v", p, e)
		}
	}
}
func TestPrepareArgoCDResourceExclusionsRequiresDeclaredScope(t *testing.T) {
	for _, tc := range []struct {
		complete, precedence bool
		intent               *bool
	}{{false, true, argoBool(true)}, {true, false, argoBool(true)}, {true, true, nil}} {
		p, e := PrepareArgoCDResourceExclusions(argoExclusionsConfig("[]"), ArgoCDFrom, ArgoCDTo, tc.complete, tc.precedence, tc.intent)
		if e != nil || p.State != StateUnknown {
			t.Fatalf("%#v %v", p, e)
		}
	}
}
func argoBool(v bool) *bool { return &v }

func TestPrepareArgoCDResourceExclusionsDoesNotClassifyFuturePair(t *testing.T) {
	yes := true
	p, err := PrepareArgoCDResourceExclusions(argoExclusionsConfig("[]"), "3.0.0", "3.1.0", true, true, &yes)
	if err != nil || p.State != StateUnknown || p.Reason != ReasonArgoCDResourceExclusionsEmpty {
		t.Fatalf("prepared=%#v err=%v", p, err)
	}
}

func TestPrepareArgoCDResourceExclusionsRejectsMalformedPresentData(t *testing.T) {
	yes := true
	for _, raw := range [][]byte{
		[]byte("apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: argocd-cm\nData:\n  resource.exclusions: '[]'\n"),
		[]byte("apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: argocd-cm\ndata:\n  resource.exclusions: '[]'\ndata:\n  resource.exclusions: '[]'\n"),
		[]byte("apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: argocd-cm\n  name: argocd-cm\ndata:\n  resource.exclusions: '[]'\n"),
		[]byte("apiVersion: v1\nkind: ConfigMap\nmetadata: &meta\n  name: argocd-cm\ndata:\n  resource.exclusions: '[]'\n"),
		[]byte("apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: argocd-cm\ndata:\n  resource.exclusions: !unsafe '[]'\n"),
		[]byte("apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: argocd-cm\ndata:\n  <<: {resource.exclusions: '[]'}\n"),
	} {
		p, err := PrepareArgoCDResourceExclusions(raw, ArgoCDFrom, ArgoCDTo, true, true, &yes)
		if err != nil || p.State != StateUnknown || p.Reason != ReasonArgoCDResourceExclusionsUnsupported {
			t.Fatalf("prepared=%#v err=%v", p, err)
		}
	}
}

func TestPrepareArgoCDResourceExclusionsFalseIntentStaysUnknown(t *testing.T) {
	no := false
	p, err := PrepareArgoCDResourceExclusions(argoExclusionsConfig("[]"), ArgoCDFrom, ArgoCDTo, true, true, &no)
	if err != nil || p.State != StateUnknown {
		t.Fatalf("prepared=%#v err=%v", p, err)
	}
}
