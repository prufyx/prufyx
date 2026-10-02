// SPDX-License-Identifier: AGPL-3.0-only

package cncfprepare

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
)

func k8sSetsRegistered(id string) bool { return strings.HasSuffix(id, "_set") }

func k8sSetFacts(t *testing.T, from, to string, complete []string, registered func(string) bool, sources ...k8sSrc) (Prepared, map[string]k8sFactView) {
	t.Helper()
	selection, contents := k8sSelection(t, complete, nil, sources...)
	prepared, err := PrepareKubernetesComponentConfig(selection, contents, from, to, "official_upstream", registered)
	if err != nil {
		t.Fatalf("prepare: %v", err)
	}
	return prepared, k8sProposedFacts(t, prepared)
}

// k8sSetState renders one set fact as "members|complete", "members|partial",
// or its non-declared state.
func k8sSetState(t *testing.T, facts map[string]k8sFactView, id string) string {
	t.Helper()
	view, found := facts[id]
	switch {
	case !found:
		return "absent-from-input"
	case view.State != "declared":
		return view.State
	case view.SetValue == nil || view.BoolValue != nil:
		t.Fatalf("%s is not a set: %+v", id, view)
	}
	completeness := "partial"
	if view.SetValue.Complete {
		completeness = "complete"
	}
	return strings.Join(view.SetValue.Members, ",") + "|" + completeness
}

const k8sKubeletConfigWithGates = "apiVersion: kubelet.config.k8s.io/v1beta1\nkind: KubeletConfiguration\nfeatureGates:\n  ConfigGate: false\n"

func TestKubernetesComponentSetFacts(t *testing.T) {
	kubeletConfig := k8sSrc{scope: K8sScopeKubelet, format: K8sFormatKubeletConfig, body: k8sKubeletConfigWithGates}
	apiserver := func(args ...string) k8sSrc {
		return k8sSrc{scope: K8sScopeAPIServer, format: K8sFormatPodManifest, body: k8sStaticPod("kube-apiserver", args...)}
	}
	for _, test := range []struct {
		name     string
		complete []string
		sources  []k8sSrc
		fact     string
		want     string
	}{
		{"flag and config gates, false still counts", []string{K8sScopeKubelet}, []k8sSrc{k8sKubeletEnv("--config=/var/lib/kubelet/config.yaml --feature-gates=FlagGate=true,OffGate=false"), kubeletConfig}, "kubelet_feature_gates_set", "ConfigGate,FlagGate,OffGate|complete"},
		{"kubelet flags", []string{K8sScopeKubelet}, []k8sSrc{k8sKubeletEnv("--config=/var/lib/kubelet/config.yaml --feature-gates=FlagGate=true --node-ip=10.1.2.3"), kubeletConfig}, "kubelet_flags_set", "config,feature-gates,node-ip|complete"},
		{"scope not declared complete", nil, []k8sSrc{k8sKubeletEnv("--config=/var/lib/kubelet/config.yaml --feature-gates=FlagGate=true"), kubeletConfig}, "kubelet_feature_gates_set", "ConfigGate,FlagGate|partial"},
		{"kubelet config file referenced but not supplied", []string{K8sScopeKubelet}, []k8sSrc{k8sKubeletEnv("--config=/var/lib/kubelet/config.yaml --feature-gates=FlagGate=true")}, "kubelet_feature_gates_set", "FlagGate|partial"},
		{"repeated gate flags", []string{K8sScopeAPIServer}, []k8sSrc{apiserver("--feature-gates=A=true", "--feature-gates=B=false,A=false")}, "kube_apiserver_feature_gates_set", "A,B|complete"},
		{"gate without a value is set", []string{K8sScopeAPIServer}, []k8sSrc{apiserver("--feature-gates=RemovedGate")}, "kube_apiserver_feature_gates_set", "RemovedGate|complete"},
		{"gate with a non-boolean value is set", []string{K8sScopeAPIServer}, []k8sSrc{apiserver("--feature-gates=RemovedGate=maybe")}, "kube_apiserver_feature_gates_set", "RemovedGate|complete"},
		{"underscore spelling is normalised", []string{K8sScopeAPIServer}, []k8sSrc{apiserver("--feature_gates=RemovedGate=true")}, "kube_apiserver_flags_set", "feature-gates|complete"},
		{"underscore spelling still sets gates", []string{K8sScopeAPIServer}, []k8sSrc{apiserver("--feature_gates=RemovedGate=true")}, "kube_apiserver_feature_gates_set", "RemovedGate|complete"},
		{"dependent variable value is unresolved", []string{K8sScopeAPIServer}, []k8sSrc{apiserver("--feature-gates=$(GATES)")}, "kube_apiserver_feature_gates_set", "|partial"},
		{"unrepresentable gate name drops and stays partial", []string{K8sScopeAPIServer}, []k8sSrc{apiserver("--feature-gates=Kept=true,bad name=true")}, "kube_apiserver_feature_gates_set", "Kept|partial"},
		{"bare double dash is unresolved", []string{K8sScopeAPIServer}, []k8sSrc{apiserver("--v=2", "--")}, "kube_apiserver_flags_set", "v|partial"},
		{"empty complete scope", k8sGateAll, []k8sSrc{apiserver("--v=2")}, "kube_scheduler_feature_gates_set", "|complete"},
		{"other components are separate", []string{K8sScopeAPIServer, K8sScopeControllerManager}, []k8sSrc{apiserver("--feature-gates=OnlyAPIServer=true")}, "kube_controller_manager_feature_gates_set", "|complete"},
		{"kube-proxy config gates", []string{K8sScopeKubeProxy}, []k8sSrc{{scope: K8sScopeKubeProxy, format: K8sFormatKubeProxyConfig, body: "apiVersion: kubeproxy.config.k8s.io/v1alpha1\nkind: KubeProxyConfiguration\nfeatureGates: {ProxyGate: true}\n"}}, "kube_proxy_feature_gates_set", "ProxyGate|complete"},
		{"featureGates not a map is unresolved", []string{K8sScopeKubeProxy}, []k8sSrc{{scope: K8sScopeKubeProxy, format: K8sFormatKubeProxyConfig, body: "apiVersion: kubeproxy.config.k8s.io/v1alpha1\nkind: KubeProxyConfiguration\nfeatureGates: [ProxyGate]\n"}}, "kube_proxy_feature_gates_set", "|partial"},
		{"kubeadm extra args route gates", []string{K8sScopeControllerManager, K8sScopeKubeadm}, []k8sSrc{{scope: K8sScopeKubeadm, format: K8sFormatKubeadmConfig, body: "apiVersion: kubeadm.k8s.io/v1beta4\nkind: ClusterConfiguration\ncontrollerManager:\n  extraArgs:\n  - {name: feature-gates, value: KcmGate=false}\n"}}, "kube_controller_manager_feature_gates_set", "KcmGate|complete"},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, facts := k8sSetFacts(t, "1.36.2", "1.37.0", test.complete, k8sSetsRegistered, test.sources...)
			if got := k8sSetState(t, facts, "component.kubernetes."+test.fact); got != test.want {
				t.Fatalf("%s = %q, want %q", test.fact, got, test.want)
			}
		})
	}
}

func TestKubernetesComponentSetFactsEmission(t *testing.T) {
	apiserver := k8sSrc{scope: K8sScopeAPIServer, format: K8sFormatPodManifest, body: k8sStaticPod("kube-apiserver", "--feature-gates=RemovedGate=false", "--etcd-servers=https://private-etcd.example:2379")}
	onlyAPIServer := func(id string) bool { return strings.HasPrefix(id, "component.kubernetes.kube_apiserver_") }

	// Only registered set facts are emitted; a line without predicates is
	// still prepared when a set fact is registered.
	prepared, facts := k8sSetFacts(t, "1.38.0", "1.39.0", []string{K8sScopeAPIServer}, onlyAPIServer, apiserver)
	if len(facts) != 2 || prepared.State != StatePrepared || prepared.Reason != ReasonKubernetesComponentSettingSetsComplete {
		t.Fatalf("state=%s reason=%s facts=%v", prepared.State, prepared.Reason, facts)
	}
	if k8sSetState(t, facts, "component.kubernetes.kube_apiserver_flags_set") != "etcd-servers,feature-gates|complete" {
		t.Fatalf("flags=%v", facts)
	}
	// Argument values and paths never reach the canonical input.
	for _, private := range []string{"private-etcd", "2379", "/private/selected", "RemovedGate=false"} {
		if bytes.Contains(prepared.CanonicalInputJSON, []byte(private)) {
			t.Fatalf("canonical input leaks %q: %s", private, prepared.CanonicalInputJSON)
		}
	}
	again, _ := k8sSetFacts(t, "1.38.0", "1.39.0", []string{K8sScopeAPIServer}, onlyAPIServer, apiserver)
	if !bytes.Equal(again.CanonicalInputJSON, prepared.CanonicalInputJSON) {
		t.Fatal("set preparation is not deterministic")
	}

	partial, _ := k8sSetFacts(t, "1.38.0", "1.39.0", nil, onlyAPIServer, apiserver)
	if partial.State != StateUnknown || partial.Reason != ReasonKubernetesComponentEvidenceIncomplete {
		t.Fatalf("partial state=%s reason=%s", partial.State, partial.Reason)
	}

	// Set facts follow the adapter's single-minor-line rule.
	for _, pair := range [][2]string{{"1.36.0", "1.38.0"}, {"1.37.0", "1.37.3"}} {
		prepared, facts := k8sSetFacts(t, pair[0], pair[1], []string{K8sScopeAPIServer}, k8sSetsRegistered, apiserver)
		if len(facts) != 0 || prepared.Reason != ReasonKubernetesComponentNoReviewedRule {
			t.Fatalf("pair %v reason=%s facts=%v", pair, prepared.Reason, facts)
		}
	}

	// Unregistered set facts are never emitted, so predicate preparation is
	// unchanged.
	_, none := k8sSetFacts(t, "1.38.0", "1.39.0", []string{K8sScopeAPIServer}, func(string) bool { return false }, apiserver)
	if len(none) != 0 {
		t.Fatalf("unregistered set facts emitted: %v", none)
	}

	// A custom build declares nothing.
	selection, contents := k8sSelection(t, []string{K8sScopeAPIServer}, nil, apiserver)
	custom, err := PrepareKubernetesComponentConfig(selection, contents, "1.38.0", "1.39.0", "custom_build", k8sSetsRegistered)
	if err != nil || custom.Reason != ReasonKubernetesComponentDistribution {
		t.Fatalf("custom err=%v reason=%s", err, custom.Reason)
	}
	customFacts := k8sProposedFacts(t, custom)
	if len(customFacts) != len(KubernetesComponentConfigSetFacts()) {
		t.Fatalf("custom distribution facts=%v", customFacts)
	}
	for id, view := range customFacts {
		if view.State != "unsupported" || view.SetValue != nil {
			t.Fatalf("custom distribution declared %s: %+v", id, view)
		}
	}
}

// TestKubernetesComponentSetFactsBound: a set the engine cannot hold is
// declared unsupported rather than truncated.
func TestKubernetesComponentSetFactsBound(t *testing.T) {
	args := make([]string, 0, 257)
	for index := 0; index < 257; index++ {
		args = append(args, fmt.Sprintf("--flag-%03d=x", index))
	}
	over := k8sSrc{scope: K8sScopeAPIServer, format: K8sFormatPodManifest, body: k8sStaticPod("kube-apiserver", args...)}
	prepared, facts := k8sSetFacts(t, "1.38.0", "1.39.0", []string{K8sScopeAPIServer}, k8sSetsRegistered, over)
	if k8sSetState(t, facts, "component.kubernetes.kube_apiserver_flags_set") != "unsupported" || prepared.Reason != ReasonKubernetesComponentEvidenceIncomplete {
		t.Fatalf("over-limit set: reason=%s facts=%v", prepared.Reason, facts["component.kubernetes.kube_apiserver_flags_set"])
	}
	at := k8sSrc{scope: K8sScopeAPIServer, format: K8sFormatPodManifest, body: k8sStaticPod("kube-apiserver", args[:256]...)}
	_, facts = k8sSetFacts(t, "1.38.0", "1.39.0", []string{K8sScopeAPIServer}, k8sSetsRegistered, at)
	if state := k8sSetState(t, facts, "component.kubernetes.kube_apiserver_flags_set"); !strings.HasSuffix(state, "|complete") || strings.Count(state, ",") != 255 {
		t.Fatalf("set at the bound: %.80s", state)
	}
}

func TestKubernetesComponentSetFactTable(t *testing.T) {
	facts := KubernetesComponentConfigSetFacts()
	want := []string{
		"component.kubernetes.kube_apiserver_feature_gates_set", "component.kubernetes.kube_apiserver_flags_set",
		"component.kubernetes.kube_controller_manager_feature_gates_set", "component.kubernetes.kube_controller_manager_flags_set",
		"component.kubernetes.kube_scheduler_feature_gates_set", "component.kubernetes.kube_scheduler_flags_set",
		"component.kubernetes.kubelet_feature_gates_set", "component.kubernetes.kubelet_flags_set",
		"component.kubernetes.kube_proxy_feature_gates_set", "component.kubernetes.kube_proxy_flags_set",
	}
	if strings.Join(facts, " ") != strings.Join(want, " ") {
		t.Fatalf("set facts = %v", facts)
	}
	all := strings.Join(KubernetesComponentConfigAllFacts(), " ")
	for _, fact := range want {
		if !strings.Contains(all, fact) {
			t.Fatalf("%s missing from the adapter fact family", fact)
		}
		if _, lined := KubernetesComponentConfigFactLines()[fact]; lined {
			t.Fatalf("%s is tied to a minor line", fact)
		}
	}
}
