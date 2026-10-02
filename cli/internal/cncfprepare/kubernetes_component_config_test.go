// SPDX-License-Identifier: AGPL-3.0-only

package cncfprepare

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"testing"
)

type k8sSrc struct {
	scope, format, body string
	static              bool
}

func k8sSelection(t *testing.T, complete []string, cgroupV1 *bool, sources ...k8sSrc) (KubernetesComponentSelection, [][]byte) {
	t.Helper()
	type source struct {
		Scope     string `json:"scope"`
		Format    string `json:"format"`
		Path      string `json:"path"`
		StaticPod bool   `json:"staticPod,omitempty"`
	}
	document := map[string]any{"apiVersion": KubernetesComponentSelectionAPIVersion, "kind": KubernetesComponentSelectionKind}
	if complete != nil {
		document["complete"] = complete
	}
	declarations := map[string]any{}
	if cgroupV1 != nil {
		declarations["linuxNodeCgroupV1"] = *cgroupV1
	}
	items := make([]source, 0, len(sources))
	contents := make([][]byte, 0, len(sources))
	for index, src := range sources {
		if src.scope == "declare" {
			declarations[src.format] = true
			continue
		}
		items = append(items, source{Scope: src.scope, Format: src.format, Path: fmt.Sprintf("/private/selected/source-%d", index), StaticPod: src.static})
		contents = append(contents, []byte(src.body))
	}
	if len(declarations) > 0 {
		document["declarations"] = declarations
	}
	document["sources"] = items
	raw, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	selection, err := ParseKubernetesComponentSelection(raw)
	if err != nil {
		t.Fatalf("parse selection %s: %v", raw, err)
	}
	return selection, contents
}

// k8sAllRegistered registers every bool predicate fact. The set facts have
// their own tests (kubernetes_component_sets_test.go), so the predicate tests
// keep their fact counts and preparation reasons.
func k8sAllRegistered(id string) bool { return !strings.HasSuffix(id, "_set") }

func k8sComponentFacts(t *testing.T, from, to string, complete []string, cgroupV1 *bool, sources ...k8sSrc) (Prepared, map[string]k8sFactView) {
	t.Helper()
	selection, contents := k8sSelection(t, complete, cgroupV1, sources...)
	prepared, err := PrepareKubernetesComponentConfig(selection, contents, from, to, "official_upstream", k8sAllRegistered)
	if err != nil {
		t.Fatalf("prepare: %v", err)
	}
	return prepared, k8sProposedFacts(t, prepared)
}

func k8sFactState(view k8sFactView, found bool) string {
	switch {
	case !found:
		return "absent-from-input"
	case view.State == "declared" && view.BoolValue != nil && *view.BoolValue:
		return "true"
	case view.State == "declared" && view.BoolValue != nil:
		return "false"
	default:
		return view.State
	}
}

var (
	k8sAllScopes  = []string{K8sScopeAPIServer, K8sScopeControllerManager, K8sScopeScheduler, K8sScopeKubelet, K8sScopeKubeProxy, K8sScopeKubeadm, K8sScopeStaticPods, K8sScopeWorkloads}
	k8sGateAll    = []string{K8sScopeAPIServer, K8sScopeControllerManager, K8sScopeScheduler, K8sScopeKubelet, K8sScopeKubeProxy}
	k8sTrue       = true
	k8sFalse      = false
	k8sKubeletEnv = func(args string) k8sSrc {
		return k8sSrc{scope: K8sScopeKubelet, format: K8sFormatKubeletEnv, body: "# generated\nKUBELET_KUBEADM_ARGS=\"" + args + "\"\n"}
	}
	// k8sNoConfigFile and k8sNoConfigDir add the matching selection declaration.
	k8sNoConfigFile = k8sSrc{scope: "declare", format: "kubeletNoConfigFile"}
	k8sNoConfigDir  = k8sSrc{scope: "declare", format: "kubeletNoConfigDir"}
	k8sArgs         = func(scope string, args ...string) k8sSrc {
		raw, _ := json.Marshal(args)
		return k8sSrc{scope: scope, format: K8sFormatArgs, body: string(raw)}
	}
)

func k8sStaticPod(binary string, args ...string) string {
	command, _ := json.Marshal(append([]string{binary}, args...))
	return `apiVersion: v1
kind: Pod
metadata:
  name: ` + binary + `
  namespace: kube-system
spec:
  containers:
  - name: ` + binary + `
    image: registry.k8s.io/` + binary + `:v1.30.0
    command: ` + string(command) + `
`
}

func k8sDeployment(volumes string) string {
	return `apiVersion: apps/v1
kind: Deployment
metadata: {name: app}
spec:
  template:
    metadata: {labels: {app: x}}
    spec:
      containers: [{name: app, image: app}]
      volumes: ` + volumes + `
`
}

func TestKubernetesComponentConfigPredicates(t *testing.T) {
	kubeletConfig := func(extra string) k8sSrc {
		return k8sSrc{scope: K8sScopeKubelet, format: K8sFormatKubeletConfig, body: "apiVersion: kubelet.config.k8s.io/v1beta1\nkind: KubeletConfiguration\n" + extra}
	}
	for _, test := range []struct {
		name, from, to, fact, want string
		complete                   []string
		cgroup                     *bool
		sources                    []k8sSrc
	}{
		// Removed flags: presence is decisive; absence needs a complete scope.
		{"kubelet dockershim flag present without completeness", "1.23.4", "1.24.0", "kubelet_dockershim_flags_removed", "true", nil, nil, []k8sSrc{k8sKubeletEnv("--network-plugin=cni --pod-infra-container-image=pause")}},
		{"kubelet dockershim flags absent and complete", "1.23.4", "1.24.0", "kubelet_dockershim_flags_removed", "false", []string{K8sScopeKubelet}, nil, []k8sSrc{k8sKubeletEnv("--container-runtime-endpoint=unix:///run/containerd/containerd.sock")}},
		{"kubelet dockershim flags absent but incomplete", "1.23.4", "1.24.0", "kubelet_dockershim_flags_removed", "unsupported", nil, nil, []k8sSrc{k8sKubeletEnv("--v=2")}},
		{"underscore spelling is normalised", "1.23.0", "1.24.1", "kubelet_dockershim_flags_removed", "true", nil, nil, []k8sSrc{k8sArgs(K8sScopeKubelet, "--cni_bin_dir=/opt/cni/bin")}},
		{"separate value spelling", "1.23.0", "1.24.0", "kubelet_dockershim_flags_removed", "true", nil, nil, []k8sSrc{k8sArgs(K8sScopeKubelet, "--docker-endpoint", "unix:///var/run/docker.sock")}},
		{"single dash is a shorthand not the long option", "1.23.0", "1.24.0", "kubelet_dockershim_flags_removed", "false", []string{K8sScopeKubelet}, nil, []k8sSrc{k8sArgs(K8sScopeKubelet, "-v=2")}},
		{"end of options leaves arguments unresolved", "1.23.0", "1.24.0", "kubelet_dockershim_flags_removed", "unsupported", []string{K8sScopeKubelet}, nil, []k8sSrc{k8sArgs(K8sScopeKubelet, "--v=2", "--", "x")}},
		{"shell expansion in env file is unresolved", "1.23.0", "1.24.0", "kubelet_dockershim_flags_removed", "unsupported", []string{K8sScopeKubelet}, nil, []k8sSrc{{scope: K8sScopeKubelet, format: K8sFormatKubeletEnv, body: "KUBELET_EXTRA_ARGS=$EXTRA\n"}}},
		{"templated source is unresolved", "1.23.0", "1.24.0", "kubelet_dockershim_flags_removed", "unsupported", []string{K8sScopeKubelet}, nil, []k8sSrc{k8sArgs(K8sScopeKubelet, "--v={{ .Verbosity }}")}},
		{"static pod insecure port", "1.23.0", "1.24.0", "apiserver_insecure_address_flags_removed", "true", nil, nil, []k8sSrc{{scope: K8sScopeAPIServer, format: K8sFormatPodManifest, body: k8sStaticPod("kube-apiserver", "--insecure-port=0", "--secure-port=6443")}}},
		{"static pod clear and complete", "1.23.0", "1.24.0", "apiserver_insecure_address_flags_removed", "false", []string{K8sScopeAPIServer}, nil, []k8sSrc{{scope: K8sScopeAPIServer, format: K8sFormatPodManifest, body: k8sStaticPod("kube-apiserver", "--secure-port=6443")}}},
		{"static pod for another binary is unresolved", "1.23.0", "1.24.0", "apiserver_insecure_address_flags_removed", "unsupported", []string{K8sScopeAPIServer}, nil, []k8sSrc{{scope: K8sScopeAPIServer, format: K8sFormatPodManifest, body: k8sStaticPod("/usr/local/bin/wrapper", "--secure-port=6443")}}},
		{"absolute binary path matches", "1.23.0", "1.24.0", "controller_manager_insecure_flags_removed", "true", nil, nil, []k8sSrc{{scope: K8sScopeControllerManager, format: K8sFormatPodManifest, body: k8sStaticPod("/usr/local/bin/kube-controller-manager", "--port=0")}}},

		// kubeadm extraArgs: map form up to v1beta3, list form from v1beta4.
		{"kubeadm v1beta3 map extraArgs", "1.23.0", "1.24.0", "apiserver_insecure_address_flags_removed", "true", nil, nil, []k8sSrc{{scope: K8sScopeKubeadm, format: K8sFormatKubeadmConfig, body: "apiVersion: kubeadm.k8s.io/v1beta3\nkind: ClusterConfiguration\napiServer:\n  extraArgs:\n    insecure-port: \"0\"\n"}}},
		{"kubeadm v1beta4 list extraArgs", "1.34.2", "1.35.0", "kubelet_pod_infra_container_image_removed", "true", nil, nil, []k8sSrc{{scope: K8sScopeKubeadm, format: K8sFormatKubeadmConfig, body: "apiVersion: kubeadm.k8s.io/v1beta4\nkind: InitConfiguration\nnodeRegistration:\n  kubeletExtraArgs:\n  - name: pod-infra-container-image\n    value: registry.k8s.io/pause:3.10\n"}}},
		{"kubeadm map form in v1beta4 is unresolved", "1.34.2", "1.35.0", "kubelet_pod_infra_container_image_removed", "unsupported", []string{K8sScopeKubelet, K8sScopeKubeadm}, nil, []k8sSrc{{scope: K8sScopeKubeadm, format: K8sFormatKubeadmConfig, body: "apiVersion: kubeadm.k8s.io/v1beta4\nkind: InitConfiguration\nnodeRegistration:\n  kubeletExtraArgs:\n    v: \"2\"\n"}}},
		{"kubeadm list form in v1beta3 is unresolved", "1.23.0", "1.24.0", "apiserver_insecure_address_flags_removed", "unsupported", []string{K8sScopeAPIServer, K8sScopeKubeadm}, nil, []k8sSrc{{scope: K8sScopeKubeadm, format: K8sFormatKubeadmConfig, body: "apiVersion: kubeadm.k8s.io/v1beta3\nkind: ClusterConfiguration\napiServer:\n  extraArgs:\n  - name: insecure-port\n    value: \"0\"\n"}}},
		{"kubeadm v1beta4 list clear with complete scopes", "1.34.2", "1.35.0", "kubelet_pod_infra_container_image_removed", "false", []string{K8sScopeKubelet}, nil, []k8sSrc{{scope: K8sScopeKubeadm, format: K8sFormatKubeadmConfig, body: "apiVersion: kubeadm.k8s.io/v1beta4\nkind: JoinConfiguration\nnodeRegistration:\n  kubeletExtraArgs:\n  - name: v\n    value: \"2\"\n"}}},
		{"kubeadm config v1beta3 present", "1.36.1", "1.37.0", "kubeadm_config_v1beta3_removed", "true", nil, nil, []k8sSrc{{scope: K8sScopeKubeadm, format: K8sFormatKubeadmConfig, body: "apiVersion: kubeadm.k8s.io/v1beta3\nkind: ClusterConfiguration\n"}}},
		{"kubeadm config v1beta4 complete", "1.36.1", "1.37.0", "kubeadm_config_v1beta3_removed", "false", []string{K8sScopeKubeadm}, nil, []k8sSrc{{scope: K8sScopeKubeadm, format: K8sFormatKubeadmConfig, body: "apiVersion: kubeadm.k8s.io/v1beta4\nkind: ClusterConfiguration\n---\napiVersion: kubelet.config.k8s.io/v1beta1\nkind: KubeletConfiguration\n"}}},
		{"kubeadm config map v1beta3 present", "1.36.1", "1.37.0", "kubeadm_config_v1beta3_removed", "true", nil, nil, []k8sSrc{{scope: K8sScopeKubeadm, format: K8sFormatKubeadmConfig, body: "apiVersion: v1\nkind: ConfigMap\nmetadata: {name: kubeadm-config, namespace: kube-system}\ndata:\n  ClusterConfiguration: |\n    apiVersion: kubeadm.k8s.io/v1beta3\n    kind: ClusterConfiguration\n"}}},

		// Feature gates in flag and configuration form.
		{"removed gate in kube-proxy flag", "1.36.0", "1.37.0", "feature_gates_sidecarcontainers_removed", "true", nil, nil, []k8sSrc{k8sArgs(K8sScopeKubeProxy, "--feature-gates=SidecarContainers=true,Foo=false")}},
		{"removed gate in kubelet config", "1.36.0", "1.37.0", "feature_gates_sidecarcontainers_removed", "true", nil, nil, []k8sSrc{kubeletConfig("featureGates:\n  SidecarContainers: true\n")}},
		{"removed gate in kubeadm extraArgs", "1.22.0", "1.23.0", "feature_gates_boundserviceaccounttokenvolume_removed", "true", nil, nil, []k8sSrc{{scope: K8sScopeKubeadm, format: K8sFormatKubeadmConfig, body: "apiVersion: kubeadm.k8s.io/v1beta3\nkind: ClusterConfiguration\ncontrollerManager:\n  extraArgs:\n    feature-gates: BoundServiceAccountTokenVolume=true\n"}}},
		{"gates absent in every complete component", "1.36.0", "1.37.0", "feature_gates_sidecarcontainers_removed", "false", k8sGateAll, nil, []k8sSrc{k8sArgs(K8sScopeKubeProxy, "--feature-gates=Foo=true"), kubeletConfig("featureGates: {Bar: false}\n")}},
		{"gates absent but one component incomplete", "1.36.0", "1.37.0", "feature_gates_sidecarcontainers_removed", "unsupported", []string{K8sScopeAPIServer, K8sScopeControllerManager, K8sScopeScheduler, K8sScopeKubelet}, nil, []k8sSrc{kubeletConfig("featureGates: {Bar: false}\n")}},
		{"kubelet config referenced but not supplied", "1.36.0", "1.37.0", "feature_gates_sidecarcontainers_removed", "unsupported", k8sGateAll, nil, []k8sSrc{k8sKubeletEnv("--config=/var/lib/kubelet/config.yaml")}},
		{"case variant key is unresolved", "1.36.0", "1.37.0", "feature_gates_sidecarcontainers_removed", "unsupported", k8sGateAll, nil, []k8sSrc{kubeletConfig("FeatureGates:\n  SidecarContainers: true\n")}},
		{"kubelet config through ConfigMap", "1.27.0", "1.28.0", "feature_gates_podsecurity_acceleratormetrics_removed", "true", nil, nil, []k8sSrc{{scope: K8sScopeKubelet, format: K8sFormatKubeletConfig, body: "apiVersion: v1\nkind: ConfigMap\nmetadata: {name: kubelet-config}\ndata:\n  kubelet: |\n    apiVersion: kubelet.config.k8s.io/v1beta1\n    kind: KubeletConfiguration\n    featureGates:\n      DisableAcceleratorUsageMetrics: true\n"}}},
		{"cloud provider gates removed", "1.32.0", "1.33.0", "feature_gates_disablecloudproviders_removed", "true", nil, nil, []k8sSrc{k8sArgs(K8sScopeControllerManager, "--feature-gates", "DisableCloudProviders=false")}},

		// cgroup v1 node declaration with the failCgroupV1 override.
		{"cgroup v1 node without override blocks", "1.34.1", "1.35.0", "kubelet_cgroup_v1_fail_by_default", "true", []string{K8sScopeKubelet}, &k8sTrue, []k8sSrc{kubeletConfig("cgroupDriver: systemd\n")}},
		{"cgroup v1 node with failCgroupV1 false passes", "1.34.1", "1.35.0", "kubelet_cgroup_v1_fail_by_default", "false", []string{K8sScopeKubelet}, &k8sTrue, []k8sSrc{kubeletConfig("failCgroupV1: false\n")}},
		{"cgroup v1 override by flag", "1.34.1", "1.35.0", "kubelet_cgroup_v1_fail_by_default", "false", []string{K8sScopeKubelet}, &k8sTrue, []k8sSrc{k8sKubeletEnv("--fail-cgroupv1=false"), k8sNoConfigFile}},
		{"cgroup v1 bare flag means true", "1.34.1", "1.35.0", "kubelet_cgroup_v1_fail_by_default", "true", nil, &k8sTrue, []k8sSrc{k8sKubeletEnv("--fail-cgroupv1")}},
		{"cgroup v1 explicit true", "1.34.1", "1.35.0", "kubelet_cgroup_v1_fail_by_default", "true", nil, &k8sTrue, []k8sSrc{kubeletConfig("failCgroupV1: true\n")}},
		{"cgroup v1 override with incomplete kubelet evidence", "1.34.1", "1.35.0", "kubelet_cgroup_v1_fail_by_default", "unsupported", nil, &k8sTrue, []k8sSrc{kubeletConfig("failCgroupV1: false\n")}},
		{"cgroup v1 default with incomplete kubelet evidence", "1.34.1", "1.35.0", "kubelet_cgroup_v1_fail_by_default", "unsupported", nil, &k8sTrue, []k8sSrc{kubeletConfig("cgroupDriver: systemd\n")}},
		{"no cgroup v1 node declared", "1.34.1", "1.35.0", "kubelet_cgroup_v1_fail_by_default", "false", nil, &k8sFalse, []k8sSrc{kubeletConfig("cgroupDriver: systemd\n")}},
		{"cgroup v1 undeclared", "1.34.1", "1.35.0", "kubelet_cgroup_v1_fail_by_default", "unsupported", []string{K8sScopeKubelet}, nil, []k8sSrc{kubeletConfig("failCgroupV1: false\n")}},
		{"cgroup v1 non-boolean override", "1.34.1", "1.35.0", "kubelet_cgroup_v1_fail_by_default", "unsupported", []string{K8sScopeKubelet}, &k8sTrue, []k8sSrc{kubeletConfig("failCgroupV1: \"no\"\n")}},

		// Admission plugins and other list or value options.
		{"psp admission plugin", "1.24.0", "1.25.0", "apiserver_psp_admission_plugin_removed", "true", nil, nil, []k8sSrc{k8sArgs(K8sScopeAPIServer, "--enable-admission-plugins=NodeRestriction,PodSecurityPolicy")}},
		{"psp absent", "1.24.0", "1.25.0", "apiserver_psp_admission_plugin_removed", "false", []string{K8sScopeAPIServer}, nil, []k8sSrc{k8sArgs(K8sScopeAPIServer, "--enable-admission-plugins=NodeRestriction")}},
		{"securitycontextdeny plugin", "1.29.3", "1.30.0", "apiserver_securitycontextdeny_plugin_removed", "true", nil, nil, []k8sSrc{k8sArgs(K8sScopeAPIServer, "--enable-admission-plugins", "SecurityContextDeny")}},
		{"in-tree aws on kubelet", "1.26.0", "1.27.0", "in_tree_aws_cloud_provider_removed", "true", nil, nil, []k8sSrc{k8sKubeletEnv("--cloud-provider=aws")}},
		{"external provider everywhere", "1.26.0", "1.27.0", "in_tree_aws_cloud_provider_removed", "false", []string{K8sScopeAPIServer, K8sScopeControllerManager, K8sScopeKubelet}, nil, []k8sSrc{k8sKubeletEnv("--cloud-provider=external"), k8sArgs(K8sScopeControllerManager, "--cloud-provider=external")}},
		{"provider value from runtime expansion", "1.26.0", "1.27.0", "in_tree_aws_cloud_provider_removed", "unsupported", []string{K8sScopeAPIServer, K8sScopeControllerManager, K8sScopeKubelet}, nil, []k8sSrc{k8sArgs(K8sScopeControllerManager, "--cloud-provider=$(PROVIDER)")}},
		{"in-tree provider with opt-in gate", "1.28.4", "1.29.0", "in_tree_cloud_providers_off_by_default", "false", []string{K8sScopeAPIServer, K8sScopeControllerManager, K8sScopeKubelet}, nil, []k8sSrc{k8sArgs(K8sScopeControllerManager, "--cloud-provider=gce", "--feature-gates=DisableCloudProviders=false")}},
		{"in-tree provider without opt-in", "1.28.4", "1.29.0", "in_tree_cloud_providers_off_by_default", "true", nil, nil, []k8sSrc{k8sArgs(K8sScopeControllerManager, "--cloud-provider=gce")}},
		{"kcm external value", "1.31.0", "1.32.0", "kcm_cloud_provider_value_invalid", "false", []string{K8sScopeControllerManager}, nil, []k8sSrc{k8sArgs(K8sScopeControllerManager, "--cloud-provider=external")}},
		{"kcm empty value", "1.31.0", "1.32.0", "kcm_cloud_provider_value_invalid", "false", []string{K8sScopeControllerManager}, nil, []k8sSrc{k8sArgs(K8sScopeControllerManager, "--cloud-provider=")}},
		{"kcm in-tree value", "1.31.0", "1.32.0", "kcm_cloud_provider_value_invalid", "true", nil, nil, []k8sSrc{k8sArgs(K8sScopeControllerManager, "--cloud-provider", "azure")}},
		{"kcm value missing", "1.31.0", "1.32.0", "kcm_cloud_provider_value_invalid", "unsupported", []string{K8sScopeControllerManager}, nil, []k8sSrc{k8sArgs(K8sScopeControllerManager, "--cloud-provider")}},

		// Component configuration documents.
		{"scheduler config v1beta2", "1.27.0", "1.28.0", "kube_scheduler_config_v1beta2_removed", "true", nil, nil, []k8sSrc{{scope: K8sScopeScheduler, format: K8sFormatSchedulerConfig, body: "apiVersion: kubescheduler.config.k8s.io/v1beta2\nkind: KubeSchedulerConfiguration\n"}}},
		{"scheduler config v1 complete", "1.27.0", "1.28.0", "kube_scheduler_config_v1beta2_removed", "false", []string{K8sScopeScheduler}, nil, []k8sSrc{k8sArgs(K8sScopeScheduler, "--config=/etc/kubernetes/scheduler.yaml"), {scope: K8sScopeScheduler, format: K8sFormatSchedulerConfig, body: "apiVersion: kubescheduler.config.k8s.io/v1\nkind: KubeSchedulerConfiguration\n"}}},
		{"scheduler config referenced and missing", "1.27.0", "1.28.0", "kube_scheduler_config_v1beta2_removed", "unsupported", []string{K8sScopeScheduler}, nil, []k8sSrc{k8sArgs(K8sScopeScheduler, "--config=/etc/kubernetes/scheduler.yaml")}},
		{"scheduler without config file", "1.28.0", "1.29.0", "kube_scheduler_config_v1beta3_removed", "false", []string{K8sScopeScheduler}, nil, []k8sSrc{{scope: K8sScopeScheduler, format: K8sFormatPodManifest, body: k8sStaticPod("kube-scheduler", "--kubeconfig=/etc/kubernetes/scheduler.conf")}}},
		{"scheduler removed volume-limit plugin", "1.31.0", "1.32.0", "scheduler_noncsi_volumelimit_plugins_removed", "true", nil, nil, []k8sSrc{{scope: K8sScopeScheduler, format: K8sFormatSchedulerConfig, body: "apiVersion: kubescheduler.config.k8s.io/v1\nkind: KubeSchedulerConfiguration\nprofiles:\n- schedulerName: default-scheduler\n  plugins:\n    filter:\n      enabled:\n      - name: EBSLimits\n"}}},
		{"scheduler plugins clear", "1.31.0", "1.32.0", "scheduler_noncsi_volumelimit_plugins_removed", "false", []string{K8sScopeScheduler}, nil, []k8sSrc{{scope: K8sScopeScheduler, format: K8sFormatSchedulerConfig, body: "apiVersion: kubescheduler.config.k8s.io/v1\nkind: KubeSchedulerConfiguration\nprofiles:\n- schedulerName: default-scheduler\n  plugins:\n    filter:\n      disabled:\n      - name: NodePorts\n  pluginConfig:\n  - name: NodeResourcesFit\n    args: {}\n"}}},
		{"kube-proxy userspace in ConfigMap", "1.25.0", "1.26.0", "kube_proxy_userspace_mode_removed", "true", nil, nil, []k8sSrc{{scope: K8sScopeKubeProxy, format: K8sFormatKubeProxyConfig, body: "apiVersion: v1\nkind: ConfigMap\nmetadata: {name: kube-proxy}\ndata:\n  config.conf: |\n    apiVersion: kubeproxy.config.k8s.io/v1alpha1\n    kind: KubeProxyConfiguration\n    mode: userspace\n"}}},
		{"kube-proxy userspace flag in daemonset", "1.25.0", "1.26.0", "kube_proxy_userspace_mode_removed", "true", nil, nil, []k8sSrc{{scope: K8sScopeKubeProxy, format: K8sFormatPodManifest, body: "apiVersion: apps/v1\nkind: DaemonSet\nmetadata: {name: kube-proxy}\nspec:\n  template:\n    spec:\n      containers:\n      - name: kube-proxy\n        command: [/usr/local/bin/kube-proxy, --proxy-mode=userspace, --hostname-override=$(NODE_NAME)]\n"}}},
		{"kube-proxy iptables complete", "1.25.0", "1.26.0", "kube_proxy_userspace_mode_removed", "false", []string{K8sScopeKubeProxy}, nil, []k8sSrc{k8sArgs(K8sScopeKubeProxy, "--config=/var/lib/kube-proxy/config.conf"), {scope: K8sScopeKubeProxy, format: K8sFormatKubeProxyConfig, body: "apiVersion: kubeproxy.config.k8s.io/v1alpha1\nkind: KubeProxyConfiguration\nmode: iptables\n"}}},
		{"memory swap unlimited", "1.29.0", "1.30.0", "kubelet_memoryswap_unlimitedswap_dropped", "true", nil, nil, []k8sSrc{kubeletConfig("memorySwap:\n  swapBehavior: UnlimitedSwap\n")}},
		{"memory swap limited", "1.29.0", "1.30.0", "kubelet_memoryswap_unlimitedswap_dropped", "false", []string{K8sScopeKubelet}, nil, []k8sSrc{kubeletConfig("memorySwap:\n  swapBehavior: LimitedSwap\n")}},
		{"webhook admission v1alpha1 embedded", "1.35.0", "1.36.0", "apiserver_webhook_admission_config_v1alpha1_removed", "true", nil, nil, []k8sSrc{{scope: K8sScopeAPIServer, format: K8sFormatAdmissionConfig, body: "apiVersion: apiserver.config.k8s.io/v1\nkind: AdmissionConfiguration\nplugins:\n- name: ValidatingAdmissionWebhook\n  configuration:\n    apiVersion: apiserver.config.k8s.io/v1alpha1\n    kind: WebhookAdmission\n    kubeConfigFile: /etc/kubernetes/webhook.kubeconfig\n"}}},
		{"webhook admission v1 complete", "1.35.0", "1.36.0", "apiserver_webhook_admission_config_v1alpha1_removed", "false", []string{K8sScopeAPIServer}, nil, []k8sSrc{k8sArgs(K8sScopeAPIServer, "--admission-control-config-file=/etc/kubernetes/admission.yaml"), {scope: K8sScopeAPIServer, format: K8sFormatAdmissionConfig, body: "apiVersion: apiserver.config.k8s.io/v1\nkind: AdmissionConfiguration\nplugins:\n- name: ValidatingAdmissionWebhook\n  configuration:\n    apiVersion: apiserver.config.k8s.io/v1\n    kind: WebhookAdmissionConfiguration\n"}}},
		{"webhook admission path not supplied", "1.35.0", "1.36.0", "apiserver_webhook_admission_config_v1alpha1_removed", "unsupported", []string{K8sScopeAPIServer}, nil, []k8sSrc{{scope: K8sScopeAPIServer, format: K8sFormatAdmissionConfig, body: "apiVersion: apiserver.config.k8s.io/v1\nkind: AdmissionConfiguration\nplugins:\n- name: ValidatingAdmissionWebhook\n  path: /etc/kubernetes/webhook.yaml\n"}}},
		{"admission config referenced and missing", "1.35.0", "1.36.0", "apiserver_webhook_admission_config_v1alpha1_removed", "unsupported", []string{K8sScopeAPIServer}, nil, []k8sSrc{k8sArgs(K8sScopeAPIServer, "--admission-control-config-file=/etc/kubernetes/admission.yaml")}},

		// Field-level manifest predicates.
		{"seccomp alpha annotation in a workload is still copied by the API server", "1.24.0", "1.25.0", "static_pod_seccomp_alpha_annotations_ignored", "false", []string{K8sScopeStaticPods}, nil, []k8sSrc{{scope: K8sScopeWorkloads, format: K8sFormatManifests, body: "apiVersion: batch/v1\nkind: CronJob\nmetadata: {name: c}\nspec:\n  jobTemplate:\n    spec:\n      template:\n        metadata:\n          annotations:\n            container.seccomp.security.alpha.kubernetes.io/app: runtime/default\n        spec:\n          containers: [{name: app, image: app}]\n"}}},
		{"seccomp alpha annotation in a static pod", "1.24.0", "1.25.0", "static_pod_seccomp_alpha_annotations_ignored", "true", nil, nil, []k8sSrc{{scope: K8sScopeStaticPods, format: K8sFormatPodManifest, body: "apiVersion: v1\nkind: Pod\nmetadata:\n  name: p\n  annotations:\n    seccomp.security.alpha.kubernetes.io/pod: runtime/default\nspec:\n  containers: [{name: app, image: app}]\n"}}},
		{"seccomp fields only", "1.24.0", "1.25.0", "static_pod_seccomp_alpha_annotations_ignored", "false", []string{K8sScopeStaticPods}, nil, []k8sSrc{{scope: K8sScopeStaticPods, format: K8sFormatPodManifest, body: "apiVersion: v1\nkind: Pod\nmetadata: {name: p}\nspec:\n  containers: [{name: app, securityContext: {seccompProfile: {type: RuntimeDefault}}}]\n"}}},
		{"seccomp needs complete static pods", "1.24.0", "1.25.0", "static_pod_seccomp_alpha_annotations_ignored", "unsupported", []string{K8sScopeWorkloads}, nil, []k8sSrc{{scope: K8sScopeWorkloads, format: K8sFormatManifests, body: k8sDeployment("[]")}}},
		{"rbd persistent volume", "1.30.2", "1.31.0", "in_tree_rbd_volume_plugin_removed", "true", nil, nil, []k8sSrc{{scope: K8sScopeWorkloads, format: K8sFormatManifests, body: `{"apiVersion":"v1","kind":"List","items":[{"apiVersion":"v1","kind":"PersistentVolume","metadata":{"name":"pv"},"spec":{"rbd":{"image":"x","monitors":["m"]}}}]}`}}},
		{"rbd pod volume", "1.30.2", "1.31.0", "in_tree_rbd_volume_plugin_removed", "true", nil, nil, []k8sSrc{{scope: K8sScopeWorkloads, format: K8sFormatManifests, body: k8sDeployment("[{name: data, rbd: {image: x, monitors: [m]}}]")}}},
		{"rbd key in an unrecognised place", "1.30.2", "1.31.0", "in_tree_rbd_volume_plugin_removed", "unsupported", k8sPodScopes, nil, []k8sSrc{{scope: K8sScopeWorkloads, format: K8sFormatManifests, body: "apiVersion: example.com/v1\nkind: Thing\nmetadata: {name: t}\nspec:\n  storage:\n    rbd: {image: x}\n"}}},
		{"paginated manifest list is unresolved", "1.30.2", "1.31.0", "in_tree_rbd_volume_plugin_removed", "unsupported", k8sPodScopes, nil, []k8sSrc{{scope: K8sScopeWorkloads, format: K8sFormatManifests, body: `{"apiVersion":"v1","kind":"List","metadata":{"continue":"abc"},"items":[]}`}}},
		{"gitRepo volume removed", "1.35.0", "1.36.0", "pod_gitrepo_volume_removed", "true", nil, nil, []k8sSrc{{scope: K8sScopeWorkloads, format: K8sFormatManifests, body: k8sDeployment("[{name: src, gitRepo: {repository: https://example.com/r.git}}]")}}},
		{"gitRepo absent complete", "1.35.0", "1.36.0", "pod_gitrepo_volume_removed", "false", k8sPodScopes, nil, []k8sSrc{{scope: K8sScopeWorkloads, format: K8sFormatManifests, body: k8sDeployment("[{name: cache, emptyDir: {}}]") + "---\napiVersion: v1\nkind: Service\nmetadata: {name: s}\nspec: {ports: [{port: 80}]}\n"}}},
		{"gitRepo disabled by default", "1.32.0", "1.33.0", "pod_gitrepo_volume_disabled_by_default", "true", []string{K8sScopeKubelet}, nil, []k8sSrc{{scope: K8sScopeWorkloads, format: K8sFormatManifests, body: k8sDeployment("[{name: src, gitRepo: {repository: r}}]")}, kubeletConfig("cgroupDriver: systemd\n")}},
		{"gitRepo re-enabled somewhere", "1.32.0", "1.33.0", "pod_gitrepo_volume_disabled_by_default", "unsupported", []string{K8sScopeKubelet}, nil, []k8sSrc{{scope: K8sScopeWorkloads, format: K8sFormatManifests, body: k8sDeployment("[{name: src, gitRepo: {repository: r}}]")}, kubeletConfig("featureGates: {GitRepoVolumeDriver: true}\n")}},
		{"gitRepo with incomplete kubelet evidence", "1.32.0", "1.33.0", "pod_gitrepo_volume_disabled_by_default", "unsupported", nil, nil, []k8sSrc{{scope: K8sScopeWorkloads, format: K8sFormatManifests, body: k8sDeployment("[{name: src, gitRepo: {repository: r}}]")}}},
		{"gitRepo absent needs no kubelet evidence", "1.32.0", "1.33.0", "pod_gitrepo_volume_disabled_by_default", "false", k8sPodScopes, nil, []k8sSrc{{scope: K8sScopeWorkloads, format: K8sFormatManifests, body: k8sDeployment("[]")}}},
		{"portworx volume", "1.35.0", "1.36.0", "in_tree_portworx_volume_plugin_removed", "true", nil, nil, []k8sSrc{{scope: K8sScopeWorkloads, format: K8sFormatManifests, body: k8sDeployment("[{name: px, portworxVolume: {volumeID: v}}]")}}},
		{"static pod secret volume", "1.33.0", "1.34.0", "static_pod_api_object_references_denied", "true", []string{K8sScopeKubelet}, nil, []k8sSrc{{scope: K8sScopeStaticPods, format: K8sFormatPodManifest, body: "apiVersion: v1\nkind: Pod\nmetadata: {name: p}\nspec:\n  containers: [{name: app, image: app}]\n  volumes: [{name: s, secret: {secretName: creds}}]\n"}, kubeletConfig("cgroupDriver: systemd\n")}},
		{"static pod env secret reference", "1.33.0", "1.34.0", "static_pod_api_object_references_denied", "true", []string{K8sScopeKubelet}, nil, []k8sSrc{{scope: K8sScopeAPIServer, format: K8sFormatPodManifest, static: true, body: "apiVersion: v1\nkind: Pod\nmetadata: {name: kube-apiserver}\nspec:\n  containers:\n  - name: kube-apiserver\n    command: [kube-apiserver]\n    env: [{name: X, valueFrom: {secretKeyRef: {name: s, key: k}}}]\n"}, kubeletConfig("cgroupDriver: systemd\n")}},
		{"static pod hostPath only", "1.33.0", "1.34.0", "static_pod_api_object_references_denied", "false", []string{K8sScopeStaticPods}, nil, []k8sSrc{{scope: K8sScopeAPIServer, format: K8sFormatPodManifest, static: true, body: "apiVersion: v1\nkind: Pod\nmetadata: {name: kube-apiserver}\nspec:\n  containers: [{name: kube-apiserver, command: [kube-apiserver]}]\n  volumes: [{name: certs, hostPath: {path: /etc/kubernetes/pki}}, {name: info, projected: {sources: [{downwardAPI: {items: []}}]}}]\n"}}},
		{"static pod projected token", "1.33.0", "1.34.0", "static_pod_api_object_references_denied", "true", []string{K8sScopeKubelet}, nil, []k8sSrc{{scope: K8sScopeStaticPods, format: K8sFormatPodManifest, body: "apiVersion: v1\nkind: Pod\nmetadata: {name: p}\nspec:\n  containers: [{name: app}]\n  volumes: [{name: t, projected: {sources: [{serviceAccountToken: {path: t}}]}}]\n"}, kubeletConfig("cgroupDriver: systemd\n")}},
		{"static pod gate opt-out", "1.33.0", "1.34.0", "static_pod_api_object_references_denied", "unsupported", []string{K8sScopeKubelet, K8sScopeStaticPods}, nil, []k8sSrc{{scope: K8sScopeStaticPods, format: K8sFormatPodManifest, body: "apiVersion: v1\nkind: Pod\nmetadata: {name: p}\nspec:\n  serviceAccountName: x\n  containers: [{name: app}]\n"}, k8sKubeletEnv("--feature-gates=PreventStaticPodAPIReferences=false")}},
		{"yaml anchors are unresolved", "1.35.0", "1.36.0", "pod_gitrepo_volume_removed", "unsupported", k8sPodScopes, nil, []k8sSrc{{scope: K8sScopeWorkloads, format: K8sFormatManifests, body: "apiVersion: v1\nkind: Pod\nmetadata: &m {name: p}\nspec: {containers: [{name: a}]}\n"}}},
		{"cadvisor flag", "1.36.2", "1.37.0", "kubelet_cadvisor_flags_removed", "true", nil, nil, []k8sSrc{k8sKubeletEnv("--containerd=/run/containerd/containerd.sock")}},
		{"containerd endpoint flag is not a cadvisor flag", "1.36.2", "1.37.0", "kubelet_cadvisor_flags_removed", "false", []string{K8sScopeKubelet}, nil, []k8sSrc{k8sKubeletEnv("--container-runtime-endpoint=unix:///run/containerd/containerd.sock --housekeeping-interval=10s")}},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, facts := k8sComponentFacts(t, test.from, test.to, test.complete, test.cgroup, test.sources...)
			view, found := facts["component.kubernetes."+test.fact]
			if got := k8sFactState(view, found); got != test.want {
				t.Fatalf("%s = %s, want %s (facts %+v)", test.fact, got, test.want, facts)
			}
		})
	}
}

func TestKubernetesComponentConfigOverallStateAndPrivacy(t *testing.T) {
	sources := []k8sSrc{k8sKubeletEnv("--network-plugin=cni --node-ip=10.1.2.3"), {scope: K8sScopeAPIServer, format: K8sFormatPodManifest, body: k8sStaticPod("kube-apiserver", "--etcd-servers=https://private-etcd.example:2379")}}
	prepared, facts := k8sComponentFacts(t, "1.23.17", "1.24.0", nil, nil, sources...)
	if prepared.State != StateUnknown || prepared.Reason != ReasonKubernetesComponentSettingPresent {
		t.Fatalf("state=%s reason=%s", prepared.State, prepared.Reason)
	}
	if len(facts) != 3 {
		t.Fatalf("facts for 1.24 = %d (%v)", len(facts), facts)
	}
	for _, private := range []string{"10.1.2.3", "private-etcd", "/private/selected", "cni"} {
		if bytes.Contains(prepared.CanonicalInputJSON, []byte(private)) {
			t.Fatalf("canonical input leaks %q: %s", private, prepared.CanonicalInputJSON)
		}
	}
	again, _ := k8sComponentFacts(t, "1.23.17", "1.24.0", nil, nil, sources...)
	if !bytes.Equal(again.CanonicalInputJSON, prepared.CanonicalInputJSON) || again.SourceDigest != prepared.SourceDigest {
		t.Fatal("preparation is not deterministic")
	}

	clear, _ := k8sComponentFacts(t, "1.23.17", "1.24.0", k8sAllScopes, nil, k8sKubeletEnv("--v=2"))
	if clear.State != StatePrepared || clear.Reason != ReasonKubernetesComponentSettingAbsent {
		t.Fatalf("clear state=%s reason=%s", clear.State, clear.Reason)
	}

	incomplete, _ := k8sComponentFacts(t, "1.23.17", "1.24.0", nil, nil, k8sKubeletEnv("--v=2"))
	if incomplete.State != StateUnknown || incomplete.Reason != ReasonKubernetesComponentEvidenceIncomplete {
		t.Fatalf("incomplete state=%s reason=%s", incomplete.State, incomplete.Reason)
	}
}

func TestKubernetesComponentConfigSelectionGuards(t *testing.T) {
	selection, contents := k8sSelection(t, nil, nil, k8sKubeletEnv("--network-plugin=cni"))

	custom, err := PrepareKubernetesComponentConfig(selection, contents, "1.23.0", "1.24.0", "custom_build", k8sAllRegistered)
	if err != nil || custom.State != StateUnknown || custom.Reason != ReasonKubernetesComponentDistribution {
		t.Fatalf("custom distribution err=%v state=%s reason=%s", err, custom.State, custom.Reason)
	}
	for _, fact := range k8sProposedFacts(t, custom) {
		if fact.State != "unsupported" {
			t.Fatalf("custom distribution declared %+v", fact)
		}
	}

	unregistered, err := PrepareKubernetesComponentConfig(selection, contents, "1.23.0", "1.24.0", "official_upstream", func(string) bool { return false })
	if err != nil || unregistered.Reason != ReasonKubernetesComponentNoReviewedRule || len(k8sProposedFacts(t, unregistered)) != 0 {
		t.Fatalf("unregistered err=%v reason=%s", err, unregistered.Reason)
	}
	for _, pair := range [][2]string{{"1.23.0", "1.25.0"}, {"1.24.0", "1.24.3"}, {"1.24.0", "1.23.0"}, {"1.38.0", "1.39.0"}} {
		prepared, err := PrepareKubernetesComponentConfig(selection, contents, pair[0], pair[1], "official_upstream", k8sAllRegistered)
		if err != nil || prepared.Reason != ReasonKubernetesComponentNoReviewedRule || len(k8sProposedFacts(t, prepared)) != 0 {
			t.Fatalf("pair %v err=%v reason=%s", pair, err, prepared.Reason)
		}
	}
	if _, err := PrepareKubernetesComponentConfig(selection, contents, "1.23.0", "1.23.0", "official_upstream", k8sAllRegistered); err == nil {
		t.Fatal("same-version pair accepted")
	}
	if _, err := PrepareKubernetesComponentConfig(selection, nil, "1.23.0", "1.24.0", "official_upstream", k8sAllRegistered); err == nil {
		t.Fatal("missing contents accepted")
	}
	pinned := selection
	pinned.Sources = append([]KubernetesComponentSource(nil), selection.Sources...)
	pinned.Sources[0].Digest = digestBytes([]byte("other"))
	if _, err := PrepareKubernetesComponentConfig(pinned, contents, "1.23.0", "1.24.0", "official_upstream", k8sAllRegistered); err == nil {
		t.Fatal("source digest mismatch accepted")
	}
	pinned.Sources[0].Digest = digestBytes(contents[0])
	if _, err := PrepareKubernetesComponentConfig(pinned, contents, "1.23.0", "1.24.0", "official_upstream", k8sAllRegistered); err != nil {
		t.Fatalf("matching source digest rejected: %v", err)
	}

	base := `apiVersion: prufyx.io/kubernetes-component-config/v1alpha1
kind: ComponentConfigSelection
`
	for name, raw := range map[string]string{
		"relative path":        base + "sources: [{scope: kubelet, format: kubelet-env, path: etc/kubeadm-flags.env}]\n",
		"unclean path":         base + "sources: [{scope: kubelet, format: kubelet-env, path: /etc/../etc/kubeadm-flags.env}]\n",
		"duplicate path":       base + "sources: [{scope: kubelet, format: kubelet-env, path: /a}, {scope: kubelet, format: kubelet-config, path: /a}]\n",
		"unknown scope":        base + "sources: [{scope: etcd, format: args, path: /a}]\n",
		"format not for scope": base + "sources: [{scope: kubelet, format: scheduler-config, path: /a}]\n",
		"unknown field":        base + "sources: [{scope: kubelet, format: args, path: /a, extra: true}]\n",
		"static on args":       base + "sources: [{scope: kubelet, format: args, path: /a, staticPod: true}]\n",
		"bad digest":           base + "sources: [{scope: kubelet, format: args, path: /a, digest: md5:00}]\n",
		"duplicate complete":   base + "complete: [kubelet, kubelet]\nsources: [{scope: kubelet, format: args, path: /a}]\n",
		"unknown complete":     base + "complete: [etcd]\nsources: [{scope: kubelet, format: args, path: /a}]\n",
		"non-bool declaration": base + "declarations: {linuxNodeCgroupV1: \"yes\"}\nsources: [{scope: kubelet, format: args, path: /a}]\n",
		"no sources":           base + "sources: []\n",
		"wrong kind":           "apiVersion: prufyx.io/kubernetes-component-config/v1alpha1\nkind: Other\nsources: [{scope: kubelet, format: args, path: /a}]\n",
		"two documents":        base + "sources: [{scope: kubelet, format: args, path: /a}]\n---\n" + base,
		"duplicate key":        base + "kind: ComponentConfigSelection\nsources: [{scope: kubelet, format: args, path: /a}]\n",
	} {
		if _, err := ParseKubernetesComponentSelection([]byte(raw)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestKubernetesComponentConfigPredicateTable(t *testing.T) {
	factRE := regexp.MustCompile(`^component\.kubernetes\.[a-z0-9][a-z0-9_]{0,127}$`)
	seen := map[string]bool{}
	perLine := map[string]int{}
	for _, predicate := range k8sComponentPredicates {
		if !factRE.MatchString(predicate.Fact) || seen[predicate.Fact] || predicate.Eval == nil {
			t.Fatalf("invalid or duplicate predicate %q", predicate.Fact)
		}
		seen[predicate.Fact] = true
		major, minor, ok := strings.Cut(predicate.Line, ".")
		if !ok || major != "1" || len(minor) != 2 || minor < "23" || minor > "37" {
			t.Fatalf("%s: line %q outside 1.23-1.37", predicate.Fact, predicate.Line)
		}
		for _, scope := range predicate.Reads {
			if k8sScopeFormats[scope] == nil {
				t.Fatalf("%s: unknown scope %q", predicate.Fact, scope)
			}
		}
		perLine[predicate.Line]++
	}
	if len(k8sComponentPredicates) != 39 || len(perLine) != 15 {
		t.Fatalf("predicates=%d lines=%d", len(k8sComponentPredicates), len(perLine))
	}
	// The removed-API adapter owns other facts; the two tables never overlap.
	for _, removals := range kubernetesRemovalsByTargetMinor {
		for _, removal := range removals {
			if seen[removal.Fact] {
				t.Fatalf("fact %s owned by two adapters", removal.Fact)
			}
		}
	}
	if got := KubernetesComponentConfigFacts("1.36.9", "1.37.0"); len(got) != perLine["1.37"] {
		t.Fatalf("facts for 1.37 = %v", got)
	}
	if got := KubernetesComponentConfigFacts("1.30.0", "1.32.0"); len(got) != 0 {
		t.Fatalf("multi-minor facts = %v", got)
	}
}

func TestKubernetesComponentConfigGateScopesIgnoreUnrelatedConfigFiles(t *testing.T) {
	// The API server's admission configuration file has no feature gates, so a
	// reference to it without the file does not block a gate decision.
	_, facts := k8sComponentFacts(t, "1.36.0", "1.37.0", k8sGateAll, nil, k8sArgs(K8sScopeAPIServer, "--admission-control-config-file=/etc/kubernetes/admission.yaml"))
	view, found := facts["component.kubernetes.feature_gates_sidecarcontainers_removed"]
	if got := k8sFactState(view, found); got != "false" {
		t.Fatalf("gate fact = %s", got)
	}
	// A complete scope without sources declares that the component has no
	// arguments or configuration (for example no kube-proxy).
	_, facts = k8sComponentFacts(t, "1.25.0", "1.26.0", []string{K8sScopeKubeProxy}, nil, k8sKubeletEnv("--v=2"))
	view, found = facts["component.kubernetes.kube_proxy_userspace_mode_removed"]
	if got := k8sFactState(view, found); got != "false" {
		t.Fatalf("kube-proxy fact = %s", got)
	}
}

func TestKubernetesComponentConfigKubeletConfigSourceRequired(t *testing.T) {
	const swap = "component.kubernetes.kubelet_memoryswap_unlimitedswap_dropped"
	const gate = "component.kubernetes.feature_gates_sidecarcontainers_removed"
	kubeletCfg := func(body string) k8sSrc {
		return k8sSrc{scope: K8sScopeKubelet, format: K8sFormatKubeletConfig, body: "apiVersion: kubelet.config.k8s.io/v1beta1\nkind: KubeletConfiguration\n" + body}
	}
	dropin := func(body string) k8sSrc {
		return k8sSrc{scope: K8sScopeKubelet, format: K8sFormatKubeletDropIn, body: "apiVersion: kubelet.config.k8s.io/v1beta1\nkind: KubeletConfiguration\n" + body}
	}
	withConfig := "--config=/var/lib/kubelet/config.yaml"
	withDir := withConfig + " --config-dir=/etc/kubernetes/kubelet.conf.d"
	for _, test := range []struct {
		name, from, to, fact, want string
		sources                    []k8sSrc
	}{
		// Finding 1: --config-dir named, drop-ins not supplied.
		{"config-dir without drop-ins", "1.29.0", "1.30.0", swap, "unsupported", []k8sSrc{k8sKubeletEnv(withDir), kubeletCfg("cgroupDriver: systemd\n")}},
		{"config-dir without drop-ins gates", "1.36.0", "1.37.0", gate, "unsupported", []k8sSrc{k8sKubeletEnv(withDir), kubeletCfg("cgroupDriver: systemd\n")}},
		{"config-dir with a clean drop-in", "1.29.0", "1.30.0", swap, "false", []k8sSrc{k8sKubeletEnv(withDir), kubeletCfg("cgroupDriver: systemd\n"), dropin("cgroupDriver: systemd\n")}},
		{"config-dir drop-in sets the removed value", "1.29.0", "1.30.0", swap, "true", []k8sSrc{k8sKubeletEnv(withDir), kubeletCfg("cgroupDriver: systemd\n"), dropin("memorySwap:\n  swapBehavior: UnlimitedSwap\n")}},
		{"config-dir drop-in sets a removed gate", "1.36.0", "1.37.0", gate, "true", []k8sSrc{k8sKubeletEnv(withDir), kubeletCfg("cgroupDriver: systemd\n"), dropin("featureGates: {SidecarContainers: true}\n")}},
		{"config-dir declared absent", "1.29.0", "1.30.0", swap, "false", []k8sSrc{k8sKubeletEnv(withConfig), kubeletCfg("cgroupDriver: systemd\n"), k8sNoConfigDir}},
		{"config-dir declared absent but named", "1.29.0", "1.30.0", swap, "unsupported", []k8sSrc{k8sKubeletEnv(withDir), kubeletCfg("cgroupDriver: systemd\n"), k8sNoConfigDir}},
		{"config-dir declared absent but drop-in supplied", "1.29.0", "1.30.0", swap, "unsupported", []k8sSrc{k8sKubeletEnv(withDir), kubeletCfg("cgroupDriver: systemd\n"), dropin("cgroupDriver: systemd\n"), k8sNoConfigDir}},
		{"drop-in supplied without --config-dir still counts", "1.29.0", "1.30.0", swap, "true", []k8sSrc{k8sKubeletEnv(withConfig), kubeletCfg("cgroupDriver: systemd\n"), dropin("memorySwap: {swapBehavior: UnlimitedSwap}\n")}},
		// Finding 2: kubeadm env file carries no --config.
		{"env file only", "1.29.0", "1.30.0", swap, "unsupported", []k8sSrc{k8sKubeletEnv("--container-runtime-endpoint=unix:///run/containerd/containerd.sock")}},
		{"env file only with no-config-file declaration", "1.29.0", "1.30.0", swap, "false", []k8sSrc{k8sKubeletEnv("--container-runtime-endpoint=unix:///run/containerd/containerd.sock"), k8sNoConfigFile}},
		{"no-config-file declaration contradicted by --config", "1.29.0", "1.30.0", swap, "unsupported", []k8sSrc{k8sKubeletEnv(withConfig), k8sNoConfigFile}},
		{"no-config-file declaration contradicted by a source", "1.29.0", "1.30.0", swap, "unsupported", []k8sSrc{k8sKubeletEnv("--v=2"), kubeletCfg("cgroupDriver: systemd\n"), k8sNoConfigFile}},
		{"env file with a kubelet-config source", "1.29.0", "1.30.0", swap, "false", []k8sSrc{k8sKubeletEnv("--v=2"), kubeletCfg("cgroupDriver: systemd\n")}},
		{"env file only gates", "1.36.0", "1.37.0", gate, "unsupported", []k8sSrc{k8sKubeletEnv("--v=2")}},
		{"argument-only fact still needs no config", "1.23.17", "1.24.0", "component.kubernetes.kubelet_dockershim_flags_removed", "false", []k8sSrc{k8sKubeletEnv("--v=2")}},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, facts := k8sComponentFacts(t, test.from, test.to, []string{K8sScopeKubelet}, nil, test.sources...)
			view, found := facts[test.fact]
			if got := k8sFactState(view, found); got != test.want {
				t.Fatalf("%s = %s, want %s", test.fact, got, test.want)
			}
		})
	}
	// A kubelet-dropin source is a kubelet-scope format only.
	raw := []byte(`{"apiVersion":"` + KubernetesComponentSelectionAPIVersion + `","kind":"` + KubernetesComponentSelectionKind + `","sources":[{"scope":"kube-proxy","format":"kubelet-dropin","path":"/a/b"}]}`)
	if _, err := ParseKubernetesComponentSelection(raw); err == nil {
		t.Fatal("kubelet-dropin accepted outside the kubelet scope")
	}
	raw = []byte(`{"apiVersion":"` + KubernetesComponentSelectionAPIVersion + `","kind":"` + KubernetesComponentSelectionKind + `","declarations":{"kubeletNoConfigFile":"yes"},"sources":[{"scope":"kubelet","format":"args","path":"/a/b"}]}`)
	if _, err := ParseKubernetesComponentSelection(raw); err == nil {
		t.Fatal("non-boolean declaration accepted")
	}
}

func TestKubernetesComponentConfigTwoContainersNamingTheBinaryAreUnknown(t *testing.T) {
	pod := func(first, second string) k8sSrc {
		return k8sSrc{scope: K8sScopeAPIServer, format: K8sFormatPodManifest, body: "apiVersion: v1\nkind: Pod\nmetadata: {name: kube-apiserver}\nspec:\n  containers:\n  - {name: a, command: [kube-apiserver, " + first + "]}\n  - {name: b, command: [/usr/local/bin/kube-apiserver, " + second + "]}\n"}
	}
	const fact = "component.kubernetes.apiserver_insecure_address_flags_removed"
	for _, test := range []struct{ name, first, second string }{
		{"removed flag in the first", "--insecure-port=0", "--v=2"},
		{"removed flag in the second", "--v=2", "--insecure-port=0"},
		{"neither", "--v=2", "--v=3"},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, facts := k8sComponentFacts(t, "1.23.0", "1.24.0", []string{K8sScopeAPIServer}, nil, pod(test.first, test.second))
			view, found := facts[fact]
			if got := k8sFactState(view, found); got != "unsupported" {
				t.Fatalf("%s = %s, want unsupported", fact, got)
			}
		})
	}
}

func TestKubernetesComponentConfigNonBooleanCloudProviderGateIsNotAnOptIn(t *testing.T) {
	const fact = "component.kubernetes.in_tree_cloud_providers_off_by_default"
	for _, test := range []struct{ name, gate, want string }{
		{"explicit false opts in", "DisableCloudProviders=false", "false"},
		{"non-boolean value is unknown", "DisableCloudProviders=maybe", "unsupported"},
		{"empty value is unknown", "DisableCloudProviders=", "unsupported"},
		{"valueless gate is unknown", "DisableCloudProviders", "unsupported"},
		{"explicit true stays unknown", "DisableCloudProviders=true", "unsupported"},
	} {
		t.Run(test.name, func(t *testing.T) {
			scopes := []string{K8sScopeAPIServer, K8sScopeControllerManager, K8sScopeKubelet}
			_, facts := k8sComponentFacts(t, "1.28.4", "1.29.0", scopes, nil, k8sArgs(K8sScopeControllerManager, "--cloud-provider=gce", "--feature-gates="+test.gate))
			view, found := facts[fact]
			if got := k8sFactState(view, found); got != test.want {
				t.Fatalf("%s = %s, want %s", fact, got, test.want)
			}
		})
	}
}
