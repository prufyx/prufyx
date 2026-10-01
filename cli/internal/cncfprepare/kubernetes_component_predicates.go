// SPDX-License-Identifier: AGPL-3.0-only

package cncfprepare

import (
	"strconv"
	"strings"
)

// k8sPredicate is one reviewed component-configuration predicate. Line is the
// target minor line ("1.24") whose crossing the predicate concerns; Reads lists
// every scope whose completeness a false (absent) result depends on. A
// predicate emits its fact only when the active knowledge declares that fact,
// which happens only when a maintainer publishes the matching rule.
type k8sPredicate struct {
	Fact  string
	Line  string
	Reads []string
	Eval  func(*k8sComponentModel) k8sResult
}

// k8sResult: present is decisive; resolved reports that every read source was
// understood, so that absence may be concluded when the scopes are complete.
type k8sResult struct {
	present, resolved bool
}

var (
	k8sGateScopes          = []string{K8sScopeAPIServer, K8sScopeControllerManager, K8sScopeScheduler, K8sScopeKubelet, K8sScopeKubeProxy}
	k8sCloudProviderScopes = []string{K8sScopeAPIServer, K8sScopeControllerManager, K8sScopeKubelet}
	k8sPodScopes           = []string{K8sScopeWorkloads, K8sScopeStaticPods}
)

// k8sComponentPredicates is the adapter's predicate table. Fact identifiers are
// stable public names; a published rule references them.
var k8sComponentPredicates = []k8sPredicate{
	{Fact: "component.kubernetes.kube_scheduler_config_v1beta1_removed", Line: "1.23", Reads: []string{K8sScopeScheduler},
		Eval: k8sConfigAPIVersion(K8sScopeScheduler, "kubescheduler.config.k8s.io/v1beta1")},
	{Fact: "component.kubernetes.feature_gates_boundserviceaccounttokenvolume_removed", Line: "1.23", Reads: k8sGateScopes,
		Eval: k8sGatesPresent("BoundServiceAccountTokenVolume")},

	{Fact: "component.kubernetes.kubelet_dockershim_flags_removed", Line: "1.24", Reads: []string{K8sScopeKubelet},
		Eval: k8sFlagsPresent([]string{K8sScopeKubelet}, "experimental-dockershim-root-directory", "docker-endpoint", "image-pull-progress-deadline", "network-plugin", "cni-conf-dir", "cni-bin-dir", "cni-cache-dir", "network-plugin-mtu")},
	{Fact: "component.kubernetes.apiserver_insecure_address_flags_removed", Line: "1.24", Reads: []string{K8sScopeAPIServer},
		Eval: k8sFlagsPresent([]string{K8sScopeAPIServer}, "address", "insecure-bind-address", "port", "insecure-port")},
	{Fact: "component.kubernetes.controller_manager_insecure_flags_removed", Line: "1.24", Reads: []string{K8sScopeControllerManager},
		Eval: k8sFlagsPresent([]string{K8sScopeControllerManager}, "address", "port")},

	{Fact: "component.kubernetes.apiserver_psp_admission_plugin_removed", Line: "1.25", Reads: []string{K8sScopeAPIServer},
		Eval: k8sListFlagContains(K8sScopeAPIServer, "PodSecurityPolicy", "enable-admission-plugins", "admission-control")},
	{Fact: "component.kubernetes.apiserver_service_account_api_audiences_removed", Line: "1.25", Reads: []string{K8sScopeAPIServer},
		Eval: k8sFlagsPresent([]string{K8sScopeAPIServer}, "service-account-api-audiences")},
	{Fact: "component.kubernetes.pod_seccomp_alpha_annotations_ignored", Line: "1.25", Reads: k8sPodScopes,
		Eval: k8sPodsMatch(k8sSeccompAlphaAnnotations)},

	{Fact: "component.kubernetes.kube_proxy_userspace_mode_removed", Line: "1.26", Reads: []string{K8sScopeKubeProxy},
		Eval: k8sKubeProxyMode("userspace")},
	{Fact: "component.kubernetes.in_tree_openstack_cloud_provider_removed", Line: "1.26", Reads: k8sCloudProviderScopes,
		Eval: k8sFlagValue(k8sCloudProviderScopes, "cloud-provider", func(value string) bool { return value == "openstack" })},

	{Fact: "component.kubernetes.kubelet_container_runtime_flag_removed", Line: "1.27", Reads: []string{K8sScopeKubelet},
		Eval: k8sFlagsPresent([]string{K8sScopeKubelet}, "container-runtime")},
	{Fact: "component.kubernetes.in_tree_aws_cloud_provider_removed", Line: "1.27", Reads: k8sCloudProviderScopes,
		Eval: k8sFlagValue(k8sCloudProviderScopes, "cloud-provider", func(value string) bool { return value == "aws" })},
	{Fact: "component.kubernetes.kcm_taint_manager_flags_removed", Line: "1.27", Reads: []string{K8sScopeControllerManager},
		Eval: k8sFlagsPresent([]string{K8sScopeControllerManager}, "enable-taint-manager", "pod-eviction-timeout")},

	{Fact: "component.kubernetes.kube_scheduler_config_v1beta2_removed", Line: "1.28", Reads: []string{K8sScopeScheduler},
		Eval: k8sConfigAPIVersion(K8sScopeScheduler, "kubescheduler.config.k8s.io/v1beta2")},
	{Fact: "component.kubernetes.feature_gates_podsecurity_acceleratormetrics_removed", Line: "1.28", Reads: k8sGateScopes,
		Eval: k8sGatesPresent("DisableAcceleratorUsageMetrics", "PodSecurity")},

	{Fact: "component.kubernetes.kube_scheduler_config_v1beta3_removed", Line: "1.29", Reads: []string{K8sScopeScheduler},
		Eval: k8sConfigAPIVersion(K8sScopeScheduler, "kubescheduler.config.k8s.io/v1beta3")},
	{Fact: "component.kubernetes.in_tree_cloud_providers_off_by_default", Line: "1.29", Reads: k8sCloudProviderScopes,
		Eval: k8sInTreeCloudProviderWithoutOptIn},

	{Fact: "component.kubernetes.apiserver_securitycontextdeny_plugin_removed", Line: "1.30", Reads: []string{K8sScopeAPIServer},
		Eval: k8sListFlagContains(K8sScopeAPIServer, "SecurityContextDeny", "enable-admission-plugins", "admission-control")},
	{Fact: "component.kubernetes.in_tree_azure_cloud_provider_removed", Line: "1.30", Reads: k8sCloudProviderScopes,
		Eval: k8sFlagValue(k8sCloudProviderScopes, "cloud-provider", func(value string) bool { return value == "azure" })},
	{Fact: "component.kubernetes.kubelet_memoryswap_unlimitedswap_dropped", Line: "1.30", Reads: []string{K8sScopeKubelet},
		Eval: k8sConfigStringEquals(K8sScopeKubelet, "UnlimitedSwap", "memorySwap", "swapBehavior")},

	{Fact: "component.kubernetes.kubelet_keep_terminated_pod_volumes_removed", Line: "1.31", Reads: []string{K8sScopeKubelet},
		Eval: k8sFlagsPresent([]string{K8sScopeKubelet}, "keep-terminated-pod-volumes")},
	{Fact: "component.kubernetes.in_tree_gce_cloud_provider_removed", Line: "1.31", Reads: k8sCloudProviderScopes,
		Eval: k8sFlagValue(k8sCloudProviderScopes, "cloud-provider", func(value string) bool { return value == "gce" })},
	{Fact: "component.kubernetes.in_tree_rbd_volume_plugin_removed", Line: "1.31", Reads: k8sPodScopes,
		Eval: k8sPodsMatch(k8sVolumeSource("rbd"))},

	{Fact: "component.kubernetes.kcm_cloud_provider_value_invalid", Line: "1.32", Reads: []string{K8sScopeControllerManager},
		Eval: k8sFlagValue([]string{K8sScopeControllerManager}, "cloud-provider", func(value string) bool { return value != "external" && value != "" })},
	{Fact: "component.kubernetes.scheduler_noncsi_volumelimit_plugins_removed", Line: "1.32", Reads: []string{K8sScopeScheduler},
		Eval: k8sSchedulerPlugins("AzureDiskLimits", "CinderLimits", "EBSLimits", "GCEPDLimits")},

	{Fact: "component.kubernetes.apiserver_cloud_provider_flags_removed", Line: "1.33", Reads: []string{K8sScopeAPIServer},
		Eval: k8sFlagsPresent([]string{K8sScopeAPIServer}, "cloud-provider", "cloud-config")},
	{Fact: "component.kubernetes.feature_gates_disablecloudproviders_removed", Line: "1.33", Reads: k8sGateScopes,
		Eval: k8sGatesPresent("DisableCloudProviders", "DisableKubeletCloudCredentialProviders")},
	{Fact: "component.kubernetes.pod_gitrepo_volume_disabled_by_default", Line: "1.33", Reads: k8sPodScopes,
		Eval: k8sPodsMatchUnlessKubeletGate(k8sVolumeSource("gitRepo"), "GitRepoVolumeDriver", true)},

	{Fact: "component.kubernetes.kubelet_cloud_config_flag_removed", Line: "1.34", Reads: []string{K8sScopeKubelet},
		Eval: k8sFlagsPresent([]string{K8sScopeKubelet}, "cloud-config")},
	{Fact: "component.kubernetes.static_pod_api_object_references_denied", Line: "1.34", Reads: []string{K8sScopeStaticPods},
		Eval: k8sStaticPodsMatchUnlessKubeletGate(k8sStaticPodAPIReference, "PreventStaticPodAPIReferences", false)},

	{Fact: "component.kubernetes.kubelet_pod_infra_container_image_removed", Line: "1.35", Reads: []string{K8sScopeKubelet},
		Eval: k8sFlagsPresent([]string{K8sScopeKubelet}, "pod-infra-container-image")},
	{Fact: "component.kubernetes.kubelet_cgroup_v1_fail_by_default", Line: "1.35", Reads: nil,
		Eval: k8sCgroupV1FailByDefault},

	{Fact: "component.kubernetes.pod_gitrepo_volume_removed", Line: "1.36", Reads: k8sPodScopes,
		Eval: k8sPodsMatch(k8sVolumeSource("gitRepo"))},
	{Fact: "component.kubernetes.apiserver_webhook_admission_config_v1alpha1_removed", Line: "1.36", Reads: []string{K8sScopeAPIServer},
		Eval: k8sWebhookAdmissionV1alpha1},
	{Fact: "component.kubernetes.in_tree_portworx_volume_plugin_removed", Line: "1.36", Reads: k8sPodScopes,
		Eval: k8sPodsMatch(k8sVolumeSource("portworxVolume"))},

	{Fact: "component.kubernetes.kubelet_cadvisor_flags_removed", Line: "1.37", Reads: []string{K8sScopeKubelet},
		Eval: k8sFlagsPresent([]string{K8sScopeKubelet}, "application-metrics-count-limit", "boot-id-file", "container-hints", "containerd", "containerd-namespace", "enable-load-reader", "event-storage-age-limit", "event-storage-event-limit", "global-housekeeping-interval", "log-cadvisor-usage", "machine-id-file", "storage-driver-user", "storage-driver-password", "storage-driver-host", "storage-driver-db", "storage-driver-table", "storage-driver-secure", "storage-driver-buffer-duration")},
	{Fact: "component.kubernetes.kcm_concurrent_service_syncs_removed", Line: "1.37", Reads: []string{K8sScopeControllerManager},
		Eval: k8sFlagsPresent([]string{K8sScopeControllerManager}, "concurrent-service-syncs")},
	{Fact: "component.kubernetes.kubeadm_config_v1beta3_removed", Line: "1.37", Reads: []string{K8sScopeKubeadm},
		Eval: k8sKubeadmAPIVersion("kubeadm.k8s.io/v1beta3")},
	{Fact: "component.kubernetes.feature_gates_sidecarcontainers_removed", Line: "1.37", Reads: k8sGateScopes,
		Eval: k8sGatesPresent("SidecarContainers")},
}

// KubernetesComponentConfigFacts returns every fact the adapter can evaluate for
// the minor line a transition crosses, before any knowledge filtering.
func KubernetesComponentConfigFacts(from, to string) []string {
	line, ok := kubernetesCrossedMinorLine(from, to)
	if !ok {
		return nil
	}
	facts := make([]string, 0)
	for _, predicate := range k8sComponentPredicates {
		if predicate.Line == line {
			facts = append(facts, predicate.Fact)
		}
	}
	return facts
}

// KubernetesComponentConfigFactLines maps every adapter fact to its target
// minor line. Tests use it to compare the table with published rules.
func KubernetesComponentConfigFactLines() map[string]string {
	lines := make(map[string]string, len(k8sComponentPredicates))
	for _, predicate := range k8sComponentPredicates {
		lines[predicate.Fact] = predicate.Line
	}
	return lines
}

// k8sFlag is one parsed long option. value is known only for --name=value or
// --name VALUE where VALUE does not start with a dash.
type k8sFlag struct {
	name, value          string
	valueKnown, attached bool
}

// k8sScanArgs parses Kubernetes (pflag) long options conservatively. Every
// token is examined, including tokens another option might consume as its
// value, so a removed spelling is never skipped. Names are normalised the way
// Kubernetes components normalise them (underscore to dash). A bare "--" or
// "-" leaves the list unresolved. Single-dash tokens are pflag shorthands and
// cannot spell a long option.
func k8sScanArgs(tokens []string) ([]k8sFlag, bool) {
	flags := make([]k8sFlag, 0, len(tokens))
	for index, token := range tokens {
		if token == "--" || token == "-" {
			return flags, false
		}
		if !strings.HasPrefix(token, "--") {
			continue
		}
		name, value, attached := strings.Cut(token[2:], "=")
		if name == "" {
			return flags, false
		}
		flag := k8sFlag{name: strings.ReplaceAll(name, "_", "-"), value: value, valueKnown: attached, attached: attached}
		if !attached && index+1 < len(tokens) && !strings.HasPrefix(tokens[index+1], "-") {
			flag.value, flag.valueKnown = tokens[index+1], true
		}
		if strings.Contains(flag.value, "$(") {
			// Kubernetes dependent-variable expansion: the effective value is
			// decided at runtime.
			flag.value, flag.valueKnown = "", false
		}
		flags = append(flags, flag)
	}
	return flags, true
}

// flags returns every parsed option of one scope and whether all of its
// argument sources were resolved.
func (m *k8sComponentModel) flags(scope string) ([]k8sFlag, bool) {
	evidence := m.scope(scope)
	result := make([]k8sFlag, 0)
	resolved := !evidence.unresolved
	for _, tokens := range evidence.argv {
		flags, ok := k8sScanArgs(tokens)
		result = append(result, flags...)
		resolved = resolved && ok
	}
	return result, resolved
}

// configResolved is false when the component's arguments reference a
// configuration file and no configuration document was supplied for it.
func (m *k8sComponentModel) configResolved(scope string) bool {
	flagName := "config"
	if scope == K8sScopeAPIServer {
		flagName = "admission-control-config-file"
	}
	flags, _ := m.flags(scope)
	for _, flag := range flags {
		if flag.name == flagName && len(m.scope(scope).configs) == 0 {
			return false
		}
	}
	return true
}

func k8sFlagsPresent(scopes []string, names ...string) func(*k8sComponentModel) k8sResult {
	wanted := map[string]bool{}
	for _, name := range names {
		wanted[name] = true
	}
	return func(m *k8sComponentModel) k8sResult {
		result := k8sResult{resolved: true}
		for _, scope := range scopes {
			flags, resolved := m.flags(scope)
			result.resolved = result.resolved && resolved
			for _, flag := range flags {
				if wanted[flag.name] {
					result.present = true
				}
			}
		}
		return result
	}
}

// k8sFlagValue tests the value of one value-taking option. An occurrence whose
// value cannot be read is unresolved, never absent.
func k8sFlagValue(scopes []string, name string, matches func(string) bool) func(*k8sComponentModel) k8sResult {
	return func(m *k8sComponentModel) k8sResult {
		result := k8sResult{resolved: true}
		for _, scope := range scopes {
			flags, resolved := m.flags(scope)
			result.resolved = result.resolved && resolved
			for _, flag := range flags {
				if flag.name != name {
					continue
				}
				if !flag.valueKnown {
					result.resolved = false
					continue
				}
				if matches(flag.value) {
					result.present = true
				}
			}
		}
		return result
	}
}

func k8sListFlagContains(scope, item string, names ...string) func(*k8sComponentModel) k8sResult {
	return func(m *k8sComponentModel) k8sResult {
		flags, resolved := m.flags(scope)
		result := k8sResult{resolved: resolved}
		for _, flag := range flags {
			if !containsString(names, flag.name) {
				continue
			}
			if !flag.valueKnown {
				result.resolved = false
				continue
			}
			for _, entry := range strings.Split(flag.value, ",") {
				if strings.TrimSpace(entry) == item {
					result.present = true
				}
			}
		}
		return result
	}
}

// k8sGateValue is one occurrence of a feature gate: its value, or known=false
// when the value is not a boolean.
type k8sGateValue struct {
	value, known bool
}

// gates collects every feature gate a scope sets through --feature-gates or
// a configuration document's featureGates map.
func (m *k8sComponentModel) gates(scope string) (map[string][]k8sGateValue, bool) {
	result := map[string][]k8sGateValue{}
	flags, resolved := m.flags(scope)
	for _, flag := range flags {
		if flag.name != "feature-gates" {
			continue
		}
		if !flag.valueKnown {
			resolved = false
			continue
		}
		for _, entry := range strings.Split(flag.value, ",") {
			entry = strings.TrimSpace(entry)
			if entry == "" {
				continue
			}
			key, text, found := strings.Cut(entry, "=")
			key = strings.TrimSpace(key)
			parsed, err := strconv.ParseBool(strings.TrimSpace(text))
			result[key] = append(result[key], k8sGateValue{value: parsed, known: found && err == nil})
		}
	}
	for _, config := range m.scope(scope).configs {
		value, found, ok := k8sPath(config, "featureGates")
		if !ok {
			resolved = false
			continue
		}
		if !found || value == nil {
			continue
		}
		gates, isMap := value.(map[string]any)
		if !isMap {
			resolved = false
			continue
		}
		for key, raw := range gates {
			parsed, isBool := raw.(bool)
			result[key] = append(result[key], k8sGateValue{value: parsed, known: isBool})
		}
	}
	if scope == K8sScopeKubelet || scope == K8sScopeKubeProxy {
		// Only these components carry featureGates in a configuration file.
		resolved = resolved && m.configResolved(scope)
	}
	return result, resolved
}

// k8sGatesPresent: a removed gate is rejected by every Kubernetes component
// that registers the shared gate set, so any mention in any component counts.
func k8sGatesPresent(names ...string) func(*k8sComponentModel) k8sResult {
	return func(m *k8sComponentModel) k8sResult {
		result := k8sResult{resolved: true}
		for _, scope := range k8sGateScopes {
			gates, resolved := m.gates(scope)
			result.resolved = result.resolved && resolved
			for _, name := range names {
				if len(gates[name]) > 0 {
					result.present = true
				}
			}
		}
		return result
	}
}

// gateSetTo reports whether every occurrence of a gate in a scope sets it to
// value (and there is at least one), whether any occurrence sets another or
// an unreadable value, and whether the scope was resolved.
func (m *k8sComponentModel) gateSetTo(scope, gate string, value bool) (allSet, other, resolved bool) {
	gates, resolved := m.gates(scope)
	occurrences := gates[gate]
	for _, occurrence := range occurrences {
		if !occurrence.known || occurrence.value != value {
			other = true
		}
	}
	return len(occurrences) > 0 && !other, other, resolved
}

// k8sInTreeCloudProviderWithoutOptIn: from 1.29 an in-tree --cloud-provider
// value works only while the component explicitly sets
// DisableCloudProviders=false.
func k8sInTreeCloudProviderWithoutOptIn(m *k8sComponentModel) k8sResult {
	inTree := map[string]bool{"aws": true, "azure": true, "gce": true, "openstack": true, "vsphere": true}
	result := k8sResult{resolved: true}
	for _, scope := range k8sCloudProviderScopes {
		flags, resolved := m.flags(scope)
		result.resolved = result.resolved && resolved
		for _, flag := range flags {
			if flag.name != "cloud-provider" {
				continue
			}
			if !flag.valueKnown {
				result.resolved = false
				continue
			}
			if !inTree[flag.value] {
				continue
			}
			optedIn, other, gatesResolved := m.gateSetTo(scope, "DisableCloudProviders", false)
			switch {
			case optedIn:
			case other || !gatesResolved:
				result.resolved = false
			default:
				result.present = true
			}
		}
	}
	return result
}

// k8sConfigAPIVersion matches the apiVersion of any configuration document in
// the scope. A document referenced by the arguments but not supplied leaves
// the result unresolved.
func k8sConfigAPIVersion(scope, apiVersion string) func(*k8sComponentModel) k8sResult {
	return func(m *k8sComponentModel) k8sResult {
		_, resolved := m.flags(scope)
		result := k8sResult{resolved: resolved && m.configResolved(scope)}
		for _, config := range m.scope(scope).configs {
			if config["apiVersion"] == apiVersion {
				result.present = true
			}
		}
		return result
	}
}

func k8sConfigStringEquals(scope, want string, path ...string) func(*k8sComponentModel) k8sResult {
	return func(m *k8sComponentModel) k8sResult {
		_, resolved := m.flags(scope)
		result := k8sResult{resolved: resolved && m.configResolved(scope)}
		for _, config := range m.scope(scope).configs {
			value, found, ok := k8sPath(config, path...)
			if !ok {
				result.resolved = false
				continue
			}
			if !found || value == nil {
				continue
			}
			text, isString := value.(string)
			if !isString {
				result.resolved = false
				continue
			}
			if text == want {
				result.present = true
			}
		}
		return result
	}
}

// k8sKubeProxyMode matches --proxy-mode or KubeProxyConfiguration mode. Either
// source naming the removed mode counts; the comparison ignores case.
func k8sKubeProxyMode(mode string) func(*k8sComponentModel) k8sResult {
	byFlag := k8sFlagValue([]string{K8sScopeKubeProxy}, "proxy-mode", func(value string) bool { return strings.EqualFold(value, mode) })
	return func(m *k8sComponentModel) k8sResult {
		result := byFlag(m)
		result.resolved = result.resolved && m.configResolved(K8sScopeKubeProxy)
		for _, config := range m.scope(K8sScopeKubeProxy).configs {
			value, found, ok := k8sPath(config, "mode")
			if !ok {
				result.resolved = false
				continue
			}
			if !found || value == nil {
				continue
			}
			text, isString := value.(string)
			if !isString {
				result.resolved = false
				continue
			}
			if strings.EqualFold(text, mode) {
				result.present = true
			}
		}
		return result
	}
}

// k8sSchedulerPlugins matches plugin names in any profile's extension-point
// enabled/disabled lists, multiPoint, or pluginConfig.
func k8sSchedulerPlugins(names ...string) func(*k8sComponentModel) k8sResult {
	return func(m *k8sComponentModel) k8sResult {
		_, resolved := m.flags(K8sScopeScheduler)
		result := k8sResult{resolved: resolved && m.configResolved(K8sScopeScheduler)}
		check := func(value any) {
			object, ok := value.(map[string]any)
			if !ok {
				result.resolved = false
				return
			}
			name, ok := object["name"].(string)
			if !ok {
				result.resolved = false
				return
			}
			if containsString(names, name) {
				result.present = true
			}
		}
		for _, config := range m.scope(K8sScopeScheduler).configs {
			profiles, found, ok := k8sPath(config, "profiles")
			if !ok {
				result.resolved = false
				continue
			}
			if !found || profiles == nil {
				continue
			}
			items, isList := profiles.([]any)
			if !isList {
				result.resolved = false
				continue
			}
			for _, item := range items {
				profile, isMap := item.(map[string]any)
				if !isMap {
					result.resolved = false
					continue
				}
				if plugins, found, ok := k8sPath(profile, "plugins"); !ok {
					result.resolved = false
				} else if found && plugins != nil {
					points, isMap := plugins.(map[string]any)
					if !isMap {
						result.resolved = false
						continue
					}
					for _, point := range points {
						set, isMap := point.(map[string]any)
						if !isMap {
							result.resolved = false
							continue
						}
						for _, list := range []string{"enabled", "disabled"} {
							entries, found, ok := k8sPath(set, list)
							if !ok {
								result.resolved = false
								continue
							}
							if !found || entries == nil {
								continue
							}
							values, isList := entries.([]any)
							if !isList {
								result.resolved = false
								continue
							}
							for _, entry := range values {
								check(entry)
							}
						}
					}
				}
				if configs, found, ok := k8sPath(profile, "pluginConfig"); !ok {
					result.resolved = false
				} else if found && configs != nil {
					values, isList := configs.([]any)
					if !isList {
						result.resolved = false
						continue
					}
					for _, entry := range values {
						check(entry)
					}
				}
			}
		}
		return result
	}
}

func k8sWebhookAdmissionKind(kind string) bool {
	return kind == "WebhookAdmission" || kind == "WebhookAdmissionConfiguration"
}

// k8sWebhookAdmissionV1alpha1 matches an apiserver.config.k8s.io/v1alpha1
// webhook admission configuration, embedded in an AdmissionConfiguration or
// supplied as a standalone file. A plugin configuration loaded from a path
// that was not supplied leaves the result unresolved.
func k8sWebhookAdmissionV1alpha1(m *k8sComponentModel) k8sResult {
	_, resolved := m.flags(K8sScopeAPIServer)
	result := k8sResult{resolved: resolved && m.configResolved(K8sScopeAPIServer)}
	isRemoved := func(object map[string]any) bool {
		api, kind, ok := kubernetesGVK(object)
		return ok && api == "apiserver.config.k8s.io/v1alpha1" && k8sWebhookAdmissionKind(kind)
	}
	standalone := 0
	paths := 0
	for _, config := range m.scope(K8sScopeAPIServer).configs {
		if _, kind, _ := kubernetesGVK(config); kind != "AdmissionConfiguration" {
			standalone++
			if isRemoved(config) {
				result.present = true
			}
			continue
		}
		plugins, found, ok := k8sPath(config, "plugins")
		if !ok {
			result.resolved = false
			continue
		}
		if !found || plugins == nil {
			continue
		}
		items, isList := plugins.([]any)
		if !isList {
			result.resolved = false
			continue
		}
		for _, item := range items {
			plugin, isMap := item.(map[string]any)
			if !isMap {
				result.resolved = false
				continue
			}
			if _, hasPath := plugin["path"]; hasPath {
				paths++
			}
			embedded, found, ok := k8sPath(plugin, "configuration")
			if !ok {
				result.resolved = false
				continue
			}
			if object, isMap := embedded.(map[string]any); found && isMap && isRemoved(object) {
				result.present = true
			}
		}
	}
	if paths > standalone {
		result.resolved = false
	}
	return result
}

func k8sKubeadmAPIVersion(apiVersion string) func(*k8sComponentModel) k8sResult {
	return func(m *k8sComponentModel) k8sResult {
		result := k8sResult{resolved: !m.scope(K8sScopeKubeadm).unresolved}
		for _, document := range m.kubeadm {
			if document["apiVersion"] == apiVersion {
				result.present = true
			}
		}
		return result
	}
}

// k8sCgroupV1FailByDefault: from 1.35 the kubelet's failCgroupV1 defaults to
// true. The fact is true when the caller declares a cgroup v1 Linux node and
// no supplied kubelet source sets failCgroupV1 (or --fail-cgroupv1) to false;
// an explicit false in every occurrence, with complete kubelet evidence, makes
// it false. A declaration of no cgroup v1 node makes it false.
func k8sCgroupV1FailByDefault(m *k8sComponentModel) k8sResult {
	if m.cgroupV1 == nil {
		return k8sResult{}
	}
	if !*m.cgroupV1 {
		return k8sResult{resolved: true}
	}
	flags, resolved := m.flags(K8sScopeKubelet)
	resolved = resolved && m.configResolved(K8sScopeKubelet)
	values := make([]k8sGateValue, 0)
	for _, flag := range flags {
		if flag.name != "fail-cgroupv1" {
			continue
		}
		// A boolean option takes its value only in --name=value form; a bare
		// --fail-cgroupv1 means true.
		if !flag.attached {
			values = append(values, k8sGateValue{value: true, known: true})
			continue
		}
		parsed, err := strconv.ParseBool(flag.value)
		values = append(values, k8sGateValue{value: parsed, known: err == nil})
	}
	for _, config := range m.scope(K8sScopeKubelet).configs {
		value, found, ok := k8sPath(config, "failCgroupV1")
		if !ok {
			resolved = false
			continue
		}
		if !found || value == nil {
			continue
		}
		parsed, isBool := value.(bool)
		values = append(values, k8sGateValue{value: parsed, known: isBool})
	}
	allFalse := len(values) > 0
	for _, occurrence := range values {
		if !occurrence.known {
			return k8sResult{}
		}
		if occurrence.value {
			return k8sResult{present: true, resolved: true}
		}
		allFalse = allFalse && !occurrence.value
	}
	if allFalse {
		return k8sResult{resolved: resolved && m.allComplete([]string{K8sScopeKubelet})}
	}
	// No override anywhere: the default applies to every supplied kubelet.
	// With complete kubelet evidence that is decisive; otherwise an unseen
	// source could still carry the override.
	if resolved && m.allComplete([]string{K8sScopeKubelet}) {
		return k8sResult{present: true, resolved: true}
	}
	return k8sResult{}
}

// Pod-level predicates.

// k8sPodView is one pod specification with its metadata. k8sPodViews finds
// every object in a document whose spec holds containers: a Pod itself, and
// any pod template at any depth (Deployment, StatefulSet, DaemonSet, Job,
// CronJob, ReplicaSet, or a custom resource embedding one).
type k8sPodView struct {
	metadata map[string]any
	spec     map[string]any
}

func k8sPodViews(document map[string]any) ([]k8sPodView, bool) {
	views := make([]k8sPodView, 0, 1)
	resolved := true
	var walk func(object map[string]any, depth int)
	walk = func(object map[string]any, depth int) {
		if depth > maxJSONDepth {
			resolved = false
			return
		}
		if spec, ok := object["spec"].(map[string]any); ok {
			if _, hasContainers := spec["containers"]; hasContainers {
				metadata, _ := object["metadata"].(map[string]any)
				views = append(views, k8sPodView{metadata: metadata, spec: spec})
			}
		}
		for _, value := range object {
			switch typed := value.(type) {
			case map[string]any:
				walk(typed, depth+1)
			case []any:
				for _, item := range typed {
					if child, ok := item.(map[string]any); ok {
						walk(child, depth+1)
					}
				}
			}
		}
	}
	walk(document, 0)
	return views, resolved
}

// k8sPodsMatch evaluates a per-document matcher over workloads and static
// pods. A matcher returns (present, resolved).
func k8sPodsMatch(match func(map[string]any) (bool, bool)) func(*k8sComponentModel) k8sResult {
	return func(m *k8sComponentModel) k8sResult {
		result := k8sResult{resolved: true}
		for _, scope := range k8sPodScopes {
			for _, document := range m.scope(scope).pods {
				present, resolved := match(document)
				result.present = result.present || present
				result.resolved = result.resolved && resolved
			}
		}
		return result
	}
}

// k8sPodsMatchUnlessKubeletGate: a pod-level hit counts unless the kubelet
// gate is set to the escape value. When a hit exists and the kubelet evidence
// sets the gate to the escape value anywhere, the node coverage of that
// setting is unknown, so the result is unresolved.
func k8sPodsMatchUnlessKubeletGate(match func(map[string]any) (bool, bool), gate string, escape bool) func(*k8sComponentModel) k8sResult {
	pods := k8sPodsMatch(match)
	return func(m *k8sComponentModel) k8sResult {
		result := pods(m)
		if !result.present {
			return k8sResult{resolved: result.resolved}
		}
		return k8sKubeletGateEscape(m, gate, escape)
	}
}

func k8sStaticPodsMatchUnlessKubeletGate(match func(map[string]any) (bool, bool), gate string, escape bool) func(*k8sComponentModel) k8sResult {
	return func(m *k8sComponentModel) k8sResult {
		result := k8sResult{resolved: true}
		for _, document := range m.scope(K8sScopeStaticPods).pods {
			present, resolved := match(document)
			result.present = result.present || present
			result.resolved = result.resolved && resolved
		}
		if !result.present {
			return result
		}
		return k8sKubeletGateEscape(m, gate, escape)
	}
}

// k8sKubeletGateEscape decides a pod-level hit against the kubelet gate that
// can switch the behaviour back. An occurrence of the escape value (or an
// unreadable value) anywhere leaves the result unresolved, because the
// supplied evidence does not map kubelet settings to the nodes that run the
// matching pods. Otherwise the hit is decisive once the kubelet evidence is
// complete.
func k8sKubeletGateEscape(m *k8sComponentModel, gate string, escape bool) k8sResult {
	gates, resolved := m.gates(K8sScopeKubelet)
	for _, occurrence := range gates[gate] {
		if !occurrence.known || occurrence.value == escape {
			return k8sResult{}
		}
	}
	if resolved && m.allComplete([]string{K8sScopeKubelet}) {
		return k8sResult{present: true, resolved: true}
	}
	return k8sResult{}
}

// k8sVolumeSource matches a pod volume (any pod specification in the
// document) or a PersistentVolume using the named in-tree volume source. The
// same key anywhere else in an unrecognised object is unresolved, because an
// embedded pod template under an unreviewed key could hide it.
func k8sVolumeSource(key string) func(map[string]any) (bool, bool) {
	return func(document map[string]any) (bool, bool) {
		present := false
		if _, kind, ok := kubernetesGVK(document); ok && kind == "PersistentVolume" {
			if spec, ok := document["spec"].(map[string]any); ok {
				if _, exists := spec[key]; exists {
					present = true
				}
			}
		}
		views, resolved := k8sPodViews(document)
		counted := 0
		for _, view := range views {
			value, exists := view.spec["volumes"]
			if !exists || value == nil {
				continue
			}
			volumes, ok := value.([]any)
			if !ok {
				resolved = false
				continue
			}
			for _, item := range volumes {
				volume, ok := item.(map[string]any)
				if !ok {
					resolved = false
					continue
				}
				if _, exists := volume[key]; exists {
					present = true
					counted++
				}
			}
		}
		if !present && k8sKeyCount(document, key, 0) > counted {
			resolved = false
		}
		return present, resolved
	}
}

func k8sKeyCount(value any, key string, depth int) int {
	if depth > maxJSONDepth {
		return 1
	}
	count := 0
	switch typed := value.(type) {
	case map[string]any:
		for name, child := range typed {
			if name == key {
				count++
			}
			count += k8sKeyCount(child, key, depth+1)
		}
	case []any:
		for _, child := range typed {
			count += k8sKeyCount(child, key, depth+1)
		}
	}
	return count
}

// k8sSeccompAlphaAnnotations matches the alpha seccomp annotation keys on any
// pod or pod template metadata in the document.
func k8sSeccompAlphaAnnotations(document map[string]any) (bool, bool) {
	views, resolved := k8sPodViews(document)
	for _, view := range views {
		annotations, ok := view.metadata["annotations"].(map[string]any)
		if !ok {
			continue
		}
		for key := range annotations {
			if key == "seccomp.security.alpha.kubernetes.io/pod" || strings.HasPrefix(key, "container.seccomp.security.alpha.kubernetes.io/") {
				return true, resolved
			}
		}
	}
	return false, resolved
}

// k8sStaticPodAPIReference mirrors the kubelet's static-pod API reference
// check at v1.34.0 (pkg/api/pod/util.go HasAPIObjectReference): a service
// account, Secret or ConfigMap references from containers, image pull secrets
// or volumes, resource claims, and any volume type outside the kubelet's
// allowed list.
func k8sStaticPodAPIReference(document map[string]any) (bool, bool) {
	spec, ok := document["spec"].(map[string]any)
	if !ok {
		return false, false
	}
	nonEmptyName := func(value any, key string) bool {
		object, ok := value.(map[string]any)
		if !ok {
			return false
		}
		name, _ := object[key].(string)
		return name != ""
	}
	for _, key := range []string{"serviceAccountName", "serviceAccount"} {
		if name, _ := spec[key].(string); name != "" {
			return true, true
		}
	}
	if claims, ok := spec["resourceClaims"].([]any); ok && len(claims) > 0 {
		return true, true
	}
	if pullSecrets, ok := spec["imagePullSecrets"].([]any); ok {
		for _, item := range pullSecrets {
			if nonEmptyName(item, "name") {
				return true, true
			}
		}
	}
	for _, list := range []string{"initContainers", "containers", "ephemeralContainers"} {
		containers, _ := spec[list].([]any)
		for _, item := range containers {
			container, ok := item.(map[string]any)
			if !ok {
				return false, false
			}
			envFrom, _ := container["envFrom"].([]any)
			for _, entry := range envFrom {
				object, _ := entry.(map[string]any)
				if nonEmptyName(object["secretRef"], "name") || nonEmptyName(object["configMapRef"], "name") {
					return true, true
				}
			}
			env, _ := container["env"].([]any)
			for _, entry := range env {
				object, _ := entry.(map[string]any)
				valueFrom, _ := object["valueFrom"].(map[string]any)
				if nonEmptyName(valueFrom["secretKeyRef"], "name") || nonEmptyName(valueFrom["configMapKeyRef"], "name") {
					return true, true
				}
			}
		}
	}
	allowed := map[string]bool{
		"awsElasticBlockStore": true, "azureDisk": true, "cephfs": true, "cinder": true, "downwardAPI": true,
		"emptyDir": true, "fc": true, "flexVolume": true, "flocker": true, "gcePersistentDisk": true,
		"gitRepo": true, "hostPath": true, "image": true, "iscsi": true, "nfs": true, "photonPersistentDisk": true,
		"portworxVolume": true, "quobyte": true, "rbd": true, "scaleIO": true, "storageos": true, "vsphereVolume": true,
	}
	secretRefs := map[string]string{"cephfs": "secretRef", "cinder": "secretRef", "flexVolume": "secretRef", "rbd": "secretRef", "scaleIO": "secretRef", "iscsi": "secretRef", "storageos": "secretRef"}
	volumes, _ := spec["volumes"].([]any)
	for _, item := range volumes {
		volume, ok := item.(map[string]any)
		if !ok {
			return false, false
		}
		for key, value := range volume {
			if key == "name" {
				continue
			}
			if allowed[key] {
				if field, ok := secretRefs[key]; ok {
					if object, ok := value.(map[string]any); ok && nonEmptyName(object[field], "name") {
						return true, true
					}
				}
				continue
			}
			if key == "projected" {
				object, _ := value.(map[string]any)
				sources, _ := object["sources"].([]any)
				for _, source := range sources {
					sourceObject, _ := source.(map[string]any)
					for sourceKey := range sourceObject {
						if sourceKey != "downwardAPI" {
							return true, true
						}
					}
				}
				continue
			}
			// configMap, secret, csi, glusterfs, persistentVolumeClaim,
			// ephemeral, azureFile, and any unknown volume type are denied.
			return true, true
		}
	}
	return false, true
}

// KubernetesComponentConfigAllFacts returns every fact the adapter defines, in
// table order. A native route passes it to select the rules this adapter can
// decide.
func KubernetesComponentConfigAllFacts() []string {
	facts := make([]string, 0, len(k8sComponentPredicates))
	for _, predicate := range k8sComponentPredicates {
		facts = append(facts, predicate.Fact)
	}
	return facts
}
