// SPDX-License-Identifier: AGPL-3.0-only

package cncfprepare

import (
	"encoding/json"
	"github.com/prufyx/prufyx/cli/internal/intake"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"
)

// This file implements the Kubernetes component-configuration adapter. One
// caller-written selection document names local files and the role of each;
// the adapter reduces them to one normalised model per component (argument
// tokens, feature gates and parsed configuration documents, plus rendered pod
// specifications for field-level predicates) and evaluates the reviewed
// predicates for the minor line a transition crosses. Every predicate yields one
// bool fact:
//
//   - true when a supplied source shows the removed setting (presence is
//     decisive, even when other sources are missing);
//   - false only when every scope the predicate reads is declared complete by
//     the caller and every source in those scopes was fully resolved;
//   - unsupported (UNKNOWN) otherwise.
//
// Absence is never inferred from sources that were not supplied.

const (
	KubernetesComponentSelectionAPIVersion = "prufyx.io/kubernetes-component-config/v1alpha1"
	KubernetesComponentSelectionKind       = "ComponentConfigSelection"

	maxK8sComponentSources = 64
	// MaxKubernetesComponentSourceBytes bounds each referenced file.
	MaxKubernetesComponentSourceBytes = 1 << 20
	maxK8sComponentPathBytes          = 1024
)

const (
	ReasonKubernetesComponentSettingPresent     Reason = "KUBERNETES_COMPONENT_REMOVED_SETTING_PRESENT"
	ReasonKubernetesComponentSettingAbsent      Reason = "KUBERNETES_COMPONENT_REMOVED_SETTING_ABSENT"
	ReasonKubernetesComponentEvidenceIncomplete Reason = "KUBERNETES_COMPONENT_EVIDENCE_INCOMPLETE"
	ReasonKubernetesComponentNoReviewedRule     Reason = "KUBERNETES_COMPONENT_NO_REVIEWED_PREDICATE_FOR_TRANSITION"
	ReasonKubernetesComponentDistribution       Reason = "KUBERNETES_COMPONENT_OFFICIAL_DISTRIBUTION_UNRESOLVED"
)

// Scopes a selection may name. Each control-plane and node component scope
// holds that component's arguments and configuration; kubeadm holds kubeadm
// configuration documents; static-pods and workloads hold pod specifications
// read by the field-level predicates.
const (
	K8sScopeAPIServer         = "kube-apiserver"
	K8sScopeControllerManager = "kube-controller-manager"
	K8sScopeScheduler         = "kube-scheduler"
	K8sScopeKubelet           = "kubelet"
	K8sScopeKubeProxy         = "kube-proxy"
	K8sScopeKubeadm           = "kubeadm"
	K8sScopeStaticPods        = "static-pods"
	K8sScopeWorkloads         = "workloads"
)

// Source formats.
const (
	K8sFormatPodManifest     = "pod-manifest"
	K8sFormatArgs            = "args"
	K8sFormatKubeletEnv      = "kubelet-env"
	K8sFormatKubeletConfig   = "kubelet-config"
	K8sFormatKubeletDropIn   = "kubelet-dropin"
	K8sFormatSchedulerConfig = "scheduler-config"
	K8sFormatKubeProxyConfig = "kube-proxy-config"
	K8sFormatAdmissionConfig = "admission-config"
	K8sFormatKubeadmConfig   = "kubeadm-config"
	K8sFormatManifests       = "manifests"
)

var k8sScopeFormats = map[string]map[string]bool{
	K8sScopeAPIServer:         {K8sFormatPodManifest: true, K8sFormatArgs: true, K8sFormatAdmissionConfig: true},
	K8sScopeControllerManager: {K8sFormatPodManifest: true, K8sFormatArgs: true},
	K8sScopeScheduler:         {K8sFormatPodManifest: true, K8sFormatArgs: true, K8sFormatSchedulerConfig: true},
	K8sScopeKubelet:           {K8sFormatKubeletEnv: true, K8sFormatArgs: true, K8sFormatKubeletConfig: true, K8sFormatKubeletDropIn: true},
	K8sScopeKubeProxy:         {K8sFormatPodManifest: true, K8sFormatArgs: true, K8sFormatKubeProxyConfig: true},
	K8sScopeKubeadm:           {K8sFormatKubeadmConfig: true},
	K8sScopeStaticPods:        {K8sFormatPodManifest: true},
	K8sScopeWorkloads:         {K8sFormatManifests: true},
}

var k8sDigestRE = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// KubernetesComponentSource is one caller-selected local file and its role.
// Path and Digest are used only to read and pin the file; neither reaches the
// canonical input or a report.
type KubernetesComponentSource struct {
	Scope     string
	Format    string
	Path      string
	Digest    string
	StaticPod bool
}

// KubernetesComponentSelection is the parsed selection document.
type KubernetesComponentSelection struct {
	Complete map[string]bool
	CgroupV1 *bool
	// KubeletNoConfigFile and KubeletNoConfigDir are caller declarations that
	// no kubelet uses a configuration file (--config) or a drop-in directory
	// (--config-dir), so the absence of a kubelet-config or kubelet-dropin
	// source is meaningful.
	KubeletNoConfigFile bool
	KubeletNoConfigDir  bool
	Sources             []KubernetesComponentSource
	selection           []byte
}

// ParseKubernetesComponentSelection strictly parses the caller's selection
// document. It never opens a referenced file.
func ParseKubernetesComponentSelection(raw []byte) (KubernetesComponentSelection, error) {
	if len(raw) == 0 || len(raw) > maxInputBytes || !utf8.Valid(raw) {
		return KubernetesComponentSelection{}, ErrInvalid
	}
	documents, err := intake.DecodeDocuments(raw)
	if err != nil || len(documents) != 1 {
		return KubernetesComponentSelection{}, ErrInvalid
	}
	root, ok := documents[0].(map[string]any)
	if !ok || allowFields(root, map[string]bool{"apiVersion": true, "kind": true, "complete": true, "declarations": true, "sources": true}) != nil {
		return KubernetesComponentSelection{}, ErrInvalid
	}
	if root["apiVersion"] != KubernetesComponentSelectionAPIVersion || root["kind"] != KubernetesComponentSelectionKind {
		return KubernetesComponentSelection{}, ErrInvalid
	}
	selection := KubernetesComponentSelection{Complete: map[string]bool{}, selection: append([]byte(nil), raw...)}
	if value, exists := root["complete"]; exists {
		items, ok := value.([]any)
		if !ok {
			return KubernetesComponentSelection{}, ErrInvalid
		}
		for _, item := range items {
			scope, ok := item.(string)
			if !ok || k8sScopeFormats[scope] == nil || selection.Complete[scope] {
				return KubernetesComponentSelection{}, ErrInvalid
			}
			selection.Complete[scope] = true
		}
	}
	if value, exists := root["declarations"]; exists {
		declarations, ok := value.(map[string]any)
		if !ok || allowFields(declarations, map[string]bool{"linuxNodeCgroupV1": true, "kubeletNoConfigFile": true, "kubeletNoConfigDir": true}) != nil {
			return KubernetesComponentSelection{}, ErrInvalid
		}
		for key, target := range map[string]*bool{"kubeletNoConfigFile": &selection.KubeletNoConfigFile, "kubeletNoConfigDir": &selection.KubeletNoConfigDir} {
			if value, exists := declarations[key]; exists {
				declared, ok := value.(bool)
				if !ok {
					return KubernetesComponentSelection{}, ErrInvalid
				}
				*target = declared
			}
		}
		if value, exists := declarations["linuxNodeCgroupV1"]; exists {
			declared, ok := value.(bool)
			if !ok {
				return KubernetesComponentSelection{}, ErrInvalid
			}
			selection.CgroupV1 = &declared
		}
	}
	items, ok := root["sources"].([]any)
	if !ok || len(items) == 0 || len(items) > maxK8sComponentSources {
		return KubernetesComponentSelection{}, ErrInvalid
	}
	paths := map[string]bool{}
	for _, item := range items {
		object, ok := item.(map[string]any)
		if !ok || allowFields(object, map[string]bool{"scope": true, "format": true, "path": true, "digest": true, "staticPod": true}) != nil {
			return KubernetesComponentSelection{}, ErrInvalid
		}
		scope, scopeOK := object["scope"].(string)
		format, formatOK := object["format"].(string)
		path, pathOK := object["path"].(string)
		if !scopeOK || !formatOK || !pathOK || !k8sScopeFormats[scope][format] || !validK8sSourcePath(path) || paths[path] {
			return KubernetesComponentSelection{}, ErrInvalid
		}
		paths[path] = true
		source := KubernetesComponentSource{Scope: scope, Format: format, Path: path}
		if value, exists := object["digest"]; exists {
			digest, ok := value.(string)
			if !ok || !k8sDigestRE.MatchString(digest) {
				return KubernetesComponentSelection{}, ErrInvalid
			}
			source.Digest = digest
		}
		if value, exists := object["staticPod"]; exists {
			static, ok := value.(bool)
			if !ok || format != K8sFormatPodManifest || scope == K8sScopeStaticPods {
				return KubernetesComponentSelection{}, ErrInvalid
			}
			source.StaticPod = static
		}
		selection.Sources = append(selection.Sources, source)
	}
	return selection, nil
}

func validK8sSourcePath(path string) bool {
	return path != "" && len(path) <= maxK8sComponentPathBytes && utf8.ValidString(path) && filepath.IsAbs(path) && filepath.Clean(path) == path && !strings.ContainsAny(path, "\x00\n\r")
}

// KubernetesComponentSourceDigest binds the selection bytes and every source's
// bytes, in selection order, into one digest. Callers compare it with
// Prepared.SourceDigest.
func KubernetesComponentSourceDigest(selectionRaw []byte, contents [][]byte) string {
	digests := make([]string, 0, len(contents))
	for _, content := range contents {
		digests = append(digests, digestBytes(content))
	}
	encoded, _ := json.Marshal(struct {
		Selection string   `json:"selection"`
		Sources   []string `json:"sources"`
	}{digestBytes(selectionRaw), digests})
	return digestBytes(encoded)
}

// PrepareKubernetesComponentConfig evaluates the reviewed predicates for the
// minor line that from -> to crosses. contents holds each selected source's
// bytes in selection order. registered reports whether the active knowledge
// declares a fact; facts it does not declare are not emitted, so the adapter
// never invents a fact no reviewed rule consumes.
func PrepareKubernetesComponentConfig(selection KubernetesComponentSelection, contents [][]byte, from, to, distribution string, registered func(string) bool) (Prepared, error) {
	if !validVersionSyntax(from) || !validVersionSyntax(to) || from == to || len(selection.selection) == 0 || len(contents) != len(selection.Sources) || registered == nil {
		return Prepared{}, ErrInvalid
	}
	for index, content := range contents {
		if len(content) > MaxKubernetesComponentSourceBytes || !utf8.Valid(content) {
			return Prepared{}, ErrInvalid
		}
		if digest := selection.Sources[index].Digest; digest != "" && digest != digestBytes(content) {
			return Prepared{}, ErrInvalid
		}
	}
	predicates := make([]k8sPredicate, 0)
	if line, ok := kubernetesCrossedMinorLine(from, to); ok {
		for _, predicate := range k8sComponentPredicates {
			if predicate.Line == line && registered(predicate.Fact) {
				predicates = append(predicates, predicate)
			}
		}
	}
	// Set facts are not tied to one minor line: a published
	// forbid_set_member rule's own subject decides which transitions it
	// covers. Like every adapter fact they are emitted only for a transition
	// that crosses exactly one minor line.
	sets := make([]k8sSetFact, 0)
	if _, ok := kubernetesCrossedMinorLine(from, to); ok {
		for _, set := range k8sComponentSetFacts {
			if registered(set.Fact) {
				sets = append(sets, set)
			}
		}
	}
	model := buildK8sComponentModel(selection, contents)
	facts := make([]inputFact, 0, len(predicates)+len(sets))
	state, reason := StatePrepared, ReasonKubernetesComponentSettingAbsent
	if len(predicates) == 0 {
		reason = ReasonKubernetesComponentSettingSetsComplete
	}
	anyPresent := false
	switch {
	case len(predicates) == 0 && len(sets) == 0:
		state, reason = StateUnknown, ReasonKubernetesComponentNoReviewedRule
	case distribution != "official_upstream":
		state, reason = StateUnknown, ReasonKubernetesComponentDistribution
		for _, predicate := range predicates {
			facts = append(facts, inputFact{ID: predicate.Fact, State: "unsupported"})
		}
		for _, set := range sets {
			facts = append(facts, inputFact{ID: set.Fact, State: "unsupported"})
		}
	default:
		for _, set := range sets {
			members, complete, ok := model.members(set)
			switch {
			case !ok:
				state, reason = StateUnknown, ReasonKubernetesComponentEvidenceIncomplete
				facts = append(facts, inputFact{ID: set.Fact, State: "unsupported"})
			case !complete:
				state, reason = StateUnknown, ReasonKubernetesComponentEvidenceIncomplete
				facts = append(facts, setFact(set.Fact, members, false))
			default:
				facts = append(facts, setFact(set.Fact, members, true))
			}
		}
		for _, predicate := range predicates {
			result := predicate.Eval(model)
			switch {
			case result.present:
				anyPresent = true
				facts = append(facts, boolFact(predicate.Fact, true))
			case result.resolved && model.allComplete(predicate.Reads):
				facts = append(facts, boolFact(predicate.Fact, false))
			default:
				state, reason = StateUnknown, ReasonKubernetesComponentEvidenceIncomplete
				facts = append(facts, inputFact{ID: predicate.Fact, State: "unsupported"})
			}
		}
		if anyPresent {
			reason = ReasonKubernetesComponentSettingPresent
		}
	}
	sort.Slice(facts, func(i, j int) bool { return facts[i].ID < facts[j].ID })
	canonical, err := marshalComponentInput(KubernetesComponent, from, to, facts)
	if err != nil {
		return Prepared{}, ErrInvalid
	}
	return Prepared{
		CanonicalInputJSON: canonical,
		SourceDigest:       KubernetesComponentSourceDigest(selection.selection, contents),
		InputDigest:        digestBytes(canonical),
		State:              state,
		Reason:             reason,
		Omissions: []string{
			"CALLER_SELECTED_COMPONENT_CONFIGURATION_NOT_LIVE_OBSERVATION",
			"SCOPE_COMPLETENESS_AND_NODE_DECLARATIONS_ARE_CALLER_DECLARATIONS",
			"PATHS_ARGUMENT_VALUES_AND_RAW_DOCUMENTS_ARE_MINIMIZED_OUT",
			"COMPONENT_STARTUP_RUNTIME_BEHAVIOR_AND_WHOLE_UPGRADE_NOT_EVALUATED",
		},
	}, nil
}

// k8sScopeEvidence is the normalised evidence for one scope.
type k8sScopeEvidence struct {
	argv       [][]string
	configs    []map[string]any
	dropins    int // how many of configs came from kubelet drop-in files
	pods       []map[string]any
	unresolved bool
}

type k8sComponentModel struct {
	scopes   map[string]*k8sScopeEvidence
	complete map[string]bool
	cgroupV1 *bool
	kubeadm  []map[string]any

	kubeletNoConfigFile, kubeletNoConfigDir bool
}

func (m *k8sComponentModel) scope(name string) *k8sScopeEvidence {
	evidence, ok := m.scopes[name]
	if !ok {
		evidence = &k8sScopeEvidence{}
		m.scopes[name] = evidence
	}
	return evidence
}

// allComplete reports whether every read scope is declared complete and every
// source in it was resolved.
func (m *k8sComponentModel) allComplete(scopes []string) bool {
	for _, name := range scopes {
		if !m.complete[name] || m.scope(name).unresolved {
			return false
		}
	}
	return true
}

func buildK8sComponentModel(selection KubernetesComponentSelection, contents [][]byte) *k8sComponentModel {
	model := &k8sComponentModel{scopes: map[string]*k8sScopeEvidence{}, complete: selection.Complete, cgroupV1: selection.CgroupV1,
		kubeletNoConfigFile: selection.KubeletNoConfigFile, kubeletNoConfigDir: selection.KubeletNoConfigDir}
	for name := range k8sScopeFormats {
		model.scope(name)
	}
	for index, source := range selection.Sources {
		model.addSource(source, contents[index])
	}
	return model
}

func (m *k8sComponentModel) addSource(source KubernetesComponentSource, raw []byte) {
	scope := m.scope(source.Scope)
	// kubeadm configuration feeds several component scopes; an unreadable
	// kubeadm source therefore leaves each of them unresolved.
	affected := []*k8sScopeEvidence{scope}
	if source.Format == K8sFormatKubeadmConfig {
		affected = append(affected, m.scope(K8sScopeAPIServer), m.scope(K8sScopeControllerManager), m.scope(K8sScopeScheduler), m.scope(K8sScopeKubelet), m.scope(K8sScopeKubeProxy))
	}
	if source.StaticPod || source.Scope == K8sScopeStaticPods {
		affected = append(affected, m.scope(K8sScopeStaticPods))
	}
	unresolved := func() {
		for _, evidence := range affected {
			evidence.unresolved = true
		}
	}
	if len(raw) == 0 || argvRenderingUnresolved(raw) {
		unresolved()
		return
	}
	if source.Format == K8sFormatKubeletEnv {
		tokens, ok := k8sParseEnvFile(string(raw))
		if !ok {
			unresolved()
			return
		}
		scope.argv = append(scope.argv, tokens)
		return
	}
	documents, err := intake.DecodeDocuments(raw)
	if err != nil || len(documents) == 0 {
		unresolved()
		return
	}
	switch source.Format {
	case K8sFormatArgs:
		tokens, ok := k8sStringList(documents)
		if !ok {
			unresolved()
			return
		}
		scope.argv = append(scope.argv, tokens)
	case K8sFormatPodManifest:
		if len(documents) != 1 {
			unresolved()
			return
		}
		pod, ok := documents[0].(map[string]any)
		if !ok {
			unresolved()
			return
		}
		if source.StaticPod || source.Scope == K8sScopeStaticPods {
			if api, kind, ok := kubernetesGVK(pod); !ok || api != "v1" || kind != "Pod" {
				unresolved()
				return
			}
			m.scope(K8sScopeStaticPods).pods = append(m.scope(K8sScopeStaticPods).pods, pod)
		}
		if source.Scope != K8sScopeStaticPods {
			tokens, ok := k8sPodComponentArgv(pod, source.Scope)
			if !ok {
				scope.unresolved = true
				return
			}
			scope.argv = append(scope.argv, tokens)
		}
	case K8sFormatKubeletConfig:
		m.addConfigDocuments(scope, documents, "kubelet.config.k8s.io", "KubeletConfiguration", "kubelet")
	case K8sFormatKubeletDropIn:
		before := len(scope.configs)
		m.addConfigDocuments(scope, documents, "kubelet.config.k8s.io", "KubeletConfiguration", "")
		scope.dropins += len(scope.configs) - before
	case K8sFormatKubeProxyConfig:
		m.addConfigDocuments(scope, documents, "kubeproxy.config.k8s.io", "KubeProxyConfiguration", "config.conf")
	case K8sFormatSchedulerConfig:
		m.addConfigDocuments(scope, documents, "kubescheduler.config.k8s.io", "KubeSchedulerConfiguration", "")
	case K8sFormatAdmissionConfig:
		for _, document := range documents {
			object, ok := document.(map[string]any)
			api, kind, gvkOK := kubernetesGVK(object)
			group, _, _ := strings.Cut(api, "/")
			if !ok || !gvkOK || (kind != "AdmissionConfiguration" && !k8sWebhookAdmissionKind(kind)) || (group != "apiserver.config.k8s.io" && group != "apiserver.k8s.io") {
				scope.unresolved = true
				return
			}
			scope.configs = append(scope.configs, object)
		}
	case K8sFormatKubeadmConfig:
		if !m.addKubeadmDocuments(documents) {
			unresolved()
		}
	case K8sFormatManifests:
		pods, ok := k8sManifestDocuments(documents)
		if !ok {
			scope.unresolved = true
			return
		}
		scope.pods = append(scope.pods, pods...)
	default:
		unresolved()
	}
}

// addConfigDocuments accepts component configuration documents of one group
// and kind, or a v1 ConfigMap carrying one in the named data key.
func (m *k8sComponentModel) addConfigDocuments(scope *k8sScopeEvidence, documents []any, group, kind, configMapKey string) {
	for _, document := range documents {
		object, ok := document.(map[string]any)
		if !ok {
			scope.unresolved = true
			return
		}
		api, documentKind, gvkOK := kubernetesGVK(object)
		if gvkOK && api == "v1" && documentKind == "ConfigMap" && configMapKey != "" {
			inner, ok := k8sConfigMapDocument(object, configMapKey)
			if !ok {
				scope.unresolved = true
				return
			}
			object = inner
			api, documentKind, gvkOK = kubernetesGVK(object)
		}
		documentGroup, _, _ := strings.Cut(api, "/")
		if !gvkOK || documentGroup != group || documentKind != kind {
			scope.unresolved = true
			return
		}
		scope.configs = append(scope.configs, object)
	}
}

func k8sConfigMapDocument(configMap map[string]any, key string) (map[string]any, bool) {
	data, ok := configMap["data"].(map[string]any)
	if !ok {
		return nil, false
	}
	text, ok := data[key].(string)
	if !ok || text == "" || argvRenderingUnresolved([]byte(text)) {
		return nil, false
	}
	documents, err := intake.DecodeDocuments([]byte(text))
	if err != nil || len(documents) != 1 {
		return nil, false
	}
	object, ok := documents[0].(map[string]any)
	return object, ok
}

// addKubeadmDocuments records kubeadm documents and routes their extraArgs and
// embedded component configuration to the component scopes. extraArgs is a
// string map up to kubeadm.k8s.io/v1beta3 and a list of name/value objects
// from v1beta4; the form must match the document's version.
func (m *k8sComponentModel) addKubeadmDocuments(documents []any) bool {
	for _, document := range documents {
		object, ok := document.(map[string]any)
		if !ok {
			return false
		}
		api, kind, gvkOK := kubernetesGVK(object)
		if !gvkOK {
			return false
		}
		if api == "v1" && kind == "ConfigMap" {
			inner, ok := k8sConfigMapDocument(object, "ClusterConfiguration")
			if !ok {
				return false
			}
			object = inner
			if api, kind, gvkOK = kubernetesGVK(object); !gvkOK {
				return false
			}
		}
		group, version, _ := strings.Cut(api, "/")
		switch {
		case group == "kubeadm.k8s.io":
			m.kubeadm = append(m.kubeadm, object)
			listForm := false
			switch version {
			case "v1beta1", "v1beta2", "v1beta3":
			case "v1beta4":
				listForm = true
			default:
				return false
			}
			if !m.addKubeadmExtraArgs(object, kind, listForm) {
				return false
			}
		case group == "kubelet.config.k8s.io" && kind == "KubeletConfiguration":
			m.scope(K8sScopeKubelet).configs = append(m.scope(K8sScopeKubelet).configs, object)
		case group == "kubeproxy.config.k8s.io" && kind == "KubeProxyConfiguration":
			m.scope(K8sScopeKubeProxy).configs = append(m.scope(K8sScopeKubeProxy).configs, object)
		default:
			return false
		}
	}
	return true
}

func (m *k8sComponentModel) addKubeadmExtraArgs(object map[string]any, kind string, listForm bool) bool {
	type route struct {
		path  []string
		scope string
	}
	var routes []route
	switch kind {
	case "ClusterConfiguration":
		routes = []route{
			{[]string{"apiServer", "extraArgs"}, K8sScopeAPIServer},
			{[]string{"controllerManager", "extraArgs"}, K8sScopeControllerManager},
			{[]string{"scheduler", "extraArgs"}, K8sScopeScheduler},
		}
	case "InitConfiguration", "JoinConfiguration":
		routes = []route{{[]string{"nodeRegistration", "kubeletExtraArgs"}, K8sScopeKubelet}}
	case "ResetConfiguration", "UpgradeConfiguration":
		return true
	default:
		return false
	}
	for _, route := range routes {
		value, found, ok := k8sPath(object, route.path...)
		if !ok {
			return false
		}
		if !found || value == nil {
			continue
		}
		tokens, ok := k8sKubeadmExtraArgs(value, listForm)
		if !ok {
			return false
		}
		m.scope(route.scope).argv = append(m.scope(route.scope).argv, tokens)
	}
	return true
}

func k8sKubeadmExtraArgs(value any, listForm bool) ([]string, bool) {
	tokens := make([]string, 0)
	if listForm {
		items, ok := value.([]any)
		if !ok {
			return nil, false
		}
		for _, item := range items {
			object, ok := item.(map[string]any)
			if !ok || allowFields(object, map[string]bool{"name": true, "value": true}) != nil {
				return nil, false
			}
			name, nameOK := object["name"].(string)
			text, valueOK := object["value"].(string)
			if !nameOK || name == "" || strings.HasPrefix(name, "-") || (!valueOK && object["value"] != nil) {
				return nil, false
			}
			tokens = append(tokens, "--"+name+"="+text)
		}
		return tokens, true
	}
	object, ok := value.(map[string]any)
	if !ok {
		return nil, false
	}
	names := make([]string, 0, len(object))
	for name := range object {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		text, ok := object[name].(string)
		if !ok || strings.HasPrefix(name, "-") {
			return nil, false
		}
		tokens = append(tokens, "--"+name+"="+text)
	}
	return tokens, true
}

// k8sPodComponentArgv selects the one container whose explicit command names
// the component binary and returns its arguments (command[1:] then args). A
// container that relies on the image entrypoint, or a manifest where zero or
// several containers name the binary, stays unresolved.
func k8sPodComponentArgv(document map[string]any, binary string) ([]string, bool) {
	spec, ok := k8sPodSpec(document)
	if !ok {
		return nil, false
	}
	containers, ok := spec["containers"].([]any)
	if !ok {
		return nil, false
	}
	var selected []string
	matches := 0
	for _, item := range containers {
		container, ok := item.(map[string]any)
		if !ok {
			return nil, false
		}
		command, commandSet := container["command"]
		if !commandSet {
			continue
		}
		commandTokens, ok := k8sStrings(command)
		if !ok || len(commandTokens) == 0 || !argvExecutableMatches(commandTokens[0], binary) {
			continue
		}
		tokens := append([]string(nil), commandTokens[1:]...)
		if args, exists := container["args"]; exists {
			argTokens, ok := k8sStrings(args)
			if !ok {
				return nil, false
			}
			tokens = append(tokens, argTokens...)
		}
		selected = tokens
		matches++
	}
	if matches != 1 {
		return nil, false
	}
	return selected, true
}

// k8sPodSpec returns the pod specification of a v1 Pod or of an apps/v1
// DaemonSet, Deployment or StatefulSet template.
func k8sPodSpec(document map[string]any) (map[string]any, bool) {
	api, kind, ok := kubernetesGVK(document)
	if !ok {
		return nil, false
	}
	var value any
	var found bool
	switch {
	case api == "v1" && kind == "Pod":
		value, found, ok = k8sPath(document, "spec")
	case api == "apps/v1" && (kind == "DaemonSet" || kind == "Deployment" || kind == "StatefulSet"):
		value, found, ok = k8sPath(document, "spec", "template", "spec")
	default:
		return nil, false
	}
	spec, isMap := value.(map[string]any)
	return spec, ok && found && isMap
}

// k8sManifestDocuments flattens one level of v1 List and rejects nested or
// paginated lists, mirroring the rendered apply-set contract.
func k8sManifestDocuments(documents []any) ([]map[string]any, bool) {
	result := make([]map[string]any, 0, len(documents))
	for _, document := range documents {
		object, ok := document.(map[string]any)
		if !ok {
			return nil, false
		}
		api, kind, ok := kubernetesGVK(object)
		if !ok {
			return nil, false
		}
		if kind != "List" {
			if strings.HasSuffix(kind, "List") {
				return nil, false
			}
			result = append(result, object)
			continue
		}
		if api != "v1" {
			return nil, false
		}
		paginated, metadataOK := kubernetesListPagination(object)
		if !metadataOK || paginated {
			return nil, false
		}
		items, ok := object["items"].([]any)
		if !ok {
			return nil, false
		}
		for _, item := range items {
			itemObject, ok := item.(map[string]any)
			if !ok {
				return nil, false
			}
			if _, itemKind, ok := kubernetesGVK(itemObject); !ok || strings.HasSuffix(itemKind, "List") {
				return nil, false
			}
			result = append(result, itemObject)
		}
	}
	return result, true
}

// k8sParseEnvFile reads a systemd EnvironmentFile-style kubelet flags file
// (kubeadm-flags.env, /etc/default/kubelet, /etc/sysconfig/kubelet). Every
// assigned value is split on whitespace into argument tokens. Any construct
// whose expansion would need a shell (quotes inside values, $, backticks,
// backslashes, line continuations) leaves the file unresolved.
func k8sParseEnvFile(text string) ([]string, bool) {
	tokens := make([]string, 0)
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(strings.TrimSuffix(line, "\r"))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.TrimPrefix(line, "export ")
		name, value, found := strings.Cut(line, "=")
		if !found || !k8sEnvName(name) {
			return nil, false
		}
		if len(value) >= 2 && (value[0] == '"' || value[0] == '\'') {
			if value[len(value)-1] != value[0] {
				return nil, false
			}
			value = value[1 : len(value)-1]
		}
		if strings.ContainsAny(value, "\"'$`\\") {
			return nil, false
		}
		tokens = append(tokens, strings.Fields(value)...)
	}
	return tokens, true
}

func k8sEnvName(name string) bool {
	if name == "" {
		return false
	}
	for index, character := range name {
		if !(character == '_' || character >= 'A' && character <= 'Z' || character >= 'a' && character <= 'z' || index > 0 && character >= '0' && character <= '9') {
			return false
		}
	}
	return true
}

func k8sStringList(documents []any) ([]string, bool) {
	if len(documents) != 1 {
		return nil, false
	}
	return k8sStrings(documents[0])
}

func k8sStrings(value any) ([]string, bool) {
	items, ok := value.([]any)
	if !ok {
		return nil, false
	}
	result := make([]string, 0, len(items))
	for _, item := range items {
		text, ok := item.(string)
		if !ok {
			return nil, false
		}
		result = append(result, text)
	}
	return result, true
}

// k8sPath walks object keys. found is false when a key is absent; ok is false
// when an intermediate value is not an object or when a key differs from the
// wanted spelling only by case, which a case-sensitive component decoder would
// reject but a lenient reader could mistake for absence.
func k8sPath(object map[string]any, keys ...string) (value any, found, ok bool) {
	current := any(object)
	for _, key := range keys {
		mapping, isMap := current.(map[string]any)
		if !isMap {
			if current == nil {
				return nil, false, true
			}
			return nil, false, false
		}
		for candidate := range mapping {
			if candidate != key && strings.EqualFold(candidate, key) {
				return nil, false, false
			}
		}
		next, exists := mapping[key]
		if !exists {
			return nil, false, true
		}
		current = next
	}
	return current, true, true
}
