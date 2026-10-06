// SPDX-License-Identifier: AGPL-3.0-only

package localcollector

import (
	"encoding/json"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/prufyx/prufyx/cli/internal/imageidentity"
)

var strictVersionRE = regexp.MustCompile(`^v?(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-(0|[1-9][0-9]*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*)(?:\.(0|[1-9][0-9]*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*))*)?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$`)
var digestSuffixRE = regexp.MustCompile(`@sha256:[0-9a-fA-F]{64}$`)

type containerRecord struct {
	workloadIndex int
	workloadKind  string
	image         string
	container     map[string]any
	init          []any
}

func projectWorkload(root any, adapter adapterAssets, profile string, now time.Time) (map[string]any, error) {
	items, err := listRoot(root, 50000)
	if err != nil {
		return nil, err
	}
	containers := []containerRecord{}
	omissions := []any{}
	for index, item := range items {
		kind, ok := stringValue(at(item, "kind"))
		if !ok {
			return nil, errProjection
		}
		podSpec := workloadPodSpec(item, kind)
		if podSpec == nil {
			if kind == "ReplicationController" && at(item, "spec", "template") == nil {
				continue
			}
			return nil, errProjection
		}
		regular := nullDefault(podSpec["containers"], []any{})
		initValue := nullDefault(podSpec["initContainers"], []any{})
		regularContainers, ok1 := array(regular)
		initContainers, ok2 := array(initValue)
		if !ok1 || !ok2 {
			return nil, errProjection
		}
		if len(regularContainers) == 0 && len(initContainers) > 0 {
			omissions = append(omissions, newProjectionOmission("COMPONENT_CONFIGURATION_NO_REGULAR_CONTAINERS", "Only initContainers were present; init containers are never an effective reviewed component workload."))
		} else if profile == "v3" && len(regularContainers) > 0 && len(initContainers) > 0 {
			omissions = append(omissions, newProjectionOmission("COMPONENT_CONFIGURATION_INIT_CONTAINERS_IGNORED", "Init containers were present but are outside the reviewed effective component configuration surface."))
		}
		for _, value := range regularContainers {
			container, ok := object(value)
			if !ok {
				return nil, errProjection
			}
			image, ok := stringValue(container["image"])
			if !ok || strings.ContainsAny(image, "\x00\r\n") {
				return nil, errProjection
			}
			containers = append(containers, containerRecord{index, kind, image, container, initContainers})
		}
	}

	publicImages := []any{}
	configuration := []any{}
	for _, record := range containers {
		identity, version, scheme, _ := publicImage(record.image)
		matched := findAdapter(adapter.Contract, identity)
		if profile == "v3" && strings.HasPrefix(record.image, "index.docker.io/") {
			matched = nil
		}
		if matched != nil && contains(matched.WorkloadKinds, record.workloadKind) {
			publicImages = append(publicImages, map[string]any{
				"componentId": matched.ComponentID, "observedVersion": version, "versionScheme": scheme,
				"observationState": "active", "observationCount": 1, "versionConflict": false,
			})
		}
		if observed := registryImage(record, matched, now); observed != nil {
			publicImages = append(publicImages, observed)
		}
		row, omission := configureContainer(record, containers, matched, profile, version, scheme)
		if row != nil {
			configuration = append(configuration, row)
		}
		if omission != nil {
			omissions = append(omissions, omission)
		}
	}
	sortAny(publicImages)
	return map[string]any{"images": []any{}, "publicImages": publicImages, "configuration": configuration, "omissions": omissions, "version": "v1"}, nil
}

// registryWorkloadKinds are the kinds whose regular containers the reviewed
// image registry may identify, the same long-running kinds the adapter
// registry reads.
var registryWorkloadKinds = []string{"Deployment", "StatefulSet", "DaemonSet"}

// registryImage projects one container image that only the reviewed image
// registry (not the adapter registry) identifies. It returns nil unless the
// image matches a registry record, so no other image, tag or field is ever
// recorded; a matched image yields exactly the public-image row shape the
// collector already writes, carrying the project's component and the version
// the registry derived (or none). Digest-only, unknown-tag, distribution and
// unlisted images produce no version, and unlisted or distribution images no
// row at all.
func registryImage(record containerRecord, adapterMatch *componentAdapter, now time.Time) map[string]any {
	if adapterMatch != nil || !contains(registryWorkloadKinds, record.workloadKind) {
		return nil
	}
	res := imageidentity.Match(record.image, now)
	if res.Kind != imageidentity.KindMatched {
		return nil
	}
	var version any
	if res.Version != "" {
		version = res.Version
	}
	return map[string]any{
		"componentId": res.Component, "observedVersion": version, "versionScheme": res.Scheme,
		"observationState": "active", "observationCount": 1, "versionConflict": false,
	}
}

func workloadPodSpec(item any, kind string) map[string]any {
	if kind == "CronJob" {
		value, _ := object(at(item, "spec", "jobTemplate", "spec", "template", "spec"))
		return value
	}
	value, _ := object(at(item, "spec", "template", "spec"))
	return value
}

func publicImage(raw string) (identity string, version any, scheme, imageDigest string) {
	imageDigest = ""
	if loc := digestSuffixRE.FindStringIndex(raw); loc != nil {
		imageDigest = raw[loc[0]+1:]
		raw = raw[:loc[0]]
		scheme = "digest"
	}
	if strings.HasPrefix(raw, "docker.io/") {
		raw = strings.TrimPrefix(raw, "docker.io/")
	} else if strings.HasPrefix(raw, "index.docker.io/") {
		raw = strings.TrimPrefix(raw, "index.docker.io/")
	}
	lastSlash := strings.LastIndexByte(raw, '/')
	lastColon := strings.LastIndexByte(raw, ':')
	identity = raw
	if lastColon > lastSlash {
		tag := raw[lastColon+1:]
		identity = raw[:lastColon]
		if strictVersionRE.MatchString(tag) && len(tag) <= 128 {
			version = tag
			if scheme == "" {
				scheme = "tag"
			}
		}
	}
	if scheme == "" {
		scheme = "unknown"
	}
	return identity, version, scheme, imageDigest
}

func findAdapter(registry adapterRegistry, identity string) *componentAdapter {
	for i := range registry.Adapters {
		if contains(registry.Adapters[i].Identities, identity) {
			return &registry.Adapters[i]
		}
	}
	return nil
}

func configureContainer(record containerRecord, all []containerRecord, adapter *componentAdapter, profile string, version any, scheme string) (map[string]any, any) {
	if adapter == nil {
		return nil, newProjectionOmission("COMPONENT_CONFIGURATION_IDENTITY_UNRESOLVED", "No exact public adapter identity matched the workload image.")
	}
	if profile == "v3" && adapter.ComponentID == "pkg:oci/prometheus/prometheus" && (record.workloadKind == "ReplicaSet" || record.workloadKind == "Pod") {
		return nil, nil
	}
	if !contains(adapter.WorkloadKinds, record.workloadKind) {
		return nil, newProjectionOmission("COMPONENT_CONFIGURATION_WORKLOAD_ROLE_UNSUPPORTED", "The workload kind is not an approved controller role for this component adapter.")
	}
	if profile == "v3" && adapter.ComponentID == "pkg:oci/prometheus/prometheus" && !prometheusContextComplete(all, adapter) {
		return nil, newProjectionOmission("COMPONENT_CONFIGURATION_DECLARED_ROLE_AMBIGUOUS", "At least one recognized eligible component controller lacked complete source-bound declared context; no subset is retained.")
	}
	if scheme == "unknown" {
		return nil, newProjectionOmission("COMPONENT_CONFIGURATION_VERSION_UNRESOLVED", "The approved public identity did not carry a strict release-version tag or digest pin.")
	}
	if state := validateEntrypoint(record, all, adapter, profile, version); state != "observed" {
		code := map[string]string{
			"unsupported_version": "COMPONENT_CONFIGURATION_ENTRYPOINT_VERSION_UNSUPPORTED",
			"unverified_image":    "COMPONENT_CONFIGURATION_IMAGE_BINDING_UNVERIFIED",
			"ambiguous_role":      "COMPONENT_CONFIGURATION_DECLARED_ROLE_AMBIGUOUS",
		}[state]
		if code == "" {
			code = "COMPONENT_CONFIGURATION_COMMAND_SURFACE_UNAVAILABLE"
		}
		return nil, newProjectionOmission(code, "The workload command or image is outside the exact source-bound component contract.")
	}
	args, state := validatedArgs(record.container, profile)
	if state == "unavailable" && profile == "v3" && adapter.ComponentID == "pkg:oci/prometheus/prometheus" && imageDefaultFalse(record.image, adapter, "component.prometheus.agent_mode") {
		args, state = []string{}, "observed"
	}
	if state != "observed" {
		if state == "unavailable" {
			return nil, newProjectionOmission("COMPONENT_CONFIGURATION_ARGS_UNAVAILABLE", "The workload did not declare an argument array for the approved adapter.")
		}
		return nil, newProjectionOmission("COMPONENT_CONFIGURATION_ARGS_MALFORMED", "The workload argument surface was malformed or exceeded the local bound.")
	}
	predicates := map[string]any{}
	for _, rule := range adapter.Predicates {
		state, value := summarizeRule(args, rule, record.image, adapter)
		if state == "malformed" {
			return nil, newProjectionOmission("COMPONENT_CONFIGURATION_PREDICATE_MALFORMED", "A registered component predicate had an invalid or disallowed value.")
		}
		if state == "conflict" {
			return nil, newProjectionOmission("COMPONENT_CONFIGURATION_PREDICATE_CONFLICT", "Duplicate arguments disagreed for a registered component predicate.")
		}
		if state == "observed" {
			predicates[rule.ID] = value
		}
	}
	if roleID := certManagerRole(publicIdentityOnly(record.image)); roleID != "" {
		predicates[roleID] = true
	}
	if len(predicates) == 0 {
		return nil, newProjectionOmission("COMPONENT_CONFIGURATION_PREDICATE_UNOBSERVED", "No registered component predicate was explicitly observed.")
	}
	row := map[string]any{
		"componentId": adapter.ComponentID, "observedVersion": version, "versionScheme": scheme,
		"versionConflict": false, "observationState": "observed", "observationCount": 1, "predicates": predicates,
	}
	if profile == "v3" && adapter.Entrypoint != nil {
		row["observedVersion"] = strings.TrimPrefix(asString(version), "v")
		row["versionScheme"] = "tag"
	}
	if (profile == "v2" || profile == "v3") && adapter.DeclaredRole != "" && adapter.RoleEvidenceClass != "" {
		row["roles"] = []any{adapter.DeclaredRole}
		evidence := []any{}
		for id := range predicates {
			evidence = append(evidence, map[string]any{"predicateId": id, "state": "observed", "sourceRole": adapter.DeclaredRole, "evidenceClass": adapter.RoleEvidenceClass})
		}
		sortAny(evidence)
		row["predicateEvidence"] = evidence
	}
	return row, nil
}

func validatedArgs(container map[string]any, profile string) ([]string, string) {
	value, present := container["args"]
	if !present {
		return nil, "unavailable"
	}
	values, ok := array(value)
	if !ok || len(values) > 256 {
		return nil, "malformed"
	}
	out := make([]string, 0, len(values))
	total := 0
	for _, value := range values {
		text, ok := value.(string)
		if !ok || len(text) > 512 || strings.ContainsAny(text, "\x00\r\n") || (profile == "v3" && (text == "" || text == "--" || strings.Contains(text, "$("))) {
			return nil, "malformed"
		}
		total += len(text)
		out = append(out, text)
	}
	if profile == "v3" && total > 16384 {
		return nil, "malformed"
	}
	if profile == "v3" {
		for i, text := range out {
			if strings.HasPrefix(text, "--") {
				continue
			}
			if i == 0 || !strings.HasPrefix(out[i-1], "--") || strings.Contains(out[i-1], "=") || out[i-1] == "--agent" || strings.HasPrefix(out[i-1], "--no-agent") {
				return nil, "malformed"
			}
		}
	}
	return out, "observed"
}

func validateEntrypoint(record containerRecord, all []containerRecord, adapter *componentAdapter, profile string, version any) string {
	commandValue, present := record.container["command"]
	if profile != "v3" || adapter.Entrypoint == nil {
		if present {
			return "unavailable"
		}
		return "observed"
	}
	binding := bindingFor(adapter, version)
	if binding == nil {
		return "unsupported_version"
	}
	if declaredImageTag(record.image) != "v"+binding.Version {
		return "unverified_image"
	}
	_, _, _, imageDigest := publicImage(record.image)
	if binding.ReferenceClass == "tag_and_platform_digest" && !contains(binding.PlatformDigests, imageDigest) {
		return "unverified_image"
	}
	if binding.ReferenceClass == "tag" && imageDigest != "" {
		return "unverified_image"
	}
	candidates := 0
	for _, candidate := range all {
		if candidate.workloadIndex == record.workloadIndex {
			matched := findAdapterByParticipation(adapter, candidate.image)
			if matched {
				candidates++
			}
		}
	}
	for _, value := range record.init {
		if image, ok := stringValue(at(value, "image")); ok && findAdapterByParticipation(adapter, image) {
			return "ambiguous_role"
		}
	}
	if candidates != 1 {
		return "ambiguous_role"
	}
	if !present && binding.ReferenceClass == "tag_and_platform_digest" {
		return "observed"
	}
	command, ok := stringArray(commandValue, 8, 128)
	if !ok {
		return "malformed"
	}
	for _, accepted := range adapter.Entrypoint.AcceptedCommands {
		if equalStrings(command, accepted) {
			return "observed"
		}
	}
	return "unavailable"
}

func findAdapterByParticipation(adapter *componentAdapter, image string) bool {
	identity := publicIdentityOnly(image)
	if adapter.ComponentID == "pkg:oci/prometheus/prometheus" && identity == "index.docker.io/prom/prometheus" {
		identity = "prom/prometheus"
	}
	return contains(adapter.Identities, identity)
}

func bindingFor(adapter *componentAdapter, version any) *imageBinding {
	text, _ := version.(string)
	text = strings.TrimPrefix(text, "v")
	for i := range adapter.Entrypoint.ImageBindings {
		if adapter.Entrypoint.ImageBindings[i].Version == text {
			return &adapter.Entrypoint.ImageBindings[i]
		}
	}
	return nil
}

func imageDefaultFalse(image string, adapter *componentAdapter, id string) bool {
	_, version, _, _ := publicImage(image)
	binding := bindingFor(adapter, version)
	return binding != nil && binding.DefaultPredicateValues[id] == false
}

func declaredImageTag(image string) string {
	image = digestSuffixRE.ReplaceAllString(image, "")
	if colon := strings.LastIndexByte(image, ':'); colon > strings.LastIndexByte(image, '/') {
		return image[colon+1:]
	}
	return ""
}

func prometheusContextComplete(all []containerRecord, adapter *componentAdapter) bool {
	found := false
	for _, record := range all {
		if !contains(adapter.WorkloadKinds, record.workloadKind) || !findAdapterByParticipation(adapter, record.image) {
			continue
		}
		found = true
		_, version, _, _ := publicImage(record.image)
		if validateEntrypoint(record, all, adapter, "v3", version) != "observed" {
			return false
		}
		args, state := validatedArgs(record.container, "v3")
		if state == "unavailable" && imageDefaultFalse(record.image, adapter, "component.prometheus.agent_mode") {
			args, state = []string{}, "observed"
		}
		if state != "observed" {
			return false
		}
		for _, rule := range adapter.Predicates {
			state, _ := summarizeRule(args, rule, record.image, adapter)
			if state != "observed" {
				return false
			}
		}
	}
	return found
}

func summarizeRule(args []string, rule predicateRule, image string, adapter *componentAdapter) (string, any) {
	if rule.ValueKind == "publicImageDigest" {
		_, version, _, value := publicImage(image)
		if bindingFor(adapter, version) != nil && value != "" {
			return "observed", value
		}
		return "unsupported", nil
	}
	if rule.ValueKind == "versionedAgentMode" {
		_, version, _, _ := publicImage(image)
		return prometheusAgentMode(args, strings.TrimPrefix(asString(version), "v"))
	}
	if len(rule.Flags) != 1 {
		return "malformed", nil
	}
	matches := []any{}
	for i, token := range args {
		flag := rule.Flags[0]
		inline := ""
		present := token == flag
		if strings.HasPrefix(token, flag+"=") {
			present, inline = true, strings.TrimPrefix(token, flag+"=")
		}
		if !present {
			continue
		}
		value, state := ruleValue(args, i, inline, rule)
		if state != "observed" {
			return state, nil
		}
		matches = append(matches, value)
	}
	if len(matches) == 0 {
		return "absent", nil
	}
	first, _ := json.Marshal(matches[0])
	for _, value := range matches[1:] {
		raw, _ := json.Marshal(value)
		if string(raw) != string(first) {
			return "conflict", nil
		}
	}
	return "observed", matches[0]
}

func ruleValue(args []string, index int, inline string, rule predicateRule) (any, string) {
	value := inline
	if rule.ValueKind == "presence" {
		value := inline
		if value == "" && index+1 < len(args) && !strings.HasPrefix(args[index+1], "--") {
			value = args[index+1]
		}
		if rule.ID == "component.argo_workflows.managed_namespace_configured" {
			if dns1123(value) {
				return true, "observed"
			}
			return nil, "malformed"
		}
		if value != "" {
			return nil, "malformed"
		}
		return true, "observed"
	}
	if value == "" && index+1 < len(args) && !strings.HasPrefix(args[index+1], "--") {
		value = args[index+1]
	}
	if rule.ValueKind == "boolean" {
		if value == "" {
			return true, "observed"
		}
		if value == "true" {
			return true, "observed"
		}
		if value == "false" {
			return false, "observed"
		}
		return nil, "malformed"
	}
	if rule.ValueKind == "enum" {
		if contains(rule.AllowedValues, value) {
			return value, "observed"
		}
		return nil, "malformed"
	}
	if rule.ValueKind == "featureGate" {
		seen := []bool{}
		for _, pair := range strings.Split(value, ",") {
			parts := strings.Split(pair, "=")
			if len(parts) != 2 || (parts[1] != "true" && parts[1] != "false") {
				return nil, "malformed"
			}
			if parts[0] == rule.FeatureGate {
				seen = append(seen, parts[1] == "true")
			}
		}
		if len(seen) == 0 {
			return nil, "absent"
		}
		for _, item := range seen[1:] {
			if item != seen[0] {
				return nil, "conflict"
			}
		}
		return seen[0], "observed"
	}
	return nil, "malformed"
}

var dns1123RE = regexp.MustCompile(`^[a-z0-9](?:[-a-z0-9]{0,61}[a-z0-9])?$`)

func dns1123(value string) bool {
	return len(value) >= 1 && len(value) <= 63 && dns1123RE.MatchString(value)
}

func prometheusAgentMode(args []string, version string) (string, any) {
	if version == "3.1.0" {
		count := 0
		for _, arg := range args {
			if arg == "--agent" {
				count++
			}
			if strings.HasPrefix(arg, "--no-agent") || (strings.HasPrefix(arg, "--agent") && arg != "--agent") {
				return "malformed", nil
			}
		}
		if count > 1 {
			return "conflict", nil
		}
		return "observed", count == 1
	}
	if version == "2.55.1" {
		enabled := false
		for i, arg := range args {
			if strings.HasPrefix(arg, "--agent") {
				return "malformed", nil
			}
			value := ""
			if arg == "--enable-feature" && i+1 < len(args) {
				value = args[i+1]
			}
			if strings.HasPrefix(arg, "--enable-feature=") {
				value = strings.TrimPrefix(arg, "--enable-feature=")
			}
			for _, feature := range strings.Split(value, ",") {
				if feature == "agent" {
					enabled = true
				}
			}
		}
		return "observed", enabled
	}
	return "unsupported", nil
}

func certManagerRole(identity string) string {
	for suffix, id := range map[string]string{
		"cert-manager-controller":      "component.cert_manager.controller_present",
		"cert-manager-webhook":         "component.cert_manager.webhook_present",
		"cert-manager-cainjector":      "component.cert_manager.cainjector_present",
		"cert-manager-startupapicheck": "component.cert_manager.startupapicheck_present",
	} {
		if strings.HasSuffix(identity, "/"+suffix) {
			return id
		}
	}
	return ""
}

func publicIdentityOnly(image string) string {
	identity, _, _, _ := publicImage(image)
	return identity
}
func newProjectionOmission(code, reason string) map[string]any {
	return map[string]any{"code": code, "reason": reason, "requiredForEvaluation": true}
}
func contains[T comparable](values []T, wanted T) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}
func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
func stringArray(value any, maxItems, maxBytes int) ([]string, bool) {
	values, ok := array(value)
	if !ok || len(values) == 0 || len(values) > maxItems {
		return nil, false
	}
	out := []string{}
	for _, value := range values {
		text, ok := value.(string)
		if !ok || text == "" || !utf8.ValidString(text) || len(text) > maxBytes || strings.ContainsAny(text, "\x00\r\n") {
			return nil, false
		}
		out = append(out, text)
	}
	return out, true
}
func asString(value any) string { text, _ := value.(string); return text }
func sortAny(values []any) {
	sort.SliceStable(values, func(i, j int) bool {
		a, _ := json.Marshal(values[i])
		b, _ := json.Marshal(values[j])
		return string(a) < string(b)
	})
}
