// SPDX-License-Identifier: AGPL-3.0-only

// Package cncfprepare derives one minimized Kyverno declaration from a local
// Kubernetes workload document. It does not read files, inspect a cluster, or
// retain the source workload.
package cncfprepare

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"strconv"
	"strings"
	"unicode/utf8"
)

const (
	InputSchema                     = "prufyx.io/operator-declared-constraint-input/v1alpha1"
	InputAuthority                  = "OPERATOR_DECLARED_MINIMIZED"
	KyvernoComponent                = "pkg:github/kyverno/kyverno"
	KyvernoDistributionFact         = "component.kyverno.distribution"
	KyvernoExecutionSurfaceFact     = "component.kyverno.execution_surface"
	KyvernoFact                     = "component.kyverno.reports_chunk_size_flag_present"
	KyvernoDistributionOfficial     = "official_upstream"
	KyvernoDistributionCustom       = "custom_build"
	KyvernoSurfaceReportsController = "reports_controller"
	FromVersion                     = "1.12.5"
	ToVersion                       = "1.13.0"
	maxInputBytes                   = 1 << 20
	maxJSONDepth                    = 32
	maxObjectMembers                = 4096
	maxArrayItems                   = 2048
)

var (
	ErrInvalid = errors.New("invalid Kyverno preparation input")
)

// State describes whether the adapter produced a declared fact.
type State = string

const (
	StatePrepared State = "PREPARED"
	StateUnknown  State = "UNKNOWN"
)

// Reason is a stable, public reason code. It never contains a private
// container name, workload name, image, argument, path, or source fragment.
type Reason = string

const (
	ReasonDirectCommandParsed        Reason = "DIRECT_REPORTS_CONTROLLER_COMMAND_PARSED"
	ReasonDistributionMissing        Reason = "DISTRIBUTION_DECLARATION_MISSING"
	ReasonCustomDistribution         Reason = "CUSTOM_DISTRIBUTION_DECLARED"
	ReasonUnsupportedVersionPair     Reason = "UNSUPPORTED_VERSION_PAIR"
	ReasonSelectedContainerMissing   Reason = "SELECTED_CONTAINER_MISSING"
	ReasonSelectedContainerAmbiguous Reason = "SELECTED_CONTAINER_AMBIGUOUS"
	ReasonImplicitEntrypoint         Reason = "IMPLICIT_IMAGE_ENTRYPOINT"
	ReasonUnsupportedCommand         Reason = "UNSUPPORTED_COMMAND"
	ReasonUnsupportedArguments       Reason = "UNSUPPORTED_ARGUMENTS"
	ReasonFlagAfterDelimiter         Reason = "FLAG_AFTER_END_OF_OPTIONS"
)

const (
	OmissionNoLiveObservation = "LIVE_OBSERVATION_NOT_PERFORMED"
	OmissionNoWholeUpgrade    = "WHOLE_UPGRADE_COMPATIBILITY_NOT_EVALUATED"
)

// Prepared is the only output retained by callers. CanonicalInputJSON is
// compact canonical JSON followed by exactly one newline and is accepted by
// cncfcheck. SourceDigest hashes the input workload bytes; InputDigest hashes
// CanonicalInputJSON exactly, including that one trailing newline.
type Prepared struct {
	CanonicalInputJSON []byte
	SourceDigest       string
	InputDigest        string
	State              State
	Reason             Reason
	Omissions          []string
}

// PrepareKyverno remains for callers using the original signature. It validates
// the local document but deliberately supplies no distribution declaration, so
// it cannot produce a scoped Kyverno result.
func PrepareKyverno(raw []byte, containerName, from, to string) (Prepared, error) {
	return PrepareKyvernoScoped(raw, containerName, from, to, "")
}

// PrepareKyvernoScoped derives a minimized declaration only for the exact
// reports-controller scope. Distribution is an explicit operator declaration;
// it is not inferred from the selected image or any workload field.
func PrepareKyvernoScoped(raw []byte, containerName, from, to, distribution string) (Prepared, error) {
	if len(raw) == 0 || len(raw) > maxInputBytes || !utf8.Valid(raw) || containerName == "" {
		return Prepared{}, ErrInvalid
	}
	if !validVersionSyntax(from) || !validVersionSyntax(to) || from == to {
		return Prepared{}, ErrInvalid
	}
	if distribution != "" && distribution != KyvernoDistributionOfficial && distribution != KyvernoDistributionCustom {
		return Prepared{}, ErrInvalid
	}
	value, err := decodeStrict(raw)
	if err != nil {
		return Prepared{}, err
	}
	root, ok := value.(map[string]any)
	if !ok {
		return Prepared{}, ErrInvalid
	}
	if err := allowFields(root, map[string]bool{"apiVersion": true, "kind": true, "metadata": true, "spec": true}); err != nil {
		return Prepared{}, err
	}
	container, selection, err := selectContainer(root, containerName)
	if err != nil {
		return Prepared{}, err
	}
	facts := []inputFact{
		{ID: KyvernoDistributionFact, State: "missing"},
		{ID: KyvernoExecutionSurfaceFact, State: "unsupported"},
		{ID: KyvernoFact, State: "unsupported"},
	}
	state := StateUnknown
	reason := ReasonDistributionMissing
	if distribution != "" {
		facts[0] = inputFact{ID: KyvernoDistributionFact, State: "declared", EnumValue: distribution}
	}
	switch {
	case distribution == "":
		// The compatibility wrapper and an omitted CLI flag cannot establish a
		// distribution guard. Do not inspect a command to manufacture a fact.
	case distribution == KyvernoDistributionCustom:
		reason = ReasonCustomDistribution
	case !supportedKyvernoPair(from, to):
		reason = ReasonUnsupportedVersionPair
	case selection != selectionReady:
		switch selection {
		case selectionMissing:
			reason = ReasonSelectedContainerMissing
		case selectionAmbiguous:
			reason = ReasonSelectedContainerAmbiguous
		}
		facts[1].State = "missing"
		facts[2].State = "missing"
	case !container.commandSet:
		reason = ReasonImplicitEntrypoint
	case len(container.command) == 0 || container.command[0] != "reports-controller":
		reason = ReasonUnsupportedCommand
	default:
		facts[1] = inputFact{ID: KyvernoExecutionSurfaceFact, State: "declared", EnumValue: KyvernoSurfaceReportsController}
		presence, commandReason := inspectReportsControllerArguments(append(append([]string{}, container.command[1:]...), container.args...))
		if commandReason != "" {
			reason = commandReason
			break
		}
		facts[2] = inputFact{ID: KyvernoFact, State: "declared", BoolValue: &presence}
		state = StatePrepared
		reason = ReasonDirectCommandParsed
	}
	canonical, err := marshalInput(from, to, facts)
	if err != nil {
		return Prepared{}, err
	}
	return Prepared{
		CanonicalInputJSON: canonical,
		SourceDigest:       digestBytes(raw),
		InputDigest:        digestBytes(canonical),
		State:              state,
		Reason:             reason,
		Omissions:          []string{OmissionNoLiveObservation, OmissionNoWholeUpgrade},
	}, nil
}

func supportedKyvernoPair(from, to string) bool {
	if from == FromVersion && to == ToVersion {
		return true
	}
	if to != "1.19.1" {
		return false
	}
	switch from {
	case "1.14.5", "1.15.3", "1.16.4", "1.17.2", "1.18.2":
		return true
	default:
		return false
	}
}

type selectionState uint8

const (
	selectionReady selectionState = iota
	selectionMissing
	selectionAmbiguous
)

type workloadContainer struct {
	name       string
	command    []string
	args       []string
	commandSet bool
	argsSet    bool
}

func selectContainer(root map[string]any, wanted string) (workloadContainer, selectionState, error) {
	apiVersion, err := requiredString(root, "apiVersion")
	if err != nil {
		return workloadContainer{}, selectionMissing, err
	}
	kind, err := requiredString(root, "kind")
	if err != nil {
		return workloadContainer{}, selectionMissing, err
	}
	if apiVersion != "v1" && apiVersion != "apps/v1" {
		return workloadContainer{}, selectionMissing, ErrInvalid
	}
	if kind != "Pod" && kind != "Deployment" {
		return workloadContainer{}, selectionMissing, ErrInvalid
	}
	if err := validateMetadata(root["metadata"]); err != nil && root["metadata"] != nil {
		return workloadContainer{}, selectionMissing, err
	}
	spec, ok := root["spec"].(map[string]any)
	if !ok {
		return workloadContainer{}, selectionMissing, ErrInvalid
	}
	var containers any
	var podSpec map[string]any
	if kind == "Pod" {
		if apiVersion != "v1" {
			return workloadContainer{}, selectionMissing, ErrInvalid
		}
		containers = spec["containers"]
		podSpec = spec
		if err := validatePodSpecFields(spec); err != nil {
			return workloadContainer{}, selectionMissing, err
		}
	} else {
		if apiVersion != "apps/v1" {
			return workloadContainer{}, selectionMissing, ErrInvalid
		}
		if err := validateDeploymentSpecFields(spec); err != nil {
			return workloadContainer{}, selectionMissing, err
		}
		template, ok := spec["template"].(map[string]any)
		if !ok {
			return workloadContainer{}, selectionMissing, ErrInvalid
		}
		if err := validateTemplateFields(template); err != nil {
			return workloadContainer{}, selectionMissing, err
		}
		templateSpec, ok := template["spec"].(map[string]any)
		if !ok {
			return workloadContainer{}, selectionMissing, ErrInvalid
		}
		if err := validatePodSpecFields(templateSpec); err != nil {
			return workloadContainer{}, selectionMissing, err
		}
		containers = templateSpec["containers"]
		podSpec = templateSpec
	}
	for _, key := range []string{"initContainers", "ephemeralContainers"} {
		value, exists := podSpec[key]
		if !exists {
			continue
		}
		names, err := containerNames(value)
		if err != nil {
			return workloadContainer{}, selectionMissing, err
		}
		for _, name := range names {
			if name == wanted {
				return workloadContainer{}, selectionAmbiguous, nil
			}
		}
	}
	list, ok := containers.([]any)
	if !ok {
		return workloadContainer{}, selectionMissing, ErrInvalid
	}
	var selected workloadContainer
	found := 0
	seenNames := map[string]bool{}
	for _, item := range list {
		parsed, err := parseContainer(item)
		if err != nil {
			return workloadContainer{}, selectionMissing, err
		}
		if seenNames[parsed.name] {
			if parsed.name == wanted {
				return workloadContainer{}, selectionAmbiguous, nil
			}
		}
		seenNames[parsed.name] = true
		if parsed.name == wanted {
			selected, found = parsed, found+1
		}
	}
	if found == 0 {
		return workloadContainer{}, selectionMissing, nil
	}
	if found != 1 {
		return workloadContainer{}, selectionAmbiguous, nil
	}
	return selected, selectionReady, nil
}

func inspectReportsControllerArguments(arguments []string) (bool, Reason) {
	if len(arguments) == 0 {
		return false, ""
	}
	for index := 0; index < len(arguments); index++ {
		argument := arguments[index]
		if hasExpansion(argument) || argument == "--" {
			if argument == "--" {
				return false, ReasonFlagAfterDelimiter
			}
			return false, ReasonUnsupportedArguments
		}
		name, value, attached, ok := reportsChunkSizeOption(argument)
		if !ok || name != "reportsChunkSize" {
			return false, ReasonUnsupportedArguments
		}
		if !attached {
			if index+1 >= len(arguments) || hasExpansion(arguments[index+1]) {
				return false, ReasonUnsupportedArguments
			}
			value = arguments[index+1]
			index++
		}
		if _, err := strconv.ParseInt(value, 0, 32); err != nil {
			return false, ReasonUnsupportedArguments
		}
	}
	return true, ""
}

// reportsChunkSizeOption recognizes only the one/two-dash spelling admitted
// by the reviewed standard-library grammar. It intentionally rejects every
// other option rather than trying to implement the controller's flag registry.
func reportsChunkSizeOption(argument string) (name, value string, attached, ok bool) {
	if hasExpansion(argument) || len(argument) < 2 || argument[0] != '-' {
		return "", "", false, false
	}
	trimmed := argument[1:]
	if strings.HasPrefix(trimmed, "-") {
		trimmed = trimmed[1:]
	}
	if trimmed == "" || strings.HasPrefix(trimmed, "-") || strings.HasPrefix(trimmed, "=") {
		return "", "", false, false
	}
	if equal := strings.IndexByte(trimmed, '='); equal >= 0 {
		return trimmed[:equal], trimmed[equal+1:], true, true
	}
	return trimmed, "", false, true
}

func marshalInput(from, to string, facts []inputFact) ([]byte, error) {
	return marshalComponentInput(KyvernoComponent, from, to, facts)
}

func marshalComponentInput(component, from, to string, facts []inputFact) ([]byte, error) {
	return marshalComponentInputBoth(component, from, to, nil, facts)
}

func marshalComponentInputBoth(component, from, to string, currentFacts, proposedFacts []inputFact) ([]byte, error) {
	if currentFacts == nil {
		currentFacts = []inputFact{}
	}
	if proposedFacts == nil {
		proposedFacts = []inputFact{}
	}
	input := inputEnvelope{
		Schema: InputSchema, Authority: InputAuthority,
		Current:  inputSide{Components: []inputComponent{{Component: component, Version: from, Facts: currentFacts}}},
		Proposed: inputSide{Components: []inputComponent{{Component: component, Version: to, Facts: proposedFacts}}},
	}
	compact, err := json.Marshal(input)
	if err != nil {
		return nil, err
	}
	return append(compact, '\n'), nil
}

type inputEnvelope struct {
	Schema    string    `json:"schema"`
	Authority string    `json:"authority"`
	Current   inputSide `json:"current"`
	Proposed  inputSide `json:"proposed"`
}
type inputSide struct {
	Components []inputComponent `json:"components"`
}
type inputComponent struct {
	Component string      `json:"component"`
	Version   string      `json:"version"`
	Facts     []inputFact `json:"facts"`
}
type inputFact struct {
	ID        string `json:"id"`
	State     string `json:"state"`
	BoolValue *bool  `json:"boolValue,omitempty"`
	EnumValue string `json:"enumValue,omitempty"`
	// SetValue is present only for a declared set fact; every other fact
	// marshals exactly as before set facts existed.
	SetValue *inputSetValue `json:"setValue,omitempty"`
}

// inputSetValue is a declared set: members in ascending byte order and
// whether the declaration is complete.
type inputSetValue struct {
	Members  []string `json:"members"`
	Complete bool     `json:"complete"`
}

func parseContainer(value any) (workloadContainer, error) {
	object, ok := value.(map[string]any)
	if !ok {
		return workloadContainer{}, ErrInvalid
	}
	if err := allowFields(object, map[string]bool{
		"name": true, "image": true, "command": true, "args": true, "env": true,
		"envFrom": true, "workingDir": true, "ports": true, "resources": true,
		"volumeMounts": true, "livenessProbe": true, "readinessProbe": true,
		"startupProbe": true, "securityContext": true, "lifecycle": true,
		"stdin": true, "stdinOnce": true, "tty": true, "terminationMessagePath": true,
		"terminationMessagePolicy": true, "imagePullPolicy": true,
	}); err != nil {
		return workloadContainer{}, err
	}
	name, err := requiredString(object, "name")
	if err != nil || name == "" {
		return workloadContainer{}, ErrInvalid
	}
	result := workloadContainer{name: name}
	if value, exists := object["command"]; exists {
		result.commandSet = true
		result.command, err = stringArray(value)
		if err != nil {
			return workloadContainer{}, err
		}
	}
	if value, exists := object["args"]; exists {
		result.argsSet = true
		result.args, err = stringArray(value)
		if err != nil {
			return workloadContainer{}, err
		}
	}
	if value, exists := object["env"]; exists {
		if _, err := objectArray(value); err != nil {
			return workloadContainer{}, err
		}
	}
	return result, nil
}

func validateTemplateFields(template map[string]any) error {
	if err := allowFields(template, map[string]bool{"metadata": true, "spec": true}); err != nil {
		return err
	}
	if metadata, exists := template["metadata"]; exists {
		if err := validateMetadata(metadata); err != nil {
			return err
		}
	}
	return nil
}

func validatePodSpecFields(spec map[string]any) error {
	allowed := map[string]bool{
		"containers": true, "initContainers": true, "ephemeralContainers": true,
		"restartPolicy": true, "serviceAccountName": true, "automountServiceAccountToken": true,
		"nodeSelector": true, "tolerations": true, "affinity": true, "volumes": true,
		"imagePullSecrets": true, "securityContext": true, "dnsPolicy": true,
		"hostNetwork": true, "hostPID": true, "hostIPC": true, "terminationGracePeriodSeconds": true,
		"activeDeadlineSeconds": true, "priorityClassName": true, "priority": true,
		"enableServiceLinks": true, "preemptionPolicy": true, "runtimeClassName": true,
		"setHostnameAsFQDN": true, "hostAliases": true, "shareProcessNamespace": true,
		"hostname": true, "subdomain": true, "schedulerName": true, "readinessGates": true,
		"overhead": true, "topologySpreadConstraints": true, "os": true,
		"schedulingGates": true, "resourceClaims": true,
	}
	return allowFields(spec, allowed)
}

func validateMetadata(value any) error {
	if value == nil {
		return ErrInvalid
	}
	object, ok := value.(map[string]any)
	if !ok {
		return ErrInvalid
	}
	if err := allowFields(object, map[string]bool{
		"name": true, "generateName": true, "namespace": true, "labels": true, "annotations": true,
	}); err != nil {
		return err
	}
	for _, key := range []string{"name", "generateName", "namespace"} {
		if value, exists := object[key]; exists {
			if _, ok := value.(string); !ok {
				return ErrInvalid
			}
		}
	}
	for _, key := range []string{"labels", "annotations"} {
		if value, exists := object[key]; exists {
			mapValue, ok := value.(map[string]any)
			if !ok {
				return ErrInvalid
			}
			for _, item := range mapValue {
				if _, ok := item.(string); !ok {
					return ErrInvalid
				}
			}
		}
	}
	return nil
}

func allowFields(object map[string]any, allowed map[string]bool) error {
	for key := range object {
		if !allowed[key] {
			return ErrInvalid
		}
	}
	return nil
}

func validateDeploymentSpecFields(spec map[string]any) error {
	return allowFields(spec, map[string]bool{
		"replicas": true, "selector": true, "template": true, "strategy": true,
		"minReadySeconds": true, "revisionHistoryLimit": true, "paused": true,
		"progressDeadlineSeconds": true,
	})
}

func containerNames(value any) ([]string, error) {
	items, ok := value.([]any)
	if !ok || len(items) > maxArrayItems {
		return nil, ErrInvalid
	}
	names := make([]string, len(items))
	for index, item := range items {
		object, ok := item.(map[string]any)
		if !ok {
			return nil, ErrInvalid
		}
		name, err := requiredString(object, "name")
		if err != nil || name == "" {
			return nil, ErrInvalid
		}
		names[index] = name
	}
	return names, nil
}

func requiredString(object map[string]any, key string) (string, error) {
	value, exists := object[key]
	if !exists {
		return "", ErrInvalid
	}
	result, ok := value.(string)
	if !ok {
		return "", ErrInvalid
	}
	return result, nil
}

func stringArray(value any) ([]string, error) {
	items, ok := value.([]any)
	if !ok || len(items) > maxArrayItems {
		return nil, ErrInvalid
	}
	result := make([]string, len(items))
	for index, item := range items {
		stringValue, ok := item.(string)
		if !ok {
			return nil, ErrInvalid
		}
		result[index] = stringValue
	}
	return result, nil
}

func objectArray(value any) ([]map[string]any, error) {
	items, ok := value.([]any)
	if !ok || len(items) > maxArrayItems {
		return nil, ErrInvalid
	}
	result := make([]map[string]any, len(items))
	for index, item := range items {
		object, ok := item.(map[string]any)
		if !ok {
			return nil, ErrInvalid
		}
		result[index] = object
	}
	return result, nil
}

func hasExpansion(value string) bool {
	return strings.ContainsAny(value, "$\\\n\r\t")
}

func validVersionSyntax(value string) bool {
	// Numeric major.minor.patch, no prefix or suffix, with the same uint32
	// segment bound used by the constraint engine.
	parts := strings.Split(value, ".")
	if len(parts) != 3 {
		return false
	}
	for _, part := range parts {
		if part == "" || (len(part) > 1 && part[0] == '0') {
			return false
		}
		if _, err := strconv.ParseUint(part, 10, 32); err != nil {
			return false
		}
	}
	return true
}

func digestBytes(raw []byte) string {
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func decodeStrict(raw []byte) (any, error) {
	return decodeStrictWithNull(raw, false)
}

// decodeStrictAllowNull is reserved for adapters whose closed contract gives
// JSON null an explicit UNKNOWN meaning at selected paths. Existing adapters
// retain decodeStrict's rejecting behavior.
func decodeStrictAllowNull(raw []byte) (any, error) {
	return decodeStrictWithNull(raw, true)
}

func decodeStrictWithNull(raw []byte, allowNull bool) (any, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	value, err := decodeValueWithNull(decoder, 0, allowNull)
	if err != nil {
		return nil, ErrInvalid
	}
	if token, err := decoder.Token(); err != io.EOF || token != nil {
		return nil, ErrInvalid
	}
	return value, nil
}

func decodeValue(decoder *json.Decoder, depth int) (any, error) {
	return decodeValueWithNull(decoder, depth, false)
}

func decodeValueWithNull(decoder *json.Decoder, depth int, allowNull bool) (any, error) {
	if depth > maxJSONDepth {
		return nil, ErrInvalid
	}
	token, err := decoder.Token()
	if err != nil {
		return nil, err
	}
	switch delimiter := token.(type) {
	case json.Delim:
		switch delimiter {
		case '{':
			object := make(map[string]any)
			keys := make(map[string]bool)
			members := 0
			for decoder.More() {
				keyToken, err := decoder.Token()
				if err != nil {
					return nil, err
				}
				key, ok := keyToken.(string)
				if !ok || key == "" {
					return nil, ErrInvalid
				}
				folded := strings.ToLower(key)
				if keys[folded] {
					return nil, ErrInvalid
				}
				keys[folded] = true
				members++
				if members > maxObjectMembers {
					return nil, ErrInvalid
				}
				value, err := decodeValueWithNull(decoder, depth+1, allowNull)
				if err != nil {
					return nil, err
				}
				object[key] = value
			}
			if _, err := decoder.Token(); err != nil {
				return nil, err
			}
			return object, nil
		case '[':
			array := make([]any, 0)
			for decoder.More() {
				if len(array) >= maxArrayItems {
					return nil, ErrInvalid
				}
				value, err := decodeValueWithNull(decoder, depth+1, allowNull)
				if err != nil {
					return nil, err
				}
				array = append(array, value)
			}
			if _, err := decoder.Token(); err != nil {
				return nil, err
			}
			return array, nil
		default:
			return nil, ErrInvalid
		}
	case nil:
		if allowNull {
			return nil, nil
		}
		return nil, ErrInvalid
	default:
		return token, nil
	}
}
