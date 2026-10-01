// SPDX-License-Identifier: AGPL-3.0-only

package prometheusmode

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"reflect"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/prufyx/prufyx/cli/internal/currentbundle"
	"github.com/prufyx/prufyx/cli/internal/validation"
)

const (
	maxJSONDepth       = 32
	maxJSONMembers     = 1024
	maxJSONArrayItems  = 512
	maxJSONStringBytes = 4096
	maxContainers      = 128
	maxCommandTokens   = 8
	maxCommandToken    = 128
	maxArgumentTokens  = 256
	maxArgumentToken   = 512
	maxArgumentBytes   = 16 << 10
)

var imageRE = regexp.MustCompile(`^(?:(docker\.io)/)?prom/prometheus(?::v([0-9]+\.[0-9]+\.[0-9]+))?(?:@(sha256:[0-9a-f]{64}))?$`)

type ProposedProjection struct {
	Schema              string `json:"schema"`
	ComponentID         string `json:"componentId"`
	Version             string `json:"version"`
	WorkloadKind        string `json:"workloadKind"`
	Role                string `json:"role"`
	EvidenceClass       string `json:"evidenceClass"`
	ImageIdentityState  string `json:"imageIdentityState"`
	ImageManifestDigest string `json:"imageManifestDigest,omitempty"`
	EntrypointState     string `json:"entrypointState"`
	ArgumentsState      string `json:"argumentsState"`
	AgentModeState      string `json:"agentModeState"`
	AgentMode           *bool  `json:"agentMode,omitempty"`
	Origin              string `json:"origin"`
}

type VerifiedProposedArtifact struct {
	bundle           validation.VerifiedProposedBundle
	hasGenericBundle bool
	projection       ProposedProjection
	projectionDigest string
	bundleDigest     string
	seal             *proposedSeal
}

type proposedSeal struct{}

type workloadDocument struct {
	APIVersion string       `json:"apiVersion"`
	Kind       string       `json:"kind"`
	Spec       workloadSpec `json:"spec"`
}

type workloadSpec struct {
	Template podTemplate `json:"template"`
}

type podTemplate struct {
	Spec podSpec `json:"spec"`
}

type podSpec struct {
	Containers     []container `json:"containers"`
	InitContainers []container `json:"initContainers,omitempty"`
}

type container struct {
	Image          string   `json:"image"`
	Command        []string `json:"command,omitempty"`
	Args           []string `json:"args,omitempty"`
	commandPresent bool
	commandNull    bool
	argsPresent    bool
	argsNull       bool
}

func (c *container) UnmarshalJSON(raw []byte) error {
	type wireContainer struct {
		Image   string   `json:"image"`
		Command []string `json:"command"`
		Args    []string `json:"args"`
	}
	var wire wireContainer
	if err := json.Unmarshal(raw, &wire); err != nil {
		return err
	}
	var members map[string]json.RawMessage
	if err := json.Unmarshal(raw, &members); err != nil {
		return err
	}
	*c = container{Image: wire.Image, Command: wire.Command, Args: wire.Args}
	if value, ok := members["command"]; ok {
		c.commandPresent = true
		c.commandNull = bytes.Equal(bytes.TrimSpace(value), []byte("null"))
	}
	if value, ok := members["args"]; ok {
		c.argsPresent = true
		c.argsNull = bytes.Equal(bytes.TrimSpace(value), []byte("null"))
	}
	return nil
}

// ReadProposedArtifact reads one private local workload document through a
// descriptor-rooted, no-follow boundary. expectedRawSHA256 is used only for
// local admission and is deliberately absent from every public projection.
func ReadProposedArtifact(path, expectedRawSHA256 string) (VerifiedProposedArtifact, error) {
	raw, info, err := currentbundle.ReadBoundedFileInfo(path, maxProposedArtifactSize)
	if err != nil {
		return VerifiedProposedArtifact{}, classifyProposedReadError(err)
	}
	if info == nil || !privateReadableFile(info) {
		return VerifiedProposedArtifact{}, fmt.Errorf("proposed artifact file mode: %w", ErrInvalid)
	}
	return ParseProposedArtifact(raw, expectedRawSHA256)
}

func classifyProposedReadError(err error) error {
	if errors.Is(err, currentbundle.ErrIntegrity) {
		return fmt.Errorf("read proposed artifact: %w", ErrIntegrity)
	}
	return fmt.Errorf("read proposed artifact: %w", ErrIO)
}

// ParseProposedArtifact validates already-retained bytes. It never preserves
// arbitrary manifest fields, raw arguments, workload names, paths, or the raw
// input digest in the public report capability.
func ParseProposedArtifact(raw []byte, expectedRawSHA256 string) (VerifiedProposedArtifact, error) {
	pin := expectedRawSHA256
	if len(pin) == 64 {
		pin = "sha256:" + pin
	}
	if len(raw) == 0 || len(raw) > maxProposedArtifactSize || !utf8.Valid(raw) || !digestRE.MatchString(pin) || digestBytes(raw) != pin {
		return VerifiedProposedArtifact{}, fmt.Errorf("proposed artifact bytes: %w", ErrIntegrity)
	}
	if err := validateJSONShape(raw); err != nil {
		return VerifiedProposedArtifact{}, fmt.Errorf("proposed artifact JSON: %w", ErrInvalid)
	}
	if err := validateInterpretedFieldCasing(raw); err != nil {
		return VerifiedProposedArtifact{}, fmt.Errorf("proposed artifact field casing: %w", ErrInvalid)
	}
	var workload workloadDocument
	decoder := json.NewDecoder(bytes.NewReader(raw))
	if err := decoder.Decode(&workload); err != nil {
		return VerifiedProposedArtifact{}, fmt.Errorf("proposed artifact schema: %w", ErrInvalid)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return VerifiedProposedArtifact{}, fmt.Errorf("proposed artifact trailing data: %w", ErrInvalid)
	}
	projection, err := projectWorkload(workload)
	if err != nil {
		return VerifiedProposedArtifact{}, err
	}
	canonical, err := json.Marshal(projection)
	if err != nil {
		return VerifiedProposedArtifact{}, fmt.Errorf("proposed projection: %w", ErrInvalid)
	}
	proposal, hasGeneric, bundleDigest, err := minimizedProposedBundle(projection)
	if err != nil {
		return VerifiedProposedArtifact{}, err
	}
	return VerifiedProposedArtifact{
		bundle: proposal, hasGenericBundle: hasGeneric, projection: cloneProjection(projection), projectionDigest: digestBytes(canonical), bundleDigest: bundleDigest,
		seal: &proposedSeal{},
	}, nil
}

func (v VerifiedProposedArtifact) Valid() bool {
	if v.seal == nil || !digestRE.MatchString(v.bundleDigest) || (v.hasGenericBundle && !v.bundle.Valid()) || (!v.hasGenericBundle && v.projection.Version != "") {
		return false
	}
	canonical, err := json.Marshal(v.projection)
	if err != nil || digestBytes(canonical) != v.projectionDigest || !validProjection(v.projection) {
		return false
	}
	minimized, err := json.Marshal(minimizedDocument(v.projection))
	return err == nil && digestBytes(minimized) == v.bundleDigest
}

func privateReadableFile(info os.FileInfo) bool {
	mode := info.Mode().Perm()
	return info.Mode().IsRegular() && mode&0o400 != 0 && mode&0o077 == 0 && singleLink(info)
}

func singleLink(info os.FileInfo) bool {
	value := reflect.ValueOf(info.Sys())
	if value.IsValid() && value.Kind() == reflect.Ptr {
		value = value.Elem()
	}
	if !value.IsValid() || value.Kind() != reflect.Struct {
		return false
	}
	field := value.FieldByName("Nlink")
	return field.IsValid() && field.CanUint() && field.Uint() == 1
}

func projectWorkload(workload workloadDocument) (ProposedProjection, error) {
	if workload.APIVersion != "apps/v1" || (workload.Kind != "Deployment" && workload.Kind != "StatefulSet") || len(workload.Spec.Template.Spec.Containers) > maxContainers || len(workload.Spec.Template.Spec.InitContainers) > maxContainers {
		return ProposedProjection{}, fmt.Errorf("proposed workload envelope: %w", ErrInvalid)
	}
	matching := make([]container, 0, 2)
	matchingVersions := make([]string, 0, 3)
	for _, candidate := range workload.Spec.Template.Spec.Containers {
		if recognizedPublicPrometheusImage(candidate.Image) {
			matching = append(matching, candidate)
			_, version, _, _ := parsePrometheusImage(candidate.Image)
			matchingVersions = append(matchingVersions, version)
		}
	}
	matchingInit := false
	for _, candidate := range workload.Spec.Template.Spec.InitContainers {
		if recognizedPublicPrometheusImage(candidate.Image) {
			matchingInit = true
			_, version, _, _ := parsePrometheusImage(candidate.Image)
			matchingVersions = append(matchingVersions, version)
		}
	}
	if len(matching) == 0 {
		return ProposedProjection{Schema: "prometheus-mode-proposed-projection/v1", WorkloadKind: workload.Kind, ImageIdentityState: "unsupported_or_absent_component_identity", EntrypointState: "unknown", ArgumentsState: "unknown", AgentModeState: "unknown", Origin: "prometheus_component_unresolved"}, nil
	}
	if len(matching) != 1 || matchingInit {
		return unknownProjection(workload.Kind, commonExactVersion(matchingVersions), "ambiguous_container_role", "unknown_entrypoint", "unknown", "unknown_role"), nil
	}
	candidate := matching[0]
	_, version, imageDigest, admittedImage := parsePrometheusImage(candidate.Image)
	projection := ProposedProjection{
		Schema: "prometheus-mode-proposed-projection/v1", ComponentID: ComponentID, Version: version,
		WorkloadKind: workload.Kind, Role: "server", EvidenceClass: proposedEvidenceClass,
		ImageIdentityState: "unsupported", EntrypointState: "unknown", ArgumentsState: "unknown",
		AgentModeState: "unknown", Origin: "unreviewed_image_identity",
	}
	if !admittedImage || version != ProposedVersion || imageDigest != ProposedImageDigest {
		return projection, nil
	}
	projection.ImageIdentityState = "exact_reviewed_platform_manifest"
	projection.ImageManifestDigest = imageDigest
	if !candidate.commandPresent {
		projection.EntrypointState = "reviewed_image_default"
	} else if !candidate.commandNull && validTokens(candidate.Command, maxCommandTokens, maxCommandToken, maxCommandToken) && len(candidate.Command) == 1 && candidate.Command[0] == "/bin/prometheus" {
		projection.EntrypointState = "explicit_exact"
	} else {
		projection.Origin = "unknown_entrypoint"
		return projection, nil
	}
	if !candidate.argsPresent {
		projection.ArgumentsState = "reviewed_image_default"
		projection.AgentModeState = "observed"
		projection.AgentMode = boolPointer(false)
		projection.Origin = "reviewed_image_default"
		return projection, nil
	}
	if candidate.argsNull || !validTokens(candidate.Args, maxArgumentTokens, maxArgumentToken, maxArgumentBytes) {
		projection.ArgumentsState = "unknown"
		projection.Origin = "arguments_outside_bounds"
		return projection, nil
	}
	projection.ArgumentsState = "explicit_complete"
	mode, origin, state := parseV3AgentMode(candidate.Args)
	projection.AgentModeState = state
	projection.Origin = origin
	if state == "observed" {
		projection.AgentMode = boolPointer(mode)
	}
	return projection, nil
}

// Public Prometheus repository references participate in role ambiguity even
// when their tag, host spelling, or digest is outside the strict evidence
// contract. Otherwise an unadmitted second Prometheus container could be
// ignored while a supported sibling incorrectly grants a mode fact.
func recognizedPublicPrometheusImage(image string) bool {
	for _, repository := range []string{"prom/prometheus", "docker.io/prom/prometheus", "index.docker.io/prom/prometheus"} {
		if image == repository || strings.HasPrefix(image, repository+":") || strings.HasPrefix(image, repository+"@") {
			return true
		}
	}
	return false
}

func unknownProjection(kind, version, imageState, entrypointState, argumentsState, origin string) ProposedProjection {
	return ProposedProjection{Schema: "prometheus-mode-proposed-projection/v1", ComponentID: ComponentID, Version: version, WorkloadKind: kind, Role: "server", EvidenceClass: proposedEvidenceClass, ImageIdentityState: imageState, EntrypointState: entrypointState, ArgumentsState: argumentsState, AgentModeState: "unknown", Origin: origin}
}

func parsePrometheusImage(image string) (repository, version, digest string, ok bool) {
	if len(image) == 0 || len(image) > 512 || strings.ContainsAny(image, "\x00\r\n") {
		return "", "", "", false
	}
	matches := imageRE.FindStringSubmatch(image)
	if len(matches) != 4 || (matches[2] == "" && matches[3] == "") {
		return "", "", "", false
	}
	return "docker.io/prom/prometheus", matches[2], matches[3], true
}

func validTokens(tokens []string, maxItems, maxItemBytes, maxTotalBytes int) bool {
	if len(tokens) > maxItems {
		return false
	}
	total := 0
	for _, token := range tokens {
		total += len(token)
		if len(token) == 0 || len(token) > maxItemBytes || strings.ContainsAny(token, "\x00\r\n") || total > maxTotalBytes {
			return false
		}
	}
	return true
}

func parseV3AgentMode(args []string) (bool, string, string) {
	for index, token := range args {
		if strings.Contains(token, "$(") {
			return false, "unresolved_argument_interpolation", "unknown"
		}
		if token == "--" {
			return false, "unsupported_option_terminator", "unknown"
		}
		if token == "--agent" && index > 0 {
			previous := args[index-1]
			if strings.HasPrefix(previous, "--") && !strings.Contains(previous, "=") && previous != "--agent" && previous != "--no-agent" && previous != "--enable-feature" {
				return false, "ambiguous_preceding_flag_arity", "unknown"
			}
		}
		if !strings.HasPrefix(token, "--") {
			if index == 0 {
				return false, "unsupported_positional_argument", "unknown"
			}
			previous := args[index-1]
			if previous == "--agent" || previous == "--no-agent" {
				return false, "unsupported_boolean_form", "unknown"
			}
			if !strings.HasPrefix(previous, "--") || strings.Contains(previous, "=") {
				return false, "unsupported_positional_argument", "unknown"
			}
		}
	}
	dedicated := ""
	legacyAgent := false
	for index := 0; index < len(args); index++ {
		token := args[index]
		switch {
		case token == "--agent":
			if index+1 < len(args) && !strings.HasPrefix(args[index+1], "--") {
				return false, "unsupported_boolean_form", "unknown"
			}
			if dedicated != "" {
				return false, "duplicate_dedicated_boolean", "unknown"
			}
			dedicated = token
		case token == "--no-agent" || strings.HasPrefix(token, "--agent=") || strings.HasPrefix(token, "--no-agent="):
			return false, "unsupported_boolean_form", "unknown"
		case token == "--enable-feature":
			if index+1 >= len(args) || strings.HasPrefix(args[index+1], "--") {
				return false, "malformed_enable_feature", "unknown"
			}
			index++
			legacyAgent = legacyAgent || featureListContainsAgent(args[index])
		case strings.HasPrefix(token, "--enable-feature="):
			legacyAgent = legacyAgent || featureListContainsAgent(strings.TrimPrefix(token, "--enable-feature="))
		}
	}
	if dedicated == "--agent" {
		return true, "dedicated_agent_flag", "observed"
	}
	if legacyAgent {
		return false, "legacy_feature_ignored", "observed"
	}
	return false, "explicit_arguments_without_agent", "observed"
}

func featureListContainsAgent(value string) bool {
	for _, feature := range strings.Split(value, ",") {
		if feature == "agent" {
			return true
		}
	}
	return false
}

type minimizedProposedDocument struct {
	Schema     string             `json:"schema"`
	Policy     PolicyBinding      `json:"policy"`
	Projection ProposedProjection `json:"projection"`
}

func minimizedDocument(projection ProposedProjection) minimizedProposedDocument {
	return minimizedProposedDocument{Schema: "prometheus-mode-proposed-bundle/v1", Policy: PolicyBinding{PolicyID: policyID, Revision: policyRevision, Digest: SourceContractDigest}, Projection: cloneProjection(projection)}
}

func minimizedProposedBundle(projection ProposedProjection) (validation.VerifiedProposedBundle, bool, string, error) {
	minimizedRaw, err := json.Marshal(minimizedDocument(projection))
	if err != nil {
		return validation.VerifiedProposedBundle{}, false, "", fmt.Errorf("encode minimized proposed projection: %w", ErrInvalid)
	}
	minimizedDigest := digestBytes(minimizedRaw)
	if projection.Version == "" {
		return validation.VerifiedProposedBundle{}, false, minimizedDigest, nil
	}
	configuration := map[string]json.RawMessage{}
	if projection.AgentModeState == "observed" && projection.AgentMode != nil {
		value, _ := json.Marshal(*projection.AgentMode)
		configuration[AgentModePredicateID] = value
	}
	if projection.ImageIdentityState == "exact_reviewed_platform_manifest" {
		value, _ := json.Marshal(projection.ImageManifestDigest)
		configuration[ImageDigestPredicateID] = value
	}
	bundle := validation.ProposedBundle{
		APIVersion: validation.APIVersion, Kind: validation.ProposedBundleKind, SchemaVersion: validation.SchemaVersion,
		BundleID:   "prometheus-mode-proposed-v1",
		PolicyRef:  validation.PolicyReference{APIVersion: validation.APIVersion, Kind: validation.PolicyReferenceKind, SchemaVersion: validation.SchemaVersion, PolicyID: policyID, Revision: policyRevision, Digest: SourceContractDigest},
		Components: []validation.ProposedTarget{{Component: ComponentID, Version: projection.Version, Profile: "prometheus-agent-mode-v1", Configuration: configuration}},
	}
	raw, err := json.Marshal(bundle)
	if err != nil {
		return validation.VerifiedProposedBundle{}, false, "", fmt.Errorf("encode minimized proposed bundle: %w", ErrInvalid)
	}
	verified, err := validation.ParseVerifiedProposedBundle(raw)
	if err != nil {
		return validation.VerifiedProposedBundle{}, false, "", fmt.Errorf("validate minimized proposed bundle: %w", ErrIntegrity)
	}
	return verified, true, minimizedDigest, nil
}

func validProjection(projection ProposedProjection) bool {
	if projection.Schema != "prometheus-mode-proposed-projection/v1" || (projection.WorkloadKind != "Deployment" && projection.WorkloadKind != "StatefulSet") {
		return false
	}
	if projection.ComponentID == "" {
		return projection.Version == "" && projection.Role == "" && projection.EvidenceClass == "" && projection.AgentModeState == "unknown" && projection.AgentMode == nil
	}
	if projection.ComponentID != ComponentID || projection.Role != "server" || projection.EvidenceClass != proposedEvidenceClass {
		return false
	}
	if projection.AgentModeState == "observed" {
		return projection.AgentMode != nil && projection.ImageIdentityState == "exact_reviewed_platform_manifest" && projection.ImageManifestDigest == ProposedImageDigest
	}
	return projection.AgentModeState == "unknown" && projection.AgentMode == nil
}

func cloneProjection(in ProposedProjection) ProposedProjection {
	out := in
	if in.AgentMode != nil {
		out.AgentMode = boolPointer(*in.AgentMode)
	}
	return out
}

func boolPointer(value bool) *bool { return &value }

func commonExactVersion(versions []string) string {
	if len(versions) == 0 || versions[0] == "" {
		return ""
	}
	for _, version := range versions[1:] {
		if version != versions[0] {
			return ""
		}
	}
	return versions[0]
}

func validateJSONShape(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := consumeJSONValue(decoder, 0); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return ErrInvalid
	}
	return nil
}

// encoding/json matches struct field names case-insensitively. Kubernetes JSON
// field names are exact, so reject aliases for every field this projection
// interprets before decoding into structs. Unrelated fields remain ignored.
func validateInterpretedFieldCasing(raw []byte) error {
	var root map[string]json.RawMessage
	if json.Unmarshal(raw, &root) != nil || rejectFoldedAliases(root, "apiVersion", "kind", "spec") != nil {
		return ErrInvalid
	}
	spec, ok := exactObjectMember(root, "spec")
	if !ok {
		return nil
	}
	if rejectFoldedAliases(spec, "template") != nil {
		return ErrInvalid
	}
	template, ok := exactObjectMember(spec, "template")
	if !ok {
		return nil
	}
	if rejectFoldedAliases(template, "spec") != nil {
		return ErrInvalid
	}
	pod, ok := exactObjectMember(template, "spec")
	if !ok {
		return nil
	}
	if rejectFoldedAliases(pod, "containers", "initContainers") != nil {
		return ErrInvalid
	}
	for _, name := range []string{"containers", "initContainers"} {
		member, exists := pod[name]
		if !exists {
			continue
		}
		var containers []json.RawMessage
		if json.Unmarshal(member, &containers) != nil {
			return ErrInvalid
		}
		for _, rawContainer := range containers {
			var object map[string]json.RawMessage
			if json.Unmarshal(rawContainer, &object) != nil || rejectFoldedAliases(object, "image", "command", "args") != nil {
				return ErrInvalid
			}
		}
	}
	return nil
}

func exactObjectMember(parent map[string]json.RawMessage, name string) (map[string]json.RawMessage, bool) {
	raw, ok := parent[name]
	if !ok {
		return nil, false
	}
	var object map[string]json.RawMessage
	if json.Unmarshal(raw, &object) != nil {
		return nil, false
	}
	return object, true
}

func rejectFoldedAliases(object map[string]json.RawMessage, exactNames ...string) error {
	for name := range object {
		for _, exact := range exactNames {
			if name != exact && strings.EqualFold(name, exact) {
				return ErrInvalid
			}
		}
	}
	return nil
}

func consumeJSONValue(decoder *json.Decoder, depth int) error {
	if depth > maxJSONDepth {
		return ErrInvalid
	}
	token, err := decoder.Token()
	if err != nil {
		return ErrInvalid
	}
	switch value := token.(type) {
	case json.Delim:
		switch value {
		case '{':
			seen := map[string]struct{}{}
			count := 0
			for decoder.More() {
				keyToken, keyErr := decoder.Token()
				key, ok := keyToken.(string)
				if keyErr != nil || !ok || len(key) == 0 || len(key) > maxJSONStringBytes {
					return ErrInvalid
				}
				if _, duplicate := seen[key]; duplicate {
					return ErrInvalid
				}
				seen[key] = struct{}{}
				count++
				if count > maxJSONMembers || consumeJSONValue(decoder, depth+1) != nil {
					return ErrInvalid
				}
			}
		case '[':
			count := 0
			for decoder.More() {
				count++
				if count > maxJSONArrayItems || consumeJSONValue(decoder, depth+1) != nil {
					return ErrInvalid
				}
			}
		default:
			return ErrInvalid
		}
		if _, err := decoder.Token(); err != nil {
			return ErrInvalid
		}
	case string:
		if len(value) > maxJSONStringBytes || strings.ContainsAny(value, "\x00\r\n") {
			return ErrInvalid
		}
	}
	return nil
}
