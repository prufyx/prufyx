// SPDX-License-Identifier: AGPL-3.0-only

package cncfprepare

import (
	"encoding/json"
	"regexp"
	"unicode/utf8"
)

var formatDigestRE = regexp.MustCompile(`^[a-z0-9]+(?:[+._-][a-z0-9]+)*:[0-9a-f]{32,}$`)

const (
	DistributionComponent  = "pkg:github/distribution/distribution"
	DistributionFormatFact = "component.distribution.image_manifest_format"
	DistributionFrom       = "2.8.3"
	DistributionTo         = "3.0.0"

	DistributionFormatSchema1 = "docker_schema1"
	DistributionFormatSchema2 = "docker_schema2"
	DistributionFormatOCI     = "oci_image_manifest"

	CNISpecComponent          = "pkg:generic/cni-configuration-spec"
	CNISpecShapeFact          = "component.cni_spec.configuration_shape"
	CNISpecVersionFact        = "component.cni_spec.inspected_spec_version"
	CNISpecMigrationFact      = "component.cni_spec.configuration_spec_migration_planned"
	CNISpecMigrationOperation = "configuration-spec-migration"
	CNISpecFrom               = "0.4.0"
	CNISpecTo                 = "1.0.0"

	CNISpecShapeSingle = "single_plugin"
	CNISpecShapeList   = "plugin_list"
)

const (
	ReasonDistributionFormatObserved      Reason = "DISTRIBUTION_MANIFEST_FORMAT_OBSERVED"
	ReasonDistributionFormatUnsupported   Reason = "DISTRIBUTION_MANIFEST_FORMAT_UNSUPPORTED"
	ReasonCNISpecConfigurationObserved    Reason = "CNI_SPEC_CONFIGURATION_SHAPE_OBSERVED"
	ReasonCNISpecConfigurationUnsupported Reason = "CNI_SPEC_CONFIGURATION_SHAPE_UNSUPPORTED"
)

// PrepareDistributionManifest classifies only the format of one caller-supplied
// image manifest JSON document. It does not contact a registry, resolve an image,
// validate referenced content, or establish that a manifest can be stored or run.
func PrepareDistributionManifest(raw []byte, from, to string) (Prepared, error) {
	if len(raw) == 0 || len(raw) > maxInputBytes || !utf8.Valid(raw) || !validVersionSyntax(from) || !validVersionSyntax(to) || from == to {
		return Prepared{}, ErrInvalid
	}
	value, err := decodeStrictAllowNull(raw)
	if err != nil {
		return Prepared{}, ErrInvalid
	}
	fact := inputFact{ID: DistributionFormatFact, State: "unsupported"}
	state, reason := StateUnknown, ReasonDistributionFormatUnsupported
	if format, ok := distributionManifestFormat(value); ok {
		fact = inputFact{ID: DistributionFormatFact, State: "declared", EnumValue: format}
		state, reason = StatePrepared, ReasonDistributionFormatObserved
	}
	canonical, err := marshalComponentInput(DistributionComponent, from, to, []inputFact{fact})
	if err != nil {
		return Prepared{}, ErrInvalid
	}
	return Prepared{CanonicalInputJSON: canonical, SourceDigest: digestBytes(raw), InputDigest: digestBytes(canonical), State: state, Reason: reason, Omissions: []string{
		"MANIFEST_IS_CALLER_SUPPLIED_NOT_REGISTRY_OBSERVED",
		"MANIFEST_SIGNATURE_CONTENT_REFERENCES_AND_STORAGE_NOT_VALIDATED",
		"IMAGE_PULL_PLATFORM_AND_RUNTIME_NOT_EVALUATED",
		OmissionNoLiveObservation,
		OmissionNoWholeUpgrade,
	}}, nil
}

func distributionManifestFormat(value any) (string, bool) {
	root, ok := value.(map[string]any)
	if !ok {
		return "", false
	}
	version, ok := root["schemaVersion"].(json.Number)
	if !ok {
		return "", false
	}
	switch version.String() {
	case "1":
		if distributionSchema1KeysUnambiguous(root) && formatNonemptyString(root["name"]) && formatNonemptyString(root["tag"]) && formatNonemptyString(root["architecture"]) && schema1Layers(root["fsLayers"]) && schema1History(root["history"]) {
			return DistributionFormatSchema1, true
		}
	case "2":
		mediaType, ok := root["mediaType"].(string)
		if !ok || distributionSchema2HasLegacyKeys(root) || !manifestDescriptor(root["config"]) || !manifestLayers(root["layers"]) {
			return "", false
		}
		switch mediaType {
		case "application/vnd.docker.distribution.manifest.v2+json":
			return DistributionFormatSchema2, true
		case "application/vnd.oci.image.manifest.v1+json":
			return DistributionFormatOCI, true
		}
	}
	return "", false
}

func distributionSchema1KeysUnambiguous(root map[string]any) bool {
	for _, key := range []string{"config", "layers", "manifests"} {
		if _, exists := root[key]; exists {
			return false
		}
	}
	if value, exists := root["mediaType"]; exists {
		mediaType, ok := value.(string)
		if !ok || (mediaType != "application/vnd.docker.distribution.manifest.v1+json" && mediaType != "application/vnd.docker.distribution.manifest.v1+prettyjws" && mediaType != "application/json") {
			return false
		}
	}
	return true
}

func distributionSchema2HasLegacyKeys(root map[string]any) bool {
	for _, key := range []string{"name", "tag", "architecture", "fsLayers", "history", "signatures"} {
		if _, exists := root[key]; exists {
			return true
		}
	}
	return false
}

func schema1Layers(value any) bool {
	items, ok := value.([]any)
	if !ok {
		return false
	}
	for _, item := range items {
		object, ok := item.(map[string]any)
		digest, digestOK := object["blobSum"].(string)
		if !ok || !digestOK || !formatDigestRE.MatchString(digest) {
			return false
		}
	}
	return true
}

func schema1History(value any) bool {
	items, ok := value.([]any)
	if !ok {
		return false
	}
	for _, item := range items {
		object, ok := item.(map[string]any)
		if !ok || !formatNonemptyString(object["v1Compatibility"]) {
			return false
		}
	}
	return true
}

func manifestDescriptor(value any) bool {
	object, ok := value.(map[string]any)
	digest, digestOK := object["digest"].(string)
	if !ok || !formatNonemptyString(object["mediaType"]) || !digestOK || !formatDigestRE.MatchString(digest) {
		return false
	}
	size, ok := object["size"].(json.Number)
	return ok && nonnegativeJSONInteger(size)
}

func manifestLayers(value any) bool {
	items, ok := value.([]any)
	if !ok {
		return false
	}
	for _, item := range items {
		if !manifestDescriptor(item) {
			return false
		}
	}
	return true
}

func nonnegativeJSONInteger(number json.Number) bool {
	value, err := number.Int64()
	return err == nil && value >= 0
}

// PrepareCNISpecConfiguration inspects one proposed CNI configuration for the
// exact spec 0.4.0 to 1.0.0 migration. The component identity and versions are
// specification identity, not containernetworking/cni library or plugin versions.
func PrepareCNISpecConfiguration(raw []byte, from, to, operation string) (Prepared, error) {
	if len(raw) == 0 || len(raw) > maxInputBytes || !utf8.Valid(raw) || !validVersionSyntax(from) || !validVersionSyntax(to) || from == to {
		return Prepared{}, ErrInvalid
	}
	value, err := decodeStrictAllowNull(raw)
	if err != nil {
		return Prepared{}, ErrInvalid
	}
	shape := inputFact{ID: CNISpecShapeFact, State: "unsupported"}
	version := inputFact{ID: CNISpecVersionFact, State: "unsupported"}
	planned := inputFact{ID: CNISpecMigrationFact, State: "unsupported"}
	if operation == CNISpecMigrationOperation {
		declared := true
		planned = inputFact{ID: CNISpecMigrationFact, State: "declared", BoolValue: &declared}
	}
	state, reason := StateUnknown, ReasonCNISpecConfigurationUnsupported
	if shapeValue, versionValue, ok := cniSpecConfiguration(value); ok {
		shape = inputFact{ID: CNISpecShapeFact, State: "declared", EnumValue: shapeValue}
		version = inputFact{ID: CNISpecVersionFact, State: "declared", EnumValue: versionValue}
		if operation == CNISpecMigrationOperation {
			state, reason = StatePrepared, ReasonCNISpecConfigurationObserved
		}
	}
	canonical, err := marshalComponentInput(CNISpecComponent, from, to, []inputFact{shape, planned, version})
	if err != nil {
		return Prepared{}, ErrInvalid
	}
	return Prepared{CanonicalInputJSON: canonical, SourceDigest: digestBytes(raw), InputDigest: digestBytes(canonical), State: state, Reason: reason, Omissions: []string{
		"CNI_SPEC_MIGRATION_INTENT_IS_CALLER_DECLARED",
		"CONFIGURATION_IS_CALLER_SUPPLIED_NOT_RUNTIME_OBSERVED",
		"PLUGIN_LIBRARY_RUNTIME_AND_NETWORK_COMPATIBILITY_NOT_EVALUATED",
		OmissionNoLiveObservation,
		OmissionNoWholeUpgrade,
	}}, nil
}

func cniSpecConfiguration(value any) (string, string, bool) {
	root, ok := value.(map[string]any)
	if !ok || !formatNonemptyString(root["name"]) {
		return "", "", false
	}
	version, ok := root["cniVersion"].(string)
	if !ok || (version != CNISpecFrom && version != CNISpecTo) {
		return "", "", false
	}
	_, hasType := root["type"]
	_, hasPlugins := root["plugins"]
	if hasType == hasPlugins {
		return "", "", false
	}
	if hasType {
		if !formatNonemptyString(root["type"]) {
			return "", "", false
		}
		return CNISpecShapeSingle, version, true
	}
	plugins, ok := root["plugins"].([]any)
	if !ok || len(plugins) == 0 {
		return "", "", false
	}
	for _, item := range plugins {
		plugin, ok := item.(map[string]any)
		if !ok || !formatNonemptyString(plugin["type"]) {
			return "", "", false
		}
	}
	if disable, exists := root["disableCheck"]; exists {
		if _, ok := disable.(bool); !ok {
			return "", "", false
		}
	}
	return CNISpecShapeList, version, true
}

func formatNonemptyString(value any) bool {
	text, ok := value.(string)
	return ok && text != ""
}
