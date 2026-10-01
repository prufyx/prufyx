// SPDX-License-Identifier: AGPL-3.0-only

package localcollector

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
)

// The registries are data contracts. Collection and projection are native Go;
// no shell, Python, or jq interpreter participates in the supported path.
//
//go:embed assets/component-configuration-adapters.json assets/component-configuration-adapters-v3.json
var assets embed.FS

type adapterAssets struct {
	Registry        []byte
	RegistryDigest  string
	FilterDigest    string
	AggregateDigest string
	Contract        adapterRegistry
}

type adapterRegistry struct {
	Metadata struct {
		SchemaVersion   string `json:"schemaVersion"`
		RegistryVersion string `json:"registryVersion"`
	} `json:"metadata"`
	Adapters []componentAdapter `json:"adapters"`
}

type componentAdapter struct {
	ComponentID       string              `json:"componentId"`
	Identities        []string            `json:"identities"`
	WorkloadKinds     []string            `json:"workloadKinds"`
	DeclaredRole      string              `json:"declaredRole"`
	RoleEvidenceClass string              `json:"roleEvidenceClass"`
	Predicates        []predicateRule     `json:"predicates"`
	Entrypoint        *entrypointContract `json:"entrypointContract"`
}

type predicateRule struct {
	ID            string   `json:"id"`
	ValueKind     string   `json:"valueKind"`
	AllowedValues []string `json:"allowedValues"`
	FeatureGate   string   `json:"featureGate"`
	Flags         []string `json:"flags"`
}

type entrypointContract struct {
	AcceptedCommands [][]string     `json:"acceptedExplicitCommands"`
	ImageBindings    []imageBinding `json:"imageBindings"`
}

type imageBinding struct {
	Version                string         `json:"version"`
	ReferenceClass         string         `json:"referenceClass"`
	PlatformDigests        []string       `json:"platformDigests"`
	DefaultPredicateValues map[string]any `json:"defaultPredicateValues"`
}

func loadAdapterAssets(profile string) (adapterAssets, error) {
	name := "component-configuration-adapters.json"
	if profile == "v3" {
		name = "component-configuration-adapters-v3.json"
	}
	raw, err := assets.ReadFile("assets/" + name)
	if err != nil {
		return adapterAssets{}, err
	}
	if _, err := DecodeStrict(raw); err != nil {
		return adapterAssets{}, err
	}
	var registry adapterRegistry
	if err := json.Unmarshal(raw, &registry); err != nil {
		return adapterAssets{}, err
	}
	if registry.Metadata.RegistryVersion != profile || len(registry.Adapters) == 0 {
		return adapterAssets{}, errors.New("invalid component adapter registry")
	}
	return adapterAssets{
		Registry: raw, Contract: registry, RegistryDigest: digest(raw),
		FilterDigest:    digest(componentFilterContract(profile)),
		AggregateDigest: digest(componentAggregateContract(profile)),
	}, nil
}

func digest(raw []byte) string {
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}
