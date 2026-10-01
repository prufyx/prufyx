// SPDX-License-Identifier: AGPL-3.0-only

package prometheusmode

import (
	"encoding/json"
	"fmt"
)

const (
	DemoAPIVersion = "prufyx.io/prometheus-mode-synthetic-demo/v1alpha1"
	DemoKind       = "PrometheusModeSyntheticDemonstration"
	demoAuthority  = "SYNTHETIC_NON_AUTHORITATIVE_TEST_INPUT"
)

type DemoReport struct {
	APIVersion    string            `json:"apiVersion"`
	Kind          string            `json:"kind"`
	SchemaVersion string            `json:"schemaVersion"`
	Status        string            `json:"status"`
	Aggregate     string            `json:"aggregate"`
	Question      string            `json:"question"`
	Scope         string            `json:"scope"`
	Authority     string            `json:"authority"`
	Inputs        DemoInputBindings `json:"inputs"`
	Current       DemoCurrentSample `json:"currentSyntheticSample"`
	Cases         []DemoCase        `json:"cases"`
	Omissions     []string          `json:"omissions"`
	Truth         DemoTruth         `json:"truth"`
}

type DemoInputBindings struct {
	SourceContractDigest  string `json:"sourceContractDigest"`
	ExpectedVectorsDigest string `json:"expectedVectorsDigest"`
}
type DemoCurrentSample struct {
	ComponentID         string `json:"componentId"`
	Version             string `json:"version"`
	Platform            string `json:"platform"`
	ImageManifestDigest string `json:"imageManifestDigest"`
	AgentMode           bool   `json:"agentMode"`
	EvidenceClass       string `json:"evidenceClass"`
	Authority           string `json:"authority"`
	Source              string `json:"source"`
}
type DemoCase struct {
	ID       string           `json:"id"`
	Proposed ProposedEvidence `json:"proposed"`
	Claim    Claim            `json:"claim"`
}
type DemoTruth struct {
	Synthetic             bool `json:"synthetic"`
	ActualObservationUsed bool `json:"actualObservationUsed"`
	NetworkUsed           bool `json:"networkUsed"`
	ModelUsed             bool `json:"modelUsed"`
	ClusterOperationUsed  bool `json:"clusterOperationUsed"`
	RuntimeVerified       bool `json:"runtimeVerified"`
	WholeUpgradeEvaluated bool `json:"wholeUpgradeEvaluated"`
}
type demoVectorDocument struct {
	Schema               string       `json:"schema"`
	Status               string       `json:"status"`
	SourceContractDigest string       `json:"sourceContractDigest"`
	Aggregate            string       `json:"aggregate"`
	Vectors              []demoVector `json:"vectors"`
}
type demoVector struct {
	ID      string `json:"id"`
	Current struct {
		Version     string `json:"version"`
		ImageDigest string `json:"imageDigest"`
		AgentMode   bool   `json:"agentMode"`
	} `json:"current"`
	Proposed struct {
		Version string   `json:"version"`
		Image   string   `json:"image"`
		Command []string `json:"command"`
		Args    []string `json:"args"`
	} `json:"proposed"`
}

var demoVectorIDs = []string{"proposed-dedicated-preserves-current-agent-mode", "proposed-legacy-loses-current-agent-mode", "proposed-wrapper-remains-unknown"}

// BuildDemoReport evaluates embedded authored fixtures without creating a
// production observation capability.
func BuildDemoReport() (DemoReport, error) {
	document, _, err := verifiedSourceContract()
	if err != nil || document.Question != question {
		return DemoReport{}, fmt.Errorf("demo source contract: %w", ErrIntegrity)
	}
	raw, err := contractFiles.ReadFile("expected-vectors-v1.json")
	if err != nil || digestBytes(raw) != ExpectedVectorsDigest {
		return DemoReport{}, fmt.Errorf("demo expected vectors: %w", ErrIntegrity)
	}
	var vectors demoVectorDocument
	if json.Unmarshal(raw, &vectors) != nil || vectors.Schema != "prufyx.io/prometheus-mode-expected-vectors/v1" || vectors.Status != "AUTHORED_BEFORE_EVALUATOR_COMPARISON" || vectors.SourceContractDigest != SourceContractDigest || vectors.Aggregate != "UNKNOWN" {
		return DemoReport{}, fmt.Errorf("demo vector contract: %w", ErrIntegrity)
	}
	byID := make(map[string]demoVector, len(vectors.Vectors))
	for _, vector := range vectors.Vectors {
		if vector.ID == "" {
			return DemoReport{}, fmt.Errorf("demo vector id: %w", ErrIntegrity)
		}
		if _, ok := byID[vector.ID]; ok {
			return DemoReport{}, fmt.Errorf("duplicate demo vector id: %w", ErrIntegrity)
		}
		byID[vector.ID] = vector
	}
	cases := make([]DemoCase, 0, len(demoVectorIDs))
	for _, id := range demoVectorIDs {
		vector, ok := byID[id]
		if !ok || vector.Current.Version != CurrentVersion || vector.Current.ImageDigest != CurrentImageDigest || !vector.Current.AgentMode || vector.Proposed.Version != ProposedVersion {
			return DemoReport{}, fmt.Errorf("demo vector binding %s: %w", id, ErrIntegrity)
		}
		manifest := demoProposedManifest(vector)
		verified, err := ParseProposedArtifact(manifest, digestBytes(manifest))
		if err != nil {
			return DemoReport{}, fmt.Errorf("demo proposed parser %s: %w", id, err)
		}
		proposed, _, _, err := extractProposed(verified)
		if err != nil {
			return DemoReport{}, fmt.Errorf("demo proposed projection %s: %w", id, err)
		}
		mode := true
		current := CurrentEvidence{ComponentID: ComponentID, Version: CurrentVersion, Role: "server", EvidenceClass: "synthetic_fixture_context_v1", ImageManifestDigest: CurrentImageDigest, AgentModeState: "observed", AgentMode: &mode}
		cases = append(cases, DemoCase{ID: id, Proposed: proposed, Claim: reduceClaim(current, proposed)})
	}
	return DemoReport{APIVersion: DemoAPIVersion, Kind: DemoKind, SchemaVersion: "1.0.0", Status: "SYNTHETIC_DEMONSTRATION", Aggregate: "UNKNOWN", Question: question, Scope: "declared Prometheus agent-mode parser and reducer demonstration only; no actual observation or compatibility authority", Authority: demoAuthority, Inputs: DemoInputBindings{SourceContractDigest: SourceContractDigest, ExpectedVectorsDigest: ExpectedVectorsDigest}, Current: DemoCurrentSample{ComponentID: ComponentID, Version: CurrentVersion, Platform: "linux/arm64/v8", ImageManifestDigest: CurrentImageDigest, AgentMode: true, EvidenceClass: "synthetic_fixture_context_v1", Authority: demoAuthority, Source: "embedded expected-vectors-v1.json"}, Cases: cases, Omissions: []string{"ACTUAL_CURRENT_OBSERVATION_NOT_USED", "APPLIED_RUNTIME_MODE_NOT_VERIFIED", "PROCESS_STARTUP_NOT_EVALUATED", "PROMETHEUS_DATA_AND_REMOTE_WRITE_NOT_EVALUATED", "WHOLE_UPGRADE_COMPATIBILITY_NOT_EVALUATED"}, Truth: DemoTruth{Synthetic: true}}, nil
}

func demoProposedManifest(vector demoVector) []byte {
	container := map[string]any{"name": "prometheus", "image": vector.Proposed.Image, "command": vector.Proposed.Command, "args": vector.Proposed.Args}
	document := map[string]any{"apiVersion": "apps/v1", "kind": "Deployment", "spec": map[string]any{"template": map[string]any{"spec": map[string]any{"containers": []any{container}}}}}
	raw, _ := json.Marshal(document)
	return raw
}
