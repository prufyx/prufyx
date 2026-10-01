// SPDX-License-Identifier: AGPL-3.0-only

// Package prometheusmode evaluates one source-backed, configuration-dependent
// transition question for exact Prometheus builds. It is deliberately narrow:
// results describe declared agent-mode preservation and never runtime state or
// whole-upgrade compatibility.
package prometheusmode

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"time"

	"github.com/prufyx/prufyx/cli/internal/currentbundle"
)

const (
	ComponentID             = "pkg:oci/prometheus/prometheus"
	AgentModePredicateID    = "component.prometheus.agent_mode"
	ImageDigestPredicateID  = "component.prometheus.image_digest"
	CurrentVersion          = "2.55.1"
	ProposedVersion         = "3.1.0"
	CurrentImageDigest      = "sha256:f4def6b3b61109a6eeea59945d578bb7e926c36cb0e036a23e3ceb8b6de024ad"
	ProposedImageDigest     = "sha256:0ea5254abf85f87901e8cfbd18fd243c59162c338ce0acd86aa2b0153d83dce2"
	CurrentIndexDigest      = "sha256:2659f4c2ebb718e7695cb9b25ffa7d6be64db013daba13e05c875451cf51b0d3"
	ProposedIndexDigest     = "sha256:6559acbd5d770b15bb3c954629ce190ac3cbbdb2b7f1c30f0385c4e05104e218"
	SourceContractDigest    = "sha256:ae2abefb40167d77b7bb39e6331102da00580517588197f55e3eda762fc0da2f"
	ExpectedVectorsDigest   = "sha256:64b06a67a9176918202fcc3a300e970caca8f3aef711a591dfb9ae03801efeb7"
	EvaluatorVersion        = "prometheus-mode-evaluator-v1"
	APIVersion              = "prufyx.io/prometheus-mode-assessment/v1alpha1"
	Kind                    = "PrometheusModeAssessment"
	SchemaVersion           = "1.0.0"
	currentEvidenceClass    = "declared_container_context_v1"
	proposedEvidenceClass   = "proposed_declared_container_context_v1"
	policyID                = "community-prometheus-mode-v1"
	policyRevision          = "prometheus-mode-source-contract-v1"
	maxProposedArtifactSize = 1 << 20
)

var (
	ErrInvalid   = errors.New("invalid Prometheus mode input")
	ErrIntegrity = errors.New("Prometheus mode integrity mismatch")
	ErrIO        = errors.New("Prometheus mode local I/O failure")
	digestRE     = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
)

//go:embed source-contract-v1.json expected-vectors-v1.json
var contractFiles embed.FS

type Request struct {
	Current  currentbundle.VerifiedArtifact
	Proposed VerifiedProposedArtifact
	Now      time.Time
}

type Claim struct {
	Status     string `json:"status"`
	ReasonCode string `json:"reasonCode"`
	Reason     string `json:"reason"`
	NextAction string `json:"nextAction"`
}

type CurrentEvidence struct {
	ComponentID         string                    `json:"componentId"`
	Version             string                    `json:"version,omitempty"`
	Role                string                    `json:"role,omitempty"`
	EvidenceClass       string                    `json:"evidenceClass,omitempty"`
	ImageManifestDigest string                    `json:"imageManifestDigest,omitempty"`
	AgentModeState      string                    `json:"agentModeState"`
	AgentMode           *bool                     `json:"agentMode,omitempty"`
	ReasonCode          string                    `json:"reasonCode,omitempty"`
	Sources             []currentbundle.SourceRef `json:"sources,omitempty"`
}

type ProposedEvidence struct {
	ComponentID         string `json:"componentId,omitempty"`
	Version             string `json:"version,omitempty"`
	WorkloadKind        string `json:"workloadKind"`
	Role                string `json:"role,omitempty"`
	EvidenceClass       string `json:"evidenceClass,omitempty"`
	ImageIdentityState  string `json:"imageIdentityState"`
	ImageManifestDigest string `json:"imageManifestDigest,omitempty"`
	EntrypointState     string `json:"entrypointState"`
	ArgumentsState      string `json:"argumentsState"`
	AgentModeState      string `json:"agentModeState"`
	AgentMode           *bool  `json:"agentMode,omitempty"`
	Origin              string `json:"origin"`
}

type InputBindings struct {
	CurrentBundleDigest      string `json:"currentBundleDigest"`
	ProposedBundleDigest     string `json:"proposedBundleDigest"`
	ProposedProjectionDigest string `json:"proposedProjectionDigest"`
	SourceContractDigest     string `json:"sourceContractDigest"`
	ExpectedVectorsDigest    string `json:"expectedVectorsDigest"`
	EvaluatorContractDigest  string `json:"evaluatorContractDigest"`
}

type PolicyBinding struct {
	PolicyID string `json:"policyId"`
	Revision string `json:"revision"`
	Digest   string `json:"digest"`
}

type SourceSpan struct {
	StartLine  int    `json:"startLine"`
	EndLine    int    `json:"endLine"`
	TextDigest string `json:"textDigest"`
}

type SourceEvidence struct {
	SourceID      string       `json:"sourceId"`
	URL           string       `json:"url"`
	ContentDigest string       `json:"contentDigest"`
	Spans         []SourceSpan `json:"spans"`
}

type Truth struct {
	CandidateOnly           bool `json:"candidateOnly"`
	NetworkUsed             bool `json:"networkUsed"`
	ModelUsed               bool `json:"modelUsed"`
	ClusterOperationUsed    bool `json:"clusterOperationUsed"`
	RuntimeVerificationUsed bool `json:"runtimeVerificationUsed"`
}

type Report struct {
	APIVersion    string           `json:"apiVersion"`
	Kind          string           `json:"kind"`
	SchemaVersion string           `json:"schemaVersion"`
	Status        string           `json:"status"`
	Assessment    string           `json:"assessment"`
	Question      string           `json:"question"`
	Scope         string           `json:"scope"`
	EvaluatedAt   string           `json:"evaluatedAt"`
	Claim         Claim            `json:"claim"`
	Current       CurrentEvidence  `json:"current"`
	Proposed      ProposedEvidence `json:"proposed"`
	Inputs        InputBindings    `json:"inputs"`
	Policy        PolicyBinding    `json:"policy"`
	Sources       []SourceEvidence `json:"sources"`
	Omissions     []string         `json:"omissions"`
	Truth         Truth            `json:"truth"`
	seal          *reportSeal
	canonicalHash string
}

type sourceContractDocument struct {
	Schema      string                 `json:"schema"`
	ComponentID string                 `json:"componentId"`
	Question    string                 `json:"question"`
	Current     sourceContractIdentity `json:"current"`
	Proposed    sourceContractIdentity `json:"proposed"`
	Sources     []struct {
		SourceID      string       `json:"sourceId"`
		URL           string       `json:"url"`
		ContentDigest string       `json:"contentDigest"`
		Spans         []SourceSpan `json:"spans"`
	} `json:"sources"`
}

type sourceContractIdentity struct {
	Version                string   `json:"version"`
	ExactTag               string   `json:"exactTag"`
	Repository             string   `json:"repository"`
	IndexDigest            string   `json:"indexDigest"`
	Platform               string   `json:"platform"`
	PlatformManifestDigest string   `json:"platformManifestDigest"`
	Entrypoint             []string `json:"entrypoint"`
	DefaultAgentMode       bool     `json:"defaultAgentMode"`
}

func digestBytes(raw []byte) string {
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func evaluatorContractDigest() string {
	return digestBytes([]byte(EvaluatorVersion + "\n" + APIVersion + "\n" + SchemaVersion + "\n" + SourceContractDigest + "\n" + ExpectedVectorsDigest))
}

func verifiedSourceContract() (sourceContractDocument, []SourceEvidence, error) {
	raw, err := contractFiles.ReadFile("source-contract-v1.json")
	if err != nil || digestBytes(raw) != SourceContractDigest {
		return sourceContractDocument{}, nil, fmt.Errorf("source contract bytes: %w", ErrIntegrity)
	}
	vectors, err := contractFiles.ReadFile("expected-vectors-v1.json")
	if err != nil || digestBytes(vectors) != ExpectedVectorsDigest {
		return sourceContractDocument{}, nil, fmt.Errorf("expected vector bytes: %w", ErrIntegrity)
	}
	var document sourceContractDocument
	if err := json.Unmarshal(raw, &document); err != nil || document.Schema != "prufyx.io/prometheus-mode-source-contract/v1" || document.ComponentID != ComponentID || document.Question == "" || len(document.Sources) != 4 {
		return sourceContractDocument{}, nil, fmt.Errorf("source contract schema: %w", ErrIntegrity)
	}
	exactIdentity := func(identity sourceContractIdentity, version, tag, indexDigest, platformDigest string) bool {
		return identity.Version == version && identity.ExactTag == tag && identity.Repository == "docker.io/prom/prometheus" && identity.IndexDigest == indexDigest && identity.Platform == "linux/arm64/v8" && identity.PlatformManifestDigest == platformDigest && len(identity.Entrypoint) == 1 && identity.Entrypoint[0] == "/bin/prometheus" && !identity.DefaultAgentMode
	}
	if !exactIdentity(document.Current, CurrentVersion, "v"+CurrentVersion, CurrentIndexDigest, CurrentImageDigest) || !exactIdentity(document.Proposed, ProposedVersion, "v"+ProposedVersion, ProposedIndexDigest, ProposedImageDigest) {
		return sourceContractDocument{}, nil, fmt.Errorf("source contract image identities: %w", ErrIntegrity)
	}
	sources := make([]SourceEvidence, len(document.Sources))
	seen := map[string]struct{}{}
	for i, source := range document.Sources {
		if source.SourceID == "" || source.URL == "" || !digestRE.MatchString(source.ContentDigest) || len(source.Spans) == 0 {
			return sourceContractDocument{}, nil, fmt.Errorf("source contract evidence: %w", ErrIntegrity)
		}
		if _, exists := seen[source.SourceID]; exists {
			return sourceContractDocument{}, nil, fmt.Errorf("duplicate source contract evidence: %w", ErrIntegrity)
		}
		seen[source.SourceID] = struct{}{}
		sources[i] = SourceEvidence{SourceID: source.SourceID, URL: source.URL, ContentDigest: source.ContentDigest, Spans: append([]SourceSpan(nil), source.Spans...)}
		for _, span := range source.Spans {
			if span.StartLine <= 0 || span.EndLine < span.StartLine || !digestRE.MatchString(span.TextDigest) {
				return sourceContractDocument{}, nil, fmt.Errorf("source contract span: %w", ErrIntegrity)
			}
		}
	}
	return document, sources, nil
}
