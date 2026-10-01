// SPDX-License-Identifier: AGPL-3.0-only

package prometheusmode

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"time"

	"github.com/prufyx/prufyx/cli/internal/currentbundle"
)

const (
	question = "Does the exact proposed declared configuration preserve the current declared Prometheus agent mode?"
	scope    = "source-bound declared Prometheus agent-mode preservation for exact reviewed linux/arm64 builds; not process, data, or whole-upgrade compatibility authority"
)

type reportSeal struct{}

// Evaluate is a pure, offline reducer over two parser-issued capabilities and
// an explicit clock. A successful result always keeps the aggregate UNKNOWN.
func Evaluate(request Request) (Report, error) {
	document, sources, err := verifiedSourceContract()
	if err != nil || document.Question != question {
		return Report{}, fmt.Errorf("source contract: %w", ErrIntegrity)
	}
	current, currentDigest, err := extractCurrent(request.Current, request.Now)
	if err != nil {
		return Report{}, err
	}
	proposed, proposedBundleDigest, proposedProjectionDigest, err := extractProposed(request.Proposed)
	if err != nil {
		return Report{}, err
	}
	claim := reduceClaim(current, proposed)
	report := Report{
		APIVersion: APIVersion, Kind: Kind, SchemaVersion: SchemaVersion,
		Status: "CANDIDATE_ONLY", Assessment: "UNKNOWN", Question: question, Scope: scope,
		EvaluatedAt: request.Now.UTC().Format(time.RFC3339Nano), Claim: claim, Current: current, Proposed: proposed,
		Inputs: InputBindings{
			CurrentBundleDigest: currentDigest, ProposedBundleDigest: proposedBundleDigest,
			ProposedProjectionDigest: proposedProjectionDigest, SourceContractDigest: SourceContractDigest,
			ExpectedVectorsDigest: ExpectedVectorsDigest, EvaluatorContractDigest: evaluatorContractDigest(),
		},
		Policy:  PolicyBinding{PolicyID: policyID, Revision: policyRevision, Digest: SourceContractDigest},
		Sources: sources,
		Omissions: []string{
			"APPLIED_RUNTIME_MODE_NOT_VERIFIED",
			"PROCESS_STARTUP_NOT_EVALUATED",
			"PROMETHEUS_DATA_AND_REMOTE_WRITE_NOT_EVALUATED",
			"WHOLE_UPGRADE_COMPATIBILITY_NOT_EVALUATED",
		},
		Truth: Truth{CandidateOnly: true},
	}
	return issueReport(report), nil
}

func extractCurrent(verified currentbundle.VerifiedArtifact, now time.Time) (CurrentEvidence, string, error) {
	unknown := func(code string) CurrentEvidence {
		return CurrentEvidence{ComponentID: ComponentID, AgentModeState: "unknown", ReasonCode: code}
	}
	if now.IsZero() || now.Location() != time.UTC {
		return CurrentEvidence{}, "", fmt.Errorf("evaluation time must be explicit UTC: %w", ErrInvalid)
	}
	artifact, err := verified.Artifact()
	if err != nil || currentbundle.RejectSyntheticArtifact(artifact) != nil {
		return CurrentEvidence{}, "", fmt.Errorf("current artifact authority: %w", ErrIntegrity)
	}
	digest, err := verified.Digest()
	if err != nil || digest != artifact.Digest {
		return CurrentEvidence{}, "", fmt.Errorf("current artifact digest: %w", ErrIntegrity)
	}
	if artifact.Bundle.Freshness.State != "fresh" || artifact.Bundle.Freshness.PolicyID != "community-prometheus-mode-explicit-age-v1" || artifact.Bundle.Freshness.MaxAgeSeconds <= 0 || artifact.Bundle.Freshness.MaxAgeSeconds > 30*24*60*60 {
		return unknown("CURRENT_EVIDENCE_FRESHNESS_UNAVAILABLE"), digest, nil
	}
	capturedAt, err := time.Parse(time.RFC3339Nano, artifact.Bundle.Freshness.CapturedAt)
	if err != nil || capturedAt.Location() != time.UTC || capturedAt.After(now) || now.Sub(capturedAt) > time.Duration(artifact.Bundle.Freshness.MaxAgeSeconds)*time.Second {
		return unknown("CURRENT_EVIDENCE_STALE_OR_FUTURE"), digest, nil
	}
	if artifact.Bundle.PredicateRegistryVersion != currentbundle.PredicateRegistryVersionV2 {
		return unknown("CURRENT_PROMETHEUS_MODE_NOT_ADMITTED"), digest, nil
	}
	if prometheusWorkloadCoverageIncomplete(artifact.Bundle.Omissions) {
		return unknown("CURRENT_PROMETHEUS_WORKLOAD_COVERAGE_INCOMPLETE"), digest, nil
	}
	var matches []currentbundle.CanonicalComponent
	for _, component := range artifact.Bundle.Planes.Observed.Components {
		if component.ComponentID == ComponentID {
			matches = append(matches, component)
		}
	}
	if len(matches) != 1 {
		return unknown("CURRENT_PROMETHEUS_COMPONENT_UNRESOLVED"), digest, nil
	}
	component := matches[0]
	if component.Version.State != "exact" || component.Version.Value != CurrentVersion || !containsString(component.Roles, "server") {
		result := unknown("CURRENT_PROMETHEUS_VERSION_OR_ROLE_UNSUPPORTED")
		if component.Version.State == "exact" {
			result.Version = component.Version.Value
		}
		return result, digest, nil
	}
	var modePredicate, imagePredicate *currentbundle.CanonicalPredicate
	for index := range component.Predicates {
		predicate := &component.Predicates[index]
		switch predicate.ID {
		case AgentModePredicateID:
			modePredicate = predicate
		case ImageDigestPredicateID:
			imagePredicate = predicate
		}
	}
	if !validCurrentPredicatePair(modePredicate, imagePredicate) {
		result := unknown("CURRENT_PROMETHEUS_MODE_EVIDENCE_INCOMPLETE")
		result.Version = component.Version.Value
		return result, digest, nil
	}
	var mode bool
	var imageDigest string
	if json.Unmarshal(modePredicate.Value, &mode) != nil || json.Unmarshal(imagePredicate.Value, &imageDigest) != nil || imageDigest != CurrentImageDigest {
		return CurrentEvidence{}, "", fmt.Errorf("current Prometheus evidence values: %w", ErrIntegrity)
	}
	sources := append([]currentbundle.SourceRef(nil), modePredicate.Sources...)
	sort.Slice(sources, func(i, j int) bool {
		if sources[i].PathClass != sources[j].PathClass {
			return sources[i].PathClass < sources[j].PathClass
		}
		return sources[i].Digest < sources[j].Digest
	})
	return CurrentEvidence{ComponentID: ComponentID, Version: CurrentVersion, Role: "server", EvidenceClass: currentEvidenceClass, ImageManifestDigest: imageDigest, AgentModeState: "observed", AgentMode: boolPointer(mode), Sources: sources}, digest, nil
}

func validCurrentPredicatePair(mode, image *currentbundle.CanonicalPredicate) bool {
	if mode == nil || image == nil || mode.State != "observed" || image.State != "observed" || mode.SourceRole != "server" || image.SourceRole != "server" || mode.EvidenceClass != currentEvidenceClass || image.EvidenceClass != currentEvidenceClass {
		return false
	}
	return len(mode.Sources) > 0 && reflect.DeepEqual(mode.Sources, image.Sources)
}

func prometheusWorkloadCoverageIncomplete(omissions []currentbundle.Omission) bool {
	for _, omission := range omissions {
		if !omission.RequiredForEvaluation || (omission.SourceFile != "deployment-images.json" && omission.SourceFile != "statefulset-images.json") {
			continue
		}
		switch omission.Code {
		case "COMPONENT_CONFIGURATION_KUBERNETES_API_READ_FAILED",
			"COMPONENT_CONFIGURATION_KUBERNETES_API_READ_FAILED_AUTHENTICATION_EXEC_PLUGIN_FAILURE",
			"COMPONENT_CONFIGURATION_KUBERNETES_API_READ_FAILED_AUTHORIZATION_RBAC_FORBIDDEN",
			"COMPONENT_CONFIGURATION_KUBERNETES_API_READ_FAILED_DNS",
			"COMPONENT_CONFIGURATION_KUBERNETES_API_READ_FAILED_INVALID_KUBECONFIG_CONTEXT",
			"COMPONENT_CONFIGURATION_KUBERNETES_API_READ_FAILED_TLS_CERTIFICATE",
			"COMPONENT_CONFIGURATION_KUBERNETES_API_READ_FAILED_TRANSPORT_TIMEOUT_UNREACHABLE",
			"COMPONENT_CONFIGURATION_KUBERNETES_API_READ_FAILED_UNAUTHORIZED",
			"COMPONENT_CONFIGURATION_KUBERNETES_API_READ_FAILED_UNSUPPORTED_NOT_FOUND_API",
			"COMPONENT_CONFIGURATION_STRICT_JSON_REJECTED",
			"COMPONENT_CONFIGURATION_PROJECTION_FILTER_REJECTED",
			"COMPONENT_CONFIGURATION_PIPELINE_FAILED",
			"COMPONENT_CONFIGURATION_OUTPUT_LIMIT_EXCEEDED":
			return true
		}
	}
	return false
}

func extractProposed(verified VerifiedProposedArtifact) (ProposedEvidence, string, string, error) {
	if !verified.Valid() {
		return ProposedEvidence{}, "", "", fmt.Errorf("proposed artifact capability: %w", ErrIntegrity)
	}
	if verified.hasGenericBundle {
		bundle, err := verified.bundle.Bundle()
		if err != nil || len(bundle.Components) != 1 || bundle.Components[0].Component != ComponentID || bundle.PolicyRef.PolicyID != policyID || bundle.PolicyRef.Revision != policyRevision || bundle.PolicyRef.Digest != SourceContractDigest {
			return ProposedEvidence{}, "", "", fmt.Errorf("proposed minimized bundle binding: %w", ErrIntegrity)
		}
	}
	projection := cloneProjection(verified.projection)
	return ProposedEvidence{
		ComponentID: projection.ComponentID, Version: projection.Version, WorkloadKind: projection.WorkloadKind,
		Role: projection.Role, EvidenceClass: projection.EvidenceClass, ImageIdentityState: projection.ImageIdentityState,
		ImageManifestDigest: projection.ImageManifestDigest, EntrypointState: projection.EntrypointState,
		ArgumentsState: projection.ArgumentsState, AgentModeState: projection.AgentModeState,
		AgentMode: projection.AgentMode, Origin: projection.Origin,
	}, verified.bundleDigest, verified.projectionDigest, nil
}

func reduceClaim(current CurrentEvidence, proposed ProposedEvidence) Claim {
	if current.AgentModeState != "observed" || current.AgentMode == nil {
		if current.ReasonCode == "CURRENT_PROMETHEUS_WORKLOAD_COVERAGE_INCOMPLETE" {
			return Claim{Status: "UNKNOWN", ReasonCode: "PROMETHEUS_AGENT_MODE_EVIDENCE_INCOMPLETE", Reason: "the current declared agent mode is unresolved because an eligible Prometheus workload-kind collection was incomplete", NextAction: "recollect both Deployment and StatefulSet component-configuration surfaces successfully, then reassess"}
		}
		return Claim{Status: "UNKNOWN", ReasonCode: "PROMETHEUS_AGENT_MODE_EVIDENCE_INCOMPLETE", Reason: "the current declared agent mode is unresolved for the admitted source and freshness contract", NextAction: "collect a fresh producer-v3 Prometheus server row with paired agent-mode and reviewed platform-image predicates, then reassess"}
	}
	if proposed.AgentModeState != "observed" || proposed.AgentMode == nil {
		return Claim{Status: "UNKNOWN", ReasonCode: "PROMETHEUS_AGENT_MODE_EVIDENCE_INCOMPLETE", Reason: "the proposed declared agent mode is unresolved for the admitted source grammar", NextAction: "provide one supported Prometheus workload with the exact reviewed image digest, direct /bin/prometheus entrypoint semantics, and complete declared arguments"}
	}
	currentMode := *current.AgentMode
	if currentMode == *proposed.AgentMode {
		state := "disabled"
		if currentMode {
			state = "enabled"
		}
		return Claim{Status: "PASS", ReasonCode: "PROMETHEUS_AGENT_MODE_PRESERVED", Reason: "exact declared current and proposed Prometheus agent modes are both " + state, NextAction: "retain the exact image and argument bindings, then verify applied runtime behavior before upgrade"}
	}
	if currentMode {
		return Claim{Status: "ATTENTION", ReasonCode: "PROMETHEUS_AGENT_MODE_NOT_PRESERVED", Reason: "exact declared Prometheus agent mode changes from enabled to disabled in the proposed configuration", NextAction: "replace the legacy --enable-feature=agent token with --agent, then reassess and verify applied runtime behavior"}
	}
	return Claim{Status: "ATTENTION", ReasonCode: "PROMETHEUS_AGENT_MODE_NOT_PRESERVED", Reason: "exact declared Prometheus agent mode changes from disabled to enabled in the proposed configuration", NextAction: "confirm that enabling agent mode is intended; otherwise remove --agent, then reassess and verify applied runtime behavior"}
}

func containsString(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

func issueReport(report Report) Report {
	raw, _ := json.Marshal(report)
	report.seal = &reportSeal{}
	report.canonicalHash = digestBytes(raw)
	return report
}

func validReport(report Report) bool {
	if report.APIVersion != APIVersion || report.Kind != Kind || report.SchemaVersion != SchemaVersion || report.Status != "CANDIDATE_ONLY" || report.Assessment != "UNKNOWN" || report.Question != question || report.Scope != scope || !report.Truth.CandidateOnly || report.Truth.NetworkUsed || report.Truth.ModelUsed || report.Truth.ClusterOperationUsed || report.Truth.RuntimeVerificationUsed {
		return false
	}
	if report.Inputs.SourceContractDigest != SourceContractDigest || report.Inputs.ExpectedVectorsDigest != ExpectedVectorsDigest || report.Inputs.EvaluatorContractDigest != evaluatorContractDigest() || report.Policy != (PolicyBinding{PolicyID: policyID, Revision: policyRevision, Digest: SourceContractDigest}) {
		return false
	}
	if report.Claim.Status != "PASS" && report.Claim.Status != "ATTENTION" && report.Claim.Status != "UNKNOWN" {
		return false
	}
	return digestRE.MatchString(report.Inputs.CurrentBundleDigest) && digestRE.MatchString(report.Inputs.ProposedBundleDigest) && digestRE.MatchString(report.Inputs.ProposedProjectionDigest) && len(report.Sources) == 4 && len(report.Omissions) == 4
}

func MarshalReport(report Report) ([]byte, error) {
	if report.seal == nil || !validReport(report) {
		return nil, fmt.Errorf("report contract: %w", ErrIntegrity)
	}
	raw, err := json.Marshal(report)
	if err != nil {
		return nil, fmt.Errorf("marshal report: %w", ErrInvalid)
	}
	if digestBytes(raw) != report.canonicalHash {
		return nil, fmt.Errorf("report mutation: %w", ErrIntegrity)
	}
	return raw, nil
}

// Replay checks exact canonical report bytes against a separately authored
// expectation. It never derives expected values from evaluator output.
func Replay(request Request, expectedReport []byte) (Report, error) {
	report, err := Evaluate(request)
	if err != nil {
		return Report{}, err
	}
	raw, err := MarshalReport(report)
	if err != nil {
		return Report{}, err
	}
	if !bytes.Equal(raw, expectedReport) {
		return Report{}, fmt.Errorf("expected report mismatch: %w", ErrIntegrity)
	}
	return report, nil
}
