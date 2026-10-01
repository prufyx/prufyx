// SPDX-License-Identifier: AGPL-3.0-only

// Package tikvgcpv2knowledge binds the isolated TiKV GCP v2 WIF full-backup
// target preflight to embedded or explicitly selected local knowledge.
package tikvgcpv2knowledge

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"github.com/prufyx/prufyx/cli/internal/buildidentity"
	"github.com/prufyx/prufyx/cli/internal/knowledge"
	"github.com/prufyx/prufyx/cli/internal/tikvgcpv2"
)

var (
	ErrInvalid   = errors.New("invalid TiKV GCP v2 WIF full-backup preflight request")
	ErrIntegrity = errors.New("TiKV GCP v2 WIF full-backup preflight integrity failure")
)

type KnowledgeBinding struct {
	Origin                 string                      `json:"origin"`
	TrustSource            string                      `json:"trustSource"`
	Purpose                string                      `json:"purpose"`
	EvaluationMode         string                      `json:"evaluationMode"`
	TargetPath             string                      `json:"targetPath"`
	Revision               string                      `json:"revision"`
	BundleDigest           string                      `json:"bundleDigest"`
	TrustReceiptDigest     string                      `json:"trustReceiptDigest,omitempty"`
	EngineCapabilityDigest string                      `json:"engineCapabilityDigest"`
	ImportedVerifiedAt     string                      `json:"importedVerifiedAt,omitempty"`
	EvaluatedAt            string                      `json:"evaluatedAt"`
	MetadataFreshness      string                      `json:"metadataFreshness"`
	CurrentNonRevocation   string                      `json:"currentNonRevocation"`
	NormativeSources       []tikvgcpv2.NormativeSource `json:"normativeSources"`
	TrustReceipt           *knowledge.TrustReceipt     `json:"trustReceipt,omitempty"`
}

type EngineBinding struct {
	Identity       buildidentity.Identity `json:"identity"`
	IdentityDigest string                 `json:"identityDigest"`
	Strength       string                 `json:"strength"`
}

type Check struct {
	Schema                    string                `json:"schema"`
	PreparedObservationDigest string                `json:"preparedObservationDigest"`
	Observation               tikvgcpv2.Observation `json:"observation"`
	Claim                     tikvgcpv2.Claim       `json:"claim"`
	Unchecked                 []string              `json:"unchecked"`
}

type ProfileBinding struct {
	ID       string `json:"id"`
	Revision string `json:"revision"`
}

type Report struct {
	Schema                   string           `json:"schema"`
	Kind                     string           `json:"kind"`
	Status                   string           `json:"status"`
	AggregateBackupReadiness string           `json:"aggregateBackupReadiness"`
	Purpose                  string           `json:"purpose"`
	Target                   tikvgcpv2.Target `json:"target"`
	Profile                  ProfileBinding   `json:"profile"`
	Knowledge                KnowledgeBinding `json:"knowledge"`
	Engine                   EngineBinding    `json:"engine"`
	Check                    Check            `json:"check"`
	seal                     *reportSeal
	digest                   string
}
type reportSeal struct{}

type HistoricalReplay struct {
	Schema               string          `json:"schema"`
	Mode                 string          `json:"mode"`
	Status               string          `json:"status"`
	CurrentNonRevocation string          `json:"currentNonRevocation"`
	OriginalReportDigest string          `json:"originalReportDigest"`
	OriginalReport       json.RawMessage `json:"originalReport"`
	claimExit            int
	seal                 *replaySeal
	digest               string
}
type replaySeal struct{}

type Request struct {
	Selection   knowledge.SelectionRequest
	Observation tikvgcpv2.Observation
}

func EvaluateEmbedded(observation tikvgcpv2.Observation, at time.Time) (Report, error) {
	if at.IsZero() || at.Location() != time.UTC || at.Nanosecond() != 0 {
		return Report{}, ErrInvalid
	}
	embeddedProfileBytes := tikvgcpv2.EmbeddedProfile()
	profile, err := tikvgcpv2.ParseProfile(embeddedProfileBytes)
	if err != nil {
		return Report{}, ErrIntegrity
	}
	binding := KnowledgeBinding{Origin: "embedded_reviewed", TrustSource: "EMBEDDED_SOURCE_CONTRACT", Purpose: profile.Purpose, EvaluationMode: "current", TargetPath: tikvgcpv2.TargetPath, Revision: profile.Revision, BundleDigest: digestBytes(embeddedProfileBytes), EngineCapabilityDigest: profile.EngineCapabilityDigest, EvaluatedAt: at.Format(time.RFC3339), MetadataFreshness: "evaluated_at_explicit_time", CurrentNonRevocation: "not_applicable_embedded", NormativeSources: append([]tikvgcpv2.NormativeSource(nil), profile.NormativeSources...)}
	return buildReport(profile, observation, binding)
}

// EvaluateCurrent uses only the selected local profile and the verifier's
// actual clock. It never falls back to embedded knowledge.
func EvaluateCurrent(req Request) (Report, error) {
	selected, err := knowledge.OpenSelectedTiKVGCPV2WIFBackup(req.Selection)
	if err != nil {
		return Report{}, err
	}
	return evaluateSelected(req.Observation, selected)
}

func evaluateSelected(observation tikvgcpv2.Observation, selected knowledge.VerifiedRevision) (Report, error) {
	if !selected.Valid() {
		return Report{}, ErrIntegrity
	}
	receipt := selected.TrustReceipt()
	if receipt.TargetPath != knowledge.TiKVGCPV2WIFBackupTargetPath || receipt.TrustSource != "OPERATOR_PROVISIONED" {
		return Report{}, ErrIntegrity
	}
	profile, err := tikvgcpv2.ParseProfile(selected.Bytes())
	if err != nil {
		return Report{}, ErrIntegrity
	}
	admission, err := tikvgcpv2.AdmitProfile(selected.Bytes())
	if err != nil || selected.BundleDigest() != receipt.TargetDigest || selected.Revision() != admission.Revision || receipt.KnowledgeRevision != admission.Revision || receipt.Purpose != admission.Purpose || receipt.EngineCapabilityDigest != admission.EngineCapabilityDigest || receipt.HasRule != admission.HasRule || receipt.RuleDigest != admission.RuleDigest || receipt.EvidenceExpiresAt != admission.EvidenceExpiresAt {
		return Report{}, ErrIntegrity
	}
	at := selected.VerifiedAt().UTC().Truncate(time.Second)
	binding := KnowledgeBinding{Origin: "external_signed_local", TrustSource: receipt.TrustSource, Purpose: profile.Purpose, EvaluationMode: "current", TargetPath: receipt.TargetPath, Revision: profile.Revision, BundleDigest: selected.BundleDigest(), TrustReceiptDigest: selected.TrustReceiptDigest(), EngineCapabilityDigest: profile.EngineCapabilityDigest, ImportedVerifiedAt: receipt.VerifiedAt, EvaluatedAt: at.Format(time.RFC3339), MetadataFreshness: "verified_at_evaluation_time", CurrentNonRevocation: "not_checked_offline", NormativeSources: append([]tikvgcpv2.NormativeSource(nil), profile.NormativeSources...), TrustReceipt: &receipt}
	return buildReport(profile, observation, binding)
}

func buildReport(profile tikvgcpv2.Profile, observation tikvgcpv2.Observation, binding KnowledgeBinding) (Report, error) {
	obsRaw, err := tikvgcpv2.MarshalObservation(observation)
	if err != nil {
		return Report{}, ErrInvalid
	}
	at, err := time.Parse(time.RFC3339, binding.EvaluatedAt)
	if err != nil {
		return Report{}, ErrIntegrity
	}
	claim := tikvgcpv2.Evaluate(profile, observation, at)
	identity, err := buildidentity.Report()
	if err != nil {
		return Report{}, ErrIntegrity
	}
	identityRaw, err := json.Marshal(identity)
	if err != nil {
		return Report{}, ErrIntegrity
	}
	strength := "release_source_bound"
	if identity.ReleaseState == buildidentity.ReleaseStateDevelopment {
		strength = "development_unbound"
	}
	report := Report{Schema: "prufyx.io/tikv-gcp-v2-wif-backup-report/v1", Kind: "TiKVGCPV2WIFBackupPreflightReport", Status: claim.Status, AggregateBackupReadiness: "UNKNOWN", Purpose: profile.Purpose, Target: profile.Target, Profile: ProfileBinding{ID: tikvgcpv2.ProfileID, Revision: profile.Revision}, Knowledge: binding, Engine: EngineBinding{Identity: identity, IdentityDigest: digestBytes(identityRaw), Strength: strength}, Check: Check{Schema: "prufyx.io/tikv-gcp-v2-wif-backup-check/v1", PreparedObservationDigest: digestBytes(obsRaw), Observation: observation, Claim: claim, Unchecked: []string{"effective_configuration", "workload_identity_and_credentials", "GCS_access", "backup_execution_and_completion", "restore_and_log_backup", "installation_startup_and_runtime_behavior", "data_safety"}}}
	raw, err := json.Marshal(report)
	if err != nil {
		return Report{}, ErrIntegrity
	}
	report.seal = &reportSeal{}
	report.digest = digestBytes(raw)
	return report, nil
}

func MarshalReport(report Report) ([]byte, error) {
	if report.seal == nil || report.Schema != "prufyx.io/tikv-gcp-v2-wif-backup-report/v1" || report.Kind != "TiKVGCPV2WIFBackupPreflightReport" || report.Status != report.Check.Claim.Status || (report.Status != "PASS" && report.Status != "BLOCKED" && report.Status != "UNKNOWN") || report.AggregateBackupReadiness != "UNKNOWN" || report.Purpose != report.Knowledge.Purpose || report.Target.Component != tikvgcpv2.Component || report.Target.Version != "8.5.8" || report.Profile.ID != tikvgcpv2.ProfileID || report.Profile.Revision != report.Knowledge.Revision {
		return nil, ErrIntegrity
	}
	raw, err := json.Marshal(report)
	if err != nil || digestBytes(raw) != report.digest {
		return nil, ErrIntegrity
	}
	return append(raw, '\n'), nil
}

func ClaimExit(report Report) int {
	if _, err := MarshalReport(report); err != nil {
		return 3
	}
	return tikvgcpv2.ClaimExit(report.Check.Claim)
}

func ReplayEmbedded(observation tikvgcpv2.Observation, expected []byte) (HistoricalReplay, error) {
	original, canonical, at, err := parseOriginal(expected)
	if err != nil || original.Knowledge.Origin != "embedded_reviewed" {
		return HistoricalReplay{}, ErrIntegrity
	}
	reproduced, err := EvaluateEmbedded(observation, at)
	if err != nil {
		return HistoricalReplay{}, err
	}
	return finishReplay(reproduced, canonical)
}

func ReplayHistorical(req Request, expected []byte) (HistoricalReplay, error) {
	if req.Selection.ExpectedRevision == "" || req.Selection.ExpectedBundleDigest == "" || req.Selection.ExpectedTrustReceiptDigest == "" {
		return HistoricalReplay{}, ErrIntegrity
	}
	original, canonical, at, err := parseOriginal(expected)
	if err != nil || original.Knowledge.Origin != "external_signed_local" {
		return HistoricalReplay{}, ErrIntegrity
	}
	selected, err := knowledge.OpenHistoricalTiKVGCPV2WIFBackup(req.Selection, at)
	if err != nil {
		return HistoricalReplay{}, err
	}
	reproduced, err := evaluateSelected(req.Observation, selected)
	if err != nil {
		return HistoricalReplay{}, err
	}
	return finishReplay(reproduced, canonical)
}

func parseOriginal(expected []byte) (Report, []byte, time.Time, error) {
	if len(expected) == 0 || len(expected) > 4<<20 {
		return Report{}, nil, time.Time{}, ErrIntegrity
	}
	var original Report
	d := json.NewDecoder(bytes.NewReader(expected))
	d.DisallowUnknownFields()
	if d.Decode(&original) != nil {
		return Report{}, nil, time.Time{}, ErrIntegrity
	}
	canonical, err := json.Marshal(original)
	if err != nil || !bytes.Equal(expected, append(append([]byte{}, canonical...), '\n')) {
		return Report{}, nil, time.Time{}, ErrIntegrity
	}
	at, err := time.Parse(time.RFC3339, original.Knowledge.EvaluatedAt)
	if err != nil || at.Location() != time.UTC || at.Nanosecond() != 0 {
		return Report{}, nil, time.Time{}, ErrIntegrity
	}
	return original, canonical, at, nil
}

func finishReplay(reproduced Report, canonical []byte) (HistoricalReplay, error) {
	raw, err := MarshalReport(reproduced)
	if err != nil || !bytes.Equal(bytes.TrimSuffix(raw, []byte{'\n'}), canonical) {
		return HistoricalReplay{}, ErrIntegrity
	}
	replay := HistoricalReplay{Schema: "prufyx.io/tikv-gcp-v2-wif-backup-replay/v1", Mode: "historical", Status: "MATCH", CurrentNonRevocation: "not_checked_offline", OriginalReportDigest: digestBytes(canonical), OriginalReport: append(json.RawMessage{}, canonical...), claimExit: ClaimExit(reproduced)}
	replayRaw, err := json.Marshal(replay)
	if err != nil {
		return HistoricalReplay{}, ErrIntegrity
	}
	replay.seal = &replaySeal{}
	replay.digest = digestBytes(replayRaw)
	return replay, nil
}

func MarshalHistoricalReplay(replay HistoricalReplay) ([]byte, error) {
	if replay.seal == nil || replay.Schema != "prufyx.io/tikv-gcp-v2-wif-backup-replay/v1" || replay.Status != "MATCH" || replay.Mode != "historical" || (replay.claimExit != 0 && replay.claimExit != 10 && replay.claimExit != 11) {
		return nil, ErrIntegrity
	}
	raw, err := json.Marshal(replay)
	if err != nil || digestBytes(raw) != replay.digest {
		return nil, ErrIntegrity
	}
	return append(raw, '\n'), nil
}
func HistoricalClaimExit(replay HistoricalReplay) int {
	if _, err := MarshalHistoricalReplay(replay); err != nil {
		return 3
	}
	return replay.claimExit
}

func digestBytes(raw []byte) string {
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}
