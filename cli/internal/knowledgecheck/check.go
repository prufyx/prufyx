// SPDX-License-Identifier: AGPL-3.0-only

// Package knowledgecheck binds the pure cert-manager predicate to one opaque,
// verifier-backed offline knowledge selection. It contains no updater or
// network transport.
package knowledgecheck

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"time"

	"github.com/prufyx/prufyx/cli/internal/buildidentity"
	"github.com/prufyx/prufyx/cli/internal/certmanagervalues"
	"github.com/prufyx/prufyx/cli/internal/knowledge"
)

const (
	reportAPIVersion = "prufyx.io/external-cert-manager-values-assessment/v1alpha1"
	reportKind       = "ExternalCertManagerValuesAssessment"
	replayAPIVersion = "prufyx.io/historical-knowledge-replay/v1"
)

var ErrIntegrity = errors.New("external knowledge check integrity failure")

type Request struct {
	Selection          knowledge.SelectionRequest
	ValuesPath         string
	ValuesDigest       string
	From               string
	To                 string
	CurrentChartDigest string
	TargetChartDigest  string
	SchemaValidation   string
}

type KnowledgeBinding struct {
	Origin                 string                 `json:"origin"`
	TrustSource            string                 `json:"trustSource"`
	Purpose                string                 `json:"purpose"`
	EvaluationMode         string                 `json:"evaluationMode"`
	Revision               string                 `json:"revision"`
	BundleDigest           string                 `json:"bundleDigest"`
	TrustReceiptDigest     string                 `json:"trustReceiptDigest"`
	RuleID                 string                 `json:"ruleID,omitempty"`
	RuleDigest             string                 `json:"ruleDigest,omitempty"`
	EngineCapabilityID     string                 `json:"engineCapabilityID"`
	EngineCapabilityDigest string                 `json:"engineCapabilityDigest"`
	ImportedVerifiedAt     string                 `json:"importedVerifiedAt"`
	EvaluatedAt            string                 `json:"evaluatedAt"`
	MetadataFreshness      string                 `json:"metadataFreshness"`
	CurrentNonRevocation   string                 `json:"currentNonRevocation"`
	EvidenceReviewedAt     string                 `json:"evidenceReviewedAt,omitempty"`
	EvidenceValidUntil     string                 `json:"evidenceValidUntil,omitempty"`
	EvidenceState          string                 `json:"evidenceState,omitempty"`
	EvidenceFreshness      string                 `json:"evidenceFreshness"`
	TrustReceipt           knowledge.TrustReceipt `json:"trustReceipt"`
}

type EngineBinding struct {
	Identity       buildidentity.Identity `json:"identity"`
	IdentityDigest string                 `json:"identityDigest"`
	Strength       string                 `json:"strength"`
}

type Report struct {
	APIVersion string                               `json:"apiVersion"`
	Kind       string                               `json:"kind"`
	Status     string                               `json:"status"`
	Assessment string                               `json:"assessment"`
	Knowledge  KnowledgeBinding                     `json:"knowledge"`
	Engine     EngineBinding                        `json:"engine"`
	Check      certmanagervalues.ExternalProjection `json:"check"`
	seal       *reportSeal
	hash       string
}

type reportSeal struct{}

type HistoricalReplay struct {
	APIVersion           string          `json:"apiVersion"`
	Mode                 string          `json:"mode"`
	Status               string          `json:"status"`
	CurrentNonRevocation string          `json:"currentNonRevocation"`
	OriginalReportDigest string          `json:"originalReportDigest"`
	OriginalReport       json.RawMessage `json:"originalReport"`
	claimStatus          string
	seal                 *replaySeal
	hash                 string
}

type replaySeal struct{}

// AdmitBundle is the semantic callback used by the knowledge store after TUF
// target verification. The returned fields describe parsed data only.
func AdmitBundle(target []byte) (knowledge.Admission, error) {
	bundle, err := certmanagervalues.ParseExternalBundle(target)
	if err != nil {
		return knowledge.Admission{}, err
	}
	admission, err := bundle.Admission()
	if err != nil {
		return knowledge.Admission{}, err
	}
	return knowledge.Admission{
		Revision: admission.Revision, Purpose: admission.Purpose,
		EngineCapabilityDigest: admission.EngineCapabilityDigest,
		HasRule:                admission.HasRule, RuleDigest: admission.RuleDigest,
		EvidenceExpiresAt: admission.EvidenceExpiresAt,
	}, nil
}

func EvaluateCurrent(req Request) (Report, error) {
	selected, err := knowledge.OpenSelected(req.Selection, AdmitBundle)
	if err != nil {
		return Report{}, err
	}
	return evaluateSelected(req, selected)
}

func evaluateSelected(req Request, selected knowledge.VerifiedRevision) (Report, error) {
	if !selected.Valid() {
		return Report{}, fmt.Errorf("verified selection: %w", ErrIntegrity)
	}
	bundle, err := certmanagervalues.ParseExternalBundle(selected.Bytes())
	if err != nil {
		return Report{}, err
	}
	artifact, err := certmanagervalues.ReadExternalArtifact(req.ValuesPath, req.ValuesDigest, bundle)
	if err != nil {
		return Report{}, err
	}
	projection, err := certmanagervalues.EvaluateExternalProjection(certmanagervalues.ExternalRequest{
		Values: artifact, From: req.From, To: req.To,
		CurrentChartDigest: req.CurrentChartDigest, TargetChartDigest: req.TargetChartDigest,
		SchemaValidation: req.SchemaValidation,
	}, bundle, selected.VerifiedAt())
	if err != nil {
		return Report{}, err
	}
	receipt := selected.TrustReceipt()
	if projection.Revision != selected.Revision() || projection.BundleDigest != selected.BundleDigest() ||
		projection.Purpose != receipt.Purpose || projection.EngineCapabilityDigest != receipt.EngineCapabilityDigest ||
		projection.RuleDigest != receipt.RuleDigest || (projection.RuleDigest != "") != receipt.HasRule ||
		projection.EvidenceValidUntil != receipt.EvidenceExpiresAt || receipt.TargetDigest != selected.BundleDigest() {
		return Report{}, fmt.Errorf("selection semantic binding: %w", ErrIntegrity)
	}
	identity, err := buildidentity.Report()
	if err != nil {
		return Report{}, fmt.Errorf("build identity: %w", ErrIntegrity)
	}
	identityRaw, err := json.Marshal(identity)
	if err != nil {
		return Report{}, fmt.Errorf("build identity encoding: %w", ErrIntegrity)
	}
	strength := "release_source_bound"
	if identity.ReleaseState == buildidentity.ReleaseStateDevelopment {
		strength = "development_unbound"
	}
	report := Report{
		APIVersion: reportAPIVersion, Kind: reportKind, Status: "CANDIDATE_ONLY", Assessment: "UNKNOWN",
		Knowledge: KnowledgeBinding{
			Origin: "external", TrustSource: receipt.TrustSource, Purpose: projection.Purpose,
			EvaluationMode: "current", Revision: projection.Revision, BundleDigest: projection.BundleDigest,
			TrustReceiptDigest: selected.TrustReceiptDigest(), RuleID: projection.RuleID, RuleDigest: projection.RuleDigest,
			EngineCapabilityID: projection.EngineCapabilityID, EngineCapabilityDigest: projection.EngineCapabilityDigest,
			ImportedVerifiedAt: receipt.VerifiedAt, EvaluatedAt: projection.EvaluatedAt,
			MetadataFreshness: "verified_at_evaluation_time", CurrentNonRevocation: "not_checked_offline",
			EvidenceReviewedAt: projection.EvidenceReviewedAt, EvidenceValidUntil: projection.EvidenceValidUntil,
			EvidenceState: projection.EvidenceState, EvidenceFreshness: projection.EvidenceFreshness,
			TrustReceipt: receipt,
		},
		Engine: EngineBinding{Identity: identity, IdentityDigest: digestBytes(identityRaw), Strength: strength},
		Check:  projection,
	}
	return issue(report), nil
}

func MarshalReport(report Report) ([]byte, error) {
	if report.seal == nil {
		return nil, fmt.Errorf("report capability: %w", ErrIntegrity)
	}
	raw, err := json.Marshal(report)
	if err != nil || digestBytes(raw) != report.hash {
		return nil, fmt.Errorf("report mutation: %w", ErrIntegrity)
	}
	return raw, nil
}

// ReplayHistorical reproduces the original current report at its recorded
// evaluation time. The wrapper labels that operation historical and does not
// turn it into a current freshness or non-revocation statement.
func ReplayHistorical(req Request, receipt []byte) (HistoricalReplay, error) {
	receipt = bytes.TrimSuffix(receipt, []byte("\n"))
	var original Report
	if validateReplayJSON(receipt) != nil || json.Unmarshal(receipt, &original) != nil {
		return HistoricalReplay{}, fmt.Errorf("historical receipt: %w", ErrIntegrity)
	}
	canonical, err := json.Marshal(original)
	if err != nil || !bytes.Equal(canonical, receipt) || original.Knowledge.EvaluationMode != "current" {
		return HistoricalReplay{}, fmt.Errorf("historical receipt canonical form: %w", ErrIntegrity)
	}
	evaluatedAt, err := time.Parse(time.RFC3339Nano, original.Knowledge.EvaluatedAt)
	if err != nil || evaluatedAt.Location() != time.UTC {
		return HistoricalReplay{}, fmt.Errorf("historical evaluation time: %w", ErrIntegrity)
	}
	selected, err := knowledge.OpenHistorical(req.Selection, evaluatedAt, AdmitBundle)
	if err != nil {
		return HistoricalReplay{}, err
	}
	reproduced, err := evaluateSelected(req, selected)
	if err != nil {
		return HistoricalReplay{}, err
	}
	reproducedRaw, err := MarshalReport(reproduced)
	if err != nil || !bytes.Equal(reproducedRaw, receipt) {
		return HistoricalReplay{}, fmt.Errorf("historical replay mismatch: %w", ErrIntegrity)
	}
	replay := HistoricalReplay{
		APIVersion: replayAPIVersion, Mode: "historical", Status: "MATCH",
		CurrentNonRevocation: "not_checked_offline", OriginalReportDigest: digestBytes(reproducedRaw),
		OriginalReport: append(json.RawMessage(nil), reproducedRaw...), claimStatus: reproduced.Check.Claim.Status,
	}
	raw, _ := json.Marshal(replay)
	replay.seal = &replaySeal{}
	replay.hash = digestBytes(raw)
	return replay, nil
}

func validateReplayJSON(raw []byte) error {
	if len(raw) == 0 || len(raw) > 1<<20 {
		return ErrIntegrity
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	depth := 0
	tokens := 0
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return ErrIntegrity
		}
		tokens++
		if tokens > 32768 {
			return ErrIntegrity
		}
		switch value := token.(type) {
		case json.Delim:
			switch value {
			case '{', '[':
				depth++
				if depth > 32 {
					return ErrIntegrity
				}
			case '}', ']':
				depth--
				if depth < 0 {
					return ErrIntegrity
				}
			}
		case string:
			if len(value) > 64<<10 {
				return ErrIntegrity
			}
		case json.Number:
			if len(value.String()) > 20 {
				return ErrIntegrity
			}
			if _, err := strconv.ParseInt(value.String(), 10, 64); err != nil {
				return ErrIntegrity
			}
		}
	}
	if depth != 0 {
		return ErrIntegrity
	}
	return nil
}

func MarshalHistoricalReplay(replay HistoricalReplay) ([]byte, error) {
	if replay.seal == nil {
		return nil, fmt.Errorf("historical replay capability: %w", ErrIntegrity)
	}
	raw, err := json.Marshal(replay)
	if err != nil || digestBytes(raw) != replay.hash {
		return nil, fmt.Errorf("historical replay mutation: %w", ErrIntegrity)
	}
	return raw, nil
}

func ClaimStatus(report Report) string { return report.Check.Claim.Status }

func HistoricalClaimStatus(replay HistoricalReplay) string { return replay.claimStatus }

func issue(report Report) Report {
	raw, _ := json.Marshal(report)
	report.seal = &reportSeal{}
	report.hash = digestBytes(raw)
	return report
}

func digestBytes(raw []byte) string {
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}
