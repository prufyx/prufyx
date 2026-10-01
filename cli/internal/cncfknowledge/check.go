// SPDX-License-Identifier: AGPL-3.0-only

// Package cncfknowledge binds declared CNCF source constraints to an explicit
// verified local TUF selection. It has no downloader or customer-data store.
package cncfknowledge

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"time"
	"unicode/utf8"

	"github.com/prufyx/prufyx/cli/internal/buildidentity"
	"github.com/prufyx/prufyx/cli/internal/cncfcheck"
	"github.com/prufyx/prufyx/cli/internal/knowledge"
)

var (
	ErrInvalid   = errors.New("invalid external CNCF request")
	ErrIntegrity = errors.New("external CNCF knowledge integrity failure")
)

type Request struct {
	Selection      knowledge.SelectionRequest
	Project        string
	SelectedRuleID string
	Input          []byte
	InputDigest    string
}

// CheckInput contains only the item-specific values evaluated against an
// already verified revision. It carries no store path and cannot create or
// forge a VerifiedRevision capability.
type CheckInput struct {
	Project        string
	SelectedRuleID string
	Input          []byte
	InputDigest    string
}

type KnowledgeBinding struct {
	Origin                 string                 `json:"origin"`
	TrustSource            string                 `json:"trustSource"`
	Purpose                string                 `json:"purpose"`
	EvaluationMode         string                 `json:"evaluationMode"`
	TargetPath             string                 `json:"targetPath"`
	Revision               string                 `json:"revision"`
	BundleDigest           string                 `json:"bundleDigest"`
	TrustReceiptDigest     string                 `json:"trustReceiptDigest"`
	EngineCapabilityDigest string                 `json:"engineCapabilityDigest"`
	ImportedVerifiedAt     string                 `json:"importedVerifiedAt"`
	EvaluatedAt            string                 `json:"evaluatedAt"`
	MetadataFreshness      string                 `json:"metadataFreshness"`
	CurrentNonRevocation   string                 `json:"currentNonRevocation"`
	TrustReceipt           knowledge.TrustReceipt `json:"trustReceipt"`
}

type EngineBinding struct {
	Identity       buildidentity.Identity `json:"identity"`
	IdentityDigest string                 `json:"identityDigest"`
	Strength       string                 `json:"strength"`
}

type Report struct {
	Schema     string           `json:"schema"`
	Status     string           `json:"status"`
	Assessment string           `json:"assessment"`
	Knowledge  KnowledgeBinding `json:"knowledge"`
	Engine     EngineBinding    `json:"engine"`
	Check      cncfcheck.Report `json:"check"`
	seal       *reportSeal
	digest     string
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

func validateRequest(req Request) error {
	if req.Selection.StoreRoot == "" {
		return ErrInvalid
	}
	return validateCheckInput(req.checkInput())
}

func validateCheckInput(req CheckInput) error {
	if len(req.Input) == 0 || len(req.Input) > 1<<20 || req.Project == "" {
		return ErrInvalid
	}
	if req.InputDigest != "" && req.InputDigest != digestBytes(req.Input) {
		return ErrIntegrity
	}
	return nil
}

func (r Request) checkInput() CheckInput {
	return CheckInput{Project: r.Project, SelectedRuleID: r.SelectedRuleID, Input: r.Input, InputDigest: r.InputDigest}
}

// EvaluateCurrent uses the verifier's actual current clock. An operator cannot
// backdate a current selection to avoid TUF or source-evidence expiry.
func EvaluateCurrent(req Request) (Report, error) {
	if err := validateRequest(req); err != nil {
		return Report{}, err
	}
	selected, err := knowledge.OpenSelectedConstraints(req.Selection)
	if err != nil {
		return Report{}, err
	}
	return evaluateSelected(req.checkInput(), selected)
}

// EvaluateVerified evaluates one typed CNCF input against the exact immutable
// current revision that a caller opened once. Historical capabilities are
// rejected here so batch checks cannot backdate current selection.
func EvaluateVerified(selected knowledge.VerifiedRevision, req CheckInput) (Report, error) {
	if selected.Mode() != knowledge.SelectionCurrent {
		return Report{}, ErrIntegrity
	}
	if err := validateCheckInput(req); err != nil {
		return Report{}, err
	}
	return evaluateSelected(req, selected)
}

func evaluateSelected(req CheckInput, selected knowledge.VerifiedRevision) (Report, error) {
	if !selected.Valid() {
		return Report{}, ErrIntegrity
	}
	receipt := selected.TrustReceipt()
	if receipt.TargetPath != knowledge.ConstraintsTargetPath || receipt.TrustSource != "OPERATOR_PROVISIONED" {
		return Report{}, ErrIntegrity
	}
	bundle, err := cncfcheck.ParseExternalBundle(selected.Bytes())
	if err != nil {
		return Report{}, ErrIntegrity
	}
	admission, err := bundle.Admission()
	if err != nil || bundle.BundleDigest() != selected.BundleDigest() || receipt.TargetDigest != selected.BundleDigest() || admission.Revision != selected.Revision() || admission.Revision != receipt.KnowledgeRevision || admission.Purpose != receipt.Purpose || admission.EngineCapabilityDigest != receipt.EngineCapabilityDigest || admission.HasRule != receipt.HasRule || admission.RuleDigest != receipt.RuleDigest || admission.EvidenceExpiresAt != receipt.EvidenceExpiresAt {
		return Report{}, ErrIntegrity
	}
	evaluatedAt := selected.VerifiedAt().UTC().Truncate(time.Second)
	var check cncfcheck.Report
	if req.SelectedRuleID != "" {
		check, err = bundle.EvaluateRule(req.Project, req.SelectedRuleID, req.Input, evaluatedAt)
	} else {
		check, err = bundle.Evaluate(req.Project, req.Input, evaluatedAt)
	}
	if err != nil {
		return Report{}, err
	}
	expectedSelected := ""
	if len(check.Check.Claims) == 1 && check.Check.Claims[0].RuleID == req.SelectedRuleID {
		expectedSelected = req.SelectedRuleID
	}
	if _, err := cncfcheck.MarshalReport(check); err != nil || check.KnowledgeOrigin != "external_declared" || check.SourceAuthority != "DECLARED_RULE_SOURCE_REFERENCES" || check.KnowledgeRevision != admission.Revision || check.KnowledgePackDigest != selected.BundleDigest() || check.InputFileDigest != digestBytes(req.Input) || check.RequestedRuleID != req.SelectedRuleID || check.SelectedRuleID != expectedSelected {
		return Report{}, ErrIntegrity
	}
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
	report := Report{
		Schema: "prufyx.io/external-cncf-source-check/v1alpha1", Status: "CANDIDATE_ONLY", Assessment: "UNKNOWN",
		Knowledge: KnowledgeBinding{
			Origin: "external_signed_local", TrustSource: receipt.TrustSource, Purpose: admission.Purpose,
			EvaluationMode: "current", TargetPath: receipt.TargetPath, Revision: admission.Revision,
			BundleDigest: selected.BundleDigest(), TrustReceiptDigest: selected.TrustReceiptDigest(),
			EngineCapabilityDigest: admission.EngineCapabilityDigest, ImportedVerifiedAt: receipt.VerifiedAt,
			EvaluatedAt: evaluatedAt.Format(time.RFC3339), MetadataFreshness: "verified_at_evaluation_time",
			CurrentNonRevocation: "not_checked_offline", TrustReceipt: receipt,
		},
		Engine: EngineBinding{Identity: identity, IdentityDigest: digestBytes(identityRaw), Strength: strength},
		Check:  check,
	}
	raw, err := json.Marshal(report)
	if err != nil {
		return Report{}, ErrIntegrity
	}
	report.seal, report.digest = &reportSeal{}, digestBytes(raw)
	return report, nil
}

func MarshalReport(report Report) ([]byte, error) {
	if report.seal == nil || report.Assessment != "UNKNOWN" || report.Status != "CANDIDATE_ONLY" || report.Knowledge.Origin != "external_signed_local" || report.Knowledge.CurrentNonRevocation != "not_checked_offline" {
		return nil, ErrIntegrity
	}
	if _, err := cncfcheck.MarshalReport(report.Check); err != nil {
		return nil, ErrIntegrity
	}
	raw, err := json.Marshal(report)
	if err != nil || digestBytes(raw) != report.digest {
		return nil, ErrIntegrity
	}
	return raw, nil
}

func ClaimExit(report Report) int {
	if _, err := MarshalReport(report); err != nil {
		return 3
	}
	return cncfcheck.ClaimExit(report.Check)
}

// ReplayHistorical reconstructs the original current report with the original
// selected identities and clock. Its wrapper is explicitly historical.
func ReplayHistorical(req Request, expected []byte) (HistoricalReplay, error) {
	if err := validateRequest(req); err != nil {
		return HistoricalReplay{}, err
	}
	if req.Selection.ExpectedRevision == "" || req.Selection.ExpectedBundleDigest == "" || req.Selection.ExpectedTrustReceiptDigest == "" || !boundedReportJSON(expected) {
		return HistoricalReplay{}, ErrIntegrity
	}
	var original Report
	decoder := json.NewDecoder(bytes.NewReader(expected))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&original) != nil {
		return HistoricalReplay{}, ErrIntegrity
	}
	canonical, err := json.Marshal(original)
	if err != nil || !bytes.Equal(append(append([]byte{}, canonical...), '\n'), expected) || original.Knowledge.EvaluationMode != "current" {
		return HistoricalReplay{}, ErrIntegrity
	}
	evaluatedAt, err := time.Parse(time.RFC3339, original.Knowledge.EvaluatedAt)
	if err != nil || evaluatedAt.Location() != time.UTC || evaluatedAt.Nanosecond() != 0 || evaluatedAt.Format(time.RFC3339) != original.Knowledge.EvaluatedAt {
		return HistoricalReplay{}, ErrIntegrity
	}
	selected, err := knowledge.OpenHistoricalConstraints(req.Selection, evaluatedAt)
	if err != nil {
		return HistoricalReplay{}, err
	}
	reproduced, err := evaluateSelected(req.checkInput(), selected)
	if err != nil {
		return HistoricalReplay{}, err
	}
	raw, err := MarshalReport(reproduced)
	if err != nil || !bytes.Equal(raw, canonical) {
		return HistoricalReplay{}, ErrIntegrity
	}
	replay := HistoricalReplay{
		Schema: "prufyx.io/historical-cncf-knowledge-replay/v1", Mode: "historical", Status: "MATCH",
		CurrentNonRevocation: "not_checked_offline", OriginalReportDigest: digestBytes(raw),
		OriginalReport: append(json.RawMessage{}, raw...), claimExit: ClaimExit(reproduced),
	}
	replayRaw, err := json.Marshal(replay)
	if err != nil {
		return HistoricalReplay{}, ErrIntegrity
	}
	replay.seal, replay.digest = &replaySeal{}, digestBytes(replayRaw)
	return replay, nil
}

func MarshalHistoricalReplay(replay HistoricalReplay) ([]byte, error) {
	if replay.seal == nil || replay.Mode != "historical" || replay.Status != "MATCH" || replay.CurrentNonRevocation != "not_checked_offline" || (replay.claimExit != 0 && replay.claimExit != 10 && replay.claimExit != 11) {
		return nil, ErrIntegrity
	}
	raw, err := json.Marshal(replay)
	if err != nil || digestBytes(raw) != replay.digest {
		return nil, ErrIntegrity
	}
	return raw, nil
}

func HistoricalClaimExit(replay HistoricalReplay) int {
	if _, err := MarshalHistoricalReplay(replay); err != nil {
		return 3
	}
	return replay.claimExit
}

func boundedReportJSON(raw []byte) bool {
	if len(raw) == 0 || len(raw) > 4<<20 || !utf8.Valid(raw) {
		return false
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	depth := 0
	for tokens := 0; tokens <= 200000; tokens++ {
		token, err := decoder.Token()
		if err == io.EOF {
			return depth == 0 && tokens > 0
		}
		if err != nil {
			return false
		}
		if delimiter, ok := token.(json.Delim); ok {
			switch delimiter {
			case '{', '[':
				depth++
			case '}', ']':
				depth--
			}
			if depth < 0 || depth > 32 {
				return false
			}
		}
	}
	return false
}

func digestBytes(raw []byte) string {
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}
