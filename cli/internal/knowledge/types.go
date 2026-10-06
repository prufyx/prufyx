// SPDX-License-Identifier: AGPL-3.0-only

// Package knowledge verifies and stores operator-provisioned offline knowledge
// revisions. It has no downloader and never accepts customer configuration.
package knowledge

import (
	"errors"
	"time"

	"github.com/prufyx/prufyx/cli/internal/cncfcheck"
)

const (
	TargetPath  = "knowledge/cert-manager.v1.json"
	maxRevision = int64(1<<31 - 1)
)

var (
	ErrInvalid          = errors.New("invalid knowledge input")
	ErrIntegrity        = errors.New("knowledge integrity failure")
	ErrExpired          = errors.New("knowledge trust metadata expired")
	ErrRollback         = errors.New("knowledge rollback rejected")
	ErrNoSelection      = errors.New("no verified knowledge selection")
	ErrTrustAdvanced    = errors.New("knowledge trust state advanced beyond selection")
	ErrRecoveryRequired = errors.New("knowledge import recovery required")
)

type SelectionMode string

const (
	SelectionCurrent    SelectionMode = "current"
	SelectionHistorical SelectionMode = "historical"
)

// Admission is returned by the schema-specific semantic validator. TUF proves
// target origin and identity; it does not establish this data contract.
type Admission struct {
	Revision               string
	Purpose                string
	EngineCapabilityDigest string
	HasRule                bool
	RuleDigest             string
	EvidenceExpiresAt      string
}

type AdmitFunc func(target []byte) (Admission, error)

type ImportRequest struct {
	PackagePath         string
	StoreRoot           string
	BootstrapRootPath   string
	BootstrapRootDigest string
	// PinnedRootDigest, when set, requires the store's initial root to be
	// exactly this digest. Later root versions still need the TUF chain.
	PinnedRootDigest     string
	ExpectedRevision     string
	ExpectedBundleDigest string
	// ExpectedPackageDigest binds the exact canonical package bytes read from
	// PackagePath before any store is opened or mutated. It is a local
	// transport assertion, not a trust or source-authority claim.
	ExpectedPackageDigest string
	// ExpectedVerification is an opt-in release-plan assertion. It is checked
	// against material produced by TUF verification and semantic admission; it
	// never supplies bootstrap trust.
	ExpectedVerification *VerificationAssertions
}

// VerificationAssertions binds the exact publisher-verified trust and target
// identity expected by one plan-driven import. PublisherInitialRootDigest is
// descriptive of the publisher's stateless verification input, not a client
// bootstrap root selection.
type VerificationAssertions struct {
	PublisherInitialRootDigest string             `json:"publisherInitialRootDigest"`
	RootHistory                []RootHistoryEntry `json:"rootHistory"`
	Root                       RoleReceipt        `json:"root"`
	Timestamp                  RoleReceipt        `json:"timestamp"`
	Snapshot                   RoleReceipt        `json:"snapshot"`
	Targets                    RoleReceipt        `json:"targets"`
	TargetPath                 string             `json:"targetPath"`
	Purpose                    string             `json:"purpose"`
	EngineCapabilityDigest     string             `json:"engineCapabilityDigest"`
}

// VerifyRequest describes a package-only verification against an explicit,
// operator-provisioned bootstrap root. It deliberately has no StoreRoot:
// verification does not inspect or mutate a knowledge store.
type VerifyRequest struct {
	PackagePath           string
	BootstrapRootPath     string
	BootstrapRootDigest   string
	ExpectedPackageDigest string
	ExpectedRevision      string
	ExpectedBundleDigest  string
}

// PackageVerificationReceipt reports authenticated package and target
// identities. It does not represent an import, selection, or rollback check.
type PackageVerificationReceipt struct {
	APIVersion                  string             `json:"apiVersion"`
	Status                      string             `json:"status"`
	Profile                     string             `json:"profile"`
	VerifiedAt                  string             `json:"verifiedAt"`
	TrustSource                 string             `json:"trustSource"`
	InitialRootDigest           string             `json:"initialRootDigest"`
	RootHistory                 []RootHistoryEntry `json:"rootHistory"`
	Root                        RoleReceipt        `json:"root"`
	Timestamp                   RoleReceipt        `json:"timestamp"`
	Snapshot                    RoleReceipt        `json:"snapshot"`
	Targets                     RoleReceipt        `json:"targets"`
	PackageDigest               string             `json:"packageDigest"`
	TargetPath                  string             `json:"targetPath"`
	TargetLength                int64              `json:"targetLength"`
	TargetDigest                string             `json:"targetDigest"`
	KnowledgeRevision           string             `json:"knowledgeRevision"`
	Purpose                     string             `json:"purpose"`
	EngineCapabilityDigest      string             `json:"engineCapabilityDigest"`
	HasRule                     bool               `json:"hasRule"`
	RuleDigest                  string             `json:"ruleDigest"`
	EvidenceExpiresAt           string             `json:"evidenceExpiresAt"`
	ExpectedPackageDigest       string             `json:"expectedPackageDigest,omitempty"`
	ExpectedRevision            string             `json:"expectedRevision,omitempty"`
	ExpectedBundleDigest        string             `json:"expectedBundleDigest,omitempty"`
	NetworkUsed                 bool               `json:"networkUsed"`
	StoreUsed                   bool               `json:"storeUsed"`
	StoreChanged                bool               `json:"storeChanged"`
	RollbackAgainstStoreChecked bool               `json:"rollbackAgainstStoreChecked"`
	ImportEligibility           string             `json:"importEligibility"`
	// ProjectTargets lists every verified project target of a per-project
	// package. It is empty for single-target profiles.
	ProjectTargets []ProjectTargetReceipt `json:"projectTargets,omitempty"`
}

type SelectionRequest struct {
	StoreRoot                  string
	ExpectedRevision           string
	ExpectedBundleDigest       string
	ExpectedTrustReceiptDigest string
}

type RoleReceipt struct {
	Version int64  `json:"version"`
	Digest  string `json:"digest"`
	Expires string `json:"expires"`
}

type RootHistoryEntry struct {
	Version int64  `json:"version"`
	Digest  string `json:"digest"`
}

// TrustReceipt binds the exact TUF state and target admitted by one import.
// TrustSource is intentionally operator-provisioned in this slice.
type TrustReceipt struct {
	APIVersion                           string             `json:"apiVersion"`
	TrustSource                          string             `json:"trustSource"`
	VerifiedAt                           string             `json:"verifiedAt"`
	InitialRootDigest                    string             `json:"initialRootDigest"`
	RootHistory                          []RootHistoryEntry `json:"rootHistory"`
	Root                                 RoleReceipt        `json:"root"`
	Timestamp                            RoleReceipt        `json:"timestamp"`
	Snapshot                             RoleReceipt        `json:"snapshot"`
	Targets                              RoleReceipt        `json:"targets"`
	TargetPath                           string             `json:"targetPath"`
	TargetLength                         int64              `json:"targetLength"`
	TargetDigest                         string             `json:"targetDigest"`
	KnowledgeRevision                    string             `json:"knowledgeRevision"`
	Purpose                              string             `json:"purpose"`
	EngineCapabilityDigest               string             `json:"engineCapabilityDigest"`
	HasRule                              bool               `json:"hasRule"`
	RuleDigest                           string             `json:"ruleDigest"`
	EvidenceExpiresAt                    string             `json:"evidenceExpiresAt"`
	ExpectedRevision                     string             `json:"expectedRevision,omitempty"`
	ExpectedBundleDigest                 string             `json:"expectedBundleDigest,omitempty"`
	ExpectedVerificationAssertionsDigest string             `json:"expectedVerificationAssertionsDigest,omitempty"`
}

type ImportReceipt struct {
	APIVersion         string       `json:"apiVersion"`
	Status             string       `json:"status"`
	TrustStateAdvanced bool         `json:"trustStateAdvanced"`
	SelectionChanged   bool         `json:"selectionChanged"`
	TrustStateDigest   string       `json:"trustStateDigest"`
	TrustReceipt       TrustReceipt `json:"trustReceipt"`
	TrustReceiptDigest string       `json:"trustReceiptDigest"`
	AdmissionPath      string       `json:"admissionPath"`
	// ProjectTargets lists the verified project targets of a per-project
	// import. It is empty for single-target profiles.
	ProjectTargets []ProjectTargetReceipt `json:"projectTargets,omitempty"`
}

type Status struct {
	APIVersion           string `json:"apiVersion"`
	State                string `json:"state"`
	Reason               string `json:"reason"`
	NextAction           string `json:"nextAction"`
	CheckedAt            string `json:"checkedAt"`
	TrustSource          string `json:"trustSource"`
	TrustStateDigest     string `json:"trustStateDigest"`
	RootVersion          int64  `json:"rootVersion"`
	TimestampVersion     int64  `json:"timestampVersion,omitempty"`
	SnapshotVersion      int64  `json:"snapshotVersion,omitempty"`
	TargetsVersion       int64  `json:"targetsVersion,omitempty"`
	SelectedRevision     string `json:"selectedRevision,omitempty"`
	Purpose              string `json:"purpose,omitempty"`
	SelectedBundleDigest string `json:"selectedBundleDigest,omitempty"`
	TrustReceiptDigest   string `json:"trustReceiptDigest,omitempty"`
	CurrentEligible      bool   `json:"currentEligible"`
	// Freshness is retained as the legacy TUF metadata freshness field. The
	// explicit projections below prevent callers from confusing it with source
	// review freshness.
	Freshness               string `json:"freshness"`
	TrustFreshness          string `json:"trustFreshness,omitempty"`
	SourceEvidenceFreshness string `json:"sourceEvidenceFreshness,omitempty"`
	SourceEvidenceExpiresAt string `json:"sourceEvidenceExpiresAt,omitempty"`
	NetworkChecked          bool   `json:"networkChecked"`
	CurrentNonRevocation    string `json:"currentNonRevocation"`
}

// VerifiedRevision is an immutable in-process capability. Callers can only
// obtain one after the store revalidates the selected admission.
type VerifiedRevision struct {
	bytes              []byte
	revision           string
	bundleDigest       string
	trustReceipt       TrustReceipt
	trustReceiptDigest string
	verifiedAt         time.Time
	mode               SelectionMode
	profile            profileID
	// projects holds the verified project targets requested from a
	// per-project store. The bytes above are then the index target.
	projects map[string]ProjectTarget
	seal     *verifiedSeal
}

type verifiedSeal struct{}

func (v VerifiedRevision) Bytes() []byte        { return append([]byte(nil), v.bytes...) }
func (v VerifiedRevision) Revision() string     { return v.revision }
func (v VerifiedRevision) BundleDigest() string { return v.bundleDigest }
func (v VerifiedRevision) TrustReceipt() TrustReceipt {
	r := v.trustReceipt
	r.RootHistory = append([]RootHistoryEntry(nil), r.RootHistory...)
	return r
}
func (v VerifiedRevision) TrustReceiptDigest() string { return v.trustReceiptDigest }
func (v VerifiedRevision) VerifiedAt() time.Time      { return v.verifiedAt }
func (v VerifiedRevision) Mode() SelectionMode        { return v.mode }
func (v VerifiedRevision) Valid() bool {
	if v.seal == nil || (v.mode != SelectionCurrent && v.mode != SelectionHistorical) || v.verifiedAt.IsZero() {
		return false
	}
	if v.profile != 0 {
		p := profileForID(v.profile)
		if !p.valid() || v.trustReceipt.TargetPath != p.targetPath {
			return false
		}
	}
	if (v.profile == profileConstraintsProjects) != (v.projects != nil) {
		return false
	}
	for project, target := range v.projects {
		if target.Project != project || target.Path != cncfcheck.ProjectTargetPath(project) || digestBytes(target.bytes) != target.Digest {
			return false
		}
	}
	receipt, err := marshalCanonical(v.trustReceipt)
	return err == nil && digestBytes(receipt) == v.trustReceiptDigest && digestBytes(v.bytes) == v.bundleDigest && v.revision == v.trustReceipt.KnowledgeRevision
}

// PerProject reports whether this revision was opened from a per-project
// store. Its Bytes are then the index target, and project targets are
// available through ProjectTarget.
func (v VerifiedRevision) PerProject() bool { return v.profile == profileConstraintsProjects }

// ProjectTarget returns one verified project target. It is absent when the
// selected index lists no target for the project or it was not requested.
func (v VerifiedRevision) ProjectTarget(project string) (ProjectTarget, bool) {
	target, ok := v.projects[project]
	if !ok {
		return ProjectTarget{}, false
	}
	target.bytes = append([]byte(nil), target.bytes...)
	return target, true
}
