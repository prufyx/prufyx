// SPDX-License-Identifier: AGPL-3.0-only

// Package knowledgepublish prepares exact TUF signing payloads and finalizes
// an externally signed CNCF knowledge package. It never creates, loads, or
// persists private signing keys and performs no network operation.
package knowledgepublish

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/prufyx/prufyx/cli/internal/cncfcheck"
	"github.com/prufyx/prufyx/cli/internal/knowledge"
	"github.com/prufyx/prufyx/cli/internal/knowledgereleaseplan"
	"github.com/secure-systems-lab/go-securesystemslib/cjson"
	"github.com/theupdateframework/go-tuf/v2/metadata"
)

const (
	SignatureEnvelopeSchema = "prufyx.io/external-tuf-signatures/v1"
	SigningRequestSchema    = "prufyx.io/tuf-signing-request/v1"
	FinalReceiptSchema      = "prufyx.io/knowledge-publisher-finalization/v1"
	MaxRootBytes            = 128 << 10
	MaxRoleBytes            = 512 << 10
	MaxTargetBytes          = 1 << 20
	MaxEnvelopeBytes        = 128 << 10
)

var (
	ErrRejected = errors.New("knowledge publication input rejected")
	digestRE    = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	keyIDRE     = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// Preparation is the complete public handoff for one external signing step.
// Payload is the exact OLPC-canonical JSON byte sequence signed by go-tuf.
type Preparation struct {
	Role             string
	UnsignedMetadata []byte
	Payload          []byte
	Request          []byte
}

// SignatureEnvelope carries signatures produced outside Prufyx. The signer
// must bind PayloadDigest before returning this closed envelope.
type SignatureEnvelope struct {
	Schema        string           `json:"schema"`
	Role          string           `json:"role"`
	PayloadDigest string           `json:"payloadDigest"`
	Signatures    []SignatureInput `json:"signatures"`
}

type SignatureInput struct {
	KeyID string `json:"keyid"`
	Sig   string `json:"sig"`
}

type signingRequest struct {
	Schema                 string   `json:"schema"`
	Role                   string   `json:"role"`
	PayloadFormat          string   `json:"payloadFormat"`
	PayloadDigest          string   `json:"payloadDigest"`
	PayloadLength          int      `json:"payloadLength"`
	UnsignedMetadataDigest string   `json:"unsignedMetadataDigest"`
	RootDigest             string   `json:"rootDigest"`
	RoleVersion            int64    `json:"roleVersion"`
	Expires                string   `json:"expires"`
	AuthorizedKeyIDs       []string `json:"authorizedKeyIDs"`
	Threshold              int      `json:"threshold"`
	TargetDigest           string   `json:"targetDigest,omitempty"`
	PriorMetadataDigest    string   `json:"priorMetadataDigest,omitempty"`
}

type FinalizationReceipt struct {
	Schema            string                               `json:"schema"`
	Status            string                               `json:"status"`
	Profile           string                               `json:"profile"`
	NetworkUsed       bool                                 `json:"networkUsed"`
	KeysHandled       bool                                 `json:"keysHandled"`
	RootDigest        string                               `json:"rootDigest"`
	TargetDigest      string                               `json:"targetDigest"`
	PackageDigest     string                               `json:"packageDigest"`
	KnowledgeRevision string                               `json:"knowledgeRevision"`
	CapabilityDigest  string                               `json:"capabilityDigest"`
	Verification      knowledge.PackageVerificationReceipt `json:"verification"`
}

type TargetsOptions struct {
	Root, Target []byte
	RootDigest   string
	Version      int64
	Expires      string
}

type SnapshotOptions struct {
	Root, Target, Targets []byte
	RootDigest            string
	Version               int64
	Expires               string
}

type TimestampOptions struct {
	Root, Target, Targets, Snapshot []byte
	RootDigest                      string
	Version                         int64
	Expires                         string
}

type FinalizePackageOptions struct {
	Root, Target, Targets, Snapshot, Timestamp []byte
	RootDigest                                 string
}

// FinalizePackageWithReleasePlan generates a release plan only from the exact
// package and in-memory verification receipt returned by FinalizePackage. It
// never accepts a saved receipt and the plan grants no bootstrap authority.
func FinalizePackageWithReleasePlan(opts FinalizePackageOptions, packageURL string) ([]byte, []byte, FinalizationReceipt, error) {
	packageRaw, receipt, err := FinalizePackage(opts)
	if err != nil {
		return nil, nil, FinalizationReceipt{}, err
	}
	verification := receipt.Verification
	if receipt.Status != "VERIFIED_FOR_PACKAGING" || receipt.Profile != "cncf" || receipt.NetworkUsed || receipt.KeysHandled ||
		receipt.PackageDigest != digest(packageRaw) || verification.Status != "VERIFIED" || verification.Profile != "cncf" ||
		verification.NetworkUsed || verification.StoreUsed || verification.StoreChanged ||
		verification.PackageDigest != receipt.PackageDigest || verification.TargetDigest != receipt.TargetDigest ||
		verification.KnowledgeRevision != receipt.KnowledgeRevision || verification.EngineCapabilityDigest != receipt.CapabilityDigest ||
		verification.InitialRootDigest != receipt.RootDigest {
		return nil, nil, FinalizationReceipt{}, ErrRejected
	}
	plan := knowledgereleaseplan.Plan{
		Schema:    knowledgereleaseplan.Schema,
		Authority: knowledgereleaseplan.Authority,
		Profile:   "cncf",
		Package:   knowledgereleaseplan.Package{URL: packageURL, Digest: receipt.PackageDigest},
		Target: knowledgereleaseplan.Target{
			Path: verification.TargetPath, Revision: receipt.KnowledgeRevision,
			Digest: receipt.TargetDigest, Purpose: verification.Purpose,
			EngineCapabilityDigest: receipt.CapabilityDigest,
		},
		PublisherVerification: knowledgereleaseplan.PublisherVerification{
			Mode: knowledgereleaseplan.RootMode, PublisherInitialRootDigest: verification.InitialRootDigest,
			RootHistory: append([]knowledge.RootHistoryEntry(nil), verification.RootHistory...),
			Root:        verification.Root, Timestamp: verification.Timestamp,
			Snapshot: verification.Snapshot, Targets: verification.Targets,
		},
	}
	planRaw, err := knowledgereleaseplan.Marshal(plan)
	if err != nil {
		return nil, nil, FinalizationReceipt{}, ErrRejected
	}
	return packageRaw, planRaw, receipt, nil
}

// PrepareTargets creates an unsigned targets role and its exact signing payload.
func PrepareTargets(opts TargetsOptions) (Preparation, error) {
	root, rootDigest, err := admitRoot(opts.Root, opts.RootDigest)
	if err != nil {
		return Preparation{}, err
	}
	targetDigest, _, err := admitTarget(opts.Target)
	if err != nil {
		return Preparation{}, err
	}
	expires, err := parseExpiry(opts.Expires)
	if err != nil || !validVersion(opts.Version) {
		return Preparation{}, ErrRejected
	}
	targetInfo, err := metadata.TargetFile().FromBytes(knowledge.ConstraintsTargetPath, opts.Target, "sha256")
	if err != nil {
		return Preparation{}, fmt.Errorf("target identity: %w", ErrRejected)
	}
	role := metadata.Targets(expires)
	role.Signed.Version = opts.Version
	role.Signed.Targets[knowledge.ConstraintsTargetPath] = targetInfo
	return prepare(metadata.TARGETS, root, rootDigest, role, targetDigest, "")
}

// PrepareSnapshot verifies finalized targets and creates the dependent snapshot payload.
func PrepareSnapshot(opts SnapshotOptions) (Preparation, error) {
	root, rootDigest, err := admitRoot(opts.Root, opts.RootDigest)
	if err != nil {
		return Preparation{}, err
	}
	targetDigest, _, err := admitTarget(opts.Target)
	if err != nil {
		return Preparation{}, err
	}
	targets, err := parseTargets(opts.Targets, true)
	if err != nil || root.VerifyDelegate(metadata.TARGETS, targets) != nil || validateTargets(targets, opts.Target) != nil {
		return Preparation{}, fmt.Errorf("signed targets: %w", ErrRejected)
	}
	expires, err := parseExpiry(opts.Expires)
	if err != nil || !validVersion(opts.Version) {
		return Preparation{}, ErrRejected
	}
	role := metadata.Snapshot(expires)
	role.Signed.Version = opts.Version
	role.Signed.Meta["targets.json"] = metaIdentity(targets.Signed.Version, opts.Targets)
	return prepare(metadata.SNAPSHOT, root, rootDigest, role, targetDigest, digest(opts.Targets))
}

// PrepareTimestamp verifies the target/targets/snapshot chain and creates the timestamp payload.
func PrepareTimestamp(opts TimestampOptions) (Preparation, error) {
	root, rootDigest, err := admitRoot(opts.Root, opts.RootDigest)
	if err != nil {
		return Preparation{}, err
	}
	targetDigest, _, err := admitTarget(opts.Target)
	if err != nil {
		return Preparation{}, err
	}
	targets, snapshot, err := admitTargetsSnapshot(root, opts.Target, opts.Targets, opts.Snapshot)
	if err != nil || validateSnapshot(snapshot, opts.Targets, targets.Signed.Version) != nil {
		return Preparation{}, fmt.Errorf("signed snapshot chain: %w", ErrRejected)
	}
	expires, err := parseExpiry(opts.Expires)
	if err != nil || !validVersion(opts.Version) {
		return Preparation{}, ErrRejected
	}
	role := metadata.Timestamp(expires)
	role.Signed.Version = opts.Version
	role.Signed.Meta["snapshot.json"] = metaIdentity(snapshot.Signed.Version, opts.Snapshot)
	return prepare(metadata.TIMESTAMP, root, rootDigest, role, targetDigest, digest(opts.Snapshot))
}

// FinalizeRole attaches externally returned signatures and verifies the
// authorized threshold under the independently supplied public root.
func FinalizeRole(rootRaw []byte, rootDigest, roleName string, unsigned, envelopeRaw []byte) ([]byte, error) {
	root, _, err := admitRoot(rootRaw, rootDigest)
	if err != nil {
		return nil, err
	}
	envelope, err := parseSignatureEnvelope(envelopeRaw, roleName)
	if err != nil {
		return nil, err
	}
	switch roleName {
	case metadata.TARGETS:
		role, parseErr := parseTargets(unsigned, false)
		if parseErr != nil || validateTargetsShape(role) != nil || validateUnsignedPayload(roleName, role.Signed, envelope) != nil {
			return nil, ErrRejected
		}
		role.Signatures = tufSignatures(envelope)
		if root.VerifyDelegate(roleName, role) != nil {
			return nil, fmt.Errorf("targets signature threshold: %w", ErrRejected)
		}
		return role.ToBytes(false)
	case metadata.SNAPSHOT:
		role, parseErr := parseSnapshot(unsigned, false)
		if parseErr != nil || validateSnapshotShape(role) != nil || validateUnsignedPayload(roleName, role.Signed, envelope) != nil {
			return nil, ErrRejected
		}
		role.Signatures = tufSignatures(envelope)
		if root.VerifyDelegate(roleName, role) != nil {
			return nil, fmt.Errorf("snapshot signature threshold: %w", ErrRejected)
		}
		return role.ToBytes(false)
	case metadata.TIMESTAMP:
		role, parseErr := parseTimestamp(unsigned, false)
		if parseErr != nil || validateTimestampShape(role) != nil || validateUnsignedPayload(roleName, role.Signed, envelope) != nil {
			return nil, ErrRejected
		}
		role.Signatures = tufSignatures(envelope)
		if root.VerifyDelegate(roleName, role) != nil {
			return nil, fmt.Errorf("timestamp signature threshold: %w", ErrRejected)
		}
		return role.ToBytes(false)
	default:
		return nil, ErrRejected
	}
}

// FinalizePackage verifies the complete signed chain with the existing
// consumer verifier at the actual clock before returning canonical package bytes.
func FinalizePackage(opts FinalizePackageOptions) ([]byte, FinalizationReceipt, error) {
	root, rootDigest, err := admitRoot(opts.Root, opts.RootDigest)
	if err != nil {
		return nil, FinalizationReceipt{}, err
	}
	return finalizeAdmittedPackage(opts.Root, rootDigest, root, nil, opts.Target, opts.Targets, opts.Snapshot, opts.Timestamp)
}

func prepare[T metadata.Roles](roleName string, root *metadata.Metadata[metadata.RootType], rootDigest string, role *metadata.Metadata[T], targetDigest, priorDigest string) (Preparation, error) {
	unsigned, err := role.ToBytes(false)
	if err != nil {
		return Preparation{}, ErrRejected
	}
	payload, err := cjson.EncodeCanonical(role.Signed)
	if err != nil {
		return Preparation{}, ErrRejected
	}
	delegation := root.Signed.Roles[roleName]
	if delegation == nil || delegation.Threshold < 1 {
		return Preparation{}, ErrRejected
	}
	keyIDs := append([]string(nil), delegation.KeyIDs...)
	sort.Strings(keyIDs)
	request, err := json.Marshal(signingRequest{
		Schema: SigningRequestSchema, Role: roleName, PayloadFormat: "olpc_canonical_json_signed", PayloadDigest: digest(payload), PayloadLength: len(payload),
		UnsignedMetadataDigest: digest(unsigned), RootDigest: rootDigest, RoleVersion: roleVersion(role), Expires: roleExpiry(role),
		AuthorizedKeyIDs: keyIDs, Threshold: delegation.Threshold, TargetDigest: targetDigest, PriorMetadataDigest: priorDigest,
	})
	if err != nil {
		return Preparation{}, ErrRejected
	}
	return Preparation{Role: roleName, UnsignedMetadata: unsigned, Payload: payload, Request: request}, nil
}

func admitRoot(raw []byte, expected string) (*metadata.Metadata[metadata.RootType], string, error) {
	if len(raw) == 0 || len(raw) > MaxRootBytes || !digestRE.MatchString(expected) || digest(raw) != expected {
		return nil, "", fmt.Errorf("root identity: %w", ErrRejected)
	}
	root, err := metadata.Root().FromBytes(raw)
	if err != nil || !validVersion(root.Signed.Version) || rootPolicy(root, true) != nil {
		return nil, "", fmt.Errorf("root policy: %w", ErrRejected)
	}
	canonical, err := root.ToBytes(false)
	if err != nil || !bytes.Equal(raw, canonical) {
		return nil, "", fmt.Errorf("root canonical: %w", ErrRejected)
	}
	return root, expected, nil
}

func admitTarget(raw []byte) (string, cncfcheck.ExternalAdmission, error) {
	if len(raw) == 0 || len(raw) > MaxTargetBytes || !json.Valid(raw) {
		return "", cncfcheck.ExternalAdmission{}, ErrRejected
	}
	var compact bytes.Buffer
	if json.Compact(&compact, raw) != nil || !bytes.Equal(compact.Bytes(), raw) {
		return "", cncfcheck.ExternalAdmission{}, fmt.Errorf("target is not compact canonical JSON: %w", ErrRejected)
	}
	bundle, err := cncfcheck.ParseExternalBundle(raw)
	if err != nil {
		return "", cncfcheck.ExternalAdmission{}, fmt.Errorf("target admission: %w", ErrRejected)
	}
	admission, err := bundle.Admission()
	if err != nil || admission.Purpose != "operator_provided" {
		return "", cncfcheck.ExternalAdmission{}, fmt.Errorf("target purpose: %w", ErrRejected)
	}
	return bundle.BundleDigest(), admission, nil
}

func admitTargetsSnapshot(root *metadata.Metadata[metadata.RootType], target, targetsRaw, snapshotRaw []byte) (*metadata.Metadata[metadata.TargetsType], *metadata.Metadata[metadata.SnapshotType], error) {
	targets, err := parseTargets(targetsRaw, true)
	if err != nil || root.VerifyDelegate(metadata.TARGETS, targets) != nil || validateTargets(targets, target) != nil {
		return nil, nil, ErrRejected
	}
	snapshot, err := parseSnapshot(snapshotRaw, true)
	if err != nil || root.VerifyDelegate(metadata.SNAPSHOT, snapshot) != nil {
		return nil, nil, ErrRejected
	}
	return targets, snapshot, nil
}

func validateTargets(role *metadata.Metadata[metadata.TargetsType], target []byte) error {
	if validateTargetsShape(role) != nil {
		return ErrRejected
	}
	info := role.Signed.Targets[knowledge.ConstraintsTargetPath]
	if info == nil || info.Length != int64(len(target)) || info.Custom != nil || len(info.UnrecognizedFields) != 0 || len(info.Hashes) != 1 || !bytes.Equal(info.Hashes["sha256"], sha256Bytes(target)) {
		return ErrRejected
	}
	return nil
}

func validateTargetsShape(role *metadata.Metadata[metadata.TargetsType]) error {
	if role == nil || role.Signed.Type != metadata.TARGETS || !validVersion(role.Signed.Version) || role.Signed.Expires.IsZero() || !strings.HasPrefix(role.Signed.SpecVersion, "1.0.") || len(role.Signed.Targets) != 1 || role.Signed.Delegations != nil || len(role.Signed.UnrecognizedFields) != 0 || len(role.UnrecognizedFields) != 0 {
		return ErrRejected
	}
	info := role.Signed.Targets[knowledge.ConstraintsTargetPath]
	if info == nil || info.Length < 1 || info.Length > MaxTargetBytes || info.Custom != nil || len(info.UnrecognizedFields) != 0 || len(info.Hashes) != 1 || len(info.Hashes["sha256"]) != sha256.Size {
		return ErrRejected
	}
	return nil
}

func validateSnapshot(role *metadata.Metadata[metadata.SnapshotType], targetsRaw []byte, targetsVersion int64) error {
	if validateSnapshotShape(role) != nil {
		return ErrRejected
	}
	return validateMeta(role.Signed.Meta["targets.json"], targetsRaw, targetsVersion)
}

func validateSnapshotShape(role *metadata.Metadata[metadata.SnapshotType]) error {
	if role == nil || role.Signed.Type != metadata.SNAPSHOT || !validVersion(role.Signed.Version) || role.Signed.Expires.IsZero() || !strings.HasPrefix(role.Signed.SpecVersion, "1.0.") || len(role.Signed.Meta) != 1 || len(role.Signed.UnrecognizedFields) != 0 || len(role.UnrecognizedFields) != 0 || validateMetaShape(role.Signed.Meta["targets.json"]) != nil {
		return ErrRejected
	}
	return nil
}

func validateTimestamp(role *metadata.Metadata[metadata.TimestampType], snapshotRaw []byte, snapshotVersion int64) error {
	if validateTimestampShape(role) != nil {
		return ErrRejected
	}
	return validateMeta(role.Signed.Meta["snapshot.json"], snapshotRaw, snapshotVersion)
}

func validateTimestampShape(role *metadata.Metadata[metadata.TimestampType]) error {
	if role == nil || role.Signed.Type != metadata.TIMESTAMP || !validVersion(role.Signed.Version) || role.Signed.Expires.IsZero() || !strings.HasPrefix(role.Signed.SpecVersion, "1.0.") || len(role.Signed.Meta) != 1 || len(role.Signed.UnrecognizedFields) != 0 || len(role.UnrecognizedFields) != 0 || validateMetaShape(role.Signed.Meta["snapshot.json"]) != nil {
		return ErrRejected
	}
	return nil
}

func validateMetaShape(info *metadata.MetaFiles) error {
	if info == nil || !validVersion(info.Version) || info.Length < 1 || info.Length > MaxRoleBytes || len(info.Hashes) != 1 || len(info.Hashes["sha256"]) != sha256.Size || len(info.UnrecognizedFields) != 0 {
		return ErrRejected
	}
	return nil
}

func validateMeta(info *metadata.MetaFiles, raw []byte, version int64) error {
	if validateMetaShape(info) != nil || info.Version != version || info.Length != int64(len(raw)) || !bytes.Equal(info.Hashes["sha256"], sha256Bytes(raw)) {
		return ErrRejected
	}
	return nil
}

func parseTargets(raw []byte, signed bool) (*metadata.Metadata[metadata.TargetsType], error) {
	if len(raw) == 0 || len(raw) > MaxRoleBytes {
		return nil, ErrRejected
	}
	role, err := metadata.Targets().FromBytes(raw)
	if err != nil || role == nil || (signed && len(role.Signatures) == 0) || (!signed && len(role.Signatures) != 0) {
		return nil, ErrRejected
	}
	canonical, err := role.ToBytes(false)
	if err != nil || !bytes.Equal(canonical, raw) {
		return nil, ErrRejected
	}
	return role, nil
}

func parseSnapshot(raw []byte, signed bool) (*metadata.Metadata[metadata.SnapshotType], error) {
	if len(raw) == 0 || len(raw) > MaxRoleBytes {
		return nil, ErrRejected
	}
	role, err := metadata.Snapshot().FromBytes(raw)
	if err != nil || role == nil || (signed && len(role.Signatures) == 0) || (!signed && len(role.Signatures) != 0) {
		return nil, ErrRejected
	}
	canonical, err := role.ToBytes(false)
	if err != nil || !bytes.Equal(canonical, raw) {
		return nil, ErrRejected
	}
	return role, nil
}

func parseTimestamp(raw []byte, signed bool) (*metadata.Metadata[metadata.TimestampType], error) {
	if len(raw) == 0 || len(raw) > MaxRoleBytes {
		return nil, ErrRejected
	}
	role, err := metadata.Timestamp().FromBytes(raw)
	if err != nil || role == nil || (signed && len(role.Signatures) == 0) || (!signed && len(role.Signatures) != 0) {
		return nil, ErrRejected
	}
	canonical, err := role.ToBytes(false)
	if err != nil || !bytes.Equal(canonical, raw) {
		return nil, ErrRejected
	}
	return role, nil
}

func parseSignatureEnvelope(raw []byte, role string) (SignatureEnvelope, error) {
	if len(raw) == 0 || len(raw) > MaxEnvelopeBytes {
		return SignatureEnvelope{}, ErrRejected
	}
	var envelope SignatureEnvelope
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&envelope) != nil || decoder.Decode(&struct{}{}) == nil || envelope.Schema != SignatureEnvelopeSchema || envelope.Role != role || !digestRE.MatchString(envelope.PayloadDigest) || len(envelope.Signatures) < 1 || len(envelope.Signatures) > 32 {
		return SignatureEnvelope{}, ErrRejected
	}
	canonical, err := json.Marshal(envelope)
	if err != nil || !bytes.Equal(canonical, raw) {
		return SignatureEnvelope{}, ErrRejected
	}
	previous := ""
	for _, signature := range envelope.Signatures {
		decoded, err := hex.DecodeString(signature.Sig)
		if !keyIDRE.MatchString(signature.KeyID) || signature.KeyID <= previous || err != nil || len(decoded) != 64 || signature.Sig != strings.ToLower(signature.Sig) {
			return SignatureEnvelope{}, ErrRejected
		}
		previous = signature.KeyID
	}
	return envelope, nil
}

func validateUnsignedPayload[T metadata.Roles](roleName string, signed T, envelope SignatureEnvelope) error {
	payload, err := cjson.EncodeCanonical(signed)
	if err != nil || envelope.Role != roleName || envelope.PayloadDigest != digest(payload) {
		return ErrRejected
	}
	return nil
}

func tufSignatures(envelope SignatureEnvelope) []metadata.Signature {
	result := make([]metadata.Signature, 0, len(envelope.Signatures))
	for _, value := range envelope.Signatures {
		raw, _ := hex.DecodeString(value.Sig)
		result = append(result, metadata.Signature{KeyID: value.KeyID, Signature: metadata.HexBytes(raw)})
	}
	return result
}

func metaIdentity(version int64, raw []byte) *metadata.MetaFiles {
	return &metadata.MetaFiles{Version: version, Length: int64(len(raw)), Hashes: metadata.Hashes{"sha256": metadata.HexBytes(sha256Bytes(raw))}}
}

func parseExpiry(value string) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil || parsed.Location() != time.UTC || parsed.Format(time.RFC3339) != value || !strings.HasSuffix(value, "Z") {
		return time.Time{}, ErrRejected
	}
	return parsed, nil
}

func validVersion(version int64) bool { return version > 0 && version <= int64(^uint32(0)>>1) }

func roleVersion[T metadata.Roles](role *metadata.Metadata[T]) int64 {
	switch value := any(role).(type) {
	case *metadata.Metadata[metadata.TargetsType]:
		return value.Signed.Version
	case *metadata.Metadata[metadata.SnapshotType]:
		return value.Signed.Version
	case *metadata.Metadata[metadata.TimestampType]:
		return value.Signed.Version
	default:
		return 0
	}
}

func roleExpiry[T metadata.Roles](role *metadata.Metadata[T]) string {
	switch value := any(role).(type) {
	case *metadata.Metadata[metadata.TargetsType]:
		return value.Signed.Expires.UTC().Format(time.RFC3339)
	case *metadata.Metadata[metadata.SnapshotType]:
		return value.Signed.Expires.UTC().Format(time.RFC3339)
	case *metadata.Metadata[metadata.TimestampType]:
		return value.Signed.Expires.UTC().Format(time.RFC3339)
	default:
		return ""
	}
}

func sha256Bytes(raw []byte) []byte { sum := sha256.Sum256(raw); return sum[:] }
func digest(raw []byte) string      { return "sha256:" + hex.EncodeToString(sha256Bytes(raw)) }
