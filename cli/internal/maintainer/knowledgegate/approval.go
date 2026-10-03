// SPDX-License-Identifier: AGPL-3.0-only

package knowledgegate

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"time"

	"github.com/prufyx/prufyx/cli/internal/strictjson"
)

// Owner approval records. An approval is the owner's signed decision that
// one exact pack entry may replace one exact base state (an earlier entry,
// or no entry) as a reviewed rule. The signing key is the web-approval key;
// its public half is pinned in the base tree and its file digest in the
// gate's configuration, so a change cannot bring its own key.
//
// Version 2 binds the base state. Version 1 records, which bound only the
// proposed entry and could be replayed after the rule was withdrawn, are
// refused.
const (
	ApprovalSchema     = "prufyx.io/knowledge-approval/v2"
	ApprovalKeysSchema = "prufyx.io/web-approval-keys/v1"
	ApprovalKeyRole    = "web-approval"
	// ApprovalDomain prefixes the signed bytes, so an approval signature
	// can never be mistaken for any other signature made with the key.
	ApprovalDomain = "prufyx.io/knowledge-approval/v2\x00"
	// ApprovalBaseAbsent is the base digest of an approval for a rule the
	// base does not hold.
	ApprovalBaseAbsent = "absent"
	// ApprovalDecisionApprove is the only decision that admits a change.
	ApprovalDecisionApprove = "approve"
	// MaxApprovalAge is how long an approval stays usable.
	MaxApprovalAge = 14 * 24 * time.Hour
	// approvalClockSkew tolerates a signer clock slightly ahead of the gate.
	approvalClockSkew = 5 * time.Minute
	maxApprovalBytes  = 16 << 10
)

// ApprovalRecord is the signed content. Every field is plain ASCII from a
// restricted alphabet, so its canonical form is unambiguous in any JSON
// implementation.
type ApprovalRecord struct {
	// BaseDigest is the digest of the base entry the approval replaces
	// (see CandidateDigest), or ApprovalBaseAbsent for a new rule.
	BaseDigest      string `json:"baseDigest"`
	CandidateDigest string `json:"candidateDigest"`
	CandidateID     string `json:"candidateId"`
	DecidedAt       string `json:"decidedAt"`
	Decision        string `json:"decision"`
	Identity        string `json:"identity"`
	Pack            string `json:"pack"`
	RuleID          string `json:"ruleId"`
}

// ApprovalEnvelope is the committed file: the record, the signing key id
// and the Ed25519 signature (standard base64) over ApprovalDomain followed
// by the record's compact JSON with keys in the order above.
type ApprovalEnvelope struct {
	Schema    string         `json:"schema"`
	Record    ApprovalRecord `json:"record"`
	KeyID     string         `json:"keyId"`
	Signature string         `json:"signature"`
}

// ApprovalKeys is the pinned key file.
type ApprovalKeys struct {
	Schema string `json:"schema"`
	Role   string `json:"role"`
	// Owners are the identities whose approvals count (GitHub logins).
	Owners []string      `json:"owners"`
	Keys   []ApprovalKey `json:"keys"`
}

// ApprovalKey is one pinned public key. KeyID is "sha256:" and the hex
// sha256 of the raw 32-byte public key.
type ApprovalKey struct {
	KeyID     string `json:"keyId"`
	PublicKey string `json:"publicKey"` // hex, 32 bytes
	NotAfter  string `json:"notAfter"`
}

var (
	approvalTokenRE  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
	approvalLoginRE  = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$`)
	approvalDigestRE = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	approvalTimeRE   = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$`)
)

// SignedApprovalBytes returns the exact bytes an approval signature covers.
func SignedApprovalBytes(r ApprovalRecord) ([]byte, error) {
	if err := r.validate(); err != nil {
		return nil, err
	}
	raw, err := json.Marshal(r)
	if err != nil {
		return nil, err
	}
	return append([]byte(ApprovalDomain), raw...), nil
}

func (r ApprovalRecord) validate() error {
	if (r.BaseDigest != ApprovalBaseAbsent && !approvalDigestRE.MatchString(r.BaseDigest)) || !approvalDigestRE.MatchString(r.CandidateDigest) || !approvalTokenRE.MatchString(r.CandidateID) || !approvalTimeRE.MatchString(r.DecidedAt) ||
		!approvalTokenRE.MatchString(r.Decision) || !approvalLoginRE.MatchString(r.Identity) || !approvalTokenRE.MatchString(r.Pack) || !approvalTokenRE.MatchString(r.RuleID) {
		return errors.New("approval record field out of range")
	}
	return nil
}

// ApprovalKeyID is the key id of a raw Ed25519 public key.
func ApprovalKeyID(public ed25519.PublicKey) string {
	sum := sha256.Sum256(public)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// CandidateDigest is the digest an approval binds: sha256 of the entry's
// canonical JSON (keys sorted, two-space indent, one final newline), the
// entry read as admission reads it.
func CandidateDigest(canonicalEntry []byte) string {
	sum := sha256.Sum256(canonicalEntry)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func strictDecode(raw []byte, v any) error {
	if err := strictjson.Check(raw); err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if dec.More() {
		return errors.New("trailing data")
	}
	return nil
}

// ParseApprovalKeys parses and checks the pinned key file.
func ParseApprovalKeys(raw []byte) (ApprovalKeys, error) {
	var k ApprovalKeys
	if err := strictDecode(raw, &k); err != nil {
		return ApprovalKeys{}, fmt.Errorf("approval keys: %w", err)
	}
	if k.Schema != ApprovalKeysSchema || k.Role != ApprovalKeyRole || len(k.Owners) == 0 || len(k.Keys) == 0 {
		return ApprovalKeys{}, errors.New("approval keys: wrong schema, role, or no owners or keys")
	}
	for _, o := range k.Owners {
		if !approvalLoginRE.MatchString(o) {
			return ApprovalKeys{}, fmt.Errorf("approval keys: owner %q", o)
		}
	}
	seen := map[string]bool{}
	for _, key := range k.Keys {
		pub, err := hex.DecodeString(key.PublicKey)
		if err != nil || len(pub) != ed25519.PublicKeySize || key.KeyID != ApprovalKeyID(pub) || seen[key.KeyID] || !approvalTimeRE.MatchString(key.NotAfter) {
			return ApprovalKeys{}, fmt.Errorf("approval keys: key %q", key.KeyID)
		}
		seen[key.KeyID] = true
	}
	return k, nil
}

// VerifyApproval checks one approval envelope for one proposed entry: the
// signature under a pinned, unexpired key; an approving decision by a
// pinned owner; the pack and rule id; a decision time not in the future
// and at most MaxApprovalAge old; a candidate digest equal to the digest
// of the proposed entry's canonical bytes; and a base digest equal to the
// digest of the base entry's canonical bytes (baseEntry nil: the base has
// no such rule, and the record must say ApprovalBaseAbsent).
func VerifyApproval(raw []byte, keys ApprovalKeys, pack, ruleID string, baseEntry, canonicalEntry []byte, now time.Time) error {
	if len(raw) > maxApprovalBytes {
		return errors.New("approval too large")
	}
	var env ApprovalEnvelope
	if err := strictDecode(bytes.TrimSuffix(raw, []byte("\n")), &env); err != nil {
		return fmt.Errorf("approval: %w", err)
	}
	if env.Schema != ApprovalSchema {
		return errors.New("approval: wrong schema")
	}
	signed, err := SignedApprovalBytes(env.Record)
	if err != nil {
		return fmt.Errorf("approval: %w", err)
	}
	var key *ApprovalKey
	for i := range keys.Keys {
		if keys.Keys[i].KeyID == env.KeyID {
			key = &keys.Keys[i]
		}
	}
	if key == nil {
		return errors.New("approval: signed by a key that is not pinned")
	}
	now = now.UTC()
	notAfter, err := time.Parse(time.RFC3339, key.NotAfter)
	if err != nil || !now.Before(notAfter) {
		return errors.New("approval: signing key has expired")
	}
	pub, _ := hex.DecodeString(key.PublicKey)
	sig, err := base64.StdEncoding.Strict().DecodeString(env.Signature)
	if err != nil || len(sig) != ed25519.SignatureSize || !ed25519.Verify(ed25519.PublicKey(pub), signed, sig) {
		return errors.New("approval: signature does not verify")
	}
	r := env.Record
	owner := false
	for _, o := range keys.Owners {
		if o == r.Identity {
			owner = true
		}
	}
	switch {
	case !owner:
		return fmt.Errorf("approval: %s is not an owner", r.Identity)
	case r.Decision != ApprovalDecisionApprove:
		return fmt.Errorf("approval: decision is %q", r.Decision)
	case r.Pack != pack || r.RuleID != ruleID:
		return errors.New("approval: approves a different rule")
	}
	decided, err := time.Parse(time.RFC3339, r.DecidedAt)
	if err != nil {
		return errors.New("approval: decidedAt")
	}
	if decided.After(now.Add(approvalClockSkew)) {
		return errors.New("approval: decided in the future")
	}
	if now.Sub(decided) > MaxApprovalAge {
		return errors.New("approval: older than 14 days")
	}
	if r.CandidateDigest != CandidateDigest(canonicalEntry) {
		return errors.New("approval: candidate digest does not match the proposed entry")
	}
	wantBase := ApprovalBaseAbsent
	if baseEntry != nil {
		wantBase = CandidateDigest(baseEntry)
	}
	if r.BaseDigest != wantBase {
		return errors.New("approval: base digest does not match the rule the change replaces")
	}
	return nil
}
