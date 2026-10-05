// SPDX-License-Identifier: AGPL-3.0-only

package knowledgegate

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/prufyx/prufyx/cli/internal/constraintengine"
	"github.com/prufyx/prufyx/cli/internal/maintainer/repinbaselines"
)

// Signing owner approvals. The signer builds the record from the same pack
// reading the gate classifies with, signs the exact bytes the gate checks
// (SignedApprovalBytes), and runs the gate's own VerifyApproval on the result
// before anything is written, so a file it produces is one the gate accepts
// for that base and head.

// ApprovalSubjectRule is the subject kind of an approval for one pack entry.
const ApprovalSubjectRule = "rule"

// MaxApprovalKeyBytes bounds a private key file or stdin key.
const MaxApprovalKeyBytes = 4 << 10

const pemPrivateKeyType = "PRIVATE KEY"

// ParseApprovalPrivateKey reads an Ed25519 private key in PKCS #8 PEM form
// (one PEM block of type PRIVATE KEY, as written by OpenSSL 3
// "openssl genpkey -algorithm ed25519"). The input must start with that
// block's BEGIN line and may end with line breaks only; nothing else is
// accepted. Errors never contain any of the input. The decoded copies are
// wiped on a best-effort basis only.
func ParseApprovalPrivateKey(raw []byte) (ed25519.PrivateKey, error) {
	refused := errors.New("the key is not one Ed25519 private key in PKCS #8 PEM form")
	end := []byte("-----END " + pemPrivateKeyType + "-----")
	if len(raw) > MaxApprovalKeyBytes || !bytes.HasPrefix(raw, []byte("-----BEGIN "+pemPrivateKeyType+"-----")) ||
		bytes.Count(raw, end) != 1 || len(bytes.Trim(raw[bytes.Index(raw, end)+len(end):], "\r\n")) != 0 {
		return nil, refused
	}
	block, rest := pem.Decode(raw)
	if block == nil || block.Type != pemPrivateKeyType || len(block.Headers) != 0 || len(bytes.Trim(rest, "\r\n")) != 0 {
		if block != nil {
			wipe(block.Bytes)
		}
		return nil, refused
	}
	defer wipe(block.Bytes)
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, refused
	}
	key, ok := parsed.(ed25519.PrivateKey)
	if !ok || len(key) != ed25519.PrivateKeySize {
		return nil, refused
	}
	return key, nil
}

func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// ApprovalSubject is what one approval is for, read from the base and head
// pack files exactly as the gate reads them.
type ApprovalSubject struct {
	Kind   string
	Pack   string
	RuleID string
	// Scope is set for a baseline approval: the repository.
	Scope string
	// Base is the canonical base entry (nil: the base has no such rule);
	// Candidate the canonical proposed entry.
	Base, Candidate []byte
	// BaseEntry and HeadEntry are the decoded entries of a baseline
	// subject (BaseEntry nil: none in the base).
	BaseEntry, HeadEntry *repinbaselines.Entry
}

// BaseDigest is the record's baseDigest for the subject.
func (s ApprovalSubject) BaseDigest() string {
	if s.Base == nil {
		return ApprovalBaseAbsent
	}
	return CandidateDigest(s.Base)
}

// RuleApprovalSubject reads one rule's base and proposed entries from the
// pack files of the base and the head. It refuses a rule the head does not
// hold, a rule held twice, an entry the gate would not admit by approval
// (any basis other than reviewed), an entry the change leaves as it is and
// a change the gate classifies as tightening (it needs no approval, and an
// approval file for it would fail the gate's records check).
func RuleApprovalSubject(spec PackSpec, basePack, headPack []byte, ruleID string) (ApprovalSubject, error) {
	if !approvalTokenRE.MatchString(ruleID) {
		return ApprovalSubject{}, errors.New("the rule id is not a valid approval rule id")
	}
	base, err := parsePack(spec, basePack)
	if err != nil {
		return ApprovalSubject{}, fmt.Errorf("base pack: %w", err)
	}
	head, err := parsePack(spec, headPack)
	if err != nil {
		return ApprovalSubject{}, fmt.Errorf("proposed pack: %w", err)
	}
	h := head.Entries[ruleID]
	if h == nil {
		return ApprovalSubject{}, fmt.Errorf("the proposed pack has no rule %s", ruleID)
	}
	if b := h.effectiveBasis(); b != constraintengine.BasisReviewed {
		return ApprovalSubject{}, fmt.Errorf("rule %s has evidence basis %q; an approval admits only a reviewed rule", ruleID, logSafe(b))
	}
	s := ApprovalSubject{Kind: ApprovalSubjectRule, Pack: spec.Name, RuleID: ruleID, Candidate: h.Canonical}
	if b := base.Entries[ruleID]; b != nil {
		if bytes.Equal(b.Canonical, h.Canonical) {
			return ApprovalSubject{}, fmt.Errorf("rule %s is the same in the base and the proposed pack; there is nothing to approve", ruleID)
		}
		if class, kinds := classifyEdit(b, h); class != ClassLoosening {
			return ApprovalSubject{}, fmt.Errorf("the change to rule %s is %s (%s), not loosening: it needs no approval, and the gate refuses an approval file for it", ruleID, class, strings.Join(kinds, ", "))
		}
		s.Base = b.Canonical
	} else if h.Evidence.State == "withdrawn" {
		return ApprovalSubject{}, fmt.Errorf("rule %s is added withdrawn, which is not loosening: it needs no approval, and the gate refuses an approval file for it", ruleID)
	}
	return s, nil
}

// LoadApprovalKeys checks a web-approval key file against its pinned digest
// (sha256 of the file without its final newline, as the gate computes it)
// and parses it.
func LoadApprovalKeys(raw []byte, pinned string) (ApprovalKeys, error) {
	if !approvalDigestRE.MatchString(pinned) {
		return ApprovalKeys{}, errors.New("the pinned key file digest must be sha256: and 64 lowercase hex digits")
	}
	if ApprovalKeysDigest(raw) != pinned {
		return ApprovalKeys{}, errors.New("the approval key file does not match the pinned digest")
	}
	return ParseApprovalKeys(raw)
}

// ApprovalKeysDigest is the digest the gate pins for a key file.
func ApprovalKeysDigest(raw []byte) string { return pinnedDigest(raw) }

// SignApprovalOptions is one approval to sign.
type SignApprovalOptions struct {
	Subject     ApprovalSubject
	CandidateID string
	Identity    string
	Keys        ApprovalKeys
	Key         ed25519.PrivateKey
	Now         time.Time
}

// SignApproval signs one approval and returns the file to commit. It
// refuses a key that is not pinned or has expired, an identity that is not
// a pinned owner, and any record the gate's verifier would refuse at Now.
func SignApproval(o SignApprovalOptions) ([]byte, ApprovalRecord, error) {
	if o.Subject.Kind != ApprovalSubjectRule && o.Subject.Kind != ApprovalSubjectRepinBaseline {
		return nil, ApprovalRecord{}, fmt.Errorf("approval subject kind %q is not supported", logSafe(o.Subject.Kind))
	}
	if len(o.Key) != ed25519.PrivateKeySize {
		return nil, ApprovalRecord{}, errors.New("the signing key is not an Ed25519 private key")
	}
	if o.Now.IsZero() {
		return nil, ApprovalRecord{}, errors.New("no signing time")
	}
	now := o.Now.UTC().Truncate(time.Second)
	keyID := ApprovalKeyID(o.Key.Public().(ed25519.PublicKey))
	var pinned *ApprovalKey
	for i := range o.Keys.Keys {
		if o.Keys.Keys[i].KeyID == keyID {
			pinned = &o.Keys.Keys[i]
		}
	}
	if pinned == nil {
		return nil, ApprovalRecord{}, fmt.Errorf("the signing key %s is not pinned in the approval key file", keyID)
	}
	notAfter, err := time.Parse(time.RFC3339, pinned.NotAfter)
	if err != nil || !now.Before(notAfter) {
		return nil, ApprovalRecord{}, fmt.Errorf("the signing key %s expired at %s", keyID, pinned.NotAfter)
	}
	owner := false
	for _, login := range o.Keys.Owners {
		owner = owner || login == o.Identity
	}
	if !owner {
		return nil, ApprovalRecord{}, fmt.Errorf("%s is not an owner in the approval key file", logSafe(o.Identity))
	}
	rec := ApprovalRecord{
		BaseDigest:      o.Subject.BaseDigest(),
		CandidateDigest: CandidateDigest(o.Subject.Candidate),
		CandidateID:     o.CandidateID,
		DecidedAt:       now.Format("2006-01-02T15:04:05Z"),
		Decision:        ApprovalDecisionApprove,
		Identity:        o.Identity,
		Pack:            o.Subject.Pack,
		RuleID:          o.Subject.RuleID,
	}
	if o.Subject.Kind == ApprovalSubjectRepinBaseline {
		rec.Subject, rec.Scope = ApprovalSubjectRepinBaseline, o.Subject.Scope
	}
	msg, err := SignedApprovalBytes(rec)
	if err != nil {
		return nil, ApprovalRecord{}, errors.New("approval record field out of range (candidate id, identity, pack or rule id)")
	}
	env := ApprovalEnvelope{Schema: ApprovalSchema, Record: rec, KeyID: keyID, Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(o.Key, msg))}
	raw, err := json.MarshalIndent(env, "", "  ")
	if err != nil {
		return nil, ApprovalRecord{}, err
	}
	raw = append(raw, '\n')
	if err := VerifyApprovalSubject(raw, o.Keys, o.Subject, now); err != nil {
		return nil, ApprovalRecord{}, fmt.Errorf("the signed approval does not verify: %w", err)
	}
	return raw, rec, nil
}

// VerifyApprovalSubject is the gate's check of one approval file for one
// subject at now.
func VerifyApprovalSubject(raw []byte, keys ApprovalKeys, s ApprovalSubject, now time.Time) error {
	switch s.Kind {
	case ApprovalSubjectRule:
	case ApprovalSubjectRepinBaseline:
		return verifyBaselineSubject(raw, keys, s, now)
	default:
		return fmt.Errorf("approval subject kind %q is not supported", logSafe(s.Kind))
	}
	return VerifyApproval(raw, keys, s.Pack, s.RuleID, s.Base, s.Candidate, now)
}

// ApprovalUsableUntil is when an approval stops being accepted: 14 days
// after its decision, or earlier when its key expires first.
func ApprovalUsableUntil(rec ApprovalRecord, key ApprovalKey) string {
	decided, err1 := time.Parse(time.RFC3339, rec.DecidedAt)
	notAfter, err2 := time.Parse(time.RFC3339, key.NotAfter)
	if err1 != nil || err2 != nil {
		return "unknown"
	}
	until := decided.Add(MaxApprovalAge)
	if notAfter.Before(until) {
		until = notAfter
	}
	return until.UTC().Format(time.RFC3339)
}
