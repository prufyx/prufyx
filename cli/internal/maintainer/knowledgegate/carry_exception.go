// SPDX-License-Identifier: AGPL-3.0-only

package knowledgegate

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/prufyx/prufyx/cli/internal/maintainer/evidencereattest"
	"github.com/prufyx/prufyx/cli/internal/maintainer/sourcecorpus"
)

// Carry exceptions. An automated reattestation statement moves the dates of
// reviewed evidence without a new derivation, so the gate refuses one unless
// the owner made a signed exception for every record it renews. The
// exception is signed by a pinned owner key (the web-approval key), is read
// from the base tree only, and binds the pack, the record ID, the digest of
// the base record and an expiry. Once the record changes, its base digest
// changes, so an exception admits at most the one renewal it was made for.
const (
	CarryExceptionSchema = "prufyx.io/carry-exception/v1"
	// CarryExceptionDomain prefixes the signed bytes, so no other signature
	// made with the same key is ever an exception, and the reverse.
	CarryExceptionDomain = "prufyx.io/carry-exception/v1\x00"
	// CarryExceptionDir holds <pack>/<hex sha256 of the record ID>.json.
	CarryExceptionDir = "cli/knowledge/carry-exceptions"
	// MaxCarryExceptionLife bounds notAfter minus decidedAt.
	MaxCarryExceptionLife = MaxApprovalAge
)

// CarryExceptionRecord is the signed decision. The field order is the
// order of the signed compact JSON.
type CarryExceptionRecord struct {
	BaseDigest string `json:"baseDigest"`
	DecidedAt  string `json:"decidedAt"`
	Identity   string `json:"identity"`
	NotAfter   string `json:"notAfter"`
	Pack       string `json:"pack"`
	RecordID   string `json:"recordId"`
}

// CarryExceptionEnvelope is the committed file.
type CarryExceptionEnvelope struct {
	Schema    string               `json:"schema"`
	Record    CarryExceptionRecord `json:"record"`
	KeyID     string               `json:"keyId"`
	Signature string               `json:"signature"`
}

// CarryExceptionPath is the one file that can hold the exception for a
// record of a pack. The name is a digest, so a record ID never becomes a
// path.
func CarryExceptionPath(pack, recordID string) string {
	return CarryExceptionDir + "/" + pack + "/" + strings.TrimPrefix(sourcecorpus.SHA([]byte(recordID)), "sha256:") + ".json"
}

func signedCarryBytes(r CarryExceptionRecord) ([]byte, error) {
	for _, v := range []string{r.BaseDigest, r.DecidedAt, r.Identity, r.NotAfter, r.Pack, r.RecordID} {
		if v == "" || len(v) > 512 {
			return nil, errors.New("carry exception: a field is empty or too long")
		}
	}
	raw, err := json.Marshal(r)
	if err != nil {
		return nil, err
	}
	return append([]byte(CarryExceptionDomain), raw...), nil
}

// VerifyCarryException checks one exception file for one record of the base:
// a signature under a pinned, unexpired owner key by a pinned owner, the
// pack and record ID, the digest of the base record, and a decision that is
// not in the future, has not expired at now and lives no longer than
// MaxCarryExceptionLife.
func VerifyCarryException(raw []byte, keys ApprovalKeys, pack, recordID string, baseCanonical []byte, now time.Time) error {
	if len(raw) > maxApprovalBytes {
		return errors.New("carry exception: too large")
	}
	var env CarryExceptionEnvelope
	if err := strictDecode(bytes.TrimSuffix(raw, []byte("\n")), &env); err != nil {
		return fmt.Errorf("carry exception: %w", err)
	}
	if env.Schema != CarryExceptionSchema {
		return errors.New("carry exception: wrong schema")
	}
	signed, err := signedCarryBytes(env.Record)
	if err != nil {
		return err
	}
	var key *ApprovalKey
	for i := range keys.Keys {
		if keys.Keys[i].KeyID == env.KeyID {
			key = &keys.Keys[i]
		}
	}
	if key == nil {
		return errors.New("carry exception: signed by a key that is not pinned")
	}
	if !key.ownerTier() {
		return errBotTierKey("carry exception", *key)
	}
	now = now.UTC()
	keyEnd, err := time.Parse(time.RFC3339, key.NotAfter)
	if err != nil || !now.Before(keyEnd) {
		return errors.New("carry exception: signing key has expired")
	}
	pub, err := hex.DecodeString(key.PublicKey)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return errors.New("carry exception: pinned key is not an Ed25519 key")
	}
	sig, err := base64.StdEncoding.Strict().DecodeString(env.Signature)
	if err != nil || len(sig) != ed25519.SignatureSize || !ed25519.Verify(ed25519.PublicKey(pub), signed, sig) {
		return errors.New("carry exception: signature does not verify")
	}
	r := env.Record
	owner := false
	for _, o := range keys.Owners {
		owner = owner || o == r.Identity
	}
	switch {
	case !owner:
		return fmt.Errorf("carry exception: %s is not an owner", logSafe(r.Identity))
	case r.Pack != pack || r.RecordID != recordID:
		return errors.New("carry exception: made for a different record")
	case baseCanonical == nil || r.BaseDigest != CandidateDigest(baseCanonical):
		return errors.New("carry exception: base digest does not match the record the change replaces")
	}
	decided, err := time.Parse(time.RFC3339, r.DecidedAt)
	if err != nil {
		return errors.New("carry exception: decidedAt")
	}
	until, err := time.Parse(time.RFC3339, r.NotAfter)
	if err != nil {
		return errors.New("carry exception: notAfter")
	}
	switch {
	case decided.After(now.Add(approvalClockSkew)):
		return errors.New("carry exception: decided in the future")
	case !until.After(decided) || until.Sub(decided) > MaxCarryExceptionLife:
		return errors.New("carry exception: notAfter must be after decidedAt and at most 14 days after it")
	case !now.Before(until):
		return errors.New("carry exception: expired")
	}
	return nil
}

// SignCarryException signs an exception for one base record and verifies
// the result as the gate would. Only an owner key signs.
func SignCarryException(key ed25519.PrivateKey, keys ApprovalKeys, rec CarryExceptionRecord, baseCanonical []byte, now time.Time) ([]byte, error) {
	if len(key) != ed25519.PrivateKeySize {
		return nil, errors.New("the signing key is not an Ed25519 private key")
	}
	signed, err := signedCarryBytes(rec)
	if err != nil {
		return nil, err
	}
	env := CarryExceptionEnvelope{
		Schema: CarryExceptionSchema, Record: rec, KeyID: ApprovalKeyID(key.Public().(ed25519.PublicKey)),
		Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(key, signed)),
	}
	raw, err := json.MarshalIndent(env, "", "  ")
	if err != nil {
		return nil, err
	}
	raw = append(raw, '\n')
	if err := VerifyCarryException(raw, keys, rec.Pack, rec.RecordID, baseCanonical, now); err != nil {
		return nil, fmt.Errorf("the signed exception does not verify: %w", err)
	}
	return raw, nil
}

// baseRecordCanonical is the canonical bytes of the base entry or record a
// statement row names; nil when the base holds none.
func baseRecordCanonical(p *loadedPack, id string) []byte {
	if p == nil {
		return nil
	}
	if e := p.Entries[id]; e != nil {
		return e.Canonical
	}
	if r := p.Records[id]; r != nil {
		return r.Canonical
	}
	return nil
}

// carryRefusal says why a statement signed by a role other than the human
// one may not renew anything: every record it renews needs its own owner
// exception in the base. Empty means each has one.
func carryRefusal(base Tree, basePack *loadedPack, pack string, statement evidencereattest.Statement, opts Options) string {
	if len(statement.Rules) == 0 {
		return "an automated statement renews nothing"
	}
	keys, err := baseApprovalKeys(opts)
	if err != nil {
		return "automated carry is refused without an owner exception: " + err.Error()
	}
	var bad []string
	for _, row := range statement.Rules {
		raw, err := base.ReadOptional(CarryExceptionPath(pack, row.RuleID), maxApprovalBytes+1)
		switch {
		case err != nil:
		case raw == nil:
			err = errors.New("no owner exception in the base")
		default:
			err = VerifyCarryException(raw, *keys, pack, row.RuleID, baseRecordCanonical(basePack, row.RuleID), opts.Now)
		}
		if err != nil {
			bad = append(bad, row.RuleID+": "+logSafe(err.Error()))
		}
	}
	if len(bad) == 0 {
		return ""
	}
	sort.Strings(bad)
	return "automated carry is refused without an owner exception for every renewed record" + listDetail(bad)
}

// baseApprovalKeys reads the owner approval key file of the base and holds
// it to the configured digest.
func baseApprovalKeys(opts Options) (*ApprovalKeys, error) {
	raw, err := opts.Base.Read(opts.Layout.ApprovalKeysPath, maxApprovalBytes*4)
	if err != nil {
		return nil, fmt.Errorf("no owner approval key is pinned in the base: %v", err)
	}
	if opts.ApprovalKeysDigest == "" {
		return nil, errors.New("no owner approval key digest is configured")
	}
	if pinnedDigest(raw) != opts.ApprovalKeysDigest {
		return nil, errors.New("the owner approval key file in the base does not match the pinned digest")
	}
	k, err := ParseApprovalKeys(raw)
	if err != nil {
		return nil, err
	}
	return &k, nil
}

// cmdCarryException signs one carry exception on the owner's machine.
func cmdCarryException(args []string, env approvalEnv, layout Layout, stdout io.Writer) (int, error) {
	f := flag.NewFlagSet("approval carry-exception", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	var pack, id, basePack, keysPath, digest, identity, notAfter, output string
	var kf keyFlags
	f.StringVar(&pack, "pack", "", "cncf or community")
	f.StringVar(&id, "record", "", "rule or record ID")
	f.StringVar(&basePack, "base-pack", "", "the pack file of the base")
	f.StringVar(&keysPath, "keys", "", "approval key file")
	f.StringVar(&digest, "keys-digest", "", "pinned digest of the key file")
	f.StringVar(&identity, "identity", "", "owner login")
	f.StringVar(&notAfter, "not-after", "", "expiry, RFC 3339 UTC, at most 14 days from now")
	f.StringVar(&output, "output", "", "new file to write")
	kf.register(f)
	if err := parseApprovalFlags(f, args); err != nil {
		return 2, err
	}
	if pack == "" || id == "" || basePack == "" || keysPath == "" || digest == "" || identity == "" || notAfter == "" || output == "" {
		return 2, usageError{"--pack, --record, --base-pack, --keys, --keys-digest, --identity, --not-after and --output are required"}
	}
	var spec *PackSpec
	for i := range layout.Packs {
		if layout.Packs[i].Name == pack {
			spec = &layout.Packs[i]
		}
	}
	if spec == nil {
		return 2, fmt.Errorf("unknown pack %q", pack)
	}
	keys, err := loadKeysFile(keysPath, digest)
	if err != nil {
		return 2, err
	}
	raw, err := readBoundedFile(basePack, MaxFileBytes)
	if err != nil {
		return 2, err
	}
	p, err := parsePack(*spec, raw)
	if err != nil {
		return 2, err
	}
	canonical := baseRecordCanonical(p, id)
	if canonical == nil {
		return 2, errors.New("the base pack holds no such rule or record")
	}
	key, err := kf.load(env)
	if err != nil {
		return 2, err
	}
	defer wipe(key)
	now := env.now().UTC().Truncate(time.Second)
	rec := CarryExceptionRecord{
		BaseDigest: CandidateDigest(canonical), DecidedAt: now.Format("2006-01-02T15:04:05Z"),
		Identity: identity, NotAfter: notAfter, Pack: pack, RecordID: id,
	}
	signed, err := SignCarryException(key, keys, rec, canonical, now)
	if err != nil {
		return 2, err
	}
	if err := writeApprovalFile(output, signed); err != nil {
		return 2, err
	}
	fmt.Fprintf(stdout, "carry exception for %s %s until %s written to %s\ncommit it as %s\n", pack, logSafe(id), logSafe(notAfter), output, CarryExceptionPath(pack, id))
	return 0, nil
}
