// SPDX-License-Identifier: AGPL-3.0-only

// Package evidencereattest implements the "evidence reattest
// prepare|sign|verify" maintainer subcommand: a deterministic, code-only
// batch renewal of the review lease on rule evidence whose citations a fresh
// "evidence repin" run classified as mechanically unchanged.
//
// It never re-derives or alters what a rule claims. A batch re-attestation
// renews exactly two fields on a rule's evidence block, reviewedAt and
// validUntil; every other byte of the rule is required to stay identical,
// enforced by requiring the recomputed next pack to be byte-identical to the
// supplied one (see checkV3). Eligibility for the batch is computed here,
// from a retained "evidence repin" worklist and the rule pack itself; it is
// never accepted as a caller-supplied claim (see Prepare and checkV3 in
// Verify, which recomputes eligibility and the whole statement from scratch
// and requires an exact byte match against what the caller supplied).
//
// The three subcommands are a pipeline:
//
//	prepare - reads a worklist, the current rule pack, and the pack's
//	          signed statement chain (see Chain), computes which rules
//	          qualify for batch renewal, and emits a canonical statement
//	          plus a candidate "next" pack with only the qualifying rules'
//	          reviewedAt/validUntil fields changed. It writes no production
//	          pack file and needs no signing key.
//	sign    - a human, at a terminal only, signs the exact statement bytes
//	          prepare produced with an Ed25519 key under a pinned trust
//	          root whose digest the caller supplies independently. It
//	          refuses to run unattended (no TTY) and refuses a statement
//	          whose sampled-for-full-review rules lack a recorded review.
//	verify  - deterministic, side-effect-free, CI-usable. It requires the
//	          pack's statement chain to extend the base branch's chain by
//	          at most the statement itself (checkAppendOnly), verifies the
//	          chain with the same derivation prepare uses
//	          (deriveChainState), recomputes the whole statement and the
//	          whole next pack from scratch and requires them to match the
//	          supplied bytes exactly, then checks every further invariant
//	          (V2, V4-V7), with a non-zero process exit from its CLI
//	          adapter on any violation. It also requires a valid signature
//	          under a pinned trust root whenever the statement renews at
//	          least one rule.
//
// This package does not wire a re-attestation statement into the runtime
// pack loader or the embedded rule pack; publishing a re-attested pack is a
// separate step. It also does not decide where the re-attestation signing
// key and its trust root are stored: ProductionTrustRootPath below is
// intentionally unset, and every function that needs a trust root takes it,
// and its digest, as an explicit caller-supplied input instead.
package evidencereattest

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/prufyx/prufyx/cli/internal/maintainer/sourcecorpus"
	"github.com/secure-systems-lab/go-securesystemslib/cjson"
	"github.com/theupdateframework/go-tuf/v2/metadata"
)

const (
	// StatementSchema identifies the canonical signed re-attestation payload.
	StatementSchema = "prufyx.io/evidence-reattestation/v1"
	// EnvelopeSchema identifies the detached signature container.
	EnvelopeSchema = "prufyx.io/evidence-reattestation-signature/v1"
	// TrustRootSchema identifies the pinned set of keys that may sign a
	// re-attestation statement. It is a different key purpose from both the
	// TUF roles and community-release signing: a signature made for one
	// purpose can never verify against another (see Purpose).
	TrustRootSchema = "prufyx.io/evidence-reattestation-trust-root/v1"

	// Purpose and Audience are bound into every statement and trust root so
	// a signature cannot be replayed across contexts.
	Purpose  = "rule-evidence-reattestation"
	Audience = "prufyx-rule-pack"

	// Authority restates plainly, inside the signed bytes, what this
	// artifact is: a renewal of an existing lease, never a new claim.
	Authority = "HUMAN_REATTESTATION_OF_MECHANICALLY_UNCHANGED_CITATIONS_NOT_A_NEW_CLAIM"

	// PackCNCF and PackCommunity name the two rule packs this command
	// understands, matching corpusattest's naming.
	PackCNCF      = "cncf"
	PackCommunity = "community"

	// ProductionTrustRootPath is intentionally unset: no production trust
	// root is configured anywhere in this repository. Every function that
	// verifies or produces a signature takes the trust root, and its
	// expected digest, as explicit caller-supplied inputs; nothing in this
	// package ever reads a path implied by this constant.
	ProductionTrustRootPath = ""

	// MaxWorklistBytes, MaxPackBytes, MaxStatementBytes, MaxEnvelopeBytes,
	// and MaxTrustRootBytes bound every parsed input. MaxWorklistBytes is
	// capped at 8 MiB to match currentbundle's own bounded-read ceiling,
	// which the CLI adapter reads every file through.
	MaxWorklistBytes     = 8 << 20
	MaxPackBytes         = 8 << 20
	MaxStatementBytes    = 8 << 20
	MaxEnvelopeBytes     = 64 << 10
	MaxTrustRootBytes    = 128 << 10
	MaxReviewRecordBytes = 256 << 10

	// freshnessBound is E4's per-repo and worklist-age bound.
	freshnessBound = 72 * time.Hour
	// maxLease is the 90-day policy-v1 window (V2), the same bound the
	// engine and pack loaders already enforce.
	maxLease = 90 * 24 * time.Hour
	// maxConsecutiveBatchCycles is E6's two-cycle cap: a rule may be batch
	// renewed at most twice in a row before it must go through an
	// individual review.
	maxConsecutiveBatchCycles = 2

	// renewalWindow is how close to expiry a rule's current lease must be
	// for a batch to renew it: three weekly waves. A rule whose validUntil
	// is further than this from attestedAt is not yet due (NOT_YET_DUE).
	// Without it, weekly batches each renewing into a slot one week later
	// than the last would pick the same just-renewed rules again every
	// week and spend their two-cycle budget within days.
	renewalWindow = 3 * 7 * 24 * time.Hour

	// minWave and maxWave bound the seven-wave stagger. Assignment of
	// projects to waves is not implemented here; this package only
	// computes the slot date for a given wave number (see SlotDate).
	minWave = 1
	maxWave = 7

	// staggerCapPercent is V7: an ISO week this batch renews rules into
	// may hold at most floor(staggerCapPercent% of the pack's rule count)
	// validUntil values, and never fewer than one (see staggerCap).
	staggerCapPercent = 15

	// MaxChainEntries bounds how many signed statements one pack's
	// statement chain may hold.
	MaxChainEntries = 4096

	// sampleFraction is the seeded full-review sample rate.
	sampleFraction = 0.10

	// slotCycleDays is the length, in days, of the repeating cycle over
	// which each of the maxWave waves recurs once: 7 days per wave, times
	// maxWave waves. It is deliberately shorter than maxLease, so the next
	// occurrence of any given wave's slot after any attestedAt is always
	// within the 90-day lease cap (see SlotDate).
	slotCycleDays = 7 * maxWave
)

// slotCycleAnchor is an arbitrary fixed instant that anchors the repeating
// weekly cycle; only its weekday and time-of-day (Monday 12:00 UTC) carry
// meaning, not the specific calendar date. Wave 1's slot recurs every
// slotCycleDays days starting from this instant, wave 2 one week after
// that, and so on through wave maxWave.
var slotCycleAnchor = time.Date(2027, 1, 4, 12, 0, 0, 0, time.UTC)

// SlotDate returns the next occurrence of wave k's (1..maxWave) recurring
// slot date that is strictly after attestedAt. Because the full cycle
// (slotCycleDays) is shorter than the 90-day lease cap (maxLease), the
// returned date is always within the cap of attestedAt, for every wave and
// every attestedAt: the cycle never runs out.
func SlotDate(wave int, attestedAt time.Time) (time.Time, error) {
	if wave < minWave || wave > maxWave {
		return time.Time{}, fmt.Errorf("%w: wave out of range", ErrRejected)
	}
	cycle := time.Duration(slotCycleDays) * 24 * time.Hour
	base := slotCycleAnchor.AddDate(0, 0, 7*(wave-1))
	attestedAt = attestedAt.UTC()
	// Step in whichever direction is needed so base always lands within
	// one cycle of attestedAt before the final adjustment below. This
	// keeps the loop short and correct whether attestedAt is before or
	// long after the anchor occurrence.
	for base.Sub(attestedAt) > cycle {
		base = base.Add(-cycle)
	}
	for !base.After(attestedAt) {
		base = base.Add(cycle)
	}
	return base, nil
}

// ErrRejected is the single opaque rejection this package returns. Detailed
// reasons stay in error wrapping for logs, never in a value a caller could
// use as an eligibility oracle.
var ErrRejected = errors.New("evidence reattest rejected")

// ---------------------------------------------------------------------
// Statement shape
// ---------------------------------------------------------------------

// PackVersion is one side (prior or next) of the pack binding.
type PackVersion struct {
	Revision      string `json:"revision"`
	PackDigest    string `json:"packDigest"`
	RuleSetDigest string `json:"ruleSetDigest"`
}

// PackRef binds the statement to one exact rule pack transition.
type PackRef struct {
	Name     string `json:"name"`
	Schema   string `json:"schema"`
	PolicyID string `json:"policyId"`
	// PolicyDigest is read from the pack file's own declared value, not
	// recomputed here; ingestion already computes and pins it.
	PolicyDigest string `json:"policyDigest"`
	// EngineCapabilityDigest identifies the compiled parser/engine/registry
	// this statement was prepared against. For the CNCF pack this is
	// cncfcheck.ExternalCapabilityDigest(); the community pack exposes no
	// equivalent external capability surface (no external profile exists
	// for it at all), so its EngineCapabilityDigest is the generic engine
	// contract digest instead. This is a known, documented gap, not a
	// silent substitution: see cli/docs/evidence-reattestation.md.
	EngineCapabilityDigest string      `json:"engineCapabilityDigest"`
	Prior                  PackVersion `json:"prior"`
	Next                   PackVersion `json:"next"`
}

// WorklistRef binds the statement to the exact retained "evidence repin"
// worklist it was computed from.
type WorklistRef struct {
	Schema               string `json:"schema"`
	Digest               string `json:"digest"`
	GeneratedAt          string `json:"generatedAt"`
	OldestRepoResolvedAt string `json:"oldestRepoResolvedAt"`
	Pending              int    `json:"pending"`
	// ToolIdentityDigest identifies this command's own build identity. No
	// build-provenance system exists in this repository yet, so this is a
	// fixed, documented placeholder digest (see ToolIdentity), not a
	// reproducible binary attestation.
	ToolIdentityDigest string `json:"toolIdentityDigest"`
}

// CitationAttestation is one cited source's mechanical classification, as
// carried into the signed statement.
type CitationAttestation struct {
	SourceID       string `json:"sourceId"`
	Class          string `json:"class"`
	PinnedCommit   string `json:"pinnedCommit"`
	ComparedTag    string `json:"comparedTag"`
	ComparedCommit string `json:"comparedCommit"`
	ContentDigest  string `json:"contentDigest"`
	// Baseline, BaselineLine and PinnedTag are set only when the citation
	// was compared with the newest release on its pinned tag's release line
	// rather than with the repository's most recent release; ComparedTag
	// is then that line's tag.
	Baseline     string `json:"baseline,omitempty"`
	BaselineLine string `json:"baselineLine,omitempty"`
	PinnedTag    string `json:"pinnedTag,omitempty"`
}

// RuleAttestation is one batch-renewed rule.
type RuleAttestation struct {
	RuleID                 string                `json:"ruleId"`
	Project                string                `json:"project"`
	PriorRuleDigest        string                `json:"priorRuleDigest"`
	NextRuleDigest         string                `json:"nextRuleDigest"`
	SourcesDigest          string                `json:"sourcesDigest"`
	PriorReviewedAt        string                `json:"priorReviewedAt"`
	LastIndividualReviewAt string                `json:"lastIndividualReviewAt"`
	ConsecutiveBatchCycles int                   `json:"consecutiveBatchCycles"`
	Citations              []CitationAttestation `json:"citations"`
}

// SampledEntry is one rule the seeded 10% audit selected for full individual
// review before signing may proceed.
type SampledEntry struct {
	RuleID string `json:"ruleId"`
	// ReviewRecordDigest is empty until a review record for this rule is
	// supplied to Prepare (--review-record-dir); Sign refuses to sign a
	// statement carrying any empty entry here (see checkSampleReviewed).
	ReviewRecordDigest string `json:"reviewRecordDigest"`
}

// IndividualReview is one individual review record supplied for a rule
// in this pack whose digest has never been recorded for that rule earlier
// in the pack's statement chain. Recording it here, inside the signed
// statement, is what resets that rule's consecutive-batch-cycle count
// (see chainState.apply).
type IndividualReview struct {
	RuleID             string `json:"ruleId"`
	ReviewRecordDigest string `json:"reviewRecordDigest"`
}

// NotExtendedEntry is one rule this batch could not renew, with the worst
// (most expensive) reason found.
type NotExtendedEntry struct {
	RuleID     string `json:"ruleId"`
	WorstClass string `json:"worstClass"`
}

// UpstreamRelease is the single most recent published release repin found
// for one cited repository. It is NOT a full release list since the last
// attestation: repin resolves only the current release (see
// evidencerepin's package doc), so this field is a documented partial
// acknowledgement, not a complete review of every upstream change since
// the prior attestation. Not implemented: fetching and acknowledging the
// full release list for each cited repository.
type UpstreamRelease struct {
	Repo string   `json:"repo"`
	Tags []string `json:"tags"`
}

// Statement is the canonical, signed re-attestation payload. Its exact
// canonical bytes (see CanonicalStatement) are both the on-disk form and the
// signed payload; there is no second serialization.
type Statement struct {
	Schema    string  `json:"schema"`
	Purpose   string  `json:"purpose"`
	Audience  string  `json:"audience"`
	Authority string  `json:"authority"`
	Pack      PackRef `json:"pack"`
	// PreviousAttestationDigest is nil for the first statement in a pack's
	// chain, and the digest of the chain's current head otherwise (V5).
	PreviousAttestationDigest *string           `json:"previousAttestationDigest"`
	Worklist                  WorklistRef       `json:"worklist"`
	Wave                      int               `json:"wave"`
	AttestedAt                string            `json:"attestedAt"`
	ValidUntil                string            `json:"validUntil"`
	Rules                     []RuleAttestation `json:"rules"`
	SampledForFullReview      []SampledEntry    `json:"sampledForFullReview"`
	// IndividualReviews lists every rule in the prior pack for which a
	// review record was supplied whose digest the chain has not recorded
	// for that rule before, sorted by rule ID.
	IndividualReviews          []IndividualReview `json:"individualReviews"`
	NotExtended                []NotExtendedEntry `json:"notExtended"`
	UpstreamReleasesSincePrior []UpstreamRelease  `json:"upstreamReleasesSincePrior"`
	// Statement is the fixed text a human signs (see FixedStatementText).
	Statement string `json:"statement"`
}

// Envelope is the detached signature over the exact canonical statement bytes.
type Envelope struct {
	SchemaVersion   string          `json:"schemaVersion"`
	StatementDigest string          `json:"statementDigest"`
	Signatures      []SignatureLine `json:"signatures"`
}

// SignatureLine is one signer's contribution.
type SignatureLine struct {
	KeyID string `json:"keyId"`
	Sig   string `json:"sig"`
}

// TrustRoot is the pinned set of keys authorized to sign a re-attestation
// statement. It is a different key purpose from release signing and from
// the TUF roles (see Purpose), distributed and verified by digest, never
// fetched by this package.
type TrustRoot struct {
	SchemaVersion string     `json:"schemaVersion"`
	Purpose       string     `json:"purpose"`
	Expires       string     `json:"expires"`
	Threshold     int        `json:"threshold"`
	Keys          []TrustKey `json:"keys"`
}

// TrustKey is one authorized signer identity.
type TrustKey struct {
	KeyID     string `json:"keyId"`
	KeyType   string `json:"keyType"`
	Scheme    string `json:"scheme"`
	PublicKey string `json:"publicKey"`
}

// ToolIdentity is the fixed, documented placeholder tool identity bound
// into every worklist reference (see WorklistRef.ToolIdentityDigest). No
// reproducible build-provenance system exists in this repository yet; this
// is deliberately a constant, not a runtime-derived value, so it never
// creates an appearance of provenance this tool cannot back.
const ToolIdentity = "prufyx-maintainer-evidence-reattest/v1"

func toolIdentityDigest() string { return sourcecorpus.SHA([]byte(ToolIdentity)) }

// FixedStatementText renders the exact fixed text a human signs, with
// generatedAt and validUntil interpolated. It is never free-form: no field
// in the statement lets a caller or an agent author its own text.
func FixedStatementText(generatedAt, validUntil string) string {
	return "I ran `evidence repin` at `" + generatedAt + "` with no reused state. " +
		"Every listed citation was mechanically classified NO_NEW_RELEASE, FILE_IDENTICAL or SPAN_IDENTICAL " +
		"against the listed upstream commit. I reviewed the listed upstream releases for errata affecting the " +
		"listed rules and found none. I fully re-reviewed the sampled rules. No rule content other than " +
		"reviewedAt and validUntil changes. This renews the maintainer review lease for these rules until `" +
		validUntil + "`. It is not a new compatibility claim."
}

// ---------------------------------------------------------------------
// Canonical encode/decode (mirrors releasesign's pattern; reused directly
// where the helper already exists: cjson for OLPC canonical bytes,
// sourcecorpus.SHA for digesting, knowledgesign for key custody).
// ---------------------------------------------------------------------

func canonicalBytes(value any) ([]byte, error) {
	raw, err := cjson.EncodeCanonical(value)
	if err != nil || len(raw) == 0 {
		return nil, ErrRejected
	}
	return raw, nil
}

func decodeExact[T any](raw []byte, limit int) (T, error) {
	var zero T
	if len(raw) == 0 || len(raw) > limit {
		return zero, ErrRejected
	}
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	var value T
	if err := decoder.Decode(&value); err != nil {
		return zero, ErrRejected
	}
	if decoder.More() {
		return zero, ErrRejected
	}
	encoded, err := canonicalBytes(value)
	if err != nil || string(encoded) != string(raw) {
		return zero, ErrRejected
	}
	return value, nil
}

// CanonicalStatement renders a Statement's exact canonical bytes.
func CanonicalStatement(s Statement) ([]byte, error) { return canonicalBytes(s) }

// ParseStatement validates bounded canonical statement bytes: strict
// decode, round-trip to the exact same bytes, and every fixed field pinned
// to its required value.
func ParseStatement(raw []byte) (Statement, error) {
	statement, err := decodeExact[Statement](raw, MaxStatementBytes)
	if err != nil {
		return Statement{}, err
	}
	if statement.Schema != StatementSchema || statement.Purpose != Purpose || statement.Audience != Audience || statement.Authority != Authority {
		return Statement{}, ErrRejected
	}
	if statement.Statement != FixedStatementText(statement.Worklist.GeneratedAt, statement.ValidUntil) {
		return Statement{}, ErrRejected
	}
	if statement.Wave < minWave || statement.Wave > maxWave {
		return Statement{}, ErrRejected
	}
	if _, err := parseUTC(statement.AttestedAt); err != nil {
		return Statement{}, ErrRejected
	}
	if _, err := parseUTC(statement.ValidUntil); err != nil {
		return Statement{}, ErrRejected
	}
	return statement, nil
}

func parseUTC(value string) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil || !strings.HasSuffix(value, "Z") || parsed.UTC().Format(time.RFC3339) != value {
		return time.Time{}, ErrRejected
	}
	return parsed.UTC(), nil
}

// ParseTrustRoot validates bounded canonical trust-root bytes against the
// declared digest and clock, and requires the reattestation purpose so it
// can never be substituted for a release or TUF root.
func ParseTrustRoot(raw []byte, expectedDigest string, now time.Time) (TrustRoot, error) {
	if !validDigest(expectedDigest) || sourcecorpus.SHA(raw) != expectedDigest {
		return TrustRoot{}, ErrRejected
	}
	root, err := decodeExact[TrustRoot](raw, MaxTrustRootBytes)
	if err != nil {
		return TrustRoot{}, err
	}
	if root.SchemaVersion != TrustRootSchema || root.Purpose != Purpose {
		return TrustRoot{}, ErrRejected
	}
	expires, err := parseUTC(root.Expires)
	if err != nil || !expires.After(now) {
		return TrustRoot{}, ErrRejected
	}
	if root.Threshold < 1 || len(root.Keys) < root.Threshold || len(root.Keys) > 32 {
		return TrustRoot{}, ErrRejected
	}
	seen := make(map[string]bool, len(root.Keys))
	previous := ""
	for _, key := range root.Keys {
		if key.KeyType != "ed25519" || key.Scheme != "ed25519" || !validHex(key.PublicKey, 2*ed25519.PublicKeySize) {
			return TrustRoot{}, ErrRejected
		}
		decoded, decodeErr := hex.DecodeString(key.PublicKey)
		if decodeErr != nil {
			return TrustRoot{}, ErrRejected
		}
		derived, idErr := keyIdentity(ed25519.PublicKey(decoded))
		if idErr != nil || derived != key.KeyID || seen[key.KeyID] {
			return TrustRoot{}, ErrRejected
		}
		if previous != "" && key.KeyID <= previous {
			return TrustRoot{}, ErrRejected
		}
		previous = key.KeyID
		seen[key.KeyID] = true
	}
	return root, nil
}

func validDigest(value string) bool {
	return len(value) == len("sha256:")+64 && strings.HasPrefix(value, "sha256:") &&
		strings.Trim(value[7:], "0123456789abcdef") == ""
}

func validHex(value string, length int) bool {
	return len(value) == length && strings.Trim(value, "0123456789abcdef") == ""
}

func keyIdentity(public ed25519.PublicKey) (string, error) {
	key, err := metadata.KeyFromPublicKey(public)
	if err != nil {
		return "", ErrRejected
	}
	id, err := key.ID()
	if err != nil || !validHex(id, 64) {
		return "", ErrRejected
	}
	return id, nil
}

func wipe(value []byte) {
	for i := range value {
		value[i] = 0
	}
}
