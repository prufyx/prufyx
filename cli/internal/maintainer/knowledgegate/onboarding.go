// SPDX-License-Identifier: AGPL-3.0-only

package knowledgegate

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/prufyx/prufyx/cli/internal/extract/crdversions"
)

// Onboarding batches. An onboarding batch is one owner signature over a
// manifest that adds up to MaxOnboardingProjects projects to the reviewed
// custom-resource catalogue as data only: per project, its CRD version target
// file and its row of the reviewed custom-resource table, and the pack
// members that move with them (registryDigest; the revision never moves in a batch). It cannot carry
// a rule, a record, code, a test, an approval or trust material: the gate
// refuses every other path (onboarding_state.go). It also turns on line
// attestation for a project already in the base (kind attest), as the only
// change to that project's target.
//
// The manifest binds the base and head states the gate recomputes, every
// file the change adds or changes, the gate's own classification of the
// change, per project the extractor dry run the proposal was made on (the
// gate re-runs it) and the claims summary of the proposal (shown, not
// checked), the sample of projects the owner read in full and the summary
// the owner was shown. A batch is single use, forward only per project,
// valid for at most MaxOnboardingValidity and decided all or nothing.
const (
	OnboardingSchema = "prufyx.io/knowledge-onboarding-batch/v1"
	// OnboardingDomain prefixes the signed bytes. It differs from
	// ApprovalDomain and BatchDomain, so an onboarding signature never
	// verifies as an approval or a batch, and the reverse.
	OnboardingDomain = OnboardingSchema + "\x00"
	// MaxOnboardingProjects bounds one batch. It is a constant, not a
	// setting.
	MaxOnboardingProjects = 50
	// MaxOnboardingValidity bounds notAfter - decidedAt.
	MaxOnboardingValidity = 72 * time.Hour
	// OnboardingKindNew adds a project; OnboardingKindAttest turns on line
	// attestation for a project of the base.
	OnboardingKindNew    = "new"
	OnboardingKindAttest = "attest"
	// ProofOnboarding is the proof of the pack member changes an onboarding
	// batch admitted.
	ProofOnboarding = "onboarding-batch"
	// CheckOnboarding names the check in a gate report; AlarmOnboarding the
	// alarm every onboarding batch raises.
	CheckOnboarding = "onboarding-batch"
	AlarmOnboarding = "onboarding-batch"

	maxOnboardingBytes = 1 << 20
	// maxOnboardingFiles bounds the onboarding directory (base and head).
	maxOnboardingFiles = 2048
	// maxOnboardingFindings bounds the scan findings one proof lists.
	maxOnboardingFindings = 100
	// maxOnboardingClaims bounds each claims count.
	maxOnboardingClaims = 1000000

	onboardingSampleDomain  = OnboardingSchema + "/sample\x00"
	onboardingChangeDomain  = OnboardingSchema + "/change-set\x00"
	onboardingTargetsDomain = OnboardingSchema + "/targets\x00"
)

var (
	onboardingIDRE   = regexp.MustCompile(`^ob-[0-9]{8}-[1-9][0-9]{0,2}$`)
	onboardingSlugRE = regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*$`)
	onboardingFactRE = regexp.MustCompile(`^component\.[a-z0-9]+(_[a-z0-9]+)*\.custom_resource_versions_set$`)
	onboardingTagRE  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$`)
	// onboardingGroupRE is an API group name: lower-case DNS labels.
	onboardingGroupRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$`)
	// onboardingRevisionRE is a pack revision: a prefix and a final
	// decimal counter.
	onboardingRevisionRE = regexp.MustCompile(`^([A-Za-z0-9][A-Za-z0-9._-]{0,99}\.)(0|[1-9][0-9]{0,8})$`)
	// onboardingPathRE bounds a repository path to printable ASCII without
	// spaces or backslashes.
	onboardingPathRE = regexp.MustCompile(`^[A-Za-z0-9._+@=,~-][A-Za-z0-9._+@=,~/-]{0,511}$`)
)

// OnboardingState is one side of the change as the gate computes it.
type OnboardingState struct {
	PackRevision   string `json:"packRevision"`
	RegistryDigest string `json:"registryDigest"`
	TableDigest    string `json:"tableDigest"`
	TargetsDigest  string `json:"targetsDigest"`
}

// OnboardingArtifact is one file the change adds or changes for a project,
// with the sha256 of its head bytes.
type OnboardingArtifact struct {
	Digest string `json:"digest"`
	Path   string `json:"path"`
}

// OnboardingPair is the release pair the proposal's dry run read: the
// newest pair the extractor names for the head target.
type OnboardingPair struct {
	FromCommit string `json:"fromCommit"`
	FromTag    string `json:"fromTag"`
	ToCommit   string `json:"toCommit"`
	ToTag      string `json:"toTag"`
}

// OnboardingFinding is one full-tree scan finding of the dry run.
type OnboardingFinding struct {
	Class  string `json:"class"`
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

// OnboardingClaims is the proposal's claims summary. The gate binds and
// shows it; it does not check it.
type OnboardingClaims struct {
	Confirmed    int    `json:"confirmed"`
	Ledger       string `json:"ledger"`
	Refuted      int    `json:"refuted"`
	Undetermined int    `json:"undetermined"`
}

// OnboardingProof is what the proposal for one project was made on.
type OnboardingProof struct {
	Claims OnboardingClaims    `json:"claims"`
	Pair   OnboardingPair      `json:"pair"`
	Scan   []OnboardingFinding `json:"scan"`
}

// OnboardingProject is one project of the batch.
type OnboardingProject struct {
	Artifacts []OnboardingArtifact `json:"artifacts"`
	Catalog   string               `json:"catalog"`
	Facts     []string             `json:"facts"`
	Groups    []string             `json:"groups"`
	Kind      string               `json:"kind"`
	Proof     OnboardingProof      `json:"proof"`
	Slug      string               `json:"slug"`
}

// OnboardingRecord is the signed content. Fields are declared in the order
// of their JSON names and every string is plain ASCII from a restricted
// alphabet, so its compact JSON is the same in any encoder.
type OnboardingRecord struct {
	Base            OnboardingState     `json:"base"`
	BatchID         string              `json:"batchId"`
	CandidateID     string              `json:"candidateId"`
	ChangeSetDigest string              `json:"changeSetDigest"`
	DecidedAt       string              `json:"decidedAt"`
	Decision        string              `json:"decision"`
	Head            OnboardingState     `json:"head"`
	Identity        string              `json:"identity"`
	Nonce           string              `json:"nonce"`
	NotAfter        string              `json:"notAfter"`
	Projects        []OnboardingProject `json:"projects"`
	Sample          []int               `json:"sample"`
	SummaryDigest   string              `json:"summaryDigest"`
}

// OnboardingEnvelope is the committed file.
type OnboardingEnvelope struct {
	Schema    string           `json:"schema"`
	Record    OnboardingRecord `json:"record"`
	KeyID     string           `json:"keyId"`
	Signature string           `json:"signature"`
}

// onboardingFindingClasses are the scan classes a proof may list (the
// classes of crdversions.Finding). A proof only describes what the scan of
// the newest release pair saw and did not read as a definition: a batch
// admits no rule, record or attestation, and a project is attested only by
// the gate's own dry run, which needs a clean scan (O6), so listing a class
// never turns attestation on. O6 requires every finding of the gate's own
// scan to be listed, whatever its class.
//
// Left out on purpose, because a target a batch admits has no reviewed scan
// exclusion (O4) and these classes only arise under one: exclusion-void,
// excluded-unread, pre-patch-copy, pre-patch and no-definition (excluded,
// accepted before them, stays). A new class of the scanner
// is refused until it is added here (TestOnboardingFindingClasses).
var onboardingFindingClasses = map[string]bool{
	crdversions.ClassConflict:        true,
	crdversions.ClassCopy:            true,
	crdversions.ClassCRDPatch:        true,
	crdversions.ClassExcluded:        true,
	crdversions.ClassExternal:        true,
	crdversions.ClassExtra:           true,
	crdversions.ClassGoDefined:       true,
	crdversions.ClassKustomizeConfig: true,
	crdversions.ClassLegacyCopy:      true,
	crdversions.ClassReference:       true,
	crdversions.ClassSchemaPatch:     true,
	crdversions.ClassTemplatedCopy:   true,
	crdversions.ClassUnread:          true,
	crdversions.ClassUnsupported:     true,
}

func (s OnboardingState) validate() error {
	if !onboardingRevisionRE.MatchString(s.PackRevision) || !validBatchDigest(s.RegistryDigest) || !validBatchDigest(s.TableDigest) || !validBatchDigest(s.TargetsDigest) {
		return errors.New("onboarding state field out of range")
	}
	return nil
}

func validOnboardingPath(p string) bool {
	return onboardingPathRE.MatchString(p) && path.Clean(p) == p && !strings.HasPrefix(p, "/") && p != "." && !strings.Contains(p, "//") &&
		!strings.HasPrefix(p, "../") && !strings.Contains(p, "/../") && !strings.HasSuffix(p, "/..") && p != ".."
}

// validate checks the record's shape: every bound, alphabet and ordering.
// What the values must equal is checked against the trees (verifyOnboarding).
func (r OnboardingRecord) validate() error {
	bad := errors.New("onboarding record field out of range")
	if !onboardingIDRE.MatchString(r.BatchID) || !approvalTokenRE.MatchString(r.CandidateID) || !validBatchDigest(r.ChangeSetDigest) ||
		!approvalTimeRE.MatchString(r.DecidedAt) || !approvalTokenRE.MatchString(r.Decision) || !approvalLoginRE.MatchString(r.Identity) ||
		!batchNonceRE.MatchString(r.Nonce) || !approvalTimeRE.MatchString(r.NotAfter) || !validBatchDigest(r.SummaryDigest) {
		return bad
	}
	if err := r.Base.validate(); err != nil {
		return err
	}
	if err := r.Head.validate(); err != nil {
		return err
	}
	if len(r.Projects) < 1 || len(r.Projects) > MaxOnboardingProjects {
		return fmt.Errorf("an onboarding batch holds 1 to %d projects, this one %d", MaxOnboardingProjects, len(r.Projects))
	}
	for i, p := range r.Projects {
		if err := p.validate(); err != nil {
			return fmt.Errorf("project %d: %w", i, err)
		}
		if i > 0 && r.Projects[i-1].Slug >= p.Slug {
			return errors.New("onboarding projects are not strictly sorted by slug")
		}
	}
	if len(r.Sample) != batchSampleSize(len(r.Projects)) {
		return errors.New("onboarding sample has the wrong size")
	}
	for i, s := range r.Sample {
		if s < 0 || s >= len(r.Projects) || (i > 0 && r.Sample[i-1] >= s) {
			return errors.New("onboarding sample out of range")
		}
	}
	return nil
}

func (p OnboardingProject) validate() error {
	bad := errors.New("project field out of range")
	if !onboardingSlugRE.MatchString(p.Slug) || len(p.Slug) > 100 || p.Catalog != "cncf" {
		return bad
	}
	if p.Kind != OnboardingKindNew && p.Kind != OnboardingKindAttest {
		return bad
	}
	if len(p.Artifacts) < 1 || len(p.Artifacts) > 2 {
		return bad
	}
	for i, a := range p.Artifacts {
		if !validOnboardingPath(a.Path) || !validBatchDigest(a.Digest) || (i > 0 && p.Artifacts[i-1].Path >= a.Path) {
			return bad
		}
	}
	if len(p.Facts) != 1 || !onboardingFactRE.MatchString(p.Facts[0]) {
		return bad
	}
	if len(p.Groups) < 1 || len(p.Groups) > 64 {
		return bad
	}
	for i, g := range p.Groups {
		if len(g) > 253 || !onboardingGroupRE.MatchString(g) || (i > 0 && p.Groups[i-1] >= g) {
			return bad
		}
	}
	pr := p.Proof
	if !onboardingTagRE.MatchString(pr.Pair.FromTag) || !onboardingTagRE.MatchString(pr.Pair.ToTag) || !shaRE.MatchString(pr.Pair.FromCommit) || !shaRE.MatchString(pr.Pair.ToCommit) {
		return bad
	}
	c := pr.Claims
	if c.Confirmed < 0 || c.Refuted < 0 || c.Undetermined < 0 || c.Confirmed > maxOnboardingClaims || c.Refuted > maxOnboardingClaims || c.Undetermined > maxOnboardingClaims || !validBatchDigest(c.Ledger) {
		return bad
	}
	if len(pr.Scan) > maxOnboardingFindings {
		return fmt.Errorf("a proof lists at most %d scan findings", maxOnboardingFindings)
	}
	for i, f := range pr.Scan {
		if !onboardingFindingClasses[f.Class] || !validOnboardingPath(f.Path) || (f.SHA256 != "" && !validBatchDigest(f.SHA256)) {
			return bad
		}
		if i > 0 && onboardingFindingKey(pr.Scan[i-1]) >= onboardingFindingKey(f) {
			return errors.New("scan findings are not strictly sorted by path, class and digest")
		}
	}
	return nil
}

func onboardingFindingKey(f OnboardingFinding) string {
	return f.Path + "\x00" + f.Class + "\x00" + f.SHA256
}

// SignedOnboardingBytes returns the exact bytes an onboarding signature
// covers.
func SignedOnboardingBytes(r OnboardingRecord) ([]byte, error) {
	if err := r.validate(); err != nil {
		return nil, err
	}
	raw, err := json.Marshal(r)
	if err != nil {
		return nil, err
	}
	return append([]byte(OnboardingDomain), raw...), nil
}

// decodeOnboarding decodes an onboarding file without verifying it.
func decodeOnboarding(raw []byte) (OnboardingEnvelope, error) {
	var env OnboardingEnvelope
	if len(raw) > maxOnboardingBytes {
		return env, errors.New("onboarding batch too large")
	}
	if err := strictDecode(bytes.TrimSuffix(raw, []byte("\n")), &env); err != nil {
		return env, fmt.Errorf("onboarding batch: %w", err)
	}
	if env.Schema != OnboardingSchema {
		return env, errors.New("onboarding batch: wrong schema")
	}
	return env, nil
}

// onboardingCore is what the sample is drawn from: everything the manifest
// binds before the owner decides, including the nonce the signing tool
// draws at review time.
type onboardingCore struct {
	Base            OnboardingState     `json:"base"`
	BatchID         string              `json:"batchId"`
	CandidateID     string              `json:"candidateId"`
	ChangeSetDigest string              `json:"changeSetDigest"`
	Head            OnboardingState     `json:"head"`
	Nonce           string              `json:"nonce"`
	Projects        []OnboardingProject `json:"projects"`
}

func (r OnboardingRecord) core() onboardingCore {
	return onboardingCore{Base: r.Base, BatchID: r.BatchID, CandidateID: r.CandidateID, ChangeSetDigest: r.ChangeSetDigest, Head: r.Head, Nonce: r.Nonce, Projects: r.Projects}
}

// onboardingSample draws the sample as batchSample does (partial
// Fisher-Yates over SHA-256(domain || core || counter), rejection sampling),
// in its own domain. The result is sorted.
func onboardingSample(core onboardingCore) ([]int, error) {
	raw, err := json.Marshal(core)
	if err != nil {
		return nil, err
	}
	seed := sha256.Sum256(append([]byte(onboardingSampleDomain), raw...))
	var counter uint64
	draw := func() uint64 {
		var buf [40]byte
		copy(buf[:32], seed[:])
		binary.BigEndian.PutUint64(buf[32:], counter)
		counter++
		sum := sha256.Sum256(buf[:])
		return binary.BigEndian.Uint64(sum[:8])
	}
	uniform := func(m uint64) uint64 {
		threshold := -m % m
		for {
			if x := draw(); x >= threshold {
				return x % m
			}
		}
	}
	n := len(core.Projects)
	k := batchSampleSize(n)
	idx := make([]int, n)
	for i := range idx {
		idx[i] = i
	}
	for i := 0; i < k; i++ {
		j := i + int(uniform(uint64(n-i)))
		idx[i], idx[j] = idx[j], idx[i]
	}
	out := append([]int(nil), idx[:k]...)
	sort.Ints(out)
	return out, nil
}

// verifyOnboardingSignature checks the envelope against the pinned keys at
// now: a pinned, unexpired key, the signature over the domain-separated
// record, an owner identity, the approve decision and the validity window.
// It checks nothing about the trees.
func verifyOnboardingSignature(env OnboardingEnvelope, keys ApprovalKeys, now time.Time) error {
	r := env.Record
	signed, err := SignedOnboardingBytes(r)
	if err != nil {
		return fmt.Errorf("onboarding batch: %w", err)
	}
	var key *ApprovalKey
	for i := range keys.Keys {
		if keys.Keys[i].KeyID == env.KeyID {
			key = &keys.Keys[i]
		}
	}
	if key == nil {
		return errors.New("onboarding batch: signed by a key that is not pinned")
	}
	now = now.UTC()
	keyNotAfter, err := time.Parse(time.RFC3339, key.NotAfter)
	if err != nil || !now.Before(keyNotAfter) {
		return errors.New("onboarding batch: signing key has expired")
	}
	pub, err := hex.DecodeString(key.PublicKey)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return errors.New("onboarding batch: the pinned key is not an Ed25519 public key")
	}
	sig, err := base64.StdEncoding.Strict().DecodeString(env.Signature)
	if err != nil || len(sig) != ed25519.SignatureSize || !ed25519.Verify(ed25519.PublicKey(pub), signed, sig) {
		return errors.New("onboarding batch: signature does not verify")
	}
	owner := false
	for _, o := range keys.Owners {
		owner = owner || o == r.Identity
	}
	switch {
	case !owner:
		return fmt.Errorf("onboarding batch: %s is not an owner", r.Identity)
	case r.Decision != ApprovalDecisionApprove:
		return fmt.Errorf("onboarding batch: decision is %q", r.Decision)
	}
	decided, err1 := time.Parse(time.RFC3339, r.DecidedAt)
	notAfter, err2 := time.Parse(time.RFC3339, r.NotAfter)
	switch {
	case err1 != nil || err2 != nil:
		return errors.New("onboarding batch: decidedAt or notAfter")
	case !notAfter.After(decided) || notAfter.Sub(decided) > MaxOnboardingValidity:
		return errors.New("onboarding batch: notAfter must lie after decidedAt and at most 72 hours after it")
	case decided.After(now.Add(approvalClockSkew)):
		return errors.New("onboarding batch: decided in the future")
	case !now.Before(notAfter):
		return fmt.Errorf("onboarding batch: expired at %s", r.NotAfter)
	}
	return nil
}

// sameOnboarding reports whether two batches are the same decision: the
// same batch id, signature or signed record.
func sameOnboarding(a, b OnboardingEnvelope) bool {
	if a.Record.BatchID == b.Record.BatchID || (a.Signature != "" && a.Signature == b.Signature) {
		return true
	}
	ra, err1 := json.Marshal(a.Record)
	rb, err2 := json.Marshal(b.Record)
	return err1 == nil && err2 == nil && bytes.Equal(ra, rb)
}
