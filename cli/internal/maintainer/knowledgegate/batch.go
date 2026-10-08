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
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/prufyx/prufyx/cli/internal/constraintengine"
)

// Batch approvals. A batch approval is one owner signature over a manifest
// that admits up to MaxBatchEntries reviewed entries (rules and line
// attestations) of one change at once, in place of one approval file per
// entry. It binds, besides every entry's base and candidate digest, the
// bytes of every pack on both sides, the gate's own classification of the
// whole change, the entries' cited sources, the sample of entries the owner
// read in full and the summary the owner was shown. The gate recomputes
// every one of these from the trees it checks, so a batch is accepted only
// for exactly the change it was signed for.
//
// A batch is single use and forward only (see baseApprovals.refuseBatch),
// valid for at most MaxBatchValidity, and decided all or nothing: one
// failing check refuses every entry.
const (
	BatchSchema = "prufyx.io/knowledge-approval-batch/v1"
	// BatchDomain prefixes the signed bytes. It differs from
	// ApprovalDomain, so a batch signature never verifies as a per-entry
	// approval and the reverse.
	BatchDomain = BatchSchema + "\x00"
	// MaxBatchEntries bounds one batch. It is a constant, not a setting.
	MaxBatchEntries = 50
	// MaxBatchValidity bounds notAfter - decidedAt.
	MaxBatchValidity = 72 * time.Hour
	// MinBatchSample is the smallest sample (or every entry of a smaller
	// batch); the sample is otherwise a tenth of the entries, rounded up.
	MinBatchSample = 3
	// BatchSubjectRule and BatchSubjectLineAttestation are the subjects of
	// batch entries.
	BatchSubjectRule            = "rule"
	BatchSubjectLineAttestation = ApprovalSubjectLineAttestation
	// ProofBatchApproval is the proof of an entry a batch admitted.
	ProofBatchApproval = "batch-approval"
	// CheckBatch names the batch check in a gate report; AlarmBatch the
	// alarm every batch raises.
	CheckBatch = "batch-approval"
	AlarmBatch = "batch-approval"

	maxBatchBytes      = 64 << 10
	maxBatchFiles      = 4096
	batchSampleDomain  = BatchSchema + "/sample\x00"
	batchChangeDomain  = BatchSchema + "/change-set\x00"
	batchCitesDomain   = BatchSchema + "/citations\x00"
	batchNonceHexBytes = 16
)

var (
	batchIDRE    = regexp.MustCompile(`^b-[0-9]{8}-[1-9][0-9]{0,2}$`)
	batchNonceRE = regexp.MustCompile(`^[0-9a-f]{32}$`)
)

// BatchEntry is one entry a batch admits. Subject is BatchSubjectRule or
// BatchSubjectLineAttestation; Scope is set for a line attestation only.
// The digests are those of a per-entry approval (CandidateDigest over the
// canonical entry or record, ApprovalBaseAbsent for a new one).
type BatchEntry struct {
	BaseDigest      string `json:"baseDigest"`
	CandidateDigest string `json:"candidateDigest"`
	ID              string `json:"id"`
	Pack            string `json:"pack"`
	Scope           string `json:"scope,omitempty"`
	Subject         string `json:"subject"`
}

// BatchPack binds one pack file on both sides: the sha256 of its bytes, or
// ApprovalBaseAbsent when the tree has no such file.
type BatchPack struct {
	Base string `json:"base"`
	Head string `json:"head"`
	Pack string `json:"pack"`
}

// BatchRecord is the signed content. Every string is plain ASCII from a
// restricted alphabet, so its compact JSON is the same in any encoder.
type BatchRecord struct {
	BatchID         string       `json:"batchId"`
	CandidateID     string       `json:"candidateId"`
	ChangeSetDigest string       `json:"changeSetDigest"`
	CitationsDigest string       `json:"citationsDigest"`
	DecidedAt       string       `json:"decidedAt"`
	Decision        string       `json:"decision"`
	Entries         []BatchEntry `json:"entries"`
	Identity        string       `json:"identity"`
	Nonce           string       `json:"nonce"`
	NotAfter        string       `json:"notAfter"`
	Packs           []BatchPack  `json:"packs"`
	Sample          []int        `json:"sample"`
	SummaryDigest   string       `json:"summaryDigest"`
}

// BatchEnvelope is the committed file.
type BatchEnvelope struct {
	Schema    string      `json:"schema"`
	Record    BatchRecord `json:"record"`
	KeyID     string      `json:"keyId"`
	Signature string      `json:"signature"`
}

func (e BatchEntry) key() string { return batchKey(e.Pack, e.Subject, e.ID) }

func batchKey(pack, subject, id string) string { return pack + "\x00" + subject + "\x00" + id }

func validBatchDigest(s string) bool { return approvalDigestRE.MatchString(s) }

func (r BatchRecord) validate() error {
	bad := errors.New("batch record field out of range")
	if !batchIDRE.MatchString(r.BatchID) || !approvalTokenRE.MatchString(r.CandidateID) || !validBatchDigest(r.ChangeSetDigest) ||
		!validBatchDigest(r.CitationsDigest) || !approvalTimeRE.MatchString(r.DecidedAt) || !approvalTokenRE.MatchString(r.Decision) ||
		!approvalLoginRE.MatchString(r.Identity) || !batchNonceRE.MatchString(r.Nonce) || !approvalTimeRE.MatchString(r.NotAfter) ||
		!validBatchDigest(r.SummaryDigest) {
		return bad
	}
	if len(r.Entries) < 1 || len(r.Entries) > MaxBatchEntries {
		return fmt.Errorf("a batch holds 1 to %d entries, this one %d", MaxBatchEntries, len(r.Entries))
	}
	for i, e := range r.Entries {
		if (e.BaseDigest != ApprovalBaseAbsent && !validBatchDigest(e.BaseDigest)) || !validBatchDigest(e.CandidateDigest) ||
			!approvalTokenRE.MatchString(e.ID) || !approvalTokenRE.MatchString(e.Pack) {
			return bad
		}
		switch e.Subject {
		case BatchSubjectRule:
			if e.Scope != "" {
				return bad
			}
		case BatchSubjectLineAttestation:
			if !approvalScopeRE.MatchString(e.Scope) {
				return bad
			}
		default:
			return bad
		}
		if i > 0 && r.Entries[i-1].key() >= e.key() {
			return errors.New("batch entries are not strictly sorted by pack, subject and id")
		}
	}
	if len(r.Packs) == 0 {
		return bad
	}
	for i, p := range r.Packs {
		if !approvalTokenRE.MatchString(p.Pack) || (p.Base != ApprovalBaseAbsent && !validBatchDigest(p.Base)) || (p.Head != ApprovalBaseAbsent && !validBatchDigest(p.Head)) {
			return bad
		}
		if i > 0 && r.Packs[i-1].Pack >= p.Pack {
			return errors.New("batch packs are not strictly sorted")
		}
	}
	if len(r.Sample) != batchSampleSize(len(r.Entries)) {
		return errors.New("batch sample has the wrong size")
	}
	for i, s := range r.Sample {
		if s < 0 || s >= len(r.Entries) || (i > 0 && r.Sample[i-1] >= s) {
			return errors.New("batch sample out of range")
		}
	}
	return nil
}

// SignedBatchBytes returns the exact bytes a batch signature covers.
func SignedBatchBytes(r BatchRecord) ([]byte, error) {
	if err := r.validate(); err != nil {
		return nil, err
	}
	raw, err := json.Marshal(r)
	if err != nil {
		return nil, err
	}
	return append([]byte(BatchDomain), raw...), nil
}

// decodeBatch decodes a batch file without verifying it.
func decodeBatch(raw []byte) (BatchEnvelope, error) {
	var env BatchEnvelope
	if len(raw) > maxBatchBytes {
		return env, errors.New("batch approval too large")
	}
	if err := strictDecode(bytes.TrimSuffix(raw, []byte("\n")), &env); err != nil {
		return env, fmt.Errorf("batch approval: %w", err)
	}
	if env.Schema != BatchSchema {
		return env, errors.New("batch approval: wrong schema")
	}
	return env, nil
}

// batchSampleSize is the number of entries the owner reads in full.
func batchSampleSize(n int) int {
	k := (n + 9) / 10
	if k < MinBatchSample {
		k = MinBatchSample
	}
	if k > n {
		k = n
	}
	return k
}

// batchCore is what the sample is drawn from: everything the manifest
// binds before the owner decides, including the nonce the signing tool
// draws at review time.
type batchCore struct {
	BatchID         string       `json:"batchId"`
	CandidateID     string       `json:"candidateId"`
	ChangeSetDigest string       `json:"changeSetDigest"`
	CitationsDigest string       `json:"citationsDigest"`
	Entries         []BatchEntry `json:"entries"`
	Nonce           string       `json:"nonce"`
	Packs           []BatchPack  `json:"packs"`
}

func (r BatchRecord) core() batchCore {
	return batchCore{BatchID: r.BatchID, CandidateID: r.CandidateID, ChangeSetDigest: r.ChangeSetDigest, CitationsDigest: r.CitationsDigest, Entries: r.Entries, Nonce: r.Nonce, Packs: r.Packs}
}

// BatchSample draws the sample: a partial Fisher-Yates shuffle of the entry
// indices driven by SHA-256(seed || counter), with rejection sampling (no
// modulo bias), seeded by the batch core. The result is sorted.
func batchSample(core batchCore) ([]int, error) {
	raw, err := json.Marshal(core)
	if err != nil {
		return nil, err
	}
	seed := sha256.Sum256(append([]byte(batchSampleDomain), raw...))
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
	n := len(core.Entries)
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

// batchItem is one entry the change calls for, with its change.
type batchItem struct {
	entry  BatchEntry
	change *Change
}

// batchState is what a batch is checked against, computed from the base
// and head trees and their classification only.
type batchState struct {
	cls   *Classification
	packs []BatchPack
	// items are the entries the change calls for: every loosening change
	// of a reviewed rule with a head, and of a reviewed line attestation
	// whose base is not mechanical, sorted by key.
	items []batchItem
	// changes indexes every rule and record change by batch key.
	changes map[string]*Change
	// problems are changes no batch change may hold.
	problems        []string
	changeSetDigest string
	citationsDigest string
}

func domainDigest(domain string, v any) (string, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	return CandidateDigest(append([]byte(domain), raw...)), nil
}

func fileDigest(p *loadedPack) string {
	if p == nil || !p.Present {
		return ApprovalBaseAbsent
	}
	return CandidateDigest(p.Raw)
}

func canonicalDigest(canonical []byte) string {
	if canonical == nil {
		return ApprovalBaseAbsent
	}
	return CandidateDigest(canonical)
}

// changeSubject is the batch subject of a rule or record change.
func changeSubject(c *Change) string {
	switch c.Section {
	case "":
		return BatchSubjectRule
	case sectionAttestations:
		return BatchSubjectLineAttestation
	default:
		return c.Section
	}
}

// changeSetItem is one change as the change-set digest binds it.
type changeSetItem struct {
	Pack    string   `json:"pack"`
	Section string   `json:"section"`
	Member  string   `json:"member"`
	ID      string   `json:"id"`
	Class   string   `json:"class"`
	Kinds   []string `json:"kinds"`
	Basis   string   `json:"basis"`
	Project string   `json:"project"`
	Base    string   `json:"base"`
	Head    string   `json:"head"`
}

func (c *Change) canonicalSides() (base, head []byte) {
	if c.Section != "" {
		if c.rbase != nil {
			base = c.rbase.Canonical
		}
		if c.rhead != nil {
			head = c.rhead.Canonical
		}
		return
	}
	if c.base != nil {
		base = c.base.Canonical
	}
	if c.head != nil {
		head = c.head.Canonical
	}
	return
}

// newBatchState computes, from a classification, the entries a batch for
// this change must hold and the digests it must carry.
func newBatchState(layout Layout, cls *Classification) (*batchState, error) {
	st := &batchState{cls: cls, changes: map[string]*Change{}}
	for _, spec := range layout.Packs {
		st.packs = append(st.packs, BatchPack{Pack: spec.Name, Base: fileDigest(cls.base[spec.Name]), Head: fileDigest(cls.head[spec.Name])})
	}
	sort.Slice(st.packs, func(i, j int) bool { return st.packs[i].Pack < st.packs[j].Pack })
	set := struct {
		Changes       []changeSetItem `json:"changes"`
		ChainsChanged []string        `json:"chainsChanged"`
		Paused        bool            `json:"paused"`
	}{Changes: []changeSetItem{}, ChainsChanged: append([]string{}, cls.ChainsChanged...), Paused: cls.Paused}
	for _, name := range cls.ChainsChanged {
		st.problems = append(st.problems, "the reattestation statement chain of "+name+" changed")
	}
	for _, c := range cls.Changes {
		b, h := c.canonicalSides()
		set.Changes = append(set.Changes, changeSetItem{Pack: c.Pack, Section: c.Section, Member: c.Member, ID: c.RuleID, Class: c.Class, Kinds: c.Kinds, Basis: c.Basis, Project: c.Project, Base: canonicalDigest(b), Head: canonicalDigest(h)})
		if c.Member != "" {
			st.problems = append(st.problems, "the pack member "+logSafe(c.Member)+" of "+c.Pack+" changed")
			continue
		}
		subject := changeSubject(c)
		st.changes[batchKey(c.Pack, subject, c.RuleID)] = c
		if c.Class != ClassLoosening {
			continue
		}
		switch {
		case c.isSupersede():
			st.problems = append(st.problems, "rule "+logSafe(c.RuleID)+" is half of a supersede pair (an owner change of its own)")
		case c.Section == "" && c.head == nil:
			st.problems = append(st.problems, "rule "+logSafe(c.RuleID)+" is removed")
		case c.Section == "" && c.Basis == constraintengine.BasisReviewed:
			st.items = append(st.items, batchItem{change: c, entry: BatchEntry{Pack: c.Pack, Subject: subject, ID: c.RuleID, BaseDigest: canonicalDigest(b), CandidateDigest: CandidateDigest(h)}})
		case c.Section == sectionAttestations && c.rhead != nil && !c.rhead.mechanical() && c.rbase != nil && c.rbase.mechanical():
			st.problems = append(st.problems, "line attestation "+logSafe(c.RuleID)+" turns a mechanical record into a reviewed one")
		case c.Section == sectionAttestations && c.rhead != nil && c.rhead.Basis == constraintengine.BasisReviewed:
			st.items = append(st.items, batchItem{change: c, entry: BatchEntry{Pack: c.Pack, Subject: subject, ID: c.RuleID, Scope: c.rhead.Scope, BaseDigest: canonicalDigest(b), CandidateDigest: CandidateDigest(h)}})
		case c.Section == sectionPolicies:
			st.problems = append(st.problems, "path policy "+logSafe(c.RuleID)+" changes (loosening)")
		}
	}
	sort.Slice(st.items, func(i, j int) bool { return st.items[i].entry.key() < st.items[j].entry.key() })
	var err error
	if st.changeSetDigest, err = domainDigest(batchChangeDomain, set); err != nil {
		return nil, err
	}
	type cites struct {
		Pack    string          `json:"pack"`
		Subject string          `json:"subject"`
		ID      string          `json:"id"`
		Sources json.RawMessage `json:"sources"`
	}
	list := []cites{}
	for _, it := range st.items {
		list = append(list, cites{Pack: it.entry.Pack, Subject: it.entry.Subject, ID: it.entry.ID, Sources: itemSources(it.change)})
	}
	if st.citationsDigest, err = domainDigest(batchCitesDomain, list); err != nil {
		return nil, err
	}
	return st, nil
}

// itemSources is the canonical JSON of an entry's evidence.sources (null
// when it has none).
func itemSources(c *Change) json.RawMessage {
	var v any
	var ok bool
	if c.Section == "" && c.head != nil {
		v, ok = lookup(c.head.generic, "rule", "evidence", "sources")
	} else if c.rhead != nil {
		v, ok = lookup(c.rhead.generic, "evidence", "sources")
	}
	if !ok {
		return json.RawMessage("null")
	}
	raw := canonicalOf(v)
	if raw == nil {
		return json.RawMessage("null")
	}
	return json.RawMessage(bytes.TrimSuffix(raw, []byte("\n")))
}

// entries returns the entries the change calls for.
func (st *batchState) entries() []BatchEntry {
	out := make([]BatchEntry, 0, len(st.items))
	for _, it := range st.items {
		out = append(out, it.entry)
	}
	return out
}

// draftRecord is the unsigned manifest for this state: entries, packs and
// digests, the sample drawn with nonce, and the summary digest. The caller
// sets identity, decision and times.
func (st *batchState) draftRecord(batchID, candidateID, nonce string) (BatchRecord, string, error) {
	rec := BatchRecord{
		BatchID: batchID, CandidateID: candidateID, ChangeSetDigest: st.changeSetDigest, CitationsDigest: st.citationsDigest,
		Entries: st.entries(), Nonce: nonce, Packs: st.packs,
	}
	sample, err := batchSample(rec.core())
	if err != nil {
		return BatchRecord{}, "", err
	}
	rec.Sample = sample
	summary := st.summary(rec)
	rec.SummaryDigest = CandidateDigest([]byte(summary))
	return rec, summary, nil
}

// readyForBatch refuses a change no batch may approve: one holding a
// change listed in problems, or no entry, or more than MaxBatchEntries.
func (st *batchState) readyForBatch() error {
	if len(st.problems) > 0 {
		return fmt.Errorf("a batch approves only reviewed rule and line attestation changes, beside tightening and re-derived mechanical changes; this change also holds: %s", strings.Join(st.problems, "; "))
	}
	switch n := len(st.items); {
	case n == 0:
		return errors.New("the change holds no reviewed loosening change for a batch to approve")
	case n > MaxBatchEntries:
		return fmt.Errorf("the change holds %d reviewed loosening changes; a batch approves at most %d", n, MaxBatchEntries)
	}
	return nil
}

// verifyBatch is every check of a batch file that needs no network: the
// file, its key, signature and time window; the entries, packs, change set,
// citations digest, sample and summary against the state. The single-use
// checks against the base (baseApprovals.refuseBatch), the upstream
// citation verification and the attestation cross-check are separate.
// name is the file name it was read from ("" to skip that check).
func verifyBatch(raw []byte, name string, st *batchState, keys ApprovalKeys, now time.Time) (BatchEnvelope, error) {
	env, err := decodeBatch(raw)
	if err != nil {
		return env, err
	}
	r := env.Record
	signed, err := SignedBatchBytes(r)
	if err != nil {
		return env, fmt.Errorf("batch approval: %w", err)
	}
	if name != "" && name != r.BatchID+".json" {
		return env, fmt.Errorf("batch approval: the file %s is not named after its batch id %s", logSafe(name), r.BatchID)
	}
	var key *ApprovalKey
	for i := range keys.Keys {
		if keys.Keys[i].KeyID == env.KeyID {
			key = &keys.Keys[i]
		}
	}
	if key == nil {
		return env, errors.New("batch approval: signed by a key that is not pinned")
	}
	now = now.UTC()
	keyNotAfter, err := time.Parse(time.RFC3339, key.NotAfter)
	if err != nil || !now.Before(keyNotAfter) {
		return env, errors.New("batch approval: signing key has expired")
	}
	pub, _ := hex.DecodeString(key.PublicKey)
	sig, err := base64.StdEncoding.Strict().DecodeString(env.Signature)
	if err != nil || len(sig) != ed25519.SignatureSize || !ed25519.Verify(ed25519.PublicKey(pub), signed, sig) {
		return env, errors.New("batch approval: signature does not verify")
	}
	owner := false
	for _, o := range keys.Owners {
		owner = owner || o == r.Identity
	}
	switch {
	case !owner:
		return env, fmt.Errorf("batch approval: %s is not an owner", r.Identity)
	case r.Decision != ApprovalDecisionApprove:
		return env, fmt.Errorf("batch approval: decision is %q", r.Decision)
	}
	decided, err1 := time.Parse(time.RFC3339, r.DecidedAt)
	notAfter, err2 := time.Parse(time.RFC3339, r.NotAfter)
	switch {
	case err1 != nil || err2 != nil:
		return env, errors.New("batch approval: decidedAt or notAfter")
	case !notAfter.After(decided) || notAfter.Sub(decided) > MaxBatchValidity:
		return env, errors.New("batch approval: notAfter must lie after decidedAt and at most 72 hours after it")
	case decided.After(now.Add(approvalClockSkew)):
		return env, errors.New("batch approval: decided in the future")
	case !now.Before(notAfter):
		return env, fmt.Errorf("batch approval: expired at %s", r.NotAfter)
	}
	if err := st.readyForBatch(); err != nil {
		return env, err
	}
	if err := st.matchEntries(r.Entries); err != nil {
		return env, err
	}
	if !equalPacks(r.Packs, st.packs) {
		return env, errors.New("batch approval: a pack file differs from the one the batch was signed for")
	}
	if r.ChangeSetDigest != st.changeSetDigest {
		return env, errors.New("batch approval: the change set differs from the one the batch was signed for")
	}
	if r.CitationsDigest != st.citationsDigest {
		return env, errors.New("batch approval: the entries' cited sources differ from the ones the batch was signed for")
	}
	sample, err := batchSample(r.core())
	if err != nil {
		return env, err
	}
	if !equalInts(sample, r.Sample) {
		return env, errors.New("batch approval: the sample is not the one drawn from the manifest")
	}
	if CandidateDigest([]byte(st.summary(r))) != r.SummaryDigest {
		return env, errors.New("batch approval: the summary digest does not match the summary of this change")
	}
	return env, nil
}

// matchEntries requires the batch's entries to be exactly the ones the
// change calls for, with their digests. An entry naming a tightening
// change, or a change that is not reviewed, is refused by name: a batch
// must never present a change that needs no approval as approved.
func (st *batchState) matchEntries(entries []BatchEntry) error {
	want := map[string]BatchEntry{}
	for _, it := range st.items {
		want[it.entry.key()] = it.entry
	}
	var problems []string
	seen := map[string]bool{}
	for _, e := range entries {
		k := e.key()
		seen[k] = true
		w, ok := want[k]
		if ok {
			switch {
			case w.Scope != e.Scope:
				problems = append(problems, fmt.Sprintf("entry %s: scope differs", logSafe(e.ID)))
			case w.CandidateDigest != e.CandidateDigest:
				problems = append(problems, fmt.Sprintf("entry %s: candidate digest does not match the proposed entry", logSafe(e.ID)))
			case w.BaseDigest != e.BaseDigest:
				problems = append(problems, fmt.Sprintf("entry %s: base digest does not match the base", logSafe(e.ID)))
			}
			continue
		}
		c := st.changes[k]
		switch {
		case c == nil:
			problems = append(problems, fmt.Sprintf("entry %s %s/%s: the change does not change it", e.Subject, e.Pack, logSafe(e.ID)))
		case c.Class == ClassTightening:
			problems = append(problems, fmt.Sprintf("entry %s %s/%s is a tightening change (%s): it needs no approval, and a batch may not present it as approved", e.Subject, e.Pack, logSafe(e.ID), strings.Join(c.Kinds, ", ")))
		default:
			problems = append(problems, fmt.Sprintf("entry %s %s/%s is a %s change with basis %q, which a batch does not approve", e.Subject, e.Pack, logSafe(e.ID), c.Class, logSafe(c.Basis)))
		}
	}
	for _, it := range st.items {
		if !seen[it.entry.key()] {
			problems = append(problems, fmt.Sprintf("the reviewed change of %s %s/%s is not in the batch", it.entry.Subject, it.entry.Pack, logSafe(it.entry.ID)))
		}
	}
	if len(problems) > 0 {
		sort.Strings(problems)
		return errors.New("batch approval: the entries are not exactly the change's reviewed changes" + listDetail(problems))
	}
	return nil
}

func equalPacks(a, b []BatchPack) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func equalInts(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// sameBatch reports whether two decoded batches are the same decision:
// the same batch id, the same signed record, or the same signature.
func sameBatch(a, b BatchEnvelope) bool {
	if a.Record.BatchID == b.Record.BatchID || (a.Signature != "" && a.Signature == b.Signature) {
		return true
	}
	ra, err1 := json.Marshal(a.Record)
	rb, err2 := json.Marshal(b.Record)
	return err1 == nil && err2 == nil && bytes.Equal(ra, rb)
}

// batchUsableUntil is when a batch stops being accepted: its notAfter, or
// earlier when its key expires first.
func batchUsableUntil(rec BatchRecord, key ApprovalKey) string {
	until, err1 := time.Parse(time.RFC3339, rec.NotAfter)
	keyEnd, err2 := time.Parse(time.RFC3339, key.NotAfter)
	if err1 != nil || err2 != nil {
		return "unknown"
	}
	if keyEnd.Before(until) {
		until = keyEnd
	}
	return until.UTC().Format(time.RFC3339)
}

// batchNonce formats nonce bytes.
func batchNonce(b []byte) (string, error) {
	if len(b) != batchNonceHexBytes {
		return "", errors.New("batch nonce: wrong length")
	}
	return hex.EncodeToString(b), nil
}
