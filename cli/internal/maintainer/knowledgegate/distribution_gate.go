// SPDX-License-Identifier: AGPL-3.0-only

package knowledgegate

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/prufyx/prufyx/cli/internal/buildidentity"
	"github.com/prufyx/prufyx/cli/internal/cncfcheck"
	"github.com/prufyx/prufyx/cli/internal/constraintengine"
	"github.com/prufyx/prufyx/cli/internal/distribution"
	"github.com/prufyx/prufyx/cli/internal/extract"
	"github.com/prufyx/prufyx/cli/internal/lineattest"
	"github.com/prufyx/prufyx/cli/internal/maintainer/providerexcerpt"
)

// Provider facts (the lifecycle, channels and deprecations of a distribution
// record, with the record's evidence) are admitted only mechanically. A
// distribution record changes through the gate only when all of these hold:
//
//  1. the base and head records are canonically identical outside the
//     provider fields (lifecycle, channels, deprecations, evidence): the
//     identity of a distribution (control plane, OpenShift mapping) never
//     changes through this gate;
//  2. the head record is mechanical, names an extractor, and equals byte for
//     byte (canonical JSON) what the deriver compiled into this binary
//     derives from the excerpts the record cites, with the record's own
//     derivedAt and validUntil (derivedAt must lie in the window every
//     mechanical record has: [now-24h, now+5m]);
//  3. the cited excerpts pass providerexcerpt.CheckSourcesAt against the
//     manifest of the base: each is a committed file of this repository
//     whose revision is already on the base, hashing to its manifest digest,
//     fetched no later than the commit that cites it, the span inside the
//     excerpt body;
//  4. the oldest-supported-client pin of the base and of the head names a
//     version at or above cncfcheck.ProviderFactsMinClientVersion, so no
//     provider fact is admitted while a client that cannot read it is still
//     supported.
//
// Anything else is refused: a hand-edited row, a reviewed or empty-basis row,
// a record of an unknown extractor, a removed record, a record without
// provider facts, a new record in a pack that already has the section. The
// applicability statements of the section are never a record change: they
// stay a pack-member change, refused. The first introduction of the section
// into a pack (the base has none) also needs an owner approval bound to every
// record (admitDistributionIntroduction), exactly as the servedAPIs member's.
//
// The production deriver registry is empty: until an extractor is compiled in
// (a code change under review) this gate admits no provider row.

// ProviderDeriveInput is what a compiled deriver reads.
type ProviderDeriveInput struct {
	// Identity is the head record reduced to its identity (distribution,
	// control plane, OpenShift mapping): no provider field, no evidence.
	Identity distribution.Record
	// Sources are the excerpts the head record cites.
	Sources []constraintengine.SourceEvidence
	// Read returns the bytes of a committed file at a revision. The gate
	// wraps it: only the (revision, path) pairs the record cites can be
	// read, anything else is refused with ErrUncitedRead, and every read is
	// recorded. The cited revisions have been checked by the gate.
	Read     providerexcerpt.Reader
	Manifest providerexcerpt.Manifest
	// DerivedAt and ValidUntil are the head record's own, which the record
	// must keep (a renewal is a re-derivation at a later time).
	DerivedAt, ValidUntil time.Time
}

// ProviderDeriver is one compiled extractor of provider facts.
type ProviderDeriver struct {
	// Identity is the extractor identity a record must name.
	Identity constraintengine.Extractor
	// Derive returns the complete record (identity as given, provider
	// fields, evidence) the extractor derives. It must not read anything but
	// its input.
	Derive func(ProviderDeriveInput) (distribution.Record, error)
}

// compiledProviderDerivers are the extractors of provider facts compiled
// into this binary, by extractor id. It is empty: no extractor exists yet,
// so the gate admits no provider row. Tests inject theirs through the
// unexported Options.derivers, which no caller outside this package can set.
var compiledProviderDerivers = map[string]ProviderDeriver{}

func (o Options) providerDerivers() map[string]ProviderDeriver {
	if o.derivers != nil {
		return o.derivers
	}
	return compiledProviderDerivers
}

// ErrUncitedRead is joined to the error of a deriver that tried to read a
// file the record does not cite (another path, another revision, a path that
// is not spelled exactly as cited).
var ErrUncitedRead = errors.New("a deriver may read only the excerpts its record cites")

// citedReader lets a deriver read exactly the cited (revision, path) pairs.
// It records every read, allowed or not, and remembers any refusal: a deriver
// that swallows the refusal still fails the record.
type citedReader struct {
	mu      sync.Mutex
	allowed map[providerexcerpt.Cite]bool
	read    providerexcerpt.Reader
	reads   []providerexcerpt.Cite
	refused []providerexcerpt.Cite
}

func newCitedReader(sources []constraintengine.SourceEvidence, read providerexcerpt.Reader) (*citedReader, error) {
	cites, err := providerexcerpt.CitedReads(sources)
	if err != nil {
		return nil, err
	}
	c := &citedReader{allowed: map[providerexcerpt.Cite]bool{}, read: read}
	for _, ct := range cites {
		c.allowed[ct] = true
	}
	return c, nil
}

// Read is the providerexcerpt.Reader handed to the deriver.
func (c *citedReader) Read(revision, path string) ([]byte, error) {
	ct := providerexcerpt.Cite{Revision: revision, Path: path}
	c.mu.Lock()
	c.reads = append(c.reads, ct)
	ok := c.allowed[ct]
	if !ok {
		c.refused = append(c.refused, ct)
	}
	c.mu.Unlock()
	if !ok {
		return nil, fmt.Errorf("read of %s at %s: %w", logSafe(path), logSafe(revision), ErrUncitedRead)
	}
	return c.read(revision, path)
}

// check compares the reads to the citations: any read outside them refuses.
func (c *citedReader) check() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, ct := range c.reads {
		if !c.allowed[ct] {
			return fmt.Errorf("the deriver read %s at %s: %w", logSafe(ct.Path), logSafe(ct.Revision), ErrUncitedRead)
		}
	}
	return nil
}

// ExcerptStore is where the gate reads committed excerpts. A nil store
// refuses every provider row.
type ExcerptStore struct {
	// Read returns a committed file of the repository at a revision.
	Read providerexcerpt.Reader
	// CommitTime returns the commit time of a revision.
	CommitTime providerexcerpt.CommitTimer
	// OnBase fails unless the revision is already part of the base.
	OnBase func(revision string) error
}

var fullRevisionRE = regexp.MustCompile(`^[0-9a-f]{40}$`)

// GitExcerptStore reads excerpts from the git object store of gitDir. A
// cited revision must be an ancestor of baseSHA (or equal to it): excerpts
// the change itself adds are not evidence for the same change.
func GitExcerptStore(gitDir, baseSHA string) (*ExcerptStore, error) {
	if gitDir == "" || !fullRevisionRE.MatchString(baseSHA) {
		return nil, errors.New("an excerpt store needs a git directory and a full base commit")
	}
	return &ExcerptStore{
		Read:       providerexcerpt.GitReader(gitDir),
		CommitTime: providerexcerpt.GitCommitTime(gitDir),
		OnBase: func(revision string) error {
			if !fullRevisionRE.MatchString(revision) {
				return fmt.Errorf("revision %s is not a full commit id", logSafe(revision))
			}
			if err := exec.Command("git", "-C", gitDir, "merge-base", "--is-ancestor", revision, baseSHA).Run(); err != nil {
				return fmt.Errorf("revision %s is not part of the base", revision)
			}
			return nil
		},
	}, nil
}

// OldestClientPinPath is the file that pins the oldest supported client.
const OldestClientPinPath = "cli/knowledge/oldest-supported-client.txt"

// pinVersion reads the version line of a pin file, which holds exactly the
// lines ref= and version=.
func pinVersion(raw []byte) (string, error) {
	text := strings.TrimSuffix(string(raw), "\n")
	lines := strings.Split(text, "\n")
	if len(lines) != 2 || !strings.HasPrefix(lines[0], "ref=") {
		return "", errors.New("the pin file does not hold exactly the lines ref= and version=")
	}
	version, ok := strings.CutPrefix(lines[1], "version=")
	if !ok || !buildidentity.ValidVersion(version) {
		return "", errors.New("the version line of the pin file is not a version")
	}
	return version, nil
}

// providerClientFloor refuses unless the oldest-supported-client pin of both
// the base and the head is at or above the version that can read provider
// facts. A missing or unreadable pin refuses.
func providerClientFloor(opts Options) error {
	for _, t := range []struct {
		name string
		tree Tree
	}{{"base", opts.Base}, {"head", opts.Head}} {
		raw, err := t.tree.Read(OldestClientPinPath, 1024)
		if err != nil {
			return fmt.Errorf("the %s's oldest supported client pin: %v", t.name, err)
		}
		version, err := pinVersion(raw)
		if err != nil {
			return fmt.Errorf("the %s's oldest supported client pin: %v", t.name, err)
		}
		if !buildidentity.AtLeast(version, cncfcheck.ProviderFactsMinClientVersion) {
			return fmt.Errorf("the %s still supports client %s, which cannot read provider facts: no provider fact is admitted before the oldest supported client is %s or later", t.name, version, cncfcheck.ProviderFactsMinClientVersion)
		}
	}
	return nil
}

// distributionResidue is the canonical JSON of a pack's distributions
// section without its records: the applicability statements. A pack without
// the section has the residue of the section with no statements.
func distributionResidue(raw []byte) ([]byte, error) {
	section, present, err := lineattest.PackMemberSection(raw, sectionDistributions)
	if err != nil {
		return nil, err
	}
	if !present {
		return canonicalOf(map[string]any{"applicability": []any{}}), nil
	}
	generic, err := decodeGeneric(section)
	if err != nil {
		return nil, err
	}
	delete(generic, "records")
	return canonicalOf(generic), nil
}

// providerFields are the members of a distribution record the deriver owns.
var providerFields = []string{"lifecycle", "channels", "deprecations", "evidence"}

// identityCanonical is a record's canonical JSON without its provider
// fields.
func identityCanonical(r *record) []byte {
	rest := deepCopy(r.generic)
	m, _ := rest.(map[string]any)
	for _, f := range providerFields {
		delete(m, f)
	}
	return canonicalOf(rest)
}

func hasProviderFacts(d *distribution.Record) bool {
	return d.Lifecycle != nil || d.Channels != nil || d.Deprecations != nil
}

// ErrApplicabilityChange is joined to the refusal of a provider record change
// whose pack also adds or changes an applicability statement. A statement
// changes an evaluation outcome, so no provider change carries one: the first
// introduction of a distribution record carries records only, and later
// changes leave the statements exactly as the base has them.
var ErrApplicabilityChange = errors.New("applicability statements are not admitted through the provider gate")

// applicabilityUnchanged refuses unless the head's applicability statements
// equal the base's (a pack without the section has none), whatever the record
// change is. A missing pack on either side refuses.
func applicabilityUnchanged(base, head *loadedPack) error {
	if base == nil || head == nil {
		return errors.Join(ErrApplicabilityChange, errors.New("the base or head pack is missing"))
	}
	baseResidue := base.DistResidue
	if !base.Present {
		baseResidue = canonicalOf(map[string]any{"applicability": []any{}})
	}
	if !bytes.Equal(baseResidue, head.DistResidue) {
		return errors.Join(ErrApplicabilityChange, errors.New("the record change adds, removes or changes an applicability statement: statements are never part of a provider change"))
	}
	return nil
}

// distributionPre runs the checks of a distribution record change that need
// no excerpt. base is the pack of the base.
func distributionPre(c *Change, base, head *loadedPack, opts Options) error {
	h := c.rhead
	if h == nil || h.dist == nil {
		return errors.New("a distribution record is not removed through the gate")
	}
	if !h.mechanical() {
		return fmt.Errorf("provider facts are admitted only when the gate re-derives them from the committed excerpts (evidence basis mechanical); basis %q is not admitted, and no approval admits it", logSafe(h.Basis))
	}
	if h.State != distribution.StateActive {
		return errors.New("a provider record is admitted only when active")
	}
	if h.Extractor == nil {
		return errors.New("a mechanical distribution record names no extractor")
	}
	if !hasProviderFacts(h.dist) {
		return errors.New("a distribution record without provider facts has nothing to re-derive")
	}
	switch {
	case c.rbase == nil:
		if base == nil || !base.Present {
			return errors.New("a distribution record may not be added together with its pack")
		}
		if _, has := base.Members[sectionDistributions]; has {
			return errors.New("a record for a new distribution is not admitted mechanically: the distribution's identity is introduced with an owner approval")
		}
	case c.rbase.dist == nil || !c.rbase.mechanical():
		return errors.New("only a mechanical distribution record is changed through the gate: its base record is not")
	case !bytes.Equal(identityCanonical(c.rbase), identityCanonical(h)):
		return errors.New("the record differs from its base outside the provider fields (identity, control plane or mapping): not admitted")
	}
	if err := applicabilityUnchanged(base, head); err != nil {
		return err
	}
	return freshRecordDerivation(h, opts.Now)
}

// rederiveDistributions decides the distribution record changes: the
// client floor, the excerpts, and the byte-identical re-derivation. It sets
// OK, Proof and Detail on each change; every refusal is final.
func rederiveDistributions(opts Options, changes []*Change) {
	if len(changes) == 0 {
		return
	}
	failAll := func(why string) {
		for _, c := range changes {
			c.fail("re-derivation failed: " + why)
		}
	}
	if err := providerClientFloor(opts); err != nil {
		failAll(err.Error())
		return
	}
	store := opts.Excerpts
	if store == nil || store.Read == nil || store.CommitTime == nil || store.OnBase == nil {
		failAll("no excerpt store is configured")
		return
	}
	raw, err := opts.Base.Read(providerexcerpt.Dir+"/manifest.json", providerexcerpt.MaxManifestBytes+1)
	if err != nil {
		failAll("the base's excerpt manifest: " + err.Error())
		return
	}
	manifest, err := providerexcerpt.ParseManifest(raw)
	if err != nil {
		failAll("the base's excerpt manifest: " + err.Error())
		return
	}
	for _, c := range changes {
		if err := rederiveDistribution(opts, store, manifest, c); err != nil {
			c.fail("re-derivation failed: " + err.Error())
			continue
		}
		c.OK, c.Proof = true, ProofRederived
	}
}

func rederiveDistribution(opts Options, store *ExcerptStore, manifest providerexcerpt.Manifest, c *Change) error {
	h := c.rhead
	deriver, ok := opts.providerDerivers()[h.Extractor.ID]
	if !ok {
		return fmt.Errorf("no deriver %s is compiled into this gate", logSafe(h.Extractor.ID))
	}
	if *h.Extractor != deriver.Identity || deriver.Derive == nil {
		return fmt.Errorf("the record names deriver %s %s %s, this gate runs %s %s %s", logSafe(h.Extractor.ID), logSafe(h.Extractor.Version), logSafe(h.Extractor.CodeDigest), deriver.Identity.ID, deriver.Identity.Version, deriver.Identity.CodeDigest)
	}
	sources := h.dist.Evidence.Sources
	if len(sources) == 0 {
		return errors.New("the record cites no excerpt")
	}
	for _, s := range sources {
		if err := store.OnBase(s.Revision); err != nil {
			return err
		}
	}
	if err := providerexcerpt.CheckSourcesAt(manifest, sources, store.Read, store.CommitTime); err != nil {
		return err
	}
	derivedAt, err1 := time.Parse(time.RFC3339, h.DerivedAt)
	validUntil, err2 := time.Parse(time.RFC3339, h.ValidUntil)
	if err1 != nil || err2 != nil {
		return errors.New("derivedAt or validUntil is not a time")
	}
	reader, err := newCitedReader(sources, store.Read)
	if err != nil {
		return err
	}
	want, err := deriver.Derive(ProviderDeriveInput{
		Identity: distribution.Record{Distribution: h.dist.Distribution, ControlPlane: h.dist.ControlPlane, KubernetesMapping: h.dist.KubernetesMapping},
		Sources:  sources, Read: reader.Read, Manifest: manifest, DerivedAt: derivedAt, ValidUntil: validUntil,
	})
	if cerr := reader.check(); cerr != nil {
		return errors.Join(cerr, err)
	}
	if err != nil {
		return err
	}
	encoded, err := json.Marshal(want)
	if err != nil {
		return err
	}
	canonical, err := extract.Canonical(json.RawMessage(encoded))
	if err != nil {
		return err
	}
	if !bytes.Equal(canonical, h.Canonical) {
		return fmt.Errorf("the record differs from what deriver %s %s derives from the cited excerpts", deriver.Identity.ID, deriver.Identity.Version)
	}
	return nil
}

const (
	// ApprovalSubjectDistributions is the subject of the owner approval that
	// introduces the distributions member into a pack.
	ApprovalSubjectDistributions = "distributions"
	// DistributionsApprovalID is the rule id such an approval names; it is
	// also the approval's file name (<pack>/member.distributions.json). It is
	// never a rule id or a record ID.
	DistributionsApprovalID = "member.distributions"
	// DistributionsApprovalScope is the scope such an approval names.
	DistributionsApprovalScope = "distributions"
	// DistributionsIntroductionSchema is the schema of the statement such an
	// approval binds.
	DistributionsIntroductionSchema = "prufyx.io/distribution-records-introduction/v1"
)

// DistributionsIntroduction is the statement an approval of subject
// distributions binds (its canonical JSON is the candidate): every record of
// the head with the digest of its canonical bytes, and the digests of the
// base and head pack files.
type DistributionsIntroduction struct {
	Schema         string                          `json:"schema"`
	BasePackDigest string                          `json:"basePackDigest"`
	HeadPackDigest string                          `json:"headPackDigest"`
	Records        []DistributionsIntroductionItem `json:"records"`
}

// DistributionsIntroductionItem is one record the statement names.
type DistributionsIntroductionItem struct {
	Distribution string `json:"distribution"`
	RecordID     string `json:"recordId"`
	Digest       string `json:"digest"`
}

func distributionsIntroductionStatement(base, head *loadedPack) (DistributionsIntroduction, []byte, error) {
	if base == nil || head == nil || !base.Present || !head.Present {
		return DistributionsIntroduction{}, nil, errors.New("the pack is missing from the base or the head")
	}
	if _, ok := base.Members[sectionDistributions]; ok {
		return DistributionsIntroduction{}, nil, errors.New("the base pack already has the distributions member: records change mechanically, with no approval")
	}
	if _, ok := head.Members[sectionDistributions]; !ok {
		return DistributionsIntroduction{}, nil, errors.New("the head pack has no distributions member")
	}
	st := DistributionsIntroduction{Schema: DistributionsIntroductionSchema, BasePackDigest: CandidateDigest(base.Raw), HeadPackDigest: CandidateDigest(head.Raw)}
	for _, id := range head.RecordOrder {
		if rec := head.Records[id]; rec.dist != nil {
			st.Records = append(st.Records, DistributionsIntroductionItem{Distribution: rec.dist.Distribution, RecordID: id, Digest: CandidateDigest(rec.Canonical)})
		}
	}
	sort.Slice(st.Records, func(i, j int) bool { return st.Records[i].RecordID < st.Records[j].RecordID })
	canonical, err := extract.Canonical(st)
	if err != nil {
		return DistributionsIntroduction{}, nil, err
	}
	return st, canonical, nil
}

// distributionsApprovalPath is where a change carries the approval of a
// pack's distributions introduction.
func distributionsApprovalPath(layout Layout, pack string) string {
	return layout.ApprovalDir + "/" + pack + "/" + DistributionsApprovalID + ".json"
}

// DistributionsApprovalSubject reads the introduction of the distributions
// member of a pack between a base and a head checkout exactly as the gate
// reads it, for the owner to sign or check an approval of it.
func DistributionsApprovalSubject(spec PackSpec, base, head Tree) (ApprovalSubject, DistributionsIntroduction, error) {
	b, err := loadPack(base, spec)
	if err != nil {
		return ApprovalSubject{}, DistributionsIntroduction{}, err
	}
	h, err := loadPack(head, spec)
	if err != nil {
		return ApprovalSubject{}, DistributionsIntroduction{}, err
	}
	st, canonical, err := distributionsIntroductionStatement(b, h)
	if err != nil {
		return ApprovalSubject{}, DistributionsIntroduction{}, err
	}
	return ApprovalSubject{Kind: ApprovalSubjectDistributions, Pack: spec.Name, RuleID: DistributionsApprovalID, Scope: DistributionsApprovalScope, Candidate: canonical}, st, nil
}

// admitDistributionIntroduction decides, for every pack whose head holds a
// distributions member the base lacks, whether the introduction is admitted:
// every record was re-derived (its own proof) and an owner approval of
// subject distributions arrives with the change, verifies under the base's
// pinned owner keys and binds exactly the statement of this change. A change
// that is not admitted fails every record of the pack. With the member in
// the base nothing is decided here. It returns the packs it admitted.
func admitDistributionIntroduction(cls *Classification, opts Options, loadKeys func() (*ApprovalKeys, error), approvals *baseApprovals) map[string]bool {
	admitted := map[string]bool{}
	for _, spec := range opts.Layout.Packs {
		base, head := cls.base[spec.Name], cls.head[spec.Name]
		if !spec.Records || base == nil || head == nil || !head.Present {
			continue
		}
		if _, ok := base.Members[sectionDistributions]; ok {
			continue
		}
		if _, ok := head.Members[sectionDistributions]; !ok {
			continue
		}
		var changes []*Change
		allOK := true
		for _, c := range cls.Changes {
			if c.Pack == spec.Name && c.Section == sectionDistributions {
				changes = append(changes, c)
				allOK = allOK && c.OK
			}
		}
		if len(changes) == 0 || !allOK {
			continue // each refused record carries its own reason
		}
		if err := checkDistributionsIntroduction(spec, base, head, opts, loadKeys, approvals); err != nil {
			for _, c := range changes {
				c.fail("introducing the distributions member needs an owner approval bound to every re-derived record: " + err.Error())
			}
			continue
		}
		admitted[spec.Name] = true
	}
	return admitted
}

func checkDistributionsIntroduction(spec PackSpec, base, head *loadedPack, opts Options, loadKeys func() (*ApprovalKeys, error), approvals *baseApprovals) error {
	_, statement, err := distributionsIntroductionStatement(base, head)
	if err != nil {
		return err
	}
	raw, err := opts.Head.ReadOptional(distributionsApprovalPath(opts.Layout, spec.Name), maxApprovalBytes+1)
	if err != nil {
		return fmt.Errorf("approval: %v", err)
	}
	if raw == nil {
		return errors.New("no owner approval")
	}
	if why, err := approvals.refuse(raw); err != nil {
		return fmt.Errorf("approval: %v", err)
	} else if why != "" {
		return errors.New(why)
	}
	keys, err := loadKeys()
	if err != nil {
		return err
	}
	return VerifyRecordApproval(raw, *keys, spec.Name, ApprovalSubjectDistributions, DistributionsApprovalID, DistributionsApprovalScope, nil, statement, opts.Now)
}
