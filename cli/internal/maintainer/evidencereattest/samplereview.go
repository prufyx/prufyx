// SPDX-License-Identifier: AGPL-3.0-only

package evidencereattest

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/prufyx/prufyx/cli/internal/maintainer/evidencerepin"
	"github.com/prufyx/prufyx/cli/internal/maintainer/reviewrecord"
	"github.com/prufyx/prufyx/cli/internal/maintainer/sourcecorpus"
)

// A sample review record is a reviewer's declared decision that one rule a
// prepared human statement sampled for full review still holds at the
// upstream commits that statement compared it with. Every binding it
// carries is computed by NewSampleReview from the prepared statement after
// that statement has been checked against the prior pack, the worklist and
// the compiled engine it names; none is supplied by the caller. Prepare and
// Verify recompute every binding from their own inputs (see
// checkSampleReviews), so a record whose bytes were edited, or that was
// made for another statement's worklist, pack or citations, rejects the
// statement.
//
// It does not bind a contribution packet, a source corpus, reviewed
// vectors or an exported target: a renewal changes no rule content, and
// none of those is an input of a renewal. The record says so in its fixed
// limitations.
const (
	SampleReviewSchema = "prufyx.io/reattestation-sample-review-record/v1"

	sampleReviewAuthority = "DECLARED_REVIEWER_DECISION_NOT_AUTHENTICATED"
	sampleReviewState     = "RULE_CONFIRMED_AT_COMPARED_COMMITS"
	sampleReviewScope     = "ONE_SAMPLED_RULE_OF_ONE_PREPARED_STATEMENT"
	// individualReviewScope is the scope of an individual review record
	// (review-record new --individual): the review of one rule the
	// statement renews, whether or not it is sampled, typically one whose
	// consecutive-batch-cycle count must be reset.
	individualReviewScope = "ONE_INDIVIDUALLY_REVIEWED_RULE_OF_ONE_PREPARED_STATEMENT"
)

// sampleReviewLimitations is the fixed text every sample review record
// carries, in this order.
var sampleReviewLimitations = []string{
	"the reviewer's identity and decision time are declared, not authenticated",
	"the record binds the prepared statement's prior pack, worklist, engine, the rule's exact prior version and its compared citations",
	"it binds no contribution packet, source corpus, reviewed vectors or exported target; a renewal changes no rule content",
}

// SampleReviewDecision is what the reviewer declares.
type SampleReviewDecision struct {
	Authority string `json:"authority"`
	State     string `json:"state"`
	Reviewer  string `json:"reviewer"`
	DecidedAt string `json:"decidedAt"`
	Scope     string `json:"scope"`
}

// SampleReviewSubject names the one rule and the pack version reviewed.
type SampleReviewSubject struct {
	Pack          string `json:"pack"`
	PriorRevision string `json:"priorRevision"`
	Project       string `json:"project"`
	RuleID        string `json:"ruleId"`
}

// SampleReviewBindings ties the record to one prepared statement's inputs
// and to one exact version of the rule and its compared citations.
type SampleReviewBindings struct {
	// PriorPackDigest is the statement's pack.prior.packDigest.
	PriorPackDigest string `json:"priorPackDigest"`
	// WorklistDigest is the statement's worklist.digest; the sample is
	// seeded from it.
	WorklistDigest string `json:"worklistDigest"`
	// EngineCapabilityDigest is the statement's pack.engineCapabilityDigest.
	EngineCapabilityDigest string `json:"engineCapabilityDigest"`
	// RuleDigest, RuleEvidenceDigest and SourcesDigest identify the rule
	// exactly as it is in the prior pack (see ruleDigestAndEvidence).
	RuleDigest         string `json:"ruleDigest"`
	RuleEvidenceDigest string `json:"ruleEvidenceDigest"`
	SourcesDigest      string `json:"sourcesDigest"`
	// CitationsDigest is the digest of the canonical form of the rule's
	// citations as the statement lists them: what was compared, at which
	// upstream tag and commit.
	CitationsDigest string `json:"citationsDigest"`
}

// SampleReviewRecord is the whole record. Its on-disk form is its
// canonical JSON followed by one newline.
type SampleReviewRecord struct {
	Schema      string               `json:"schema"`
	Decision    SampleReviewDecision `json:"decision"`
	Subject     SampleReviewSubject  `json:"subject"`
	Bindings    SampleReviewBindings `json:"bindings"`
	Limitations []string             `json:"limitations"`
}

// SampleReviewOptions names every input NewSampleReview reads. It performs
// no I/O and no network access.
type SampleReviewOptions struct {
	// StatementRaw is the exact canonical statement prepare wrote (without
	// the trailing newline of the file).
	StatementRaw []byte
	// PriorPackRaw, WorklistRaw, PackName and PackPath are the inputs the
	// statement was prepared from, as for Prepare.
	PriorPackRaw []byte
	WorklistRaw  []byte
	PackName     string
	PackPath     string
	// EngineCapabilityDigest is the compiled engine's digest for PackName.
	EngineCapabilityDigest string
	RuleID                 string
	Reviewer               string
	DecidedAt              time.Time
	// Now is the caller's clock: a decision in the future is refused.
	Now time.Time
	// Individual selects the individual review scope: the rule need not be
	// sampled, but must be renewed by the statement or excluded from it only
	// by the consecutive-batch-cycle cap. Its citations are computed from
	// the worklist and the prior pack.
	Individual bool
}

// NewSampleReview renders the sample review record for one rule a prepared
// human statement sampled for full review. It first checks that the
// statement was prepared from exactly the supplied prior pack, worklist and
// engine, that the rule is in the statement's recomputed sample and is a
// rule (not a line attestation or path-policy record), and that the rule's
// version and citations in the statement are the ones the pack and the
// worklist give. The bindings are then taken from that checked statement.
// The output is deterministic: the same inputs give the same bytes.
func NewSampleReview(opts SampleReviewOptions) ([]byte, error) {
	reject := func(format string, args ...any) ([]byte, error) {
		return nil, fmt.Errorf("%w: %s", ErrRejected, fmt.Sprintf(format, args...))
	}
	if evidencerepin.IsRecordID(opts.RuleID) {
		return reject("%s names a line attestation or path-policy record; records take no review record", opts.RuleID)
	}
	if !validReviewerName(opts.Reviewer) {
		return reject("the reviewer name is empty, too long, or contains a slash, a backslash, a control character or surrounding spaces")
	}
	statement, err := ParseStatement(opts.StatementRaw)
	if err != nil {
		return reject("the statement is not a canonical prepared statement")
	}
	role, err := statementRole(statement)
	if err != nil || role != RoleHuman {
		return reject("the statement is not a human statement; only a human statement has a sample")
	}
	if statement.Pack.Name != opts.PackName {
		return reject("the statement is for pack %s, not %s", statement.Pack.Name, opts.PackName)
	}
	doc, err := loadPack(opts.PriorPackRaw)
	if err != nil {
		return reject("prior pack: %v", err)
	}
	if statement.Pack.Prior.PackDigest != packDigest(opts.PriorPackRaw) || statement.Pack.Prior.Revision != doc.Revision {
		return reject("the statement was not prepared from this prior pack")
	}
	if statement.Worklist.Digest != sourcecorpus.SHA(opts.WorklistRaw) {
		return reject("the statement was not prepared from this worklist")
	}
	if opts.EngineCapabilityDigest == "" || statement.Pack.EngineCapabilityDigest != opts.EngineCapabilityDigest {
		return reject("the statement was prepared against a different engine")
	}
	candidates, _, err := packCandidates(doc)
	if err != nil {
		return reject("prior pack: %v", err)
	}
	candidate, ok := candidatesByID(candidates)[opts.RuleID]
	if !ok {
		return reject("rule %s is not in the prior pack", opts.RuleID)
	}
	if candidate.Fields.record {
		return reject("%s names a line attestation or path-policy record; records take no review record", opts.RuleID)
	}
	if err := checkStatementSample(statement); err != nil {
		return nil, err
	}
	sampled := false
	for _, s := range statement.SampledForFullReview {
		sampled = sampled || s.RuleID == opts.RuleID
	}
	var ra *RuleAttestation
	for i := range statement.Rules {
		if statement.Rules[i].RuleID == opts.RuleID {
			ra = &statement.Rules[i]
		}
	}
	capped := false
	for _, ne := range statement.NotExtended {
		capped = capped || (ne.RuleID == opts.RuleID && ne.WorstClass == reasonConsecutiveCycleCap)
	}
	switch {
	case !opts.Individual && !sampled:
		return reject("rule %s is not sampled for full review in this statement", opts.RuleID)
	case !opts.Individual && ra == nil:
		return reject("rule %s is not renewed by this statement under its own project", opts.RuleID)
	case opts.Individual && ra == nil && !capped:
		return reject("rule %s is neither renewed by this statement nor held back only by the consecutive-cycle cap", opts.RuleID)
	}
	ruleDigest, _, sourcesDigest, err := ruleDigestAndEvidence(candidate.Raw)
	if err != nil {
		return nil, err
	}
	citations, err := worklistCitationAttestations(opts.WorklistRaw, opts.PackPath, candidate)
	if err != nil {
		return nil, err
	}
	if len(citations) == 0 {
		return reject("rule %s has no citation in the worklist", opts.RuleID)
	}
	if ra != nil {
		if ra.Project != candidate.Project {
			return reject("rule %s is not renewed by this statement under its own project", opts.RuleID)
		}
		if ra.PriorRuleDigest != ruleDigest || ra.SourcesDigest != sourcesDigest {
			return reject("rule %s in the statement is not the rule in the prior pack", opts.RuleID)
		}
		want, err := canonicalBytes(citations)
		if err != nil {
			return nil, err
		}
		got, err := canonicalBytes(ra.Citations)
		if err != nil || !bytes.Equal(want, got) {
			return reject("rule %s's citations in the statement are not the worklist's", opts.RuleID)
		}
	}
	if opts.DecidedAt.IsZero() || opts.Now.IsZero() {
		return reject("the decision time and the caller's clock are required")
	}
	decidedAt := opts.DecidedAt.UTC().Truncate(time.Second)
	if !decidedAt.Equal(opts.DecidedAt) {
		return reject("the decision time must be whole seconds")
	}
	attestedAt, err := parseUTC(statement.AttestedAt)
	if err != nil || decidedAt.Before(attestedAt) {
		return reject("the decision time is before the statement was prepared")
	}
	if decidedAt.After(opts.Now.UTC()) {
		return reject("the decision time is in the future")
	}
	bindings, err := sampleReviewBindingsFor(statement, candidate.Raw, citations)
	if err != nil {
		return nil, err
	}
	scope := sampleReviewScope
	if opts.Individual {
		scope = individualReviewScope
	}
	record := SampleReviewRecord{
		Schema: SampleReviewSchema,
		Decision: SampleReviewDecision{
			Authority: sampleReviewAuthority, State: sampleReviewState, Reviewer: opts.Reviewer,
			DecidedAt: decidedAt.Format(time.RFC3339), Scope: scope,
		},
		Subject:     sampleReviewSubjectFor(statement, candidate.Project, opts.RuleID),
		Bindings:    bindings,
		Limitations: append([]string(nil), sampleReviewLimitations...),
	}
	raw, err := canonicalBytes(record)
	if err != nil {
		return nil, err
	}
	out := append(raw, '\n')
	if _, err := ParseSampleReview(out); err != nil {
		return reject("record failed self-check")
	}
	return out, nil
}

// checkStatementSample recomputes a human statement's seeded sample from
// its own renewed rules and worklist digest and requires the statement to
// list exactly that sample.
func checkStatementSample(statement Statement) error {
	ids := make([]string, 0, len(statement.Rules))
	for _, r := range statement.Rules {
		ids = append(ids, r.RuleID)
	}
	sort.Strings(ids)
	want := sampleRuleIDs(statement.Worklist.Digest, ids, int(math.Ceil(sampleFraction*float64(len(ids)))))
	sort.Strings(want)
	if len(want) != len(statement.SampledForFullReview) {
		return fmt.Errorf("%w: the statement's sample is not the seeded sample of its rules", ErrRejected)
	}
	for i, s := range statement.SampledForFullReview {
		if s.RuleID != want[i] {
			return fmt.Errorf("%w: the statement's sample is not the seeded sample of its rules", ErrRejected)
		}
	}
	return nil
}

// worklistCitationAttestations renders one rule's citations from the
// worklist the way Prepare puts them into the statement.
func worklistCitationAttestations(worklistRaw []byte, packPath string, candidate ruleCandidate) ([]CitationAttestation, error) {
	if len(worklistRaw) == 0 || len(worklistRaw) > MaxWorklistBytes {
		return nil, fmt.Errorf("%w: worklist size rejected", ErrRejected)
	}
	var wl evidencerepin.Worklist
	if err := json.Unmarshal(worklistRaw, &wl); err != nil || (wl.Schema != evidencerepin.Schema && wl.Schema != evidencerepin.SchemaV1) {
		return nil, fmt.Errorf("%w: decode worklist", ErrRejected)
	}
	repoByKey := map[string]evidencerepin.RepoResolution{}
	for _, repo := range wl.Repos {
		repoByKey[repo.Owner+"/"+repo.Repo] = repo
	}
	var citations []evidencerepin.ClassResult
	for _, c := range wl.Citations {
		if matchesPack(c.RulePack, packPath) && c.RuleID == candidate.RuleID {
			citations = append(citations, c)
		}
	}
	return citationAttestationsFor(candidate, citations, repoByKey), nil
}

// sampleReviewBindingsFor computes a sample review record's bindings from a
// statement, the rule's exact prior-pack bytes and the rule's citations as
// Prepare renders them (citationAttestationsFor).
func sampleReviewBindingsFor(statement Statement, ruleRaw json.RawMessage, ruleCitations []CitationAttestation) (SampleReviewBindings, error) {
	ruleDigest, evidenceDigest, sourcesDigest, err := ruleDigestAndEvidence(ruleRaw)
	if err != nil {
		return SampleReviewBindings{}, err
	}
	citations, err := canonicalBytes(ruleCitations)
	if err != nil {
		return SampleReviewBindings{}, err
	}
	return SampleReviewBindings{
		PriorPackDigest:        statement.Pack.Prior.PackDigest,
		WorklistDigest:         statement.Worklist.Digest,
		EngineCapabilityDigest: statement.Pack.EngineCapabilityDigest,
		RuleDigest:             ruleDigest,
		RuleEvidenceDigest:     evidenceDigest,
		SourcesDigest:          sourcesDigest,
		CitationsDigest:        sourcecorpus.SHA(citations),
	}, nil
}

func sampleReviewSubjectFor(statement Statement, project, ruleID string) SampleReviewSubject {
	return SampleReviewSubject{Pack: statement.Pack.Name, PriorRevision: statement.Pack.Prior.Revision, Project: project, RuleID: ruleID}
}

// IsSampleReview reports whether raw declares the sample review schema. It
// does not validate the record.
func IsSampleReview(raw []byte) bool {
	var head struct {
		Schema string `json:"schema"`
	}
	return json.Unmarshal(raw, &head) == nil && head.Schema == SampleReviewSchema
}

// ParseSampleReview validates a sample review record's exact on-disk bytes
// (canonical JSON and one newline, closed field sets, fixed values,
// well-formed digests and times) and returns it. It does not check the
// bindings; checkSampleReviews does that against a statement.
func ParseSampleReview(raw []byte) (SampleReviewRecord, error) {
	body, ok := bytes.CutSuffix(raw, []byte("\n"))
	if !ok || len(raw) > MaxReviewRecordBytes {
		return SampleReviewRecord{}, ErrRejected
	}
	record, err := decodeExact[SampleReviewRecord](body, MaxReviewRecordBytes)
	if err != nil {
		return SampleReviewRecord{}, err
	}
	d, s, b := record.Decision, record.Subject, record.Bindings
	if record.Schema != SampleReviewSchema || d.Authority != sampleReviewAuthority || d.State != sampleReviewState ||
		(d.Scope != sampleReviewScope && d.Scope != individualReviewScope) || !validReviewerName(d.Reviewer) {
		return SampleReviewRecord{}, ErrRejected
	}
	if len(record.Limitations) != len(sampleReviewLimitations) {
		return SampleReviewRecord{}, ErrRejected
	}
	for i, text := range sampleReviewLimitations {
		if record.Limitations[i] != text {
			return SampleReviewRecord{}, ErrRejected
		}
	}
	if _, err := parseUTC(d.DecidedAt); err != nil {
		return SampleReviewRecord{}, ErrRejected
	}
	if (s.Pack != PackCNCF && s.Pack != PackCommunity) || s.PriorRevision == "" || s.Project == "" || s.RuleID == "" || evidencerepin.IsRecordID(s.RuleID) {
		return SampleReviewRecord{}, ErrRejected
	}
	for _, digest := range []string{b.PriorPackDigest, b.WorklistDigest, b.EngineCapabilityDigest, b.RuleDigest, b.RuleEvidenceDigest, b.SourcesDigest, b.CitationsDigest} {
		if !validDigest(digest) {
			return SampleReviewRecord{}, ErrRejected
		}
	}
	return record, nil
}

// parseReviewRecordFields reads the fields chainState.reviewsFromRecords
// checks from either record format: a sample review record
// (SampleReviewSchema) or a declared review record (maintainer/reviewrecord).
func parseReviewRecordFields(raw []byte) (reviewrecord.RecordFields, error) {
	if !IsSampleReview(raw) {
		return reviewrecord.ParseRecordFields(raw)
	}
	record, err := ParseSampleReview(raw)
	if err != nil {
		return reviewrecord.RecordFields{}, err
	}
	decidedAt, err := parseUTC(record.Decision.DecidedAt)
	if err != nil {
		return reviewrecord.RecordFields{}, ErrRejected
	}
	return reviewrecord.RecordFields{Project: record.Subject.Project, RuleID: record.Subject.RuleID, RuleDigest: record.Bindings.RuleDigest, DecidedAt: decidedAt}, nil
}

// checkSampleReviews checks the review records of a statement being
// prepared. A sampled rule's review is recorded only from a record in this
// format (either scope; Prepare leaves the entry empty for a declared
// review record, which no longer satisfies the sample, and Sign and Verify
// then refuse the statement). Every new record in this format must be for
// a rule the statement renews (and, in the sample scope, samples), be
// decided no earlier than the worklist was generated, and carry exactly the
// subject and bindings this statement and the rule's prior-pack bytes give.
// Prepare runs it, and so Verify does too, through its recomputation
// (checkV1AndV3).
func checkSampleReviews(statement Statement, records map[string][]byte, fresh map[string]string, candidates map[string]ruleCandidate) error {
	sampled := map[string]bool{}
	for _, s := range statement.SampledForFullReview {
		sampled[s.RuleID] = true
		if s.ReviewRecordDigest != "" && !IsSampleReview(records[s.RuleID]) {
			return fmt.Errorf("%w: sample review record for rule %s: a sampled rule needs a record written by review-record new", ErrRejected, s.RuleID)
		}
	}
	renewed := map[string]RuleAttestation{}
	for _, r := range statement.Rules {
		renewed[r.RuleID] = r
	}
	generatedAt, genErr := parseUTC(statement.Worklist.GeneratedAt)
	ids := make([]string, 0, len(fresh))
	for id := range fresh {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		raw := records[id]
		if !IsSampleReview(raw) {
			continue
		}
		record, err := ParseSampleReview(raw)
		if err != nil {
			return fmt.Errorf("%w: sample review record for rule %s is not well formed", ErrRejected, id)
		}
		if record.Decision.Scope == sampleReviewScope && !sampled[id] {
			return fmt.Errorf("%w: sample review record for rule %s: the rule is not sampled for full review in this statement", ErrRejected, id)
		}
		ra, ok := renewed[id]
		candidate, inPack := candidates[id]
		if !ok || !inPack {
			return fmt.Errorf("%w: sample review record for rule %s: the rule is not renewed by this statement", ErrRejected, id)
		}
		decidedAt, err := parseUTC(record.Decision.DecidedAt)
		if err != nil || genErr != nil || decidedAt.Before(generatedAt) {
			return fmt.Errorf("%w: sample review record for rule %s was decided before the worklist was generated", ErrRejected, id)
		}
		if record.Subject != sampleReviewSubjectFor(statement, ra.Project, id) {
			return fmt.Errorf("%w: sample review record for rule %s names another pack, revision, project or rule", ErrRejected, id)
		}
		want, err := sampleReviewBindingsFor(statement, candidate.Raw, ra.Citations)
		if err != nil {
			return err
		}
		got := record.Bindings
		for _, b := range []struct{ name, got, want string }{
			{"priorPackDigest", got.PriorPackDigest, want.PriorPackDigest},
			{"worklistDigest", got.WorklistDigest, want.WorklistDigest},
			{"engineCapabilityDigest", got.EngineCapabilityDigest, want.EngineCapabilityDigest},
			{"ruleDigest", got.RuleDigest, want.RuleDigest},
			{"ruleEvidenceDigest", got.RuleEvidenceDigest, want.RuleEvidenceDigest},
			{"sourcesDigest", got.SourcesDigest, want.SourcesDigest},
			{"citationsDigest", got.CitationsDigest, want.CitationsDigest},
		} {
			if b.got != b.want {
				return fmt.Errorf("%w: sample review record for rule %s: %s does not match this statement", ErrRejected, id, b.name)
			}
		}
	}
	return nil
}

// validReviewerName accepts a public display name or handle: 1-128
// printable characters, no surrounding spaces, no slash or backslash.
func validReviewerName(value string) bool {
	if value == "" || len(value) > 128 || !utf8.ValidString(value) || strings.TrimSpace(value) != value {
		return false
	}
	for _, r := range value {
		if r == '/' || r == '\\' || !unicode.IsPrint(r) {
			return false
		}
	}
	return true
}
