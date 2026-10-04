// SPDX-License-Identifier: AGPL-3.0-only

package evidencereattest

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/maintainer/evidencerepin"
	"github.com/prufyx/prufyx/cli/internal/maintainer/sourcecorpus"
)

// sampleFlow is a human batch of 12 due rules in a pack padded to 92 rules,
// prepared once at t1 to learn its sample.
type sampleFlow struct {
	f           *chainFixture
	prior       []byte
	worklistRaw []byte
	first       PrepareResult
	t1          time.Time
}

func newSampleFlow(t *testing.T) sampleFlow {
	t.Helper()
	t1 := baseNow
	wl, pack := buildWorklistAndPack(t, chainPackPath, t1, cycleSpecs(12, t1))
	pack = padPackWithPastRules(t, pack, 80)
	s := sampleFlow{f: newChainFixture(t), prior: pack, worklistRaw: marshalWorklist(t, wl), t1: t1}
	s.first = s.prepare(t, t1, nil)
	if len(s.first.Statement.Rules) != 12 || len(s.first.Statement.SampledForFullReview) != 2 {
		t.Fatalf("setup: expected 12 renewed and 2 sampled, got %d and %d", len(s.first.Statement.Rules), len(s.first.Statement.SampledForFullReview))
	}
	return s
}

func (s sampleFlow) prepare(t *testing.T, at time.Time, records map[string][]byte) PrepareResult {
	t.Helper()
	res, err := s.prepareErr(at, records)
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	return res
}

func (s sampleFlow) prepareErr(at time.Time, records map[string][]byte) (PrepareResult, error) {
	return Prepare(PrepareOptions{
		WorklistRaw: s.worklistRaw, PackName: PackCNCF, PackPath: chainPackPath, PackRaw: s.prior, Chain: s.f.chain(),
		Wave: 1, AttestedAt: at, Now: at, NextRevision: "rev-2", EngineCapabilityDigest: testEngineCapabilityDigest,
		ReviewRecords: records,
	})
}

func (s sampleFlow) options(ruleID string) SampleReviewOptions {
	return SampleReviewOptions{
		StatementRaw: s.first.StatementCanonical, PriorPackRaw: s.prior, WorklistRaw: s.worklistRaw,
		PackName: PackCNCF, PackPath: chainPackPath, EngineCapabilityDigest: testEngineCapabilityDigest,
		RuleID: ruleID, Reviewer: "airstand", DecidedAt: s.t1.Add(10 * time.Minute), Now: s.t1.Add(10 * time.Minute),
	}
}

func (s sampleFlow) sampled() []string {
	var ids []string
	for _, e := range s.first.Statement.SampledForFullReview {
		ids = append(ids, e.RuleID)
	}
	return ids
}

func (s sampleFlow) unsampled(t *testing.T) string {
	t.Helper()
	in := map[string]bool{}
	for _, id := range s.sampled() {
		in[id] = true
	}
	for _, r := range s.first.Statement.Rules {
		if !in[r.RuleID] {
			return r.RuleID
		}
	}
	t.Fatal("setup: every renewed rule is sampled")
	return ""
}

// records writes a sample review record for every sampled rule.
func (s sampleFlow) records(t *testing.T) map[string][]byte {
	t.Helper()
	out := map[string][]byte{}
	for _, id := range s.sampled() {
		raw, err := NewSampleReview(s.options(id))
		if err != nil {
			t.Fatalf("NewSampleReview %s: %v", id, err)
		}
		out[id] = raw
	}
	return out
}

func (s sampleFlow) verify(res PrepareResult, chain *Chain, records map[string][]byte, at time.Time) error {
	base := &Chain{TrustRoot: chain.TrustRoot, ExpectedTrustRootDigest: chain.ExpectedTrustRootDigest}
	for _, e := range chain.Entries {
		if !bytes.Equal(e.Statement, res.StatementCanonical) {
			base.Entries = append(base.Entries, e)
		}
	}
	_, err := Verify(VerifyOptions{
		StatementRaw: res.StatementCanonical, PriorPackRaw: s.prior, NextPackRaw: res.NextPack,
		WorklistRaw: s.worklistRaw, Chain: chain, BaseChain: base, PackName: PackCNCF, PackPath: chainPackPath,
		EngineCapabilityDigest: testEngineCapabilityDigest, AttestedAtNow: at.Add(time.Hour), ReviewRecords: records,
		IndependentWorklistRaw: s.worklistRaw,
	})
	return err
}

func ruleAttestationOf(t *testing.T, statement Statement, id string) RuleAttestation {
	t.Helper()
	for _, r := range statement.Rules {
		if r.RuleID == id {
			return r
		}
	}
	t.Fatalf("%s not renewed", id)
	return RuleAttestation{}
}

// Acceptance: prepare → review-record new for each sampled rule → prepare
// again → sign → append → verify passes.
func TestSampleReviewPrepareSignVerify(t *testing.T) {
	s := newSampleFlow(t)
	records := s.records(t)
	t2 := s.t1.Add(20 * time.Minute)
	res := s.prepare(t, t2, records)
	if renewedIDs(res) != renewedIDs(s.first) {
		t.Fatal("recording the sample's reviews changed which rules were renewed")
	}
	for _, e := range res.Statement.SampledForFullReview {
		if e.ReviewRecordDigest != sourcecorpus.SHA(records[e.RuleID]) {
			t.Fatalf("sampled rule %s: digest %q is not the record's", e.RuleID, e.ReviewRecordDigest)
		}
	}
	if len(res.Statement.IndividualReviews) != 2 {
		t.Fatalf("expected 2 individual reviews, got %+v", res.Statement.IndividualReviews)
	}
	s.f.append("0001", res.StatementCanonical) // signs (Sign refuses an unreviewed sample)
	chain := s.f.chain()
	if _, err := VerifySignature(VerifySignatureOptions{Statement: res.StatementCanonical, Envelope: chain.Entries[0].Envelope, TrustRoot: s.f.root, ExpectedTrustRootDigest: s.f.digest, Now: t2.Add(time.Hour)}); err != nil {
		t.Fatalf("VerifySignature: %v", err)
	}
	if err := s.verify(res, chain, records, t2); err != nil {
		t.Fatalf("Verify: %v", err)
	}

	// The next statement keeps the records in the directory; the chain
	// has counted them, so they are skipped, even though they are bound to
	// the earlier worklist.
	t3 := t2.Add(cycleSpacing)
	wl3, _ := buildWorklistAndPack(t, chainPackPath, t3, cycleSpecs(12, t3))
	next := sampleFlow{f: s.f, prior: res.NextPack, worklistRaw: marshalWorklist(t, wl3), t1: t3}
	if _, err := next.prepareErr(t3, records); err != nil {
		t.Fatalf("a later statement with the counted records still present: %v", err)
	}
}

// Every binding is the value the statement and the inputs give, computed
// independently here.
func TestSampleReviewBindingsAreComputed(t *testing.T) {
	s := newSampleFlow(t)
	id := s.sampled()[0]
	raw, err := NewSampleReview(s.options(id))
	if err != nil {
		t.Fatal(err)
	}
	again, err := NewSampleReview(s.options(id))
	if err != nil || !bytes.Equal(raw, again) {
		t.Fatal("the same inputs gave different records")
	}
	record, err := ParseSampleReview(raw)
	if err != nil {
		t.Fatal(err)
	}
	ra := ruleAttestationOf(t, s.first.Statement, id)
	var ruleRaw json.RawMessage
	var project string
	doc, err := loadPack(s.prior)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range doc.Entries {
		var head struct {
			ID string `json:"id"`
		}
		_ = json.Unmarshal(e.Rule, &head)
		if head.ID == id {
			ruleRaw, project = e.Rule, e.Project
		}
	}
	var rule map[string]any
	if err := json.Unmarshal(ruleRaw, &rule); err != nil {
		t.Fatal(err)
	}
	canon := func(v any) string {
		b, err := sourcecorpus.Canonical(v)
		if err != nil {
			t.Fatal(err)
		}
		return sourcecorpus.SHA(b)
	}
	evidence := rule["evidence"].(map[string]any)
	var citations []any
	citationsJSON, _ := json.Marshal(ra.Citations)
	_ = json.Unmarshal(citationsJSON, &citations)
	if len(citations) != 1 || citations[0].(map[string]any)["comparedCommit"] != strings.Repeat("a", 40) {
		t.Fatalf("setup: unexpected citations %v", citations)
	}
	want := SampleReviewBindings{
		PriorPackDigest:        sourcecorpus.SHA(s.prior),
		WorklistDigest:         sourcecorpus.SHA(s.worklistRaw),
		EngineCapabilityDigest: testEngineCapabilityDigest,
		RuleDigest:             canon(toAny(t, ruleRaw)),
		RuleEvidenceDigest:     canon(toAny(t, mustJSON(t, evidence))),
		SourcesDigest:          canon(toAny(t, mustJSON(t, evidence["sources"]))),
		CitationsDigest:        canon(toAny(t, citationsJSON)),
	}
	if record.Bindings != want {
		t.Fatalf("bindings\n got %+v\nwant %+v", record.Bindings, want)
	}
	if record.Bindings.RuleDigest == record.Bindings.RuleEvidenceDigest || record.Bindings.RuleEvidenceDigest == record.Bindings.SourcesDigest {
		t.Fatal("rule, evidence and sources digests must differ")
	}
	wantSubject := SampleReviewSubject{Pack: PackCNCF, PriorRevision: "rev-1", Project: project, RuleID: id}
	if record.Subject != wantSubject {
		t.Fatalf("subject %+v, want %+v", record.Subject, wantSubject)
	}
	if record.Decision.Reviewer != "airstand" || record.Decision.DecidedAt != rfc3339(s.t1.Add(10*time.Minute)) {
		t.Fatalf("decision %+v", record.Decision)
	}
}

func toAny(t *testing.T, raw []byte) any {
	t.Helper()
	v, err := sourcecorpus.DecodeBounded(raw, int64(len(raw)))
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// rewriteRecord edits a record's decoded form and renders it canonically
// again, so the edit is a well-formed record carrying a wrong value.
func rewriteRecord(t *testing.T, raw []byte, edit func(*SampleReviewRecord)) []byte {
	t.Helper()
	record, err := ParseSampleReview(raw)
	if err != nil {
		t.Fatal(err)
	}
	edit(&record)
	out, err := canonicalBytes(record)
	if err != nil {
		t.Fatal(err)
	}
	return append(out, '\n')
}

// A tampered record, or one made for another statement, is refused by
// prepare; verify refuses it too.
func TestSampleReviewTamperedRecordFails(t *testing.T) {
	s := newSampleFlow(t)
	records := s.records(t)
	id := s.sampled()[0]
	other := "sha256:" + strings.Repeat("e", 64)
	t2 := s.t1.Add(20 * time.Minute)
	cases := map[string]struct {
		edit func(*SampleReviewRecord)
		want string
	}{
		"priorPackDigest":        {func(r *SampleReviewRecord) { r.Bindings.PriorPackDigest = other }, "priorPackDigest does not match"},
		"worklistDigest":         {func(r *SampleReviewRecord) { r.Bindings.WorklistDigest = other }, "worklistDigest does not match"},
		"engineCapabilityDigest": {func(r *SampleReviewRecord) { r.Bindings.EngineCapabilityDigest = other }, "engineCapabilityDigest does not match"},
		"ruleDigest":             {func(r *SampleReviewRecord) { r.Bindings.RuleDigest = other }, "not bound to the rule's current version"},
		"ruleEvidenceDigest":     {func(r *SampleReviewRecord) { r.Bindings.RuleEvidenceDigest = other }, "ruleEvidenceDigest does not match"},
		"sourcesDigest":          {func(r *SampleReviewRecord) { r.Bindings.SourcesDigest = other }, "sourcesDigest does not match"},
		"citationsDigest":        {func(r *SampleReviewRecord) { r.Bindings.CitationsDigest = other }, "citationsDigest does not match"},
		"subject pack":           {func(r *SampleReviewRecord) { r.Subject.Pack = PackCommunity }, "names another pack"},
		"subject revision":       {func(r *SampleReviewRecord) { r.Subject.PriorRevision = "rev-0" }, "names another pack"},
		"subject project":        {func(r *SampleReviewRecord) { r.Subject.Project = "proj-other" }, "names a different rule or project"},
		"decided before the worklist": {func(r *SampleReviewRecord) {
			r.Decision.DecidedAt = rfc3339(s.t1.Add(-time.Second))
		}, "decided before the worklist was generated"},
		"decided after attestedAt": {func(r *SampleReviewRecord) { r.Decision.DecidedAt = rfc3339(t2.Add(time.Second)) }, "decided after attestedAt"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			tampered := map[string][]byte{}
			for k, v := range records {
				tampered[k] = v
			}
			tampered[id] = rewriteRecord(t, records[id], tc.edit)
			_, err := s.prepareErr(t2, tampered)
			if !errors.Is(err, ErrRejected) || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("expected a rejection containing %q, got %v", tc.want, err)
			}
		})
	}

	// Malformed bytes: not canonical, no trailing newline, an extra field,
	// a changed fixed value.
	malformed := map[string][]byte{
		"indented":         append(bytes.ReplaceAll(records[id], []byte(`,"`), []byte(`, "`)), '\n'),
		"no newline":       bytes.TrimSuffix(records[id], []byte("\n")),
		"extra field":      bytes.Replace(records[id], []byte(`{"bindings"`), []byte(`{"aaa":1,"bindings"`), 1),
		"authority":        bytes.Replace(records[id], []byte(sampleReviewAuthority), []byte("DECLARED_REVIEWER_DECISION_AUTHENTICATED"), 1),
		"state":            bytes.Replace(records[id], []byte(sampleReviewState), []byte("RULE_REJECTED"), 1),
		"scope":            bytes.Replace(records[id], []byte(sampleReviewScope), []byte("ANY"), 1),
		"limitation text":  bytes.Replace(records[id], []byte("not authenticated"), []byte("authenticated"), 1),
		"reviewer slash":   bytes.Replace(records[id], []byte(`"reviewer":"airstand"`), []byte(`"reviewer":"air/stand"`), 1),
		"schema":           bytes.Replace(records[id], []byte(SampleReviewSchema), []byte(SampleReviewSchema+"x"), 1),
		"binding not hash": bytes.Replace(records[id], []byte(`"worklistDigest":"sha256:`), []byte(`"worklistDigest":"sha512:`), 1),
	}
	for name, raw := range malformed {
		t.Run(name, func(t *testing.T) {
			if bytes.Equal(raw, records[id]) {
				t.Fatal("setup: the edit changed nothing")
			}
			tampered := map[string][]byte{}
			for k, v := range records {
				tampered[k] = v
			}
			tampered[id] = raw
			if _, err := s.prepareErr(t2, tampered); !errors.Is(err, ErrRejected) {
				t.Fatalf("prepare accepted a malformed record: %v", err)
			}
		})
	}

	// Verify, on an honestly prepared and signed statement, refuses the
	// directory once a record in it is replaced.
	res := s.prepare(t, t2, records)
	s.f.append("0001", res.StatementCanonical)
	if err := s.verify(res, s.f.chain(), records, t2); err != nil {
		t.Fatalf("honest verify: %v", err)
	}
	tampered := map[string][]byte{}
	for k, v := range records {
		tampered[k] = v
	}
	tampered[id] = rewriteRecord(t, records[id], func(r *SampleReviewRecord) { r.Bindings.CitationsDigest = other })
	if err := s.verify(res, s.f.chain(), tampered, t2); err == nil {
		t.Fatal("verify accepted a tampered record")
	}
}

// A record made for one worklist is refused with any other: here a
// second repin whose citations are identical (only a repository's
// resolution time differs) and that samples the same rules, so only the
// worklist binding can refuse the record.
func TestSampleReviewIsBoundToItsWorklist(t *testing.T) {
	s := newSampleFlow(t)
	records := s.records(t)
	at := s.t1.Add(20 * time.Minute)
	for i := 1; i <= 2000; i++ {
		wl, _ := buildWorklistAndPack(t, chainPackPath, s.t1, cycleSpecs(12, s.t1))
		wl.Repos[0].ResolvedAt = rfc3339(s.t1.Add(-time.Hour - time.Duration(i)*time.Second))
		again := s
		again.worklistRaw = marshalWorklist(t, wl)
		probe, err := again.prepareErr(at, nil)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Join(sampledIDs(probe.Statement), ",") != strings.Join(s.sampled(), ",") {
			continue
		}
		_, err = again.prepareErr(at, records)
		if !errors.Is(err, ErrRejected) || !strings.Contains(err.Error(), "worklistDigest does not match") {
			t.Fatalf("expected the worklist binding to refuse the record, got %v", err)
		}
		return
	}
	t.Fatal("setup: no worklist variant sampled the same rules")
}

func sampledIDs(statement Statement) []string {
	var ids []string
	for _, e := range statement.SampledForFullReview {
		ids = append(ids, e.RuleID)
	}
	return ids
}

// Acceptance: a record for a rule the statement did not sample is refused,
// by review-record new and by prepare (and so by verify).
func TestSampleReviewRefusesUnsampledRule(t *testing.T) {
	s := newSampleFlow(t)
	id := s.unsampled(t)
	if _, err := NewSampleReview(s.options(id)); !errors.Is(err, ErrRejected) || !strings.Contains(err.Error(), "not sampled for full review") {
		t.Fatalf("NewSampleReview for an unsampled rule: %v", err)
	}

	// A record built for it by hand, with every binding right.
	ra := ruleAttestationOf(t, s.first.Statement, id)
	candidate := candidatesByIDFromPack(t, s.prior)[id]
	bindings, err := sampleReviewBindingsFor(s.first.Statement, candidate.Raw, ra.Citations)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := canonicalBytes(SampleReviewRecord{
		Schema:   SampleReviewSchema,
		Decision: SampleReviewDecision{Authority: sampleReviewAuthority, State: sampleReviewState, Reviewer: "airstand", DecidedAt: rfc3339(s.t1.Add(10 * time.Minute)), Scope: sampleReviewScope},
		Subject:  sampleReviewSubjectFor(s.first.Statement, ra.Project, ra.RuleID), Bindings: bindings, Limitations: sampleReviewLimitations,
	})
	if err != nil {
		t.Fatal(err)
	}
	records := s.records(t)
	records[id] = append(raw, '\n')
	_, err = s.prepareErr(s.t1.Add(20*time.Minute), records)
	if !errors.Is(err, ErrRejected) || !strings.Contains(err.Error(), "the rule is not sampled for full review in this statement") {
		t.Fatalf("prepare with a record for an unsampled rule: %v", err)
	}
	// The same record is accepted as a declared review record would be
	// only if the rule is sampled: with the rule sampled it passes (the
	// control for the refusal above).
	delete(records, id)
	if _, err := s.prepareErr(s.t1.Add(20*time.Minute), records); err != nil {
		t.Fatalf("control: %v", err)
	}
}

func candidatesByIDFromPack(t *testing.T, packRaw []byte) map[string]ruleCandidate {
	t.Helper()
	doc, err := loadPack(packRaw)
	if err != nil {
		t.Fatal(err)
	}
	candidates, _, err := packCandidates(doc)
	if err != nil {
		t.Fatal(err)
	}
	return candidatesByID(candidates)
}

// review-record new refuses a statement that does not match its inputs,
// and every other request it cannot honestly answer.
func TestNewSampleReviewChecksItsInputs(t *testing.T) {
	s := newSampleFlow(t)
	id := s.sampled()[0]
	other := "sha256:" + strings.Repeat("e", 64)
	editStatement := func(edit func(*Statement)) []byte {
		statement := s.first.Statement
		statement.Rules = append([]RuleAttestation(nil), statement.Rules...)
		for i := range statement.Rules {
			statement.Rules[i].Citations = append([]CitationAttestation(nil), statement.Rules[i].Citations...)
		}
		statement.SampledForFullReview = append([]SampledEntry(nil), statement.SampledForFullReview...)
		edit(&statement)
		raw, err := CanonicalStatement(statement)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ParseStatement(raw); err != nil {
			t.Fatalf("setup: edited statement does not parse: %v", err)
		}
		return raw
	}
	ruleIndex := func(statement *Statement) int {
		for i, r := range statement.Rules {
			if r.RuleID == id {
				return i
			}
		}
		t.Fatal("setup: sampled rule not renewed")
		return -1
	}
	_, otherPack := buildWorklistAndPack(t, chainPackPath, s.t1, cycleSpecs(11, s.t1))
	otherWorklist, _ := buildWorklistAndPack(t, chainPackPath, s.t1.Add(time.Minute), cycleSpecs(12, s.t1))
	cases := map[string]struct {
		edit func(*SampleReviewOptions)
		want string
	}{
		"line attestation id": {func(o *SampleReviewOptions) {
			o.RuleID = evidencerepin.LineAttestationRecordID("pkg:github/kubernetes/kubernetes", "kubernetes.removed-served-gvk", "1.30")
		}, "records take no review record"},
		"path policy id": {func(o *SampleReviewOptions) {
			o.RuleID = evidencerepin.PathPolicyRecordID("pkg:github/kubernetes/kubernetes")
		}, "records take no review record"},
		"rule not in pack":     {func(o *SampleReviewOptions) { o.RuleID = "rule-zz" }, "not in the prior pack"},
		"other pack name":      {func(o *SampleReviewOptions) { o.PackName = PackCommunity }, "is for pack cncf"},
		"other prior pack":     {func(o *SampleReviewOptions) { o.PriorPackRaw = otherPack }, "not prepared from this prior pack"},
		"other worklist":       {func(o *SampleReviewOptions) { o.WorklistRaw = marshalWorklist(t, otherWorklist) }, "not prepared from this worklist"},
		"other engine":         {func(o *SampleReviewOptions) { o.EngineCapabilityDigest = other }, "different engine"},
		"no engine":            {func(o *SampleReviewOptions) { o.EngineCapabilityDigest = "" }, "different engine"},
		"other worklist path":  {func(o *SampleReviewOptions) { o.PackPath = "/other/rules.json" }, "has no citation in the worklist"},
		"not a statement":      {func(o *SampleReviewOptions) { o.StatementRaw = append(append([]byte(nil), o.StatementRaw...), ' ') }, "not a canonical prepared statement"},
		"decided before prep":  {func(o *SampleReviewOptions) { o.DecidedAt = s.t1.Add(-time.Second) }, "before the statement was prepared"},
		"decided in future":    {func(o *SampleReviewOptions) { o.DecidedAt = o.Now.Add(time.Second) }, "in the future"},
		"fractional seconds":   {func(o *SampleReviewOptions) { o.DecidedAt = o.DecidedAt.Add(time.Millisecond) }, "whole seconds"},
		"no decision time":     {func(o *SampleReviewOptions) { o.DecidedAt = time.Time{} }, "are required"},
		"no clock":             {func(o *SampleReviewOptions) { o.Now = time.Time{} }, "are required"},
		"empty reviewer":       {func(o *SampleReviewOptions) { o.Reviewer = "" }, "reviewer name"},
		"reviewer with spaces": {func(o *SampleReviewOptions) { o.Reviewer = " airstand" }, "reviewer name"},
		"reviewer with slash":  {func(o *SampleReviewOptions) { o.Reviewer = "a/b" }, "reviewer name"},
		"reviewer control":     {func(o *SampleReviewOptions) { o.Reviewer = "a\nb" }, "reviewer name"},
		"reviewer too long":    {func(o *SampleReviewOptions) { o.Reviewer = strings.Repeat("a", 129) }, "reviewer name"},
		"sample edited": {func(o *SampleReviewOptions) {
			o.StatementRaw = editStatement(func(st *Statement) { st.SampledForFullReview[0].RuleID = s.unsampled(t) })
		}, "not the seeded sample"},
		"sample shrunk": {func(o *SampleReviewOptions) {
			o.StatementRaw = editStatement(func(st *Statement) { st.SampledForFullReview = st.SampledForFullReview[1:] })
		}, "not the seeded sample"},
		"rule digest edited": {func(o *SampleReviewOptions) {
			o.StatementRaw = editStatement(func(st *Statement) { st.Rules[ruleIndex(st)].PriorRuleDigest = other })
		}, "is not the rule in the prior pack"},
		"sources digest edited": {func(o *SampleReviewOptions) {
			o.StatementRaw = editStatement(func(st *Statement) { st.Rules[ruleIndex(st)].SourcesDigest = other })
		}, "is not the rule in the prior pack"},
		"project edited": {func(o *SampleReviewOptions) {
			o.StatementRaw = editStatement(func(st *Statement) { st.Rules[ruleIndex(st)].Project = "proj-zz" })
		}, "not renewed by this statement under its own project"},
		"compared commit edited": {func(o *SampleReviewOptions) {
			o.StatementRaw = editStatement(func(st *Statement) { st.Rules[ruleIndex(st)].Citations[0].ComparedCommit = strings.Repeat("b", 40) })
		}, "citations in the statement are not the worklist's"},
		"compared tag edited": {func(o *SampleReviewOptions) {
			o.StatementRaw = editStatement(func(st *Statement) { st.Rules[ruleIndex(st)].Citations[0].ComparedTag = "v9.9.9" })
		}, "citations in the statement are not the worklist's"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			opts := s.options(id)
			tc.edit(&opts)
			_, err := NewSampleReview(opts)
			if !errors.Is(err, ErrRejected) || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("expected a rejection containing %q, got %v", tc.want, err)
			}
		})
	}
	// The control: the unedited options succeed, also at the earliest
	// allowed decision time (attestedAt) and with Now equal to it.
	opts := s.options(id)
	opts.DecidedAt, opts.Now = s.t1, s.t1
	if _, err := NewSampleReview(opts); err != nil {
		t.Fatalf("control: %v", err)
	}
}

// review-record new refuses an automated statement (it has no sample) and
// a line attestation or path-policy record in a pack that carries them.
func TestNewSampleReviewRefusesAutomatedStatementsAndRecords(t *testing.T) {
	prior := standardRecordPack(t, baseNow)
	worklistRaw := worklistFromPack(t, prior, baseNow, nil)
	human, err := Prepare(PrepareOptions{
		WorklistRaw: worklistRaw, PackName: PackCNCF, PackPath: chainPackPath, PackRaw: prior, Chain: &Chain{},
		Wave: 1, AttestedAt: baseNow, Now: baseNow, NextRevision: "rev-2", EngineCapabilityDigest: testEngineCapabilityDigest,
	})
	if err != nil {
		t.Fatal(err)
	}
	opts := SampleReviewOptions{
		StatementRaw: human.StatementCanonical, PriorPackRaw: prior, WorklistRaw: worklistRaw, PackName: PackCNCF, PackPath: chainPackPath,
		EngineCapabilityDigest: testEngineCapabilityDigest, Reviewer: "airstand", DecidedAt: baseNow, Now: baseNow,
	}
	for _, id := range []string{reviewedAttestationID, reviewedPolicyID} {
		o := opts
		o.RuleID = id
		if _, err := NewSampleReview(o); !errors.Is(err, ErrRejected) || !strings.Contains(err.Error(), "records take no review record") {
			t.Fatalf("%s: %v", id, err)
		}
	}
	o := opts
	o.RuleID = "rule-a"
	if _, err := NewSampleReview(o); err != nil {
		t.Fatalf("control, rule-a is sampled: %v", err)
	}

	lined := worklistFromPack(t, prior, baseNow, lineBaselined)
	automated, err := Prepare(PrepareOptions{
		WorklistRaw: lined, PackName: PackCNCF, PackPath: chainPackPath, PackRaw: prior, Chain: &Chain{}, Mode: ModeAutomated,
		AttestedAt: baseNow, Now: baseNow, NextRevision: "rev-2", EngineCapabilityDigest: testEngineCapabilityDigest,
	})
	if err != nil {
		t.Fatal(err)
	}
	o.StatementRaw, o.WorklistRaw = automated.StatementCanonical, lined
	if _, err := NewSampleReview(o); !errors.Is(err, ErrRejected) || !strings.Contains(err.Error(), "not a human statement") {
		t.Fatalf("automated statement: %v", err)
	}
}

// ParseSampleReview on its own refuses records whose shape is wrong even
// where a later binding comparison would also catch them.
func TestParseSampleReviewRefusesMalformedRecords(t *testing.T) {
	s := newSampleFlow(t)
	raw, err := NewSampleReview(s.options(s.sampled()[0]))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseSampleReview(raw); err != nil {
		t.Fatalf("control: %v", err)
	}
	for name, edit := range map[string]func(*SampleReviewRecord){
		"schema":             func(r *SampleReviewRecord) { r.Schema = "prufyx.io/declared-knowledge-review-record/v1" },
		"limitation dropped": func(r *SampleReviewRecord) { r.Limitations = r.Limitations[:2] },
		"limitation added":   func(r *SampleReviewRecord) { r.Limitations = append(r.Limitations, "x") },
		"no limitations":     func(r *SampleReviewRecord) { r.Limitations = nil },
		"digest shape":       func(r *SampleReviewRecord) { r.Bindings.CitationsDigest = "sha256:" + strings.Repeat("A", 64) },
		"digest empty":       func(r *SampleReviewRecord) { r.Bindings.WorklistDigest = "" },
		"pack":               func(r *SampleReviewRecord) { r.Subject.Pack = "other" },
		"revision empty":     func(r *SampleReviewRecord) { r.Subject.PriorRevision = "" },
		"project empty":      func(r *SampleReviewRecord) { r.Subject.Project = "" },
		"rule empty":         func(r *SampleReviewRecord) { r.Subject.RuleID = "" },
		"rule is a record id": func(r *SampleReviewRecord) {
			r.Subject.RuleID = evidencerepin.PathPolicyRecordID("pkg:github/kubernetes/kubernetes")
		},
		"decidedAt offset": func(r *SampleReviewRecord) { r.Decision.DecidedAt = "2026-10-06T13:00:00+01:00" },
	} {
		t.Run(name, func(t *testing.T) {
			record, err := ParseSampleReview(raw)
			if err != nil {
				t.Fatal(err)
			}
			edit(&record)
			out, err := canonicalBytes(record)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := ParseSampleReview(append(out, '\n')); err == nil {
				t.Fatal("ParseSampleReview accepted a malformed record")
			}
		})
	}
}

// A declared review record with placeholder bindings no longer satisfies
// the sample: prepare records it as the rule's individual review but leaves
// the sampled entry empty, and sign and verify refuse the statement.
func TestDeclaredRecordDoesNotSatisfyTheSample(t *testing.T) {
	s := newSampleFlow(t)
	records := map[string][]byte{}
	for _, id := range s.sampled() {
		records[id] = testReviewRecord(t, s.prior, id, s.t1.Add(10*time.Minute), "Placeholder")
	}
	t2 := s.t1.Add(20 * time.Minute)
	res := s.prepare(t, t2, records)
	for _, e := range res.Statement.SampledForFullReview {
		if e.ReviewRecordDigest != "" {
			t.Fatalf("a declared record satisfied the sample for %s", e.RuleID)
		}
	}
	if len(res.Statement.IndividualReviews) != 2 {
		t.Fatalf("the declared records must still count as individual reviews, got %+v", res.Statement.IndividualReviews)
	}
	if !strings.Contains(string(res.Summary), "a declared review record does not satisfy the sample") {
		t.Fatalf("summary does not say why the sample is missing:\n%s", res.Summary)
	}
	if _, err := Sign(SignOptions{Role: RoleHuman, Statement: res.StatementCanonical, TrustRoot: s.f.root, EncryptedKey: s.f.key,
		Passphrase: []byte(testPassphrase), ExpectedTrustRootDigest: s.f.digest, Now: t2.Add(time.Hour)}); err == nil || !strings.Contains(err.Error(), "has no recorded individual review") {
		t.Fatalf("Sign: %v", err)
	}
	_, err := Verify(VerifyOptions{
		StatementRaw: res.StatementCanonical, PriorPackRaw: s.prior, NextPackRaw: res.NextPack, WorklistRaw: s.worklistRaw,
		Chain: s.f.chain(), BaseChain: s.f.chain(), PackName: PackCNCF, PackPath: chainPackPath,
		EngineCapabilityDigest: testEngineCapabilityDigest, AttestedAtNow: t2.Add(time.Hour), ReviewRecords: records, PreSign: true,
	})
	if err == nil || !strings.Contains(err.Error(), "has no recorded individual review") {
		t.Fatalf("Verify: %v", err)
	}
	// Replacing the declared records with sample review records, written
	// from this statement, satisfies the sample.
	for _, id := range s.sampled() {
		o := s.options(id)
		o.StatementRaw, o.DecidedAt, o.Now = res.StatementCanonical, t2, t2
		raw, err := NewSampleReview(o)
		if err != nil {
			t.Fatal(err)
		}
		records[id] = raw
	}
	final := s.prepare(t, t2, records)
	for _, e := range final.Statement.SampledForFullReview {
		if e.ReviewRecordDigest != sourcecorpus.SHA(records[e.RuleID]) {
			t.Fatalf("sample review record for %s not recorded", e.RuleID)
		}
	}
}

// review-record new --individual: a rule held back only by the
// consecutive-cycle cap is renewed again once its individual review is
// recorded, in the documented order (individual records, prepare, sample
// records, prepare, sign).
func TestIndividualReviewResetsTheCapThroughReviewRecordNew(t *testing.T) {
	f, _, c2, target, t3 := twoCycleChain(t)
	wl, _ := buildWorklistAndPack(t, chainPackPath, t3, cycleSpecs(12, t3))
	worklistRaw := marshalWorklist(t, wl)
	opts := PrepareOptions{
		WorklistRaw: worklistRaw, PackName: PackCNCF, PackPath: chainPackPath, PackRaw: c2.res.NextPack, Chain: f.chain(),
		Wave: 1, AttestedAt: t3, Now: t3, NextRevision: "rev-4", EngineCapabilityDigest: testEngineCapabilityDigest,
	}
	first, err := Prepare(opts)
	if err != nil {
		t.Fatal(err)
	}
	c := cycle{res: first}
	if worstClassOf(c, target) != reasonConsecutiveCycleCap {
		t.Fatalf("setup: %s is not held back by the cap", target)
	}
	review := SampleReviewOptions{
		StatementRaw: first.StatementCanonical, PriorPackRaw: c2.res.NextPack, WorklistRaw: worklistRaw,
		PackName: PackCNCF, PackPath: chainPackPath, EngineCapabilityDigest: testEngineCapabilityDigest,
		RuleID: target, Reviewer: "airstand", DecidedAt: t3, Now: t3,
	}
	if _, err := NewSampleReview(review); err == nil || !strings.Contains(err.Error(), "not sampled") {
		t.Fatalf("a sample-scope record for a capped rule: %v", err)
	}
	review.Individual = true
	individual, err := NewSampleReview(review)
	if err != nil {
		t.Fatalf("NewSampleReview --individual: %v", err)
	}
	parsed, err := ParseSampleReview(individual)
	if err != nil || parsed.Decision.Scope != individualReviewScope {
		t.Fatalf("scope: %+v %v", parsed.Decision, err)
	}
	opts.ReviewRecords = map[string][]byte{target: individual}
	opts = withSampleRecords(t, opts)
	res, err := Prepare(opts)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, ra := range res.Statement.Rules {
		found = found || (ra.RuleID == target && ra.ConsecutiveBatchCycles == 1)
	}
	if !found {
		t.Fatalf("%s not renewed with a reset count: %s", target, renewedIDs(res))
	}
	reviewed := false
	for _, r := range res.Statement.IndividualReviews {
		reviewed = reviewed || (r.RuleID == target && r.ReviewRecordDigest == sourcecorpus.SHA(individual))
	}
	if !reviewed || !bytes.Equal(opts.ReviewRecords[target], individual) {
		t.Fatalf("the individual review is not recorded: %+v", res.Statement.IndividualReviews)
	}
	f.append("0003", res.StatementCanonical)
	if err := verifyCycle(cycle{res: res, worklistRaw: worklistRaw, prior: c2.res.NextPack, at: t3, reviews: opts.ReviewRecords}, f.chain()); err != nil {
		t.Fatalf("verify: %v", err)
	}

	// The same record with another worklist (a fresh repin) is refused.
	other, _ := buildWorklistAndPack(t, chainPackPath, t3, cycleSpecs(12, t3))
	other.Repos[0].ResolvedAt = rfc3339(t3.Add(-2 * time.Hour))
	_, err = Prepare(PrepareOptions{
		WorklistRaw: marshalWorklist(t, other), PackName: PackCNCF, PackPath: chainPackPath, PackRaw: c2.res.NextPack, Chain: newChainFixtureFrom(f, 2).chain(),
		Wave: 1, AttestedAt: t3, Now: t3, NextRevision: "rev-4", EngineCapabilityDigest: testEngineCapabilityDigest,
		ReviewRecords: map[string][]byte{target: individual},
	})
	if !errors.Is(err, ErrRejected) || !strings.Contains(err.Error(), "worklistDigest does not match") {
		t.Fatalf("an individual record with another worklist: %v", err)
	}
}

// newChainFixtureFrom is f with only its first n chain entries.
func newChainFixtureFrom(f *chainFixture, n int) *chainFixture {
	out := *f
	out.entries = append([]ChainEntry(nil), f.entries[:n]...)
	return &out
}

// An individual record satisfies a sampled rule, and is refused, by new
// and by prepare, for a rule the statement does not renew.
func TestIndividualReviewScope(t *testing.T) {
	s := newSampleFlow(t)
	// A sampled rule's individual review satisfies the sample.
	id := s.sampled()[0]
	o := s.options(id)
	o.Individual = true
	individual, err := NewSampleReview(o)
	if err != nil {
		t.Fatal(err)
	}
	records := s.records(t)
	records[id] = individual
	res := s.prepare(t, s.t1.Add(20*time.Minute), records)
	for _, e := range res.Statement.SampledForFullReview {
		if e.RuleID == id && e.ReviewRecordDigest != sourcecorpus.SHA(individual) {
			t.Fatal("an individual record did not satisfy the sample")
		}
	}
	// An unsampled renewed rule may take an individual record.
	o = s.options(s.unsampled(t))
	o.Individual = true
	if _, err := NewSampleReview(o); err != nil {
		t.Fatalf("individual review of an unsampled renewed rule: %v", err)
	}

	// A rule that is not due is neither renewed nor capped: refused by new;
	// a correctly bound record built for it by hand is refused by prepare.
	specs := cycleSpecs(12, s.t1)
	specs[11].validUntil = rfc3339(s.t1.Add(renewalWindow + time.Hour))
	wl, pack := buildWorklistAndPack(t, chainPackPath, s.t1, specs)
	pack = padPackWithPastRules(t, pack, 80)
	worklistRaw := marshalWorklist(t, wl)
	prep := PrepareOptions{
		WorklistRaw: worklistRaw, PackName: PackCNCF, PackPath: chainPackPath, PackRaw: pack, Chain: &Chain{},
		Wave: 1, AttestedAt: s.t1, Now: s.t1, NextRevision: "rev-2", EngineCapabilityDigest: testEngineCapabilityDigest,
	}
	first, err := Prepare(prep)
	if err != nil {
		t.Fatal(err)
	}
	if worstClassOf(cycle{res: first}, "rule-11") != reasonNotYetDue {
		t.Fatalf("setup: rule-11 is %q", worstClassOf(cycle{res: first}, "rule-11"))
	}
	notDue := SampleReviewOptions{
		StatementRaw: first.StatementCanonical, PriorPackRaw: pack, WorklistRaw: worklistRaw, PackName: PackCNCF, PackPath: chainPackPath,
		EngineCapabilityDigest: testEngineCapabilityDigest, RuleID: "rule-11", Reviewer: "airstand", DecidedAt: s.t1, Now: s.t1, Individual: true,
	}
	if _, err := NewSampleReview(notDue); !errors.Is(err, ErrRejected) || !strings.Contains(err.Error(), "neither renewed by this statement nor held back only by the consecutive-cycle cap") {
		t.Fatalf("individual review of a rule not due: %v", err)
	}
	candidate := candidatesByIDFromPack(t, pack)["rule-11"]
	citations, err := worklistCitationAttestations(worklistRaw, chainPackPath, candidate)
	if err != nil {
		t.Fatal(err)
	}
	bindings, err := sampleReviewBindingsFor(first.Statement, candidate.Raw, citations)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := canonicalBytes(SampleReviewRecord{
		Schema:   SampleReviewSchema,
		Decision: SampleReviewDecision{Authority: sampleReviewAuthority, State: sampleReviewState, Reviewer: "airstand", DecidedAt: rfc3339(s.t1), Scope: individualReviewScope},
		Subject:  sampleReviewSubjectFor(first.Statement, candidate.Project, "rule-11"), Bindings: bindings, Limitations: sampleReviewLimitations,
	})
	if err != nil {
		t.Fatal(err)
	}
	prep.ReviewRecords = map[string][]byte{"rule-11": append(raw, '\n')}
	if _, err := Prepare(prep); !errors.Is(err, ErrRejected) || !strings.Contains(err.Error(), "the rule is not renewed by this statement") {
		t.Fatalf("prepare with an individual record for a rule not renewed: %v", err)
	}
}
