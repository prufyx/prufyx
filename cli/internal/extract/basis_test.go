// SPDX-License-Identifier: AGPL-3.0-only

package extract

import (
	"context"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/prufyx/prufyx/cli/internal/constraintengine"
	"github.com/prufyx/prufyx/cli/internal/lineattest"
	"github.com/prufyx/prufyx/cli/internal/maintainer/rulecheck"
)

// The toy extractor ("toy.removal", fact component.example.flags_set) is a
// stand-in mechanical extractor for these tests: the allowlist and the fact
// family table are extended here and nowhere else. The extractcli drift test
// reads the real tables (its binary does not include this file).
func init() {
	mechanicalExtractorIDs = append(mechanicalExtractorIDs, "toy.removal")
	factFamilyRules = append(factFamilyRules, struct {
		re     *regexp.Regexp
		family string
	}{regexp.MustCompile(`^component\.example\.flags_set$`), "example.flags_set"})
}

// idToy changes the id of a toy.
type idToy struct {
	toyExtractor
	id string
}

func (x idToy) ID() string { return x.id }

// emitterless hides MechanicalFamilies; its id is allowlisted.
type emitterless struct{ x toyExtractor }

func (n emitterless) ID() string                          { return n.x.ID() }
func (n emitterless) Version() string                     { return n.x.Version() }
func (n emitterless) Applies(r RepoRef) bool              { return n.x.Applies(r) }
func (n emitterless) SourceFiles() (string, fs.FS)        { return n.x.SourceFiles() }
func (n emitterless) Pairs(ix ReleaseIndex) []VersionPair { return n.x.Pairs(ix) }
func (n emitterless) Extract(ctx context.Context, r PinnedReader, p VersionPair) (Extraction, error) {
	return n.x.Extract(ctx, r, p)
}

// draftToy is a class-5 style adapter: its id is not allowlisted and it
// implements neither MechanicalEmitter nor LineAttester nor ComponentAttester.
type draftToy struct {
	basis       string
	cite        string
	start, end  int
	quote       string
	reason      string
	attestAlso  bool
	noCandidate bool
}

func (draftToy) ID() string                          { return "class5.release-notes.example" }
func (draftToy) Version() string                     { return "1.0.0" }
func (draftToy) Applies(r RepoRef) bool              { return r.Key == testRepo }
func (draftToy) SourceFiles() (string, fs.FS)        { return toyExtractor{}.SourceFiles() }
func (draftToy) Pairs(ix ReleaseIndex) []VersionPair { return toyExtractor{}.Pairs(ix) }
func (x draftToy) Extract(_ context.Context, r PinnedReader, p VersionPair) (Extraction, error) {
	if _, err := r.Read(p.Repo, p.FromCommit, "decl.go"); err != nil {
		return Extraction{}, err
	}
	if x.noCandidate {
		return Extraction{Proof: "none"}, nil
	}
	cite := x.cite
	if cite == "" {
		cite = "decl.go"
	}
	q, rs := x.quote, x.reason
	if q == "" {
		q = "The flag old is removed."
	}
	if rs == "" {
		rs = "release note names a removal"
	}
	c := Candidate{Basis: x.basis, Project: "example", Quote: q, Reason: rs,
		Sources: []SourceRef{{ID: "note", Repo: p.Repo, Commit: p.FromCommit, Path: cite, StartLine: x.start, EndLine: x.end}}}
	e := Extraction{Proof: "draft", Candidates: []Candidate{c}}
	if x.attestAlso {
		e.Attestations = []AttestationCandidate{attestCandidate(attestComponent)}
	}
	return e, nil
}

func identityForTest() constraintengine.Extractor {
	return constraintengine.Extractor{ID: "toy.removal", Version: "1.0.0", CodeDigest: "sha256:" + strings.Repeat("a", 64)}
}

func rulecheckFor(raw []byte) error {
	r, err := rulecheck.Validate(raw, rulecheck.Options{AllowRange: true})
	if err != nil {
		return err
	}
	if !r.Valid {
		return os.ErrInvalid
	}
	return nil
}

func runAny(t *testing.T, ex Extractor) (*Output, error) {
	t.Helper()
	fr := FixtureReader{Root: toyFixture(t)}
	return Run(context.Background(), ex, fr, fr, Options{Repo: repoRef(t), DerivedAt: toyTime})
}

// Test 1: the basis is default-closed.
func TestBasisEmptyOrUnknownIsNeedsReview(t *testing.T) {
	for _, in := range []string{"", "unknown", "safe", "Mechanical", "MECHANICAL", " mechanical", "reviewed", "Draft"} {
		if got := NormalizeBasis(in); got != BasisNeedsReview {
			t.Fatalf("NormalizeBasis(%q)=%q", in, got)
		}
	}
	for _, in := range []string{BasisMechanical, BasisDraft, BasisNeedsReview} {
		if got := NormalizeBasis(in); got != in {
			t.Fatalf("NormalizeBasis(%q)=%q", in, got)
		}
	}
	// Through the runner: an unknown token from a draft adapter is a
	// needs_review lead, never a rule.
	for _, b := range []string{"", "safe", "Mechanical"} {
		out, err := runAny(t, draftToy{basis: b})
		if err != nil {
			t.Fatalf("basis %q: %v", b, err)
		}
		if len(out.Entries) != 0 || len(out.Drafts) != 1 || out.Drafts[0].Basis != BasisNeedsReview {
			t.Fatalf("basis %q: entries=%d drafts=%+v", b, len(out.Entries), out.Drafts)
		}
	}
}

// Tests 2, 3, 4: mechanical needs the explicit basis, the marker and the
// allowlist together; nothing is downgraded.
func TestMechanicalNeedsMarkerAndAllowlist(t *testing.T) {
	cases := map[string]Extractor{
		"mechanical Candidate from a non-emitter that is allowlisted": emitterless{x: toyExtractor{members: []string{"old"}}},
		"emitter that is not allowlisted":                             idToy{toyExtractor: toyExtractor{members: []string{"old"}}, id: "class5.release-notes.other"},
		"emitter with a near-miss id":                                 idToy{toyExtractor: toyExtractor{members: []string{"old"}}, id: "xtoy.removal"},
		"draft adapter forced mechanical":                             draftToy{basis: BasisMechanical},
	}
	for name, ex := range cases {
		if _, err := runAny(t, ex); err == nil {
			t.Fatalf("%s: run succeeded", name)
		}
	}
	// The allowlisted emitter itself runs.
	if _, err := runAny(t, toyExtractor{members: []string{"old"}}); err != nil {
		t.Fatal(err)
	}
}

func TestMechanicalFamilyBinding(t *testing.T) {
	// A rule over a fact of a family the extractor does not declare.
	bad := toyExtractor{members: []string{"old"}}
	orig := factFamilyRules
	defer func() { factFamilyRules = orig }()
	factFamilyRules = append([]struct {
		re     *regexp.Regexp
		family string
	}(nil), orig[:len(orig)-1]...)
	if _, err := runAny(t, bad); err == nil {
		t.Fatal("a rule over a fact in no known family was stamped")
	}
	factFamilyRules = append(append([]struct {
		re     *regexp.Regexp
		family string
	}(nil), orig[:len(orig)-1]...), struct {
		re     *regexp.Regexp
		family string
	}{regexp.MustCompile(`^component\.example\.flags_set$`), "other.family"})
	if _, err := runAny(t, bad); err == nil {
		t.Fatal("a rule over a fact of an undeclared family was stamped")
	}
	if err := checkMechanicalCandidate("x", map[string]bool{"example.flags_set": true}, Candidate{}); err == nil {
		t.Fatal("a rule with no required fact was admitted as mechanical")
	}
}

// Test 22 (A1): a mechanical extractor never drops a blocker into drafts.
func TestMechanicalEmitterEmittingNonMechanicalIsRunError(t *testing.T) {
	for _, b := range []string{"", BasisNeedsReview, BasisDraft, "safe", "Mechanical"} {
		_, err := runAny(t, toyExtractor{members: []string{"old"}, basis: b, rawBasis: true})
		if err == nil || !strings.Contains(err.Error(), "mechanical extractor") {
			t.Fatalf("basis %q: err %v", b, err)
		}
	}
}

func TestStampRefusesNonMechanical(t *testing.T) {
	if _, err := stamp(Candidate{Basis: BasisDraft}, nil, identityForTest(), "", ""); err == nil {
		t.Fatal("stamp accepted a draft")
	}
	if _, err := stamp(Candidate{}, nil, identityForTest(), "", ""); err == nil {
		t.Fatal("stamp accepted an empty basis")
	}
	if _, err := stampAttestation(AttestationCandidate{Basis: BasisDraft}, nil, RepoRef{}, nil, identityForTest(), "", ""); err == nil {
		t.Fatal("stampAttestation accepted a draft basis")
	}
	if _, err := stampAttestation(AttestationCandidate{}, nil, RepoRef{}, nil, identityForTest(), "", ""); err == nil {
		t.Fatal("stampAttestation accepted an empty basis")
	}
}

// Test 8: drafts and attestations never mix; a draft pair is DRAFT_ONLY.
func TestDraftPairIsNotAttestedDraftOnly(t *testing.T) {
	out, err := runAny(t, draftToy{basis: BasisDraft})
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Entries) != 0 || len(out.Vectors) != 0 || len(out.Attestations) != 0 || len(out.Drafts) != 1 {
		t.Fatalf("out %+v", out)
	}
	p := out.Manifest.Pairs[0]
	if p.Drafts != 1 || p.Attestation == nil || p.Attestation.Status != PairNotAttested || p.Attestation.Reason != "DRAFT_ONLY" || len(p.Attestation.Families) != 0 || len(p.Rules) != 0 {
		t.Fatalf("pair %+v", p)
	}
	if out.Manifest.Totals.Drafts != 1 {
		t.Fatalf("totals %+v", out.Manifest.Totals)
	}
	d := out.Drafts[0]
	if !d.Draft || d.Basis != BasisDraft || d.Extractor.ID != "class5.release-notes.example" || d.From != "1.0.0" || d.To != "2.0.0" || len(d.Sources) != 1 || !strings.HasPrefix(d.Sources[0].ContentDigest, "sha256:") {
		t.Fatalf("draft %+v", d)
	}
	files, err := out.Files()
	if err != nil {
		t.Fatal(err)
	}
	var m Manifest
	if err := json.Unmarshal(files[FileManifest], &m); err != nil {
		t.Fatal(err)
	}
	if m.Outputs[FileDrafts] != digest(files[FileDrafts]) {
		t.Fatalf("manifest does not record the drafts digest: %v", m.Outputs)
	}
	var entries []json.RawMessage
	if err := json.Unmarshal(files[FileCandidates], &entries); err != nil || len(entries) != 0 {
		t.Fatalf("candidates.json %s", files[FileCandidates])
	}
}

func TestDraftWithAttestationsIsRunError(t *testing.T) {
	if _, err := runAny(t, draftToy{basis: BasisDraft, attestAlso: true}); err == nil {
		t.Fatal("drafts with attestations accepted")
	}
}

// Test 8, reflection part: a draft adapter implements none of the marker
// interfaces, and a LineAttester may not emit drafts.
func TestDraftAdapterImplementsNoAttestationOrEmitter(t *testing.T) {
	ty := reflect.TypeOf(draftToy{})
	for _, iface := range []reflect.Type{
		reflect.TypeOf((*LineAttester)(nil)).Elem(),
		reflect.TypeOf((*ComponentAttester)(nil)).Elem(),
		reflect.TypeOf((*MechanicalEmitter)(nil)).Elem(),
	} {
		if ty.Implements(iface) {
			t.Fatalf("draft adapter implements %s", iface)
		}
	}
	// A LineAttester that is not a mechanical emitter and emits a draft.
	if _, err := runAny(t, attestingDraft{}); err == nil {
		t.Fatal("a LineAttester emitted a draft")
	}
}

type attestingDraft struct{ draftToy }

func (attestingDraft) AttestedFamilies() []string {
	return []string{lineattest.FamilyKubernetesRemovedServedGVK}
}

// Test 9: a draft cites only bytes the extractor read.
func TestDraftCitationsMustBeRead(t *testing.T) {
	for name, x := range map[string]draftToy{
		"file not read":    {basis: BasisDraft, cite: "other.go"},
		"past the end":     {basis: BasisDraft, start: 3, end: 4},
		"inverted":         {basis: BasisDraft, start: 3, end: 2},
		"empty quote text": {basis: BasisDraft, quote: "@@@ https://x.invalid/y"},
	} {
		if _, err := runAny(t, x); err == nil {
			t.Fatalf("%s: run succeeded", name)
		}
	}
	if _, err := runAny(t, draftToy{basis: BasisDraft, start: 3, end: 3}); err != nil {
		t.Fatal(err)
	}
}

func TestDraftQuoteIsSanitized(t *testing.T) {
	out, err := runAny(t, draftToy{basis: BasisDraft, quote: "See [docs](https://example.invalid/x) @someone **removed** `old_flag` " + strings.Repeat("long ", 100)})
	if err != nil {
		t.Fatal(err)
	}
	q := out.Drafts[0].Quote
	if strings.ContainsAny(q, "[]()*`@<>") || strings.Contains(q, "http") || len(q) > maxDraftQuote {
		t.Fatalf("quote %q", q)
	}
	if !strings.Contains(q, "removed") || !strings.Contains(q, "old_flag") {
		t.Fatalf("quote lost its words: %q", q)
	}
}

func writeDraftRun(t *testing.T, ex Extractor) (string, *Output) {
	t.Helper()
	out, err := runAny(t, ex)
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "run")
	if err := out.Write(dir); err != nil {
		t.Fatal(err)
	}
	return dir, out
}

func verifyDir(t *testing.T, ex Extractor, dir string) []string {
	t.Helper()
	fr := FixtureReader{Root: toyFixtureCached(t)}
	problems, err := Verify(context.Background(), ex, fr, fr, dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	return problems
}

func toyFixtureCached(t *testing.T) string {
	t.Helper()
	return toyFixture(t)
}

// Test 10: Verify re-derives the drafts byte for byte.
func TestVerifyDraftsTamperAndSwap(t *testing.T) {
	ex := draftToy{basis: BasisDraft}
	dir, _ := writeDraftRun(t, ex)
	if p := verifyDir(t, ex, dir); len(p) != 0 {
		t.Fatalf("clean run has problems %v", p)
	}
	draftsPath := filepath.Join(dir, FileDrafts)
	orig, err := os.ReadFile(draftsPath)
	if err != nil {
		t.Fatal(err)
	}
	mutate := map[string]func(string) string{
		"quote edited":   func(s string) string { return strings.Replace(s, "removed", "kept", 1) },
		"basis swapped":  func(s string) string { return strings.Replace(s, `"basis": "draft"`, `"basis": "needs_review"`, 1) },
		"basis mechanic": func(s string) string { return strings.Replace(s, `"basis": "draft"`, `"basis": "mechanical"`, 1) },
		"basis unknown":  func(s string) string { return strings.Replace(s, `"basis": "draft"`, `"basis": "safe"`, 1) },
		"digest changed": func(s string) string { return strings.Replace(s, "sha256:", "sha256:0", 1) },
	}
	for name, f := range mutate {
		changed := f(string(orig))
		if changed == string(orig) {
			t.Fatalf("%s: mutation did nothing", name)
		}
		if err := os.WriteFile(draftsPath, []byte(changed), 0o644); err != nil {
			t.Fatal(err)
		}
		p := verifyDir(t, ex, dir)
		if len(p) == 0 {
			t.Fatalf("%s: tampered drafts.json verified", name)
		}
	}
	if err := os.WriteFile(draftsPath, orig, 0o644); err != nil {
		t.Fatal(err)
	}
	// A dropped drafts.json and a stray one.
	if err := os.Remove(draftsPath); err != nil {
		t.Fatal(err)
	}
	if p := verifyDir(t, ex, dir); len(p) == 0 {
		t.Fatal("missing drafts.json verified")
	}
	if err := os.WriteFile(draftsPath, orig, 0o644); err != nil {
		t.Fatal(err)
	}
	// Manifest: draft count and attestation record.
	mpath := filepath.Join(dir, FileManifest)
	mraw, _ := os.ReadFile(mpath)
	for name, edit := range map[string][2]string{
		"count":  {`"drafts": 1,`, `"drafts": 2,`},
		"reason": {`"reason": "DRAFT_ONLY"`, `"reason": "x"`},
		"status": {`"status": "not-attested"`, `"status": "attested"`},
	} {
		changed := strings.Replace(string(mraw), edit[0], edit[1], 1)
		if changed == string(mraw) {
			t.Fatalf("%s: manifest edit did nothing", name)
		}
		if err := os.WriteFile(mpath, []byte(changed), 0o644); err != nil {
			t.Fatal(err)
		}
		if p := verifyDir(t, ex, dir); len(p) == 0 {
			t.Fatalf("%s: tampered manifest verified", name)
		}
	}
}

// Test 5: a draft in Entries (candidates.json) or a non-mechanical pack entry
// is refused by Verify's output check and by the candidate rulecheck.
func TestDraftInEntriesIsRefused(t *testing.T) {
	good := `[{"project":"p","description":"d","requiredFacts":[],"rule":{"id":"r","evidence":{"basis":"mechanical"}}}]`
	if p := checkDraftOutputs([]byte(good), nil); len(p) != 0 {
		t.Fatalf("good entry refused: %v", p)
	}
	for name, c := range map[string]string{
		"top-level draft": `[{"draft":true,"basis":"draft","project":"p"}]`,
		"top-level basis": `[{"basis":"mechanical","rule":{"evidence":{"basis":"mechanical"}}}]`,
		"evidence draft":  `[{"rule":{"evidence":{"basis":"draft"}}}]`,
		"evidence needs":  `[{"rule":{"evidence":{"basis":"needs_review"}}}]`,
		"evidence empty":  `[{"rule":{"evidence":{}}}]`,
		"not a list":      `{"a":1}`,
	} {
		if p := checkDraftOutputs([]byte(c), nil); len(p) == 0 {
			t.Fatalf("%s: accepted", name)
		}
	}
	for name, d := range map[string]string{
		"unknown basis": `[{"draft":true,"basis":"safe","extractor":{"id":"a","version":"1.0.0","codeDigest":"c"},"project":"p","from":"1","to":"2","reason":"r","quote":"q","sources":[]}]`,
		"not draft":     `[{"draft":false,"basis":"draft","extractor":{"id":"a","version":"1.0.0","codeDigest":"c"},"project":"p","from":"1","to":"2","reason":"r","quote":"q","sources":[]}]`,
		"extra key":     `[{"draft":true,"basis":"draft","evidence":{},"extractor":{"id":"a","version":"1.0.0","codeDigest":"c"},"project":"p","from":"1","to":"2","reason":"r","quote":"q","sources":[]}]`,
	} {
		if p := checkDraftOutputs(nil, []byte(d)); len(p) == 0 {
			t.Fatalf("%s: accepted", name)
		}
	}
	// The pack rulecheck refuses a draft basis in an entry's evidence.
	out, err := runAny(t, toyExtractor{members: []string{"old"}})
	if err != nil {
		t.Fatal(err)
	}
	for _, b := range []string{BasisDraft, BasisNeedsReview, "safe"} {
		e := out.Entries[0]
		e.Rule.Evidence.Basis = b
		if err := checkCandidates([]Entry{e}, nil); err == nil {
			t.Fatalf("rulecheck accepted evidence basis %q", b)
		}
	}
}

func TestCheckPairDrafts(t *testing.T) {
	ok := PairRecord{From: "1", To: "2", Drafts: 2, Rules: []string{}, Attestation: &PairAttestation{Status: PairNotAttested, Families: []string{}, Reason: PairReasonDraftOnly}}
	if err := CheckPairDrafts(ok); err != nil {
		t.Fatal(err)
	}
	for name, mut := range map[string]func(p *PairRecord){
		"no attestation record": func(p *PairRecord) { p.Attestation = nil },
		"attested":              func(p *PairRecord) { p.Attestation = &PairAttestation{Status: PairAttested, Families: []string{"f"}} },
		"families":              func(p *PairRecord) { p.Attestation.Families = []string{"f"} },
		"other reason":          func(p *PairRecord) { p.Attestation.Reason = "later" },
		"rules listed":          func(p *PairRecord) { p.Rules = []string{"r"} },
		"negative":              func(p *PairRecord) { p.Drafts = -1 },
	} {
		p := ok
		a := *ok.Attestation
		p.Attestation = &a
		mut(&p)
		if CheckPairDrafts(p) == nil {
			t.Fatalf("%s: accepted", name)
		}
	}
}

// Test 17: the manifest schema is fail-closed in both directions.
func TestManifestSchemaBumpIsFailClosed(t *testing.T) {
	if ManifestSchema != "prufyx.io/extractor-run-manifest/v2" {
		t.Fatalf("schema %q", ManifestSchema)
	}
	write := func(schema string) string {
		dir := t.TempDir()
		raw := `{"schema":"` + schema + `","extractor":{"id":"a","version":"1.0.0","codeDigest":"c"},"codeFiles":[],"repo":"github.com/a/b","derivedAt":"","validUntil":"","pairs":[],"commits":[],"outputs":{},"totals":{}}`
		if err := os.WriteFile(filepath.Join(dir, FileManifest), []byte(raw), 0o644); err != nil {
			t.Fatal(err)
		}
		return dir
	}
	if _, err := ReadManifest(write("prufyx.io/extractor-run-manifest/v1")); err == nil {
		t.Fatal("an old manifest was read")
	}
	if _, err := ReadManifest(write("prufyx.io/extractor-run-manifest/v3")); err == nil {
		t.Fatal("a newer manifest was read")
	}
	if _, err := ReadManifest(write("")); err == nil {
		t.Fatal("a manifest without a schema was read")
	}
	if _, err := ReadManifest(write(ManifestSchema)); err != nil {
		t.Fatal(err)
	}
}

// The skeleton is a printing aid, not a pack entry.
func TestSkeletonIsNotAPackEntry(t *testing.T) {
	out, err := runAny(t, draftToy{basis: BasisDraft})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := Skeleton(out.Drafts[0])
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "<REVIEWER-") {
		t.Fatalf("no placeholders: %s", raw)
	}
	if _, err := Skeleton(DraftEntry{}); err == nil {
		t.Fatal("skeleton of a non-draft")
	}
	var generic map[string]any
	if err := json.Unmarshal(raw, &generic); err != nil {
		t.Fatal(err)
	}
	if _, has := generic["draft"]; has {
		t.Fatal("skeleton carries a draft key")
	}
	// The pack rulecheck refuses it.
	var e map[string]any
	_ = json.Unmarshal(raw, &e)
	list, _ := json.Marshal([]any{e})
	if rulecheckFor(list) == nil {
		t.Fatal("rulecheck accepted the skeleton")
	}
}

func TestAllowlistKeyChangeMovesCodeDigest(t *testing.T) {
	base, err := CodeFiles(FrameworkSource())
	if err != nil {
		t.Fatal(err)
	}
	mod := fstest.MapFS{}
	names, _ := fs.Glob(frameworkSource, "*.go")
	for _, n := range names {
		raw, err := fs.ReadFile(frameworkSource, n)
		if err != nil {
			t.Fatal(err)
		}
		if n == "drafts.go" {
			raw = []byte(strings.Replace(string(raw), `"crd.version-removal.",`, `"crd.version-removal.",`+"\n\t"+`"class5.new.",`, 1))
		}
		mod[n] = &fstest.MapFile{Data: raw}
	}
	changed, err := CodeFiles(SourceSet{Dir: FrameworkDir, Files: mod})
	if err != nil {
		t.Fatal(err)
	}
	if CodeDigest(base) == CodeDigest(changed) {
		t.Fatal("an allowlist change did not move the code digest")
	}
}

// attestOutsideMech is a mechanical emitter that attests a family it does
// not declare as mechanical: the run refuses it.
type attestOutsideMech struct{ toyExtractor }

func (attestOutsideMech) AttestedFamilies() []string {
	return []string{lineattest.FamilyKubernetesRemovedServedGVK}
}

func TestMechanicalAttesterFamilyOutsideMechanicalIsRunError(t *testing.T) {
	_, err := runAny(t, attestOutsideMech{toyExtractor{members: []string{"old"}}})
	if err == nil || !strings.Contains(err.Error(), "outside its mechanical families") {
		t.Fatalf("err %v", err)
	}
}

// strayNotAttested is a draft adapter that also returns a not-attested text.
type strayNotAttested struct{ draftToy }

func (x strayNotAttested) Extract(ctx context.Context, r PinnedReader, p VersionPair) (Extraction, error) {
	e, err := x.draftToy.Extract(ctx, r, p)
	e.NotAttested = "stray text"
	return e, err
}

func TestDraftPairWithStrayNotAttestedIsRunError(t *testing.T) {
	if _, err := runAny(t, strayNotAttested{draftToy{basis: BasisDraft}}); err == nil {
		t.Fatal("drafts together with a not-attested text accepted")
	}
	if _, err := runAny(t, draftToy{basis: BasisDraft}); err != nil {
		t.Fatal(err)
	}
}
