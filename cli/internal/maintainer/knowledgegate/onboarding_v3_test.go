// SPDX-License-Identifier: AGPL-3.0-only

package knowledgegate

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/maintainer/coveragereport"
)

const v3Captured = "2026-09-30"

// addLines adds one additions entry and its tag file per slug to tr, keeping
// the entries already there, and regenerates the README blocks.
func addLines(t *testing.T, tr Tree, slugs ...string) {
	t.Helper()
	file, _, _, err := treeAdditions(tr)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range slugs {
		e, err := coveragereport.SealAddition(s, []byte(addTags), v3Captured, false, "")
		if err != nil {
			t.Fatal(err)
		}
		file.Additions[s] = e
		writeFile(t, tagPath(tr, s), []byte(addTags))
	}
	raw, err := coveragereport.MarshalAdditions(file)
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, addPath(tr), raw)
	regenerateBlocksLoose(tr)
}

// newV3Fixture is the onboarding fixture whose head also adds the additions
// entry and tag file of the onboarded project, bound by the record.
func newV3Fixture(t *testing.T) *onboardingFixture {
	t.Helper()
	f := newOnboardingFixture(t)
	addLines(t, f.head, obSlug)
	f.addSlugs = []string{obSlug}
	return f
}

func v3Detail(t *testing.T, r *Report) string {
	t.Helper()
	c, ok := check(r, CheckOnboarding)
	if !ok {
		return ""
	}
	return c.Detail
}

func TestOnboardingV3Admits(t *testing.T) {
	t.Parallel()
	f := newV3Fixture(t)
	rec := f.record(t)
	f.sign(t, rec)
	raw, err := os.ReadFile(filepath.Join(f.head.Root, filepath.FromSlash(DefaultLayout().Onboarding.Dir), rec.BatchID+".json"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), OnboardingSchemaV3) || !strings.Contains(string(raw), `"additions"`) {
		t.Fatalf("not a v3 file:\n%s", raw)
	}
	r := f.gate(t)
	requirePass(t, r)
	if d := v3Detail(t, r); !strings.Contains(d, "admits 1 projects") {
		t.Fatalf("onboarding detail %q", d)
	}
	// The summary the owner signs shows both digests.
	sum := rec.adds[obSlug]
	st := mustState(t, f)
	text := st.envelopeSummary(OnboardingEnvelope{Schema: OnboardingSchemaV3, Record: rec})
	if !strings.Contains(text, sum.TagFileSha256) || !strings.Contains(text, sum.EntryDigest) {
		t.Fatal("the summary lacks the additions digests")
	}
	if sum.TagFileSha256 != coveragereport.TagFileDigest([]byte(addTags)) {
		t.Fatal("tagFileSha256 is not TagFileDigest(raw)")
	}
}

func mustState(t *testing.T, f *onboardingFixture) *onboardingState {
	t.Helper()
	cls, err := Classify(DefaultLayout(), f.base, f.head)
	if err != nil {
		t.Fatal(err)
	}
	paths, err := ChangedPaths(f.base, f.head)
	if err != nil {
		t.Fatal(err)
	}
	st, err := newOnboardingState(DefaultLayout(), f.base, f.head, cls, paths)
	if err != nil {
		t.Fatal(err)
	}
	return st
}

// Every case must make the gate refuse; none may admit the pack member.
func TestOnboardingV3Refusals(t *testing.T) {
	t.Parallel()
	ol := DefaultLayout().Onboarding
	headFile := func(f *onboardingFixture, rel string) string {
		return filepath.Join(f.head.Root, filepath.FromSlash(rel))
	}
	tagRel := func(s string) string { return coveragereport.PinnedTagsDir + "/" + coveragereport.TagFileName(s) }
	// v3signed signs the v3 fixture, then edit runs.
	v3signed := func(edit func(t *testing.T, f *onboardingFixture, rec OnboardingRecord)) func(t *testing.T, f *onboardingFixture) {
		return func(t *testing.T, f *onboardingFixture) {
			addLines(t, f.head, obSlug)
			f.addSlugs = []string{obSlug}
			rec := f.record(t)
			f.sign(t, rec)
			if edit != nil {
				edit(t, f, rec)
			}
		}
	}
	// withOld puts an earlier project's entry and tag file in base and head.
	withOld := func(t *testing.T, f *onboardingFixture) {
		addLines(t, f.base, "zz-old")
		addLines(t, f.head, "zz-old")
	}
	cases := []struct {
		name  string
		setup func(t *testing.T, f *onboardingFixture)
		want  string
	}{
		{"tag file edited after signing", v3signed(func(t *testing.T, f *onboardingFixture, _ OnboardingRecord) {
			writeFile(t, headFile(f, tagRel(obSlug)), []byte(addTags+"refs/tags/v1.4.0\n"))
		}), "O9"},
		{"entry edited after signing", v3signed(func(t *testing.T, f *onboardingFixture, _ OnboardingRecord) {
			e, err := coveragereport.SealAddition(obSlug, []byte(addTags), "2026-09-29", false, "")
			if err != nil {
				t.Fatal(err)
			}
			raw, _ := coveragereport.MarshalAdditions(coveragereport.AdditionsFile{Additions: map[string]coveragereport.AdditionEntry{obSlug: e}})
			writeFile(t, headFile(f, coveragereport.PinnedAdditionsPath), raw)
		}), "additions entry is not the one the batch was signed for"},
		{"record entryDigest wrong", func(t *testing.T, f *onboardingFixture) {
			addLines(t, f.head, obSlug)
			f.addSlugs = []string{obSlug}
			rec := f.record(t)
			a := rec.adds[obSlug]
			a.EntryDigest = "sha256:" + strings.Repeat("0", 64)
			rec.adds[obSlug] = a
			f.sign(t, rec)
		}, "additions entry is not the one the batch was signed for"},
		{"record tagFileSha256 wrong", func(t *testing.T, f *onboardingFixture) {
			addLines(t, f.head, obSlug)
			f.addSlugs = []string{obSlug}
			rec := f.record(t)
			a := rec.adds[obSlug]
			a.TagFileSha256 = "sha256:" + strings.Repeat("0", 64)
			rec.adds[obSlug] = a
			f.sign(t, rec)
		}, "tag file is not the one the batch was signed for"},
		{"downgrade: v1 record, additions paths in the change", func(t *testing.T, f *onboardingFixture) {
			addLines(t, f.head, obSlug)
			rec, _ := f.tryRecord(t) // addSlugs empty: a v1 record the signer would refuse
			f.sign(t, rec)
		}, "O2"},
		{"extra entry and tag file of an unsigned slug", v3signed(func(t *testing.T, f *onboardingFixture, _ OnboardingRecord) {
			addLines(t, f.head, "zz-extra")
		}), "the batch does not bind"},
		{"extra tag file of a slug not in the record", v3signed(func(t *testing.T, f *onboardingFixture, _ OnboardingRecord) {
			writeFile(t, headFile(f, tagRel("zz-other")), []byte(addTags))
		}), tagRel("zz-other")},
		{"tag file of a base project modified", func(t *testing.T, f *onboardingFixture) {
			withOld(t, f)
			v3signed(func(t *testing.T, f *onboardingFixture, _ OnboardingRecord) {
				writeFile(t, headFile(f, tagRel("zz-old")), []byte(addTags+"x\n"))
			})(t, f)
		}, tagRel("zz-old")},
		{"tag file of a base project deleted", func(t *testing.T, f *onboardingFixture) {
			withOld(t, f)
			v3signed(func(t *testing.T, f *onboardingFixture, _ OnboardingRecord) {
				if err := os.Remove(headFile(f, tagRel("zz-old"))); err != nil {
					t.Fatal(err)
				}
			})(t, f)
		}, tagRel("zz-old")},
		{"entry of an earlier project altered", func(t *testing.T, f *onboardingFixture) {
			withOld(t, f)
			v3signed(func(t *testing.T, f *onboardingFixture, _ OnboardingRecord) {
				file, _, _, err := treeAdditions(f.head)
				if err != nil {
					t.Fatal(err)
				}
				e, err := coveragereport.SealAddition("zz-old", []byte(addTags), "2026-09-29", false, "")
				if err != nil {
					t.Fatal(err)
				}
				file.Additions["zz-old"] = e
				raw, _ := coveragereport.MarshalAdditions(file)
				writeFile(t, headFile(f, coveragereport.PinnedAdditionsPath), raw)
			})(t, f)
		}, "an added entry is immutable"},
		{"bound tag file removed after signing", func(t *testing.T, f *onboardingFixture) {
			// v3 signed, the bound tag file removed again: no tag, an entry.
			v3signed(func(t *testing.T, f *onboardingFixture, _ OnboardingRecord) {
				if err := os.Remove(headFile(f, tagRel(obSlug))); err != nil {
					t.Fatal(err)
				}
			})(t, f)
		}, "O9"},
		{"bound slug already has a tag file in the base", func(t *testing.T, f *onboardingFixture) {
			writeFile(t, filepath.Join(f.base.Root, filepath.FromSlash(tagRel(obSlug))), []byte(addTags))
			addLines(t, f.head, obSlug)
			f.addSlugs = []string{obSlug}
			rec, _ := f.tryRecord(t) // the signer would refuse it
			f.sign(t, rec)
		}, "already exists in the base"},
	}
	_ = ol
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newOnboardingFixture(t)
			tc.setup(t, f)
			r := f.gate(t)
			if d := v3Detail(t, r); d != "" {
				t.Logf("onboarding: %s", d)
			}
			requireFail(t, r, tc.want)
			for _, ch := range r.Changes {
				if ch.Member != "" && ch.OK {
					t.Fatalf("member change admitted: %+v", ch)
				}
			}
		})
	}
}

// Without any record the additions paths are refused for a plain batch and
// for an onboarding change alike: the static admissions are gone.
func TestAdditionsPathsNotAllowedWithoutV3Record(t *testing.T) {
	t.Parallel()
	layout := DefaultLayout()
	base, head := shippedSlice(t), shippedSlice(t)
	putAdditions(t, head, "2026-09-30", "zz-new")
	tagRel := coveragereport.PinnedTagsDir + "/" + coveragereport.TagFileName("zz-new")
	st := &onboardingState{layout: layout, baseTree: base, headTree: head}
	for name, allowed := range map[string]map[string]bool{
		"batch":      batchAllowedPaths(layout, base, head, "batch.json"),
		"onboarding": st.allowedPaths(OnboardingRecord{}, "batch.json"),
	} {
		if allowed[coveragereport.PinnedAdditionsPath] || allowed[tagRel] {
			t.Errorf("%s: an additions path is allowed without a v3 record", name)
		}
	}
	// A v3 record admits the additions file and exactly its own slugs' tag
	// files, never the baseline or the pinned snapshot.
	rec := OnboardingRecord{adds: map[string]OnboardingAdditions{"zz-new": {}}}
	allowed := st.allowedPaths(rec, "batch.json")
	if !allowed[coveragereport.PinnedAdditionsPath] || !allowed[tagRel] {
		t.Error("a v3 record does not admit its own additions paths")
	}
	if allowed[coveragereport.PinnedTagsDir+"/zz-other.tags"] || allowed[coveragereport.BaselinePath] || allowed[coveragereport.PinnedLinesPath] || allowed[coveragereport.PinnedTagsDir] {
		t.Error("a v3 record admits a path outside its own slugs")
	}
}

func TestOnboardingV1V2RefuseAdditionsMember(t *testing.T) {
	t.Parallel()
	add := `"additions": {"entryDigest": "sha256:` + strings.Repeat("0", 64) + `", "tagFileSha256": "sha256:` + strings.Repeat("1", 64) + `"}`
	for name, raw := range map[string]string{
		"v1": `{"schema": "` + OnboardingSchema + `", "record": {"projects": [{` + add + `}]}}`,
		"v2": `{"schema": "` + OnboardingSchemaV2 + `", "record": {"projects": [{` + add + `}]}}`,
	} {
		if _, err := decodeOnboarding([]byte(raw)); err == nil || !strings.Contains(err.Error(), "unknown field") {
			t.Errorf("%s: additions member not refused as an unknown field: %v", name, err)
		}
	}
	// End to end: a signed v1 file with the member injected is O1.
	f := newOnboardingFixture(t)
	rec := f.record(t)
	f.sign(t, rec)
	p := filepath.Join(f.head.Root, filepath.FromSlash(DefaultLayout().Onboarding.Dir), rec.BatchID+".json")
	b, _ := os.ReadFile(p)
	writeFile(t, p, bytes.Replace(b, []byte(`"artifacts"`), []byte(add+`, "artifacts"`), 1))
	requireFail(t, f.gate(t), "O1:")
}

func TestOnboardingV3Validation(t *testing.T) {
	t.Parallel()
	f := newV3Fixture(t)
	good := f.record(t)
	if _, err := SignedOnboardingV3Bytes(joinV3(good)); err != nil {
		t.Fatal(err)
	}
	dig := "sha256:" + strings.Repeat("a", 64)
	mut := map[string]func(r *OnboardingRecord){
		"bad entryDigest shape": func(r *OnboardingRecord) {
			r.adds[obSlug] = OnboardingAdditions{EntryDigest: "sha256:zz", TagFileSha256: dig}
		},
		"bad tagFileSha256": func(r *OnboardingRecord) { r.adds[obSlug] = OnboardingAdditions{EntryDigest: dig, TagFileSha256: "x"} },
		"upper-case digest": func(r *OnboardingRecord) {
			r.adds[obSlug] = OnboardingAdditions{EntryDigest: strings.ToUpper(dig), TagFileSha256: dig}
		},
		"no additions at all": func(r *OnboardingRecord) { r.adds = map[string]OnboardingAdditions{} },
		"additions on kind attest": func(r *OnboardingRecord) {
			r.Projects = append([]OnboardingProject(nil), r.Projects...)
			r.Projects[0].Kind = OnboardingKindAttest
		},
	}
	for name, edit := range mut {
		rec := good
		rec.adds = map[string]OnboardingAdditions{obSlug: good.adds[obSlug]}
		edit(&rec)
		if _, err := SignedOnboardingV3Bytes(joinV3(rec)); err == nil {
			t.Errorf("%s: signed bytes produced", name)
		}
	}
	// A v1 or v2 envelope never signs a record that carries additions.
	if _, err := signedOnboardingEnvelopeBytes(OnboardingEnvelope{Schema: OnboardingSchema, Record: good}); err == nil {
		t.Error("a v1 envelope signed a record with additions")
	}
}

func TestOnboardingV3SignatureDomainAndTier(t *testing.T) {
	t.Parallel()
	f := newV3Fixture(t)
	rec := f.record(t)
	v3msg, err := SignedOnboardingV3Bytes(joinV3(rec))
	if err != nil {
		t.Fatal(err)
	}
	plain := rec
	plain.adds = nil
	v1msg, err := SignedOnboardingBytes(plain)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(v3msg, v1msg) || !bytes.HasPrefix(v3msg, []byte(OnboardingDomainV3)) || !bytes.HasPrefix(v1msg, []byte(OnboardingDomain)) || OnboardingDomainV3 == OnboardingDomain {
		t.Fatal("domains are not separate")
	}
	bot := newApprovalKey(t)
	botKeys := tieredKeys(f.key, bot, "2027-01-01T00:00:00Z")
	keys := botKeys
	// A v3 signature does not verify as v1 over the same projection.
	sig := base64.StdEncoding.EncodeToString(ed25519.Sign(f.key.private, v3msg))
	asV1 := OnboardingEnvelope{Schema: OnboardingSchema, Record: plain, KeyID: ApprovalKeyID(f.key.public), Signature: sig}
	if err := verifyOnboardingSignature(asV1, keys, gateNow); err == nil || !strings.Contains(err.Error(), "does not verify") {
		t.Fatalf("v3 signature verified as v1: %v", err)
	}
	// The reverse: a v1 signature never verifies as v3.
	asV3 := OnboardingEnvelope{Schema: OnboardingSchemaV3, Record: rec, KeyID: ApprovalKeyID(f.key.public), Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(f.key.private, v1msg))}
	if err := verifyOnboardingSignature(asV3, keys, gateNow); err == nil || !strings.Contains(err.Error(), "does not verify") {
		t.Fatalf("v1 signature verified as v3: %v", err)
	}
	// Control: the owner key verifies its v3 batch.
	ok := OnboardingEnvelope{Schema: OnboardingSchemaV3, Record: rec, KeyID: ApprovalKeyID(f.key.public), Signature: sig}
	if err := verifyOnboardingSignature(ok, keys, gateNow); err != nil {
		t.Fatalf("owner v3 refused: %v", err)
	}
	// A bot-tier key never signs v3.
	botRec := rec
	botRec.Identity = botLogin
	botRec.adds = rec.adds
	msg, err := SignedOnboardingV3Bytes(joinV3(botRec))
	if err != nil {
		t.Fatal(err)
	}
	botEnv := OnboardingEnvelope{Schema: OnboardingSchemaV3, Record: botRec, KeyID: ApprovalKeyID(bot.public), Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(bot.private, msg))}
	if err := verifyOnboardingSignature(botEnv, botKeys, gateNow); err == nil || !strings.Contains(err.Error(), "owner-only") {
		t.Fatalf("bot key on v3 not refused as owner-only: %v", err)
	}
}

// The signed bytes of v1 and v2 do not move: a fixed v1 record has one fixed
// encoding, and no v1/v2 type grows an additions member.
func TestOnboardingV1V2BytesUnchanged(t *testing.T) {
	t.Parallel()
	d := "sha256:" + strings.Repeat("a", 64)
	st := OnboardingState{PackRevision: "rev.1", RegistryDigest: d, TableDigest: d, TargetsDigest: d}
	rec := OnboardingRecord{
		Base: st, BatchID: "ob-20261003-1", CandidateID: "pr-1", ChangeSetDigest: d, DecidedAt: "2026-10-03T11:00:00Z", Decision: ApprovalDecisionApprove,
		Head: st, Identity: "airstand", Nonce: obNonce, NotAfter: "2026-10-04T11:00:00Z", Sample: []int{0}, SummaryDigest: d,
		Projects: []OnboardingProject{{
			Artifacts: []OnboardingArtifact{{Path: "a/b.json", Digest: d}}, Catalog: "cncf", Facts: []string{"component.x.custom_resource_versions_set"},
			Groups: []string{"x.example.com"}, Kind: OnboardingKindNew,
			Proof: OnboardingProof{Claims: OnboardingClaims{Confirmed: 1, Ledger: d}, Pair: OnboardingPair{FromCommit: obFrom, FromTag: "v1", ToCommit: obTo, ToTag: "v2"}, Scan: []OnboardingFinding{}},
			Slug:  "x",
		}},
	}
	got, err := SignedOnboardingBytes(rec)
	if err != nil {
		t.Fatal(err)
	}
	s := strings.Repeat("a", 64)
	want := "prufyx.io/knowledge-onboarding-batch/v1\x00" +
		`{"base":{"packRevision":"rev.1","registryDigest":"sha256:` + s + `","tableDigest":"sha256:` + s + `","targetsDigest":"sha256:` + s + `"},` +
		`"batchId":"ob-20261003-1","candidateId":"pr-1","changeSetDigest":"sha256:` + s + `","decidedAt":"2026-10-03T11:00:00Z","decision":"approve",` +
		`"head":{"packRevision":"rev.1","registryDigest":"sha256:` + s + `","tableDigest":"sha256:` + s + `","targetsDigest":"sha256:` + s + `"},` +
		`"identity":"airstand","nonce":"` + obNonce + `","notAfter":"2026-10-04T11:00:00Z",` +
		`"projects":[{"artifacts":[{"digest":"sha256:` + s + `","path":"a/b.json"}],"catalog":"cncf","facts":["component.x.custom_resource_versions_set"],"groups":["x.example.com"],"kind":"new",` +
		`"proof":{"claims":{"confirmed":1,"ledger":"sha256:` + s + `","refuted":0,"undetermined":0},"pair":{"fromCommit":"` + obFrom + `","fromTag":"v1","toCommit":"` + obTo + `","toTag":"v2"},"scan":[]},"slug":"x"}],` +
		`"sample":[0],"summaryDigest":"sha256:` + s + `"}`
	if string(got) != want {
		t.Fatalf("v1 signed bytes moved:\n got %s\nwant %s", got, want)
	}
	// The same record carrying (in-process only) additions still signs as v1
	// bytes through the v1 function, and refuses through the envelope.
	rec.adds = map[string]OnboardingAdditions{"x": {EntryDigest: d, TagFileSha256: d}}
	if again, err := SignedOnboardingBytes(rec); err != nil || !bytes.Equal(again, got) {
		t.Fatal("the unexported additions moved the v1 bytes")
	}
	if _, err := signedOnboardingEnvelopeBytes(OnboardingEnvelope{Schema: OnboardingSchema, Record: rec}); err == nil {
		t.Fatal("a v1 envelope accepted additions")
	}
	if OnboardingDomain != "prufyx.io/knowledge-onboarding-batch/v1\x00" || OnboardingSchemaV2 != "prufyx.io/knowledge-onboarding-batch/v2" {
		t.Fatal("a v1/v2 constant moved")
	}
	// No v1/v2 type encodes an additions member.
	for name, v := range map[string]any{"v1": rec, "v2": OnboardingRecordV2{OnboardingRecord: rec}} {
		raw, err := json.Marshal(v)
		if err != nil || strings.Contains(string(raw), "additions") {
			t.Errorf("%s encodes additions: %v", name, err)
		}
	}
}

// Two bound projects: both tag files and entries present pass; a second slug
// whose tag file is missing is refused, as is an unbound extra entry.
func TestOnboardingV3TwoProjects(t *testing.T) {
	t.Parallel()
	mk := func() (*onboardingState, OnboardingRecord) {
		base, head := shippedSlice(t), shippedSlice(t)
		addLines(t, head, "zz-a", "zz-b")
		adds, err := additionsFromHead(head, []string{"zz-a", "zz-b"})
		if err != nil {
			t.Fatal(err)
		}
		rec := OnboardingRecord{adds: adds, Projects: []OnboardingProject{{Slug: "zz-a", Kind: OnboardingKindNew}, {Slug: "zz-b", Kind: OnboardingKindNew}}}
		return &onboardingState{layout: DefaultLayout(), baseTree: base, headTree: head}, rec
	}
	st, rec := mk()
	if p := st.additionsProblems(rec); len(p) != 0 {
		t.Fatalf("two bound projects refused: %v", p)
	}
	if allowed := st.allowedPaths(rec, "b.json"); !allowed[tagRelOf("zz-a")] || !allowed[tagRelOf("zz-b")] {
		t.Fatal("both tag files must be allowed")
	}
	st, rec = mk()
	if err := os.Remove(tagPath(st.headTree, "zz-b")); err != nil {
		t.Fatal(err)
	}
	if p := st.additionsProblems(rec); len(p) == 0 || !strings.Contains(strings.Join(p, ";"), "zz-b") {
		t.Fatalf("missing second tag file not refused: %v", p)
	}
	st, rec = mk()
	delete(rec.adds, "zz-b") // the record binds only zz-a; the head adds both entries
	if p := st.additionsProblems(rec); len(p) == 0 || !strings.Contains(strings.Join(p, ";"), "does not bind") {
		t.Fatalf("unbound extra entry not refused: %v", p)
	}
}

func tagRelOf(s string) string {
	return coveragereport.PinnedTagsDir + "/" + coveragereport.TagFileName(s)
}
