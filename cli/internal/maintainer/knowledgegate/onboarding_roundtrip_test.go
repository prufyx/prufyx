// SPDX-License-Identifier: AGPL-3.0-only

package knowledgegate

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/maintainer/coveragereport"
)

// roundTripSigned signs a draft that names additions the way the signing
// tool reads it, through the real sign command, and returns the fixture whose
// head now carries the signed envelope.
func roundTripSigned(t *testing.T) (*onboardingFixture, string) {
	t.Helper()
	f := newOnboardingFixture(t)
	addLines(t, f.head, obSlug)
	draft, err := json.Marshal(onboardingDraft{BatchID: f.draft.BatchID, CandidateID: f.draft.CandidateID, Projects: f.draft.Projects, Additions: []string{obSlug}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(draft), `"additions":["`+obSlug+`"]`) {
		t.Fatalf("draft lacks the additions member: %s", draft)
	}
	dir := t.TempDir()
	draftPath := filepath.Join(dir, "draft.json")
	writeFile(t, draftPath, draft)
	keysPath := filepath.Join(f.base.Root, filepath.FromSlash(DefaultLayout().ApprovalKeysPath))
	keysRaw, err := os.ReadFile(keysPath)
	if err != nil {
		t.Fatal(err)
	}
	var confirmed string
	env := approvalEnv{stdin: bytes.NewReader(f.key.pemKey(t)), now: func() time.Time { return f.signedAt }, checkStdin: func(io.Reader) error { return nil },
		confirm: func(prompt string) (string, error) { confirmed = prompt; return f.draft.BatchID, nil }, random: rand.Reader}
	var out, errOut bytes.Buffer
	code := approvalMain([]string{"sign", "--onboarding", draftPath, "--base", f.base.Root, "--head", f.head.Root, "--keys", keysPath, "--keys-digest", pinnedDigest(keysRaw), "--identity", obOwner, "--key-stdin"}, env, DefaultLayout(), &out, &errOut)
	if code != 0 {
		t.Fatalf("sign: %d %s %s", code, out.String(), errOut.String())
	}
	if !strings.Contains(confirmed, "Type the batch id "+f.draft.BatchID) {
		t.Fatalf("prompt %q", confirmed)
	}
	batch := filepath.Join(f.head.Root, filepath.FromSlash(DefaultLayout().Onboarding.Dir), f.draft.BatchID+".json")
	raw, err := os.ReadFile(batch)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), OnboardingSchemaV3) || !strings.Contains(string(raw), `"additions"`) {
		t.Fatalf("the signed file is not a v3 envelope:\n%s", raw)
	}
	return f, batch
}

// The CLI draft -> signed v3 envelope -> real gate path, with the matching
// tree, passes; one flipped tag byte or an altered entry after signing is
// refused by the same gate.
func TestOnboardingV3CLIRoundTrip(t *testing.T) {
	t.Parallel()
	tagRel := coveragereport.PinnedTagsDir + "/" + coveragereport.TagFileName(obSlug)

	t.Run("passes", func(t *testing.T) {
		t.Parallel()
		f, _ := roundTripSigned(t)
		r := f.gate(t)
		requirePass(t, r)
		if d := v3Detail(t, r); !strings.Contains(d, "admits 1 projects") {
			t.Fatalf("onboarding detail %q", d)
		}
	})
	t.Run("tag byte tampered", func(t *testing.T) {
		t.Parallel()
		f, _ := roundTripSigned(t)
		p := filepath.Join(f.head.Root, filepath.FromSlash(tagRel))
		raw, err := os.ReadFile(p)
		if err != nil || len(raw) == 0 {
			t.Fatalf("tag file: %v", err)
		}
		raw[len(raw)/2] ^= 0x01
		writeFile(t, p, raw)
		r := f.gate(t)
		if r.Passed() {
			t.Fatal("a tampered tag byte passed the gate")
		}
		requireFail(t, r, "O9")
	})
	t.Run("entry tampered", func(t *testing.T) {
		t.Parallel()
		f, _ := roundTripSigned(t)
		e, err := coveragereport.SealAddition(obSlug, []byte(addTags), "2026-09-29", false, "")
		if err != nil {
			t.Fatal(err)
		}
		raw, err := coveragereport.MarshalAdditions(coveragereport.AdditionsFile{Additions: map[string]coveragereport.AdditionEntry{obSlug: e}})
		if err != nil {
			t.Fatal(err)
		}
		writeFile(t, filepath.Join(f.head.Root, filepath.FromSlash(coveragereport.PinnedAdditionsPath)), raw)
		r := f.gate(t)
		if r.Passed() {
			t.Fatal("a tampered entry passed the gate")
		}
		requireFail(t, r, "additions entry is not the one the batch was signed for")
	})
}

// A genuinely bot-signed, otherwise valid v2 record whose change also touches
// the additions paths: v2 is bot-only and has no additions member, so the
// additions paths are not admitted.
func TestOnboardingBotSignedV2AdditionsPathsRefused(t *testing.T) {
	t.Parallel()
	a := newAdmissionFixture(t, nil)
	// The signer would refuse this change offline (O2), so the record is
	// completed the way the fixture does without that verdict, then
	// bot-signed with a valid v2 admission binding over the final head.
	addLines(t, a.f.head, obSlug)
	g := a.opts.OnboardingGit
	g.HeadCommit = admissionCommit(t, g.GitDir, a.opts.Head, g.BaseCommit)
	gitIn(t, g.GitDir, "update-ref", admissionHeadRef, g.HeadCommit)
	rec, _ := a.f.tryRecord(t)
	rec.Identity, rec.Decision = botLogin, ApprovalDecisionApprove
	rec.DecidedAt, rec.NotAfter = rfc(gateNow), rfc(gateNow.Add(MaxOnboardingValidity))
	patch, err := admissionGit(context.Background(), g, "diff", "--no-ext-diff", "--no-textconv", "--no-color", "--no-renames", g.BaseCommit, g.HeadCommit, "--")
	if err != nil {
		t.Fatal(err)
	}
	export := OnboardingExportBinding{PlanDigest: CandidateDigest([]byte("plan fixture")), ManifestDigest: CandidateDigest([]byte("manifest fixture")), DraftDigest: CandidateDigest([]byte("draft fixture")), FactsDigest: CandidateDigest([]byte("facts fixture")), BundleDigest: CandidateDigest([]byte("bundle fixture")), ExportLineHash: onboardingLineHash(patch), PublicLineHash: onboardingLineHash(patch)}
	ctx := context.Background()
	cls, err := Classify(a.opts.Layout, a.opts.Base, a.opts.Head)
	if err != nil {
		t.Fatal(err)
	}
	paths, err := ChangedPaths(a.opts.Base, a.opts.Head)
	if err != nil {
		t.Fatal(err)
	}
	st, err := newOnboardingState(a.opts.Layout, a.opts.Base, a.opts.Head, cls, paths)
	if err != nil {
		t.Fatal(err)
	}
	kid := ApprovalKeyID(a.bot.public)
	baseTree, err := admissionObject(ctx, g, g.BaseCommit+"^{tree}")
	if err != nil {
		t.Fatal(err)
	}
	headTree, err := admissionObject(ctx, g, g.HeadCommit+"^{tree}")
	if err != nil {
		t.Fatal(err)
	}
	profile, err := publishedProfile(a.keys, a.opts.ApprovalKeysDigest, rec.Identity, kid, g.BaseCommit, baseTree, a.opts.Now)
	if err != nil {
		t.Fatal(err)
	}
	changes, err := admissionChanges(ctx, g, g.HeadCommit)
	if err != nil {
		t.Fatal(err)
	}
	_, files, err := onboardingFiles(a.opts)
	if err != nil {
		t.Fatal(err)
	}
	hash, err := domainDigest(OnboardingSchemaV2+"/history\x00", files)
	if err != nil {
		t.Fatal(err)
	}
	b := &OnboardingAdmissionBinding{Profile: profile, Export: export, UnsignedCommit: g.HeadCommit, UnsignedTree: headTree, Changes: changes,
		ObservedAt: rec.DecidedAt, DailyCommits: []DailyCommit{}, DailyCount: 0, HistoryDigest: hash}
	if rec.Sample, err = admissionSample(rec, *b); err != nil {
		t.Fatal(err)
	}
	a.env = OnboardingEnvelope{Schema: OnboardingSchemaV2, Record: rec, KeyID: kid, binding: b}
	a.env.Record.SummaryDigest = CandidateDigest([]byte(st.envelopeSummary(a.env)))
	a.commitApproval(t)
	if a.env.Schema != OnboardingSchemaV2 || a.env.binding == nil {
		t.Fatalf("not a v2 envelope: %q", a.env.Schema)
	}
	if err := verifyOnboardingSignature(a.env, a.keys, gateNow); err != nil {
		t.Fatalf("the bot signature must be valid: %v", err)
	}
	if err := checkBotAdmission(context.Background(), a.env, a.keys, a.opts, false); err != nil {
		t.Fatalf("the v2 admission must be valid: %v", err)
	}
	r := runGate(t, a.opts)
	if r.Passed() {
		t.Fatal("a v2 record admitted a change to the additions paths")
	}
	requireNoMemberAdmitted(t, r)
	// Refusal class: O2 (the change set carries files outside what an
	// onboarding batch may change) naming both additions paths; the batch
	// file is then not admitted either.
	requireFail(t, r, "O2: an onboarding change may change only")
	requireFail(t, r, "it also changes 2 other files: "+coveragereport.PinnedAdditionsPath)
	requireFail(t, r, "tags/"+coveragereport.TagFileName(obSlug))
	requireFail(t, r, "no onboarding batch admitted in this change is this file")
}
