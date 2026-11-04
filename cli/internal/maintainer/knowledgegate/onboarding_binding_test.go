// SPDX-License-Identifier: AGPL-3.0-only

package knowledgegate

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/extract"
)

func admissionCommit(t *testing.T, repo string, tr Tree, parent string) string {
	t.Helper()
	gitIn(t, repo, "--work-tree="+tr.Root, "read-tree", "--empty")
	gitIn(t, repo, "--work-tree="+tr.Root, "add", "--all")
	tree := gitIn(t, repo, "write-tree")
	args := []string{"--git-dir=" + repo, "-c", "user.name=Test", "-c", "user.email=test@example.invalid", "-c", "commit.gpgsign=false", "commit-tree", tree, "-m", "test snapshot"}
	if parent != "" {
		args = append(args, "-p", parent)
	}
	cmd := exec.Command("git", args...)
	old := gateNow.Add(-48 * time.Hour).Format(time.RFC3339)
	cmd.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null", "GIT_AUTHOR_DATE="+old, "GIT_COMMITTER_DATE="+old)
	raw, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("commit fixture: %v %s", err, raw)
	}
	return strings.TrimSpace(string(raw))
}

type admissionFixture struct {
	f    *onboardingFixture
	bot  testApprovalKey
	keys ApprovalKeys
	opts Options
	env  OnboardingEnvelope
}

func newAdmissionFixture(t *testing.T, history func(*onboardingFixture, testApprovalKey)) admissionFixture {
	t.Helper()
	f := newOnboardingFixture(t)
	bot := f.pinBot(t, "2027-01-01T00:00:00Z")
	if history != nil {
		history(f, bot)
	}
	repo := t.TempDir()
	gitIn(t, repo, "init", "--bare", "-q")
	base := admissionCommit(t, repo, f.base, "")
	head := admissionCommit(t, repo, f.head, base)
	gitIn(t, repo, "update-ref", admissionBaseRef, base)
	gitIn(t, repo, "update-ref", admissionHeadRef, head)
	paused := false
	zero := 0
	keyRaw, err := f.base.Read(DefaultLayout().ApprovalKeysPath, MaxFileBytes)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := ParseApprovalKeys(keyRaw)
	if err != nil {
		t.Fatal(err)
	}
	g := &OnboardingGitContext{GitDir: repo, BaseCommit: base, HeadCommit: head, DailyCommits: []DailyCommit{}, Paused: &paused, ObservedAt: gateNow}
	opts := Options{Layout: DefaultLayout(), Base: f.base, Head: f.head, Source: f.src, Now: gateNow, OnboardingGit: g, ApprovalKeysDigest: pinnedDigest(keyRaw), BotLogin: DefaultBotLogin, MaxLoosening: 200, MaxWithdrawPercent: 5, MaxWithdrawProject: 20, MaxDailyLoosening: 50, DailyLoosening: &zero, AdmissionRESTBudget: 900, Author: botLogin, Sender: botLogin}
	rec, _, err := prepareOnboarding(opts.Layout, f.base, f.head, f.draft, obNonce, opts.Layout.Onboarding.Dir+"/"+f.draft.BatchID+".json")
	if err != nil {
		t.Fatal(err)
	}
	rec.Identity, rec.Decision = botLogin, ApprovalDecisionApprove
	rec.DecidedAt, rec.NotAfter = rfc(gateNow), rfc(gateNow.Add(MaxOnboardingValidity))
	patch, err := admissionGit(context.Background(), g, "diff", "--no-ext-diff", "--no-textconv", "--no-color", "--no-renames", base, head, "--")
	if err != nil {
		t.Fatal(err)
	}
	export := OnboardingExportBinding{PlanDigest: CandidateDigest([]byte("plan fixture")), ManifestDigest: CandidateDigest([]byte("manifest fixture")), DraftDigest: CandidateDigest([]byte("draft fixture")), FactsDigest: CandidateDigest([]byte("facts fixture")), BundleDigest: CandidateDigest([]byte("bundle fixture")), ExportLineHash: onboardingLineHash(patch), PublicLineHash: onboardingLineHash(patch)}
	e, err := prepareBotAdmission(context.Background(), opts, keys, rec, export, ApprovalKeyID(bot.public))
	if err != nil {
		t.Fatal(err)
	}
	return admissionFixture{f: f, bot: bot, keys: keys, opts: opts, env: e}
}

func signAdmission(t *testing.T, e OnboardingEnvelope, key testApprovalKey) OnboardingEnvelope {
	t.Helper()
	msg, err := signedOnboardingEnvelopeBytes(e)
	if err != nil {
		t.Fatal(err)
	}
	e.KeyID = ApprovalKeyID(key.public)
	e.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(key.private, msg))
	return e
}

func (a *admissionFixture) commitApproval(t *testing.T) {
	t.Helper()
	a.env = signAdmission(t, a.env, a.bot)
	raw, err := marshalOnboardingEnvelope(a.env)
	if err != nil {
		t.Fatal(err)
	}
	a.f.writeBatch(t, a.opts.Head, a.env.Record.BatchID+".json", append(raw, '\n'))
	g := a.opts.OnboardingGit
	g.HeadCommit = admissionCommit(t, g.GitDir, a.opts.Head, g.HeadCommit)
	a.opts.HeadSHA = g.HeadCommit
	gitIn(t, g.GitDir, "update-ref", admissionHeadRef, g.HeadCommit)
}

func cloneAdmission(t *testing.T, e OnboardingEnvelope) OnboardingEnvelope {
	t.Helper()
	raw, err := marshalOnboardingEnvelope(e)
	if err != nil {
		t.Fatal(err)
	}
	out, err := decodeOnboarding(raw)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestOnboardingV2AdmissionAndGate(t *testing.T) {
	t.Parallel()
	a := newAdmissionFixture(t, nil)
	if err := checkBotAdmission(context.Background(), a.env, a.keys, a.opts, true); err != nil {
		t.Fatal(err)
	}
	a.commitApproval(t)
	if err := verifyOnboardingSignature(a.env, a.keys, gateNow); err != nil {
		t.Fatal(err)
	}
	if err := checkBotAdmission(context.Background(), a.env, a.keys, a.opts, false); err != nil {
		t.Fatal(err)
	}
	wrongHead := a.opts
	wrongHead.HeadSHA = a.opts.OnboardingGit.BaseCommit
	if err := checkBotAdmission(context.Background(), a.env, a.keys, wrongHead, false); err == nil {
		t.Fatal("verified report accepted a different head label")
	}
	r := runGate(t, a.opts)
	requirePass(t, r)
	c, _ := check(r, CheckOnboarding)
	if !strings.Contains(c.Detail, "bot tier: sample drawn, not read") {
		t.Fatalf("bot review scope: %s", c.Detail)
	}
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
	summary := st.envelopeSummary(a.env)
	if !strings.Contains(summary, "Sample drawn, not human-reviewed") || strings.Contains(summary, "Sample read in full:") || strings.Contains(summary, "| in full |") {
		t.Fatal("v2 summary implies human source reading")
	}
	if !strings.Contains(st.summary(a.env.Record), "Sample read in full:") {
		t.Fatal("v1 summary bytes changed")
	}
	if r.AutoMerge.Eligible || !strings.Contains(strings.Join(r.AutoMerge.Reasons, ";"), "onboarding batch") {
		t.Fatalf("onboarding automatic merge changed: %+v", r.AutoMerge)
	}
	msg, err := signedOnboardingEnvelopeBytes(a.env)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(msg, []byte(OnboardingSchemaV2+"\x00")) {
		t.Fatal("v2 domain missing")
	}
	v1, err := SignedOnboardingBytes(a.env.Record)
	if err != nil {
		t.Fatal(err)
	}
	sig, _ := base64.StdEncoding.DecodeString(a.env.Signature)
	if ed25519.Verify(a.bot.public, v1, sig) {
		t.Fatal("v2 verifies in v1 domain")
	}
}

func TestOnboardingV2RejectsRestoredCallerState(t *testing.T) {
	t.Parallel()
	a := newAdmissionFixture(t, nil)
	draftRaw, _ := json.Marshal(a.f.draft)
	var draft onboardingDraft
	if err := json.Unmarshal(draftRaw, &draft); err != nil {
		t.Fatal(err)
	}
	rel := draft.Projects[0].Artifacts[0].Path
	original, err := a.opts.Head.Read(rel, MaxFileBytes)
	if err != nil {
		t.Fatal(err)
	}
	tampered := append(append([]byte{}, original...), '\n')
	path := filepath.Join(a.opts.Head.Root, filepath.FromSlash(rel))
	if err := os.WriteFile(path, tampered, 0o644); err != nil {
		t.Fatal(err)
	}
	draft.Projects[0].Artifacts[0].Digest = CandidateDigest(tampered)
	stale, _, err := prepareOnboarding(a.opts.Layout, a.opts.Base, a.opts.Head, draft, obNonce, a.opts.Layout.Onboarding.Dir+"/"+draft.BatchID+".json")
	if err != nil {
		t.Fatalf("could not reproduce caller-derived stale semantic state: %v", err)
	}
	stale.Identity, stale.Decision, stale.DecidedAt, stale.NotAfter = a.env.Record.Identity, a.env.Record.Decision, a.env.Record.DecidedAt, a.env.Record.NotAfter
	if err := os.WriteFile(path, original, 0o644); err != nil {
		t.Fatal(err)
	}
	// The caller bytes now match Git again, but its previously prepared state
	// and artifact proof name different bytes. Preparation must rederive from
	// its own object exports instead of accepting that stale semantic state.
	if _, err := prepareBotAdmission(context.Background(), a.opts, a.keys, stale, a.env.binding.Export, a.env.KeyID); err == nil {
		t.Fatal("restored caller state bypassed authenticated semantic derivation")
	}
	base, head, cleanup, err := exportAdmissionTrees(context.Background(), a.opts.OnboardingGit)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	if base.Root == a.opts.Base.Root || head.Root == a.opts.Head.Root {
		t.Fatal("caller directories used as semantic authority")
	}
	if err := os.WriteFile(path, tampered, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := equalAdmissionTrees(base, head, a.opts.Base, a.opts.Head); err == nil {
		t.Fatal("swapped caller view passed the additional equivalence check")
	}
	if _, _, err := prepareOnboarding(a.opts.Layout, base, head, a.f.draft, obNonce, a.opts.Layout.Onboarding.Dir+"/"+draft.BatchID+".json"); err != nil {
		t.Fatalf("owned semantic snapshot changed with caller: %v", err)
	}
}

func TestOnboardingV2PreKeyBindingNegatives(t *testing.T) {
	t.Parallel()
	a := newAdmissionFixture(t, nil)
	cases := map[string]func(*OnboardingEnvelope, *Options){
		"missing context":             func(e *OnboardingEnvelope, o *Options) { o.OnboardingGit = nil },
		"missing pause":               func(e *OnboardingEnvelope, o *Options) { o.OnboardingGit.Paused = nil },
		"paused":                      func(e *OnboardingEnvelope, o *Options) { p := true; o.OnboardingGit.Paused = &p },
		"stale observation":           func(e *OnboardingEnvelope, o *Options) { o.OnboardingGit.ObservedAt = gateNow.Add(-6 * time.Minute) },
		"future observation":          func(e *OnboardingEnvelope, o *Options) { o.OnboardingGit.ObservedAt = gateNow.Add(time.Hour) },
		"unknown daily count":         func(e *OnboardingEnvelope, o *Options) { o.DailyLoosening = nil },
		"daily count forged":          func(e *OnboardingEnvelope, o *Options) { n := 1; o.DailyLoosening = &n },
		"missing daily metadata":      func(e *OnboardingEnvelope, o *Options) { e.binding.DailyCommits = nil },
		"changed cap":                 func(e *OnboardingEnvelope, o *Options) { o.MaxDailyLoosening = 51 },
		"changed withdrawal percent":  func(e *OnboardingEnvelope, o *Options) { o.MaxWithdrawPercent = 6 },
		"changed withdrawal project":  func(e *OnboardingEnvelope, o *Options) { o.MaxWithdrawProject = 21 },
		"changed automation identity": func(e *OnboardingEnvelope, o *Options) { o.BotLogin = botLogin },
		"shadow":                      func(e *OnboardingEnvelope, o *Options) { o.Shadow = true },
		"profile modified":            func(e *OnboardingEnvelope, o *Options) { e.binding.Profile.MaxProjects = 50 },
		"source base changed":         func(e *OnboardingEnvelope, o *Options) { e.binding.Profile.BaseCommit = e.binding.UnsignedCommit },
		"source tree changed":         func(e *OnboardingEnvelope, o *Options) { e.binding.Profile.BaseTree = e.binding.UnsignedTree },
		"head changed":                func(e *OnboardingEnvelope, o *Options) { e.binding.UnsignedCommit = o.OnboardingGit.BaseCommit },
		"tree changed":                func(e *OnboardingEnvelope, o *Options) { e.binding.UnsignedTree = e.binding.Profile.BaseTree },
		"history changed": func(e *OnboardingEnvelope, o *Options) {
			e.binding.HistoryDigest = CandidateDigest([]byte("other history"))
		},
		"missing manifest":          func(e *OnboardingEnvelope, o *Options) { e.binding.Export.ManifestDigest = "" },
		"missing draft":             func(e *OnboardingEnvelope, o *Options) { e.binding.Export.DraftDigest = "" },
		"missing plan":              func(e *OnboardingEnvelope, o *Options) { e.binding.Export.PlanDigest = "" },
		"same bytes different path": func(e *OnboardingEnvelope, o *Options) { e.binding.Changes[0].Path = "another/path.json" },
		"same bytes different mode": func(e *OnboardingEnvelope, o *Options) { e.binding.Changes[0].Head.Mode = "100755" },
		"blob substitution":         func(e *OnboardingEnvelope, o *Options) { e.binding.Changes[0].Head.Blob = e.binding.UnsignedTree },
		"digest substitution": func(e *OnboardingEnvelope, o *Options) {
			e.binding.Changes[0].Head.Digest = CandidateDigest([]byte("changed"))
		},
		"unknown key":    func(e *OnboardingEnvelope, o *Options) { e.KeyID = CandidateDigest([]byte("unknown public identity")) },
		"owner key":      func(e *OnboardingEnvelope, o *Options) { e.KeyID = ApprovalKeyID(a.f.key.public) },
		"owner identity": func(e *OnboardingEnvelope, o *Options) { e.Record.Identity = obOwner },
		"sixteenth project": func(e *OnboardingEnvelope, o *Options) {
			e.Record = spread(t, e.Record, MaxBotOnboardingProjects+1, OnboardingKindNew)
		},
		"attestation instead of new": func(e *OnboardingEnvelope, o *Options) { e.Record.Projects[0].Kind = OnboardingKindAttest },
		"expired record":             func(e *OnboardingEnvelope, o *Options) { e.Record.NotAfter = e.Record.DecidedAt },
	}
	for name, edit := range cases {
		t.Run(name, func(t *testing.T) {
			e := cloneAdmission(t, a.env)
			o := a.opts
			g := *o.OnboardingGit
			o.OnboardingGit = &g
			edit(&e, &o)
			if err := checkBotAdmission(context.Background(), e, a.keys, o, true); err == nil {
				t.Fatal("invalid pre-key admission passed")
			}
		})
	}
	// Mutating either snapshot or its ref after successful preparation is refused.
	t.Run("mutated snapshot", func(t *testing.T) {
		p := filepath.Join(a.opts.Head.Root, "unexpected-file")
		if err := os.WriteFile(p, []byte("changed"), 0o600); err != nil {
			t.Fatal(err)
		}
		defer os.Remove(p)
		if err := checkBotAdmission(context.Background(), a.env, a.keys, a.opts, true); err == nil {
			t.Fatal("mutated snapshot admitted")
		}
	})
	t.Run("moved head ref", func(t *testing.T) {
		g := a.opts.OnboardingGit
		gitIn(t, g.GitDir, "update-ref", admissionHeadRef, g.BaseCommit)
		defer gitIn(t, g.GitDir, "update-ref", admissionHeadRef, g.HeadCommit)
		if err := checkBotAdmission(context.Background(), a.env, a.keys, a.opts, true); err == nil {
			t.Fatal("moved head admitted")
		}
	})
}

func TestOnboardingV2CutoverAndHistory(t *testing.T) {
	t.Parallel()
	a := newAdmissionFixture(t, func(f *onboardingFixture, bot testApprovalKey) {
		for i, key := range []testApprovalKey{bot, f.key} {
			rec := f.record(t)
			rec.BatchID = fmt.Sprintf("ob-2026090%d-1", i+1)
			if i == 0 {
				rec.Identity = botLogin
			}
			rec.DecidedAt, rec.NotAfter = rfc(gateNow.Add(-time.Hour)), rfc(gateNow.Add(71*time.Hour))
			raw := key.signOnboarding(t, rec)
			f.writeBatch(t, f.base, rec.BatchID+".json", raw)
			f.writeBatch(t, f.head, rec.BatchID+".json", raw)
		}
	})
	files, err := a.opts.Base.Dir(a.opts.Layout.Onboarding.Dir, maxOnboardingBytes, maxOnboardingFiles)
	if err != nil {
		t.Fatal(err)
	}
	for _, raw := range files {
		e, err := decodeOnboarding(raw)
		if err != nil {
			t.Fatal(err)
		}
		if err := verifyOnboardingSignature(e, a.keys, gateNow); err != nil {
			t.Fatal(err)
		}
		if keys := a.keys.keyByID(e.KeyID); keys.botTier() {
			if err := refuseNewBotV1(e, a.keys); err == nil {
				t.Fatal("new bot v1 admitted")
			}
		} else if err := refuseNewBotV1(e, a.keys); err != nil {
			t.Fatal("manual owner v1 changed")
		}
	}
	// Correctly sign the same admissible candidate as v1: this is a downgrade,
	// not a signature corruption, and must not acquire the v2 admission route.
	rec := a.env.Record
	rec.Sample, _ = onboardingSample(rec.core())
	downgrade := envelopeOf(t, a.bot, rec)
	if err := verifyOnboardingSignature(downgrade, a.keys, gateNow); err != nil {
		t.Fatal(err)
	}
	if err := refuseNewBotV1(downgrade, a.keys); err == nil {
		t.Fatal("valid-signature downgrade admitted")
	}
	for _, author := range []string{botLogin, obOwner} {
		a.f.writeBatch(t, a.opts.Head, rec.BatchID+".json", a.bot.signOnboarding(t, rec))
		r := a.f.gateWith(t, func(o *Options) { o.Author = author })
		c, _ := check(r, CheckOnboarding)
		if c.OK || !strings.Contains(c.Detail, "require onboarding v2") {
			t.Fatalf("author %s bypassed cutover: %+v", author, c)
		}
	}
	if err := os.Remove(filepath.Join(a.opts.Head.Root, filepath.FromSlash(a.opts.Layout.Onboarding.Dir), rec.BatchID+".json")); err != nil {
		t.Fatal(err)
	}
	ownerV2 := cloneAdmission(t, a.env)
	ownerV2.Record.Identity = obOwner
	ownerV2 = signAdmission(t, ownerV2, a.f.key)
	if err := verifyOnboardingSignature(ownerV2, a.keys, gateNow); err == nil {
		t.Fatal("owner v2 admitted")
	}
	// v2 historical entries retain the same non-owner cap accounting.
	historical := signAdmission(t, a.env, a.bot)
	raw, err := marshalOnboardingEnvelope(historical)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < MaxBotBatchesWeek; i++ {
		files[fmt.Sprintf("history-%d.json", i)] = raw
	}
	if why := botOnboardingLimits(a.env, a.keys, files, gateNow, false); !strings.Contains(why, "O8c") {
		t.Fatalf("mixed v1/v2 history not counted: %s", why)
	}
}

func TestOnboardingBotMissingContextDoesNotReadKey(t *testing.T) {
	t.Parallel()
	f := newOnboardingFixture(t)
	f.pinBot(t, "2027-01-01T00:00:00Z")
	draft, _ := json.Marshal(f.draft)
	draftPath := filepath.Join(t.TempDir(), "draft.json")
	if err := os.WriteFile(draftPath, draft, 0o600); err != nil {
		t.Fatal(err)
	}
	keyRaw, err := f.base.Read(DefaultLayout().ApprovalKeysPath, MaxFileBytes)
	if err != nil {
		t.Fatal(err)
	}
	reads := 0
	env := approvalEnv{stdin: strings.NewReader("unread fixture"), checkStdin: func(_ io.Reader) error { reads++; return nil }, now: func() time.Time { return gateNow }, random: bytes.NewReader(make([]byte, 128)), confirm: func(string) (string, error) { t.Fatal("confirmation reached before admission"); return "", nil }}
	var out, errs bytes.Buffer
	code := approvalMain([]string{"sign", "--onboarding", draftPath, "--base", f.base.Root, "--head", f.head.Root, "--keys", filepath.Join(f.base.Root, filepath.FromSlash(DefaultLayout().ApprovalKeysPath)), "--keys-digest", pinnedDigest(keyRaw), "--identity", botLogin, "--key-stdin"}, env, DefaultLayout(), &out, &errs)
	if code != 2 || reads != 0 || !strings.Contains(errs.String(), "complete v2 admission") {
		t.Fatalf("code=%d key accesses=%d error=%s", code, reads, errs.String())
	}
}

func admissionSignArgs(t *testing.T, a admissionFixture) []string {
	t.Helper()
	dir := t.TempDir()
	draft, _ := json.Marshal(a.f.draft)
	export := a.env.binding.Export
	export.DraftDigest = CandidateDigest(draft)
	bindings, _ := json.Marshal(export)
	daily, _ := json.Marshal(a.opts.OnboardingGit.DailyCommits)
	for name, raw := range map[string][]byte{"draft.json": draft, "bindings.json": bindings, "daily.json": daily} {
		if err := os.WriteFile(filepath.Join(dir, name), raw, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	g := a.opts.OnboardingGit
	return []string{"sign", "--onboarding", filepath.Join(dir, "draft.json"), "--base", a.opts.Base.Root, "--head", a.opts.Head.Root,
		"--keys", filepath.Join(a.opts.Base.Root, filepath.FromSlash(a.opts.Layout.ApprovalKeysPath)), "--keys-digest", a.opts.ApprovalKeysDigest,
		"--identity", botLogin, "--key-stdin", "--expected-key-id", ApprovalKeyID(a.bot.public), "--admission-export", filepath.Join(dir, "bindings.json"),
		"--admission-source", "github", "--admission-git-dir", g.GitDir, "--admission-base", g.BaseCommit, "--admission-head", g.HeadCommit,
		"--admission-daily-commits", filepath.Join(dir, "daily.json"), "--admission-paused", "false", "--admission-observed-at", rfc(g.ObservedAt)}
}

func TestOnboardingV2SigningPreKeyOrder(t *testing.T) {
	t.Parallel()
	for _, mode := range []string{"valid", "ref moved during confirmation", "cap before key", "source failure with forged stdout", "paused input", "supervisor pause after readiness"} {
		t.Run(mode, func(t *testing.T) {
			a := newAdmissionFixture(t, nil)
			reads := 0
			confirmed := false
			if mode == "cap before key" {
				for i := 1; i <= MaxBotBatchesWeek; i++ {
					name, raw := botBaseBatch(t, a.f, a.bot, fmt.Sprintf("ob-202609%02d-5", i), 1, gateNow.Add(-time.Hour))
					a.f.writeBatch(t, a.opts.Base, name, raw)
					a.f.writeBatch(t, a.opts.Head, name, raw)
				}
				g := a.opts.OnboardingGit
				g.BaseCommit = admissionCommit(t, g.GitDir, a.opts.Base, "")
				g.HeadCommit = admissionCommit(t, g.GitDir, a.opts.Head, g.BaseCommit)
				gitIn(t, g.GitDir, "update-ref", admissionBaseRef, g.BaseCommit)
				gitIn(t, g.GitDir, "update-ref", admissionHeadRef, g.HeadCommit)
			}
			der, err := x509.MarshalPKCS8PrivateKey(a.bot.private)
			if err != nil {
				t.Fatal(err)
			}
			var out, errs bytes.Buffer
			reader, fd := admissionTestPipe(t)
			want := readinessExpected(a)
			result := make(chan error, 1)
			go func() { _, err := ReadOnboardingReadiness(reader, want); result <- err }()
			source := Source(a.f.src)
			if mode == "source failure with forged stdout" {
				request := OnboardingRecordV2{AdmissionBinding: want.Binding, OnboardingRecord: a.env.Record}
				request.AdmissionBinding.ObservedAt = request.DecidedAt
				msg, err := SignedOnboardingV2Bytes(request)
				if err != nil {
					t.Fatal(err)
				}
				frame, _ := json.Marshal(OnboardingReadiness{Schema: onboardingReadySchema, KeyID: a.env.KeyID, Request: request, RequestDigest: CandidateDigest(msg)})
				if _, err := ReadOnboardingReadiness(bytes.NewReader(append(frame, '\n')), want); err != nil {
					t.Fatalf("stdout spoof is not otherwise well formed: %v", err)
				}
				source = &failedAdmissionSource{Source: source, out: &out, frame: frame}
			}
			env := approvalEnv{onboardingSource: a.f.src, stdin: bytes.NewReader(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})), checkStdin: func(io.Reader) error {
				if err := <-result; err != nil {
					t.Fatalf("key input reached before valid control frame: %v", err)
				}
				if mode == "supervisor pause after readiness" {
					return errors.New("supervisor refused changed live pause; key not opened")
				}
				reads++
				return nil
			}, now: func() time.Time { return gateNow }, random: bytes.NewReader(make([]byte, 128)), confirm: func(string) (string, error) {
				confirmed = true
				if mode == "ref moved during confirmation" {
					g := a.opts.OnboardingGit
					gitIn(t, g.GitDir, "update-ref", admissionHeadRef, g.BaseCommit)
				}
				return a.f.draft.BatchID, nil
			}}
			env.onboardingSource = source
			args := append(admissionSignArgs(t, a), "--admission-ready-fd", strconv.Itoa(fd))
			if mode == "paused input" {
				for i := range args {
					if args[i] == "--admission-paused" {
						args[i+1] = "true"
					}
				}
			}
			code := approvalMain(args, env, DefaultLayout(), &out, &errs)
			if mode != "valid" {
				if code != 2 || reads != 0 {
					t.Fatalf("%s code=%d key accesses=%d error=%s", mode, code, reads, errs.String())
				}
				if mode == "cap before key" && confirmed {
					t.Fatal("over-cap request reached confirmation")
				}
				if mode != "supervisor pause after readiness" {
					if err := <-result; err == nil {
						t.Fatal("failed admission emitted readiness")
					}
				}
				if a.opts.Head.Exists(a.opts.Layout.Onboarding.Dir + "/" + a.f.draft.BatchID + ".json") {
					t.Fatal("refused request wrote a signature")
				}
				return
			}
			if code != 0 || reads != 1 || !confirmed {
				t.Fatalf("valid code=%d key accesses=%d confirmed=%v error=%s", code, reads, confirmed, errs.String())
			}
			raw, err := a.opts.Head.Read(a.opts.Layout.Onboarding.Dir+"/"+a.f.draft.BatchID+".json", maxOnboardingBytes)
			if err != nil {
				t.Fatal(err)
			}
			e, err := decodeOnboarding(raw)
			if err != nil || e.Schema != OnboardingSchemaV2 {
				t.Fatalf("bot signer emitted other format: %v %s", err, e.Schema)
			}
			if err := verifyOnboardingSignature(e, a.keys, gateNow); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func readinessExpected(a admissionFixture) OnboardingReadinessExpected {
	draft, _ := json.Marshal(a.f.draft)
	binding := *a.env.binding
	binding.Profile.BaseCommit = a.opts.OnboardingGit.BaseCommit
	binding.UnsignedCommit = a.opts.OnboardingGit.HeadCommit
	binding.Export.DraftDigest = CandidateDigest(draft)
	return OnboardingReadinessExpected{BatchID: a.f.draft.BatchID, CandidateID: a.f.draft.CandidateID, KeyID: ApprovalKeyID(a.bot.public), Binding: binding, Projects: a.f.draft.Projects, NotBefore: gateNow.Add(-time.Minute), NotAfter: gateNow.Add(time.Minute)}
}

type failedAdmissionSource struct {
	Source
	out   io.Writer
	frame []byte
}

func (s *failedAdmissionSource) Tags(extract.RepoRef) ([]extract.Tag, error) {
	_, _ = fmt.Fprintln(s.out, string(s.frame))
	return nil, errors.New("required source read failed")
}

func TestOnboardingReadinessFraming(t *testing.T) {
	t.Parallel()
	a := newAdmissionFixture(t, nil)
	request := OnboardingRecordV2{AdmissionBinding: *a.env.binding, OnboardingRecord: a.env.Record}
	msg, err := SignedOnboardingV2Bytes(request)
	if err != nil {
		t.Fatal(err)
	}
	frame := OnboardingReadiness{Schema: onboardingReadySchema, KeyID: a.env.KeyID, Request: request, RequestDigest: CandidateDigest(msg)}
	raw, err := json.Marshal(frame)
	if err != nil {
		t.Fatal(err)
	}
	raw = append(raw, '\n')
	want := readinessExpected(a)
	want.Binding.Export.DraftDigest = a.env.binding.Export.DraftDigest
	if _, err := ReadOnboardingReadiness(bytes.NewReader(raw), want); err != nil {
		t.Fatal(err)
	}
	for name, data := range map[string][]byte{"duplicate": append(append([]byte{}, raw...), raw...), "truncated": raw[:len(raw)-1], "human prefix": append([]byte("prepared\n"), raw...), "oversize": bytes.Repeat([]byte{'x'}, maxOnboardingReadyBytes+1)} {
		t.Run(name, func(t *testing.T) {
			if _, err := ReadOnboardingReadiness(bytes.NewReader(data), want); err == nil {
				t.Fatal("invalid control frame accepted")
			}
		})
	}
	for _, name := range []string{"schema", "request digest", "batch", "key", "source"} {
		bad := frame
		switch name {
		case "schema":
			bad.Schema = "other"
		case "request digest":
			bad.RequestDigest = CandidateDigest([]byte("other request"))
		case "batch":
			bad.Request.BatchID = "ob-20261104-2"
		case "key":
			bad.KeyID = CandidateDigest([]byte("other key"))
		case "source":
			bad.Request.AdmissionBinding.UnsignedCommit = bad.Request.AdmissionBinding.Profile.BaseCommit
		}
		data, _ := json.Marshal(bad)
		if _, err := ReadOnboardingReadiness(bytes.NewReader(append(data, '\n')), want); err == nil {
			t.Fatalf("wrong %s accepted", name)
		}
	}
}
