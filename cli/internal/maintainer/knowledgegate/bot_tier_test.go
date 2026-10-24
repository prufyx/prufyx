// SPDX-License-Identifier: AGPL-3.0-only

package knowledgegate

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const botLogin = "tier-test-bot"

// tieredKeys pins the owner key and the bot key in one key file.
func tieredKeys(owner, bot testApprovalKey, botNotAfter string) ApprovalKeys {
	return ApprovalKeys{
		Schema: ApprovalKeysSchema, Role: ApprovalKeyRole, Owners: []string{obOwner}, Bots: []string{botLogin},
		Keys: []ApprovalKey{
			{KeyID: ApprovalKeyID(owner.public), PublicKey: hex.EncodeToString(owner.public), NotAfter: "2027-10-01T00:00:00Z"},
			{KeyID: ApprovalKeyID(bot.public), PublicKey: hex.EncodeToString(bot.public), NotAfter: botNotAfter, Tier: ApprovalTierOnboardingBot},
		},
	}
}

func pinKeys(t *testing.T, keys ApprovalKeys, trs ...Tree) {
	t.Helper()
	raw, err := json.MarshalIndent(keys, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	for _, tr := range trs {
		writeFile(t, filepath.Join(tr.Root, filepath.FromSlash(DefaultLayout().ApprovalKeysPath)), raw)
	}
}

func rfc(t time.Time) string { return t.UTC().Format("2006-01-02T15:04:05Z") }

func TestBotTierKeyFile(t *testing.T) {
	t.Parallel()
	owner, bot := newApprovalKey(t), newApprovalKey(t)
	good := tieredKeys(owner, bot, "2027-01-01T00:00:00Z")
	raw, _ := json.Marshal(good)
	parsed, err := ParseApprovalKeys(raw)
	if err != nil || !parsed.isBot(botLogin) || !parsed.Keys[1].botTier() || !parsed.Keys[0].ownerTier() {
		t.Fatalf("tiered file: %v %+v", err, parsed)
	}
	for name, mut := range map[string]func(a *ApprovalKeys){
		"unknown tier":        func(a *ApprovalKeys) { a.Keys[1].Tier = "admin" },
		"bot is an owner":     func(a *ApprovalKeys) { a.Bots = []string{obOwner} },
		"duplicate bot":       func(a *ApprovalKeys) { a.Bots = []string{botLogin, botLogin} },
		"bad bot login":       func(a *ApprovalKeys) { a.Bots = []string{"-x"} },
		"too many bots":       func(a *ApprovalKeys) { a.Bots = []string{"a1", "a2", "a3", "a4", "a5", "a6", "a7", "a8", "a9"} },
		"tier case sensitive": func(a *ApprovalKeys) { a.Keys[1].Tier = "Onboarding-Bot" },
	} {
		a := good
		a.Keys = append([]ApprovalKey(nil), good.Keys...)
		mut(&a)
		raw, _ := json.Marshal(a)
		if _, err := ParseApprovalKeys(raw); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
	// An owner key may say its tier.
	a := good
	a.Keys = append([]ApprovalKey(nil), good.Keys...)
	a.Keys[0].Tier = ApprovalTierOwner
	raw, _ = json.Marshal(a)
	if _, err := ParseApprovalKeys(raw); err != nil {
		t.Fatal(err)
	}
}

// A key file without tier fields (every key file today) parses as before:
// all keys are owner keys, no bots, and it serialises without new members.
func TestBotTierOldKeyFileUnchanged(t *testing.T) {
	t.Parallel()
	raw, err := os.ReadFile(filepath.Join(repoRoot, filepath.FromSlash(DefaultLayout().ApprovalKeysPath)))
	if err != nil {
		t.Fatal(err)
	}
	k, err := ParseApprovalKeys(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(k.Bots) != 0 {
		t.Fatalf("bots %v", k.Bots)
	}
	for _, key := range k.Keys {
		if key.Tier != "" || !key.ownerTier() || key.botTier() {
			t.Fatalf("key %+v", key)
		}
	}
	out, _ := json.Marshal(k)
	if strings.Contains(string(out), "tier") || strings.Contains(string(out), "bots") {
		t.Fatalf("old key file gained members: %s", out)
	}
}

// The trust check refuses a key file the gate cannot parse.
func TestBotTierTrustCheckParsesKeyFile(t *testing.T) {
	t.Parallel()
	owner, bot := newApprovalKey(t), newApprovalKey(t)
	for name, tier := range map[string]string{"good": ApprovalTierOnboardingBot, "typo": "onboarding-bott"} {
		_, head := trees(t)
		keys := tieredKeys(owner, bot, "2027-01-01T00:00:00Z")
		keys.Keys[1].Tier = tier
		pinKeys(t, keys, head)
		layout := DefaultLayout()
		raw, _ := os.ReadFile(filepath.Join(head.Root, filepath.FromSlash(layout.ApprovalKeysPath)))
		r := &Report{ChangedPaths: []string{layout.ApprovalKeysPath}}
		r.trustCheck(Options{Layout: layout, Head: head, Author: obOwner, Sender: obOwner, BotLogin: "some-bot", ApprovalKeysDigest: pinnedDigest(raw)})
		c, ok := check(r, "trust-material")
		if !ok || c.OK != (name == "good") {
			t.Fatalf("%s: %+v", name, c)
		}
	}
}

// A bot-tier key signs nothing but a kind-new onboarding batch: every other
// verify and sign path refuses it, whatever the identity.
func TestBotKeyRefusedEverywhereElse(t *testing.T) {
	t.Parallel()
	owner, bot := newApprovalKey(t), newApprovalKey(t)
	keys := tieredKeys(owner, bot, "2027-01-01T00:00:00Z")
	now := gateNow
	digest := "sha256:" + strings.Repeat("ab", 32)
	absent := ApprovalBaseAbsent
	subjects := []struct {
		name, pack, subject, rule, scope, base string
	}{
		{"rule approval", "cncf", "", "r.one", "", absent},
		{"line attestation", "cncf", ApprovalSubjectLineAttestation, "la.one", "pkg:golang/example.test/x family 1.2", absent},
		{"path policy", "cncf", ApprovalSubjectPathPolicy, "pp.one", "pkg:golang/example.test/x", absent},
		{"repin baseline", "baselines", ApprovalSubjectRepinBaseline, "rb.one", "example/repo", absent},
		{"registry digest", "cncf", ApprovalSubjectRegistry, RegistryApprovalID, RegistryApprovalScope, digest},
		{"served APIs", "cncf", ApprovalSubjectServed, ServedApprovalID, ServedApprovalScope, absent},
	}
	for _, s := range subjects {
		rec := ApprovalRecord{BaseDigest: s.base, CandidateDigest: digest, CandidateID: "cand-1", DecidedAt: rfc(now.Add(-time.Hour)), Decision: "approve", Identity: botLogin, Pack: s.pack, RuleID: s.rule, Scope: s.scope, Subject: s.subject}
		for _, who := range []struct{ id, label string }{{botLogin, "bot identity"}, {obOwner, "owner identity"}} {
			rec.Identity = who.id
			raw := bot.sign(t, rec)
			err := verifyApproval(raw, keys, s.pack, s.subject, s.rule, s.scope, nil, []byte("x"), now)
			if err == nil || !strings.Contains(err.Error(), "bot-tier key") {
				t.Fatalf("%s, %s: %v", s.name, who.label, err)
			}
		}
		// Control: the same record under the owner key is not refused for its tier.
		rec.Identity = obOwner
		err := verifyApproval(owner.sign(t, rec), keys, s.pack, s.subject, s.rule, s.scope, nil, []byte("x"), now)
		if err == nil || strings.Contains(err.Error(), "tier") {
			t.Fatalf("%s control: %v", s.name, err)
		}
	}
	// Signing commands.
	if _, err := checkBatchSigner(keys, bot.private, botLogin, now); err == nil || !strings.Contains(err.Error(), "bot-tier key") {
		t.Fatalf("checkBatchSigner: %v", err)
	}
	if _, err := checkBatchSigner(keys, bot.private, obOwner, now); err == nil || !strings.Contains(err.Error(), "bot-tier key") {
		t.Fatalf("checkBatchSigner owner identity: %v", err)
	}
	if _, err := checkBatchSigner(keys, owner.private, obOwner, now); err != nil {
		t.Fatalf("checkBatchSigner owner: %v", err)
	}
	_, _, err := SignApproval(SignApprovalOptions{Subject: ApprovalSubject{Kind: ApprovalSubjectRule, Pack: "cncf", RuleID: "r.one", Candidate: []byte("x")}, CandidateID: "cand-1", Identity: botLogin, Keys: keys, Key: bot.private, Now: now})
	if err == nil || !strings.Contains(err.Error(), "bot-tier key") {
		t.Fatalf("SignApproval: %v", err)
	}
	// An expired bot key still gets the explicit tier refusal first.
	exp := tieredKeys(owner, bot, "2026-01-01T00:00:00Z")
	if _, err := checkBatchSigner(exp, bot.private, botLogin, now); err == nil || !strings.Contains(err.Error(), "bot-tier key") {
		t.Fatalf("expired bot key: %v", err)
	}
}

// The knowledge batch gate refuses a batch signed with a bot-tier key.
func TestBotKeyRefusedForKnowledgeBatch(t *testing.T) {
	t.Parallel()
	f := newBatchFixture(t, 3)
	owner := newApprovalKey(t)
	pinKeys(t, tieredKeys(owner, f.key, "2027-01-01T00:00:00Z"), f.base, f.head)
	f.signAndWrite(t, f.record(t))
	requireFail(t, runGate(t, Options{Base: f.base, Head: f.head}), "bot-tier key")
}

// pinBot re-pins the fixture's owner key and a new bot key in both trees.
func (f *onboardingFixture) pinBot(t *testing.T, notAfter string) testApprovalKey {
	t.Helper()
	bot := newApprovalKey(t)
	pinKeys(t, tieredKeys(f.key, bot, notAfter), f.base, f.head)
	return bot
}

// botRecord is the fixture's record signed in the name of the bot.
func (f *onboardingFixture) botRecord(t *testing.T) OnboardingRecord {
	t.Helper()
	rec := f.record(t)
	rec.Identity = botLogin
	return rec
}

func spread(t *testing.T, rec OnboardingRecord, n int, kind string) OnboardingRecord {
	t.Helper()
	first := rec.Projects[0]
	rec.Projects = nil
	for i := 0; i < n; i++ {
		p := first
		p.Slug = fmt.Sprintf("zz-spread-%02d", i)
		p.Kind = kind
		rec.Projects = append(rec.Projects, p)
	}
	var err error
	if rec.Sample, err = onboardingSample(rec.core()); err != nil {
		t.Fatal(err)
	}
	return rec
}

func envelopeOf(t *testing.T, k testApprovalKey, rec OnboardingRecord) OnboardingEnvelope {
	t.Helper()
	var env OnboardingEnvelope
	if err := json.Unmarshal(k.signOnboarding(t, rec), &env); err != nil {
		t.Fatal(err)
	}
	return env
}

func TestBotOnboardingSignature(t *testing.T) {
	t.Parallel()
	f := newOnboardingFixture(t)
	owner := f.key
	bot := newApprovalKey(t)
	keys := tieredKeys(owner, bot, "2027-01-01T00:00:00Z")
	now := gateNow
	rec := f.record(t)
	botRec := rec
	botRec.Identity = botLogin

	if err := verifyOnboardingSignature(envelopeOf(t, owner, rec), keys, now); err != nil {
		t.Fatalf("owner batch: %v", err)
	}
	if err := verifyOnboardingSignature(envelopeOf(t, bot, botRec), keys, now); err != nil {
		t.Fatalf("bot batch: %v", err)
	}
	// The same bot batch with 15 projects passes, with 16 it does not.
	if err := verifyOnboardingSignature(envelopeOf(t, bot, spread(t, botRec, MaxBotOnboardingProjects, OnboardingKindNew)), keys, now); err != nil {
		t.Fatalf("15 projects: %v", err)
	}
	if err := verifyOnboardingSignature(envelopeOf(t, bot, spread(t, botRec, MaxBotOnboardingProjects+1, OnboardingKindNew)), keys, now); err == nil || !strings.Contains(err.Error(), "at most 15") {
		t.Fatalf("16 projects: %v", err)
	}
	// The owner may still sign 16 projects.
	if err := verifyOnboardingSignature(envelopeOf(t, owner, spread(t, rec, MaxBotOnboardingProjects+1, OnboardingKindNew)), keys, now); err != nil {
		t.Fatalf("owner 16 projects: %v", err)
	}
	// kind attest is owner-only.
	attest := spread(t, botRec, 3, OnboardingKindNew)
	attest.Projects[1].Kind = OnboardingKindAttest
	if err := verifyOnboardingSignature(envelopeOf(t, bot, attest), keys, now); err == nil || !strings.Contains(err.Error(), "kind new") {
		t.Fatalf("attest: %v", err)
	}
	ownerAttest := attest
	ownerAttest.Identity = obOwner
	if err := verifyOnboardingSignature(envelopeOf(t, owner, ownerAttest), keys, now); err != nil {
		t.Fatalf("owner attest: %v", err)
	}

	ownerIDBot := rec // identity airstand
	botIDOwner := botRec
	cases := map[string]struct {
		env  OnboardingEnvelope
		keys ApprovalKeys
		now  time.Time
		want string
	}{
		"owner identity with bot key": {envelopeOf(t, bot, ownerIDBot), keys, now, "owner identity and cannot sign with a bot-tier key"},
		"bot identity with owner key": {envelopeOf(t, owner, botIDOwner), keys, now, "bot identity and cannot sign with an owner key"},
		"identity in neither list": {func() OnboardingEnvelope {
			r := botRec
			r.Identity = "somebody-else"
			return envelopeOf(t, bot, r)
		}(), keys, now, "not a pinned bot"},
		"expired bot key": {envelopeOf(t, bot, botRec), tieredKeys(owner, bot, "2026-10-03T11:00:00Z"), now, "expired"},
		"unknown tier": {envelopeOf(t, bot, botRec), func() ApprovalKeys {
			k := keys
			k.Keys = append([]ApprovalKey(nil), keys.Keys...)
			k.Keys[1].Tier = "admin"
			return k
		}(), now, "unknown tier"},
		"bot rejects":       {envelopeOf(t, bot, func() OnboardingRecord { r := botRec; r.Decision = "reject"; return r }()), keys, now, `decision is "reject"`},
		"bot not pinned":    {envelopeOf(t, newApprovalKey(t), botRec), keys, now, "not pinned"},
		"bot batch expired": {envelopeOf(t, bot, botRec), keys, now.Add(MaxOnboardingValidity), "expired at"},
	}
	for name, tc := range cases {
		err := verifyOnboardingSignature(tc.env, tc.keys, tc.now)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Fatalf("%s: %v (want %q)", name, err, tc.want)
		}
	}

	// The signing command applies the same binding before it asks anything.
	if _, err := checkOnboardingSigner(keys, bot.private, botLogin, now); err != nil {
		t.Fatalf("bot signer: %v", err)
	}
	if _, err := checkOnboardingSigner(keys, bot.private, obOwner, now); err == nil {
		t.Fatal("owner identity with the bot key signs")
	}
	if _, err := checkOnboardingSigner(keys, owner.private, botLogin, now); err == nil {
		t.Fatal("bot identity with the owner key signs")
	}
	if _, err := checkOnboardingSigner(keys, owner.private, obOwner, now); err != nil {
		t.Fatalf("owner signer: %v", err)
	}
}

// baseBatch is a bot batch file as the base tree keeps it.
func botBaseBatch(t *testing.T, f *onboardingFixture, bot testApprovalKey, id string, projects int, decided time.Time) (string, []byte) {
	t.Helper()
	rec := spread(t, f.botRecord(t), projects, OnboardingKindNew)
	rec.BatchID = id
	rec.DecidedAt = rfc(decided)
	rec.NotAfter = rfc(decided.Add(MaxOnboardingValidity))
	return id + ".json", bot.signOnboarding(t, rec)
}

func TestBotOnboardingLimits(t *testing.T) {
	t.Parallel()
	f := newOnboardingFixture(t)
	bot := newApprovalKey(t)
	keys := tieredKeys(f.key, bot, "2027-01-01T00:00:00Z")
	now := gateNow
	head := envelopeOf(t, bot, spread(t, f.botRecord(t), 5, OnboardingKindNew))
	ownerHead := envelopeOf(t, f.key, f.record(t))

	files := func(spec ...struct {
		n        int
		projects int
		decided  time.Time
	}) map[string][]byte {
		m := map[string][]byte{}
		for i, s := range spec {
			name, raw := botBaseBatch(t, f, bot, fmt.Sprintf("ob-2026090%d-%d", i+1, i+1), s.projects, s.decided)
			m[name] = raw
		}
		return m
	}
	type b = struct {
		n        int
		projects int
		decided  time.Time
	}
	recent := now.Add(-24 * time.Hour)
	cases := []struct {
		name   string
		env    OnboardingEnvelope
		files  map[string][]byte
		paused bool
		want   string
	}{
		{"no base batches", head, nil, false, ""},
		{"two base batches, third admitted", head, files(b{0, 5, recent}, b{0, 5, recent}), false, ""},
		{"fourth batch in 7 days", head, files(b{0, 1, recent}, b{0, 1, recent}, b{0, 1, recent}), false, "O8c: this would be bot-tier batch 4"},
		{"31st project in 7 days", head, files(b{0, 13, recent}, b{0, 13, recent}), false, "O8c: this would bring the bot-tier projects inside 7 days to 31"},
		{"30th project admitted", head, files(b{0, 13, recent}, b{0, 12, recent}), false, ""},
		{"paused", head, nil, true, "O8b"},
		{"paused does not touch an owner batch", ownerHead, nil, true, ""},
		{"owner batches are not counted", head, files(b{0, 1, recent}, b{0, 1, recent}), false, ""},
		// Window edge, counted by notAfter: notAfter exactly 7 days back counts, one second more does not.
		{"notAfter exactly 7 days back counts", head, files(b{0, 1, recent}, b{0, 1, recent}, b{0, 1, now.Add(-BotOnboardingWindow - MaxOnboardingValidity)}), false, "O8c"},
		{"notAfter 7 days and 1s back is out", head, files(b{0, 1, recent}, b{0, 1, recent}, b{0, 1, now.Add(-BotOnboardingWindow - MaxOnboardingValidity - time.Second)}), false, ""},
		// A bot that back-dates decidedAt by 72h still counts for 7 days after admission.
		{"back-dated decidedAt, 9 days old, notAfter 6 days old", head, files(b{0, 1, recent}, b{0, 1, recent}, b{0, 1, now.Add(-9 * 24 * time.Hour)}), false, "O8c"},
	}
	for _, tc := range cases {
		fs := tc.files
		if tc.name == "owner batches are not counted" {
			fs = map[string][]byte{}
			for i := 0; i < 2; i++ {
				rec := spread(t, f.record(t), 1, OnboardingKindNew)
				rec.BatchID = fmt.Sprintf("ob-2026091%d-1", i)
				rec.DecidedAt, rec.NotAfter = rfc(recent), rfc(recent.Add(MaxOnboardingValidity))
				fs[rec.BatchID+".json"] = f.key.signOnboarding(t, rec)
			}
			for n, raw := range files(b{0, 1, recent}, b{0, 1, recent}) {
				fs[n] = raw
			}
		}
		got := botOnboardingLimits(tc.env, keys, fs, now, tc.paused)
		if tc.want == "" && got != "" || tc.want != "" && !strings.Contains(got, tc.want) {
			t.Fatalf("%s: got %q, want %q", tc.name, got, tc.want)
		}
	}
	// A base file that does not decode never admitted anything; the owner
	// batch of a retired bot key (no longer pinned, identity not an owner)
	// still counts.
	retired := map[string][]byte{"ob-20260901-1.json": []byte("{")}
	for i := 1; i <= 3; i++ {
		name, raw := botBaseBatch(t, f, newApprovalKey(t), fmt.Sprintf("ob-2026091%d-1", i), 1, recent)
		retired[name] = raw
	}
	if got := botOnboardingLimits(head, keys, retired, now, false); !strings.Contains(got, "O8c") {
		t.Fatalf("retired bot batches not counted: %q", got)
	}
}

// A batch file stays in the tree until 14 days after its notAfter, so every
// batch of the last 7 days is counted, and the records rule refuses removing
// one inside the window.
func TestBotOnboardingRetentionEdge(t *testing.T) {
	t.Parallel()
	f := newOnboardingFixture(t)
	bot := f.pinBot(t, "2027-01-01T00:00:00Z")
	now := gateNow
	decided := now.Add(-BotOnboardingWindow)
	name, raw := botBaseBatch(t, f, bot, "ob-20260926-1", 2, decided)
	f.writeBatch(t, f.base, name, raw)
	// Removed in the head.
	opts := Options{Base: f.base, Head: f.head, Layout: DefaultLayout(), Now: now}
	p := DefaultLayout().Onboarding.Dir + "/" + name
	if why := onboardingPathReason(opts, p, nil); !strings.Contains(why, "14 days") {
		t.Fatalf("removal inside retention: %q", why)
	}
	// Still removable only after notAfter + 14 days, when it is long out of the window.
	opts.Now = decided.Add(MaxOnboardingValidity + OnboardingRetention)
	if why := onboardingPathReason(opts, p, nil); why != "" {
		t.Fatalf("removal after retention: %q", why)
	}
	if OnboardingRetention < BotOnboardingWindow+MaxOnboardingValidity {
		t.Fatal("retention shorter than the counting window")
	}
}

func TestBotOnboardingGate(t *testing.T) {
	t.Parallel()
	signBot := func(t *testing.T, f *onboardingFixture, bot testApprovalKey, edit func(*OnboardingRecord)) {
		t.Helper()
		rec := f.botRecord(t)
		if edit != nil {
			edit(&rec)
		}
		f.writeBatch(t, f.head, rec.BatchID+".json", bot.signOnboarding(t, rec))
	}
	failed := func(t *testing.T, r *Report, want string) {
		t.Helper()
		c, ok := check(r, CheckOnboarding)
		if !ok || c.OK || !strings.Contains(c.Detail, want) {
			t.Fatalf("onboarding check %+v, want %q", c, want)
		}
		if r.Passed() {
			t.Fatal("gate passed")
		}
	}

	t.Run("admitted", func(t *testing.T) {
		f := newOnboardingFixture(t)
		bot := f.pinBot(t, "2027-01-01T00:00:00Z")
		signBot(t, f, bot, nil)
		r := f.gate(t)
		requirePass(t, r)
		c, _ := check(r, CheckOnboarding)
		if !c.OK || !strings.Contains(c.Detail, "bot tier: sample drawn, not read") || !strings.Contains(c.Detail, botLogin) {
			t.Fatalf("detail %+v", c)
		}
		if r.AutoMerge.Eligible || !strings.Contains(strings.Join(r.Alarms, ";"), "onboarding batch (admitted)") {
			t.Fatalf("auto merge %+v alarms %v", r.AutoMerge, r.Alarms)
		}
	})
	t.Run("owner batch with the tiered file is unchanged", func(t *testing.T) {
		f := newOnboardingFixture(t)
		f.pinBot(t, "2027-01-01T00:00:00Z")
		f.sign(t, f.record(t))
		r := f.gateWith(t, func(o *Options) { o.BotSignerPaused = true })
		requirePass(t, r)
		if c, _ := check(r, CheckOnboarding); !strings.Contains(c.Detail, "read in full") {
			t.Fatalf("detail %+v", c)
		}
	})
	t.Run("paused", func(t *testing.T) {
		f := newOnboardingFixture(t)
		bot := f.pinBot(t, "2027-01-01T00:00:00Z")
		signBot(t, f, bot, nil)
		failed(t, f.gateWith(t, func(o *Options) { o.BotSignerPaused = true }), "O8b")
	})
	t.Run("factory pause", func(t *testing.T) {
		f := newOnboardingFixture(t)
		bot := f.pinBot(t, "2027-01-01T00:00:00Z")
		signBot(t, f, bot, nil)
		writeFile(t, filepath.Join(f.head.Root, "factory/PAUSE"), []byte("stop\n"))
		failed(t, f.gate(t), "O8")
	})
	t.Run("expired bot key", func(t *testing.T) {
		f := newOnboardingFixture(t)
		bot := f.pinBot(t, "2026-10-03T11:00:00Z")
		signBot(t, f, bot, nil)
		failed(t, f.gate(t), "expired")
	})
	t.Run("owner identity with the bot key", func(t *testing.T) {
		f := newOnboardingFixture(t)
		bot := f.pinBot(t, "2027-01-01T00:00:00Z")
		signBot(t, f, bot, func(r *OnboardingRecord) { r.Identity = obOwner })
		failed(t, f.gate(t), "cannot sign with a bot-tier key")
	})
	t.Run("kind attest", func(t *testing.T) {
		f := newOnboardingFixture(t)
		bot := f.pinBot(t, "2027-01-01T00:00:00Z")
		signBot(t, f, bot, func(r *OnboardingRecord) { r.Projects[0].Kind = OnboardingKindAttest })
		failed(t, f.gate(t), "kind new projects only")
	})
	t.Run("fourth batch in seven days", func(t *testing.T) {
		f := newOnboardingFixture(t)
		bot := f.pinBot(t, "2027-01-01T00:00:00Z")
		for i := 1; i <= MaxBotBatchesWeek; i++ {
			name, raw := botBaseBatch(t, f, bot, fmt.Sprintf("ob-2026092%d-1", i), 1, f.signedAt.Add(-time.Duration(i)*time.Hour))
			f.writeBatch(t, f.base, name, raw)
			f.writeBatch(t, f.head, name, raw)
		}
		signBot(t, f, bot, nil)
		failed(t, f.gate(t), "O8c")
	})
	t.Run("third batch in seven days", func(t *testing.T) {
		f := newOnboardingFixture(t)
		bot := f.pinBot(t, "2027-01-01T00:00:00Z")
		for i := 1; i < MaxBotBatchesWeek; i++ {
			name, raw := botBaseBatch(t, f, bot, fmt.Sprintf("ob-2026092%d-1", i), 1, f.signedAt.Add(-time.Duration(i)*time.Hour))
			f.writeBatch(t, f.base, name, raw)
			f.writeBatch(t, f.head, name, raw)
		}
		signBot(t, f, bot, nil)
		requirePass(t, f.gate(t))
	})
	t.Run("file outside the onboarding change", func(t *testing.T) {
		f := newOnboardingFixture(t)
		bot := f.pinBot(t, "2027-01-01T00:00:00Z")
		signBot(t, f, bot, nil)
		writeFile(t, filepath.Join(f.head.Root, "cli/knowledge/unrelated-bot-note.txt"), []byte("x\n"))
		r := f.gate(t)
		if r.Passed() {
			t.Fatal("gate passed with a file outside the onboarding change")
		}
		if c, ok := check(r, CheckOnboarding); ok && c.OK {
			t.Fatalf("onboarding admitted: %+v", c)
		}
	})
}
