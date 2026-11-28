// SPDX-License-Identifier: AGPL-3.0-only

package knowledgegate

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

var claimsCases = []struct {
	name                             string
	confirmed, undetermined, refuted int
	// want are the refusals expected; none means the batch is admissible.
	want []string
}{
	{"only undetermined", 0, 4, 0, []string{"no confirmed claim"}},
	{"no claim at all", 0, 0, 0, []string{"no confirmed claim"}},
	{"refuted beside confirmed", 3, 0, 1, []string{"reports 1 refuted claims"}},
	{"only refuted", 0, 0, 2, []string{"no confirmed claim", "reports 2 refuted claims"}},
	{"one confirmed", 1, 0, 0, nil},
	{"one confirmed beside undetermined", 1, 5, 0, nil},
}

func setClaims(p *OnboardingProject, confirmed, undetermined, refuted int) {
	p.Proof.Claims.Confirmed, p.Proof.Claims.Undetermined, p.Proof.Claims.Refuted = confirmed, undetermined, refuted
}

// The signer refuses a draft before it asks for confirmation or reads the
// key; verify and the gate refuse the same batch signed anyway.
func TestOnboardingClaimsRequired(t *testing.T) {
	t.Parallel()
	for _, tc := range claimsCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := newOnboardingFixture(t)
			setClaims(&f.draft.Projects[0], tc.confirmed, tc.undetermined, tc.refuted)
			ol := DefaultLayout().Onboarding
			draft, err := json.Marshal(f.draft)
			if err != nil {
				t.Fatal(err)
			}
			draftPath := filepath.Join(t.TempDir(), "draft.json")
			writeFile(t, draftPath, draft)
			keysPath := filepath.Join(f.base.Root, filepath.FromSlash(DefaultLayout().ApprovalKeysPath))
			keysRaw, err := os.ReadFile(keysPath)
			if err != nil {
				t.Fatal(err)
			}
			digest := pinnedDigest(keysRaw)
			confirms, keyReads := 0, 0
			env := approvalEnv{stdin: bytes.NewReader(f.key.pemKey(t)), now: func() time.Time { return f.signedAt },
				checkStdin: func(io.Reader) error { keyReads++; return nil },
				confirm:    func(string) (string, error) { confirms++; return f.draft.BatchID, nil }, random: bytes.NewReader(make([]byte, 128))}
			batch := filepath.Join(f.head.Root, filepath.FromSlash(ol.Dir), f.draft.BatchID+".json")
			var out, errOut bytes.Buffer
			code := approvalMain([]string{"sign", "--onboarding", draftPath, "--base", f.base.Root, "--head", f.head.Root, "--keys", keysPath, "--keys-digest", digest, "--identity", obOwner, "--key-stdin"}, env, DefaultLayout(), &out, &errOut)
			if tc.want == nil {
				if code != 0 || confirms != 1 || keyReads != 1 {
					t.Fatalf("sign: code=%d confirms=%d key reads=%d %s", code, confirms, keyReads, errOut.String())
				}
				requirePass(t, f.gate(t))
				return
			}
			if code != 2 || confirms != 0 || keyReads != 0 {
				t.Fatalf("sign: code=%d confirms=%d key reads=%d %s", code, confirms, keyReads, errOut.String())
			}
			for _, want := range tc.want {
				if !strings.Contains(errOut.String(), want) {
					t.Fatalf("sign refusal lacks %q: %s", want, errOut.String())
				}
			}
			if _, err := os.Lstat(batch); !os.IsNotExist(err) {
				t.Fatalf("a refused draft left a batch: %v", err)
			}

			rec, ok := f.tryRecord(t)
			if ok {
				t.Fatal("the offline checks accept the batch")
			}
			f.sign(t, rec)
			out.Reset()
			code = approvalMain([]string{"verify", "--onboarding", batch, "--base", f.base.Root, "--head", f.head.Root, "--keys", keysPath, "--keys-digest", digest, "--now", gateNow.Format(time.RFC3339)}, env, DefaultLayout(), &out, &errOut)
			if code != 1 || !strings.Contains(out.String(), "REFUSED") {
				t.Fatalf("verify: code=%d %s", code, out.String())
			}
			r := f.gate(t)
			for _, want := range tc.want {
				if !strings.Contains(out.String(), want) {
					t.Fatalf("verify refusal lacks %q: %s", want, out.String())
				}
				requireFail(t, r, want)
			}
		})
	}
}

// One project without a confirmed claim refuses the whole batch, and an
// attest batch is held to the same rule.
func TestOnboardingClaimsEveryProjectAndKind(t *testing.T) {
	t.Parallel()
	t.Run("second project", func(t *testing.T) {
		f := newOnboardingFixture(t)
		rec := f.record(t)
		second := rec.Projects[0]
		second.Slug = "zz-unconfirmed"
		setClaims(&second, 0, 1, 0)
		f.draft.Projects = append(f.draft.Projects, second)
		rec, ok := f.tryRecord(t)
		if ok {
			t.Fatal("the offline checks accept the batch")
		}
		f.sign(t, rec)
		requireFail(t, f.gate(t), "zz-unconfirmed: the proposal reports no confirmed claim")
	})
	t.Run("attest", func(t *testing.T) {
		f := attestFixture(t, nil)
		setClaims(&f.draft.Projects[0], 0, 2, 0)
		rec, ok := f.tryRecord(t)
		if ok {
			t.Fatal("the offline checks accept the batch")
		}
		f.sign(t, rec)
		requireFail(t, f.gate(t), "no confirmed claim")
	})
}

// The bot route is held to the rule too: before readiness and the key, and at
// the gate for a v2 batch signed anyway.
func TestOnboardingV2ClaimsRequired(t *testing.T) {
	t.Parallel()
	for _, tc := range claimsCases {
		if tc.want == nil {
			continue // TestOnboardingV2SigningPreKeyOrder and ...AdmissionAndGate
		}
		t.Run("signer "+tc.name, func(t *testing.T) {
			t.Parallel()
			a := newAdmissionFixture(t, nil)
			setClaims(&a.f.draft.Projects[0], tc.confirmed, tc.undetermined, tc.refuted)
			reader, fd := admissionTestPipe(t)
			reads := 0
			env := approvalEnv{onboardingSource: a.f.src, stdin: bytes.NewReader(a.bot.pemKey(t)),
				checkStdin: func(io.Reader) error { reads++; return nil }, now: func() time.Time { return gateNow }, random: bytes.NewReader(make([]byte, 128)),
				confirm: func(string) (string, error) { t.Error("confirmation reached"); return "", nil }}
			var out, errOut bytes.Buffer
			code := approvalMain(append(admissionSignArgs(t, a), "--admission-ready-fd", strconv.Itoa(fd)), env, DefaultLayout(), &out, &errOut)
			if code != 2 || reads != 0 || !strings.Contains(errOut.String(), tc.want[0]) {
				t.Fatalf("code=%d key accesses=%d error=%s", code, reads, errOut.String())
			}
			if raw, err := io.ReadAll(reader); err != nil || len(raw) != 0 {
				t.Fatalf("refused draft emitted readiness: %q %v", raw, err)
			}
			if a.opts.Head.Exists(a.opts.Layout.Onboarding.Dir + "/" + a.f.draft.BatchID + ".json") {
				t.Fatal("refused request wrote a signature")
			}
		})
		t.Run("gate "+tc.name, func(t *testing.T) {
			t.Parallel()
			a := newAdmissionFixture(t, nil)
			setClaims(&a.env.Record.Projects[0], tc.confirmed, tc.undetermined, tc.refuted)
			if err := checkBotAdmission(context.Background(), a.env, a.keys, a.opts, true); err != nil {
				t.Fatalf("the refusal must be the batch check's own: %v", err)
			}
			a.commitApproval(t)
			r := runGate(t, a.opts)
			for _, want := range tc.want {
				requireFail(t, r, want)
			}
		})
	}
}

// Merged batches with a project that has no confirmed claim keep loading, and
// as base history they do not stop a new batch on either signature route.
func TestOnboardingClaimsHistoryUnaffected(t *testing.T) {
	t.Parallel()
	history := map[string][]byte{}
	for _, name := range []string{"ob-20261016-2.json", "ob-20261016-3.json"} {
		raw, err := os.ReadFile(filepath.Join(repoRoot, filepath.FromSlash(DefaultLayout().Onboarding.Dir), name))
		if err != nil {
			t.Fatal(err)
		}
		e, err := decodeOnboarding(raw)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := SignedOnboardingBytes(e.Record); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		unconfirmed := 0
		for _, p := range e.Record.Projects {
			if p.Proof.Claims.Confirmed == 0 {
				unconfirmed++
			}
		}
		if unconfirmed == 0 {
			t.Fatalf("%s no longer holds a project without a confirmed claim", name)
		}
		history[name] = raw
	}
	add := func(f *onboardingFixture) {
		for name, raw := range history {
			f.writeBatch(t, f.base, name, raw)
			f.writeBatch(t, f.head, name, raw)
		}
	}
	t.Run("v1", func(t *testing.T) {
		f := newOnboardingFixture(t)
		add(f)
		f.sign(t, f.record(t))
		requirePass(t, f.gate(t))
	})
	t.Run("v2", func(t *testing.T) {
		a := newAdmissionFixture(t, func(f *onboardingFixture, _ testApprovalKey) { add(f) })
		a.commitApproval(t)
		requirePass(t, runGate(t, a.opts))
	})
}
