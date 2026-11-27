// SPDX-License-Identifier: AGPL-3.0-only

package knowledgegate

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// exceptCarry gives an automated-statement fixture what the gate needs to
// admit it: a pinned owner key in both trees and one signed carry exception
// in the base (and unchanged in the head) for every listed record.
func (f *reattestFixture) exceptCarry(t *testing.T, layout Layout, ids ...string) {
	t.Helper()
	f.owner = newApprovalKey(t)
	raw, err := json.Marshal(ApprovalKeys{
		Schema: ApprovalKeysSchema, Role: ApprovalKeyRole, Owners: []string{"airstand"},
		Keys: []ApprovalKey{{KeyID: ApprovalKeyID(f.owner.public), PublicKey: hex.EncodeToString(f.owner.public), NotAfter: "2099-01-01T00:00:00Z"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, tr := range []Tree{f.base, f.head} {
		writeFile(t, filepath.Join(tr.Root, filepath.FromSlash(layout.ApprovalKeysPath)), raw)
	}
	f.keysDigest = ApprovalKeysDigest(raw)
	for _, id := range ids {
		f.writeException(t, layout, id, f.exception(t, layout, id, nil))
	}
}

func (f reattestFixture) writeException(t *testing.T, layout Layout, id string, raw []byte) {
	t.Helper()
	for _, tr := range []Tree{f.base, f.head} {
		writeFile(t, filepath.Join(tr.Root, filepath.FromSlash(CarryExceptionPath(layout.Packs[0].Name, id))), raw)
	}
}

func (f reattestFixture) removeException(t *testing.T, id string, trees ...Tree) {
	t.Helper()
	for _, tr := range trees {
		if err := os.Remove(filepath.Join(tr.Root, filepath.FromSlash(CarryExceptionPath("community", id)))); err != nil {
			t.Fatal(err)
		}
	}
}

func (f reattestFixture) baseCanonicalOf(t *testing.T, layout Layout, id string) []byte {
	t.Helper()
	p, err := loadPack(f.base, layout.Packs[0])
	if err != nil {
		t.Fatal(err)
	}
	c := baseRecordCanonical(p, id)
	if c == nil {
		t.Fatalf("no base record %s", id)
	}
	return c
}

// exception signs, with the fixture's owner key and after edit, an exception
// for one base record. It does not check what it signs.
func (f reattestFixture) exception(t *testing.T, layout Layout, id string, edit func(r *CarryExceptionRecord)) []byte {
	t.Helper()
	rec := CarryExceptionRecord{
		BaseDigest: CandidateDigest(f.baseCanonicalOf(t, layout, id)),
		DecidedAt:  f.now.Add(-time.Hour).Format("2006-01-02T15:04:05Z"),
		Identity:   "airstand",
		NotAfter:   f.now.Add(48 * time.Hour).Format("2006-01-02T15:04:05Z"),
		Pack:       layout.Packs[0].Name,
		RecordID:   id,
	}
	if edit != nil {
		edit(&rec)
	}
	msg, err := signedCarryBytes(rec)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.MarshalIndent(CarryExceptionEnvelope{
		Schema: CarryExceptionSchema, Record: rec, KeyID: ApprovalKeyID(f.owner.public),
		Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(f.owner.private, msg)),
	}, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return append(raw, '\n')
}

func readTreeFile(t *testing.T, tr Tree, rel string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(tr.Root, filepath.FromSlash(rel)))
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// An automated statement carries dates without a new derivation: the gate
// admits it only with the owner's exception, read from the base, for every
// record it renews.
func TestGateRefusesAutomatedCarryWithoutAnOwnerException(t *testing.T) {
	t.Parallel()
	l := synthLayout()
	type mutation func(t *testing.T, f *reattestFixture, o *Options)
	type tc struct {
		mutate mutation
		want   string
	}
	write := func(raw func(t *testing.T, f *reattestFixture) []byte) mutation {
		return func(t *testing.T, f *reattestFixture, o *Options) {
			f.writeException(t, l, f.ruleID, raw(t, f))
		}
	}
	signed := func(edit func(f *reattestFixture, r *CarryExceptionRecord)) mutation {
		return write(func(t *testing.T, f *reattestFixture) []byte {
			return f.exception(t, l, f.ruleID, func(r *CarryExceptionRecord) { edit(f, r) })
		})
	}
	stamp := func(at time.Time) string { return at.Format("2006-01-02T15:04:05Z") }
	cases := map[string]tc{
		"no exception": {func(t *testing.T, f *reattestFixture, o *Options) {
			f.removeException(t, f.ruleID, f.base, f.head)
		}, "no owner exception in the base"},
		"exception only in the head": {func(t *testing.T, f *reattestFixture, o *Options) {
			f.removeException(t, f.ruleID, f.base)
		}, "no owner exception in the base"},
		"unsigned": {write(func(t *testing.T, f *reattestFixture) []byte {
			var env CarryExceptionEnvelope
			if err := json.Unmarshal(f.exception(t, l, f.ruleID, nil), &env); err != nil {
				t.Fatal(err)
			}
			env.Signature = ""
			raw, err := json.Marshal(env)
			if err != nil {
				t.Fatal(err)
			}
			return raw
		}), "signature does not verify"},
		"plain file, no envelope": {write(func(t *testing.T, f *reattestFixture) []byte {
			return []byte("owner agrees\n")
		}), "carry exception"},
		"key that is not pinned": {write(func(t *testing.T, f *reattestFixture) []byte {
			other := *f
			other.owner = newApprovalKey(t)
			return other.exception(t, l, f.ruleID, nil)
		}), "not pinned"},
		"flipped byte": {write(func(t *testing.T, f *reattestFixture) []byte {
			raw := f.exception(t, l, f.ruleID, nil)
			return bytes.Replace(raw, []byte(`"identity": "airstand"`), []byte(`"identity": "airstanD"`), 1)
		}), "signature does not verify"},
		"another schema": {write(func(t *testing.T, f *reattestFixture) []byte {
			raw := f.exception(t, l, f.ruleID, nil)
			return bytes.Replace(raw, []byte(CarryExceptionSchema), []byte(ApprovalSchema), 1)
		}), "wrong schema"},
		"not an owner":   {signed(func(f *reattestFixture, r *CarryExceptionRecord) { r.Identity = "someone" }), "not an owner"},
		"another record": {signed(func(f *reattestFixture, r *CarryExceptionRecord) { r.RecordID = "other.rule" }), "different record"},
		"another pack":   {signed(func(f *reattestFixture, r *CarryExceptionRecord) { r.Pack = "cncf" }), "different record"},
		"another base digest": {signed(func(f *reattestFixture, r *CarryExceptionRecord) {
			r.BaseDigest = "sha256:" + strings.Repeat("0", 64)
		}), "base digest does not match"},
		"expired": {signed(func(f *reattestFixture, r *CarryExceptionRecord) {
			r.DecidedAt, r.NotAfter = stamp(f.now.Add(-48*time.Hour)), stamp(f.now.Add(-time.Second))
		}), "expired"},
		"expires at the gate clock": {signed(func(f *reattestFixture, r *CarryExceptionRecord) { r.NotAfter = stamp(f.now) }), "expired"},
		"decided in the future": {signed(func(f *reattestFixture, r *CarryExceptionRecord) {
			r.DecidedAt, r.NotAfter = stamp(f.now.Add(time.Hour)), stamp(f.now.Add(2*time.Hour))
		}), "decided in the future"},
		"lives longer than 14 days": {signed(func(f *reattestFixture, r *CarryExceptionRecord) {
			r.NotAfter = stamp(f.now.Add(15 * 24 * time.Hour))
		}), "at most 14 days"},
		"ends before it was decided": {signed(func(f *reattestFixture, r *CarryExceptionRecord) {
			r.NotAfter = stamp(f.now.Add(-2 * time.Hour))
		}), "must be after decidedAt"},
		"unreadable expiry": {signed(func(f *reattestFixture, r *CarryExceptionRecord) { r.NotAfter = "never" }), "notAfter"},
		// "none" is the test helper's word for an unconfigured digest.
		"no key digest configured": {func(t *testing.T, f *reattestFixture, o *Options) { o.ApprovalKeysDigest = "none" }, "no owner approval key digest"},
		"other key digest configured": {func(t *testing.T, f *reattestFixture, o *Options) {
			o.ApprovalKeysDigest = "sha256:" + strings.Repeat("0", 64)
		}, "does not match the pinned digest"},
		"key file only in the head": {func(t *testing.T, f *reattestFixture, o *Options) {
			if err := os.Remove(filepath.Join(f.base.Root, filepath.FromSlash(l.ApprovalKeysPath))); err != nil {
				t.Fatal(err)
			}
		}, "no owner approval key is pinned in the base"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			f := newReattestFixture(t)
			o := f.opts()
			c.mutate(t, &f, &o)
			r := runGate(t, o)
			requireFail(t, r, c.want)
			if got := change(t, r, f.ruleID); got.OK {
				t.Fatal("the renewal was admitted")
			}
			if ch, ok := check(r, "reattestation/community"); !ok || ch.OK {
				t.Fatalf("reattestation check %+v", ch)
			}
		})
	}
}

// One exception is not enough for a statement that renews several records:
// each record, rule or not, needs its own.
func TestGateAutomatedCarryNeedsAnExceptionForEveryRecord(t *testing.T) {
	t.Parallel()
	for _, missing := range []string{reviewedAttestationID, reviewedPolicyID} {
		f := newRecordFixture(t, false)
		f.removeException(t, missing, f.base, f.head)
		r := runGate(t, f.opts())
		requireFail(t, r, "no owner exception in the base")
		for _, id := range []string{f.ruleID, reviewedAttestationID, reviewedPolicyID} {
			if change(t, r, id).OK {
				t.Fatalf("%s admitted with %s unexcepted", id, missing)
			}
		}
	}
}

// The automation account may neither add, change nor remove an exception.
func TestGateAutomationAccountMayNotChangeCarryExceptions(t *testing.T) {
	t.Parallel()
	const refusal = "the automation account may not change carry exceptions"
	for name, edit := range map[string]func(t *testing.T, f reattestFixture){
		"added": func(t *testing.T, f reattestFixture) {
			writeFile(t, filepath.Join(f.head.Root, filepath.FromSlash(CarryExceptionDir), "community", "new.json"), []byte("{}\n"))
		},
		"changed": func(t *testing.T, f reattestFixture) {
			writeFile(t, filepath.Join(f.head.Root, filepath.FromSlash(CarryExceptionPath("community", f.ruleID))), []byte("{}\n"))
		},
		"removed": func(t *testing.T, f reattestFixture) { f.removeException(t, f.ruleID, f.head) },
	} {
		t.Run(name, func(t *testing.T) {
			f := newReattestFixture(t)
			edit(t, f)
			requireFail(t, runGate(t, f.opts()), refusal)
			o := f.opts()
			o.Author = ""
			requireFail(t, runGate(t, o), refusal)
		})
	}
}

func TestSignCarryExceptionRefusesWhatTheGateWouldRefuse(t *testing.T) {
	t.Parallel()
	f := newReattestFixture(t)
	l := synthLayout()
	keys, err := LoadApprovalKeys(readTreeFile(t, f.base, l.ApprovalKeysPath), f.keysDigest)
	if err != nil {
		t.Fatal(err)
	}
	canonical := f.baseCanonicalOf(t, l, f.ruleID)
	good := CarryExceptionRecord{
		BaseDigest: CandidateDigest(canonical), DecidedAt: f.now.Format("2006-01-02T15:04:05Z"),
		Identity: "airstand", NotAfter: f.now.Add(time.Hour).Format("2006-01-02T15:04:05Z"), Pack: "community", RecordID: f.ruleID,
	}
	raw, err := SignCarryException(f.owner.private, keys, good, canonical, f.now)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyCarryException(raw, keys, "community", f.ruleID, canonical, f.now); err != nil {
		t.Fatal(err)
	}
	if err := VerifyCarryException(raw, keys, "community", f.ruleID, nil, f.now); err == nil {
		t.Fatal("verified against an absent base record")
	}
	bot := keys
	bot.Keys = append([]ApprovalKey(nil), keys.Keys...)
	bot.Keys[0].Tier = ApprovalTierOnboardingBot
	if err := VerifyCarryException(raw, bot, "community", f.ruleID, canonical, f.now); err == nil {
		t.Fatal("a bot-tier key signed an exception")
	}
	expired := keys
	expired.Keys = append([]ApprovalKey(nil), keys.Keys...)
	expired.Keys[0].NotAfter = f.now.Format("2006-01-02T15:04:05Z")
	if err := VerifyCarryException(raw, expired, "community", f.ruleID, canonical, f.now); err == nil {
		t.Fatal("an expired key signed an exception")
	}
	if _, err := SignCarryException(newApprovalKey(t).private, keys, good, canonical, f.now); err == nil {
		t.Fatal("an unpinned key signed")
	}
	bad := good
	bad.NotAfter = f.now.Add(30 * 24 * time.Hour).Format("2006-01-02T15:04:05Z")
	if _, err := SignCarryException(f.owner.private, keys, bad, canonical, f.now); err == nil {
		t.Fatal("signed a 30-day exception")
	}
}
