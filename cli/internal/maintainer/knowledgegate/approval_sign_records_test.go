// SPDX-License-Identifier: AGPL-3.0-only

package knowledgegate

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// attestationFixture proposes a reviewed line attestation for 1.25 beside
// the base's 1.22, with a pinned key.
func attestationFixture(t *testing.T, headLines ...string) signFixture {
	t.Helper()
	if len(headLines) == 0 {
		headLines = []string{"1.22", "1.25"}
	}
	base, head := attestedTrees(t, []string{"1.22"}, headLines, nil)
	return pinFixture(t, base, head, attestationID("1.25"))
}

func (f signFixture) recordSubjectArgs(record string) []string {
	return []string{
		"--subject", "lineAttestation", "--pack", "cncf", "--record", record,
		"--base-pack", filepath.Join(f.base.Root, filepath.FromSlash(cncfRulesPath)),
		"--head-pack", filepath.Join(f.head.Root, filepath.FromSlash(cncfRulesPath)),
		"--keys", f.keysPath(), "--keys-digest", f.keysDigest,
	}
}

func (f signFixture) recordSignArgs(keyArgs ...string) []string {
	args := append([]string{"sign"}, f.recordSubjectArgs(f.id)...)
	args = append(args, "--identity", "airstand", "--candidate-id", "pr-42", "--output", f.out())
	return append(args, keyArgs...)
}

func (f signFixture) recordVerifyArgs() []string {
	return append([]string{"verify", "--approval", f.out(), "--base-root", f.base.Root}, f.recordSubjectArgs(f.id)...)
}

// A line attestation approval written by "approval sign" is admitted by the
// gate (the only failing check is the known per-project split refusal for
// packs with records), is byte for byte the gate's own format, and
// "approval verify" accepts it.
func TestApprovalSignAttestationRoundTrip(t *testing.T) {
	f := attestationFixture(t)
	requireCode(t, runApproval(t, f.key.pemKey(t), signNow, f.recordSignArgs("--key-stdin")...), 0, "line attestation cncf/"+f.id)
	r := runGate(t, Options{Base: f.base, Head: f.head, Source: fixtureSource, Author: DefaultBotLogin, ApprovalKeysDigest: f.keysDigest})
	requireAdmittedButUnsplit(t, r)
	if c := change(t, r, f.id); c.Proof != ProofApproval {
		t.Fatalf("proof %q", c.Proof)
	}
	requireCode(t, runApproval(t, nil, gateNow, f.recordVerifyArgs()...), 0, "approval OK")

	want := recordApproval(f.id, "1.25", ApprovalBaseAbsent, recordDigest(t, f.head, f.id))
	want.CandidateID = "pr-42"
	got, err := os.ReadFile(f.out())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, f.key.sign(t, want)) {
		t.Fatalf("signer output differs from the gate's format:\n%s", got)
	}
}

func TestApprovalSignAttestationTamperRefused(t *testing.T) {
	f := attestationFixture(t)
	requireCode(t, runApproval(t, f.key.pemKey(t), signNow, f.recordSignArgs("--key-stdin")...), 0, "approval written")
	signed, err := os.ReadFile(f.out())
	if err != nil {
		t.Fatal(err)
	}
	var env ApprovalEnvelope
	if err := json.Unmarshal(signed, &env); err != nil {
		t.Fatal(err)
	}
	for name, mut := range map[string]func(e *ApprovalEnvelope){
		"scope":           func(e *ApprovalEnvelope) { e.Record.Scope = recordApproval(f.id, "1.26", "", "").Scope },
		"subject removed": func(e *ApprovalEnvelope) { e.Record.Subject, e.Record.Scope = "", "" },
		"record id":       func(e *ApprovalEnvelope) { e.Record.RuleID = attestationID("1.26") },
		"candidate digest": func(e *ApprovalEnvelope) {
			e.Record.CandidateDigest = "sha256:" + string(bytes.Repeat([]byte("ab"), 32))
		},
		"base digest":  func(e *ApprovalEnvelope) { e.Record.BaseDigest = env.Record.CandidateDigest },
		"identity":     func(e *ApprovalEnvelope) { e.Record.Identity = "airstand2" },
		"decided at":   func(e *ApprovalEnvelope) { e.Record.DecidedAt = "2026-10-03T11:00:01Z" },
		"candidate id": func(e *ApprovalEnvelope) { e.Record.CandidateID = "pr-43" },
	} {
		t.Run(name, func(t *testing.T) {
			e := env
			mut(&e)
			raw, err := json.MarshalIndent(e, "", "  ")
			if err != nil {
				t.Fatal(err)
			}
			writeFile(t, f.out(), append(raw, '\n'))
			requireCode(t, runApproval(t, nil, gateNow, f.recordVerifyArgs()...), 1, "approval REFUSED")
		})
	}
}

func TestApprovalSignAttestationRefusals(t *testing.T) {
	t.Run("record id given as a rule", func(t *testing.T) {
		f := attestationFixture(t)
		requireCode(t, runApproval(t, f.key.pemKey(t), signNow, f.signArgs("--key-stdin")...), 2, "has no rule")
	})
	t.Run("rule flag with the attestation subject", func(t *testing.T) {
		f := attestationFixture(t)
		requireCode(t, runApproval(t, f.key.pemKey(t), signNow, append(f.recordSignArgs("--key-stdin"), "--rule", "x")...), 2, "takes --record ID, not --rule")
	})
	t.Run("record not in the proposed pack", func(t *testing.T) {
		f := attestationFixture(t)
		f.id = attestationID("1.26")
		requireCode(t, runApproval(t, f.key.pemKey(t), signNow, f.recordSignArgs("--key-stdin")...), 2, "has no record")
	})
	t.Run("unchanged record", func(t *testing.T) {
		f := attestationFixture(t)
		f.id = attestationID("1.22")
		requireCode(t, runApproval(t, f.key.pemKey(t), signNow, f.recordSignArgs("--key-stdin")...), 2, "nothing to approve")
	})
	t.Run("community pack has no records", func(t *testing.T) {
		f := attestationFixture(t)
		args := f.recordSignArgs("--key-stdin")
		for i := range args {
			if args[i] == "cncf" && args[i-1] == "--pack" {
				args[i] = "community"
			}
		}
		requireCode(t, runApproval(t, f.key.pemKey(t), signNow, args...), 2, "carries no line attestations")
	})
	t.Run("duplicate record in the proposed pack", func(t *testing.T) {
		f := attestationFixture(t)
		p := readPack(t, f.head, cncfRulesPath)
		var atts []json.RawMessage
		if err := json.Unmarshal(p.fields["lineAttestations"], &atts); err != nil {
			t.Fatal(err)
		}
		raw, err := json.Marshal(append(atts, atts[len(atts)-1]))
		if err != nil {
			t.Fatal(err)
		}
		p.fields["lineAttestations"] = raw
		p.write(t, f.head, cncfRulesPath)
		r := runApproval(t, f.key.pemKey(t), signNow, f.recordSignArgs("--key-stdin")...)
		if r.code != 2 || !strings.Contains(r.stderr, "two attestations for") {
			t.Fatalf("exit %d: %s", r.code, r.stderr)
		}
	})
}

// Only reviewed line attestations are approvable: the gate admits a
// mechanical attestation only by re-derivation and accepts no approval for
// a path policy.
func TestApprovalSignRecordKinds(t *testing.T) {
	spec := recordLayout().Packs[0]
	base, _, _ := recordPack(t, gateNow, false)
	withMechanical, _, _ := recordPack(t, gateNow, true)
	if _, err := AttestationApprovalSubject(spec, base, withMechanical, mechanicalAttestationID); err == nil || !strings.Contains(err.Error(), "admits only a reviewed attestation") {
		t.Fatalf("mechanical attestation: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(base, &doc); err != nil {
		t.Fatal(err)
	}
	ev := sectionRecord(doc, "pathPolicies", 0)["evidence"].(map[string]any)
	ev["validUntil"] = shiftTime(t, ev["validUntil"], 24*time.Hour)
	head, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := AttestationApprovalSubject(spec, base, head, reviewedPolicyID); err == nil || !strings.Contains(err.Error(), "is not a line attestation") {
		t.Fatalf("path policy: %v", err)
	}

	edit := func(t *testing.T, raw []byte, change func(doc map[string]any)) []byte {
		t.Helper()
		var doc map[string]any
		if err := json.Unmarshal(raw, &doc); err != nil {
			t.Fatal(err)
		}
		change(doc)
		out, err := json.Marshal(doc)
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	// A mechanical base record turned reviewed: the gate refuses it ("evidence
	// basis ... is not admitted here"), so the signer refuses to sign it.
	reviewedHead := edit(t, withMechanical, func(doc map[string]any) {
		ev := sectionRecord(doc, "lineAttestations", 1)["evidence"].(map[string]any)
		ev["basis"] = "reviewed"
		delete(ev, "extractor")
		delete(ev, "derivedAt")
		ev["validUntil"] = shiftTime(t, ev["validUntil"], 24*time.Hour)
	})
	if _, err := AttestationApprovalSubject(spec, withMechanical, reviewedHead, mechanicalAttestationID); err == nil || !strings.Contains(err.Error(), "mechanical in the base") {
		t.Fatalf("mechanical base: %v", err)
	}
	// A change that only shortens validUntil is tightening: it needs no
	// approval, and an approval file for it fails the gate.
	shortened := edit(t, base, func(doc map[string]any) {
		ev := sectionRecord(doc, "lineAttestations", 0)["evidence"].(map[string]any)
		ev["validUntil"] = shiftTime(t, ev["validUntil"], -24*time.Hour)
	})
	if _, err := AttestationApprovalSubject(spec, base, shortened, reviewedAttestationID); err == nil || !strings.Contains(err.Error(), "not loosening") {
		t.Fatalf("tightening edit: %v", err)
	}
	// Control: the same record with a later validUntil is loosening and signs.
	extended := edit(t, base, func(doc map[string]any) {
		ev := sectionRecord(doc, "lineAttestations", 0)["evidence"].(map[string]any)
		ev["validUntil"] = shiftTime(t, ev["validUntil"], 24*time.Hour)
	})
	if s, err := AttestationApprovalSubject(spec, base, extended, reviewedAttestationID); err != nil || s.Base == nil {
		t.Fatalf("loosening edit: %+v %v", s, err)
	}
}

// A signed record approval follows the gate's single-use and forward-only
// rules, which the signer does not see (it reads no base approvals): the
// owner moves the file out of the way and signs again. The first approval
// sits in the base as the one a former change used; the gate refuses the
// same file again, refuses a new one decided at the same time, and admits
// one decided later.
func TestApprovalSignAttestationSingleUseAndForwardOnly(t *testing.T) {
	f := attestationFixture(t)
	signAt := func(now time.Time, candidate string) {
		t.Helper()
		args := f.recordSignArgs("--key-stdin")
		for i := range args {
			if args[i] == "pr-42" {
				args[i] = candidate
			}
		}
		requireCode(t, runApproval(t, f.key.pemKey(t), now, args...), 0, "approval written")
	}
	gate := func() *Report {
		return runGate(t, Options{Base: f.base, Head: f.head, Source: fixtureSource, Author: DefaultBotLogin, ApprovalKeysDigest: f.keysDigest})
	}
	refused := func(want string) {
		t.Helper()
		c := change(t, gate(), f.id)
		if c.OK || !strings.Contains(c.Detail, want) {
			t.Fatalf("want a refusal containing %q, got ok=%v %q", want, c.OK, c.Detail)
		}
	}

	signAt(signNow, "pr-42")
	spent, err := os.ReadFile(f.out())
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, approvalPath(f.base, f.id), spent) // an earlier change used it
	refused("already in the base")
	// "approval verify" says the same before it says OK.
	requireCode(t, runApproval(t, nil, gateNow, f.recordVerifyArgs()...), 1, "already in the base")

	if err := os.Remove(f.out()); err != nil {
		t.Fatal(err)
	}
	signAt(signNow, "pr-43") // a different decision, same time
	refused("decided at the same time or later")

	if err := os.Remove(f.out()); err != nil {
		t.Fatal(err)
	}
	signAt(signNow.Add(time.Minute), "pr-44")
	requireAdmittedButUnsplit(t, gate())
	if c := change(t, gate(), f.id); c.Proof != ProofApproval {
		t.Fatalf("proof %q", c.Proof)
	}
}

// An approval for a record the base already holds binds the base record's
// digest: signing, verification and the gate agree on it.
func TestApprovalSignAttestationChangedRecord(t *testing.T) {
	base, head := attestedTrees(t, []string{"1.22"}, []string{"1.22"}, func(p *packDoc, atts []map[string]any) []map[string]any {
		ev := atts[0]["evidence"].(map[string]any)
		ev["validUntil"] = shiftTime(t, ev["validUntil"], 24*time.Hour)
		return atts
	})
	f := pinFixture(t, base, head, attestationID("1.22"))
	requireCode(t, runApproval(t, f.key.pemKey(t), signNow, f.recordSignArgs("--key-stdin")...), 0, "approval written")
	var env ApprovalEnvelope
	raw, err := os.ReadFile(f.out())
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatal(err)
	}
	if env.Record.BaseDigest == ApprovalBaseAbsent || env.Record.BaseDigest == env.Record.CandidateDigest {
		t.Fatalf("base digest %q", env.Record.BaseDigest)
	}
	requireCode(t, runApproval(t, nil, gateNow, f.recordVerifyArgs()...), 0, "approval OK")
	r := runGate(t, Options{Base: f.base, Head: f.head, Source: fixtureSource, Author: DefaultBotLogin, ApprovalKeysDigest: f.keysDigest})
	// The fixture's pinned upstream bytes derive no pair into line 1.22, so
	// the extractor cross-check refuses; the approval itself is not the
	// reason.
	c := change(t, r, f.id)
	if c.OK || strings.Contains(c.Detail, "approval:") || strings.Contains(c.Detail, "no owner approval") || !strings.Contains(c.Detail, "cross-check with the extractor") {
		t.Fatalf("gate: ok=%v %s", c.OK, c.Detail)
	}
}

func TestApprovalSignSubjectFlagCombinations(t *testing.T) {
	f := attestationFixture(t)
	t.Run("record with the rule subject", func(t *testing.T) {
		args := append(f.signArgs("--key-stdin"), "--record", f.id)
		requireCode(t, runApproval(t, f.key.pemKey(t), signNow, args...), 2, "--subject rule takes --rule ID, not --record")
	})
	t.Run("record id outside the alphabet", func(t *testing.T) {
		g := f
		g.id = "bad id"
		requireCode(t, runApproval(t, f.key.pemKey(t), signNow, g.recordSignArgs("--key-stdin")...), 2, "not a valid approval record ID")
	})
	// The baseline flags belong to --subject repinBaseline only.
	for _, flag := range [][]string{
		{"--repository", "owner/repo"},
		{"--head-baselines", "head.json"},
		{"--base-baselines", "base.json"},
	} {
		t.Run("record with baseline flag "+flag[0], func(t *testing.T) {
			args := append(f.recordSignArgs("--key-stdin"), flag...)
			requireCode(t, runApproval(t, f.key.pemKey(t), signNow, args...), 2, "belong to --subject repinBaseline")
		})
		t.Run("rule with baseline flag "+flag[0], func(t *testing.T) {
			g := newRuleFixture(t)
			args := append(g.signArgs("--key-stdin"), flag...)
			requireCode(t, runApproval(t, g.key.pemKey(t), signNow, args...), 2, "belong to --subject repinBaseline")
		})
	}
	t.Run("baseline with the record flag", func(t *testing.T) {
		g := newBaselineSignFixture(t)
		args := append(g.signArgs(false, "--key-stdin"), "--record", "x")
		requireCode(t, runApproval(t, g.key.pemKey(t), signNow, args...), 2, "--record")
	})
	// verify checks the base's approvals, so it needs the base checkout for
	// the subjects the gate checks them for, and refuses it for a rule.
	t.Run("verify without the base checkout", func(t *testing.T) {
		requireCode(t, runApproval(t, f.key.pemKey(t), signNow, f.recordSignArgs("--key-stdin")...), 0, "approval written")
		args := f.recordVerifyArgs()
		args = append(args[:3], args[5:]...) // drop --base-root DIR
		requireCode(t, runApproval(t, nil, gateNow, args...), 2, "--base-root is required")
	})
	t.Run("verify a rule with a base checkout", func(t *testing.T) {
		g := newRuleFixture(t)
		args := append(g.verifyArgs(""), "--base-root", g.base.Root)
		requireCode(t, runApproval(t, nil, gateNow, args...), 2, "--base-root belongs to")
	})
}
