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
	return append([]string{"verify", "--approval", f.out()}, f.recordSubjectArgs(f.id)...)
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
}
