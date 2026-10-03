// SPDX-License-Identifier: AGPL-3.0-only

package knowledgegate

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// testApprovalKey is a throwaway web-approval key for tests only. The
// production key is pinned separately, in the base tree.
type testApprovalKey struct {
	public  ed25519.PublicKey
	private ed25519.PrivateKey
}

func newApprovalKey(t *testing.T) testApprovalKey {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return testApprovalKey{pub, priv}
}

func (k testApprovalKey) pin(t *testing.T, tr Tree, owners ...string) {
	t.Helper()
	k.pinUntil(t, tr, "2027-10-01T00:00:00Z", owners...)
}

// pinBoth pins the key in the base and leaves the file unchanged in the
// head, as in any change made on top of the base.
func (k testApprovalKey) pinBoth(t *testing.T, base, head Tree, owners ...string) {
	t.Helper()
	k.pin(t, base, owners...)
	k.pin(t, head, owners...)
}

func (k testApprovalKey) pinUntil(t *testing.T, tr Tree, notAfter string, owners ...string) {
	t.Helper()
	raw, err := json.MarshalIndent(ApprovalKeys{
		Schema: ApprovalKeysSchema, Role: ApprovalKeyRole, Owners: owners,
		Keys: []ApprovalKey{{KeyID: ApprovalKeyID(k.public), PublicKey: hex.EncodeToString(k.public), NotAfter: notAfter}},
	}, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(tr.Root, filepath.FromSlash(DefaultLayout().ApprovalKeysPath)), raw)
}

func (k testApprovalKey) sign(t *testing.T, r ApprovalRecord) []byte {
	t.Helper()
	msg, err := SignedApprovalBytes(r)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.MarshalIndent(ApprovalEnvelope{Schema: ApprovalSchema, Record: r, KeyID: ApprovalKeyID(k.public), Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(k.private, msg))}, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return append(raw, '\n')
}

// approvalTrees proposes a new reviewed rule in the head and returns its id
// and the digest of its canonical entry.
func approvalTrees(t *testing.T) (Tree, Tree, string, string) {
	t.Helper()
	base, head := trees(t)
	ids := readPack(t, base, cncfRulesPath).activeReviewed()
	newID := ids[0] + "-approved"
	editPack(t, head, cncfRulesPath, func(p *packDoc) {
		added := deepCopy(p.find(t, ids[0])).(map[string]any)
		ruleOf(added)["id"] = newID
		// A lease outside the crowded weeks of the shipped pack, so the
		// stagger cap holds.
		evidenceOf(added)["reviewedAt"] = gateNow.Add(-2 * time.Hour).Format(time.RFC3339)
		evidenceOf(added)["validUntil"] = gateNow.Add(60 * 24 * time.Hour).Format(time.RFC3339)
		p.entries = append(p.entries, added)
		p.sortByID()
	})
	cls, err := Classify(DefaultLayout(), base, head)
	if err != nil {
		t.Fatal(err)
	}
	e := cls.head["cncf"].Entries[newID]
	return base, head, newID, CandidateDigest(e.Canonical)
}

func approvalPath(head Tree, id string) string {
	return filepath.Join(head.Root, filepath.FromSlash(DefaultLayout().ApprovalDir), "cncf", id+".json")
}

func TestGateOwnerApproval(t *testing.T) {
	key := newApprovalKey(t)
	good := func(id, digest string) ApprovalRecord {
		return ApprovalRecord{BaseDigest: ApprovalBaseAbsent, CandidateDigest: digest, CandidateID: "cand-1", DecidedAt: gateNow.Add(-time.Hour).Format(time.RFC3339), Decision: "approve", Identity: "airstand", Pack: "cncf", RuleID: id}
	}

	t.Run("valid", func(t *testing.T) {
		base, head, id, digest := approvalTrees(t)
		key.pinBoth(t, base, head, "airstand")
		writeFile(t, approvalPath(head, id), key.sign(t, good(id, digest)))
		r := runGate(t, Options{Base: base, Head: head})
		requirePass(t, r)
		if c := change(t, r, id); c.Proof != ProofApproval {
			t.Fatalf("proof %q", c.Proof)
		}
	})

	cases := map[string]struct {
		setup func(t *testing.T, base, head Tree, id, digest string)
		want  string
	}{
		"no approval": {func(t *testing.T, base, head Tree, id, digest string) { key.pinBoth(t, base, head, "airstand") }, "no owner approval"},
		"no pinned key": {func(t *testing.T, base, head Tree, id, digest string) {
			writeFile(t, approvalPath(head, id), key.sign(t, good(id, digest)))
		}, "no owner approval key is pinned"},
		"key pinned only in the head": {func(t *testing.T, base, head Tree, id, digest string) {
			key.pin(t, head, "airstand")
			writeFile(t, approvalPath(head, id), key.sign(t, good(id, digest)))
		}, "no owner approval key is pinned"},
		"unpinned signer": {func(t *testing.T, base, head Tree, id, digest string) {
			key.pinBoth(t, base, head, "airstand")
			writeFile(t, approvalPath(head, id), newApprovalKey(t).sign(t, good(id, digest)))
		}, "not pinned"},
		"entry changed after approval": {func(t *testing.T, base, head Tree, id, digest string) {
			key.pinBoth(t, base, head, "airstand")
			r := good(id, "sha256:"+strings.Repeat("ab", 32))
			writeFile(t, approvalPath(head, id), key.sign(t, r))
		}, "candidate digest does not match"},
		"not an owner": {func(t *testing.T, base, head Tree, id, digest string) {
			key.pinBoth(t, base, head, "airstand")
			r := good(id, digest)
			r.Identity = "someone-else"
			writeFile(t, approvalPath(head, id), key.sign(t, r))
		}, "is not an owner"},
		"rejected": {func(t *testing.T, base, head Tree, id, digest string) {
			key.pinBoth(t, base, head, "airstand")
			r := good(id, digest)
			r.Decision = "reject"
			writeFile(t, approvalPath(head, id), key.sign(t, r))
		}, `decision is "reject"`},
		"other rule": {func(t *testing.T, base, head Tree, id, digest string) {
			key.pinBoth(t, base, head, "airstand")
			r := good(id, digest)
			r.RuleID = "other.rule"
			writeFile(t, approvalPath(head, id), key.sign(t, r))
		}, "approves a different rule"},
		"older than 14 days": {func(t *testing.T, base, head Tree, id, digest string) {
			key.pinBoth(t, base, head, "airstand")
			r := good(id, digest)
			r.DecidedAt = gateNow.Add(-15 * 24 * time.Hour).Format(time.RFC3339)
			writeFile(t, approvalPath(head, id), key.sign(t, r))
		}, "older than 14 days"},
		"decided in the future": {func(t *testing.T, base, head Tree, id, digest string) {
			key.pinBoth(t, base, head, "airstand")
			r := good(id, digest)
			r.DecidedAt = gateNow.Add(time.Hour).Format(time.RFC3339)
			writeFile(t, approvalPath(head, id), key.sign(t, r))
		}, "decided in the future"},
		"other pack": {func(t *testing.T, base, head Tree, id, digest string) {
			key.pinBoth(t, base, head, "airstand")
			r := good(id, digest)
			r.Pack = "community"
			writeFile(t, approvalPath(head, id), key.sign(t, r))
		}, "approves a different rule"},
		"base digest of another state": {func(t *testing.T, base, head Tree, id, digest string) {
			key.pinBoth(t, base, head, "airstand")
			r := good(id, digest)
			r.BaseDigest = digest
			writeFile(t, approvalPath(head, id), key.sign(t, r))
		}, "base digest does not match"},
		"expired key": {func(t *testing.T, base, head Tree, id, digest string) {
			key.pinUntil(t, base, gateNow.Add(-time.Minute).Format(time.RFC3339), "airstand")
			key.pinUntil(t, head, gateNow.Add(-time.Minute).Format(time.RFC3339), "airstand")
			writeFile(t, approvalPath(head, id), key.sign(t, good(id, digest)))
		}, "signing key has expired"},
		"version 1 record": {func(t *testing.T, base, head Tree, id, digest string) {
			key.pinBoth(t, base, head, "airstand")
			raw := strings.Replace(string(key.sign(t, good(id, digest))), ApprovalSchema, "prufyx.io/knowledge-approval/v1", 1)
			writeFile(t, approvalPath(head, id), []byte(raw))
		}, "wrong schema"},
		"case-variant member": {func(t *testing.T, base, head Tree, id, digest string) {
			key.pinBoth(t, base, head, "airstand")
			raw := strings.Replace(string(key.sign(t, good(id, digest))), `"keyId"`, `"KeyId": "x", "keyId"`, 1)
			writeFile(t, approvalPath(head, id), []byte(raw))
		}, "letter case"},
		"tampered record": {func(t *testing.T, base, head Tree, id, digest string) {
			key.pinBoth(t, base, head, "airstand")
			r := good(id, digest)
			raw := key.sign(t, r)
			raw = []byte(strings.Replace(string(raw), `"cand-1"`, `"cand-2"`, 1))
			writeFile(t, approvalPath(head, id), raw)
		}, "signature does not verify"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			base, head, id, digest := approvalTrees(t)
			tc.setup(t, base, head, id, digest)
			r := runGate(t, Options{Base: base, Head: head})
			requireFail(t, r, tc.want)
		})
	}

	// The key file read from the base must match the digest pinned in the
	// gate's configuration.
	for name, tc := range map[string]struct{ digest, want string }{
		"no key digest configured": {"none", "no owner approval key digest is configured"},
		"key file digest mismatch": {"sha256:" + strings.Repeat("0", 64), "does not match the pinned digest"},
	} {
		t.Run(name, func(t *testing.T) {
			base, head, id, digest := approvalTrees(t)
			key.pinBoth(t, base, head, "airstand")
			writeFile(t, approvalPath(head, id), key.sign(t, good(id, digest)))
			requireFail(t, runGate(t, Options{Base: base, Head: head, ApprovalKeysDigest: tc.digest}), tc.want)
		})
	}
}

// An approval never admits a mechanical rule: those loosen only by
// re-derivation.
func TestApprovalDoesNotCoverMechanical(t *testing.T) {
	key := newApprovalKey(t)
	base, head, entries := mechanicalTrees(t, func(entries []map[string]any) { ruleOf(entries[0])["nextAction"] = "Changed." })
	key.pinBoth(t, base, head, "airstand")
	id := ruleID(entries[0])
	cls, err := Classify(DefaultLayout(), base, head)
	if err != nil {
		t.Fatal(err)
	}
	digest := CandidateDigest(cls.head["cncf"].Entries[id].Canonical)
	writeFile(t, approvalPath(head, id), key.sign(t, ApprovalRecord{BaseDigest: ApprovalBaseAbsent, CandidateDigest: digest, CandidateID: "c", DecidedAt: gateNow.Format(time.RFC3339), Decision: "approve", Identity: "airstand", Pack: "cncf", RuleID: id}))
	r := runGate(t, Options{Base: base, Head: head, Source: nil})
	if c := change(t, r, id); c.OK {
		t.Fatal("an approval admitted a mechanical rule")
	}
}

func TestParseApprovalKeysRejects(t *testing.T) {
	k := newApprovalKey(t)
	ok := ApprovalKeys{Schema: ApprovalKeysSchema, Role: ApprovalKeyRole, Owners: []string{"airstand"}, Keys: []ApprovalKey{{KeyID: ApprovalKeyID(k.public), PublicKey: hex.EncodeToString(k.public), NotAfter: "2027-01-01T00:00:00Z"}}}
	for name, mut := range map[string]func(a *ApprovalKeys){
		"role":     func(a *ApprovalKeys) { a.Role = "human" },
		"no owner": func(a *ApprovalKeys) { a.Owners = nil },
		"key id":   func(a *ApprovalKeys) { a.Keys[0].KeyID = "sha256:" + strings.Repeat("0", 64) },
		"short":    func(a *ApprovalKeys) { a.Keys[0].PublicKey = "abcd" },
	} {
		a := ok
		a.Keys = append([]ApprovalKey(nil), ok.Keys...)
		mut(&a)
		raw, _ := json.Marshal(a)
		if _, err := ParseApprovalKeys(raw); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
	raw, _ := json.Marshal(ok)
	if _, err := ParseApprovalKeys(raw); err != nil {
		t.Fatal(err)
	}
}
