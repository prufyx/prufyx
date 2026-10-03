// SPDX-License-Identifier: AGPL-3.0-only

package knowledgegate

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/maintainer/evidencereattest"
	"github.com/prufyx/prufyx/cli/internal/maintainer/evidencerepin"
	"github.com/prufyx/prufyx/cli/internal/maintainer/knowledgesign"
	"github.com/prufyx/prufyx/cli/internal/maintainer/sourcecorpus"
	"github.com/secure-systems-lab/go-securesystemslib/cjson"
	"github.com/theupdateframework/go-tuf/v2/metadata"
)

const (
	synthPackPath   = "knowledge/rules.json"
	synthAttestPath = "knowledge/attestation.json"
	testPassphrase  = "gate test passphrase, tests only"
)

// synthLayout is a one-pack layout over a synthetic pack, so the
// reattestation path can be exercised end to end without the shipped
// pack's admission rules.
func synthLayout() Layout {
	return Layout{
		Packs: []PackSpec{{
			Name: evidencereattest.PackCommunity, Path: synthPackPath,
			Admit: func(t Tree) (PackStats, error) {
				raw, err := t.Read(synthPackPath, MaxFileBytes)
				if err != nil {
					return PackStats{}, err
				}
				return PackStats{Entries: 1, TargetBytes: len(raw), MaxTargetBytes: 1 << 20, RegistryFacts: 1, MaxRegistryFacts: 64}, nil
			},
			View: rawPackView, Entry: rawEntryView,
			AttestationPath: synthAttestPath,
			Attest:          func(t Tree) ([]byte, error) { return []byte("attested\n"), nil },
			CapabilityDigest: func() (string, error) {
				return "sha256:" + strings.Repeat("5", 64), nil
			},
		}},
		PausePath:        "factory/PAUSE",
		ReattestDir:      "knowledge/reattestation",
		TrustRootPath:    "knowledge/reattestation/trust-root.json",
		ApprovalDir:      "knowledge/approvals",
		ApprovalKeysPath: "knowledge/trust/web-approval-keys.json",
		AutoMergePaths:   []string{"knowledge/"},
	}
}

// rawPackView and rawEntryView read a synthetic pack as plain JSON.
func rawPackView(raw []byte) (map[string]json.RawMessage, []json.RawMessage, error) {
	var members map[string]json.RawMessage
	if err := json.Unmarshal(raw, &members); err != nil {
		return nil, nil, err
	}
	var entries []json.RawMessage
	if err := json.Unmarshal(members["entries"], &entries); err != nil {
		return nil, nil, err
	}
	delete(members, "entries")
	return members, entries, nil
}

func rawEntryView(raw []byte) (json.RawMessage, error) { return json.RawMessage(raw), nil }

type reattestFixture struct {
	base, head      Tree
	worklist        []byte
	rootDigest      string
	ruleID          string
	now             time.Time
	statement, envl []byte
}

func signingKey(t *testing.T) (ed25519.PublicKey, []byte, string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pem, err := knowledgesign.EncryptedKeyPEM(priv, []byte(testPassphrase))
	if err != nil {
		t.Fatal(err)
	}
	k, err := metadata.KeyFromPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	id, err := k.ID()
	if err != nil {
		t.Fatal(err)
	}
	return pub, pem, id
}

func trustRoot(t *testing.T, keys map[string]ed25519.PublicKey, ids map[string]string, now time.Time) []byte {
	t.Helper()
	var list []any
	for role, pub := range keys {
		list = append(list, map[string]any{"keyId": ids[role], "keyType": "ed25519", "scheme": "ed25519", "publicKey": hex.EncodeToString(pub), "role": role})
	}
	if list[0].(map[string]any)["keyId"].(string) > list[1].(map[string]any)["keyId"].(string) {
		list[0], list[1] = list[1], list[0]
	}
	raw, err := cjson.EncodeCanonical(map[string]any{
		"schemaVersion": evidencereattest.TrustRootSchema, "purpose": evidencereattest.Purpose, "threshold": 1, "keys": list,
		"expires": now.Add(365 * 24 * time.Hour).Truncate(time.Second).Format(time.RFC3339),
	})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// newReattestFixture prepares, signs and lays out an automated
// reattestation of one due reviewed rule: the base holds the pack and the
// trust root, the head the renewed pack, the appended statement chain
// entry and its retained worklist.
func newReattestFixture(t *testing.T) reattestFixture {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	at := now.Add(-time.Hour)
	f := reattestFixture{base: Tree{Root: t.TempDir()}, head: Tree{Root: t.TempDir()}, now: now}

	// One real community rule, cut to one source, made due for renewal.
	community := readPack(t, copyKnowledge(t), commRulesPath)
	e := deepCopy(community.entries[0]).(map[string]any)
	f.ruleID = ruleID(e)
	ev := evidenceOf(e)
	src := ev["sources"].([]any)[0].(map[string]any)
	ev["sources"] = []any{src}
	slot, err := evidencereattest.SlotDate(1, at)
	if err != nil {
		t.Fatal(err)
	}
	validUntil := at.Add(7 * 24 * time.Hour)
	if !validUntil.Before(slot) {
		validUntil = slot.Add(-time.Hour)
	}
	ev["reviewedAt"] = at.Add(-30 * 24 * time.Hour).Format(time.RFC3339)
	ev["validUntil"] = validUntil.Format(time.RFC3339)
	packRaw, err := json.Marshal(map[string]any{
		"schema": "test-pack/v1", "revision": "rev-1", "policyId": "policy-1", "policyDigest": "sha256:" + strings.Repeat("ab", 32),
		"entries": []any{e},
	})
	if err != nil {
		t.Fatal(err)
	}

	url := src["url"].(string) // https://github.com/<owner>/<repo>/blob/<commit>/<path>
	parts := strings.SplitN(strings.TrimPrefix(url, "https://github.com/"), "/", 5)
	owner, repo, commit, path := parts[0], parts[1], parts[3], parts[4]
	wl := evidencerepin.Worklist{
		Schema: evidencerepin.Schema, Authority: evidencerepin.Authority, GeneratedAt: at.Add(-time.Hour).Format(time.RFC3339),
		Scope: evidencerepin.WorklistScope{RulePacks: []string{synthPackPath}},
		Repos: []evidencerepin.RepoResolution{{Owner: owner, Repo: repo, Status: "RESOLVED", CurrentTag: "v0.9.4", CurrentCommit: commit, ResolvedAt: at.Add(-time.Hour).Format(time.RFC3339)}},
		Lines: []evidencerepin.LineResolution{{Owner: owner, Repo: repo, Prefix: "v", Line: "0.9", Status: "RESOLVED", Tag: "v0.9.4", Commit: commit, ResolvedAt: at.Add(-time.Hour).Format(time.RFC3339)}},
		Citations: []evidencerepin.ClassResult{{
			RulePack: synthPackPath, RuleID: f.ruleID, Project: e["project"].(string), SourceID: src["id"].(string),
			Owner: owner, Repo: repo, Path: path, OldCommit: commit, NewCommit: commit, Class: evidencerepin.ClassFileIdentical,
			Baseline: evidencerepin.BaselineReleaseLine, BaselineMode: evidencerepin.BaselineModeReleaseLine, BaselineLine: "0.9", PinnedTag: "v0.9.0", BaselineTag: "v0.9.4",
		}},
	}
	if f.worklist, err = json.Marshal(wl); err != nil {
		t.Fatal(err)
	}

	humanPub, _, humanID := signingKey(t)
	autoPub, autoPEM, autoID := signingKey(t)
	root := trustRoot(t, map[string]ed25519.PublicKey{evidencereattest.RoleHuman: humanPub, evidencereattest.RoleAutomation: autoPub}, map[string]string{evidencereattest.RoleHuman: humanID, evidencereattest.RoleAutomation: autoID}, now)
	f.rootDigest = sourcecorpus.SHA(root)

	capability, _ := synthLayout().Packs[0].CapabilityDigest()
	res, err := evidencereattest.Prepare(evidencereattest.PrepareOptions{
		WorklistRaw: f.worklist, PackName: evidencereattest.PackCommunity, PackPath: synthPackPath, PackRaw: packRaw,
		Chain: &evidencereattest.Chain{}, Mode: evidencereattest.ModeAutomated, AttestedAt: at, Now: now,
		NextRevision: "rev-1", EngineCapabilityDigest: capability,
	})
	if err != nil {
		t.Fatalf("prepare: %v", err)
	}
	if res.EligibleRuleCount != 1 {
		t.Fatalf("prepare renews %d rules", res.EligibleRuleCount)
	}
	f.statement = res.StatementCanonical
	if f.envl, err = evidencereattest.Sign(evidencereattest.SignOptions{
		Statement: f.statement, TrustRoot: root, EncryptedKey: autoPEM, Passphrase: []byte(testPassphrase),
		Role: evidencereattest.RoleAutomation, ExpectedTrustRootDigest: f.rootDigest, Now: now,
	}); err != nil {
		t.Fatalf("sign: %v", err)
	}

	l := synthLayout()
	for _, tr := range []Tree{f.base, f.head} {
		writeFile(t, filepath.Join(tr.Root, synthAttestPath), []byte("attested\n"))
		writeFile(t, filepath.Join(tr.Root, l.TrustRootPath), append(append([]byte(nil), root...), '\n'))
		if err := os.MkdirAll(filepath.Join(tr.Root, l.ReattestDir, "community", "chain"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	writeFile(t, filepath.Join(f.base.Root, synthPackPath), packRaw)
	writeFile(t, filepath.Join(f.head.Root, synthPackPath), res.NextPack)
	dir := filepath.Join(f.head.Root, l.ReattestDir, "community")
	writeFile(t, filepath.Join(dir, "chain", "0001.statement.json"), append(append([]byte(nil), f.statement...), '\n'))
	writeFile(t, filepath.Join(dir, "chain", "0001.statement.sig.json"), append(append([]byte(nil), f.envl...), '\n'))
	writeFile(t, filepath.Join(dir, "worklists", "0001.worklist.json"), f.worklist)
	return f
}

func (f reattestFixture) opts() Options {
	return Options{Layout: synthLayout(), Base: f.base, Head: f.head, Now: f.now, TrustRootDigest: f.rootDigest, RerunWorklist: f.worklist, Author: DefaultBotLogin}
}

func TestGateReattestationStatement(t *testing.T) {
	f := newReattestFixture(t)
	r := runGate(t, f.opts())
	requirePass(t, r)
	c := change(t, r, f.ruleID)
	if c.Class != ClassLoosening || c.Kinds[0] != KindRenew || c.Proof != ProofReattestation {
		t.Fatalf("change %+v", c)
	}
	if ch, ok := check(r, "reattestation/community"); !ok || !strings.Contains(ch.Detail, "role automation renews 1 rules") {
		t.Fatalf("reattestation check %+v", ch)
	}
	if !r.AutoMerge.Eligible {
		t.Fatalf("not eligible: %v", r.AutoMerge.Reasons)
	}
}

func TestGateReattestationRejects(t *testing.T) {
	cases := map[string]struct {
		mutate func(t *testing.T, f *reattestFixture, o *Options)
		want   string
	}{
		"no independent worklist": {func(t *testing.T, f *reattestFixture, o *Options) { o.RerunWorklist = nil }, "own evidence repin run is required"},
		"independent worklist disagrees": {func(t *testing.T, f *reattestFixture, o *Options) {
			var wl evidencerepin.Worklist
			if err := json.Unmarshal(f.worklist, &wl); err != nil {
				t.Fatal(err)
			}
			wl.Citations[0].Class = evidencerepin.ClassSpanIdentical
			o.RerunWorklist, _ = json.Marshal(wl)
		}, "V9"},
		"no trust root digest": {func(t *testing.T, f *reattestFixture, o *Options) { o.TrustRootDigest = "" }, "no reattestation trust root digest"},
		"wrong trust root digest": {func(t *testing.T, f *reattestFixture, o *Options) {
			o.TrustRootDigest = "sha256:" + strings.Repeat("0", 64)
		}, "reattestation/community"},
		"trust root only in the head": {func(t *testing.T, f *reattestFixture, o *Options) {
			if err := os.Remove(filepath.Join(f.base.Root, synthLayout().TrustRootPath)); err != nil {
				t.Fatal(err)
			}
		}, "reattestation trust root"},
		"next pack edited after preparing": {func(t *testing.T, f *reattestFixture, o *Options) {
			p := readPack(t, f.head, synthPackPath)
			ruleOf(p.entries[0])["nextAction"] = "Changed."
			p.write(t, f.head, synthPackPath)
		}, "V1"},
		"missing retained worklist": {func(t *testing.T, f *reattestFixture, o *Options) {
			if err := os.Remove(filepath.Join(f.head.Root, synthLayout().ReattestDir, "community", "worklists", "0001.worklist.json")); err != nil {
				t.Fatal(err)
			}
		}, "retained worklist"},
		"unsigned statement": {func(t *testing.T, f *reattestFixture, o *Options) {
			if err := os.Remove(filepath.Join(f.head.Root, synthLayout().ReattestDir, "community", "chain", "0001.statement.sig.json")); err != nil {
				t.Fatal(err)
			}
		}, "unpaired files"},
		"pack renewed with no statement": {func(t *testing.T, f *reattestFixture, o *Options) {
			for _, n := range []string{"0001.statement.json", "0001.statement.sig.json"} {
				if err := os.Remove(filepath.Join(f.head.Root, synthLayout().ReattestDir, "community", "chain", n)); err != nil {
					t.Fatal(err)
				}
			}
		}, "no reattestation statement"},
		"two statements appended": {func(t *testing.T, f *reattestFixture, o *Options) {
			dir := filepath.Join(f.head.Root, synthLayout().ReattestDir, "community", "chain")
			writeFile(t, filepath.Join(dir, "0002.statement.json"), append(append([]byte(nil), f.statement...), '\n'))
			writeFile(t, filepath.Join(dir, "0002.statement.sig.json"), append(append([]byte(nil), f.envl...), '\n'))
		}, "appends 2"},
		"kill switch": {func(t *testing.T, f *reattestFixture, o *Options) {
			writeFile(t, filepath.Join(f.base.Root, "factory", "PAUSE"), nil)
		}, "kill switch"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			f := newReattestFixture(t)
			o := f.opts()
			tc.mutate(t, &f, &o)
			r := runGate(t, o)
			requireFail(t, r, tc.want)
			if c := change(t, r, f.ruleID); c.OK {
				t.Fatal("the renewal was admitted")
			}
		})
	}
}

// Worklists and review records change only with the statement appended in
// the same change: its own worklist, and records of rules it renews.
func TestGateReattestationRecordFiles(t *testing.T) {
	dir := func(f reattestFixture) string {
		return filepath.Join(f.head.Root, synthLayout().ReattestDir, "community")
	}
	for name, tc := range map[string]struct {
		edit func(t *testing.T, f reattestFixture)
		ok   bool
	}{
		"statement and its worklist": {func(t *testing.T, f reattestFixture) {}, true},
		"worklist of another stem": {func(t *testing.T, f reattestFixture) {
			writeFile(t, filepath.Join(dir(f), "worklists", "0002.worklist.json"), f.worklist)
		}, false},
		"worklist rewritten": {func(t *testing.T, f reattestFixture) {
			writeFile(t, filepath.Join(f.base.Root, synthLayout().ReattestDir, "community", "worklists", "0000.worklist.json"), f.worklist)
			writeFile(t, filepath.Join(dir(f), "worklists", "0000.worklist.json"), append(append([]byte(nil), f.worklist...), ' '))
		}, false},
		"review record of another rule": {func(t *testing.T, f reattestFixture) {
			writeFile(t, filepath.Join(dir(f), "review-records", "other.rule.json"), []byte("{}\n"))
		}, false},
		"unexpected directory": {func(t *testing.T, f reattestFixture) {
			writeFile(t, filepath.Join(dir(f), "notes", "x.json"), []byte("{}\n"))
		}, false},
	} {
		t.Run(name, func(t *testing.T) {
			f := newReattestFixture(t)
			tc.edit(t, f)
			r := runGate(t, f.opts())
			c, _ := check(r, "knowledge-records")
			if c.OK != tc.ok || (tc.ok && !r.Passed()) {
				t.Fatalf("knowledge-records ok=%v pass=%v: %s %v", c.OK, r.Passed(), c.Detail, failedChecks(r))
			}
		})
	}
}
