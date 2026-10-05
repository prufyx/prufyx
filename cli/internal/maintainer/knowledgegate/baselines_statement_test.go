// SPDX-License-Identifier: AGPL-3.0-only

package knowledgegate

import (
	"crypto/ed25519"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/maintainer/evidencereattest"
	"github.com/prufyx/prufyx/cli/internal/maintainer/evidencerepin"
	"github.com/prufyx/prufyx/cli/internal/maintainer/repinbaselines"
	"github.com/prufyx/prufyx/cli/internal/maintainer/sourcecorpus"
)

const synthBaselinesPath = "knowledge/repin-baselines.json"

func baselineLayout() Layout {
	l := synthLayout()
	l.BaselinesPath = synthBaselinesPath
	return l
}

// ownerStatementFixture is newReattestFixture for a HUMAN statement that
// renews a rule on an owner-chosen baseline of an ambiguous repository.
type ownerStatementFixture struct {
	reattestFixture
	entry    repinbaselines.Entry
	baseline []byte
}

func newOwnerStatementFixture(t *testing.T) ownerStatementFixture {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	at := now.Add(-time.Hour)
	f := ownerStatementFixture{reattestFixture: reattestFixture{base: Tree{Root: t.TempDir()}, head: Tree{Root: t.TempDir()}, now: now}}

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
	parts := strings.SplitN(strings.TrimPrefix(src["url"].(string), "https://github.com/"), "/", 5)
	owner, repo, commit, path := parts[0], parts[1], parts[3], parts[4]

	f.entry = repinbaselines.Entry{
		Approval: "pr-15", Commit: strings.Repeat("e", 40), DecidedAt: "2026-10-05T10:00:00Z",
		Reason: "the project publishes this tag as its stable line", Repository: owner + "/" + repo, Tag: "v9.9.9",
	}
	if f.baseline, err = (repinbaselines.File{Schema: repinbaselines.Schema, Entries: []repinbaselines.Entry{f.entry}}).Marshal(); err != nil {
		t.Fatal(err)
	}
	resolvedAt := at.Add(-time.Hour).Format(time.RFC3339)
	wl := evidencerepin.Worklist{
		Schema: evidencerepin.Schema, Authority: evidencerepin.Authority, GeneratedAt: at.Add(-time.Hour).Format(time.RFC3339),
		Scope: evidencerepin.WorklistScope{RulePacks: []string{synthPackPath}},
		Repos: []evidencerepin.RepoResolution{{
			Owner: owner, Repo: repo, Status: "PENDING_AMBIGUOUS_LATEST", ResolvedAt: resolvedAt,
			OwnerBaseline: &evidencerepin.OwnerBaseline{Tag: f.entry.Tag, Commit: f.entry.Commit, EntryDigest: f.entry.Digest()},
		}},
		Citations: []evidencerepin.ClassResult{{
			RulePack: synthPackPath, RuleID: f.ruleID, Project: e["project"].(string), SourceID: src["id"].(string),
			Owner: owner, Repo: repo, Path: path, OldCommit: commit, NewCommit: f.entry.Commit, Class: evidencerepin.ClassFileIdentical,
			Baseline: evidencerepin.BaselineOwnerChoice, BaselineMode: evidencerepin.BaselineModeReleaseLine, BaselineTag: f.entry.Tag, BaselineEntryDigest: f.entry.Digest(),
		}},
	}
	if f.worklist, err = json.Marshal(wl); err != nil {
		t.Fatal(err)
	}

	humanPub, humanPEM, humanID := signingKey(t)
	autoPub, _, autoID := signingKey(t)
	root := trustRoot(t, map[string]ed25519.PublicKey{evidencereattest.RoleHuman: humanPub, evidencereattest.RoleAutomation: autoPub}, map[string]string{evidencereattest.RoleHuman: humanID, evidencereattest.RoleAutomation: autoID}, now)
	f.rootDigest = sourcecorpus.SHA(root)

	capability, _ := synthLayout().Packs[0].CapabilityDigest()
	prep := evidencereattest.PrepareOptions{
		WorklistRaw: f.worklist, PackName: evidencereattest.PackCommunity, PackPath: synthPackPath, PackRaw: packRaw,
		Chain: &evidencereattest.Chain{}, Mode: evidencereattest.ModeHuman, Wave: 1, AttestedAt: at, Now: now,
		NextRevision: "rev-1", EngineCapabilityDigest: capability, BaselinesRaw: f.baseline,
	}
	records := map[string][]byte{}
	var res evidencereattest.PrepareResult
	for attempt := 0; attempt < 8; attempt++ {
		prep.ReviewRecords = records
		if res, err = evidencereattest.Prepare(prep); err != nil {
			t.Fatalf("prepare: %v", err)
		}
		missing := false
		for _, s := range res.Statement.SampledForFullReview {
			if s.ReviewRecordDigest != "" {
				continue
			}
			missing = true
			raw, err := evidencereattest.NewSampleReview(evidencereattest.SampleReviewOptions{
				StatementRaw: res.StatementCanonical, PriorPackRaw: packRaw, WorklistRaw: f.worklist,
				PackName: prep.PackName, PackPath: prep.PackPath, EngineCapabilityDigest: capability,
				RuleID: s.RuleID, Reviewer: "airstand", DecidedAt: at, Now: at,
			})
			if err != nil {
				t.Fatalf("sample review: %v", err)
			}
			records[s.RuleID] = raw
		}
		if !missing {
			break
		}
	}
	if res.EligibleRuleCount != 1 {
		t.Fatalf("prepare renews %d rules: %+v", res.EligibleRuleCount, res.Statement.NotExtended)
	}
	f.statement = res.StatementCanonical
	if f.envl, err = evidencereattest.Sign(evidencereattest.SignOptions{
		Statement: f.statement, TrustRoot: root, EncryptedKey: humanPEM, Passphrase: []byte(testPassphrase),
		Role: evidencereattest.RoleHuman, ExpectedTrustRootDigest: f.rootDigest, Now: now,
	}); err != nil {
		t.Fatalf("sign: %v", err)
	}

	l := baselineLayout()
	for _, tr := range []Tree{f.base, f.head} {
		writeFile(t, filepath.Join(tr.Root, synthAttestPath), []byte("attested\n"))
		writeFile(t, filepath.Join(tr.Root, l.TrustRootPath), append(append([]byte(nil), root...), '\n'))
		if err := os.MkdirAll(filepath.Join(tr.Root, l.ReattestDir, "community", "chain"), 0o755); err != nil {
			t.Fatal(err)
		}
		writeFile(t, filepath.Join(tr.Root, synthBaselinesPath), f.baseline)
	}
	writeFile(t, filepath.Join(f.base.Root, synthPackPath), packRaw)
	writeFile(t, filepath.Join(f.head.Root, synthPackPath), res.NextPack)
	dir := filepath.Join(f.head.Root, l.ReattestDir, "community")
	writeFile(t, filepath.Join(dir, "chain", "0001.statement.json"), append(append([]byte(nil), f.statement...), '\n'))
	writeFile(t, filepath.Join(dir, "chain", "0001.statement.sig.json"), append(append([]byte(nil), f.envl...), '\n'))
	writeFile(t, filepath.Join(dir, "worklists", "0001.worklist.json"), f.worklist)
	for id, raw := range records {
		writeFile(t, filepath.Join(dir, "review-records", id+".json"), raw)
	}
	return f
}

func (f ownerStatementFixture) opts() Options {
	o := f.reattestFixture.opts()
	o.Layout = baselineLayout()
	o.Author = "airstand"
	return o
}

// A human statement that renews on an owner-chosen baseline is admitted
// when the baseline entry is already in the base the gate trusts.
func TestGateAdmitsAHumanStatementOnAnOwnerBaseline(t *testing.T) {
	f := newOwnerStatementFixture(t)
	r := runGate(t, f.opts())
	requirePass(t, r)
	if c := change(t, r, f.ruleID); c.Proof != ProofReattestation {
		t.Fatalf("%+v", c)
	}
	if _, ok := check(r, "repin-baselines"); ok {
		t.Fatal("an unchanged baseline file adds no check")
	}
}

func TestGateRefusesAStatementOnABaselineTheBaseDoesNotHold(t *testing.T) {
	cases := map[string]func(t *testing.T, f ownerStatementFixture, o *Options){
		"entry only in the head (added with the statement)": func(t *testing.T, f ownerStatementFixture, o *Options) {
			if err := os.Remove(filepath.Join(f.base.Root, synthBaselinesPath)); err != nil {
				t.Fatal(err)
			}
		},
		"base holds another entry": func(t *testing.T, f ownerStatementFixture, o *Options) {
			other := f.entry
			other.Reason = "an earlier decision"
			raw, _ := repinbaselines.File{Schema: repinbaselines.Schema, Entries: []repinbaselines.Entry{other}}.Marshal()
			writeFile(t, filepath.Join(f.base.Root, synthBaselinesPath), raw)
		},
		"independent run did not read the file": func(t *testing.T, f ownerStatementFixture, o *Options) {
			var wl evidencerepin.Worklist
			if err := json.Unmarshal(f.worklist, &wl); err != nil {
				t.Fatal(err)
			}
			wl.Citations[0].Baseline, wl.Citations[0].BaselineEntryDigest, wl.Citations[0].Class = "", "", evidencerepin.ClassPending
			o.RerunWorklist, _ = json.Marshal(wl)
		},
	}
	want := map[string]string{
		"entry only in the head (added with the statement)": "V12",
		"base holds another entry":                          "V12",
		"independent run did not read the file":             "V9",
	}
	for name, mutate := range cases {
		f := newOwnerStatementFixture(t)
		o := f.opts()
		mutate(t, f, &o)
		r := runGate(t, o)
		requireFail(t, r, want[name])
		if c := change(t, r, f.ruleID); c.OK {
			t.Fatalf("%s: the renewal was admitted", name)
		}
	}
}
