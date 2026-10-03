// SPDX-License-Identifier: AGPL-3.0-only

package knowledgegate

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/extract"
)

// Regression tests for attacks on the gate found in review. Each builds a
// change an automation account could propose and requires the gate to stop
// it (fail, or refuse the input) and never report it eligible for
// automatic merging.

func cloneTree(t *testing.T, src Tree) Tree {
	t.Helper()
	dst := t.TempDir()
	if err := os.CopyFS(dst, os.DirFS(src.Root)); err != nil {
		t.Fatal(err)
	}
	return Tree{Root: dst}
}

// tryGate runs the gate and reports whether it stopped the change: an
// error (refused input) or a failing result.
func tryGate(t *testing.T, opts Options) (*Report, bool) {
	t.Helper()
	if opts.Layout.Packs == nil {
		opts.Layout = DefaultLayout()
	}
	if opts.Now.IsZero() {
		opts.Now = gateNow
	}
	pinBaseKeys(&opts)
	fromBot(&opts)
	r, err := Verify(context.Background(), opts)
	if err != nil {
		t.Logf("gate refused the input: %v", err)
		return nil, true
	}
	if r.AutoMerge.Eligible && !r.Passed() {
		t.Fatal("eligible without passing")
	}
	return r, !r.Passed()
}

// writePackRaw writes a pack whose entry id is replaced by custom bytes.
func writePackRaw(t *testing.T, tr Tree, rel string, p *packDoc, id string, custom []byte) {
	t.Helper()
	var parts [][]byte
	for _, e := range p.entries {
		if ruleID(e) == id {
			parts = append(parts, custom)
			continue
		}
		raw, err := json.Marshal(e)
		if err != nil {
			t.Fatal(err)
		}
		parts = append(parts, raw)
	}
	p.fields["entries"] = json.RawMessage("[" + string(bytes.Join(parts, []byte(","))) + "]")
	raw, err := json.Marshal(p.fields)
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(tr.Root, filepath.FromSlash(rel)), append(raw, '\n'))
}

// An entry carrying both "rule" and "Rule": struct decoding (the engine)
// takes the last, a map keeps both. The first change adds it as an
// apparently withdrawn rule; the second only swaps the member order so the
// engine reads an active rule while the canonical bytes stay the same.
func TestRegressionCaseVariantRuleSwap(t *testing.T) {
	base, head := trees(t)
	p := readPack(t, head, cncfRulesPath)
	ids := p.activeReviewed()
	src := p.find(t, ids[0])
	newID := ids[0] + "-zz"
	active := deepCopy(ruleOf(src)).(map[string]any)
	active["id"] = newID
	ev := active["evidence"].(map[string]any)
	ev["reviewedAt"] = gateNow.Add(-2 * time.Hour).Format(time.RFC3339)
	ev["validUntil"] = gateNow.Add(60 * 24 * time.Hour).Format(time.RFC3339)
	withdrawn := deepCopy(active).(map[string]any)
	withdrawn["evidence"].(map[string]any)["state"] = "withdrawn"
	entry := deepCopy(src).(map[string]any)
	entry["rule"] = map[string]any{"id": newID}
	p.entries = append(p.entries, entry)
	p.sortByID()
	mk := func(firstKey string, first any, secondKey string, second any) []byte {
		rest, _ := json.Marshal(map[string]any{"description": entry["description"], "project": entry["project"], "requiredFacts": entry["requiredFacts"]})
		a, _ := json.Marshal(first)
		b, _ := json.Marshal(second)
		return []byte(strings.TrimSuffix(string(rest), "}") + `,"` + firstKey + `":` + string(a) + `,"` + secondKey + `":` + string(b) + "}")
	}
	writePackRaw(t, head, cncfRulesPath, p, newID, mk("rule", active, "Rule", withdrawn))
	if _, blocked := tryGate(t, Options{Base: base, Head: head, Author: DefaultBotLogin}); !blocked {
		t.Fatal("an entry with case-variant members was admitted")
	}
	// The swap on top of such a pack (as if it had merged).
	base2, head2 := cloneTree(t, head), cloneTree(t, head)
	writePackRaw(t, head2, cncfRulesPath, p, newID, mk("Rule", withdrawn, "rule", active))
	if _, blocked := tryGate(t, Options{Base: base2, Head: head2, Author: DefaultBotLogin}); !blocked {
		t.Fatal("swapping case-variant members was not stopped")
	}
	// A repeated member deep inside an entry is refused as well.
	base3, head3 := trees(t)
	raw, err := os.ReadFile(filepath.Join(head3.Root, cncfRulesPath))
	if err != nil {
		t.Fatal(err)
	}
	dup := bytes.Replace(raw, []byte(`"state": "active"`), []byte(`"state": "withdrawn", "state": "active"`), 1)
	if bytes.Equal(dup, raw) {
		t.Fatal("no active state in the shipped pack")
	}
	writeFile(t, filepath.Join(head3.Root, cncfRulesPath), dup)
	if _, blocked := tryGate(t, Options{Base: base3, Head: head3, Author: DefaultBotLogin}); !blocked {
		t.Fatal("a repeated member was admitted")
	}
}

// The automation account pins its own owner-approval key next to one
// withdrawal, then uses the key to approve a new active rule.
func TestRegressionApprovalKeyInjection(t *testing.T) {
	base, head := trees(t)
	ids := readPack(t, base, cncfRulesPath).activeReviewed()
	editPack(t, head, cncfRulesPath, func(p *packDoc) { evidenceOf(p.find(t, ids[1]))["state"] = "withdrawn" })
	key := newApprovalKey(t)
	key.pin(t, head, "attacker")
	r1, blocked := tryGate(t, Options{Base: base, Head: head, Author: DefaultBotLogin})
	if !blocked {
		t.Fatal("a change adding an owner-approval key passed")
	}
	if r1 != nil {
		requireFail(t, r1, "trust-material")
		if r1.AutoMerge.Eligible {
			t.Fatal("a change adding an owner-approval key is eligible")
		}
	}
	// Even if it had merged, its key is pinned by no digest: the next
	// change cannot use it.
	base2, head2 := cloneTree(t, head), cloneTree(t, head)
	newID := ids[0] + "-forged"
	editPack(t, head2, cncfRulesPath, func(p *packDoc) {
		added := deepCopy(p.find(t, ids[0])).(map[string]any)
		ruleOf(added)["id"] = newID
		evidenceOf(added)["reviewedAt"] = gateNow.Add(-2 * time.Hour).Format(time.RFC3339)
		evidenceOf(added)["validUntil"] = gateNow.Add(60 * 24 * time.Hour).Format(time.RFC3339)
		p.entries = append(p.entries, added)
		p.sortByID()
	})
	cls, err := Classify(DefaultLayout(), base2, head2)
	if err != nil {
		t.Fatal(err)
	}
	digest := CandidateDigest(cls.head["cncf"].Entries[newID].Canonical)
	writeFile(t, approvalPath(head2, newID), key.sign(t, ApprovalRecord{BaseDigest: ApprovalBaseAbsent, CandidateDigest: digest, CandidateID: "x", DecidedAt: gateNow.Add(-time.Minute).Format(time.RFC3339), Decision: "approve", Identity: "attacker", Pack: "cncf", RuleID: newID}))
	if _, blocked := tryGate(t, Options{Base: base2, Head: head2, Author: DefaultBotLogin, ApprovalKeysDigest: "none"}); !blocked {
		t.Fatal("an approval signed with an unpinned key admitted a new rule")
	}
	if _, blocked := tryGate(t, Options{Base: base2, Head: head2, Author: DefaultBotLogin, ApprovalKeysDigest: "sha256:" + strings.Repeat("1", 64)}); !blocked {
		t.Fatal("an approval signed with a key file that does not match the pinned digest admitted a new rule")
	}
}

// Trust material: no change by the automation account, a person's change
// only when it matches the pinned digest, and never eligible.
func TestTrustMaterialChanges(t *testing.T) {
	key := newApprovalKey(t)
	for name, tc := range map[string]struct {
		path   string
		author string
		sender string
		pin    func(raw []byte) string
		ok     bool
	}{
		"bot adds keys":                {approvalKeys, DefaultBotLogin, "", pinnedDigest, false},
		"person, sender bot":           {approvalKeys, "airstand", DefaultBotLogin, pinnedDigest, false},
		"person, unknown author":       {approvalKeys, "", "airstand", pinnedDigest, false},
		"person, digest mismatch":      {approvalKeys, "airstand", "airstand", func([]byte) string { return "sha256:" + strings.Repeat("2", 64) }, false},
		"person, no digest":            {approvalKeys, "airstand", "airstand", func([]byte) string { return "none" }, false},
		"person, pinned keys":          {approvalKeys, "airstand", "airstand", pinnedDigest, true},
		"other trust dir file":         {"cli/knowledge/trust/other.json", "airstand", "airstand", pinnedDigest, false},
		"trust root by bot":            {trustRootPath, DefaultBotLogin, "", pinnedDigest, false},
		"trust root by person, pinned": {trustRootPath, "airstand", "airstand", pinnedDigest, true},
		"trust root name elsewhere":    {"cli/internal/x/trust-root-v3.json", "airstand", "airstand", pinnedDigest, false},
		"approval keys name elsewhere": {"cli/knowledge/approvals/web-approval-keys.json", DefaultBotLogin, "", pinnedDigest, false},
	} {
		t.Run(name, func(t *testing.T) {
			base, head := trees(t)
			key.pin(t, head, "airstand")
			raw, err := os.ReadFile(filepath.Join(head.Root, filepath.FromSlash(approvalKeys)))
			if err != nil {
				t.Fatal(err)
			}
			if tc.path != approvalKeys {
				if err := os.RemoveAll(filepath.Join(head.Root, "cli", "knowledge", "trust")); err != nil {
					t.Fatal(err)
				}
				writeFile(t, filepath.Join(head.Root, filepath.FromSlash(tc.path)), raw)
			}
			digest := tc.pin(raw)
			opts := Options{Base: base, Head: head, Author: tc.author, Sender: tc.sender}
			if tc.path == trustRootPath {
				opts.TrustRootDigest, opts.ApprovalKeysDigest = digest, "none"
			} else {
				opts.ApprovalKeysDigest = digest
			}
			if tc.author == DefaultBotLogin && tc.sender == "" {
				fromBot(&opts)
			}
			r := runGate(t, opts)
			c, _ := check(r, "trust-material")
			if c.OK != tc.ok || r.Passed() != tc.ok {
				t.Fatalf("trust-material ok=%v pass=%v: %s", c.OK, r.Passed(), c.Detail)
			}
			if r.AutoMerge.Eligible {
				t.Fatal("a trust change is eligible for automatic merging")
			}
		})
	}
	if !DefaultLayout().trustPath(approvalKeys) || DefaultLayout().autoMergePath(approvalKeys) || DefaultLayout().autoMergePath(trustRootPath) || DefaultLayout().autoMergePath("cli/knowledge/trust/x.json") {
		t.Fatal("trust material is allow-listed for automatic merging")
	}
}

// An approval binds the base state: after the approved rule is withdrawn,
// the same approval cannot re-activate it.
func TestRegressionApprovalReplayAfterWithdrawal(t *testing.T) {
	base, head, id, digest := approvalTrees(t)
	key := newApprovalKey(t)
	key.pinBoth(t, base, head, "airstand")
	writeFile(t, approvalPath(head, id), key.sign(t, ApprovalRecord{BaseDigest: ApprovalBaseAbsent, CandidateDigest: digest, CandidateID: "c", DecidedAt: gateNow.Add(-time.Hour).Format(time.RFC3339), Decision: "approve", Identity: "airstand", Pack: "cncf", RuleID: id}))
	requirePass(t, runGate(t, Options{Base: base, Head: head, Author: DefaultBotLogin}))
	merged := cloneTree(t, head)
	withdrawn := cloneTree(t, merged)
	editPack(t, withdrawn, cncfRulesPath, func(p *packDoc) { evidenceOf(p.find(t, id))["state"] = "withdrawn" })
	requirePass(t, runGate(t, Options{Base: merged, Head: withdrawn, Author: DefaultBotLogin}))
	base3, head3 := cloneTree(t, withdrawn), cloneTree(t, withdrawn)
	editPack(t, head3, cncfRulesPath, func(p *packDoc) { evidenceOf(p.find(t, id))["state"] = "active" })
	r, blocked := tryGate(t, Options{Base: base3, Head: head3, Author: DefaultBotLogin, Now: gateNow.Add(10 * 24 * time.Hour)})
	if !blocked || r.AutoMerge.Eligible {
		t.Fatal("a withdrawn rule was re-activated with its old approval")
	}
	requireFail(t, r, "base digest does not match")
}

// Top-level pack members other than entries are compared too; a change to
// any of them fails.
func TestRegressionPackMemberChange(t *testing.T) {
	for name, edit := range map[string]func(p *packDoc){
		"revision":   func(p *packDoc) { p.fields["revision"] = json.RawMessage(`"1"`) },
		"schema":     func(p *packDoc) { p.fields["schema"] = json.RawMessage(`"prufyx.io/cncf-source-rule-pack/v1alpha1"`) },
		"policy":     func(p *packDoc) { p.fields["policyId"] = json.RawMessage(`"other"`) },
		"new member": func(p *packDoc) { p.fields["lineAttestations"] = json.RawMessage(`[]`) },
	} {
		t.Run(name, func(t *testing.T) {
			base, head := trees(t)
			ids := readPack(t, base, cncfRulesPath).activeReviewed()
			editPack(t, head, cncfRulesPath, func(p *packDoc) { evidenceOf(p.find(t, ids[1]))["state"] = "withdrawn" })
			// The member edit itself is written as proposed; the derived
			// files may no longer regenerate from it.
			p := readPack(t, head, cncfRulesPath)
			edit(p)
			p.write(t, head, cncfRulesPath)
			if cls, err := Classify(DefaultLayout(), base, head); err == nil {
				found := false
				for _, c := range cls.Changes {
					found = found || (c.Member != "" && c.Class == ClassLoosening)
				}
				if !found {
					t.Fatalf("no pack-member change classified: %+v", cls.Changes)
				}
			}
			r, blocked := tryGate(t, Options{Base: base, Head: head, Author: DefaultBotLogin})
			if !blocked {
				t.Fatal("a pack member change passed")
			}
			if r != nil && r.AutoMerge.Eligible {
				t.Fatal("a pack member change is eligible")
			}
		})
	}
	// The classification names the member.
	base, head := trees(t)
	editPack(t, head, cncfRulesPath, func(p *packDoc) { p.fields["revision"] = json.RawMessage(`"1"`) })
	cls, err := Classify(DefaultLayout(), base, head)
	if err != nil {
		t.Fatal(err)
	}
	if len(cls.Changes) != 1 || cls.Changes[0].Member != "revision" || cls.Changes[0].Class != ClassLoosening {
		t.Fatalf("changes %+v", cls.Changes)
	}
	r := runGate(t, Options{Base: base, Head: head})
	requireFail(t, r, "member revision changed")
	// Re-spelling a member with another letter case reads the same to the
	// engine, so it is no change at all (and no change hides behind one).
	base2, head2 := trees(t)
	raw, err := os.ReadFile(filepath.Join(head2.Root, cncfRulesPath))
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(head2.Root, cncfRulesPath), bytes.Replace(raw, []byte(`"revision"`), []byte(`"Revision"`), 1))
	cls, err = Classify(DefaultLayout(), base2, head2)
	if err != nil || len(cls.Changes) != 0 {
		t.Fatalf("respelt member: %v %+v", err, cls.Changes)
	}
}

// A rule id carrying line breaks never reaches the job log as a line of
// its own (a workflow command).
func TestRegressionWorkflowCommandInRuleID(t *testing.T) {
	base, head := trees(t)
	ids := readPack(t, base, cncfRulesPath).activeReviewed()
	evil := "zz\n::error title=x::injected\r\n::set-output name=auto_merge_eligible::true%0A::add-mask::x"
	p := readPack(t, head, cncfRulesPath)
	added := deepCopy(p.find(t, ids[0])).(map[string]any)
	ruleOf(added)["id"] = evil
	evidenceOf(added)["state"] = "withdrawn"
	ruleOf(added)["nextAction"] = "x\n::warning::y"
	p.entries = append(p.entries, added)
	p.write(t, head, cncfRulesPath)
	var out, errOut bytes.Buffer
	code, err := cmdClassify([]string{"--base", base.Root, "--head", head.Root}, DefaultLayout(), &out)
	t.Logf("classify exit=%d err=%v", code, err)
	code = mainWith([]string{"verify", "--base", base.Root, "--head", head.Root, "--now", gateNow.Format(time.RFC3339)}, func(string) string { return "" }, &out, &errOut, DefaultLayout())
	t.Logf("verify exit=%d", code)
	for _, line := range strings.Split(out.String()+errOut.String(), "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "::") || strings.Contains(line, "\r") {
			t.Fatalf("a proposed string formed a log line of its own: %q", line)
		}
	}
	if !strings.Contains(out.String(), "zz%0A") {
		t.Fatalf("the rule id is not printed escaped:\n%s", out.String())
	}
	if got := logSafe(strings.Repeat("a", 3*maxLogField)); len(got) > maxLogField+40 {
		t.Fatalf("logSafe does not cap length: %d", len(got))
	}
	if got := logSafe("50% ::x y"); strings.Contains(got, "::") || strings.Contains(got, " ") || strings.Contains(got, "% ") {
		t.Fatalf("logSafe(%q) = %q", "50% ::x y", got)
	}
}

// Eligibility needs the automation account to have triggered the run and
// to have authored and committed every commit, with verified signatures,
// up to exactly the head the gate checked.
func TestEligibilityNeedsBotProvenance(t *testing.T) {
	base, head := trees(t)
	ids := readPack(t, base, cncfRulesPath).activeReviewed()
	editPack(t, head, cncfRulesPath, func(p *packDoc) { evidenceOf(p.find(t, ids[1]))["state"] = "withdrawn" })
	ok := runGate(t, Options{Base: base, Head: head, Author: DefaultBotLogin})
	if !ok.AutoMerge.Eligible || ok.HeadSHA != testHeadSHA {
		t.Fatalf("bot change not eligible: %v (head %s)", ok.AutoMerge.Reasons, ok.HeadSHA)
	}
	person := &loginField{"someone"}
	for name, tc := range map[string]struct {
		edit func(o *Options)
		want string
	}{
		"sender is a person": {func(o *Options) { o.Sender = "someone" }, "triggered by"},
		"no commit list":     {func(o *Options) { o.Commits = nil }, "commit list was not supplied"},
		"no head sha":        {func(o *Options) { o.HeadSHA = "" }, "head commit was not supplied"},
		"other head":         {func(o *Options) { o.HeadSHA = strings.Repeat("f", 40) }, "does not end at the head"},
		"person authored":    {func(o *Options) { o.Commits.Commits[0].Author = person }, "not authored by the automation account"},
		"no linked author":   {func(o *Options) { o.Commits.Commits[0].Author = nil }, "not authored by the automation account"},
		"person committed":   {func(o *Options) { o.Commits.Commits[0].Committer = person }, "not committed by the automation account"},
		"unverified":         {func(o *Options) { o.Commits.Commits[0].Commit.Verification.Verified = false }, "no verified signature"},
		"incomplete list":    {func(o *Options) { o.Commits.TotalCommits = 2 }, "incomplete"},
		"behind the base":    {func(o *Options) { o.Commits.BehindBy, o.Commits.Status = 1, "diverged" }, "not strictly ahead"},
		"a second person commit": {func(o *Options) {
			c := o.Commits.Commits[0]
			c.SHA = strings.Repeat("e", 40)
			c.Author = person
			o.Commits.Commits = append([]CommitRecord{c}, o.Commits.Commits...)
			o.Commits.TotalCommits = 2
		}, "not authored by the automation account"},
	} {
		t.Run(name, func(t *testing.T) {
			o := Options{Base: base, Head: head, Author: DefaultBotLogin, Sender: DefaultBotLogin, HeadSHA: testHeadSHA, Commits: botCommits()}
			tc.edit(&o)
			if o.Sender == "" {
				o.Sender = "-"
			}
			r := runGate(t, o)
			if !r.Passed() || r.AutoMerge.Eligible || !strings.Contains(strings.Join(r.AutoMerge.Reasons, "; "), tc.want) {
				t.Fatalf("pass=%v eligible=%v reasons=%v", r.Passed(), r.AutoMerge.Eligible, r.AutoMerge.Reasons)
			}
		})
	}
	raw, err := json.Marshal(botCommits())
	if err != nil {
		t.Fatal(err)
	}
	if l, err := ParseCommitList(raw); err != nil || len(l.Commits) != 1 || l.Commits[0].Author.Login != DefaultBotLogin {
		t.Fatalf("ParseCommitList: %v %+v", err, l)
	}
	if _, err := ParseCommitList([]byte(`{"commits":[],"Commits":[]}`)); err == nil {
		t.Fatal("a case-variant commit list was accepted")
	}
}

// A mechanical rule must have been derived around the gate's own clock: a
// rule minted for the future, or presented as derived long ago, fails.
func TestMechanicalDerivationTimeBound(t *testing.T) {
	src := extract.FixtureReader{Root: servedFixture}
	base, head, _ := mechanicalTrees(t, nil)
	for name, tc := range map[string]struct {
		now  time.Time
		pass bool
	}{
		"just derived":          {servedDerivedAt.Add(time.Minute), true},
		"derived 23h ago":       {servedDerivedAt.Add(23 * time.Hour), true},
		"derived 25h ago":       {servedDerivedAt.Add(25 * time.Hour), false},
		"derived 4m ahead":      {servedDerivedAt.Add(-4 * time.Minute), true},
		"derived 10m ahead":     {servedDerivedAt.Add(-10 * time.Minute), false},
		"minted 300 days ahead": {servedDerivedAt.Add(-300 * 24 * time.Hour), false},
	} {
		t.Run(name, func(t *testing.T) {
			r := runGate(t, Options{Base: base, Head: head, Source: src, Now: tc.now})
			if r.Passed() != tc.pass {
				t.Fatalf("pass=%v, want %v: %v", r.Passed(), tc.pass, failedChecks(r))
			}
			if !tc.pass {
				requireFail(t, r, "outside [now-24h, now+5m]")
			}
		})
	}
	// The bound applies to loosening changes only: --rederive-all of
	// unchanged rules later still passes.
	r := runGate(t, Options{Base: head, Head: head, Source: src, Now: servedDerivedAt.Add(30 * 24 * time.Hour), RederiveAll: true})
	requirePass(t, r)
}

// Approval files, worklists and review records change only together with
// what they belong to.
func TestRecordFilesNeedTheirChange(t *testing.T) {
	key := newApprovalKey(t)
	t.Run("approval with no rule change", func(t *testing.T) {
		base, head := trees(t)
		ids := readPack(t, base, cncfRulesPath).activeReviewed()
		editPack(t, head, cncfRulesPath, func(p *packDoc) { evidenceOf(p.find(t, ids[1]))["state"] = "withdrawn" })
		writeFile(t, approvalPath(head, ids[0]), []byte("{}\n"))
		requireFail(t, runGate(t, Options{Base: base, Head: head, Author: DefaultBotLogin}), "no admitted change of this rule")
	})
	t.Run("approval beside a tightening change", func(t *testing.T) {
		base, head := trees(t)
		ids := readPack(t, base, cncfRulesPath).activeReviewed()
		editPack(t, head, cncfRulesPath, func(p *packDoc) { evidenceOf(p.find(t, ids[1]))["state"] = "withdrawn" })
		writeFile(t, approvalPath(head, ids[1]), []byte("{}\n"))
		requireFail(t, runGate(t, Options{Base: base, Head: head, Author: DefaultBotLogin}), "not admitted by this approval")
	})
	t.Run("approval in another layout", func(t *testing.T) {
		base, head := trees(t)
		writeFile(t, filepath.Join(head.Root, "cli", "knowledge", "approvals", "cncf", "nested", "x.json"), []byte("{}\n"))
		requireFail(t, runGate(t, Options{Base: base, Head: head}), "not <pack>/<rule id>.json")
	})
	t.Run("approval with its change", func(t *testing.T) {
		base, head, id, digest := approvalTrees(t)
		key.pinBoth(t, base, head, "airstand")
		writeFile(t, approvalPath(head, id), key.sign(t, ApprovalRecord{BaseDigest: ApprovalBaseAbsent, CandidateDigest: digest, CandidateID: "c", DecidedAt: gateNow.Add(-time.Hour).Format(time.RFC3339), Decision: "approve", Identity: "airstand", Pack: "cncf", RuleID: id}))
		r := runGate(t, Options{Base: base, Head: head, Author: DefaultBotLogin})
		requirePass(t, r)
		if !r.AutoMerge.Eligible {
			t.Fatalf("not eligible: %v", r.AutoMerge.Reasons)
		}
	})
	for name, rel := range map[string]string{
		"worklist without statement":      "cli/knowledge/reattestation/cncf/worklists/0009.worklist.json",
		"review record without statement": "cli/knowledge/reattestation/cncf/review-records/some.rule.json",
		"other reattestation file":        "cli/knowledge/reattestation/cncf/notes.json",
	} {
		t.Run(name, func(t *testing.T) {
			base, head := trees(t)
			ids := readPack(t, base, cncfRulesPath).activeReviewed()
			editPack(t, head, cncfRulesPath, func(p *packDoc) { evidenceOf(p.find(t, ids[1]))["state"] = "withdrawn" })
			writeFile(t, filepath.Join(head.Root, filepath.FromSlash(rel)), []byte("{}\n"))
			r := runGate(t, Options{Base: base, Head: head, Author: DefaultBotLogin})
			requireFail(t, r, "knowledge-records")
			if r.AutoMerge.Eligible {
				t.Fatal("eligible")
			}
		})
	}
}
