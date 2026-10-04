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

	"github.com/prufyx/prufyx/cli/internal/lineattest"
	"github.com/prufyx/prufyx/cli/internal/maintainer/evidencereattest"
	"github.com/prufyx/prufyx/cli/internal/maintainer/evidencerepin"
	"github.com/prufyx/prufyx/cli/internal/maintainer/sourcecorpus"
)

// Records (line attestations and path policies) renewed by an automated
// reattestation statement, over a synthetic one-pack layout that reads
// records.

const recordComponent = "pkg:github/kubernetes/kubernetes"

var (
	reviewedAttestationID   = evidencerepin.LineAttestationRecordID(recordComponent, lineattest.FamilyKubernetesRemovedServedGVK, "1.30")
	mechanicalAttestationID = evidencerepin.LineAttestationRecordID(recordComponent, lineattest.FamilyKubernetesRemovedServedGVK, "1.31")
	reviewedPolicyID        = evidencerepin.PathPolicyRecordID(recordComponent)
)

func recordLayout() Layout {
	l := synthLayout()
	l.Packs[0].Records = true
	return l
}

type recordFixture struct {
	reattestFixture
	packRaw []byte
	stmt    evidencereattest.Statement
}

func (f recordFixture) opts() Options {
	o := f.reattestFixture.opts()
	o.Layout = recordLayout()
	return o
}

// recordPack is a synthetic pack holding one due community rule, a due
// reviewed 1.30 line attestation, a due reviewed path policy and, when
// mechanical is set, a mechanical 1.31 line attestation, all citing the
// rule's own source file.
func recordPack(t *testing.T, at time.Time, mechanical bool) ([]byte, map[string]any, map[string]any) {
	t.Helper()
	community := readPack(t, copyKnowledge(t), commRulesPath)
	e := deepCopy(community.entries[0]).(map[string]any)
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
	reviewedAt := at.Add(-30 * 24 * time.Hour).Format(time.RFC3339)
	ev["reviewedAt"], ev["validUntil"] = reviewedAt, validUntil.Format(time.RFC3339)
	recordSource := func(id string) map[string]any {
		s := deepCopy(src).(map[string]any)
		s["id"] = id
		return s
	}
	attestations := []any{map[string]any{
		"component": recordComponent, "line": "1.30", "factFamily": lineattest.FamilyKubernetesRemovedServedGVK,
		"completeness": lineattest.Completeness, "ruleIds": []any{},
		"evidence": map[string]any{"basis": "reviewed", "reviewedAt": reviewedAt, "validUntil": validUntil.Format(time.RFC3339), "sources": []any{recordSource("attestation-src")}},
	}}
	if mechanical {
		derived := at.Add(-20 * 24 * time.Hour).Format(time.RFC3339)
		attestations = append(attestations, map[string]any{
			"component": recordComponent, "line": "1.31", "factFamily": lineattest.FamilyKubernetesRemovedServedGVK,
			"completeness": lineattest.Completeness, "ruleIds": []any{},
			"evidence": map[string]any{
				"basis": "mechanical", "extractor": map[string]any{"id": "k8s.served-api-removal", "version": "1.1.0", "codeDigest": "sha256:" + strings.Repeat("ab", 32)},
				"derivedAt": derived, "reviewedAt": derived, "validUntil": validUntil.Format(time.RFC3339), "sources": []any{recordSource("mechanical-src")},
			},
		})
	}
	policies := []any{map[string]any{
		"component": recordComponent, "policy": "sequential_minor",
		"evidence": map[string]any{"state": "active", "reviewedAt": reviewedAt, "validUntil": validUntil.Format(time.RFC3339), "sources": []any{recordSource("policy-src")}},
	}}
	raw, err := json.Marshal(map[string]any{
		"schema": "test-pack/v1", "revision": "rev-1", "policyId": "policy-1", "policyDigest": "sha256:" + strings.Repeat("ab", 32),
		"entries": []any{e}, "lineAttestations": attestations, "pathPolicies": policies,
	})
	if err != nil {
		t.Fatal(err)
	}
	return raw, e, src
}

// recordWorklist is a worklist over every citation of the pack, each file
// identical on its release line (the only baseline automated mode renews).
func recordWorklist(t *testing.T, packRaw []byte, at time.Time) []byte {
	t.Helper()
	citations, err := evidencerepin.LoadCitations(synthPackPath, packRaw)
	if err != nil {
		t.Fatal(err)
	}
	resolved := at.Add(-time.Hour).Format(time.RFC3339)
	wl := evidencerepin.Worklist{
		Schema: evidencerepin.Schema, Authority: evidencerepin.Authority, GeneratedAt: resolved,
		Scope: evidencerepin.WorklistScope{RulePacks: []string{synthPackPath}},
	}
	repos := map[string]bool{}
	for _, c := range citations {
		wl.Citations = append(wl.Citations, evidencerepin.ClassResult{
			RulePack: c.RulePack, RuleID: c.RuleID, Project: c.Project, SourceID: c.SourceID,
			Owner: c.Owner, Repo: c.Repo, Path: c.Path, OldCommit: c.OldCommit, NewCommit: c.OldCommit, Class: evidencerepin.ClassFileIdentical,
			Baseline: evidencerepin.BaselineReleaseLine, BaselineMode: evidencerepin.BaselineModeReleaseLine, BaselineLine: "0.9", PinnedTag: "v0.9.0", BaselineTag: "v0.9.4",
		})
		if !repos[c.Owner+"/"+c.Repo] {
			repos[c.Owner+"/"+c.Repo] = true
			wl.Repos = append(wl.Repos, evidencerepin.RepoResolution{Owner: c.Owner, Repo: c.Repo, Status: "RESOLVED", CurrentTag: "v0.9.4", CurrentCommit: c.OldCommit, ResolvedAt: resolved})
			wl.Lines = append(wl.Lines, evidencerepin.LineResolution{Owner: c.Owner, Repo: c.Repo, Prefix: "v", Line: "0.9", Status: "RESOLVED", Tag: "v0.9.4", Commit: c.OldCommit, ResolvedAt: resolved})
		}
	}
	wl.Summary = evidencerepin.Summary{TotalCitations: len(wl.Citations), Classified: len(wl.Citations)}
	raw, err := json.Marshal(wl)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// newRecordFixture prepares, signs and lays out an automated reattestation
// that renews the rule, the reviewed attestation and the reviewed path
// policy of recordPack. With mechanical, the pack also holds a mechanical
// attestation, which the statement leaves out.
func newRecordFixture(t *testing.T, mechanical bool) recordFixture {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	at := now.Add(-time.Hour)
	f := recordFixture{reattestFixture: reattestFixture{base: Tree{Root: t.TempDir()}, head: Tree{Root: t.TempDir()}, now: now}}
	var e map[string]any
	f.packRaw, e, _ = recordPack(t, at, mechanical)
	f.ruleID = ruleID(e)
	f.worklist = recordWorklist(t, f.packRaw, at)

	humanPub, _, humanID := signingKey(t)
	autoPub, autoPEM, autoID := signingKey(t)
	root := trustRoot(t, map[string]ed25519.PublicKey{evidencereattest.RoleHuman: humanPub, evidencereattest.RoleAutomation: autoPub}, map[string]string{evidencereattest.RoleHuman: humanID, evidencereattest.RoleAutomation: autoID}, now)
	f.rootDigest = sourcecorpus.SHA(root)
	capability, _ := recordLayout().Packs[0].CapabilityDigest()
	res, err := evidencereattest.Prepare(evidencereattest.PrepareOptions{
		WorklistRaw: f.worklist, PackName: evidencereattest.PackCommunity, PackPath: synthPackPath, PackRaw: f.packRaw,
		Chain: &evidencereattest.Chain{}, Mode: evidencereattest.ModeAutomated, AttestedAt: at, Now: now,
		NextRevision: "rev-1", EngineCapabilityDigest: capability,
	})
	if err != nil {
		t.Fatalf("prepare: %v", err)
	}
	if res.EligibleRuleCount != 3 {
		t.Fatalf("prepare renews %d items; not extended %+v", res.EligibleRuleCount, res.Statement.NotExtended)
	}
	f.stmt = res.Statement
	f.statement = res.StatementCanonical
	if f.envl, err = evidencereattest.Sign(evidencereattest.SignOptions{
		Statement: f.statement, TrustRoot: root, EncryptedKey: autoPEM, Passphrase: []byte(testPassphrase),
		Role: evidencereattest.RoleAutomation, ExpectedTrustRootDigest: f.rootDigest, Now: now,
	}); err != nil {
		t.Fatalf("sign: %v", err)
	}
	l := recordLayout()
	for _, tr := range []Tree{f.base, f.head} {
		writeFile(t, filepath.Join(tr.Root, synthAttestPath), []byte("attested\n"))
		writeFile(t, filepath.Join(tr.Root, l.TrustRootPath), append(append([]byte(nil), root...), '\n'))
		if err := os.MkdirAll(filepath.Join(tr.Root, l.ReattestDir, "community", "chain"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	writeFile(t, filepath.Join(f.base.Root, synthPackPath), f.packRaw)
	writeFile(t, filepath.Join(f.head.Root, synthPackPath), res.NextPack)
	dir := filepath.Join(f.head.Root, l.ReattestDir, "community")
	writeFile(t, filepath.Join(dir, "chain", "0001.statement.json"), append(append([]byte(nil), f.statement...), '\n'))
	writeFile(t, filepath.Join(dir, "chain", "0001.statement.sig.json"), append(append([]byte(nil), f.envl...), '\n'))
	writeFile(t, filepath.Join(dir, "worklists", "0001.worklist.json"), f.worklist)
	return f
}

// editHeadPack rewrites the head pack after edit; it keeps every other
// member as it is.
func editHeadPack(t *testing.T, f recordFixture, edit func(doc map[string]any)) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(f.head.Root, synthPackPath))
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	edit(doc)
	out, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(f.head.Root, synthPackPath), append(out, '\n'))
}

func sectionRecord(doc map[string]any, section string, i int) map[string]any {
	return doc[section].([]any)[i].(map[string]any)
}

// Acceptance 1 and 4: a bot renewal of a rule, a reviewed line attestation
// and a reviewed path policy, with one verified statement, is admitted
// record by record and is eligible; every renewal counts as loosening.
func TestGateRecordRenewal(t *testing.T) {
	f := newRecordFixture(t, false)
	r := runGate(t, f.opts())
	requirePass(t, r)
	for _, id := range []string{f.ruleID, reviewedAttestationID, reviewedPolicyID} {
		c := change(t, r, id)
		if c.Class != ClassLoosening || !containsKind(c.Kinds, KindRenew) || c.Proof != ProofReattestation || !c.OK {
			t.Fatalf("%s: %+v", id, c)
		}
	}
	if c := change(t, r, reviewedAttestationID); c.Section != "lineAttestations" || c.Project != evidencerepin.RecordProjectLineAttestations {
		t.Fatalf("attestation change %+v", c)
	}
	if c := change(t, r, reviewedPolicyID); c.Section != "pathPolicies" || c.Project != evidencerepin.RecordProjectPathPolicies {
		t.Fatalf("policy change %+v", c)
	}
	for _, c := range r.Changes {
		if c.Member != "" {
			t.Fatalf("pack-member change %+v", c)
		}
	}
	if r.Totals.Loosening != 3 || r.Daily.Change != 3 {
		t.Fatalf("totals %+v daily %+v", r.Totals, r.Daily)
	}
	if ch, ok := check(r, "stagger/community/records"); !ok || !ch.OK {
		t.Fatalf("record stagger check %+v", ch)
	}
	if !r.AutoMerge.Eligible {
		t.Fatalf("not eligible: %v", r.AutoMerge.Reasons)
	}

	// The same renewal against a pack the gate does not read records of
	// is a pack-member change, as before.
	o := f.opts()
	o.Layout = synthLayout()
	requireFail(t, runGate(t, o), "top-level member lineAttestations")
}

// Acceptance 1, 4 and 8: what a renewal through a statement may not do.
func TestGateRecordRenewalRejects(t *testing.T) {
	type tc struct {
		mutate func(t *testing.T, f recordFixture, o *Options)
		want   string
		id     string
	}
	cases := map[string]tc{
		"renewal plus a ruleIds edit": {func(t *testing.T, f recordFixture, o *Options) {
			editHeadPack(t, f, func(doc map[string]any) {
				sectionRecord(doc, "lineAttestations", 0)["ruleIds"] = []any{"some.rule"}
			})
		}, "attestation-extra-rule", reviewedAttestationID},
		"renewal plus a policy change": {func(t *testing.T, f recordFixture, o *Options) {
			editHeadPack(t, f, func(doc map[string]any) {
				sectionRecord(doc, "pathPolicies", 0)["policy"] = "direct"
			})
		}, "a reviewed path policy changes only by renewal", reviewedPolicyID},
		"dates other than the statement's": {func(t *testing.T, f recordFixture, o *Options) {
			editHeadPack(t, f, func(doc map[string]any) {
				ev := sectionRecord(doc, "lineAttestations", 0)["evidence"].(map[string]any)
				ev["validUntil"] = shiftTime(t, ev["validUntil"], time.Hour)
			})
		}, "V1", reviewedAttestationID},
		"record added": {func(t *testing.T, f recordFixture, o *Options) {
			editHeadPack(t, f, func(doc map[string]any) {
				added := deepCopy(sectionRecord(doc, "lineAttestations", 0)).(map[string]any)
				added["line"] = "1.29"
				doc["lineAttestations"] = []any{added, sectionRecord(doc, "lineAttestations", 0)}
			})
		}, "no owner approval", evidencerepin.LineAttestationRecordID(recordComponent, lineattest.FamilyKubernetesRemovedServedGVK, "1.29")},
		"policy removed": {func(t *testing.T, f recordFixture, o *Options) {
			editHeadPack(t, f, func(doc map[string]any) {
				delete(doc, "pathPolicies")
			})
		}, "may not be removed", reviewedPolicyID},
		"renewal with no statement": {func(t *testing.T, f recordFixture, o *Options) {
			for _, n := range []string{"0001.statement.json", "0001.statement.sig.json"} {
				if err := os.Remove(filepath.Join(f.head.Root, recordLayout().ReattestDir, "community", "chain", n)); err != nil {
					t.Fatal(err)
				}
			}
		}, "no reattestation statement", reviewedPolicyID},
		"revision bumped": {func(t *testing.T, f recordFixture, o *Options) {
			editHeadPack(t, f, func(doc map[string]any) { doc["revision"] = "rev-2" })
		}, "top-level member revision", ""},
		"kill switch": {func(t *testing.T, f recordFixture, o *Options) {
			writeFile(t, filepath.Join(f.head.Root, "factory", "PAUSE"), nil)
		}, "kill switch", reviewedAttestationID},
		"loosening cap": {func(t *testing.T, f recordFixture, o *Options) { o.MaxLoosening = 2 }, "3 loosening changes, cap 2", ""},
		"daily limit": {func(t *testing.T, f recordFixture, o *Options) {
			before := DefaultMaxDailyLoosening - 2
			o.DailyLoosening = &before
		}, "plus 3 in this change", ""},
		"review record of a record": {func(t *testing.T, f recordFixture, o *Options) {
			writeFile(t, filepath.Join(f.head.Root, recordLayout().ReattestDir, "community", "review-records", reviewedAttestationID+".json"), []byte("{}\n"))
		}, "review records for line attestations and path policies are not accepted", ""},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			f := newRecordFixture(t, false)
			o := f.opts()
			c.mutate(t, f, &o)
			r := runGate(t, o)
			requireFail(t, r, c.want)
			if c.id != "" {
				if ch := change(t, r, c.id); ch.OK {
					t.Fatalf("record change admitted: %+v", ch)
				}
			}
			if r.AutoMerge.Eligible {
				t.Fatal("eligible")
			}
		})
	}
}

// Acceptance 2 and 8: a mechanical record never renews through a
// statement. Its dates moved by hand to the statement's fail: the
// statement's own checks refuse them and the gate sends the record to
// re-derivation, which needs the extractor's exact output.
func TestGateMechanicalRecordIsNeverRenewedByAStatement(t *testing.T) {
	f := newRecordFixture(t, true)
	for _, ra := range f.stmt.Rules {
		if ra.RuleID == mechanicalAttestationID {
			t.Fatal("the statement renews the mechanical attestation")
		}
	}
	requirePass(t, runGate(t, f.opts()))
	editHeadPack(t, f, func(doc map[string]any) {
		ev := sectionRecord(doc, "lineAttestations", 1)["evidence"].(map[string]any)
		ev["reviewedAt"], ev["derivedAt"] = f.stmt.AttestedAt, f.stmt.AttestedAt
		ev["validUntil"] = f.stmt.ValidUntil
	})
	r := runGate(t, f.opts())
	requireFail(t, r, "reattestation/community")
	c := change(t, r, mechanicalAttestationID)
	if c.OK || c.Proof == ProofReattestation || !strings.Contains(c.Detail, "re-derivation failed") {
		t.Fatalf("mechanical record change %+v", c)
	}
}

// admitRecord's own checks, with a statement result the test controls
// (in the gate the statement is verified first, and V1/V6/V10 refuse most
// of these too; the gate does not rely on them).
func TestAdmitRecordChecksTheStatement(t *testing.T) {
	f := newRecordFixture(t, false)
	o := f.opts()
	o.Now = f.now
	cls, err := Classify(o.Layout, f.base, f.head)
	if err != nil {
		t.Fatal(err)
	}
	var att *Change
	for _, c := range cls.Changes {
		if c.RuleID == reviewedAttestationID {
			att = c
		}
	}
	if att == nil || !att.renewal {
		t.Fatalf("attestation change %+v", att)
	}
	good := statementResult{OK: true, Role: evidencereattest.RoleAutomation, Stem: "0001", Renewed: map[string]bool{reviewedAttestationID: true}, Statement: f.stmt}
	noKeys := func() (*ApprovalKeys, error) { return nil, os.ErrNotExist }
	noCheck := func(string, *record) error { return nil }
	run := func(stmt statementResult, edit func(c *Change)) *Change {
		c := *att
		if edit != nil {
			edit(&c)
		}
		c.OK, c.Proof, c.Detail = false, "", ""
		admitRecord(&c, stmt, noKeys, noCheck, &baseApprovals{opts: o}, o)
		return &c
	}
	if c := run(good, nil); !c.OK || c.Proof != ProofReattestation {
		t.Fatalf("good statement: %+v", c)
	}
	for name, tc := range map[string]struct {
		stmt func(s statementResult) statementResult
		edit func(c *Change)
		want string
	}{
		"statement not verified": {func(s statementResult) statementResult { s.OK, s.Detail = false, "V1: no"; return s }, nil, "reattestation: V1"},
		"no statement":           {func(s statementResult) statementResult { return statementResult{} }, nil, "no reattestation statement"},
		"record not renewed":     {func(s statementResult) statementResult { s.Renewed = map[string]bool{f.ruleID: true}; return s }, nil, "does not renew this record"},
		"human statement":        {func(s statementResult) statementResult { s.Role = evidencereattest.RoleHuman; return s }, nil, "only by an automated statement"},
		"not a pure renewal":     {nil, func(c *Change) { c.renewal = false }, "more than its evidence.reviewedAt"},
		"other attestedAt": {func(s statementResult) statementResult {
			s.Statement.AttestedAt = shiftTime(t, s.Statement.AttestedAt, time.Second)
			return s
		}, nil, "not the statement's"},
		"other validUntil": {func(s statementResult) statementResult {
			s.Statement.Rules = append([]evidencereattest.RuleAttestation(nil), s.Statement.Rules...)
			for i := range s.Statement.Rules {
				if s.Statement.Rules[i].RuleID == reviewedAttestationID {
					s.Statement.Rules[i].ValidUntil = shiftTime(t, s.Statement.Rules[i].ValidUntil, time.Second)
				}
			}
			return s
		}, nil, "not the statement's"},
		"mechanical head": {nil, func(c *Change) {
			h := *c.rhead
			h.Basis = "mechanical"
			c.rhead = &h
		}, "is not admitted here"},
		"mechanical base": {nil, func(c *Change) {
			b := *c.rbase
			b.Basis = "mechanical"
			c.rbase = &b
		}, "is not admitted here"},
	} {
		t.Run(name, func(t *testing.T) {
			stmt := good
			if tc.stmt != nil {
				stmt = tc.stmt(good)
			}
			c := run(stmt, tc.edit)
			if c.OK || !strings.Contains(c.Detail, tc.want) {
				t.Fatalf("admitted=%v detail %q, want %q", c.OK, c.Detail, tc.want)
			}
		})
	}
}
