// SPDX-License-Identifier: AGPL-3.0-only

package knowledgegate

import (
	"context"
	"encoding/json"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/extract"
	"github.com/prufyx/prufyx/cli/internal/extract/extractcli"
	"github.com/prufyx/prufyx/cli/internal/extract/k8sservedapis"
	"github.com/prufyx/prufyx/cli/internal/lineattest"
	"github.com/prufyx/prufyx/cli/internal/maintainer/evidencerepin"
)

// Line attestations in the shipped CNCF pack: removal, owner approval with
// the extractor cross-check, and mechanical re-derivation.

const attestedPackSchema = "prufyx.io/cncf-source-rule-pack/v1alpha4"

func attestationID(line string) string {
	return evidencerepin.LineAttestationRecordID(recordComponent, lineattest.FamilyKubernetesRemovedServedGVK, line)
}

// packLineRules returns, per line, the ids of the pack's rules of the
// served-API family, sorted.
func packLineRules(t *testing.T, p *packDoc) map[string][]string {
	t.Helper()
	var rules []json.RawMessage
	for _, e := range p.entries {
		raw, err := json.Marshal(ruleOf(e))
		if err != nil {
			t.Fatal(err)
		}
		rules = append(rules, raw)
	}
	byKey, _, err := lineattest.RulesByScope(rules)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string][]string{}
	for k, ids := range byKey {
		if k.Family == lineattest.FamilyKubernetesRemovedServedGVK {
			out[k.Line] = ids
		}
	}
	return out
}

// reviewedAttestation is a reviewed attestation of line listing exactly
// the pack's rules for it, reviewed two hours before the gate's clock.
func reviewedAttestation(t *testing.T, p *packDoc, line string) map[string]any {
	t.Helper()
	ids := []any{}
	for _, id := range packLineRules(t, p)[line] {
		ids = append(ids, id)
	}
	src := deepCopy(evidenceOf(p.find(t, "kubernetes.cronjob-v1beta1-removed.1-24-0-to-1-25-0"))["sources"].([]any)[0]).(map[string]any)
	return map[string]any{
		"component": recordComponent, "line": line, "factFamily": lineattest.FamilyKubernetesRemovedServedGVK,
		"completeness": lineattest.Completeness, "ruleIds": ids,
		"evidence": map[string]any{
			"basis": "reviewed", "reviewedAt": gateNow.Add(-2 * time.Hour).Format(time.RFC3339),
			"validUntil": gateNow.Add(50 * 24 * time.Hour).Format(time.RFC3339), "sources": []any{src},
		},
	}
}

// setAttestations sets the pack's attestation section (sorted by line) and
// its schema.
func setAttestations(t *testing.T, p *packDoc, atts []map[string]any) {
	t.Helper()
	sort.Slice(atts, func(i, j int) bool { return lineattest.LineLess(atts[i]["line"].(string), atts[j]["line"].(string)) })
	raw, err := json.Marshal(atts)
	if err != nil {
		t.Fatal(err)
	}
	p.fields["lineAttestations"] = raw
	p.fields["schema"] = json.RawMessage(`"` + attestedPackSchema + `"`)
}

// attestedTrees returns a base and a head whose CNCF pack carries reviewed
// attestations of baseLines, and the head also of headLines (or, when
// edit is set, whatever edit makes of the head's list).
func attestedTrees(t *testing.T, baseLines, headLines []string, edit func(p *packDoc, atts []map[string]any) []map[string]any) (Tree, Tree) {
	t.Helper()
	base, head := trees(t)
	editPack(t, base, cncfRulesPath, func(p *packDoc) {
		var atts []map[string]any
		for _, l := range baseLines {
			atts = append(atts, reviewedAttestation(t, p, l))
		}
		setAttestations(t, p, atts)
	})
	editPack(t, head, cncfRulesPath, func(p *packDoc) {
		var atts []map[string]any
		for _, l := range headLines {
			atts = append(atts, reviewedAttestation(t, p, l))
		}
		if edit != nil {
			atts = edit(p, atts)
		}
		setAttestations(t, p, atts)
	})
	return base, head
}

// recordDigest is the candidate digest of a record of the head.
func recordDigest(t *testing.T, tr Tree, id string) string {
	t.Helper()
	p, err := loadPack(tr, DefaultLayout().Packs[0])
	if err != nil {
		t.Fatal(err)
	}
	r := p.Records[id]
	if r == nil {
		t.Fatalf("no record %s", id)
	}
	return CandidateDigest(r.Canonical)
}

func recordApproval(id, line, base, digest string) ApprovalRecord {
	return ApprovalRecord{
		BaseDigest: base, CandidateDigest: digest, CandidateID: "cand-1", DecidedAt: gateNow.Add(-time.Hour).Format(time.RFC3339),
		Decision: "approve", Identity: "airstand", Pack: "cncf", RuleID: id,
		Subject: ApprovalSubjectLineAttestation, Scope: recordComponent + " " + lineattest.FamilyKubernetesRemovedServedGVK + " " + line,
	}
}

var fixtureSource = extract.FixtureReader{Root: servedFixture}

// requireAdmittedButUnsplit requires every change admitted and every check
// green except one: a CNCF pack with records cannot be split into the
// per-project targets it is published as yet (cncfcheck refuses), so the
// gate still fails such a pack on targets/cncf, and nothing is eligible.
func requireAdmittedButUnsplit(t *testing.T, r *Report) {
	t.Helper()
	failed := failedChecks(r)
	if len(failed) != 1 || !strings.HasPrefix(failed[0], "targets/cncf: the pack cannot be split") || r.AutoMerge.Eligible {
		t.Fatalf("want only the split refusal, got:\n%s", strings.Join(failed, "\n"))
	}
}

// The base attests line 1.22; the shipped pack's 1.22 rules are line-wide,
// so an attested pack is admitted unchanged.
func TestGateAttestedPackUnchanged(t *testing.T) {
	base, head := attestedTrees(t, []string{"1.22"}, []string{"1.22"}, nil)
	r := runGate(t, Options{Base: base, Head: head, Author: DefaultBotLogin})
	requireAdmittedButUnsplit(t, r)
	if len(r.Changes) != 0 {
		t.Fatalf("changes %+v", r.Changes)
	}
	if c, ok := check(r, "rulecheck/cncf/lineAttestations"); !ok || !c.OK {
		t.Fatalf("attestation rulecheck %+v", c)
	}
}

// Acceptance 6: removing a line attestation is tightening; adding a rule to
// an attested line without updating the attestation fails the rule check
// (and admission).
func TestGateAttestationRemovalAndRuleSets(t *testing.T) {
	base, head := attestedTrees(t, []string{"1.22", "1.25"}, []string{"1.22"}, nil)
	r := runGate(t, Options{Base: base, Head: head, Author: DefaultBotLogin})
	requireAdmittedButUnsplit(t, r)
	c := change(t, r, attestationID("1.25"))
	if c.Class != ClassTightening || c.Kinds[0] != KindRemove || c.Proof != ProofNoneRequired || c.Section != "lineAttestations" {
		t.Fatalf("removal %+v", c)
	}
	if ch, ok := check(r, "breaker/withdrawals/cncf/records"); !ok || !ch.OK {
		t.Fatalf("record breaker %+v", ch)
	}

	// A new 1.22 rule the 1.22 attestation does not list.
	base, head = attestedTrees(t, []string{"1.22"}, []string{"1.22"}, nil)
	// The pack is no longer admissible, so nothing derived from it can be
	// regenerated: the pack file alone changes.
	p := readPack(t, head, cncfRulesPath)
	added := deepCopy(p.find(t, "kubernetes.lease-v1beta1-removed.1-21-0-to-1-22-0")).(map[string]any)
	ruleOf(added)["id"] = "kubernetes.lease-v1beta1-removed-again.1-21-0-to-1-22-0"
	p.entries = append(p.entries, added)
	p.sortByID()
	p.write(t, head, cncfRulesPath)
	r = runGate(t, Options{Base: base, Head: head, Author: DefaultBotLogin})
	requireFail(t, r, "attestation-missing-rule")
	requireFail(t, r, "admit/cncf")
}

// Acceptance 4: switching off many records trips the record breaker; the
// rule breaker is unchanged.
func TestGateRecordBreaker(t *testing.T) {
	lines := []string{"1.22", "1.23", "1.24", "1.25", "1.26", "1.27", "1.28", "1.29", "1.30", "1.31", "1.33", "1.34"}
	base, head := attestedTrees(t, append(lines, "1.35"), []string{"1.35"}, nil)
	r := runGate(t, Options{Base: base, Head: head, Author: DefaultBotLogin, MaxWithdrawPercent: 5})
	requireFail(t, r, "breaker/withdrawals/cncf/records")
	if ch, ok := check(r, "breaker/withdrawals/cncf"); !ok || !ch.OK {
		t.Fatalf("rule breaker %+v", ch)
	}
	found := false
	for _, b := range r.Breakers {
		if b.Kind == BreakerWithdrawProject && b.Subject == evidencerepin.RecordProjectLineAttestations && b.Observed == 12 {
			found = true
		}
	}
	if !found {
		t.Fatalf("no project breaker for the removed attestations: %+v", r.Breakers)
	}
	// Raised, the same change passes.
	r = runGate(t, Options{Base: base, Head: head, Author: DefaultBotLogin, MaxWithdrawPercent: 10})
	requireAdmittedButUnsplit(t, r)
}

// Acceptance 3: a reviewed attestation added outside a renewal needs an
// owner approval for exactly that record and the extractor cross-check.
func TestGateReviewedAttestationApproval(t *testing.T) {
	key := newApprovalKey(t)
	setup := func(t *testing.T, line string) (Tree, Tree, string) {
		base, head := attestedTrees(t, []string{"1.22"}, []string{"1.22", line}, nil)
		key.pinBoth(t, base, head, "airstand")
		return base, head, attestationID(line)
	}
	sign := func(t *testing.T, head Tree, id string, r ApprovalRecord) {
		writeFile(t, approvalPath(head, id), key.sign(t, r))
	}

	// 1.25: the extractor derives four removals; the listed shipped rules
	// read every one of them.
	for _, line := range []string{"1.25", "1.19"} {
		t.Run("valid "+line, func(t *testing.T) {
			base, head, id := setup(t, line)
			sign(t, head, id, recordApproval(id, line, ApprovalBaseAbsent, recordDigest(t, head, id)))
			r := runGate(t, Options{Base: base, Head: head, Source: fixtureSource, Author: DefaultBotLogin})
			requireAdmittedButUnsplit(t, r)
			c := change(t, r, id)
			if c.Proof != ProofApproval || c.Class != ClassLoosening || c.Kinds[0] != KindNew {
				t.Fatalf("change %+v", c)
			}
		})
	}

	cases := map[string]struct {
		line string
		edit func(t *testing.T, base, head Tree, id string, rec *ApprovalRecord) Options
		want string
	}{
		// No 1.33 rule in the pack, but upstream 1.33 removes the
		// SelfSubjectReview beta: an empty attestation is refused.
		"upstream removal not listed":        {"1.33", nil, "no rule the attestation lists decides it the same way"},
		"line the extractor does not derive": {"1.28", nil, "derives no pair into line 1.28"},
		"no upstream source": {"1.25", func(t *testing.T, base, head Tree, id string, rec *ApprovalRecord) Options {
			return Options{Base: base, Head: head, Author: DefaultBotLogin}
		}, "no upstream source"},
		"no approval": {"1.25", func(t *testing.T, base, head Tree, id string, rec *ApprovalRecord) Options {
			rec.RuleID = ""
			return Options{}
		}, "no owner approval"},
		"rule approval for the record": {"1.25", func(t *testing.T, base, head Tree, id string, rec *ApprovalRecord) Options {
			rec.Subject, rec.Scope = "", ""
			return Options{}
		}, "approves a different kind of subject"},
		"other scope": {"1.25", func(t *testing.T, base, head Tree, id string, rec *ApprovalRecord) Options {
			rec.Scope = strings.Replace(rec.Scope, "1.25", "1.26", 1)
			return Options{}
		}, "approves a different rule"},
		"other record id": {"1.25", func(t *testing.T, base, head Tree, id string, rec *ApprovalRecord) Options {
			rec.RuleID = attestationID("1.26")
			return Options{}
		}, "approves a different rule"},
		"record changed after approval": {"1.25", func(t *testing.T, base, head Tree, id string, rec *ApprovalRecord) Options {
			rec.CandidateDigest = "sha256:" + strings.Repeat("0", 64)
			return Options{}
		}, "candidate digest does not match"},
		"base state other than absent": {"1.25", func(t *testing.T, base, head Tree, id string, rec *ApprovalRecord) Options {
			rec.BaseDigest = rec.CandidateDigest
			return Options{}
		}, "base digest does not match"},
		// Removing an attestation is tightening; an approval left in the
		// tree may not add the same record again in a later change.
		"approval already in the base": {"1.25", func(t *testing.T, base, head Tree, id string, rec *ApprovalRecord) Options {
			writeFile(t, approvalPath(base, id), key.sign(t, *rec))
			return Options{}
		}, "already in the base"},
		"line at the declared first line": {"1.20", nil, "derives no pair into line 1.20"},
		"kill switch": {"1.25", func(t *testing.T, base, head Tree, id string, rec *ApprovalRecord) Options {
			writeFile(t, head.Root+"/factory/PAUSE", nil)
			return Options{}
		}, "kill switch"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			base, head, id := setup(t, tc.line)
			rec := recordApproval(id, tc.line, ApprovalBaseAbsent, recordDigest(t, head, id))
			o := Options{Base: base, Head: head, Source: fixtureSource, Author: DefaultBotLogin}
			if tc.edit != nil {
				if got := tc.edit(t, base, head, id, &rec); got.Base.Root != "" {
					o = got
				}
			}
			if rec.RuleID != "" {
				sign(t, head, id, rec)
			}
			r := runGate(t, o)
			requireFail(t, r, tc.want)
			if c := change(t, r, id); c.OK {
				t.Fatalf("admitted: %+v", c)
			}
		})
	}

	// The stagger cap counts rules and records together: a new record's
	// lease may not land in a week that already holds more than the cap.
	t.Run("stagger", func(t *testing.T) {
		base, head := attestedTrees(t, []string{"1.22"}, []string{"1.22"}, func(p *packDoc, atts []map[string]any) []map[string]any {
			a := reviewedAttestation(t, p, "1.19")
			// 2026-W50, where most of the shipped pack's leases end.
			a["evidence"].(map[string]any)["validUntil"] = "2026-12-08T12:00:00Z"
			return append(atts, a)
		})
		key.pinBoth(t, base, head, "airstand")
		id := attestationID("1.19")
		sign(t, head, id, recordApproval(id, "1.19", ApprovalBaseAbsent, recordDigest(t, head, id)))
		r := runGate(t, Options{Base: base, Head: head, Source: fixtureSource, Author: DefaultBotLogin})
		requireFail(t, r, "stagger/cncf/records")
		if c, _ := check(r, "stagger/cncf"); !c.OK {
			t.Fatalf("rule stagger %+v", c)
		}
	})

	// A rule approval never verifies as a record approval, and the reverse.
	t.Run("record approval for a rule", func(t *testing.T) {
		base, head, id, digest := approvalTrees(t)
		key.pinBoth(t, base, head, "airstand")
		rec := ApprovalRecord{BaseDigest: ApprovalBaseAbsent, CandidateDigest: digest, CandidateID: "cand-1", DecidedAt: gateNow.Add(-time.Hour).Format(time.RFC3339), Decision: "approve", Identity: "airstand", Pack: "cncf", RuleID: id,
			Subject: ApprovalSubjectLineAttestation, Scope: recordComponent + " " + lineattest.FamilyKubernetesRemovedServedGVK + " 1.25"}
		writeFile(t, approvalPath(head, id), key.sign(t, rec))
		requireFail(t, runGate(t, Options{Base: base, Head: head}), "approves a different kind of subject")
	})

	// A changed attestation: the approval binds the base record.
	t.Run("modified attestation", func(t *testing.T) {
		base, head := attestedTrees(t, []string{"1.22", "1.25"}, []string{"1.22", "1.25"}, func(p *packDoc, atts []map[string]any) []map[string]any {
			for _, a := range atts {
				if a["line"] == "1.25" {
					a["evidence"].(map[string]any)["validUntil"] = gateNow.Add(55 * 24 * time.Hour).Format(time.RFC3339)
				}
			}
			return atts
		})
		key.pinBoth(t, base, head, "airstand")
		id := attestationID("1.25")
		sign(t, head, id, recordApproval(id, "1.25", recordDigest(t, base, id), recordDigest(t, head, id)))
		r := runGate(t, Options{Base: base, Head: head, Source: fixtureSource, Author: DefaultBotLogin})
		requireAdmittedButUnsplit(t, r)
		if c := change(t, r, id); c.Proof != ProofApproval || !containsKind(c.Kinds, KindRenew) {
			t.Fatalf("change %+v", c)
		}
		sign(t, head, id, recordApproval(id, "1.25", ApprovalBaseAbsent, recordDigest(t, head, id)))
		requireFail(t, runGate(t, Options{Base: base, Head: head, Source: fixtureSource, Author: DefaultBotLogin}), "base digest does not match")
	})
}

// crossCheckAttestation on its own: the extractor's run over the fixture
// derives lines 1.25, 1.31, 1.32 and 1.33; its declared first line is 1.20.
func TestCrossCheckAttestation(t *testing.T) {
	out, floor, err := runAttester(context.Background(), fixtureSource, extractcli.Catalog(), 0, lineattest.FamilyKubernetesRemovedServedGVK, gateNow)
	if err != nil {
		t.Fatal(err)
	}
	if floor != "1.20" {
		t.Fatalf("floor %q", floor)
	}
	base, _ := trees(t)
	pack, err := loadPack(base, DefaultLayout().Packs[0])
	if err != nil {
		t.Fatal(err)
	}
	att := func(line string, ids ...string) lineattest.LineAttestation {
		return lineattest.LineAttestation{Component: recordComponent, Line: line, FactFamily: lineattest.FamilyKubernetesRemovedServedGVK, RuleIDs: ids}
	}
	r125 := packLineRules(t, readPack(t, base, cncfRulesPath))["1.25"]
	// rewritten is the pack with every 1.25 rule changed by edit.
	rewritten := func(edit func(rule map[string]any)) *loadedPack {
		p := *pack
		p.Entries = map[string]*entry{}
		for id, e := range pack.Entries {
			p.Entries[id] = e
		}
		for _, id := range r125 {
			var doc map[string]any
			if err := json.Unmarshal(pack.Entries[id].Raw, &doc); err != nil {
				t.Fatal(err)
			}
			edit(doc["rule"].(map[string]any))
			raw, err := json.Marshal(doc)
			if err != nil {
				t.Fatal(err)
			}
			e := *pack.Entries[id]
			e.Raw = raw
			p.Entries[id] = &e
		}
		return &p
	}
	cond := func(rule map[string]any) map[string]any { return rule["condition"].(map[string]any) }
	for name, tc := range map[string]struct {
		a     lineattest.LineAttestation
		pack  *loadedPack
		floor string
		want  string
	}{
		"all derived rules listed":          {att("1.25", r125...), nil, "", ""},
		"quiet line":                        {att("1.31"), nil, "", ""},
		"before the declared first line":    {att("1.19"), nil, "", ""},
		"at the declared first line":        {att("1.20"), nil, "", "derives no pair into line 1.20"},
		"no declared first line":            {att("1.19"), nil, "none", "derives no pair into line 1.19"},
		"a derived rule not listed":         {att("1.25", without(r125, "kubernetes.psp-v1beta1-removed.1-24-0-to-1-25-0")...), nil, "", "psp_v1beta1_removed_gvk_present"},
		"listed rule not in pack":           {att("1.25", append([]string{"no.such.rule"}, r125...)...), nil, "", "not in the pack"},
		"line not derived":                  {att("1.29"), nil, "", "derives no pair into line 1.29"},
		"line after the last":               {att("1.40"), nil, "", "derives no pair into line 1.40"},
		"unknown family":                    {lineattest.LineAttestation{Line: "1.25", FactFamily: "x"}, nil, "", "unknown fact family"},
		"removal upstream, no rules":        {att("1.32"), nil, "", "flowcontrol_v1beta3_removed_gvk_present"},
		"listed rules read the other side":  {att("1.25", r125...), rewritten(func(r map[string]any) { cond(r)["side"] = "current" }), "", "hpa_v2beta1_removed_gvk_present"},
		"listed rules expect the opposite":  {att("1.25", r125...), rewritten(func(r map[string]any) { cond(r)["boolValue"] = false }), "", "cronjob_v1beta1_removed_gvk_present"},
		"listed rules use another operator": {att("1.25", r125...), rewritten(func(r map[string]any) { r["operator"] = "forbid_target_version" }), "", "pdb_v1beta1_removed_gvk_present"},
		"listed rules are notices":          {att("1.25", r125...), rewritten(func(r map[string]any) { r["operator"] = "notice_one_way" }), "", "psp_v1beta1_removed_gvk_present"},
		"listed rules are leads": {att("1.25", r125...), rewritten(func(r map[string]any) {
			r["evidence"].(map[string]any)["basis"] = "lead"
		}), "", "hpa_v2beta1_removed_gvk_present"},
		"listed rules only gate on the fact": {att("1.25", r125...), rewritten(func(r map[string]any) {
			r["appliesWhen"] = []any{cond(r)}
			r["condition"] = map[string]any{"side": "proposed", "component": recordComponent, "factId": "component.kubernetes.other_fact", "boolValue": true}
		}), "", "cronjob_v1beta1_removed_gvk_present"},
	} {
		t.Run(name, func(t *testing.T) {
			p, f := pack, floor
			if tc.pack != nil {
				p = tc.pack
			}
			switch tc.floor {
			case "none":
				f = ""
			case "":
			default:
				f = tc.floor
			}
			err := crossCheckAttestation(out, f, tc.a, p)
			if (err == nil) != (tc.want == "") || (err != nil && !strings.Contains(err.Error(), tc.want)) {
				t.Fatalf("err %v, want %q", err, tc.want)
			}
		})
	}

	// An attested pair that is not derived, and a derived pair that is not
	// attested, are refused.
	setPair := func(line string, edit func(p *extract.PairRecord)) *extract.Output {
		copied := *out
		copied.Manifest.Pairs = nil
		for _, p := range out.Manifest.Pairs {
			if strings.HasPrefix(p.To, line+".") {
				a := *p.Attestation
				p.Attestation = &a
				edit(&p)
			}
			copied.Manifest.Pairs = append(copied.Manifest.Pairs, p)
		}
		return &copied
	}
	notDerived := setPair("1.31", func(p *extract.PairRecord) { p.Status = extract.PairWithheld })
	if err := crossCheckAttestation(notDerived, floor, att("1.31"), pack); err == nil || !strings.Contains(err.Error(), "does not attest line 1.31") {
		t.Fatalf("pair not derived: %v", err)
	}
	notAttested := setPair("1.31", func(p *extract.PairRecord) {
		p.Attestation.Status, p.Attestation.Reason = extract.PairNotAttested, "test"
	})
	if err := crossCheckAttestation(notAttested, floor, att("1.31"), pack); err == nil || !strings.Contains(err.Error(), "does not attest line 1.31") {
		t.Fatalf("not attested pair: %v", err)
	}
	otherFamily := setPair("1.31", func(p *extract.PairRecord) { p.Attestation.Families = []string{"other.family"} })
	if err := crossCheckAttestation(otherFamily, floor, att("1.31"), pack); err == nil || !strings.Contains(err.Error(), "does not attest line 1.31") {
		t.Fatalf("pair of another family: %v", err)
	}
	if _, _, err := runAttester(context.Background(), fixtureSource, extractcli.Catalog(), 0, "no.family", gateNow); err == nil {
		t.Fatal("an unknown family found an extractor")
	}
}

func without(ids []string, drop string) []string {
	var out []string
	for _, id := range ids {
		if id != drop {
			out = append(out, id)
		}
	}
	return out
}

// derivedAttestation is the extractor's own attestation of line, as the
// factory would publish it.
func derivedAttestation(t *testing.T, line string) map[string]any {
	t.Helper()
	repo, err := extract.ParseRepo(k8sservedapis.Repo)
	if err != nil {
		t.Fatal(err)
	}
	out, err := extract.Run(context.Background(), k8sservedapis.New(0), fixtureSource, fixtureSource, extract.Options{Repo: repo, DerivedAt: servedDerivedAt})
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range out.Attestations {
		if a.Line == line {
			raw, err := json.Marshal(a)
			if err != nil {
				t.Fatal(err)
			}
			var m map[string]any
			if err := json.Unmarshal(raw, &m); err != nil {
				t.Fatal(err)
			}
			return m
		}
	}
	t.Fatalf("no derived attestation for %s", line)
	return nil
}

// Acceptance 2: a mechanical attestation is admitted only when the
// extractor re-derives it byte for byte, under the derivation-time bound.
func TestGateMechanicalAttestation(t *testing.T) {
	add := func(tamper func(a map[string]any)) (Tree, Tree) {
		return attestedTrees(t, []string{"1.22"}, []string{"1.22"}, func(p *packDoc, atts []map[string]any) []map[string]any {
			a := derivedAttestation(t, "1.31")
			if tamper != nil {
				tamper(a)
			}
			return append(atts, a)
		})
	}
	base, head := add(nil)
	r := runGate(t, Options{Base: base, Head: head, Source: fixtureSource, Author: DefaultBotLogin})
	requireAdmittedButUnsplit(t, r)
	if c := change(t, r, attestationID("1.31")); c.Proof != ProofRederived || c.Basis != "mechanical" {
		t.Fatalf("change %+v", c)
	}

	// The lease is the factory's choice, as for mechanical rules: the gate
	// re-derives with the record's own lease.
	base, head = add(func(a map[string]any) {
		ev := a["evidence"].(map[string]any)
		ev["validUntil"] = shiftTime(t, ev["validUntil"], -24*time.Hour)
	})
	requireAdmittedButUnsplit(t, runGate(t, Options{Base: base, Head: head, Source: fixtureSource, Author: DefaultBotLogin}))
	base, head = add(nil)

	// --rederive-all re-derives it again on a scheduled run.
	r = runGate(t, Options{Base: head, Head: head, Source: fixtureSource, RederiveAll: true})
	requireAdmittedButUnsplit(t, r)
	if c, _ := check(r, "rederive-all"); !strings.Contains(c.Detail, "1 of them line attestations") {
		t.Fatalf("rederive-all %+v", c)
	}

	for name, tc := range map[string]struct {
		tamper func(a map[string]any)
		opts   func(o *Options)
		want   string
	}{
		"source span": {func(a map[string]any) {
			src := a["evidence"].(map[string]any)["sources"].([]any)[0].(map[string]any)
			src["endLine"] = json.Number("2")
		}, nil, "differs from what extractor"},
		"extractor version": {func(a map[string]any) {
			a["evidence"].(map[string]any)["extractor"].(map[string]any)["version"] = "9.9.9"
		}, nil, "this gate runs"},
		"no source":            {nil, func(o *Options) { o.Source = nil }, "no upstream source"},
		"derived too long ago": {nil, func(o *Options) { o.Now = gateNow.Add(48 * time.Hour) }, "outside [now-24h, now+5m]"},
	} {
		t.Run(name, func(t *testing.T) {
			base, head := add(tc.tamper)
			o := Options{Base: base, Head: head, Source: fixtureSource, Author: DefaultBotLogin}
			if tc.opts != nil {
				tc.opts(&o)
			}
			r := runGate(t, o)
			requireFail(t, r, tc.want)
			if c := change(t, r, attestationID("1.31")); c.OK {
				t.Fatalf("admitted %+v", c)
			}
		})
	}

	// An owner approval never admits a mechanical attestation.
	t.Run("approval does not admit a mechanical attestation", func(t *testing.T) {
		key := newApprovalKey(t)
		base, head := add(func(a map[string]any) {
			a["evidence"].(map[string]any)["sources"].([]any)[0].(map[string]any)["startLine"] = json.Number("2")
		})
		key.pinBoth(t, base, head, "airstand")
		id := attestationID("1.31")
		writeFile(t, approvalPath(head, id), key.sign(t, recordApproval(id, "1.31", ApprovalBaseAbsent, recordDigest(t, head, id))))
		r := runGate(t, Options{Base: base, Head: head, Source: fixtureSource, Author: DefaultBotLogin})
		requireFail(t, r, "differs from what extractor")
		if c := change(t, r, id); c.OK || c.Proof == ProofApproval {
			t.Fatalf("admitted %+v", c)
		}
	})

	// A stored attestation the extractor no longer reproduces fails the
	// scheduled run that re-derives everything.
	_, head = add(func(a map[string]any) {
		a["evidence"].(map[string]any)["sources"].([]any)[0].(map[string]any)["startLine"] = json.Number("2")
	})
	requireFail(t, runGate(t, Options{Base: head, Head: head, Source: fixtureSource, RederiveAll: true}), "rederive-all")
}
