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

	"github.com/prufyx/prufyx/cli/internal/constraintengine"
	"github.com/prufyx/prufyx/cli/internal/extract"
	"github.com/prufyx/prufyx/cli/internal/supersedepred"
)

const ownerLogin = DefaultOwnerLogin

// pairIDs are the five shipped reviewed Kubernetes rules the served-API
// extractor re-derives (K8R-4: the shipped pack, fixture run).
var pairIDs = []string{
	"kubernetes.hpa-v2beta1-removed.1-24-0-to-1-25-0",
	"kubernetes.cronjob-v1beta1-removed.1-24-0-to-1-25-0",
	"kubernetes.flowcontrol-v1beta3-removed.1-31-0-to-1-32-0",
	"kubernetes.pdb-v1beta1-removed.1-24-0-to-1-25-0",
	"kubernetes.psp-v1beta1-removed.1-24-0-to-1-25-0",
}

func factID(e map[string]any) string {
	return ruleOf(e)["condition"].(map[string]any)["factId"].(string)
}

// derivedFor returns the derived rule over the same fact as the reviewed
// rule r.
func derivedFor(t *testing.T, r map[string]any) map[string]any {
	t.Helper()
	for _, m := range derivedEntries(t) {
		if factID(m) == factID(r) {
			return m
		}
	}
	t.Fatalf("no derived rule over fact %s", factID(r))
	return nil
}

// supersedeCase is a change from the shipped pack: the reviewed rules
// removed (ids) and, for each, the derived rule added in the same change.
// edit may change the removed rules (as in the base), the additions, and the
// head's pack.
type supersedeCase struct {
	ids  []string
	base func(rs []map[string]any)
	adds func(ms []map[string]any)
	head func(p *packDoc)
}

func (c supersedeCase) build(t *testing.T) (Tree, Tree, []map[string]any, []map[string]any) {
	t.Helper()
	base, head := trees(t)
	var rs, ms []map[string]any
	for _, id := range c.ids {
		r := deepCopy(readPack(t, base, cncfRulesPath).find(t, id)).(map[string]any)
		rs = append(rs, r)
		ms = append(ms, derivedFor(t, r))
	}
	if c.base != nil {
		c.base(rs)
		editPack(t, base, cncfRulesPath, func(p *packDoc) {
			for _, r := range rs {
				for i, e := range p.entries {
					if ruleID(e) == ruleID(r) {
						p.entries[i] = r
					}
				}
			}
			p.sortByID()
		})
		editPack(t, head, cncfRulesPath, func(p *packDoc) {
			for _, r := range rs {
				for i, e := range p.entries {
					if ruleID(e) == ruleID(r) {
						p.entries[i] = r
					}
				}
			}
		})
	}
	if c.adds != nil {
		c.adds(ms)
	}
	editPack(t, head, cncfRulesPath, func(p *packDoc) {
		removed := map[string]bool{}
		for _, id := range c.ids {
			removed[id] = true
		}
		var kept []map[string]any
		for _, e := range p.entries {
			if !removed[ruleID(e)] {
				kept = append(kept, e)
			}
		}
		p.entries = append(kept, ms...)
		p.sortByID()
		if c.head != nil {
			c.head(p)
		}
	})
	return base, head, rs, ms
}

func ownerOpts(base, head Tree) Options {
	return Options{Base: base, Head: head, Source: extract.FixtureReader{Root: servedFixture}, Author: ownerLogin, Sender: ownerLogin,
		HeadSHA: testHeadSHA, Commits: loginCommits(ownerLogin, ownerLogin)}
}

// loginCommits is a complete commit list of one commit ending at testHeadSHA.
func loginCommits(author, committer string) *CommitList {
	c := CommitRecord{SHA: testHeadSHA, Author: &loginField{author}, Committer: &loginField{committer}}
	return &CommitList{Status: "ahead", AheadBy: 1, TotalCommits: 1, Commits: []CommitRecord{c}}
}

func supersedeChange(t *testing.T, r *Report, id string) *Change { return change(t, r, id) }

func TestSupersedeAdmitted(t *testing.T) {
	base, head, rs, ms := supersedeCase{ids: pairIDs[:1]}.build(t)
	r := runGate(t, ownerOpts(base, head))
	requirePass(t, r)
	rid, mid := ruleID(rs[0]), ruleID(ms[0])
	rc, mc := supersedeChange(t, r, rid), supersedeChange(t, r, mid)
	if !rc.OK || rc.Proof != ProofSupersede || rc.SupersededBy != mid || !containsKind(rc.Kinds, KindSupersede) || !containsKind(rc.Kinds, KindRemove) {
		t.Fatalf("removal half: %+v", rc)
	}
	if !mc.OK || mc.Proof != ProofRederived || mc.Supersedes != rid {
		t.Fatalf("added half: %+v", mc)
	}
	if len(r.Supersedes) != 1 || r.Supersedes[0] != (Supersede{Pack: rc.Pack, Old: rid, New: mid, OK: true}) {
		t.Fatalf("report pairs: %+v", r.Supersedes)
	}
	if r.AutoMerge.Eligible || !hasReason(r, "supersedes a reviewed rule") {
		t.Fatalf("auto-merge: %+v", r.AutoMerge)
	}
}

func hasReason(r *Report, sub string) bool {
	for _, x := range r.AutoMerge.Reasons {
		if strings.Contains(x, sub) {
			return true
		}
	}
	return false
}

// Never merged automatically, even when the pair is the automation's own
// change: the removal is refused (not its author's to make) and the reason is
// reported in addition to the refusal.
func TestSupersedeNeverAutoMerged(t *testing.T) {
	base, head, rs, _ := supersedeCase{ids: pairIDs[:1]}.build(t)
	opts := ownerOpts(base, head)
	opts.Author, opts.Sender = DefaultBotLogin, ""
	r := runGate(t, opts)
	if r.Passed() || r.AutoMerge.Eligible || !hasReason(r, "supersedes a reviewed rule") {
		t.Fatalf("passed %v, auto-merge %+v", r.Passed(), r.AutoMerge)
	}
	if c := supersedeChange(t, r, ruleID(rs[0])); c.OK || !strings.Contains(c.Detail, "not the owner") {
		t.Fatalf("%+v", c)
	}
}

func TestSupersedeOnlyTheOwner(t *testing.T) {
	cases := map[string]struct {
		edit func(o *Options)
		want string
	}{
		"bot author":        {func(o *Options) { o.Author = DefaultBotLogin }, "is not the owner"},
		"other author":      {func(o *Options) { o.Author = "someone" }, "is not the owner"},
		"no author":         {func(o *Options) { o.Author = "" }, "is not the owner"},
		"bot sender":        {func(o *Options) { o.Sender = DefaultBotLogin }, "not the owner"},
		"other sender":      {func(o *Options) { o.Sender = "someone" }, "not the owner"},
		"no sender":         {func(o *Options) { o.Sender = "" }, "not the owner"},
		"owner is the bot":  {func(o *Options) { o.Owner, o.BotLogin = "x", "x"; o.Author, o.Sender = "x", "x" }, "no owner is configured"},
		"owner other login": {func(o *Options) { o.Owner = "someone-else" }, "is not the owner"},
		"configured owner ok": {func(o *Options) {
			o.Owner = "maintainer"
			o.Author, o.Sender = "maintainer", "maintainer"
			o.Commits = loginCommits("maintainer", "maintainer")
		}, ""},
	}
	base, head, rs, _ := supersedeCase{ids: pairIDs[:1]}.build(t)
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			opts := ownerOpts(base, head)
			tc.edit(&opts)
			r := runGate(t, opts)
			c := supersedeChange(t, r, ruleID(rs[0]))
			if tc.want == "" {
				requirePass(t, r)
				return
			}
			if r.Passed() || c.OK || !strings.Contains(c.Detail, tc.want) {
				t.Fatalf("passed %v, removal %+v", r.Passed(), c)
			}
			if c.SupersededBy == "" || len(r.Supersedes) != 1 || r.Supersedes[0].OK {
				t.Fatalf("the pair is still reported, refused: %+v", r.Supersedes)
			}
		})
	}
}

func TestSupersedeRefusals(t *testing.T) {
	cases := map[string]struct {
		c    supersedeCase
		want string
		// paired: the pair is recognised and refused by its proof, not
		// left as a plain removal.
		paired bool
	}{
		"M does not re-derive": {supersedeCase{ids: pairIDs[:1], adds: func(ms []map[string]any) {
			ruleOf(ms[0])["nextAction"] = "Upgrade; nothing to do."
		}}, "is not re-derived", true},
		"M derived at another time": {supersedeCase{ids: pairIDs[:1], adds: func(ms []map[string]any) {
			evidenceOf(ms[0])["derivedAt"] = shiftTime(t, evidenceOf(ms[0])["derivedAt"], time.Hour)
		}}, "is not re-derived", true},
		"M cites other lines": {supersedeCase{ids: pairIDs[:1], adds: func(ms []map[string]any) {
			src := evidenceOf(ms[0])["sources"].([]any)[0].(map[string]any)
			src["endLine"] = src["startLine"]
		}}, "is not re-derived", true},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			base, head, rs, _ := tc.c.build(t)
			r := runGate(t, ownerOpts(base, head))
			rc := supersedeChange(t, r, ruleID(rs[0]))
			if r.Passed() || rc.OK || !strings.Contains(rc.Detail, tc.want) {
				t.Fatalf("passed %v, removal %+v", r.Passed(), rc)
			}
			if tc.paired != (rc.SupersededBy != "") || tc.paired != (len(r.Supersedes) == 1) {
				t.Fatalf("paired %v, SupersededBy %q, pairs %+v", tc.paired, rc.SupersededBy, r.Supersedes)
			}
		})
	}
	t.Run("no re-derivation source", func(t *testing.T) {
		base, head, rs, _ := supersedeCase{ids: pairIDs[:1]}.build(t)
		opts := ownerOpts(base, head)
		opts.Source = nil
		r := runGate(t, opts)
		if rc := supersedeChange(t, r, ruleID(rs[0])); r.Passed() || rc.OK || !strings.Contains(rc.Detail, "is not re-derived") {
			t.Fatalf("%+v", rc)
		}
	})
	t.Run("removal without an M", func(t *testing.T) {
		base, head, rs, ms := supersedeCase{ids: pairIDs[:1]}.build(t)
		editPack(t, head, cncfRulesPath, func(p *packDoc) {
			var kept []map[string]any
			for _, e := range p.entries {
				if ruleID(e) != ruleID(ms[0]) {
					kept = append(kept, e)
				}
			}
			p.entries = kept
		})
		r := runGate(t, ownerOpts(base, head))
		rc := supersedeChange(t, r, ruleID(rs[0]))
		if r.Passed() || rc.OK || !strings.Contains(rc.Detail, "may not be removed") || rc.SupersededBy != "" || len(r.Supersedes) != 0 {
			t.Fatalf("%+v", rc)
		}
	})
}

// M must be a mechanical rule: a reviewed (or any non-mechanical) addition
// does not make the removal a supersede.
func TestSupersedeMNotMechanical(t *testing.T) {
	for _, basis := range []string{"reviewed"} {
		t.Run(basis, func(t *testing.T) {
			base, head, rs, ms := supersedeCase{ids: pairIDs[:1], adds: func(ms []map[string]any) {
				// The reviewed rule itself under a new id.
				ev := evidenceOf(ms[0])
				ev["basis"] = basis
				delete(ev, "extractor")
				delete(ev, "derivedAt")
			}}.build(t)
			r := runGate(t, ownerOpts(base, head))
			rc := supersedeChange(t, r, ruleID(rs[0]))
			if r.Passed() || rc.OK || !strings.Contains(rc.Detail, "may not be removed") || rc.SupersededBy != "" {
				t.Fatalf("passed %v, removal %+v", r.Passed(), rc)
			}
			if mc := supersedeChange(t, r, ruleID(ms[0])); mc.OK || mc.Supersedes != "" {
				t.Fatalf("added half %+v", mc)
			}
		})
	}
}

// An addition that is withdrawn protects nothing; only an active M replaces R.
func TestSupersedeMWithdrawn(t *testing.T) {
	base, head, rs, _ := supersedeCase{ids: pairIDs[:1], adds: func(ms []map[string]any) {
		evidenceOf(ms[0])["state"] = "withdrawn"
	}}.build(t)
	cls, err := Classify(DefaultLayout(), base, head)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range cls.Changes {
		if c.isSupersede() {
			t.Fatalf("paired: %+v", c)
		}
	}
	r := runGate(t, ownerOpts(base, head))
	if rc := supersedeChange(t, r, ruleID(rs[0])); r.Passed() || rc.OK {
		t.Fatalf("%+v", rc)
	}
}

// A mechanical rule removed in favour of an equal one is not a supersede:
// the class replaces a reviewed rule.
func TestSupersedeRMustBeReviewed(t *testing.T) {
	base, derived, _ := mechanicalTrees(t, nil)
	head := copyTree(t, derived)
	var victim string
	editPack(t, head, cncfRulesPath, func(p *packDoc) {
		for i, e := range p.entries {
			if evidenceOf(e)["basis"] == "mechanical" {
				victim = ruleID(e)
				c := deepCopy(e).(map[string]any)
				ruleOf(c)["id"] = victim + "-copy"
				p.entries[i] = c
				return
			}
		}
	})
	_ = base
	cls, err := Classify(DefaultLayout(), derived, head)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range cls.Changes {
		if c.isSupersede() {
			t.Fatalf("paired: %+v", c)
		}
	}
	r := runGate(t, ownerOpts(derived, head))
	if c := change(t, r, victim); r.Passed() || c.OK || !strings.Contains(c.Detail, "may not be removed") {
		t.Fatalf("%+v", c)
	}
}

// ---- the pairing, on synthetic changes ----

// synth is one rule change for pairSupersedes: the base entry of a removal
// or the head entry of an addition.
func synth(t *testing.T, id, basis, state string, mut func(r map[string]any)) *Change {
	t.Helper()
	e := map[string]any{"project": "p", "rule": map[string]any{
		"id": id, "operator": "forbid_fact",
		"subject":   map[string]any{"component": "kubernetes", "from": "1.24.0", "to": "1.25.0"},
		"condition": map[string]any{"side": "to", "component": "kubernetes", "factId": "f", "boolValue": true},
		"evidence":  map[string]any{"state": state}, "reasonCode": "X", "nextAction": "n",
	}}
	if basis != "" {
		evidenceOf(e)["basis"] = basis
	}
	if mut != nil {
		mut(ruleOf(e))
	}
	raw, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	en, err := newEntry(raw)
	if err != nil {
		t.Fatal(err)
	}
	c := &Change{Pack: "pk", RuleID: id, Class: ClassLoosening, Project: "p", Basis: constraintengine.EffectiveBasis(basis)}
	return c.with(en)
}

func (c *Change) with(e *entry) *Change {
	if strings.HasPrefix(c.RuleID, "R") {
		c.base, c.Kinds = e, []string{KindRemove}
	} else {
		c.head, c.Kinds = e, []string{KindNew}
	}
	return c
}

type pairCase struct {
	name string
	rs   []*Change
	ms   []*Change
	want [][2]string // pairs, by id
}

// withProject moves a synthetic change to another project.
func withProject(t *testing.T, c *Change, project string) *Change {
	t.Helper()
	e := c.base
	if e == nil {
		e = c.head
	}
	var obj map[string]any
	if err := json.Unmarshal(e.Raw, &obj); err != nil {
		t.Fatal(err)
	}
	obj["project"] = project
	en, err := newEntry(mustJSON(t, obj))
	if err != nil {
		t.Fatal(err)
	}
	if c.base != nil {
		c.base = en
	} else {
		c.head = en
	}
	c.Project = project
	return c
}

// pairCases is the table of supersede pairings. The gate's TestPairSupersedes
// and the tool-versus-gate cross-check both run it, so the tool and the gate
// are held to the same cases.
func pairCases(t *testing.T) []pairCase {
	wide := withRange("1.24.0", "1.25.0", "1.25.0", "1.26.0")
	return []pairCase{
		{"covering mechanical addition", []*Change{synth(t, "R1", "", "active", nil)}, []*Change{synth(t, "M1", "mechanical", "active", wide)}, [][2]string{{"R1", "M1"}}},
		{"explicit reviewed basis", []*Change{synth(t, "R1", "reviewed", "active", nil)}, []*Change{synth(t, "M1", "mechanical", "active", wide)}, [][2]string{{"R1", "M1"}}},
		{"already withdrawn R", []*Change{synth(t, "R1", "", "withdrawn", nil)}, []*Change{synth(t, "M1", "mechanical", "active", wide)}, [][2]string{{"R1", "M1"}}},
		{"two independent pairs", []*Change{synth(t, "R1", "", "active", nil), synth(t, "R2", "", "active", func(r map[string]any) { r["condition"].(map[string]any)["factId"] = "g" })},
			[]*Change{synth(t, "M1", "mechanical", "active", wide), synth(t, "M2", "mechanical", "active", func(r map[string]any) { wide(r); r["condition"].(map[string]any)["factId"] = "g" })},
			[][2]string{{"R1", "M1"}, {"R2", "M2"}}},
		{"R from starts before M", []*Change{synth(t, "R1", "", "active", withRange("1.23.0", "1.25.0", "1.25.0", "1.26.0"))}, []*Change{synth(t, "M1", "mechanical", "active", wide)}, nil},
		{"R to ends after M", []*Change{synth(t, "R1", "", "active", withRange("1.24.0", "1.25.0", "1.25.0", "1.27.0"))}, []*Change{synth(t, "M1", "mechanical", "active", wide)}, nil},
		{"R anchor outside M", []*Change{synth(t, "R1", "", "active", func(r map[string]any) { r["subject"].(map[string]any)["from"] = "1.23.0" })}, []*Change{synth(t, "M1", "mechanical", "active", wide)}, nil},
		{"different key", []*Change{synth(t, "R1", "", "active", func(r map[string]any) { r["condition"].(map[string]any)["factId"] = "g" })}, []*Change{synth(t, "M1", "mechanical", "active", wide)}, nil},
		{"different side", []*Change{synth(t, "R1", "", "active", func(r map[string]any) { r["condition"].(map[string]any)["side"] = "from" })}, []*Change{synth(t, "M1", "mechanical", "active", wide)}, nil},
		{"different operator", []*Change{synth(t, "R1", "", "active", func(r map[string]any) { r["operator"] = "forbid_other" })}, []*Change{synth(t, "M1", "mechanical", "active", wide)}, nil},
		{"different component", []*Change{synth(t, "R1", "", "active", func(r map[string]any) { r["subject"].(map[string]any)["component"] = "etcd" })}, []*Change{synth(t, "M1", "mechanical", "active", wide)}, nil},
		{"different predicate", []*Change{synth(t, "R1", "", "active", func(r map[string]any) { r["condition"].(map[string]any)["boolValue"] = false })}, []*Change{synth(t, "M1", "mechanical", "active", wide)}, nil},
		{"M reviewed", []*Change{synth(t, "R1", "", "active", nil)}, []*Change{synth(t, "M1", "reviewed", "active", wide)}, nil},
		{"M consensus", []*Change{synth(t, "R1", "", "active", nil)}, []*Change{synth(t, "M1", "consensus", "active", wide)}, nil},
		{"M empirical", []*Change{synth(t, "R1", "", "active", nil)}, []*Change{synth(t, "M1", "empirical", "active", wide)}, nil},
		{"M lead", []*Change{synth(t, "R1", "", "active", nil)}, []*Change{synth(t, "M1", "lead", "active", wide)}, nil},
		{"M withdrawn", []*Change{synth(t, "R1", "", "active", nil)}, []*Change{synth(t, "M1", "mechanical", "withdrawn", wide)}, nil},
		{"R mechanical", []*Change{synth(t, "R1", "mechanical", "active", nil)}, []*Change{synth(t, "M1", "mechanical", "active", wide)}, nil},
		{"R consensus", []*Change{synth(t, "R1", "consensus", "active", nil)}, []*Change{synth(t, "M1", "mechanical", "active", wide)}, nil},
		{"no addition", []*Change{synth(t, "R1", "", "active", nil)}, nil, nil},
		{"two additions cover one removal", []*Change{synth(t, "R1", "", "active", nil)}, []*Change{synth(t, "M1", "mechanical", "active", wide), synth(t, "M2", "mechanical", "active", wide)}, nil},
		{"one addition covers two removals", []*Change{synth(t, "R1", "", "active", nil), synth(t, "R2", "", "active", nil)}, []*Change{synth(t, "M1", "mechanical", "active", wide)}, nil},
		{"set superset", []*Change{synth(t, "R1", "", "active", setRule("a"))}, []*Change{synth(t, "M1", "mechanical", "active", setRule("a", "b"))}, [][2]string{{"R1", "M1"}}},
		{"set not a superset", []*Change{synth(t, "R1", "", "active", setRule("a", "c"))}, []*Change{synth(t, "M1", "mechanical", "active", setRule("a", "b"))}, nil},
		{"different project", []*Change{withProject(t, synth(t, "R1", "", "active", nil), "q")}, []*Change{synth(t, "M1", "mechanical", "active", wide)}, nil},
		{"opposite boolValue (cronjob rule flipped)", []*Change{synth(t, "R1", "", "active", func(r map[string]any) { r["condition"].(map[string]any)["boolValue"] = false })}, []*Change{synth(t, "M1", "mechanical", "active", wide)}, nil},
		{"R empirical", []*Change{synth(t, "R1", "empirical", "active", nil)}, []*Change{synth(t, "M1", "mechanical", "active", wide)}, nil},
		{"R lead", []*Change{synth(t, "R1", "lead", "active", nil)}, []*Change{synth(t, "M1", "mechanical", "active", wide)}, nil},
	}
}

func TestPairSupersedes(t *testing.T) {
	cases := pairCases(t)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			all := append(append([]*Change{}, tc.rs...), tc.ms...)
			pairSupersedes(all)
			var got [][2]string
			for _, c := range tc.rs {
				if c.supersededBy != nil {
					got = append(got, [2]string{c.RuleID, c.supersededBy.RuleID})
					if c.SupersededBy != c.supersededBy.RuleID || c.supersededBy.supersedes != c || c.supersededBy.Supersedes != c.RuleID || !containsKind(c.Kinds, KindSupersede) {
						t.Fatalf("pair not linked both ways: %+v", c)
					}
				} else if c.SupersededBy != "" || containsKind(c.Kinds, KindSupersede) {
					t.Fatalf("unpaired removal marked: %+v", c)
				}
			}
			for _, m := range tc.ms {
				if m.supersedes == nil && (m.Supersedes != "" || containsKind(m.Kinds, KindSupersede)) {
					t.Fatalf("unpaired addition marked: %+v", m)
				}
			}
			if len(got) != len(tc.want) {
				t.Fatalf("pairs %v, want %v", got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("pairs %v, want %v", got, tc.want)
				}
			}
		})
	}
	t.Run("record and member changes are not paired", func(t *testing.T) {
		r := synth(t, "R1", "", "active", nil)
		m := synth(t, "M1", "mechanical", "active", withRange("1.24.0", "1.25.0", "1.25.0", "1.26.0"))
		r.Section = "lineAttestations"
		pairSupersedes([]*Change{r, m})
		if r.supersededBy != nil {
			t.Fatal("a record was paired")
		}
		r.Section, r.Member = "", "schema"
		pairSupersedes([]*Change{r, m})
		if r.supersededBy != nil {
			t.Fatal("a member change was paired")
		}
	})
}

// All five pairs of the shipped pack at once: the report lists each R to M,
// and the pairs are neither withdrawals for the breakers (set to trip at
// one) nor more than one loosening each for the limits.
func TestSupersedeFivePairsBreakersAndLimits(t *testing.T) {
	base, head, rs, ms := supersedeCase{ids: pairIDs}.build(t)
	opts := ownerOpts(base, head)
	opts.MaxWithdrawPercent, opts.MaxWithdrawProject = 1, 1
	opts.MaxLoosening = 5
	five := 0
	opts.DailyLoosening, opts.MaxDailyLoosening = &five, 10
	r := runGate(t, opts)
	requirePass(t, r)
	if len(r.Supersedes) != 5 {
		t.Fatalf("pairs %+v", r.Supersedes)
	}
	for i := 1; i < len(r.Supersedes); i++ {
		if r.Supersedes[i-1].Old >= r.Supersedes[i].Old {
			t.Fatalf("pairs not sorted by the removed rule: %+v", r.Supersedes)
		}
	}
	want := map[string]string{}
	for i := range rs {
		want[ruleID(rs[i])] = ruleID(ms[i])
	}
	for _, p := range r.Supersedes {
		if want[p.Old] != p.New || !p.OK {
			t.Fatalf("pair %+v", p)
		}
		delete(want, p.Old)
	}
	if len(want) != 0 {
		t.Fatalf("pairs missing: %v", want)
	}
	if r.Totals.Loosening != 5 || r.Limits.Loosening != 5 || r.Daily.Change != 5 {
		t.Fatalf("totals %+v limits %+v daily %+v", r.Totals, r.Limits, r.Daily)
	}
	for _, b := range r.Breakers {
		if b.Observed != 0 || b.Tripped {
			t.Fatalf("breaker %+v", b)
		}
	}
	if c, ok := check(r, "breaker/withdrawals-project"); !ok || !c.OK || !strings.Contains(c.Detail, "0 projects") {
		t.Fatalf("%+v", c)
	}

	// Six loosening changes (five pairs and one more) exceed a cap of five;
	// five do not exceed a cap of five but exceed a cap of four.
	for cap, wantOK := range map[int]bool{5: true, 4: false} {
		o := ownerOpts(base, head)
		o.MaxLoosening = cap
		if got := runGate(t, o); got.Limits.OK != wantOK {
			t.Fatalf("cap %d: limits %+v", cap, got.Limits)
		}
	}
	// The daily limit counts the same five.
	o := ownerOpts(base, head)
	four := 0
	o.DailyLoosening, o.MaxDailyLoosening = &four, 4
	if got := runGate(t, o); got.Daily.OK || got.Daily.Change != 5 {
		t.Fatalf("daily %+v", got.Daily)
	}
	// And so does Limits, the check without re-derivation.
	lim, err := Limits(Options{Layout: DefaultLayout(), Base: base, Head: head, MaxLoosening: 5})
	if err != nil {
		t.Fatal(err)
	}
	if lim.Totals.Loosening != 5 || !lim.Limits.OK || len(lim.Supersedes) != 5 || lim.Supersedes[0].OK {
		t.Fatalf("limits: totals %+v pairs %+v", lim.Totals, lim.Supersedes)
	}
}

func TestSupersedeKillSwitch(t *testing.T) {
	base, head, rs, _ := supersedeCase{ids: pairIDs[:1]}.build(t)
	writeFile(t, filepath.Join(head.Root, "factory", "PAUSE"), []byte("stop\n"))
	r := runGate(t, ownerOpts(base, head))
	if c := supersedeChange(t, r, ruleID(rs[0])); r.Passed() || c.OK || !strings.Contains(c.Detail, "kill switch") {
		t.Fatalf("%+v", c)
	}
}

// The report text lists R -> M, in the log and in the Markdown summary.
func TestSupersedeReportText(t *testing.T) {
	base, head, rs, ms := supersedeCase{ids: pairIDs[:2]}.build(t)
	r := runGate(t, ownerOpts(base, head))
	var log, md bytes.Buffer
	printChecks(&log, r)
	writeSummary(&md, r)
	for i := range rs {
		line := ruleID(rs[i]) + " -> " + ruleID(ms[i])
		if !strings.Contains(log.String(), "ok   supersede ") || !strings.Contains(log.String(), line) {
			t.Fatalf("log lacks %s:\n%s", line, log.String())
		}
		if !strings.Contains(md.String(), ruleID(ms[i])) {
			t.Fatalf("summary lacks %s:\n%s", ruleID(ms[i]), md.String())
		}
	}
	if !strings.Contains(md.String(), "Superseded rule") || !strings.Contains(md.String(), "Replaced by") {
		t.Fatalf("summary lacks the pair table:\n%s", md.String())
	}
	raw, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	var back struct {
		Supersedes []struct{ Pack, Old, New string }
	}
	if err := json.Unmarshal(raw, &back); err != nil || len(back.Supersedes) != 2 {
		t.Fatalf("json: %v %s", err, raw)
	}
	// A change without pairs reports an empty list, not null.
	plain := runGate(t, Options{Base: base, Head: base})
	raw, _ = json.Marshal(plain)
	if !bytes.Contains(raw, []byte(`"supersedes":[]`)) {
		t.Fatalf("no empty list: %s", raw)
	}
}

// The owner login flag defaults to the repository owner and can be set.
func TestSupersedeOwnerFlag(t *testing.T) {
	base, head, _, _ := supersedeCase{ids: pairIDs[:1]}.build(t)
	commits := filepath.Join(t.TempDir(), "commits.json")
	writeFile(t, commits, mustJSON(t, map[string]any{"status": "ahead", "ahead_by": 1, "behind_by": 0, "total_commits": 1, "commits": []any{
		map[string]any{"sha": testHeadSHA, "author": map[string]any{"login": "maintainer"}, "committer": map[string]any{"login": "maintainer"}}}}))
	run := func(owner string) int {
		args := []string{"verify", "--base", base.Root, "--head", head.Root, "--source", "fixture:" + servedFixture, "--author", "maintainer", "--sender", "maintainer", "--head-sha", testHeadSHA, "--commits", commits, "--now", gateNow.Format("2006-01-02T15:04:05Z")}
		if owner != "" {
			args = append(args, "--owner-login", owner)
		}
		var out, errb bytes.Buffer
		code := Main(args, os.Getenv, &out, &errb)
		t.Log(errb.String())
		return code
	}
	if run("") == 0 {
		t.Fatal("the default owner admitted another login")
	}
	if code := run("maintainer"); code != 0 {
		t.Fatalf("exit %d", code)
	}
}

// ---- the pairing predicate, on its own ----

func facts(t *testing.T, mut func(r map[string]any)) ruleFacts {
	t.Helper()
	e := map[string]any{"project": "p", "rule": map[string]any{
		"id": "r", "operator": "forbid_fact",
		"subject":   map[string]any{"component": "kubernetes", "from": "1.24.0", "to": "1.25.0"},
		"condition": map[string]any{"side": "to", "component": "kubernetes", "factId": "f", "boolValue": true},
		"evidence":  map[string]any{"state": "active"}, "reasonCode": "X", "nextAction": "n",
	}}
	if mut != nil {
		mut(ruleOf(e))
	}
	raw, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	f, err := factsOf(&entry{RuleID: "r", Raw: raw})
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func withRange(fromGte, fromLt, toGte, toLt string) func(r map[string]any) {
	return func(r map[string]any) {
		r["range"] = map[string]any{"from": map[string]any{"gte": fromGte, "lt": fromLt}, "to": map[string]any{"gte": toGte, "lt": toLt}}
	}
}

func setRule(members ...string) func(r map[string]any) {
	return func(r map[string]any) {
		r["operator"] = "forbid_set_member"
		delete(r, "condition")
		ms := make([]any, len(members))
		for i, m := range members {
			ms[i] = m
		}
		r["setCondition"] = map[string]any{"side": "to", "component": "kubernetes", "factId": "s", "members": ms}
	}
}

func TestSupersedesPredicate(t *testing.T) {
	cases := []struct {
		name string
		m, r func(r map[string]any)
		want bool
	}{
		{"identical exact", nil, nil, true},
		{"range covers the anchor", withRange("1.24.0", "1.25.0", "1.25.0", "1.26.0"), nil, true},
		{"range covers a range", withRange("1.23.0", "1.25.0", "1.25.0", "1.27.0"), withRange("1.24.0", "1.25.0", "1.25.0", "1.26.0"), true},
		{"equal ranges", withRange("1.24.0", "1.25.0", "1.25.0", "1.26.0"), withRange("1.24.0", "1.25.0", "1.25.0", "1.26.0"), true},
		{"R anchor inside M's range, another anchor", withRange("1.24.0", "1.25.0", "1.25.0", "1.26.0"), func(r map[string]any) {
			r["subject"].(map[string]any)["from"], r["subject"].(map[string]any)["to"] = "1.24.5", "1.25.1"
		}, true},
		{"exact M does not cover a range", nil, withRange("1.24.0", "1.25.0", "1.25.0", "1.26.0"), false},
		{"from partly outside", withRange("1.24.0", "1.25.0", "1.25.0", "1.26.0"), withRange("1.23.0", "1.25.0", "1.25.0", "1.26.0"), false},
		{"to partly outside", withRange("1.24.0", "1.25.0", "1.25.0", "1.26.0"), withRange("1.24.0", "1.25.0", "1.25.0", "1.27.0"), false},
		{"from ends later", withRange("1.24.0", "1.25.0", "1.25.0", "1.26.0"), withRange("1.24.0", "1.26.0", "1.25.0", "1.26.0"), false},
		{"anchor at the open end", withRange("1.23.0", "1.24.0", "1.25.0", "1.26.0"), nil, false},
		{"to anchor at the open end", withRange("1.24.0", "1.25.0", "1.24.0", "1.25.0"), nil, false},
		{"anchor at the closed start", withRange("1.24.0", "1.25.0", "1.25.0", "1.26.0"), func(r map[string]any) {
			r["subject"].(map[string]any)["from"], r["subject"].(map[string]any)["to"] = "1.24.0", "1.25.0"
		}, true},
		{"another exact anchor", func(r map[string]any) { r["subject"].(map[string]any)["to"] = "1.26.0" }, nil, false},
		{"unreadable version covers nothing", withRange("v?", "1.25.0", "1.25.0", "1.26.0"), nil, false},
		{"unreadable end covers nothing", withRange("1.24.0", "latest", "1.25.0", "1.26.0"), nil, false},
		{"other fact", func(r map[string]any) { r["condition"].(map[string]any)["factId"] = "g" }, nil, false},
		{"other side", func(r map[string]any) { r["condition"].(map[string]any)["side"] = "from" }, nil, false},
		{"other fact component", func(r map[string]any) { r["condition"].(map[string]any)["component"] = "etcd" }, nil, false},
		{"other operator", func(r map[string]any) { r["operator"] = "forbid_fact_x" }, nil, false},
		{"other component", func(r map[string]any) { r["subject"].(map[string]any)["component"] = "etcd" }, nil, false},
		{"other bool", func(r map[string]any) { r["condition"].(map[string]any)["boolValue"] = false }, nil, false},
		{"applies when only on M", func(r map[string]any) {
			r["appliesWhen"] = []any{map[string]any{"side": "to", "component": "kubernetes", "factId": "w", "boolValue": true}}
		}, nil, false},
		{"applies when only on R", nil, func(r map[string]any) {
			r["appliesWhen"] = []any{map[string]any{"side": "to", "component": "kubernetes", "factId": "w", "boolValue": true}}
		}, false},
		{"severity differs", func(r map[string]any) { r["severity"] = "unsupported" }, nil, false},
		{"intermediate differs", func(r map[string]any) { r["intermediate"] = "1.24.5" }, nil, false},
		{"different reason, action, id and evidence are fine", func(r map[string]any) {
			r["reasonCode"], r["nextAction"], r["id"] = "Y", "other text", "m"
			r["evidence"] = map[string]any{"state": "active", "basis": "mechanical"}
		}, nil, true},
		{"set superset", setRule("a", "b", "c"), setRule("a", "c"), true},
		{"set equal", setRule("a", "b"), setRule("a", "b"), true},
		{"set not a superset", setRule("a", "b"), setRule("a", "c"), false},
		{"set subset", setRule("a"), setRule("a", "b"), false},
		{"set vs plain", setRule("a"), nil, false},
		{"plain vs set", nil, setRule("a"), false},
		{"set other fact", func(r map[string]any) { setRule("a")(r); r["setCondition"].(map[string]any)["factId"] = "t" }, setRule("a"), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := supersedes(facts(t, tc.m), facts(t, tc.r)); got != tc.want {
				t.Fatalf("supersedes = %v, want %v", got, tc.want)
			}
		})
	}
	t.Run("other project", func(t *testing.T) {
		m, r := facts(t, nil), facts(t, nil)
		m.Project = "q"
		if supersedes(m, r) {
			t.Fatal("a rule of another project supersedes")
		}
	})
}

// The pairing uses the engine's one constraint key.
func TestSupersedeUsesEngineKey(t *testing.T) {
	a, b := facts(t, nil), facts(t, func(r map[string]any) { r["condition"].(map[string]any)["factId"] = "g" })
	if a.Key == b.Key || a.Key == "" {
		t.Fatalf("keys %q %q", a.Key, b.Key)
	}
	if _, err := factsOf(&entry{RuleID: "x", Raw: []byte(`{"rule":"no"}`)}); err == nil {
		t.Fatal("a rule that is not an object was read")
	}
}

// The owner's own commits: a foreign commit on the owner's change, or an
// unusable list, means no pair is admitted.
func TestSupersedeOwnerCommits(t *testing.T) {
	base, head, rs, _ := supersedeCase{ids: pairIDs[:1]}.build(t)
	foreign := loginCommits(ownerLogin, ownerLogin)
	foreign.Commits = append([]CommitRecord{{SHA: "1123456789abcdef0123456789abcdef01234567", Author: &loginField{"collaborator"}, Committer: &loginField{ownerLogin}}}, foreign.Commits...)
	foreign.AheadBy, foreign.TotalCommits = 2, 2
	incomplete := loginCommits(ownerLogin, ownerLogin)
	incomplete.TotalCommits = 2
	notHead := loginCommits(ownerLogin, ownerLogin)
	notHead.Commits[0].SHA = "2123456789abcdef0123456789abcdef01234567"
	behind := loginCommits(ownerLogin, ownerLogin)
	behind.Status = "diverged"
	cases := map[string]struct {
		edit func(o *Options)
		want string
	}{
		"foreign author":     {func(o *Options) { o.Commits = foreign }, "is not authored by the owner"},
		"foreign committer":  {func(o *Options) { o.Commits = loginCommits(ownerLogin, "web-flow") }, "is not committed by the owner"},
		"bot author":         {func(o *Options) { o.Commits = loginCommits(DefaultBotLogin, ownerLogin) }, "is not authored by the owner"},
		"no list":            {func(o *Options) { o.Commits = nil }, "commit list was not supplied"},
		"incomplete list":    {func(o *Options) { o.Commits = incomplete }, "incomplete"},
		"not ending at head": {func(o *Options) { o.Commits = notHead }, "does not end at the head"},
		"no head sha":        {func(o *Options) { o.HeadSHA = "" }, "head commit was not supplied"},
		"not ahead":          {func(o *Options) { o.Commits = behind }, "not strictly ahead"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			opts := ownerOpts(base, head)
			tc.edit(&opts)
			r := runGate(t, opts)
			c := supersedeChange(t, r, ruleID(rs[0]))
			if r.Passed() || c.OK || !strings.Contains(c.Detail, tc.want) || c.SupersededBy == "" {
				t.Fatalf("passed %v, removal %+v", r.Passed(), c)
			}
		})
	}
	// An unsigned list is fine: only authorship is required of the owner.
	requirePass(t, runGate(t, ownerOpts(base, head)))
}

// A rule whose canonical form cannot be computed is never paired.
func TestSupersedeFailsClosedOnCanonicalForm(t *testing.T) {
	old := supersedepred.CanonicalRule
	defer func() { supersedepred.CanonicalRule = old }()
	supersedepred.CanonicalRule = func(any) []byte { return nil }
	if _, err := factsOf(&entry{RuleID: "x", Raw: mustJSON(t, map[string]any{"project": "p", "rule": map[string]any{"id": "x", "operator": "forbid_fact"}})}); err == nil {
		t.Fatal("a rule without a canonical form has facts")
	}
	r, m := synth(t, "R1", "", "active", nil), synth(t, "M1", "mechanical", "active", withRange("1.24.0", "1.25.0", "1.25.0", "1.26.0"))
	pairSupersedes([]*Change{r, m})
	if r.supersededBy != nil {
		t.Fatal("paired although no canonical form exists")
	}
	supersedepred.CanonicalRule = old
	pairSupersedes([]*Change{r, m})
	if r.supersededBy == nil {
		t.Fatal("control: not paired with a canonical form")
	}
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func dependency(comparison, version string) func(r map[string]any) {
	return func(r map[string]any) {
		r["operator"] = "require_component_version"
		delete(r, "condition")
		r["dependency"] = map[string]any{"side": "to", "component": "etcd", "comparison": comparison, "version": version}
	}
}

// A dependency rule is the same constraint only with the same comparison and
// version: a lower minimum version would turn BLOCKED into PASS.
func TestPairSupersedesDependency(t *testing.T) {
	wide := func(dep func(r map[string]any)) func(r map[string]any) {
		return func(r map[string]any) { dep(r); withRange("1.24.0", "1.25.0", "1.25.0", "1.26.0")(r) }
	}
	cases := []struct {
		name string
		r, m func(r map[string]any)
		want bool
	}{
		{"same dependency", dependency("gte", "1.5.0"), wide(dependency("gte", "1.5.0")), true},
		{"only the version differs", dependency("gte", "1.5.0"), wide(dependency("gte", "1.2.0")), false},
		{"only the comparison differs", dependency("gte", "1.5.0"), wide(dependency("gt", "1.5.0")), false},
		{"other dependency component", dependency("gte", "1.5.0"), wide(func(r map[string]any) {
			dependency("gte", "1.5.0")(r)
			r["dependency"].(map[string]any)["component"] = "coredns"
		}), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r, m := synth(t, "R1", "", "active", tc.r), synth(t, "M1", "mechanical", "active", tc.m)
			pairSupersedes([]*Change{r, m})
			if got := r.supersededBy != nil; got != tc.want {
				t.Fatalf("paired = %v, want %v", got, tc.want)
			}
		})
	}
}
