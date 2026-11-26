// SPDX-License-Identifier: AGPL-3.0-only

package knowledgegate

import (
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/cncfcheck"
)

const schemaBoundaryCovered = "prufyx.io/cncf-source-rule-pack/v1alpha16"

// activeRanged returns the first id, in order, of an active reviewed rule
// with a range whose upper target bound is above the patch after its anchor,
// and that patch.
func activeRanged(t *testing.T, tr Tree) (string, string) {
	t.Helper()
	p := readPack(t, tr, cncfRulesPath)
	next := map[string]string{}
	var ids []string
	for _, e := range p.entries {
		ev := evidenceOf(e)
		rng, ok := ruleOf(e)["range"].(map[string]any)
		if !ok || ev["state"] != "active" || ev["basis"] != nil || ev["lease"] != nil {
			continue
		}
		parts := strings.Split(ruleOf(e)["subject"].(map[string]any)["to"].(string), ".")
		if len(parts) != 3 {
			continue
		}
		patch, err := strconv.Atoi(parts[2])
		if err != nil {
			continue
		}
		lt := parts[0] + "." + parts[1] + "." + strconv.Itoa(patch+1)
		if rng["to"].(map[string]any)["lt"] == lt {
			continue
		}
		next[ruleID(e)] = lt
		ids = append(ids, ruleID(e))
	}
	sort.Strings(ids)
	if len(ids) == 0 {
		t.Fatal("no ranged rule to alter")
	}
	return ids[0], next[ids[0]]
}

// narrowRange cuts the upper target bound of a rule's range to the patch
// after its anchor.
func narrowRange(t *testing.T, e map[string]any, lt string) {
	t.Helper()
	rng := ruleOf(e)["range"].(map[string]any)
	rng["to"].(map[string]any)["lt"] = lt
	for _, b := range rng["bounds"].([]any) {
		if bound := b.(map[string]any); bound["bound"] == "to.lt" {
			bound["basis"] = "ANCHOR_ONLY"
			return
		}
	}
	t.Fatal("the range has no to.lt bound")
}

func renewEvidence(e map[string]any) {
	evidenceOf(e)["reviewedAt"] = gateNow.Add(-2 * time.Hour).Format(time.RFC3339)
	evidenceOf(e)["validUntil"] = gateNow.Add(60 * 24 * time.Hour).Format(time.RFC3339)
}

// writeClientPin sets the tree's oldest-supported-client pin.
func writeClientPin(t *testing.T, tr Tree, version string) {
	t.Helper()
	writeFile(t, filepath.Join(tr.Root, filepath.FromSlash(OldestClientPinPath)), []byte("ref="+strings.Repeat("a", 40)+"\nversion="+version+"\n"))
}

// optInFixture raises the head pack to the opt-in level and applies edit, if
// any, to the head's rule id, which the fixture's approval then covers. Both
// trees pin an oldest supported client that reads the level.
func optInFixture(t *testing.T, base, head Tree, id string, edit func(e map[string]any)) signFixture {
	t.Helper()
	writeClientPin(t, base, cncfcheck.BoundaryCoveredFloor)
	writeClientPin(t, head, cncfcheck.BoundaryCoveredFloor)
	editPack(t, head, cncfRulesPath, func(p *packDoc) {
		p.fields["schema"] = []byte(`"` + schemaBoundaryCovered + `"`)
		if edit != nil {
			edit(p.find(t, id))
		}
	})
	return pinFixture(t, base, head, id)
}

func rangeChangeFixture(t *testing.T) signFixture {
	t.Helper()
	base, head := trees(t)
	id, lt := activeRanged(t, base)
	return optInFixture(t, base, head, id, func(e map[string]any) {
		narrowRange(t, e, lt)
		renewEvidence(e)
	})
}

func approveAndRun(t *testing.T, f signFixture) *Report {
	t.Helper()
	requireCode(t, runApproval(t, nil, signNow, f.signArgs("--key", f.key.keyFile(t, 0o600))...), 0, "approval written")
	return runGate(t, Options{Base: f.base, Head: f.head, ApprovalKeysDigest: f.keysDigest, Author: DefaultBotLogin})
}

// The opt-in level beside an owner-approved change of a rule's range is
// admitted, and is still merged by the owner only.
func TestOptInSchemaAdmittedWithOwnerApprovedRangeChange(t *testing.T) {
	t.Parallel()
	f := rangeChangeFixture(t)
	r := approveAndRun(t, f)
	requirePass(t, r)
	if c := schemaChange(t, r); !c.OK || c.Proof != ProofSchemaLevel {
		t.Fatalf("schema change %+v", c)
	}
	if c := change(t, r, f.id); c.Proof != ProofApproval {
		t.Fatalf("rule change %+v", c)
	}
	if r.AutoMerge.Eligible {
		t.Fatal("an opt-in schema change is auto-merge eligible")
	}
}

// Declaring the level alone would change answers with no authority behind it.
func TestOptInSchemaAloneRefused(t *testing.T) {
	t.Parallel()
	base, head := trees(t)
	id, _ := activeRanged(t, base)
	f := optInFixture(t, base, head, id, nil)
	r := runGate(t, Options{Base: f.base, Head: f.head, ApprovalKeysDigest: f.keysDigest})
	requireSchemaRefused(t, r, "opt-in schema level")
}

// A range change without its approval is not authority for the level.
func TestOptInSchemaWithUnapprovedRangeChangeRefused(t *testing.T) {
	t.Parallel()
	f := rangeChangeFixture(t)
	r := runGate(t, Options{Base: f.base, Head: f.head, ApprovalKeysDigest: f.keysDigest})
	requireSchemaRefused(t, r, "not admitted")
}

// An approved rule whose range does not change is not authority for the
// level, whether or not it has a range.
func TestOptInSchemaWithUnrelatedApprovedRuleRefused(t *testing.T) {
	t.Parallel()
	for name, pick := range map[string]func(t *testing.T, tr Tree) string{
		"unranged": func(t *testing.T, tr Tree) string { return readPack(t, tr, cncfRulesPath).activeReviewed()[0] },
		"ranged":   func(t *testing.T, tr Tree) string { id, _ := activeRanged(t, tr); return id },
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			base, head := trees(t)
			f := optInFixture(t, base, head, pick(t, base), renewEvidence)
			r := approveAndRun(t, f)
			if c := change(t, r, f.id); !c.OK || c.Proof != ProofApproval {
				t.Fatalf("rule change %+v", c)
			}
			requireSchemaRefused(t, r, "range changes")
		})
	}
}

// The same range change admits the level only on an owner approval: a
// reattestation, which automation signs, and every other proof do not.
func TestOptInSchemaProofOfTheRangeChange(t *testing.T) {
	t.Parallel()
	f := rangeChangeFixture(t)
	for proof, admitted := range map[string]bool{
		ProofApproval: true, ProofBatchApproval: true,
		ProofReattestation: false, ProofRederived: false, ProofNoneRequired: false, ProofOnboarding: false, ProofSupersede: false,
	} {
		cls, err := Classify(DefaultLayout(), f.base, f.head)
		if err != nil {
			t.Fatal(err)
		}
		var pending []*Change
		for _, c := range cls.Changes {
			switch {
			case c.Member == "schema":
				pending = append(pending, c)
			case c.RuleID == f.id:
				c.OK, c.Proof = true, proof
			default:
				t.Fatalf("unexpected change %+v", c)
			}
		}
		if len(pending) != 1 {
			t.Fatalf("%d schema changes", len(pending))
		}
		admitSchemaChanges(cls, pending, nil, Options{Layout: DefaultLayout(), Base: f.base, Head: f.head})
		c := pending[0]
		if c.OK != admitted || (!admitted && !strings.Contains(c.Detail, "range changes")) {
			t.Fatalf("%s: schema change %+v, admitted want %v", proof, c, admitted)
		}
	}
}

// A complete, approved range change is still refused unless the oldest
// supported client of both the base and the head reads the level.
func TestOptInSchemaClientFloorRefused(t *testing.T) {
	t.Parallel()
	const old, floor = "v0.1.0-beta.0", cncfcheck.BoundaryCoveredFloor
	set := func(version string) func(t *testing.T, tr Tree) {
		return func(t *testing.T, tr Tree) { writeClientPin(t, tr, version) }
	}
	raw := func(content string) func(t *testing.T, tr Tree) {
		return func(t *testing.T, tr Tree) {
			writeFile(t, filepath.Join(tr.Root, filepath.FromSlash(OldestClientPinPath)), []byte(content))
		}
	}
	missing := func(t *testing.T, tr Tree) {
		if err := os.Remove(filepath.Join(tr.Root, filepath.FromSlash(OldestClientPinPath))); err != nil {
			t.Fatal(err)
		}
	}
	for name, tc := range map[string]struct {
		base, head func(t *testing.T, tr Tree)
		want       string
	}{
		"both below":           {set(old), set(old), "the base still supports client " + old},
		"only the head raises": {set(old), set(floor), "the base still supports client " + old},
		"head below":           {set(floor), set(old), "the head still supports client " + old},
		"base missing":         {missing, set(floor), "the base's oldest supported client pin"},
		"head missing":         {set(floor), missing, "the head's oldest supported client pin"},
		"base unparsable":      {raw("version=" + floor + "\n"), set(floor), "the base's oldest supported client pin"},
		"head unparsable":      {set(floor), raw("junk\n"), "the head's oldest supported client pin"},
		"base not a version":   {set("latest"), set(floor), "the base's oldest supported client pin"},
		"head not a version":   {set(floor), set(""), "the head's oldest supported client pin"},
		"base one release low": {set("v0.1.0-beta.2"), set(floor), "the base still supports client v0.1.0-beta.2"},
		"base no v prefix":     {set("0.2.0"), set(floor), "the base's oldest supported client pin"},
		"head no v prefix":     {set(floor), set("0.2.0"), "the head's oldest supported client pin"},
		"head build metadata":  {set(floor), set("v0.2.0+build"), "the head's oldest supported client pin"},
		"head bare prerelease": {set(floor), set("v0.2.0-rc"), "the head's oldest supported client pin"},
		"base short ref":       {raw("ref=abc\nversion=" + floor + "\n"), set(floor), "the base's oldest supported client pin"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			f := rangeChangeFixture(t)
			tc.base(t, f.base)
			tc.head(t, f.head)
			r := approveAndRun(t, f)
			if c := change(t, r, f.id); !c.OK || c.Proof != ProofApproval {
				t.Fatalf("rule change %+v", c)
			}
			requireSchemaRefused(t, r, tc.want)
		})
	}
}

// A client pin above the floor admits the level too.
func TestOptInSchemaAdmittedAboveClientFloor(t *testing.T) {
	t.Parallel()
	f := rangeChangeFixture(t)
	writeClientPin(t, f.base, "v0.1.0")
	writeClientPin(t, f.head, "v0.1.0")
	r := approveAndRun(t, f)
	requirePass(t, r)
	if c := schemaChange(t, r); !c.OK || c.Proof != ProofSchemaLevel {
		t.Fatalf("schema change %+v", c)
	}
}

// A pack at the opt-in level is not lowered again.
func TestOptInSchemaLoweringRefused(t *testing.T) {
	t.Parallel()
	base, head := trees(t)
	editPack(t, base, cncfRulesPath, func(p *packDoc) {
		p.fields["schema"] = []byte(`"` + schemaBoundaryCovered + `"`)
	})
	r := runGate(t, Options{Base: base, Head: head})
	requireSchemaRefused(t, r, "not raised")
}

// While a pack is at the opt-in level, a later change that lowers, removes or
// breaks the oldest supported client pin fails the gate; one that keeps or
// raises it passes. A pack at any other level is not held to this floor.
func TestOptInSchemaLaterPinChange(t *testing.T) {
	t.Parallel()
	const old, floor, name = "v0.1.0-beta.0", cncfcheck.BoundaryCoveredFloor, "opt-in-client-pin/cncf"
	pinPath := func(tr Tree) string { return filepath.Join(tr.Root, filepath.FromSlash(OldestClientPinPath)) }
	set := func(version string) func(t *testing.T, tr Tree) {
		return func(t *testing.T, tr Tree) { writeClientPin(t, tr, version) }
	}
	raw := func(content string) func(t *testing.T, tr Tree) {
		return func(t *testing.T, tr Tree) { writeFile(t, pinPath(tr), []byte(content)) }
	}
	missing := func(t *testing.T, tr Tree) {
		if err := os.Remove(pinPath(tr)); err != nil {
			t.Fatal(err)
		}
	}
	for label, tc := range map[string]struct {
		head func(t *testing.T, tr Tree)
		want string // empty: admitted
	}{
		"unchanged":     {set(floor), ""},
		"raised":        {set("v0.1.0"), ""},
		"lowered":       {set(old), "the head still supports client " + old},
		"removed":       {missing, "the head's oldest supported client pin"},
		"unparsable":    {raw("junk\n"), "the head's oldest supported client pin"},
		"no ref line":   {raw("version=" + floor + "\n"), "the head's oldest supported client pin"},
		"not a version": {set("latest"), "the head's oldest supported client pin"},
		"too large":     {raw(strings.Repeat("a", 2048)), "the head's oldest supported client pin"},
		"no v prefix":   {set("0.2.0"), "the head's oldest supported client pin"},
		"build suffix":  {set("v0.2.0+build"), "the head's oldest supported client pin"},
		"bare rc":       {set("v0.2.0-rc"), "the head's oldest supported client pin"},
		"empty ref":     {raw("ref=\nversion=" + floor + "\n"), "the head's oldest supported client pin"},
	} {
		t.Run(label, func(t *testing.T) {
			t.Parallel()
			base, head := trees(t)
			for _, tr := range []Tree{base, head} {
				writeClientPin(t, tr, floor)
				editPack(t, tr, cncfRulesPath, func(p *packDoc) {
					p.fields["schema"] = []byte(`"` + schemaBoundaryCovered + `"`)
				})
			}
			tc.head(t, head)
			r := runGate(t, Options{Base: base, Head: head})
			c, ok := check(r, name)
			if !ok || c.OK != (tc.want == "") || !strings.Contains(c.Detail, tc.want) {
				t.Fatalf("check %+v, present %v, want %q", c, ok, tc.want)
			}
			if tc.want != "" {
				requireFail(t, r, tc.want)
			}
		})
	}
	t.Run("other level", func(t *testing.T) {
		t.Parallel()
		for label, change := range map[string]func(t *testing.T, tr Tree){"lowered": set(old), "removed": missing, "unparsable": raw("junk\n")} {
			base, head := trees(t)
			change(t, head)
			r := runGate(t, Options{Base: base, Head: head})
			if c, ok := check(r, name); ok {
				t.Fatalf("%s: a pack at another level got the check %+v", label, c)
			}
			requirePass(t, r)
		}
	})
}

// The opt-in pin form is the publication workflow's: the same two
// expressions, and nothing the workflow refuses is read.
func TestPublishPinForm(t *testing.T) {
	t.Parallel()
	workflow, err := os.ReadFile(filepath.Join("..", "..", "..", "..", ".github", "workflows", "knowledge-publish.yml"))
	if err != nil {
		t.Fatal(err)
	}
	for _, re := range []string{publishPinRefRE.String(), publishPinVersionRE.String()} {
		if !strings.Contains(string(workflow), "=~ "+re+" ]]") {
			t.Fatalf("the publication workflow does not match the pin with %s", re)
		}
	}
	ref := "ref=" + strings.Repeat("a", 40)
	for _, version := range []string{"v0.1.0", "v1.2.3", "v0.1.0-beta.3", "v0.2.0-rc.1"} {
		for _, end := range []string{"", "\n"} {
			if got, err := publishPinVersion([]byte(ref + "\nversion=" + version + end)); err != nil || got != version {
				t.Fatalf("%q: %q, %v", version, got, err)
			}
		}
	}
	good := "version=v0.2.0"
	for _, raw := range []string{
		"", ref, good, good + "\n" + ref, ref + "\n" + good + "\n\n", ref + "\n" + good + "\nx\n", "\n" + ref + "\n" + good,
		ref + "\r\n" + good, ref + "\n" + good + "\r\n", ref + "\n" + good + " ", ref + " \n" + good,
		"ref=\n" + good, "ref=abc\n" + good, "ref=" + strings.Repeat("A", 40) + "\n" + good, ref + "a\n" + good,
		ref + "\nversion=", ref + "\nversion=0.2.0", ref + "\nversion=v0.2", ref + "\nversion=v00.2.0", ref + "\nversion=v0.2.0+build",
		ref + "\nversion=v0.2.0-beta.3+build", ref + "\nversion=v0.2.0-rc", ref + "\nversion=v0.2.0-rc1", ref + "\nversion=v0.2.0-beta.1.2",
		ref + "\nversion=v0.2.0-beta-x.1", ref + "\nversion=latest",
	} {
		if got, err := publishPinVersion([]byte(raw)); err == nil {
			t.Fatalf("%q accepted as %q", raw, got)
		}
	}
}

// Only admitted changes of an existing rule of the same pack count, and only
// when they add or alter its range.
func TestOptInSchemaAuthority(t *testing.T) {
	t.Parallel()
	ent := func(rng string) *entry {
		raw := `{"rule":{"id":"r"}}`
		if rng != "" {
			raw = `{"rule":{"id":"r","range":` + rng + `}}`
		}
		generic, err := decodeGeneric([]byte(raw))
		if err != nil {
			t.Fatal(err)
		}
		e := &entry{RuleID: "r", generic: generic}
		if rng != "" {
			e.Range = []byte(rng)
		}
		return e
	}
	one, two := `{"from":{"gte":"1.0.0"}}`, `{"from":{"gte":"1.0.1"}}`
	rule := func(proof string, base, head *entry) *Change {
		return &Change{Pack: "cncf", RuleID: "r", OK: true, Proof: proof, base: base, head: head}
	}
	counts := func(c *Change) bool {
		return ownerApprovedRangeChange(&Classification{Changes: []*Change{c}}, "cncf")
	}
	for name, c := range map[string]*Change{
		"altered":       rule(ProofApproval, ent(one), ent(two)),
		"added":         rule(ProofApproval, ent(""), ent(one)),
		"batch altered": rule(ProofBatchApproval, ent(one), ent(two)),
	} {
		if !counts(c) {
			t.Fatalf("%s not counted", name)
		}
	}
	changed := func(edit func(c *Change)) *Change {
		c := rule(ProofApproval, ent(one), ent(two))
		edit(c)
		return c
	}
	for name, c := range map[string]*Change{
		"same range":    rule(ProofApproval, ent(one), ent(one)),
		"no range":      rule(ProofApproval, ent(""), ent("")),
		"range removed": rule(ProofApproval, ent(one), ent("")),
		"range null":    rule(ProofApproval, ent(one), ent("null")),
		"new rule":      rule(ProofApproval, nil, ent(one)),
		"removed rule":  rule(ProofApproval, ent(one), nil),
		"reattestation": rule(ProofReattestation, ent(one), ent(two)),
		"rederived":     rule(ProofRederived, ent(one), ent(two)),
		"not admitted":  changed(func(c *Change) { c.OK = false }),
		"other pack":    changed(func(c *Change) { c.Pack = "community" }),
		"record":        changed(func(c *Change) { c.Section = "lineAttestations" }),
		"member":        changed(func(c *Change) { c.Member = "schema" }),
		"no rule id":    changed(func(c *Change) { c.RuleID = "" }),
	} {
		if counts(c) {
			t.Fatalf("%s counted", name)
		}
	}
}
