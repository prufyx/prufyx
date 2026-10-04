// SPDX-License-Identifier: AGPL-3.0-only

package knowledgegate

import (
	"encoding/json"
	"slices"
	"testing"
	"time"
)

// recordPair loads the synthetic record pack as base and a copy changed by
// edit as head, and returns the change of record id (nil when none).
func recordPair(t *testing.T, edit func(doc map[string]any)) (*loadedPack, *loadedPack) {
	t.Helper()
	raw, _, _ := recordPack(t, gateNow, false)
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	edit(doc)
	headRaw, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	load := func(raw []byte) *loadedPack {
		root := t.TempDir()
		writeFile(t, root+"/"+synthPackPath, raw)
		p, err := loadPack(Tree{Root: root}, recordLayout().Packs[0])
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	return load(raw), load(headRaw)
}

func recordChange(t *testing.T, base, head *loadedPack, id string) *Change {
	t.Helper()
	var out *Change
	for _, c := range diffPacks(base, head) {
		if c.Member != "" {
			t.Fatalf("pack-member change %+v", c)
		}
		if c.RuleID == id {
			out = c
		}
	}
	return out
}

func TestClassifyRecordEdits(t *testing.T) {
	ev := func(doc map[string]any, section string) map[string]any {
		return sectionRecord(doc, section, 0)["evidence"].(map[string]any)
	}
	shift := func(m map[string]any, field string, d time.Duration) { m[field] = shiftTime(t, m[field], d) }
	const att, pol = "lineAttestations", "pathPolicies"
	for name, tc := range map[string]struct {
		section string
		edit    func(doc map[string]any)
		class   string
		kinds   []string
		renewal bool
	}{
		"attestation expires earlier": {att, func(d map[string]any) { shift(ev(d, att), "validUntil", -time.Hour) }, ClassTightening, []string{KindExpire}, false},
		"attestation renewed": {att, func(d map[string]any) {
			shift(ev(d, att), "reviewedAt", time.Hour)
			shift(ev(d, att), "validUntil", time.Hour)
		}, ClassLoosening, []string{KindRenew}, true},
		"attestation reviewed later, ends earlier": {att, func(d map[string]any) {
			shift(ev(d, att), "reviewedAt", time.Hour)
			shift(ev(d, att), "validUntil", -time.Hour)
		}, ClassLoosening, []string{KindExpire, KindRenew}, false},
		"attestation backdated renewal": {att, func(d map[string]any) {
			shift(ev(d, att), "reviewedAt", -time.Hour)
			shift(ev(d, att), "validUntil", time.Hour)
		}, ClassLoosening, []string{KindRenew}, false},
		"attestation lease only": {att, func(d map[string]any) { shift(ev(d, att), "validUntil", time.Hour) }, ClassLoosening, []string{KindRenew}, false},
		"attestation renewed and repinned": {att, func(d map[string]any) {
			shift(ev(d, att), "reviewedAt", time.Hour)
			shift(ev(d, att), "validUntil", time.Hour)
			ev(d, att)["sources"].([]any)[0].(map[string]any)["endLine"] = json.Number("1")
		}, ClassLoosening, []string{KindRenew, KindRepin}, false},
		"attestation rule list": {att, func(d map[string]any) { sectionRecord(d, att, 0)["ruleIds"] = []any{"a.rule"} }, ClassLoosening, []string{KindModify}, false},
		"policy withdrawn":      {pol, func(d map[string]any) { ev(d, pol)["state"] = "withdrawn" }, ClassTightening, []string{KindWithdraw}, false},
		"policy withdrawn and expires": {pol, func(d map[string]any) {
			ev(d, pol)["state"] = "withdrawn"
			shift(ev(d, pol), "validUntil", -time.Hour)
		}, ClassTightening, []string{KindWithdraw, KindExpire}, false},
		"policy renewed": {pol, func(d map[string]any) {
			shift(ev(d, pol), "reviewedAt", time.Hour)
			shift(ev(d, pol), "validUntil", time.Hour)
		}, ClassLoosening, []string{KindRenew}, true},
		"policy renewed while withdrawn": {pol, func(d map[string]any) {
			ev(d, pol)["state"] = "withdrawn"
			shift(ev(d, pol), "reviewedAt", time.Hour)
			shift(ev(d, pol), "validUntil", time.Hour)
		}, ClassLoosening, []string{KindWithdraw, KindRenew}, false},
		"policy renewed and changed": {pol, func(d map[string]any) {
			shift(ev(d, pol), "reviewedAt", time.Hour)
			shift(ev(d, pol), "validUntil", time.Hour)
			sectionRecord(d, pol, 0)["policy"] = "direct"
		}, ClassLoosening, []string{KindRenew, KindModify}, false},
		"policy renewed and basis named": {pol, func(d map[string]any) {
			shift(ev(d, pol), "reviewedAt", time.Hour)
			shift(ev(d, pol), "validUntil", time.Hour)
			ev(d, pol)["basis"] = "reviewed"
		}, ClassLoosening, []string{KindRenew, KindBasis}, false},
		"policy changed":     {pol, func(d map[string]any) { sectionRecord(d, pol, 0)["policy"] = "direct" }, ClassLoosening, []string{KindModify}, false},
		"policy basis named": {pol, func(d map[string]any) { ev(d, pol)["basis"] = "reviewed" }, ClassLoosening, []string{KindBasis}, false},
		"policy withdrawn and changed": {pol, func(d map[string]any) {
			ev(d, pol)["state"] = "withdrawn"
			sectionRecord(d, pol, 0)["policy"] = "direct"
		}, ClassLoosening, []string{KindWithdraw, KindModify}, false},
	} {
		t.Run(name, func(t *testing.T) {
			base, head := recordPair(t, tc.edit)
			id := reviewedAttestationID
			if tc.section == pol {
				id = reviewedPolicyID
			}
			c := recordChange(t, base, head, id)
			if c == nil || c.Class != tc.class || !slices.Equal(c.Kinds, tc.kinds) || c.renewal != tc.renewal || c.Section != tc.section {
				t.Fatalf("change %+v renewal=%v, want %s %v renewal=%v", c, c != nil && c.renewal, tc.class, tc.kinds, tc.renewal)
			}
		})
	}

	// Removal: tightening for an attestation, loosening for a policy.
	base, head := recordPair(t, func(d map[string]any) {
		d["lineAttestations"] = []any{}
		delete(d, "lineAttestations")
	})
	if c := recordChange(t, base, head, reviewedAttestationID); c == nil || c.Class != ClassTightening || c.Kinds[0] != KindRemove {
		t.Fatalf("attestation removal %+v", c)
	}
	base, head = recordPair(t, func(d map[string]any) { delete(d, "pathPolicies") })
	if c := recordChange(t, base, head, reviewedPolicyID); c == nil || c.Class != ClassLoosening || c.Kinds[0] != KindRemove {
		t.Fatalf("policy removal %+v", c)
	}
	// Addition: loosening, even of a withdrawn policy.
	base, head = recordPair(t, func(d map[string]any) {
		p := deepCopy(sectionRecord(d, "pathPolicies", 0)).(map[string]any)
		p["component"] = "pkg:github/kubernetes/kubectl"
		p["evidence"].(map[string]any)["state"] = "withdrawn"
		d["pathPolicies"] = []any{p, sectionRecord(d, "pathPolicies", 0)}
	})
	for _, c := range diffPacks(base, head) {
		if c.Class != ClassLoosening || c.Kinds[0] != KindNew {
			t.Fatalf("addition %+v", c)
		}
	}
	// Unchanged bytes in another spelling: no change.
	base, head = recordPair(t, func(d map[string]any) {})
	if cs := diffPacks(base, head); len(cs) != 0 {
		t.Fatalf("changes %+v", cs)
	}
}

// A record section that differs while no record does is a pack-member
// change: the section never changes unseen.
func TestRecordSectionFallsBackToMemberChange(t *testing.T) {
	base, head := recordPair(t, func(d map[string]any) {})
	head.Members["lineAttestations"] = json.RawMessage(`[]`)
	var member bool
	for _, c := range diffPacks(base, head) {
		if c.Member == "lineAttestations" && c.Class == ClassLoosening {
			member = true
		}
	}
	if !member {
		t.Fatal("no pack-member change for the section")
	}
}

// A pack whose records cannot be read is refused, never read as having
// none.
func TestLoadPackRefusesUnreadableRecords(t *testing.T) {
	raw, _, _ := recordPack(t, gateNow, false)
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	doc["pathPolicies"] = []any{}
	bad, _ := json.Marshal(doc)
	root := t.TempDir()
	writeFile(t, root+"/"+synthPackPath, bad)
	if _, err := loadPack(Tree{Root: root}, recordLayout().Packs[0]); err == nil {
		t.Fatal("an empty path-policy section was read")
	}
	if _, err := loadPack(Tree{Root: root}, synthLayout().Packs[0]); err != nil {
		t.Fatalf("a pack read without records: %v", err)
	}
}

// The signed fields of an approval: a rule approval names no subject and no
// scope; a record approval names a known subject and a well-formed scope.
func TestApprovalRecordSubjectAndScope(t *testing.T) {
	base := ApprovalRecord{BaseDigest: ApprovalBaseAbsent, CandidateDigest: "sha256:0000000000000000000000000000000000000000000000000000000000000000",
		CandidateID: "cand-1", DecidedAt: "2026-10-03T11:00:00Z", Decision: "approve", Identity: "airstand", Pack: "cncf", RuleID: "line-attestation.000000000000000000000000"}
	good := base
	good.Subject, good.Scope = ApprovalSubjectLineAttestation, recordComponent+" kubernetes.removed_served_gvk 1.33"
	if _, err := SignedApprovalBytes(base); err != nil {
		t.Fatalf("rule approval: %v", err)
	}
	if _, err := SignedApprovalBytes(good); err != nil {
		t.Fatalf("record approval: %v", err)
	}
	for name, edit := range map[string]func(r *ApprovalRecord){
		"scope without subject":   func(r *ApprovalRecord) { r.Subject = "" },
		"subject without scope":   func(r *ApprovalRecord) { r.Scope = "" },
		"unknown subject":         func(r *ApprovalRecord) { r.Subject = "pathPolicy" },
		"scope without a line":    func(r *ApprovalRecord) { r.Scope = recordComponent + " kubernetes.removed_served_gvk" },
		"scope with a newline":    func(r *ApprovalRecord) { r.Scope = recordComponent + " kubernetes.removed_served_gvk\n1.33" },
		"scope not a package URL": func(r *ApprovalRecord) { r.Scope = "kubernetes kubernetes.removed_served_gvk 1.33" },
	} {
		t.Run(name, func(t *testing.T) {
			r := good
			edit(&r)
			if _, err := SignedApprovalBytes(r); err == nil {
				t.Fatal("accepted")
			}
		})
	}
}
