// SPDX-License-Identifier: AGPL-3.0-only

package knowledgegate

import (
	"encoding/json"
	"reflect"
	"testing"
)

func entryFrom(t *testing.T, e map[string]any) *entry {
	t.Helper()
	raw, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	tr := Tree{Root: dir}
	doc, _ := json.Marshal(map[string]any{"entries": []json.RawMessage{raw}})
	writeFile(t, dir+"/p.json", doc)
	p, err := loadPack(tr, PackSpec{Name: "x", Path: "p.json"})
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range p.Entries {
		return v
	}
	t.Fatal("no entry")
	return nil
}

// TestClassifyTable covers every class and kind with edits of a real
// reviewed rule (with a range) from the shipped CNCF pack.
func TestClassifyTable(t *testing.T) {
	tr := copyKnowledge(t)
	p := readPack(t, tr, cncfRulesPath)
	var ranged, plain map[string]any
	for _, e := range p.entries {
		if evidenceOf(e)["state"] != "active" {
			continue
		}
		if ruleOf(e)["range"] != nil && ranged == nil {
			ranged = e
		}
		if ruleOf(e)["range"] == nil && plain == nil {
			plain = e
		}
	}
	type edit func(e map[string]any)
	setEv := func(k string, v any) edit { return func(e map[string]any) { evidenceOf(e)[k] = v } }
	cases := []struct {
		name  string
		base  map[string]any
		edits []edit
		class string
		kinds []string
	}{
		{"withdraw", plain, []edit{setEv("state", "withdrawn")}, ClassTightening, []string{KindWithdraw}},
		{"expire", plain, []edit{func(e map[string]any) { evidenceOf(e)["validUntil"] = shiftTime(t, evidenceOf(e)["validUntil"], -240*3600e9) }}, ClassTightening, []string{KindExpire}},
		{"withdraw and expire", plain, []edit{setEv("state", "withdrawn"), func(e map[string]any) { evidenceOf(e)["validUntil"] = shiftTime(t, evidenceOf(e)["validUntil"], -3600e9) }}, ClassTightening, []string{KindWithdraw, KindExpire}},
		{"renew", plain, []edit{func(e map[string]any) { evidenceOf(e)["validUntil"] = shiftTime(t, evidenceOf(e)["validUntil"], 3600e9) }}, ClassLoosening, []string{KindRenew}},
		{"reviewedAt only", plain, []edit{func(e map[string]any) { evidenceOf(e)["reviewedAt"] = shiftTime(t, evidenceOf(e)["reviewedAt"], 3600e9) }}, ClassLoosening, []string{KindRenew}},
		{"reactivate", withState(plain, "withdrawn"), []edit{setEv("state", "active")}, ClassLoosening, []string{KindReactivate}},
		{"unknown state", plain, []edit{setEv("state", "paused")}, ClassLoosening, []string{KindModify}},
		{"repin", plain, []edit{func(e map[string]any) {
			src := evidenceOf(e)["sources"].([]any)[0].(map[string]any)
			src["endLine"] = json.Number("9999")
		}}, ClassLoosening, []string{KindRepin}},
		{"text", plain, []edit{func(e map[string]any) { ruleOf(e)["nextAction"] = "Do something else." }}, ClassLoosening, []string{KindModify}},
		{"description", plain, []edit{func(e map[string]any) { e["description"] = "Other." }}, ClassLoosening, []string{KindModify}},
		{"withdraw plus text", plain, []edit{setEv("state", "withdrawn"), func(e map[string]any) { ruleOf(e)["nextAction"] = "Other." }}, ClassLoosening, []string{KindWithdraw, KindModify}},
		{"basis", plain, []edit{setEv("basis", "reviewed")}, ClassLoosening, []string{KindBasis}},
		{"narrow by removing the range", ranged, []edit{func(e map[string]any) { delete(ruleOf(e), "range") }}, ClassLoosening, []string{KindNarrow}},
		{"narrow a bound", ranged, []edit{func(e map[string]any) {
			r := ruleOf(e)["range"].(map[string]any)
			r["to"].(map[string]any)["lt"] = r["to"].(map[string]any)["gte"].(string)[:len(r["to"].(map[string]any)["gte"].(string))-1] + "5"
		}}, ClassLoosening, []string{KindNarrow}},
		{"widen", plain, []edit{func(e map[string]any) {
			ruleOf(e)["range"] = map[string]any{"from": map[string]any{"gte": "0.0.0", "lt": "99.0.0"}, "to": map[string]any{"gte": "0.0.0", "lt": "99.0.0"}, "bounds": []any{}}
		}}, ClassLoosening, []string{KindWiden}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b := deepCopy(tc.base).(map[string]any)
			h := deepCopy(tc.base).(map[string]any)
			for _, e := range tc.edits {
				e(h)
			}
			class, kinds := classifyEdit(entryFrom(t, b), entryFrom(t, h))
			if class != tc.class || !reflect.DeepEqual(kinds, tc.kinds) {
				t.Fatalf("got %s %v, want %s %v", class, kinds, tc.class, tc.kinds)
			}
		})
	}
}

func withState(e map[string]any, state string) map[string]any {
	c := deepCopy(e).(map[string]any)
	evidenceOf(c)["state"] = state
	return c
}

// TestClassifyAddRemove covers rules present in only one pack.
func TestClassifyAddRemove(t *testing.T) {
	base, head := trees(t)
	p := readPack(t, base, cncfRulesPath)
	ids := p.activeReviewed()
	editPack(t, head, cncfRulesPath, func(p *packDoc) {
		removed := ids[0]
		var kept []map[string]any
		for _, e := range p.entries {
			if ruleID(e) != removed {
				kept = append(kept, e)
			}
		}
		added := deepCopy(p.find(t, ids[1])).(map[string]any)
		ruleOf(added)["id"] = ids[1] + "-copy"
		addedWithdrawn := deepCopy(p.find(t, ids[2])).(map[string]any)
		ruleOf(addedWithdrawn)["id"] = ids[2] + "-copy"
		evidenceOf(addedWithdrawn)["state"] = "withdrawn"
		p.entries = append(kept, added, addedWithdrawn)
		p.sortByID()
	})
	cls, err := Classify(DefaultLayout(), base, head)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, c := range cls.Changes {
		got[c.RuleID] = c.Class + " " + c.Kinds[0]
	}
	want := map[string]string{
		ids[0]:           ClassLoosening + " " + KindRemove,
		ids[1] + "-copy": ClassLoosening + " " + KindNew,
		ids[2] + "-copy": ClassTightening + " " + KindAddWithdrawn,
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	if tight, loose := cls.Counts(); tight != 1 || loose != 2 {
		t.Fatalf("counts %d %d", tight, loose)
	}
}
