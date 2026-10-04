// SPDX-License-Identifier: AGPL-3.0-only

package knowledgegate

import (
	"slices"
	"testing"
)

// Support-range rules (severity unsupported): adding or removing a
// severity, or changing a severity rule's reason code, is loosening (each
// needs a proof); withdrawing a severity rule is tightening. These pin the
// classification so that no later change treats adding a severity as
// tightening.
func TestClassifySeverityChanges(t *testing.T) {
	const id = "fluentd.ruby-minimum-target.1-14-6-to-1-19-3"
	set := func(sev bool, reason, state string) func(p *packDoc) {
		return func(p *packDoc) {
			r := ruleOf(p.find(t, id))
			delete(r, "severity")
			if sev {
				r["severity"] = "unsupported"
			}
			if reason != "" {
				r["reasonCode"] = reason
			}
			if state != "" {
				evidenceOf(p.find(t, id))["state"] = state
			}
		}
	}
	for name, tc := range map[string]struct {
		base, head func(p *packDoc)
		class      string
		kinds      []string
	}{
		"add severity":                 {set(false, "", ""), set(true, "", ""), ClassLoosening, []string{KindModify}},
		"remove severity":              {set(true, "", ""), set(false, "", ""), ClassLoosening, []string{KindModify}},
		"change a severity reason":     {set(true, "", ""), set(true, "REVIEWED_SUPPORT_RANGE", ""), ClassLoosening, []string{KindModify}},
		"add severity and withdraw":    {set(false, "", ""), set(true, "", "withdrawn"), ClassLoosening, []string{KindWithdraw, KindModify}},
		"withdraw a severity rule":     {set(true, "", ""), set(true, "", "withdrawn"), ClassTightening, []string{KindWithdraw}},
		"withdraw, severity unchanged": {set(false, "", ""), set(false, "", "withdrawn"), ClassTightening, []string{KindWithdraw}},
	} {
		t.Run(name, func(t *testing.T) {
			base, head := trees(t)
			for _, x := range []struct {
				tr   Tree
				edit func(p *packDoc)
			}{{base, tc.base}, {head, tc.head}} {
				p := readPack(t, x.tr, cncfRulesPath)
				x.edit(p)
				p.write(t, x.tr, cncfRulesPath)
			}
			cls, err := Classify(DefaultLayout(), base, head)
			if err != nil {
				t.Fatal(err)
			}
			var got *Change
			for _, c := range cls.Changes {
				if c.RuleID == id {
					got = c
				} else if c.Member == "" {
					t.Fatalf("unexpected change %+v", c)
				}
			}
			if got == nil || got.Class != tc.class || !slices.Equal(got.Kinds, tc.kinds) {
				t.Fatalf("change %+v, want %s %v", got, tc.class, tc.kinds)
			}
		})
	}
}
