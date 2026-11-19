// SPDX-License-Identifier: AGPL-3.0-only

package scanreport

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

const jumpDigest = "sha256:1111111111111111111111111111111111111111111111111111111111111111"

func jh(index int, from, to, status string) JumpHop {
	h := JumpHop{Index: index, From: from, To: to, Status: status, ObjectSetDigest: jumpDigest}
	switch status {
	case JumpHopBlocked:
		h.RuleIDs = []string{"x.crd-version-removal.a"}
	case JumpHopAttention:
		h.Entries = []string{"changelog 1.2.0: removed flag --x"}
	}
	return h
}

func TestComposeJump(t *testing.T) {
	t.Parallel()
	other := jh(2, "1.1.0", "1.2.0", JumpHopPass)
	other.ObjectSetDigest = "sha256:2222222222222222222222222222222222222222222222222222222222222222"
	blockedNoRule := jh(2, "1.1.0", "1.2.0", JumpHopBlocked)
	blockedNoRule.RuleIDs = nil
	attentionNoEntry := jh(2, "1.1.0", "1.2.0", JumpHopAttention)
	attentionNoEntry.Entries = nil
	broken := jh(2, "1.5.0", "1.6.0", JumpHopPass)
	badIndex := jh(3, "1.1.0", "1.2.0", JumpHopPass)
	cases := map[string]struct {
		hops   []JumpHop
		digest string
		want   string
		by     []int
	}{
		"all pass":                  {[]JumpHop{jh(1, "1.0.0", "1.1.0", JumpHopPass), jh(2, "1.1.0", "1.2.0", JumpHopPass)}, jumpDigest, JumpStepwisePass, []int{1, 2}},
		"one undecided":             {[]JumpHop{jh(1, "1.0.0", "1.1.0", JumpHopPass), jh(2, "1.1.0", "1.2.0", JumpHopUndecided)}, jumpDigest, JumpUnknown, []int{}},
		"block wins over undecided": {[]JumpHop{jh(1, "1.0.0", "1.1.0", JumpHopUndecided), jh(2, "1.1.0", "1.2.0", JumpHopBlocked)}, jumpDigest, JumpBlocked, []int{2}},
		"block wins over attention": {[]JumpHop{jh(1, "1.0.0", "1.1.0", JumpHopAttention), jh(2, "1.1.0", "1.2.0", JumpHopBlocked)}, jumpDigest, JumpBlocked, []int{2}},
		"attention over pass":       {[]JumpHop{jh(1, "1.0.0", "1.1.0", JumpHopPass), jh(2, "1.1.0", "1.2.0", JumpHopAttention)}, jumpDigest, JumpAttention, []int{2}},
		"attention with undecided":  {[]JumpHop{jh(1, "1.0.0", "1.1.0", JumpHopUndecided), jh(2, "1.1.0", "1.2.0", JumpHopAttention)}, jumpDigest, JumpAttention, []int{2}},
		"other object set":          {[]JumpHop{jh(1, "1.0.0", "1.1.0", JumpHopPass), other}, jumpDigest, JumpUnknown, []int{}},
		"no digest":                 {[]JumpHop{jh(1, "1.0.0", "1.1.0", JumpHopPass), jh(2, "1.1.0", "1.2.0", JumpHopPass)}, "", JumpUnknown, []int{}},
		"block without rule":        {[]JumpHop{jh(1, "1.0.0", "1.1.0", JumpHopPass), blockedNoRule}, jumpDigest, JumpUnknown, []int{}},
		"attention without entry":   {[]JumpHop{jh(1, "1.0.0", "1.1.0", JumpHopPass), attentionNoEntry}, jumpDigest, JumpUnknown, []int{}},
		"unknown status":            {[]JumpHop{jh(1, "1.0.0", "1.1.0", JumpHopPass), jh(2, "1.1.0", "1.2.0", "PASS ")}, jumpDigest, JumpUnknown, []int{}},
		"empty status":              {[]JumpHop{jh(1, "1.0.0", "1.1.0", JumpHopPass), jh(2, "1.1.0", "1.2.0", "")}, jumpDigest, JumpUnknown, []int{}},
		"broken chain":              {[]JumpHop{jh(1, "1.0.0", "1.1.0", JumpHopPass), broken}, jumpDigest, JumpUnknown, []int{}},
		"bad index":                 {[]JumpHop{jh(1, "1.0.0", "1.1.0", JumpHopPass), badIndex}, jumpDigest, JumpUnknown, []int{}},
		"no hops":                   {nil, jumpDigest, JumpUnknown, []int{}},
	}
	for name, tc := range cases {
		got, by := ComposeJump(tc.hops, tc.digest)
		if got != tc.want || !reflect.DeepEqual(by, tc.by) {
			t.Errorf("%s: %s %v, want %s %v", name, got, by, tc.want, tc.by)
		}
		if got == JumpStepwisePass && tc.want != JumpStepwisePass {
			t.Errorf("%s: wrong pass", name)
		}
	}
}

// Every hop is always listed; a jump that is not decided names each hop that
// is not and its missing evidence; an UNKNOWN is never bare.
func TestJumpNeverBare(t *testing.T) {
	t.Parallel()
	undecided := jh(1, "1.0.0", "1.1.0", JumpHopUndecided)
	undecided.Reasons = []string{"LINE_NOT_ATTESTED"}
	j := NewJump([]JumpHop{undecided, jh(2, "1.1.0", "1.2.0", JumpHopBlocked)}, jumpDigest, nil, map[int]string{1: "request coverage"})
	if j.Status != JumpBlocked || len(j.Hops) != 2 || len(j.Missing) != 1 || j.Missing[0].Hop != 1 || j.Missing[0].Evidence != "LINE_NOT_ATTESTED" || j.Missing[0].Action != "request coverage" {
		t.Fatalf("%+v", j)
	}
	text := strings.Join(JumpLines("kyverno", "1.14.5", "1.16.0", j), "\n")
	for _, want := range []string{"BLOCKED on the stepwise path (hop 2 decides)", "hop 1 1.0.0 -> 1.1.0: UNDECIDED (LINE_NOT_ATTESTED)", "hop 2 1.1.0 -> 1.2.0: BLOCKED x.crd-version-removal.a", "missing for hop 1", "a direct skip"} {
		if !strings.Contains(text, want) {
			t.Fatalf("lacks %q:\n%s", want, text)
		}
	}
	u := NewJump([]JumpHop{undecided, jh(2, "1.1.0", "1.2.0", JumpHopPass)}, jumpDigest, nil, nil)
	if u.Status != JumpUnknown || len(u.Hops) != 2 || len(u.Missing) != 1 || u.Missing[0].Action == "" || len(u.DecidedBy) != 0 {
		t.Fatalf("%+v", u)
	}
	utext := strings.Join(JumpLines("kyverno", "1.0.0", "1.2.0", u), "\n")
	if !strings.Contains(utext, "hop 1 ") || !strings.Contains(utext, "hop 2 ") || !strings.Contains(utext, "missing for hop 1") {
		t.Fatalf("bare unknown:\n%s", utext)
	}
	p := NewJump([]JumpHop{jh(1, "1.0.0", "1.1.0", JumpHopPass), jh(2, "1.1.0", "1.2.0", JumpHopPass)}, jumpDigest, []JumpRelease{{Line: "1.1", Version: "1.1.0", Commit: strings.Repeat("a", 40)}}, nil)
	ptext := strings.Join(JumpLines("kyverno", "1.0.0", "1.2.0", p), "\n")
	if p.Status != JumpStepwisePass || !strings.Contains(ptext, "STEPWISE_PASS") || !strings.Contains(ptext, strings.Repeat("a", 40)) {
		t.Fatalf("%+v\n%s", p, ptext)
	}
	for _, line := range strings.Split(strings.ToLower(ptext+utext+text), "\n") {
		if strings.Contains(line, "direct") && (strings.Contains(line, "safe") || strings.Contains(line, "compatible")) {
			t.Fatalf("direct and safe wording: %q", line)
		}
		if !strings.HasPrefix(line, " ") && strings.Contains(line, "pass") && !strings.Contains(line, "stepwise_pass") {
			t.Fatalf("bare pass: %q", line)
		}
	}
}

// The jump is recomputable from what is recorded in it.
func TestJumpReplay(t *testing.T) {
	t.Parallel()
	j := NewJump([]JumpHop{jh(1, "1.0.0", "1.1.0", JumpHopPass), jh(2, "1.1.0", "1.2.0", JumpHopAttention)}, jumpDigest, nil, nil)
	raw, err := json.Marshal(j)
	if err != nil {
		t.Fatal(err)
	}
	var back Jump
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatal(err)
	}
	status, by := ComposeJump(back.Hops, back.ObjectSetDigest)
	if status != back.Status || !reflect.DeepEqual(by, back.DecidedBy) {
		t.Fatalf("replay %s %v != %s %v", status, by, back.Status, back.DecidedBy)
	}
	if !strings.Contains(string(raw), `"hops":[`) || !strings.Contains(string(raw), `"missing":[]`) {
		t.Fatalf("hops or missing absent: %s", raw)
	}
}

// Verdict and exit never read the jump: every status of it leaves them as
// they are without it.
func TestJumpNeverChangesVerdictOrExit(t *testing.T) {
	t.Parallel()
	hopsFor := func(status string) []JumpHop {
		return []JumpHop{jh(1, "1.0.0", "1.1.0", status), jh(2, "1.1.0", "1.2.0", status)}
	}
	for _, withFindings := range []bool{false, true} {
		for _, status := range []string{JumpHopPass, JumpHopBlocked, JumpHopAttention, JumpHopUndecided} {
			base := Report{Paths: []Path{{Component: "x", From: "1.0.0", To: "1.2.0", Hops: []Hop{{Index: 1, Status: HopPartial}, {Index: 2, Status: HopCovered}}}}}
			if withFindings {
				base.Findings = []Finding{{RuleID: "r", Component: "x"}}
			}
			with := base
			jump := NewJump(hopsFor(status), jumpDigest, nil, nil)
			with.Paths = []Path{base.Paths[0]}
			with.Paths[0].Jump = &jump
			if verdict(base) != verdict(with) {
				t.Fatalf("verdict %s != %s", verdict(base), verdict(with))
			}
			base.Verdict, with.Verdict = verdict(base), verdict(with)
			if Exit(base) != Exit(with) {
				t.Fatalf("exit %d != %d", Exit(base), Exit(with))
			}
		}
	}
	// Even a jump that says STEPWISE_PASS on every hop leaves a report with
	// an uncovered hop UNKNOWN.
	jump := NewJump(hopsFor(JumpHopPass), jumpDigest, nil, nil)
	report := Report{Paths: []Path{{Component: "x", Hops: []Hop{{Index: 1, Status: HopPartial}}, Jump: &jump}}}
	if verdict(report) != VerdictUnknown {
		t.Fatalf("verdict %s", verdict(report))
	}
}
