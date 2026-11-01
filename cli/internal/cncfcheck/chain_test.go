// SPDX-License-Identifier: AGPL-3.0-only

package cncfcheck

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func hopOf(verdict string) ChainHop { return ChainHop{From: "1.0.0", To: "1.1.0", Verdict: verdict} }

func TestChainVerdictCombinesHops(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name  string
		hops  []string
		whole string
		want  string
	}{
		{"all pass, no end-to-end rule", []string{ChainPass, ChainPass}, ChainNoRule, ChainPass},
		{"all pass, end-to-end pass", []string{ChainPass, ChainPass}, ChainPass, ChainPass},
		{"a hop without a rule is never absorbed", []string{ChainPass, ChainUnknown, ChainPass}, ChainNoRule, ChainUnknown},
		{"a blocked hop wins over unknown hops", []string{ChainUnknown, ChainBlocked, ChainPass}, ChainNoRule, ChainBlocked},
		{"a blocked end-to-end rule wins over passing hops", []string{ChainPass, ChainPass}, ChainBlocked, ChainBlocked},
		{"an undecided end-to-end rule stops a pass", []string{ChainPass, ChainPass}, ChainUnknown, ChainUnknown},
		{"blocked and unknown", []string{ChainBlocked, ChainUnknown}, ChainUnknown, ChainBlocked},
	} {
		var hops []ChainHop
		for _, verdict := range tc.hops {
			hops = append(hops, hopOf(verdict))
		}
		got, action := chainVerdict(hops, hopOf(tc.whole))
		if got != tc.want || action == "" {
			t.Errorf("%s: verdict %q (action %q), want %q", tc.name, got, action, tc.want)
		}
	}
}

func TestWithTransitionKeepsFactsAndRefusesOtherShapes(t *testing.T) {
	t.Parallel()
	raw := kubernetesInput(t, "1.24.17", "1.25.3", true)
	moved, err := withTransition(raw, "1.20.0", "1.21.0")
	if err != nil {
		t.Fatal(err)
	}
	from, to, ok := inputTransition(moved)
	if !ok || from != "1.20.0" || to != "1.21.0" {
		t.Fatalf("transition %q -> %q (%v)", from, to, ok)
	}
	if !strings.Contains(string(moved), `"boolValue":true`) || !strings.Contains(string(moved), "cronjob_v1beta1_removed_gvk_present") {
		t.Fatalf("the fact was lost: %s", moved)
	}
	var shape struct {
		Current struct{ Components []any }
	}
	two := strings.Replace(string(raw), `"facts":[]}]`, `"facts":[]},{"component":"pkg:github/x/y","version":"1.0.0","facts":[]}]`, 1)
	if err := json.Unmarshal([]byte(two), &shape); err != nil || len(shape.Current.Components) != 2 {
		t.Fatalf("fixture: %v", err)
	}
	if _, _, ok := inputTransition([]byte(two)); ok {
		t.Fatal("an input with two components has a single transition")
	}
	if _, err := withTransition([]byte(`{"current":{}}`), "1.0.0", "1.1.0"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("shape without components: %v", err)
	}
}

func TestCheckChainRefusesAnInvalidPath(t *testing.T) {
	t.Parallel()
	raw := kubernetesInput(t, "1.23.5", "1.25.3", true)
	tooMany := make([]string, MaxChainVia+1)
	for i := range tooMany {
		tooMany[i] = "1.24." + string(rune('0'+i%10)) + string(rune('0'+i/10))
	}
	for name, via := range map[string][]string{
		"none":           nil,
		"equals from":    {"1.23.5"},
		"equals to":      {"1.25.3"},
		"below from":     {"1.22.0"},
		"above to":       {"1.26.0"},
		"not ascending":  {"1.24.17", "1.24.2"},
		"duplicate":      {"1.24.2", "1.24.2"},
		"v prefix":       {"v1.24.2"},
		"not a version":  {"latest"},
		"too many steps": tooMany,
	} {
		if _, err := (Checker{}).CheckChain("kubernetes", raw, via, rangeReviewClock); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: err=%v, want ErrInvalid", name, err)
		}
	}
	two := strings.Replace(string(raw), `"facts":[]}]`, `"facts":[]},{"component":"pkg:github/x/y","version":"1.0.0","facts":[]}]`, 1)
	if _, err := (Checker{}).CheckChain("kubernetes", []byte(two), []string{"1.24.17"}, rangeReviewClock); !errors.Is(err, ErrInvalid) {
		t.Errorf("two components: err=%v", err)
	}
}

// The published Kubernetes rules over the path 1.23.5 -> 1.24.17 -> 1.25.3:
// the CronJob hop is blocked whatever the other hop says, and without the
// CronJob nothing on the path may pass.
func TestCheckChainOverPublishedRules(t *testing.T) {
	t.Parallel()
	now := currentKubernetesReviewClock(t, rangeReviewClock)
	via := []string{"1.24.17"}
	blocked, err := (Checker{}).CheckChain("kubernetes", kubernetesInput(t, "1.23.5", "1.25.3", true), via, now)
	if err != nil {
		t.Fatal(err)
	}
	if blocked.Verdict != ChainBlocked || ChainExit(blocked) != 10 || len(blocked.Hops) != 2 {
		t.Fatalf("verdict %s exit %d hops %d", blocked.Verdict, ChainExit(blocked), len(blocked.Hops))
	}
	if h := blocked.Hops[0]; h.From != "1.23.5" || h.To != "1.24.17" || h.Index != 1 || h.Verdict == ChainBlocked || h.Verdict == ChainPass {
		t.Fatalf("hop 1: %+v", h)
	}
	if h := blocked.Hops[1]; h.From != "1.24.17" || h.To != "1.25.3" || h.Index != 2 || h.Verdict != ChainBlocked || h.Decided == 0 {
		t.Fatalf("hop 2: %+v", h)
	}
	if blocked.Whole.From != "1.23.5" || blocked.Whole.To != "1.25.3" {
		t.Fatalf("whole: %s -> %s", blocked.Whole.From, blocked.Whole.To)
	}
	encoded, err := MarshalChain(blocked)
	if err != nil || !strings.Contains(string(encoded), ChainSchema) {
		t.Fatalf("encode: %v", err)
	}

	clear, err := (Checker{}).CheckChain("kubernetes", kubernetesInput(t, "1.23.5", "1.25.3", false), via, now)
	if err != nil {
		t.Fatal(err)
	}
	if clear.Verdict != ChainUnknown || ChainExit(clear) != 11 {
		t.Fatalf("no CronJob: verdict %s exit %d, want UNKNOWN 11", clear.Verdict, ChainExit(clear))
	}
	for _, hop := range clear.Hops {
		if hop.Verdict == ChainBlocked {
			t.Fatalf("hop %d blocked without the CronJob", hop.Index)
		}
	}

	// A hop evaluated through the chain equals the same pair checked alone.
	alone, err := (Checker{}).Check("kubernetes", kubernetesInput(t, "1.24.17", "1.25.3", true), now)
	if err != nil {
		t.Fatal(err)
	}
	left, _ := json.Marshal(alone.Check.Claims)
	right, _ := json.Marshal(blocked.Hops[1].Report.Check.Claims)
	if string(left) != string(right) {
		t.Fatal("a chained hop differs from the single check of the same pair")
	}

	// A project with no rule for any hop is UNKNOWN, never a pass.
	none, err := (Checker{}).CheckChain("kubernetes", kubernetesInput(t, "1.9.0", "1.12.0", false), []string{"1.10.0", "1.11.0"}, now)
	if err != nil {
		t.Fatal(err)
	}
	if none.Verdict != ChainUnknown {
		t.Fatalf("hops without a rule: %s", none.Verdict)
	}
}
