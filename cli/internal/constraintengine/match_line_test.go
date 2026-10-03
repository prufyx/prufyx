// SPDX-License-Identifier: AGPL-3.0-only

package constraintengine

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"strings"
	"testing"
)

func TestCoversLineTable(t *testing.T) {
	cases := []struct {
		name  string
		bound VersionBound
		line  string
		want  bool
	}{
		{"whole line", VersionBound{"1.24.0", "1.25.0"}, "1.24", true},
		{"wider than the line", VersionBound{"1.23.0", "1.26.0"}, "1.24", true},
		{"wider below only", VersionBound{"1.23.5", "1.25.0"}, "1.24", true},
		{"wider above only", VersionBound{"1.24.0", "1.25.3"}, "1.24", true},
		{"wider across majors", VersionBound{"0.9.0", "2.0.0"}, "1.24", true},
		{"gte above line start", VersionBound{"1.24.1", "1.25.0"}, "1.24", false},
		{"lt below next line start", VersionBound{"1.24.0", "1.24.999"}, "1.24", false},
		{"lt one patch short", VersionBound{"1.24.0", "1.24.4294967295"}, "1.24", false},
		{"previous line", VersionBound{"1.23.0", "1.24.0"}, "1.24", false},
		{"next line", VersionBound{"1.25.0", "1.26.0"}, "1.24", false},
		{"anchor only width", VersionBound{"1.24.3", "1.24.4"}, "1.24", false},
		{"minor zero line", VersionBound{"2.0.0", "2.1.0"}, "2.0", true},
		{"line 0.0", VersionBound{"0.0.0", "0.1.0"}, "0.0", true},
		{"invalid line major only", VersionBound{"1.0.0", "2.0.0"}, "1", false},
		{"invalid line wildcard", VersionBound{"1.0.0", "2.0.0"}, "1.x", false},
		{"invalid line leading zero major", VersionBound{"1.0.0", "2.0.0"}, "01.2", false},
		{"invalid line leading zero minor", VersionBound{"1.0.0", "2.0.0"}, "1.02", false},
		{"invalid line with patch", VersionBound{"1.0.0", "2.0.0"}, "1.2.0", false},
		{"invalid line empty", VersionBound{"1.0.0", "2.0.0"}, "", false},
		{"invalid line v prefix", VersionBound{"1.0.0", "2.0.0"}, "v1.2", false},
		{"invalid line space", VersionBound{"1.0.0", "2.0.0"}, " 1.2", false},
		{"invalid line sign", VersionBound{"1.0.0", "2.0.0"}, "1.+2", false},
		{"invalid line overflow", VersionBound{"0.0.0", "9999999999.0.0"}, "4294967296.1", false},
		{"no next minor line", VersionBound{"1.4294967295.0", "2.0.0"}, "1.4294967295", false},
		{"invalid gte", VersionBound{"1.24", "1.25.0"}, "1.24", false},
		{"invalid lt", VersionBound{"1.24.0", "1.25"}, "1.24", false},
		{"empty bound", VersionBound{}, "1.24", false},
		{"inverted bound", VersionBound{"1.25.0", "1.24.0"}, "1.24", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := c.bound.CoversLine(c.line); got != c.want {
				t.Fatalf("[%s,%s).CoversLine(%q) = %v, want %v", c.bound.Gte, c.bound.Lt, c.line, got, c.want)
			}
		})
	}
}

// CoversLine agrees with Contains: a bound covers the line exactly when it
// contains the line's first and last release (M.m.0 and M.m.4294967295, the
// version one patch below M.(m+1).0), and then it contains every probe patch
// in between.
func TestCoversLineProperty(t *testing.T) {
	rng := rand.New(rand.NewSource(20261004))
	const maxPatch = "4294967295"
	pick := func() string {
		// Versions cluster around lines 1.1-1.4 so both outcomes occur often.
		major := 1
		if rng.Intn(8) == 0 {
			major = rng.Intn(3)
		}
		patches := []string{"0", "1", "7", "999", maxPatch, fmt.Sprint(rng.Intn(2000))}
		return fmt.Sprintf("%d.%d.%s", major, rng.Intn(5), patches[rng.Intn(len(patches))])
	}
	covered, uncovered := 0, 0
	for i := 0; i < 20000; i++ {
		bound := VersionBound{Gte: pick(), Lt: pick()}
		line := fmt.Sprintf("%d.%d", rng.Intn(3), rng.Intn(5))
		got := bound.CoversLine(line)
		first, last := line+".0", line+"."+maxPatch
		if want := bound.Contains(first) && bound.Contains(last); got != want {
			t.Fatalf("[%s,%s) line %s: CoversLine %v, Contains(first)&&Contains(last) %v", bound.Gte, bound.Lt, line, got, want)
		}
		if got {
			covered++
			for _, p := range []string{"0", "1", "7", "999"} {
				if !bound.Contains(line + "." + p) {
					t.Fatalf("[%s,%s) covers %s but not %s.%s", bound.Gte, bound.Lt, line, line, p)
				}
			}
		} else {
			uncovered++
		}
		// The rule-side helpers agree with the bound on each side.
		rt := RuleTransition{Range: &VersionRange{From: bound, To: bound}}
		if rt.CoversFromLine(line) != got || rt.CoversToLine(line) != got {
			t.Fatalf("rule-side helpers disagree with the bound for line %s", line)
		}
	}
	if covered < 100 || uncovered < 100 {
		t.Fatalf("property sample is degenerate: %d covered, %d not", covered, uncovered)
	}
}

func TestRuleTransitionLineCoverage(t *testing.T) {
	whole := &VersionRange{From: VersionBound{"1.24.0", "1.25.0"}, To: VersionBound{"1.25.0", "1.26.0"}}
	ranged := RuleTransition{From: "1.24.0", To: "1.25.0", Range: whole}
	if !ranged.CoversFromLine("1.24") || !ranged.CoversToLine("1.25") {
		t.Fatal("a whole-line range does not cover its lines")
	}
	if ranged.CoversFromLine("1.25") || ranged.CoversToLine("1.24") {
		t.Fatal("a range covers the other side's line")
	}
	anchor := RuleTransition{From: "1.24.0", To: "1.25.0"}
	for _, line := range []string{"1.24", "1.25"} {
		if anchor.CoversFromLine(line) || anchor.CoversToLine(line) {
			t.Fatalf("an anchor-only rule covers line %s", line)
		}
	}
	narrow := RuleTransition{From: "1.24.3", To: "1.25.0", Range: &VersionRange{From: VersionBound{"1.24.3", "1.24.4"}, To: VersionBound{"1.25.0", "1.26.0"}}}
	if narrow.CoversFromLine("1.24") || !narrow.CoversToLine("1.25") {
		t.Fatal("an anchor-only side covers its line, or the other side lost coverage")
	}
}

// Every reviewed Kubernetes range in the published pack covers the whole
// minor line of its anchor on both sides, so it can decide an intermediate
// hop of a multi-line path as it is.
func TestShippedKubernetesRangesCoverWholeLines(t *testing.T) {
	raw, err := os.ReadFile("../cncfcheck/data/rules.json")
	if err != nil {
		t.Fatal(err)
	}
	var pack struct {
		Entries []struct {
			Rule json.RawMessage `json:"rule"`
		} `json:"entries"`
	}
	if err := json.Unmarshal(raw, &pack); err != nil {
		t.Fatal(err)
	}
	line := func(version string) string {
		parts := strings.Split(version, ".")
		return parts[0] + "." + parts[1]
	}
	checked := 0
	for _, entry := range pack.Entries {
		tr, err := RuleTransitionOf(entry.Rule)
		if err != nil {
			t.Fatal(err)
		}
		if tr.Component != "pkg:github/kubernetes/kubernetes" || tr.Range == nil {
			continue
		}
		checked++
		if !tr.CoversFromLine(line(tr.From)) || !tr.CoversToLine(line(tr.To)) {
			t.Errorf("rule %s -> %s: range from [%s,%s) to [%s,%s) does not cover lines %s and %s", tr.From, tr.To, tr.Range.From.Gte, tr.Range.From.Lt, tr.Range.To.Gte, tr.Range.To.Lt, line(tr.From), line(tr.To))
		}
	}
	if checked == 0 {
		t.Fatal("no ranged Kubernetes rule found in the published pack")
	}
}
