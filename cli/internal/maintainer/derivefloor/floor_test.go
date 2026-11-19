// SPDX-License-Identifier: AGPL-3.0-only

package derivefloor

import (
	"strings"
	"testing"
)

// chain builds consecutive pairs of minors 1..n+1 of major 3: pair i is
// 3.(i+1) -> 3.(i+2). spec is one char per pair, oldest first: 'A' attested,
// a letter 's' a final stop, 'p' a transient stop, '.' no outcome.
func chain(spec string, depth int) Facts {
	f := Facts{Depth: depth}
	for i, c := range spec {
		p := PairFact{From: Line{3, i + 1}, To: Line{3, i + 2}}
		switch c {
		case 'A':
			p.Attested = true
		case 's':
			p.Stop = "scan-unclean"
		case 'p':
			p.Stop = "release-pending"
		}
		f.Pairs = append(f.Pairs, p)
	}
	return f
}

func TestDeriveFloorTable(t *testing.T) {
	cases := []struct {
		name, spec  string
		depth       int
		floor       bool
		min, derive int // minor of the from line; 0 when no floor
		stops       []int
	}{
		{"all attest", "AAAA", 10, true, 1, 1, nil},
		{"gap mid chain: floor above the gap", "AAsAA", 10, true, 4, 1, []int{3}},
		{"no outcome cuts derivedFrom", "AA.sAA", 10, true, 5, 4, []int{4}},
		{"attested pairs below a stop stay out of the floor", "AAAsAA", 10, true, 5, 1, []int{4}},
		{"newest pair stops: no floor", "AAAs", 10, false, 0, 0, []int{4}},
		{"newest pair has no outcome: no floor", "AAA.", 10, false, 0, 0, nil},
		{"transient stop is no outcome", "AApAA", 10, true, 4, 4, nil},
		{"depth bound", "AAAAAA", 3, true, 4, 4, nil},
		{"single pair", "A", 1, true, 1, 1, nil},
		{"two stops", "sAsA", 10, true, 4, 1, []int{1, 3}},
	}
	for _, c := range cases {
		got, err := DeriveFloor(chain(c.spec, c.depth))
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if got.Floor != c.floor {
			t.Fatalf("%s: floor = %v", c.name, got.Floor)
		}
		if c.floor && (got.MinFrom != Line{3, c.min} || got.DerivedFrom != Line{3, c.derive}) {
			t.Fatalf("%s: got %v / %v, want minor %d / %d", c.name, got.MinFrom, got.DerivedFrom, c.min, c.derive)
		}
		if !c.floor && (got.MinFrom != Line{} || got.DerivedFrom != Line{}) {
			t.Fatalf("%s: numbers set without a floor", c.name)
		}
		var gs []int
		for _, s := range got.Stops {
			gs = append(gs, s.From[1])
			if !FinalStop(s.Code) {
				t.Fatalf("%s: non-final stop %q recorded", c.name, s.Code)
			}
		}
		if len(gs) != len(c.stops) {
			t.Fatalf("%s: stops %v, want %v", c.name, gs, c.stops)
		}
		for i := range gs {
			if gs[i] != c.stops[i] {
				t.Fatalf("%s: stops %v, want %v", c.name, gs, c.stops)
			}
		}
	}
}

// Property over every attest vector of 8 pairs (each pair attested, stopped
// or without outcome): the floor is the lowest contiguous attested run to
// the newest pair, derivedFrom <= minFrom, and no stop sits at or above the
// floor.
func TestDeriveFloorProperty(t *testing.T) {
	const n = 8
	total := 1
	for i := 0; i < n; i++ {
		total *= 3
	}
	for v := 0; v < total; v++ {
		spec := make([]byte, n)
		x := v
		for i := range spec {
			spec[i] = "As."[x%3]
			x /= 3
		}
		f := chain(string(spec), 10)
		got, err := DeriveFloor(f)
		if err != nil {
			t.Fatal(err)
		}
		run := 0
		for i := n - 1; i >= 0 && spec[i] == 'A'; i-- {
			run++
		}
		if got.Floor != (run > 0) {
			t.Fatalf("%s: floor %v, run %d", spec, got.Floor, run)
		}
		if !got.Floor {
			continue
		}
		if got.MinFrom != (Line{3, n - run + 1}) {
			t.Fatalf("%s: minFrom %v", spec, got.MinFrom)
		}
		if less(got.MinFrom, got.DerivedFrom) {
			t.Fatalf("%s: derivedFrom %v above minFrom %v", spec, got.DerivedFrom, got.MinFrom)
		}
		for _, s := range got.Stops {
			if !less(s.From, got.MinFrom) || less(s.From, got.DerivedFrom) {
				t.Fatalf("%s: stop %v outside [derivedFrom, minFrom)", spec, s)
			}
		}
		if err := Verify(f, Claim{MinFrom: got.MinFrom, DerivedFrom: got.DerivedFrom, Stops: got.Stops}); err != nil {
			t.Fatalf("%s: own result refused: %v", spec, err)
		}
	}
}

func TestDeriveFloorRefusesBadFacts(t *testing.T) {
	good := chain("AAA", 5)
	bad := map[string]Facts{}
	{
		f := chain("AAA", 0)
		bad["depth zero"] = f
		bad["depth over hard max"] = chain("AAA", MaxDepth+1)
		bad["no pairs"] = Facts{Depth: 3}
	}
	{
		f := chain("AAA", 5)
		f.Pairs[1], f.Pairs[2] = f.Pairs[2], f.Pairs[1]
		bad["unsorted"] = f
	}
	{
		f := chain("AAA", 5)
		f.Pairs = append(f.Pairs, f.Pairs[2])
		bad["duplicate"] = f
	}
	{
		f := chain("AAA", 5)
		f.Pairs = append(f.Pairs[:1], f.Pairs[2:]...)
		bad["missing line"] = f
	}
	{
		f := chain("AAA", 5)
		f.Pairs[1].Stop = "scan-unclean"
		bad["attested and stopped"] = f
	}
	{
		f := chain("sAA", 5)
		f.Pairs[0].Stop = "free text reason"
		bad["unknown stop code"] = f
	}
	{
		f := chain("sAA", 5)
		f.Pairs[0].Stop = "family-stop:whatever"
		bad["unknown family stop"] = f
	}
	{
		f := chain("AAA", 5)
		f.Pairs[0].To = f.Pairs[0].From
		bad["non ascending pair"] = f
	}
	if _, err := DeriveFloor(good); err != nil {
		t.Fatal(err)
	}
	for name, f := range bad {
		if _, err := DeriveFloor(f); err == nil {
			t.Fatalf("%s: accepted", name)
		}
		if err := Verify(f, Claim{MinFrom: Line{3, 1}, DerivedFrom: Line{3, 1}}); err == nil {
			t.Fatalf("%s: Verify accepted", name)
		}
	}
}

func TestVerifyRefusals(t *testing.T) {
	f := chain("AAsAA", 10) // floor 3.4, derivedFrom 3.1, stop at 3.3
	res, err := DeriveFloor(f)
	if err != nil {
		t.Fatal(err)
	}
	ok := Claim{MinFrom: res.MinFrom, DerivedFrom: res.DerivedFrom, Stops: res.Stops}
	if err := Verify(f, ok); err != nil {
		t.Fatal(err)
	}
	cases := map[string]Claim{
		"hand-lowered minFrom":      {MinFrom: Line{3, 3}, DerivedFrom: Line{3, 1}, Stops: res.Stops},
		"hand-lowered derivedFrom":  {MinFrom: res.MinFrom, DerivedFrom: Line{3, 0}, Stops: res.Stops},
		"raised derivedFrom":        {MinFrom: res.MinFrom, DerivedFrom: Line{3, 2}, Stops: res.Stops},
		"derivedFrom above minFrom": {MinFrom: res.MinFrom, DerivedFrom: Line{3, 5}, Stops: res.Stops},
		"missing stop":              {MinFrom: res.MinFrom, DerivedFrom: res.DerivedFrom},
		"wrong stop code":           {MinFrom: res.MinFrom, DerivedFrom: res.DerivedFrom, Stops: []Stop{{From: Line{3, 3}, To: Line{3, 4}, Code: "scan-unclean-x"}}},
		"raised minFrom":            {MinFrom: Line{3, 5}, DerivedFrom: Line{3, 1}, Stops: res.Stops},
	}
	for name, c := range cases {
		if err := Verify(f, c); err == nil {
			t.Fatalf("%s: accepted", name)
		}
	}
	// A pair in [derivedFrom, minFrom) with neither attestation nor stop is
	// refused with that pair named.
	g := chain("AA.AA", 10)
	err = Verify(g, Claim{MinFrom: Line{3, 4}, DerivedFrom: Line{3, 1}})
	if err == nil || !strings.Contains(err.Error(), "neither an attestation nor a final stop") {
		t.Fatalf("missing outcome: %v", err)
	}
	// An unattested pair at or above the claimed floor is refused.
	h := chain("AAsAA", 10)
	err = Verify(h, Claim{MinFrom: Line{3, 1}, DerivedFrom: Line{3, 1}})
	if err == nil || !strings.Contains(err.Error(), "not attested") {
		t.Fatalf("floor over an unattested pair: %v", err)
	}
	// No floor, no claim.
	if err := Verify(chain("AAs", 10), Claim{MinFrom: Line{3, 1}, DerivedFrom: Line{3, 1}}); err == nil {
		t.Fatal("claim over facts without a floor accepted")
	}
}

// Transient codes are accepted as input (a run state) but never become a
// recorded stop and never count as an outcome.
func TestTransientStopsAreNotRecorded(t *testing.T) {
	f := chain("ApAA", 10)
	res, err := DeriveFloor(f)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Stops) != 0 || res.DerivedFrom != res.MinFrom {
		t.Fatalf("%+v", res)
	}
	if FinalStop("release-pending") || FinalStop("derive-failed") || !TransientStop("derive-failed") {
		t.Fatal("transient codes classified as final")
	}
}
