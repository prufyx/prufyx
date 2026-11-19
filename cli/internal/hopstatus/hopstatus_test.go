// SPDX-License-Identifier: AGPL-3.0-only

package hopstatus

import (
	"errors"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/hopstop"
	"github.com/prufyx/prufyx/cli/internal/lineattest"
)

func stop(from, to, code string) *hopstop.Record {
	return &hopstop.Record{
		Schema: hopstop.Schema, Project: "synthetic-proj", Family: lineattest.FamilyCustomResourceVersions,
		FromLine: from, ToLine: to, Code: code, Reasons: []string{},
		ToolCommit: strings.Repeat("c", 40), FactsDigest: "sha256:" + strings.Repeat("d", 64),
	}
}

func lines(n int) []string {
	var out []string
	for i := 1; i <= n; i++ {
		out = append(out, "2."+string(rune('0'+i)))
	}
	return out
}

// An empty pack answers every hop of every path with G not-derived: never a
// PASS, wherever derivedFrom lies, and derivedFrom itself decides nothing.
func TestEmptyPackNeverPasses(t *testing.T) {
	for _, derived := range []string{"", "2.1", "2.3", "2.6"} {
		p := Project{Lines: lines(6), DerivedFrom: derived}
		for a := 0; a < 6; a++ {
			for b := a + 1; b < 6; b++ {
				hops, err := Resolve(p, p.Lines[a], p.Lines[b])
				if err != nil || len(hops) != b-a {
					t.Fatalf("%v %d", err, len(hops))
				}
				for _, h := range hops {
					if h.Status != Gap || h.ReasonCode != ReasonNotDerived || h.Source != SourceNone {
						t.Fatalf("derivedFrom %q: %+v", derived, h)
					}
				}
			}
		}
	}
}

func TestNextActionOnlyAdvises(t *testing.T) {
	p := Project{Lines: lines(4), DerivedFrom: "2.3"}
	hops, _ := Resolve(p, "2.1", "2.4")
	want := []string{ActionBackfillDepth, ActionBackfillDepth, ActionReDerive}
	for i, h := range hops {
		if h.NextAction != want[i] || h.Status != Gap {
			t.Fatalf("%d: %+v", i, h)
		}
	}
	none, _ := Resolve(Project{Lines: lines(4)}, "2.1", "2.4")
	for _, h := range none {
		if h.NextAction != ActionBackfillDepth {
			t.Fatalf("unknown derivedFrom: %+v", h)
		}
	}
}

// Every combination of evidence on one hop: PASS only with an attestation
// and nothing else; BLOCKED beats everything; the order of the rest follows
// the documented priority.
func TestPriorityTable(t *testing.T) {
	for mask := 0; mask < 16; mask++ {
		ev := Evidence{}
		if mask&1 != 0 {
			ev.Blocked = []Block{{RuleID: "r1", Citation: "v2.1.0:crds/a.yaml"}}
		}
		if mask&2 != 0 {
			ev.Attested = true
		}
		if mask&4 != 0 {
			ev.Change = "notes for 2.2"
		}
		if mask&8 != 0 {
			ev.Stop = stop("2.1", "2.2", "scan-unclean")
		}
		p := Project{Lines: lines(2), Hops: map[string]Evidence{Key("2.1", "2.2"): ev}}
		hops, err := Resolve(p, "2.1", "2.2")
		if err != nil || len(hops) != 1 {
			t.Fatal(err)
		}
		h := hops[0]
		var want Status
		switch {
		case mask&1 != 0:
			want = Blocked
		case mask&2 != 0 && mask&8 != 0:
			want = Gap
		case mask&2 != 0:
			want = Pass
		case mask&4 != 0:
			want = Change
		default:
			want = Gap
		}
		if h.Status != want {
			t.Fatalf("mask %d: %+v, want %s", mask, h, want)
		}
		if h.Status == Pass && (mask&2 == 0 || mask&9 != 0 || h.Source != SourceAttestation) {
			t.Fatalf("mask %d: PASS without an attestation, or with a block or stop", mask)
		}
		if h.Status == Blocked && h.Citation == "" {
			t.Fatalf("mask %d: BLOCKED without citation", mask)
		}
		if mask&10 == 10 && mask&1 == 0 && h.ReasonCode != ReasonEvidenceConflict {
			t.Fatalf("mask %d: conflict not marked", mask)
		}
		if mask == 8 && (h.ReasonCode != "scan-unclean" || h.Source != SourceHopStop) {
			t.Fatalf("stop hop: %+v", h)
		}
	}
}

// Wrong-PASS corpus: over every assignment of {attested, nothing, stop,
// blocked} to the hops of a 5-hop path and every derivedFrom, a hop is PASS
// only when it is attested without a block or a stop.
func TestWrongPassCorpusAcrossDerivedFrom(t *testing.T) {
	const hopsN = 5
	total := 1
	for i := 0; i < hopsN; i++ {
		total *= 4
	}
	ls := lines(hopsN + 1)
	for _, derived := range []string{"", "2.1", "2.2", "2.4", "2.6"} {
		for v := 0; v < total; v++ {
			p := Project{Lines: ls, DerivedFrom: derived, Hops: map[string]Evidence{}}
			kinds := make([]int, hopsN)
			x := v
			for i := 0; i < hopsN; i++ {
				kinds[i] = x % 4
				x /= 4
				k := Key(ls[i], ls[i+1])
				switch kinds[i] {
				case 1:
					p.Hops[k] = Evidence{Attested: true}
				case 2:
					p.Hops[k] = Evidence{Stop: stop(ls[i], ls[i+1], "declared-incomplete")}
				case 3:
					p.Hops[k] = Evidence{Blocked: []Block{{RuleID: "r", Citation: "c"}}}
				}
			}
			hops, err := Resolve(p, ls[0], ls[hopsN])
			if err != nil {
				t.Fatal(err)
			}
			for i, h := range hops {
				if (h.Status == Pass) != (kinds[i] == 1) {
					t.Fatalf("derivedFrom %q vector %v hop %d: %+v", derived, kinds, i, h)
				}
				if kinds[i] == 0 && h.Status != Gap {
					t.Fatalf("no evidence resolved to %s", h.Status)
				}
			}
		}
	}
}

func TestRefusals(t *testing.T) {
	ok := Project{Lines: lines(3)}
	cases := map[string]func() (Project, string, string){
		"unknown from":    func() (Project, string, string) { return ok, "1.9", "2.3" },
		"unknown to":      func() (Project, string, string) { return ok, "2.1", "2.9" },
		"reverse":         func() (Project, string, string) { return ok, "2.3", "2.1" },
		"same line":       func() (Project, string, string) { return ok, "2.2", "2.2" },
		"unsorted lines":  func() (Project, string, string) { return Project{Lines: []string{"2.2", "2.1"}}, "2.2", "2.1" },
		"duplicate lines": func() (Project, string, string) { return Project{Lines: []string{"2.1", "2.1"}}, "2.1", "2.1" },
		"bad derivedFrom": func() (Project, string, string) { return Project{Lines: lines(3), DerivedFrom: "x"}, "2.1", "2.3" },
		"evidence for non hop": func() (Project, string, string) {
			return Project{Lines: lines(3), Hops: map[string]Evidence{Key("2.1", "2.3"): {Attested: true}}}, "2.1", "2.3"
		},
		"block without citation": func() (Project, string, string) {
			return Project{Lines: lines(3), Hops: map[string]Evidence{Key("2.1", "2.2"): {Blocked: []Block{{RuleID: "r"}}}}}, "2.1", "2.3"
		},
		"block without rule id": func() (Project, string, string) {
			return Project{Lines: lines(3), Hops: map[string]Evidence{Key("2.1", "2.2"): {Blocked: []Block{{Citation: "c"}}}}}, "2.1", "2.3"
		},
		"stop of another hop": func() (Project, string, string) {
			return Project{Lines: lines(3), Hops: map[string]Evidence{Key("2.1", "2.2"): {Stop: stop("2.2", "2.3", "scan-unclean")}}}, "2.1", "2.3"
		},
		"invalid stop": func() (Project, string, string) {
			return Project{Lines: lines(3), Hops: map[string]Evidence{Key("2.1", "2.2"): {Stop: stop("2.1", "2.2", "release-pending")}}}, "2.1", "2.3"
		},
	}
	for name, c := range cases {
		p, a, b := c()
		hops, err := Resolve(p, a, b)
		if err == nil || !errors.Is(err, ErrRefused) || hops != nil {
			t.Fatalf("%s: %v %v", name, hops, err)
		}
	}
}

func TestPartialPathListsEveryHop(t *testing.T) {
	ls := lines(4)
	p := Project{Lines: ls, DerivedFrom: "2.2", Hops: map[string]Evidence{
		Key("2.1", "2.2"): {Stop: stop("2.1", "2.2", "hop-not-previous-minor")},
		Key("2.2", "2.3"): {Attested: true},
		Key("2.3", "2.4"): {Blocked: []Block{{RuleID: "r", Citation: "v2.4.0:crds/x.yaml"}}},
	}}
	hops, err := Resolve(p, "2.1", "2.4")
	if err != nil || len(hops) != 3 {
		t.Fatal(err)
	}
	got := []Status{hops[0].Status, hops[1].Status, hops[2].Status}
	if got[0] != Gap || got[1] != Pass || got[2] != Blocked {
		t.Fatalf("%v", got)
	}
}
