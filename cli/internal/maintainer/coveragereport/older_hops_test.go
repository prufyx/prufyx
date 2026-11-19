// SPDX-License-Identifier: AGPL-3.0-only

package coveragereport

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func olderInput() OlderHopsInput {
	return OlderHopsInput{DepthBound: 3, Projects: []OlderHopsProject{
		{Project: "synth-b", Hops: []OlderHop{{From: "1.1", To: "1.2", Stop: "scan-unclean"}, {From: "1.2", To: "1.3"}}},
		{Project: "synth-a", Hops: []OlderHop{
			{From: "2.0", To: "2.1"},
			{From: "2.1", To: "2.2", Attested: true},
			{From: "2.2", To: "2.3", Attested: true, Blocked: true},
			{From: "2.3", To: "2.4", Blocked: true},
			{From: "2.4", To: "3.0", Stop: "hop-not-previous-minor"},
		}},
	}}
}

func TestOlderHopsCounts(t *testing.T) {
	o, err := ComputeOlderHops(olderInput())
	if err != nil {
		t.Fatal(err)
	}
	if o.Projects[0].Project != "synth-a" || o.Title != OlderHopsTitle || o.DepthBound != 3 {
		t.Fatalf("%+v", o)
	}
	a, b := o.Projects[0], o.Projects[1]
	// synth-a: the 3 hops nearest to the window (depth cap) are counted.
	if a.Pairs != 3 || a.Attested != 1 || a.BlockedKnown != 2 || a.Derived != 3 || a.NotDerived != 0 || a.Stops["hop-not-previous-minor"] != 1 {
		t.Fatalf("a %+v", a)
	}
	if b.Pairs != 2 || b.Derived != 1 || b.NotDerived != 1 || b.Stops["scan-unclean"] != 1 {
		t.Fatalf("b %+v", b)
	}
	if o.Total.Pairs != 5 || o.Total.Derived != 4 || o.Total.NotDerived != 1 || o.Total.Derived+o.Total.NotDerived != o.Total.Pairs {
		t.Fatalf("total %+v", o.Total)
	}
	line := o.Line()
	if !strings.Contains(line, "older hops derived") || strings.Contains(strings.ToLower(line), "coverage") {
		t.Fatalf("wording: %s", line)
	}
	if md := o.Markdown(); !strings.Contains(md, OlderHopsTitle) || strings.Contains(strings.ToLower(md), "coverage") {
		t.Fatalf("markdown wording: %s", md)
	}
}

func TestOlderHopsRefusals(t *testing.T) {
	mut := map[string]func(*OlderHopsInput){
		"depth zero":           func(i *OlderHopsInput) { i.DepthBound = 0 },
		"depth over hard max":  func(i *OlderHopsInput) { i.DepthBound = MaxOlderDepth + 1 },
		"unknown stop code":    func(i *OlderHopsInput) { i.Projects[0].Hops[0].Stop = "flaky" },
		"transient stop code":  func(i *OlderHopsInput) { i.Projects[0].Hops[0].Stop = "release-pending" },
		"attested and stopped": func(i *OlderHopsInput) { i.Projects[0].Hops[0].Attested = true },
		"not consecutive":      func(i *OlderHopsInput) { i.Projects[0].Hops[1].From = "1.9"; i.Projects[0].Hops[1].To = "1.10" },
		"reversed lines":       func(i *OlderHopsInput) { i.Projects[0].Hops[0].From, i.Projects[0].Hops[0].To = "1.2", "1.1" },
		"bad line":             func(i *OlderHopsInput) { i.Projects[0].Hops[0].From = "x" },
		"repeated project":     func(i *OlderHopsInput) { i.Projects[1].Project = "synth-b" },
		"empty project":        func(i *OlderHopsInput) { i.Projects[1].Project = "" },
	}
	for name, m := range mut {
		in := olderInput()
		m(&in)
		if o, err := ComputeOlderHops(in); err == nil || o != nil {
			t.Fatalf("%s: accepted", name)
		}
	}
}

// The block is a separate member: the default report, with or without the
// block computed or attached, keeps its bytes (the cohort figures included),
// and every member but olderHops of a report that carries it is the one of
// the report without it. Nothing sums the block into a cohort total.
func TestOlderHopsDoNotTouchTheCohort(t *testing.T) {
	report, err := Compute(Input{Pack: read(t, "testdata/pack-cncf-2026-09-13.4-reduced.json"), Lines: read(t, "testdata/lines-2026-10-08.json"), Now: baselineNow})
	if err != nil {
		t.Fatal(err)
	}
	plain, err := report.JSON()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(plain, read(t, "testdata/default-report-2026-10-08.json")) {
		t.Fatal("default JSON changed")
	}
	o, err := ComputeOlderHops(olderInput())
	if err != nil {
		t.Fatal(err)
	}
	with := report.WithOlderHops(o)
	if report.OlderHops != nil {
		t.Fatal("WithOlderHops changed the receiver")
	}
	if with.Fleet != report.Fleet || with.Priority != report.Priority {
		t.Fatal("cohort totals moved")
	}
	rawWith, err := with.JSON()
	if err != nil {
		t.Fatal(err)
	}
	var a, b map[string]json.RawMessage
	if err := json.Unmarshal(plain, &a); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(rawWith, &b); err != nil {
		t.Fatal(err)
	}
	if _, ok := b["olderHops"]; !ok {
		t.Fatal("no olderHops member")
	}
	delete(b, "olderHops")
	if len(a) != len(b) {
		t.Fatalf("members differ: %d vs %d", len(a), len(b))
	}
	for k, v := range a {
		if !bytes.Equal(v, b[k]) {
			t.Fatalf("member %s differs", k)
		}
	}
	if !bytes.HasPrefix(with.Markdown(), report.Markdown()) {
		t.Fatal("the Markdown of the cohort changed")
	}
	if !bytes.Equal(report.Markdown(), read(t, "testdata/default-report-2026-10-08.md")) {
		t.Fatal("default Markdown changed")
	}
}
