// SPDX-License-Identifier: AGPL-3.0-only

package changelogattest

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func mustTime() time.Time { return time.Date(2026, 11, 17, 0, 0, 0, 0, time.UTC) }

var digestA = strings.Repeat("a", 64)

func fileOf(marks ...Mark) []byte {
	b, _ := json.Marshal(Dispositions{Component: component, Marks: marks})
	return b
}

func good() Mark {
	return Mark{ItemDigest: digestA, Occurrence: 1, Tag: "v3.5.0", Kind: KindNotOperatorFacing, ReasonClass: "docs",
		State: StateReviewed, ReviewedAt: "2026-11-01T00:00:00Z", ProposedBy: ProposedByPerson}
}

func TestLoadDispositionsAccepts(t *testing.T) {
	m := good()
	rm := good()
	rm.Occurrence, rm.Kind, rm.ReasonClass, rm.RuleID = 2, KindRule, "", "r.1"
	model := good()
	model.ItemDigest, model.ProposedBy = strings.Repeat("b", 64), ProposedByModel
	r2 := rm
	r2.RuleID = "r.2" // one item may bind several rules
	d, err := LoadDispositions(fileOf(m, rm, r2, model), component)
	if err != nil || len(d.Marks) != 4 {
		t.Fatalf("%+v %v", d, err)
	}
	// An empty mark list is a valid (quiet) file.
	if _, err := LoadDispositions([]byte(`{"component":"prometheus","marks":[]}`), component); err != nil {
		t.Fatal(err)
	}
}

func TestLoadDispositionsRefuses(t *testing.T) {
	mut := func(f func(*Mark)) []byte {
		m := good()
		f(&m)
		return fileOf(m)
	}
	cases := map[string][]byte{
		"model proposal not reviewed":  mut(func(m *Mark) { m.ProposedBy, m.State = ProposedByModel, "proposed" }),
		"person proposal not reviewed": mut(func(m *Mark) { m.State = "" }),
		"unknown state":                mut(func(m *Mark) { m.State = "approved" }),
		"bad proposer":                 mut(func(m *Mark) { m.ProposedBy = "tool" }),
		"short digest":                 mut(func(m *Mark) { m.ItemDigest = "abc" }),
		"upper digest":                 mut(func(m *Mark) { m.ItemDigest = strings.ToUpper(digestA) }),
		"occurrence zero":              mut(func(m *Mark) { m.Occurrence = 0 }),
		"no tag":                       mut(func(m *Mark) { m.Tag = "" }),
		"unknown kind":                 mut(func(m *Mark) { m.Kind = "neutral" }),
		"unknown reason class":         mut(func(m *Mark) { m.ReasonClass = "other" }),
		"no reason class":              mut(func(m *Mark) { m.ReasonClass = "" }),
		"neutral with a rule id":       mut(func(m *Mark) { m.RuleID = "r.1" }),
		"rule without id":              mut(func(m *Mark) { m.Kind, m.ReasonClass = KindRule, "" }),
		"rule with reason class":       mut(func(m *Mark) { m.Kind, m.RuleID = KindRule, "r.1" }),
		"reviewedAt not UTC":           mut(func(m *Mark) { m.ReviewedAt = "2026-11-01T00:00:00+02:00" }),
		"reviewedAt date only":         mut(func(m *Mark) { m.ReviewedAt = "2026-11-01" }),
		"another component":            []byte(`{"component":"other","marks":[]}`),
		"unknown field":                []byte(`{"component":"prometheus","marks":[],"extra":1}`),
		"unknown mark field":           []byte(`{"component":"prometheus","marks":[{"itemDigest":"` + digestA + `","bogus":1}]}`),
		"trailing document":            append(fileOf(), []byte(`{}`)...),
		"not json":                     []byte(`marks`),
		"duplicate mark":               fileOf(good(), good()),
		"empty":                        nil,
	}
	rm := good()
	rm.Kind, rm.ReasonClass, rm.RuleID = KindRule, "", "r.1"
	cases["neutral and rule on one item"] = fileOf(good(), rm)
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := LoadDispositions(raw, component); err == nil {
				t.Fatal("accepted")
			}
		})
	}
	big := make([]byte, MaxFileBytes+1)
	if _, err := LoadDispositions(big, component); err == nil {
		t.Fatal("oversize accepted")
	}
}
