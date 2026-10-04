// SPDX-License-Identifier: AGPL-3.0-only

package scanreport

import (
	"sort"
	"testing"
)

// TestRedactOrderDoesNotRevealHiddenPaths: "a" sorts before "b", but the
// digest of "b" sorts before the digest of "a". After Redact the locations
// and omitted documents follow the digests, not the hidden paths, and the
// result is the same whatever the input order.
func TestRedactOrderDoesNotRevealHiddenPaths(t *testing.T) {
	if !(RedactValue("b") < RedactValue("a")) {
		t.Fatal("fixture: the digests no longer sort against the paths")
	}
	build := func(files ...string) Report {
		finding := Finding{RuleID: "r", Component: "kubernetes", Hop: ref(1, "1.24.0", "1.25"), Title: "title", Fix: "fix it"}
		var omitted []Omitted
		for _, file := range files {
			finding.Locations = append(finding.Locations, Location{File: file, Document: 0, Item: -1, Kind: "CronJob", Name: "n-" + file})
			omitted = append(omitted, Omitted{File: file, Document: 0, Item: -1, Reason: "parse-error"})
		}
		report := Report{Findings: []Finding{finding}, Omitted: omitted, Paths: []Path{{Component: "kubernetes", Hops: []Hop{{Index: 1, Status: HopBlocked}}}}}
		Finalize(&report)
		Redact(&report)
		return report
	}
	for _, order := range [][]string{{"a", "b", "c", "d"}, {"d", "c", "b", "a"}, {"b", "d", "a", "c"}} {
		report := build(order...)
		locations, omitted := report.Findings[0].Locations, report.Omitted
		if !sort.SliceIsSorted(locations, func(i, j int) bool { return locations[i].File < locations[j].File }) {
			t.Fatalf("%v: locations not ordered by redacted file: %+v", order, locations)
		}
		if !sort.SliceIsSorted(omitted, func(i, j int) bool { return omitted[i].File < omitted[j].File }) {
			t.Fatalf("%v: omitted not ordered by redacted file: %+v", order, omitted)
		}
		if locations[0].File != RedactValue("d") || omitted[0].File != RedactValue("d") || locations[0].Name != RedactValue("n-d") {
			t.Fatalf("%v: first entries %+v %+v", order, locations[0], omitted[0])
		}
	}
	// Without redaction the plain order is kept.
	plain := Report{Omitted: []Omitted{{File: "b"}, {File: "a"}}}
	Finalize(&plain)
	if plain.Omitted[0].File != "a" {
		t.Fatalf("plain order changed: %+v", plain.Omitted)
	}
}
