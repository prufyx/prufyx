// SPDX-License-Identifier: AGPL-3.0-only

package crdversions

import (
	"encoding/json"
	"path/filepath"
	"testing"
)

// A mixed attest vector: the hop 1.1 -> 1.3 skips a minor, so it never
// attests; the pairs on both sides do. The shared derivation gives minFrom
// 1.3 (the run to the newest pair), a recorded stop for the skipped hop and
// derivedFrom 1.0 (the attested pair below the stop).
func TestOracleFloorMixedVector(t *testing.T) {
	a := crd("Alpha", "v1")
	files := map[string]string{"deploy/crds/a.yaml": a}
	out := runSynth(t, communityTarget(), newSynth(
		release{"v1.0.0", files}, release{"v1.1.0", files}, release{"v1.3.0", files}, release{"v1.4.0", files},
	))
	dir := filepath.Join(t.TempDir(), "out")
	must(t, out.Write(dir))
	good := ExpectedFloor{MinFrom: "1.3", DerivedFrom: "1.0", Depth: 10, Stops: []ExpectedStop{{FromLine: "1.1", ToLine: "1.3", Code: "hop-not-previous-minor"}}}
	run := func(f ExpectedFloor) error {
		raw, err := json.Marshal(Expected{Floor: &f})
		must(t, err)
		_, err = Oracle(dir, raw)
		return err
	}
	if err := run(good); err != nil {
		t.Fatalf("the derived floor was refused: %v", err)
	}
	cases := map[string]func(*ExpectedFloor){
		"hand-lowered minFrom over the skipped hop": func(f *ExpectedFloor) { f.MinFrom = "1.1" },
		"hand-lowered minFrom to the start":         func(f *ExpectedFloor) { f.MinFrom = "1.0" },
		"hand-lowered derivedFrom":                  func(f *ExpectedFloor) { f.DerivedFrom = "0.9" },
		"raised derivedFrom":                        func(f *ExpectedFloor) { f.DerivedFrom = "1.1" },
		"derivedFrom above minFrom":                 func(f *ExpectedFloor) { f.DerivedFrom = "1.4" },
		"missing stop":                              func(f *ExpectedFloor) { f.Stops = nil },
		"unknown stop code":                         func(f *ExpectedFloor) { f.Stops[0].Code = "because" },
		"transient stop code":                       func(f *ExpectedFloor) { f.Stops[0].Code = "release-pending" },
		"stop on an attested pair": func(f *ExpectedFloor) {
			f.Stops = append(f.Stops, ExpectedStop{FromLine: "1.0", ToLine: "1.1", Code: "scan-unclean"})
		},
		"no depth":                func(f *ExpectedFloor) { f.Depth = 0 },
		"depth over the hard max": func(f *ExpectedFloor) { f.Depth = 25 },
		"not a line":              func(f *ExpectedFloor) { f.MinFrom = "one" },
	}
	for name, mutate := range cases {
		f := good
		f.Stops = append([]ExpectedStop(nil), good.Stops...)
		mutate(&f)
		if err := run(f); err == nil {
			t.Fatalf("%s: accepted", name)
		}
	}
}
