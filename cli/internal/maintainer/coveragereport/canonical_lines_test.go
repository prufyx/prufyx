// SPDX-License-Identifier: AGPL-3.0-only

package coveragereport

import (
	"bytes"
	"os"
	"reflect"
	"strings"
	"testing"
)

const canonicalLinesFile = "data/coverage-lines.json"

func readCanonicalLines(t *testing.T) []byte {
	t.Helper()
	raw, err := os.ReadFile(canonicalLinesFile)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestCanonicalLinesParsesAndRoundTrips(t *testing.T) {
	raw := readCanonicalLines(t)
	f, err := ParseLines(raw)
	if err != nil {
		t.Fatal(err)
	}
	if f.Schema != LinesSchema {
		t.Fatalf("schema %q, want %q", f.Schema, LinesSchema)
	}
	out, err := MarshalLines(f)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out, raw) {
		t.Fatal("data/coverage-lines.json is not the canonical MarshalLines form")
	}
}

// The canonical snapshot holds exactly the lines the README block is
// measured against: the pinned snapshot plus the additions file.
func TestCanonicalLinesEqualPinnedUnion(t *testing.T) {
	canon, err := ParseLines(readCanonicalLines(t))
	if err != nil {
		t.Fatal(err)
	}
	pinnedRaw, err := os.ReadFile("../../../../" + PinnedLinesPath)
	if err != nil {
		t.Fatal(err)
	}
	addRaw, err := os.ReadFile("../../../../" + PinnedAdditionsPath)
	if err != nil {
		t.Fatal(err)
	}
	pinned, err := ParseLines(pinnedRaw)
	if err != nil {
		t.Fatal(err)
	}
	add, err := ParseAdditions(addRaw)
	if err != nil {
		t.Fatal(err)
	}
	if err := CheckDisjoint(pinned, add); err != nil {
		t.Fatal(err)
	}
	for slug, e := range add.Additions {
		pl := e.ProjectLines
		pl.CapturedOn = e.CapturedOn
		pinned.Projects[slug] = pl
	}
	if !reflect.DeepEqual(canon.Projects, pinned.Projects) {
		t.Fatal("canonical projects differ from pinned snapshot plus additions")
	}
	if canon.CapturedOn != pinnedCapturedOn(t, pinnedRaw) {
		t.Errorf("capturedOn %q differs from the pinned snapshot's", canon.CapturedOn)
	}
	// The file-level date is the pinned snapshot's; each addition keeps its
	// own capture date as a per-project capturedOn, and no other project has
	// one (the DeepEqual above covers both).
	for slug, e := range add.Additions {
		if canon.Projects[slug].CapturedOn != e.CapturedOn {
			t.Errorf("%s: capturedOn %q, its capture date is %q", slug, canon.Projects[slug].CapturedOn, e.CapturedOn)
		}
	}
	date, err := EvaluationClockDate(pinned, add)
	if err != nil {
		t.Fatal(err)
	}
	if canon.PinnedOn != date {
		t.Errorf("pinnedOn %q, README evaluation date %q", canon.PinnedOn, date)
	}
}

func pinnedCapturedOn(t *testing.T, raw []byte) string {
	t.Helper()
	f, err := ParseLines(raw)
	if err != nil {
		t.Fatal(err)
	}
	return f.CapturedOn
}

func TestCanonicalLinesMutationsRejected(t *testing.T) {
	raw := string(readCanonicalLines(t))
	for name, mutated := range map[string]string{
		"unknown field": strings.Replace(raw, `"projects"`, `"extra": 1,`+"\n  "+`"projects"`, 1),
		"wrong schema":  strings.Replace(raw, LinesSchema, "prufyx.io/coverage-lines/v2", 1),
		"trailing data": raw + "{}",
	} {
		if mutated == raw && name != "trailing data" {
			t.Fatalf("%s: mutation did not apply", name)
		}
		if _, err := ParseLines([]byte(mutated)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// A report computed from the canonical file alone equals the report of the
// README block inputs (pinned snapshot plus additions): every project, every
// count and every completion reason, so no addition loses its own capture date.
func TestCanonicalLinesReportEqualsReadmeInputs(t *testing.T) {
	canonRaw := readCanonicalLines(t)
	pinnedRaw, err := os.ReadFile("../../../../" + PinnedLinesPath)
	if err != nil {
		t.Fatal(err)
	}
	addRaw, err := os.ReadFile("../../../../" + PinnedAdditionsPath)
	if err != nil {
		t.Fatal(err)
	}
	packRaw, err := os.ReadFile("testdata/pack-cncf-2026-09-13.4-reduced.json")
	if err != nil {
		t.Fatal(err)
	}
	canon, _ := ParseLines(canonRaw)
	pinned, _ := ParseLines(pinnedRaw)
	add, err := ParseAdditions(addRaw)
	if err != nil {
		t.Fatal(err)
	}
	now, err := EvaluationClock(pinned, add)
	if err != nil {
		t.Fatal(err)
	}
	alone, err := EvaluationClock(canon, AdditionsFile{})
	if err != nil || !alone.Equal(now) {
		t.Fatalf("canonical clock %v, README clock %v (%v)", alone, now, err)
	}
	for _, all := range []bool{false, true} {
		want, err := Compute(Input{Pack: packRaw, Lines: pinnedRaw, Additions: addRaw, Now: now, All: all})
		if err != nil {
			t.Fatal(err)
		}
		got, err := Compute(Input{Pack: packRaw, Lines: canonRaw, Now: now, All: all})
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(want.Fleet, got.Fleet) || !reflect.DeepEqual(want.Projects, got.Projects) {
			t.Errorf("all=%v: report from the canonical file differs from the README inputs", all)
		}
	}
}
