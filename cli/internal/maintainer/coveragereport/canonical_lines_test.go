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
		pinned.Projects[slug] = e.ProjectLines
	}
	if !reflect.DeepEqual(canon.Projects, pinned.Projects) {
		t.Fatal("canonical projects differ from pinned snapshot plus additions")
	}
	if canon.CapturedOn != pinnedCapturedOn(t, pinnedRaw) {
		t.Errorf("capturedOn %q differs from the pinned snapshot's", canon.CapturedOn)
	}
	// Per-project capture dates are dropped on purpose: the single capturedOn
	// must not be newer than any addition's own capture date.
	for slug, e := range add.Additions {
		if canon.CapturedOn > e.CapturedOn {
			t.Errorf("capturedOn %q is newer than the capture date %q of %s", canon.CapturedOn, e.CapturedOn, slug)
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
