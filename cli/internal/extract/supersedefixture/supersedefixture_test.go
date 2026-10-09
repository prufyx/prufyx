// SPDX-License-Identifier: AGPL-3.0-only

package supersedefixture

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/extract/supersedeids"
)

func shipped(t *testing.T) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "cncfcheck", "data", "rules.json"))
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// The fixture's 25 entries are the reviewed rules, one for each reviewed id.
func TestFixtureHoldsTheReviewedRules(t *testing.T) {
	want := map[string]bool{}
	for _, id := range supersedeids.ReviewedIDs() {
		want[id] = true
	}
	entries := ReviewedEntries()
	if len(entries) != 25 {
		t.Fatalf("%d entries", len(entries))
	}
	for _, raw := range entries {
		id, err := ruleID(raw)
		if err != nil || !want[id] {
			t.Fatalf("entry %q: %v", id, err)
		}
		delete(want, id)
	}
}

// Reviewed restores the reviewed generation from either generation and is a
// fixed point; on the reviewed pack it changes nothing.
func TestReviewedRestoresTheReviewedGeneration(t *testing.T) {
	out, err := Reviewed(shipped(t))
	if err != nil {
		t.Fatal(err)
	}
	if superseded, err := supersedeids.Generation(out); err != nil || superseded {
		t.Fatalf("generation %v err %v", superseded, err)
	}
	again, err := Reviewed(out)
	if err != nil || string(again) != string(out) {
		t.Fatalf("not a fixed point: %v", err)
	}
	if !supersedeids.Superseded() && string(out) != string(shipped(t)) {
		t.Fatal("the reviewed shipped pack was changed")
	}
}

// While the shipped pack holds the reviewed rules, each of the 25 fixture
// entries is byte-for-byte the entry of the shipped pack (compared compact,
// key order included), so that a reattestation or any other edit of one of
// the 25 rules before the supersede cannot leave a stale fixture behind. After
// the supersede the shipped pack no longer holds them and the fixture is the
// only copy.
func TestFixtureEntriesAreTheShippedReviewedEntries(t *testing.T) {
	if supersedeids.Superseded() {
		t.Skip("the shipped pack holds the mechanical rules; the fixture is the only copy of the reviewed ones")
	}
	var pack struct {
		Entries []json.RawMessage `json:"entries"`
	}
	if err := json.Unmarshal(shipped(t), &pack); err != nil {
		t.Fatal(err)
	}
	compact := func(raw json.RawMessage) []byte {
		var out bytes.Buffer
		if err := json.Compact(&out, raw); err != nil {
			t.Fatal(err)
		}
		return out.Bytes()
	}
	shippedByID := map[string][]byte{}
	for _, raw := range pack.Entries {
		id, err := ruleID(raw)
		if err != nil {
			t.Fatal(err)
		}
		shippedByID[id] = compact(raw)
	}
	matched := 0
	for _, raw := range ReviewedEntries() {
		id, err := ruleID(raw)
		if err != nil {
			t.Fatal(err)
		}
		want, ok := shippedByID[id]
		if !ok {
			t.Errorf("%s is not in the shipped pack", id)
			continue
		}
		if !bytes.Equal(compact(raw), want) {
			t.Errorf("%s: the fixture entry differs from the shipped pack's", id)
			continue
		}
		matched++
	}
	if matched != 25 {
		t.Fatalf("%d of 25 fixture entries equal the shipped ones", matched)
	}
}
