// SPDX-License-Identifier: AGPL-3.0-only

//go:build prufyx_synthetic_knowledge

package cncfcheck

import (
	"reflect"
	"testing"
)

// Synthetic build: loads inside one generation return equal, independent
// clones; a swap or restore starts a new generation.
func TestSyntheticLoadMemoizedPerGeneration(t *testing.T) {
	restore, err := UseSyntheticKnowledge(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer restore()
	first, err := load()
	if err != nil {
		t.Fatal(err)
	}
	second, err := load()
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(first, second) {
		t.Fatal("two loads in one generation differ")
	}
	if len(first.pack.Entries) == 0 || len(first.priority.Priority) == 0 {
		t.Fatal("fixture bundle unexpectedly empty")
	}
	first.pack.Entries[0].Rule[0] ^= 0xff
	first.priority.Priority[0] = "mutated"
	third, err := load()
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(second, third) {
		t.Fatal("mutating one load's copy changed a later load")
	}
	if second.pack.Revision != "synthetic-test-only" {
		t.Fatalf("revision %q", second.pack.Revision)
	}
}

func TestSyntheticRestoreInvalidatesMemo(t *testing.T) {
	restore, err := UseSyntheticKnowledge(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	during, err := load()
	if err != nil {
		restore()
		t.Fatal(err)
	}
	restore()
	after, err := load()
	if err != nil {
		t.Fatal(err)
	}
	if during.pack.Revision == after.pack.Revision {
		t.Fatalf("restore served the synthetic bundle (revision %q)", after.pack.Revision)
	}
	restoreAgain, err := UseSyntheticKnowledge(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer restoreAgain()
	again, err := load()
	if err != nil {
		t.Fatal(err)
	}
	if again.pack.Revision != "synthetic-test-only" {
		t.Fatalf("new swap served revision %q", again.pack.Revision)
	}
}
