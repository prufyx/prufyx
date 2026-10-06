// SPDX-License-Identifier: AGPL-3.0-only

package cncfcheck

import (
	"errors"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
)

// The memoized bundle is exactly the uncached one, call after call.
func TestMemoizedBundleEqualsUncached(t *testing.T) {
	want, err := loadUncached()
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		got, err := load()
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("call %d: load() differs from loadUncached()", i)
		}
	}
}

// Concurrent first use runs the loader once and every caller sees the same
// bundle. Run under -race.
func TestBundleMemoConcurrentFirstUse(t *testing.T) {
	var m bundleMemo
	var calls int32
	loader := func() (bundle, error) {
		atomic.AddInt32(&calls, 1)
		return loadUncached()
	}
	want, err := loadUncached()
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			got, err := m.get(loader)
			if err != nil || !reflect.DeepEqual(got, want) {
				t.Errorf("concurrent get: err=%v equal=%v", err, reflect.DeepEqual(got, want))
			}
			got.pack.Entries[0].Description = "mutated" // own copy: race detector proves isolation
		}()
	}
	wg.Wait()
	if calls != 1 {
		t.Fatalf("loader ran %d times", calls)
	}
}

// Chosen policy: mutation cannot affect the cache (copy on read). Every
// writable part is changed in one caller; the next caller still gets the
// uncached bundle.
func TestMutatingALoadedBundleDoesNotAffectTheCache(t *testing.T) {
	want, err := loadUncached()
	if err != nil {
		t.Fatal(err)
	}
	b, err := load()
	if err != nil {
		t.Fatal(err)
	}
	b.landscape.Projects[0].Name = "x"
	b.priority.Priority[0] = "x"
	b.pack.Revision = "x"
	b.pack.Entries[0].Description = "x"
	b.pack.Entries[0].Rule[0] = '#'
	b.pack.Entries[0].RequiredFacts[0].ID = "x"
	if len(b.pack.Entries[0].RequiredFacts[0].EnumTokens) > 0 {
		b.pack.Entries[0].RequiredFacts[0].EnumTokens[0] = "x"
	}
	for _, raw := range []*[]byte{(*[]byte)(&b.pack.LineAttestations), (*[]byte)(&b.pack.PathPolicies), (*[]byte)(&b.pack.Distributions), (*[]byte)(&b.pack.ServedAPIs)} {
		if len(*raw) > 0 {
			(*raw)[0] = '#'
		}
	}
	again, err := load()
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(again, want) {
		t.Fatal("a caller's mutation reached the cache")
	}
}

// A failed first load is cached as a failure: no retry, no fallback.
func TestBundleMemoCachesFailure(t *testing.T) {
	var m bundleMemo
	calls := 0
	loader := func() (bundle, error) { calls++; return bundle{}, ErrIntegrity }
	for i := 0; i < 3; i++ {
		b, err := m.get(loader)
		if !errors.Is(err, ErrIntegrity) || !reflect.DeepEqual(b, bundle{}) {
			t.Fatalf("call %d: %v", i, err)
		}
	}
	if calls != 1 {
		t.Fatalf("loader ran %d times after a failure", calls)
	}
}
