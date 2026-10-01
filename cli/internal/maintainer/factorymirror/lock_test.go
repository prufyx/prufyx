// SPDX-License-Identifier: AGPL-3.0-only

package factorymirror

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func plantStaleRecord(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(`{"nonce":"x","pid":1,"host":"other","startedAt":"2020-01-01T00:00:00Z"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-time.Hour)
	if err := os.Chtimes(path, old, old); err != nil {
		t.Fatal(err)
	}
}

func TestLockExcludesAndReleases(t *testing.T) {
	path := filepath.Join(t.TempDir(), "locks", "mirror.lock")
	l1, err := AcquireLock(path, 0, fixedNow())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := AcquireLock(path, 0, fixedNow()); !errors.Is(err, ErrLocked) {
		t.Fatalf("want ErrLocked, got %v", err)
	}
	raw, err := os.ReadFile(path)
	var rec lockRecord
	if err != nil || json.Unmarshal(raw, &rec) != nil || rec.PID != os.Getpid() || rec.Nonce == "" {
		t.Fatalf("lock record: %q %v", raw, err)
	}
	l1.Release()
	l1.Release() // idempotent
	if _, err := os.Stat(path); err == nil {
		t.Fatal("release must remove the lock file")
	}
	l2, err := AcquireLock(path, 0, fixedNow())
	if err != nil {
		t.Fatalf("lock not free after release: %v", err)
	}
	l2.Release()
}

// holders runs fn from many goroutines against one lock path, each holding
// for a short while, and reports the highest number of simultaneous holders.
func stressLock(t *testing.T, goroutines, rounds int, acquire func() (func(), error)) (maxHolders int32, acquired int32) {
	t.Helper()
	var cur, peak, got atomic.Int32
	for r := 0; r < rounds; r++ {
		var wg sync.WaitGroup
		start := make(chan struct{})
		for i := 0; i < goroutines; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				release, err := acquire()
				if err != nil {
					return
				}
				n := cur.Add(1)
				for {
					p := peak.Load()
					if n <= p || peak.CompareAndSwap(p, n) {
						break
					}
				}
				got.Add(1)
				time.Sleep(time.Millisecond)
				cur.Add(-1)
				release()
			}()
		}
		close(start)
		wg.Wait()
	}
	return peak.Load(), got.Load()
}

func TestExclFallbackNeverTakesOverAndHasExactlyOneHolder(t *testing.T) {
	path := filepath.Join(t.TempDir(), "locks", "mirror.lock")
	acquire := func() (func(), error) {
		rec := lockRecord{Nonce: randHex(t), PID: os.Getpid(), Host: "this"}
		body, _ := json.Marshal(rec)
		return acquireExcl(path, body, rec, DefaultLockStaleAfter)
	}
	for r := 0; r < 20; r++ {
		plantStaleRecord(t, path)
		if p, a := stressLock(t, 16, 1, acquire); p != 0 || a != 0 {
			t.Fatalf("round %d: a stale lock was taken over (peak %d, acquired %d)", r, p, a)
		}
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
		if p, a := stressLock(t, 16, 1, acquire); p != 1 || a < 1 {
			t.Fatalf("round %d: free lock: peak %d holders, %d acquisitions", r, p, a)
		}
	}
}

var nonceSeq atomic.Int64

func randHex(t *testing.T) string {
	t.Helper()
	return fmt.Sprintf("%d-%d", time.Now().UnixNano(), nonceSeq.Add(1))
}

func TestExclFallbackRefusesStaleAndDeadHolders(t *testing.T) {
	path := filepath.Join(t.TempDir(), "locks", "mirror.lock")
	acquire := func() (func(), error) {
		rec := lockRecord{Nonce: randHex(t), PID: os.Getpid(), Host: "this"}
		body, _ := json.Marshal(rec)
		return acquireExcl(path, body, rec, DefaultLockStaleAfter)
	}
	plantStaleRecord(t, path)
	fresh := time.Now()
	if err := os.Chtimes(path, fresh, fresh); err != nil {
		t.Fatal(err)
	}
	if _, err := acquire(); !errors.Is(err, ErrLocked) || errors.Is(err, ErrStaleLock) {
		t.Fatalf("fresh lock of another host must hold as live: %v", err)
	}
	plantStaleRecord(t, path)
	if _, err := acquire(); !errors.Is(err, ErrStaleLock) || !errors.Is(err, ErrLocked) {
		t.Fatalf("stale lock must be refused, not taken over: %v", err)
	}
	if runtime.GOOS != "windows" {
		host, _ := os.Hostname()
		body := `{"nonce":"x","pid":2147483646,"host":"` + host + `","startedAt":"2020-01-01T00:00:00Z"}`
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		rec := lockRecord{Nonce: "y", PID: os.Getpid(), Host: host}
		b, _ := json.Marshal(rec)
		if _, err := acquireExcl(path, b, rec, DefaultLockStaleAfter); !errors.Is(err, ErrStaleLock) {
			t.Fatalf("dead-pid lock must be refused, not taken over: %v", err)
		}
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	rel, err := acquire()
	if err != nil {
		t.Fatalf("lock not free after manual removal: %v", err)
	}
	rel()
	if _, err := os.Stat(path); err == nil {
		t.Fatal("release must remove the lock file")
	}
}

func TestExclFallbackForeignReleaseKeepsLock(t *testing.T) {
	path := filepath.Join(t.TempDir(), "locks", "mirror.lock")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	rec1 := lockRecord{Nonce: "one", PID: os.Getpid(), Host: "h"}
	b1, _ := json.Marshal(rec1)
	rel1, err := acquireExcl(path, b1, rec1, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	// Someone else took over (simulated): the file now carries another nonce.
	if err := os.WriteFile(path, []byte(`{"nonce":"two","pid":1,"host":"h"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	rel1()
	if _, err := os.Stat(path); err != nil {
		t.Fatal("a late release removed somebody else's lock")
	}
}
