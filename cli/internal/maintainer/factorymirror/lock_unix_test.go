// SPDX-License-Identifier: AGPL-3.0-only

//go:build unix

package factorymirror

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"
)

func TestFlockLeftoverFileWithoutHolderIsAcquirable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "locks", "mirror.lock")
	// A crashed holder leaves its file behind; the kernel dropped its lock.
	plantStaleRecord(t, path)
	l, err := AcquireLock(path, 0, fixedNow())
	if err != nil {
		t.Fatalf("leftover lock file blocked acquisition: %v", err)
	}
	l.Release()
}

func TestFlockStaleLockRecoveryHasExactlyOneHolder(t *testing.T) {
	path := filepath.Join(t.TempDir(), "locks", "mirror.lock")
	var peak, acquired int32
	const rounds = 60
	for r := 0; r < rounds; r++ {
		plantStaleRecord(t, path)
		p, a := stressLock(t, 16, 1, func() (func(), error) {
			l, err := AcquireLock(path, time.Minute, fixedNow())
			if err != nil {
				return nil, err
			}
			return l.Release, nil
		})
		if p > peak {
			peak = p
		}
		acquired += a
	}
	if peak != 1 {
		t.Fatalf("%d simultaneous holders", peak)
	}
	if acquired < rounds {
		t.Fatalf("nobody won some rounds: %d/%d", acquired, rounds)
	}
}

// Back-to-back acquire/release across goroutines exercises the unlink race
// of lock files that are removed on release.
func TestFlockReleaseRaceNeverAdmitsTwoHolders(t *testing.T) {
	path := filepath.Join(t.TempDir(), "locks", "mirror.lock")
	var inside, violations int32
	var mu sync.Mutex
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				l, err := AcquireLock(path, time.Minute, fixedNow())
				if err != nil {
					continue
				}
				mu.Lock()
				inside++
				if inside > 1 {
					violations++
				}
				mu.Unlock()
				mu.Lock()
				inside--
				mu.Unlock()
				l.Release()
			}
		}()
	}
	wg.Wait()
	if violations != 0 {
		t.Fatalf("%d overlapping holders", violations)
	}
}

const lockHelperEnv = "PRUFYX_TEST_LOCK_HELPER"

// TestLockHelperProcess is the body of the child processes started by
// TestFlockStaleLockRecoveryAcrossProcesses; it does nothing otherwise.
func TestLockHelperProcess(t *testing.T) {
	dir := os.Getenv(lockHelperEnv)
	if dir == "" {
		t.Skip("helper process only")
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		l, err := AcquireLock(filepath.Join(dir, "locks", "mirror.lock"), time.Minute, time.Now)
		if err != nil {
			time.Sleep(time.Millisecond)
			continue
		}
		marker := filepath.Join(dir, "inside")
		f, err := os.OpenFile(marker, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
		if err != nil {
			_ = os.WriteFile(filepath.Join(dir, fmt.Sprintf("violation-%d", os.Getpid())), nil, 0o644)
		} else {
			f.Close()
			time.Sleep(5 * time.Millisecond)
			_ = os.Remove(marker)
			_ = os.WriteFile(filepath.Join(dir, fmt.Sprintf("won-%d", os.Getpid())), nil, 0o644)
		}
		l.Release()
		return
	}
}

func TestFlockStaleLockRecoveryAcrossProcesses(t *testing.T) {
	if testing.Short() {
		t.Skip("spawns processes")
	}
	for round := 0; round < 6; round++ {
		dir := t.TempDir()
		plantStaleRecord(t, filepath.Join(dir, "locks", "mirror.lock"))
		var cmds []*exec.Cmd
		for i := 0; i < 8; i++ {
			cmd := exec.Command(os.Args[0], "-test.run=^TestLockHelperProcess$", "-test.count=1")
			cmd.Env = append(os.Environ(), lockHelperEnv+"="+dir)
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			cmds = append(cmds, cmd)
		}
		for _, c := range cmds {
			_ = c.Wait()
		}
		if v, _ := filepath.Glob(filepath.Join(dir, "violation-*")); len(v) != 0 {
			t.Fatalf("round %d: %d processes held the lock at the same time", round, len(v))
		}
		won, _ := filepath.Glob(filepath.Join(dir, "won-*"))
		if len(won) != len(cmds) {
			t.Fatalf("round %d: %s of %d processes completed", round, strconv.Itoa(len(won)), len(cmds))
		}
	}
}
