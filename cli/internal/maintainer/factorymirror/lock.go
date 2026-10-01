// SPDX-License-Identifier: AGPL-3.0-only

package factorymirror

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// ErrLocked is returned when another live process holds the lock.
var ErrLocked = errors.New("factory mirror: state is locked by another run")

// DefaultLockStaleAfter is how long a lock may go without a heartbeat before
// it is considered abandoned.
const DefaultLockStaleAfter = 10 * time.Minute

type lockRecord struct {
	Nonce     string `json:"nonce"`
	PID       int    `json:"pid"`
	Host      string `json:"host"`
	StartedAt string `json:"startedAt"`
}

// Heartbeat age is measured against the real clock because it is compared
// with file modification times.
//
// Lock is a single-writer lock file with heartbeat-based stale recovery.
// A lock is stale when its heartbeat (file modification time) is older than
// the stale interval, or when it names a process on this host that no longer
// exists. Heartbeats rather than pid checks are the primary signal because
// container restarts reuse small pids.
type Lock struct {
	path  string
	nonce string
	stop  chan struct{}
	done  chan struct{}
	once  sync.Once
}

// AcquireLock takes the lock at path, recovering it if stale.
func AcquireLock(path string, staleAfter time.Duration, now func() time.Time) (*Lock, error) {
	if staleAfter <= 0 {
		staleAfter = DefaultLockStaleAfter
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	nonceBytes := make([]byte, 8)
	if _, err := rand.Read(nonceBytes); err != nil {
		return nil, err
	}
	host, _ := os.Hostname()
	rec := lockRecord{Nonce: hex.EncodeToString(nonceBytes), PID: os.Getpid(), Host: host, StartedAt: now().UTC().Format(time.RFC3339)}
	body, _ := json.Marshal(rec)
	for attempt := 0; attempt < 3; attempt++ {
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
		if err == nil {
			_, werr := f.Write(body)
			cerr := f.Close()
			if werr != nil || cerr != nil {
				_ = os.Remove(path)
				return nil, errors.Join(werr, cerr)
			}
			l := &Lock{path: path, nonce: rec.Nonce, stop: make(chan struct{}), done: make(chan struct{})}
			go l.heartbeat(staleAfter / 4)
			return l, nil
		}
		if !errors.Is(err, os.ErrExist) {
			return nil, err
		}
		if !lockIsStale(path, staleAfter, host) {
			return nil, ErrLocked
		}
		// Atomically move the stale lock aside; only one contender wins the rename.
		aside := fmt.Sprintf("%s.stale-%s", path, rec.Nonce)
		if err := os.Rename(path, aside); err == nil {
			_ = os.Remove(aside)
		}
	}
	return nil, ErrLocked
}

func lockIsStale(path string, staleAfter time.Duration, host string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return true // vanished; retry the create
	}
	if time.Since(info.ModTime()) > staleAfter {
		return true
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	var rec lockRecord
	if json.Unmarshal(raw, &rec) != nil {
		// Unreadable lock: wait for the heartbeat window to pass.
		return false
	}
	if rec.Host == host && rec.PID > 0 && !processAlive(rec.PID) {
		return true
	}
	return false
}

func (l *Lock) heartbeat(every time.Duration) {
	defer close(l.done)
	if every < time.Second {
		every = time.Second
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-l.stop:
			return
		case now := <-t.C:
			_ = os.Chtimes(l.path, now, now)
		}
	}
}

// Release removes the lock if it is still ours.
func (l *Lock) Release() {
	l.once.Do(func() {
		close(l.stop)
		<-l.done
		raw, err := os.ReadFile(l.path)
		if err != nil {
			return
		}
		var rec lockRecord
		if json.Unmarshal(raw, &rec) == nil && rec.Nonce == l.nonce {
			_ = os.Remove(l.path)
		}
	})
}
