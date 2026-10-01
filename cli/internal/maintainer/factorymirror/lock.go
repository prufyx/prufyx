// SPDX-License-Identifier: AGPL-3.0-only

package factorymirror

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// ErrLocked is returned when another live process holds the lock.
var ErrLocked = errors.New("factory mirror: state is locked by another run")

// DefaultLockStaleAfter is how long a lock may go without a heartbeat before
// it is considered abandoned. It only matters where the operating system
// cannot tell us whether the holder is alive (see lock_other.go).
const DefaultLockStaleAfter = 10 * time.Minute

type lockRecord struct {
	Nonce     string `json:"nonce"`
	PID       int    `json:"pid"`
	Host      string `json:"host"`
	StartedAt string `json:"startedAt"`
}

// Lock is a single-writer lock on the state directory.
//
// On unix systems it is an advisory flock(2) on the lock file: the kernel
// drops the lock when the holder dies, so there is no stale-lock recovery
// that two contenders could race through. Elsewhere it falls back to an
// exclusive-create lock file with heartbeat-based recovery (lock_excl.go).
type Lock struct {
	release func()
	once    sync.Once
}

// AcquireLock takes the lock at path. staleAfter applies only to the
// fallback implementation.
func AcquireLock(path string, staleAfter time.Duration, now func() time.Time) (*Lock, error) {
	if staleAfter <= 0 {
		staleAfter = DefaultLockStaleAfter
	}
	if now == nil {
		now = time.Now
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
	release, err := platformAcquire(path, body, rec, staleAfter)
	if err != nil {
		return nil, err
	}
	return &Lock{release: release}, nil
}

// Release gives the lock up. It is safe to call more than once.
func (l *Lock) Release() {
	l.once.Do(func() {
		if l.release != nil {
			l.release()
		}
	})
}
