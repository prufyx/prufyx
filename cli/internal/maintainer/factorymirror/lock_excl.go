// SPDX-License-Identifier: AGPL-3.0-only

package factorymirror

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"
)

// ErrStaleLock is returned by the portable lock when the existing lock looks
// abandoned. The portable lock never takes over a lock automatically:
// without an advisory file lock a takeover can race with a live holder, so a
// person must confirm the previous run is gone and remove the file.
var ErrStaleLock = fmt.Errorf("%w (the lock looks stale; confirm no run is active and remove the lock file)", ErrLocked)

// acquireExcl is the portable lock used where flock is unavailable: an
// exclusively created file whose modification time is refreshed while the
// holder lives. An existing lock is never removed or replaced here.
func acquireExcl(path string, body []byte, rec lockRecord, staleAfter time.Duration) (func(), error) {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		if !errors.Is(err, os.ErrExist) {
			return nil, err
		}
		if _, stale := lockIsStale(path, staleAfter, rec.Host); stale {
			return nil, ErrStaleLock
		}
		return nil, ErrLocked
	}
	_, werr := f.Write(body)
	cerr := f.Close()
	if werr != nil || cerr != nil {
		_ = os.Remove(path)
		return nil, errors.Join(werr, cerr)
	}
	stop, done := make(chan struct{}), make(chan struct{})
	go heartbeat(path, staleAfter/4, stop, done)
	return func() {
		close(stop)
		<-done
		raw, err := os.ReadFile(path)
		if err != nil {
			return
		}
		var cur lockRecord
		if json.Unmarshal(raw, &cur) == nil && cur.Nonce == rec.Nonce {
			_ = os.Remove(path)
		}
	}, nil
}

// lockIsStale returns the lock file content that was judged and whether it
// is stale.
func lockIsStale(path string, staleAfter time.Duration, host string) ([]byte, bool) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, true // vanished; retry the create
	}
	raw, rerr := os.ReadFile(path)
	if time.Since(info.ModTime()) > staleAfter {
		return raw, true
	}
	if rerr != nil {
		return nil, false
	}
	var rec lockRecord
	if json.Unmarshal(raw, &rec) != nil {
		// Unreadable lock: wait for the heartbeat window to pass.
		return nil, false
	}
	if rec.Host == host && rec.PID > 0 && !processAlive(rec.PID) {
		return raw, true
	}
	return nil, false
}

func heartbeat(path string, every time.Duration, stop, done chan struct{}) {
	defer close(done)
	if every < time.Second {
		every = time.Second
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case now := <-t.C:
			_ = os.Chtimes(path, now, now)
		}
	}
}
