// SPDX-License-Identifier: AGPL-3.0-only

package factorymirror

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"
)

// exclTakeover serializes stale-lock takeovers inside one process, so that
// the rename below always acts on the file whose staleness was just judged.
// Between processes the fallback remains best effort; the flock
// implementation is the one that is exact.
var exclTakeover sync.Mutex

// acquireExcl is the portable lock: an exclusively created file whose
// modification time is refreshed while the holder lives. A lock whose
// heartbeat is older than staleAfter (or whose holder process is gone) is
// taken over by moving it aside and creating a new one. The moved-aside file
// is checked to still be the record that was judged stale; if a live lock was
// moved by mistake it is put back.
func acquireExcl(path string, body []byte, rec lockRecord, staleAfter time.Duration) (func(), error) {
	for attempt := 0; attempt < 3; attempt++ {
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
		if err == nil {
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
		if !errors.Is(err, os.ErrExist) {
			return nil, err
		}
		if !takeOverIfStale(path, staleAfter, rec) {
			return nil, ErrLocked
		}
	}
	return nil, ErrLocked
}

// takeOverIfStale reports whether the lock at path is gone (removed or
// moved away) so that the caller may retry creating it.
func takeOverIfStale(path string, staleAfter time.Duration, rec lockRecord) bool {
	exclTakeover.Lock()
	defer exclTakeover.Unlock()
	raw, stale := lockIsStale(path, staleAfter, rec.Host)
	if !stale {
		return false
	}
	aside := fmt.Sprintf("%s.stale-%s", path, rec.Nonce)
	if err := os.Rename(path, aside); err != nil {
		return errors.Is(err, os.ErrNotExist) // vanished meanwhile: retry the create
	}
	moved, err := os.ReadFile(aside)
	if err == nil && !bytes.Equal(moved, raw) {
		// A different, possibly live, lock was moved. Put it back.
		if lerr := os.Link(aside, path); lerr == nil {
			_ = os.Remove(aside)
			return false
		}
	}
	_ = os.Remove(aside)
	return true
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
