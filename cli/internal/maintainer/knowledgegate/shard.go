// SPDX-License-Identifier: AGPL-3.0-only

package knowledgegate

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Shard selects a deterministic slice of the extractors for a full
// re-derivation (--rederive-all). An extractor belongs to exactly one of the
// Count shards, chosen by a hash of its id, so the assignment does not move
// when other extractors are added. Running every index 0..Count-1 re-derives
// everything exactly once. The zero value selects everything.
type Shard struct {
	Index, Count int
	// Day is set for "day/N": the index is the UTC day number mod Count, so
	// a run every day covers every extractor once every Count days.
	Day bool
	// Least is set for "least/N": the shard whose last passing run is the
	// oldest, decided from the recorded ShardState (see Resolve).
	Least bool
}

// ParseShard reads "i/n" (0 <= i < n) or "day/n". "" and "all" select
// everything. now is the gate's clock, used only for "day/n".
func ParseShard(s string, now time.Time) (Shard, error) {
	if s == "" || s == "all" {
		return Shard{}, nil
	}
	a, b, ok := strings.Cut(s, "/")
	n, err := strconv.Atoi(b)
	if !ok || err != nil || n < 1 || n > 365 {
		return Shard{}, errors.New("--shard must be all, i/n day/n or least/n with 1 <= n <= 365")
	}
	if a == "least" {
		return Shard{Count: n, Least: true}, nil
	}
	if a == "day" {
		days := int(now.UTC().Unix() / 86400)
		return Shard{Index: days % n, Count: n, Day: true}, nil
	}
	i, err := strconv.Atoi(a)
	if err != nil || i < 0 || i >= n {
		return Shard{}, errors.New("--shard index must satisfy 0 <= i < n")
	}
	return Shard{Index: i, Count: n}, nil
}

// All reports whether the shard selects every extractor.
func (s Shard) All() bool { return s.Count <= 1 }

// Has reports whether extractor id belongs to the shard.
func (s Shard) Has(id string) bool {
	if s.All() {
		return true
	}
	sum := sha256.Sum256([]byte("prufyx-gate-shard\x00" + id))
	return int(binary.BigEndian.Uint64(sum[:8])%uint64(s.Count)) == s.Index
}

func (s Shard) String() string {
	if s.All() {
		return "all"
	}
	return fmt.Sprintf("%d/%d", s.Index, s.Count)
}

// ShardRecord is what the gate remembers of one shard. LastSuccess is the
// last run that passed with that shard (zero: none recorded); LastAttempt the
// last run at all, so a shard that always fails is visible, not just absent.
type ShardRecord struct {
	LastAttempt time.Time `json:"lastAttempt"`
	LastSuccess time.Time `json:"lastSuccess,omitzero"`
	LastResult  string    `json:"lastResult"`
}

// ShardState maps "i/n" to its record. It is a small file the caller
// persists between runs (--shard-state); the workflow does not persist one
// yet, so without it these features are inert.
type ShardState map[string]ShardRecord

const shardStateSchema = "prufyx.io/knowledge-gate-shards/v1"

type shardStateFile struct {
	Schema string     `json:"schema"`
	Shards ShardState `json:"shards"`
}

// ParseShardState reads the state file. An empty file is an empty state; a
// file of another schema or with unknown fields is an error, never guessed.
func ParseShardState(raw []byte) (ShardState, error) {
	if len(strings.TrimSpace(string(raw))) == 0 {
		return ShardState{}, nil
	}
	var f shardStateFile
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&f); err != nil || f.Schema != shardStateSchema {
		return nil, errors.New("the shard state file is not a valid " + shardStateSchema + " document")
	}
	if f.Shards == nil {
		f.Shards = ShardState{}
	}
	return f.Shards, nil
}

// Marshal writes the state file.
func (st ShardState) Marshal() ([]byte, error) {
	return json.MarshalIndent(shardStateFile{Schema: shardStateSchema, Shards: st}, "", "  ")
}

// Resolve turns "least/n" into the shard with the oldest last success (never
// succeeded counts as oldest; ties go to the lowest index). Other shards are
// returned unchanged. Without state every shard is equally old, so it is
// shard 0: callers refuse "least/n" without a state file.
func (s Shard) Resolve(st ShardState) Shard {
	if !s.Least {
		return s
	}
	best, bestAt := 0, time.Time{}
	for i := 0; i < s.Count; i++ {
		at := st[fmt.Sprintf("%d/%d", i, s.Count)].LastSuccess
		if i == 0 || at.Before(bestAt) {
			best, bestAt = i, at
		}
	}
	return Shard{Index: best, Count: s.Count, Least: true}
}

// shardStaleAfter is how long a shard may go without a passing run: its own
// cycle plus a day of slack.
func shardStaleAfter(count int) time.Duration {
	return time.Duration(count+1) * 24 * time.Hour
}

// Update returns the state with this run recorded. Only a --rederive-all run
// with a real shard changes anything. A pass records a success; anything else
// (a failed rule, could not run) only records the attempt.
func (st ShardState) Update(r *Report, shard Shard, now time.Time) ShardState {
	out := ShardState{}
	for k, v := range st {
		out[k] = v
	}
	if shard.All() || r == nil || r.Shard == "" {
		return out
	}
	key := fmt.Sprintf("%d/%d", shard.Index, shard.Count)
	rec := out[key]
	rec.LastAttempt, rec.LastResult = now.UTC(), r.Result
	if r.CouldNotRun != "" {
		rec.LastResult = "could-not-run"
	}
	if r.Passed() && r.CouldNotRun == "" {
		rec.LastSuccess = now.UTC()
	}
	out[key] = rec
	return out
}

// shardStaleCheck raises an alarm for every shard that has been attempted
// before but has no passing run within its schedule. Shards never recorded
// are unknown, not stale; a shard that only ever fails is stale.
func (r *Report) shardStaleCheck(opts Options) {
	sh := opts.Shard
	if !opts.RederiveAll || sh.All() || opts.ShardState == nil {
		return
	}
	for i := 0; i < sh.Count; i++ {
		key := fmt.Sprintf("%d/%d", i, sh.Count)
		rec, ok := opts.ShardState[key]
		if !ok {
			continue
		}
		if rec.LastSuccess.IsZero() {
			r.alarm(AlarmShardStale, "shard %s has never passed (last attempt %s: %s); its rules are not being re-derived", key, rec.LastAttempt.UTC().Format("2006-01-02"), logSafe(rec.LastResult))
		} else if opts.Now.Sub(rec.LastSuccess) > shardStaleAfter(sh.Count) {
			r.alarm(AlarmShardStale, "shard %s last passed on %s, more than %d days ago; its rules are not being re-derived", key, rec.LastSuccess.UTC().Format("2006-01-02"), sh.Count+1)
		}
	}
}
