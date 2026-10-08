// SPDX-License-Identifier: AGPL-3.0-only

package knowledgegate

import (
	"crypto/sha256"
	"encoding/binary"
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
		return Shard{}, errors.New("--shard must be all, i/n or day/n with 1 <= n <= 365")
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
