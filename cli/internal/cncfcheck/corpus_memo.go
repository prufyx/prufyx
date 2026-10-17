// SPDX-License-Identifier: AGPL-3.0-only

package cncfcheck

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"sync"

	"github.com/prufyx/prufyx/cli/internal/constraintengine"
)

// maxCorpusMemo bounds the memo: a check selects a handful of distinct rule
// documents per project, so the bound is generous. A full memo is dropped
// whole, which only costs a re-parse.
const maxCorpusMemo = 512

// corpusMemo remembers parsed rule documents by the content that produced
// them. The key is a SHA-256 over everything parseRulesCorpus reads (document
// identity fields, registry digest, corpus attestation components and every
// rule's bytes, each length-prefixed), so a different or modified bundle,
// registry or selection never reuses a parse. Only successes are kept.
// constraintengine.RuleSet is a value whose fields are unexported and which
// the engine only reads, so one parse is shared by concurrent checks without
// copying.
var corpusMemo struct {
	sync.Mutex
	parsed map[[sha256.Size]byte]constraintengine.RuleSet
}

func corpusKey(b bundle, rules []json.RawMessage, corpus []string) [sha256.Size]byte {
	h := sha256.New()
	var length [8]byte
	write := func(part []byte) {
		binary.BigEndian.PutUint64(length[:], uint64(len(part)))
		h.Write(length[:])
		h.Write(part)
	}
	write([]byte(b.pack.Revision))
	write([]byte(b.pack.PolicyID))
	write([]byte(b.pack.PolicyDigest))
	write([]byte(b.registry.Digest()))
	binary.BigEndian.PutUint64(length[:], uint64(len(corpus)))
	h.Write(length[:])
	for _, component := range corpus {
		write([]byte(component))
	}
	binary.BigEndian.PutUint64(length[:], uint64(len(rules)))
	h.Write(length[:])
	for _, rule := range rules {
		write(rule)
	}
	var key [sha256.Size]byte
	h.Sum(key[:0])
	return key
}

// memoizedParse returns the memoized parse of the document, or runs parse
// once more and keeps a successful result.
func memoizedParse(b bundle, rules []json.RawMessage, corpus []string, parse func() (constraintengine.RuleSet, error)) (constraintengine.RuleSet, error) {
	key := corpusKey(b, rules, corpus)
	corpusMemo.Lock()
	cached, ok := corpusMemo.parsed[key]
	corpusMemo.Unlock()
	if ok {
		return cached, nil
	}
	parsed, err := parse()
	if err != nil {
		return constraintengine.RuleSet{}, err
	}
	corpusMemo.Lock()
	if corpusMemo.parsed == nil || len(corpusMemo.parsed) >= maxCorpusMemo {
		corpusMemo.parsed = map[[sha256.Size]byte]constraintengine.RuleSet{}
	}
	corpusMemo.parsed[key] = parsed
	corpusMemo.Unlock()
	return parsed, nil
}
