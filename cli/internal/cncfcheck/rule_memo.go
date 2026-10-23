// SPDX-License-Identifier: AGPL-3.0-only

package cncfcheck

import (
	"crypto/sha256"
	"encoding/json"
	"sync"

	"github.com/prufyx/prufyx/cli/internal/constraintengine"
)

// maxRuleMemo bounds the per-rule memo. It holds a few derived values per
// distinct rule document; a full memo is dropped whole and rebuilt.
const maxRuleMemo = 1 << 15

type ruleMemoKey struct {
	kind byte
	sum  [sha256.Size]byte
}

const (
	memoFacts byte = iota + 1
	memoTransition
	memoNeutral
	memoBasis
	memoTransitionOnly
)

// ruleMemo remembers values derived from one rule document by the SHA-256 of
// its bytes, so a changed rule never reuses an old derivation and the bundle
// copy a caller got from load() (whose byte slices are its own) hits the same
// entry as every other copy. Only successes are kept. The values are read
// only by their callers.
var ruleMemo struct {
	sync.Mutex
	values map[ruleMemoKey]any
}

func memoRule[T any](kind byte, raw json.RawMessage, derive func(json.RawMessage) (T, error)) (T, error) {
	key := ruleMemoKey{kind: kind, sum: sha256.Sum256(raw)}
	ruleMemo.Lock()
	cached, ok := ruleMemo.values[key]
	ruleMemo.Unlock()
	if ok {
		return cached.(T), nil
	}
	value, err := derive(raw)
	if err != nil {
		var zero T
		return zero, err
	}
	ruleMemo.Lock()
	if ruleMemo.values == nil || len(ruleMemo.values) >= maxRuleMemo {
		ruleMemo.values = map[ruleMemoKey]any{}
	}
	ruleMemo.values[key] = value
	ruleMemo.Unlock()
	return value, nil
}

// ruleFactIDs lists every fact the rule reads (applicability, condition and
// set condition). The slice is shared: callers must not change it.
func ruleFactIDs(raw json.RawMessage) ([]string, error) {
	return memoRule(memoFacts, raw, func(raw json.RawMessage) ([]string, error) {
		var shape ruleShape
		if err := json.Unmarshal(raw, &shape); err != nil {
			return nil, err
		}
		conditions := shape.conditions()
		ids := make([]string, len(conditions))
		for i, condition := range conditions {
			ids[i] = condition.FactID
		}
		return ids, nil
	})
}

// ruleTransition is constraintengine.RuleTransitionOf, memoized. The value is
// shared: callers only read it.
func ruleTransition(raw json.RawMessage) (constraintengine.RuleTransition, error) {
	return memoRule(memoTransition, raw, func(raw json.RawMessage) (constraintengine.RuleTransition, error) {
		return constraintengine.RuleTransitionOf(raw)
	})
}

func ruleVerdictNeutral(raw json.RawMessage) (bool, error) {
	return memoRule(memoNeutral, raw, isVerdictNeutralRule)
}

// transitionOnlyBlocker reports whether a rule that reads no fact may be
// selected for a fact-family evaluation: only a mandatory-intermediate rule,
// which can only BLOCK or stay UNKNOWN. An operator that can PASS from the
// versions alone (require_component_version) or that is not decided by the
// transition (forbid_target_version) is not admitted. This is the one place
// to admit a further operator, deliberately.
func transitionOnlyBlocker(raw json.RawMessage) (bool, error) {
	return memoRule(memoTransitionOnly, raw, func(raw json.RawMessage) (bool, error) {
		var shape ruleShape
		if err := json.Unmarshal(raw, &shape); err != nil {
			return false, err
		}
		return shape.Operator == "require_intermediate_version", nil
	})
}

func ruleBasis(raw json.RawMessage) (string, error) {
	return memoRule(memoBasis, raw, constraintengine.RawRuleBasis)
}
