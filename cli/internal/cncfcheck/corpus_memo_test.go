// SPDX-License-Identifier: AGPL-3.0-only

package cncfcheck

import (
	"encoding/json"
	"errors"
	"sync"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/constraintengine"
)

func corpusTestBundle(t *testing.T) (bundle, []json.RawMessage) {
	t.Helper()
	b, err := load()
	if err != nil {
		t.Fatal(err)
	}
	rules := b.packRules()
	if len(rules) < 2 {
		t.Fatal("embedded pack unexpectedly small")
	}
	return b, rules[:2]
}

func ruleSetDigest(t *testing.T, set constraintengine.RuleSet) string {
	t.Helper()
	digest, err := set.Digest()
	if err != nil {
		t.Fatal(err)
	}
	return digest
}

// The first parse of a bundle, rules and corpus is memoized; the second call
// returns the same valid document.
func TestParseRulesCorpusReusesTheSameDocument(t *testing.T) {
	t.Parallel()
	b, rules := corpusTestBundle(t)
	key := corpusKey(b, rules, nil)
	corpusMemo.Lock()
	delete(corpusMemo.parsed, key)
	corpusMemo.Unlock()
	first, err := b.parseRulesCorpus(rules, nil)
	if err != nil {
		t.Fatal(err)
	}
	corpusMemo.Lock()
	_, ok := corpusMemo.parsed[key]
	corpusMemo.Unlock()
	if !ok {
		t.Fatal("parseRulesCorpus did not memoize its result")
	}
	second, err := b.parseRulesCorpus(rules, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !second.Valid() || ruleSetDigest(t, first) != ruleSetDigest(t, second) {
		t.Fatal("memoized document differs from the first parse")
	}
}

// A different rule list, corpus, revision, policy or registry never reuses a
// parse.
func TestCorpusKeyDistinguishesEveryInput(t *testing.T) {
	t.Parallel()
	b, rules := corpusTestBundle(t)
	base := corpusKey(b, rules, nil)
	if base != corpusKey(b, rules, nil) {
		t.Fatal("key not deterministic")
	}
	changed := map[string][32]byte{
		"fewer rules": corpusKey(b, rules[:1], nil),
		"reordered":   corpusKey(b, []json.RawMessage{rules[1], rules[0]}, nil),
		"edited rule": corpusKey(b, []json.RawMessage{rules[0], append(append(json.RawMessage{}, rules[1]...), ' ')}, nil),
		"corpus":      corpusKey(b, rules, []string{"pkg:github/x/y"}),
	}
	for name, mutate := range map[string]func(*bundle){
		"revision":        func(m *bundle) { m.pack.Revision += "x" },
		"policy id":       func(m *bundle) { m.pack.PolicyID += "x" },
		"policy digest":   func(m *bundle) { m.pack.PolicyDigest += "x" },
		"registry digest": func(m *bundle) { m.registry = constraintengine.Registry{} },
	} {
		other := b
		mutate(&other)
		changed[name] = corpusKey(other, rules, nil)
	}
	for name, key := range changed {
		if key == base {
			t.Fatalf("%s: key unchanged", name)
		}
	}
	// Length prefixes keep rule boundaries apart.
	joined := corpusKey(b, []json.RawMessage{append(append(json.RawMessage{}, rules[0]...), rules[1]...)}, nil)
	if joined == corpusKey(b, rules, nil) {
		t.Fatal("two rules and their concatenation share a key")
	}
}

// Failures are never kept: the next call parses again.
func TestMemoizedParseDoesNotKeepFailures(t *testing.T) {
	t.Parallel()
	b, rules := corpusTestBundle(t)
	bad := append([]json.RawMessage{}, rules...)
	bad[0] = json.RawMessage(`{"id":"memo.failure.sentinel"}`)
	calls := 0
	failing := func() (constraintengine.RuleSet, error) {
		calls++
		return constraintengine.RuleSet{}, errors.New("boom")
	}
	for i := 0; i < 2; i++ {
		if _, err := memoizedParse(b, bad, nil, failing); err == nil {
			t.Fatal("failure swallowed")
		}
	}
	if calls != 2 {
		t.Fatalf("failing parse ran %d times, want 2", calls)
	}
}

// Callers of the real seam cannot change what the next caller reads: the
// rule slice a caller passes may be reused or edited afterwards.
func TestParseRulesCorpusIgnoresLaterEditsOfTheInput(t *testing.T) {
	t.Parallel()
	b, rules := corpusTestBundle(t)
	copyOf := make([]json.RawMessage, len(rules))
	for i, rule := range rules {
		copyOf[i] = append(json.RawMessage{}, rule...)
	}
	first, err := b.parseRulesCorpus(copyOf, nil)
	if err != nil {
		t.Fatal(err)
	}
	want := ruleSetDigest(t, first)
	copyOf[0][2] ^= 0x01
	again, err := b.parseRulesCorpus(rules, nil)
	if err != nil {
		t.Fatal(err)
	}
	if ruleSetDigest(t, again) != want {
		t.Fatal("edit of a caller's copy changed a later parse")
	}
}

func TestParseRulesCorpusConcurrent(t *testing.T) {
	t.Parallel()
	b, rules := corpusTestBundle(t)
	want, err := b.parseRulesCorpus(rules, nil)
	if err != nil {
		t.Fatal(err)
	}
	digest := ruleSetDigest(t, want)
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			got, err := b.parseRulesCorpus(rules, nil)
			if err != nil || !got.Valid() {
				t.Error("concurrent parse failed")
				return
			}
			if d, err := got.Digest(); err != nil || d != digest {
				t.Error("concurrent parse differs")
			}
		}()
	}
	wg.Wait()
}

// A rule's derived values are memoized by its bytes: the same bytes reuse the
// derivation, a changed rule gets its own, and a failed derivation is not kept.
func TestRuleMemoKeysOnRuleBytes(t *testing.T) {
	t.Parallel()
	_, rules := corpusTestBundle(t)
	first, err := ruleBasis(rules[0])
	if err != nil {
		t.Fatal(err)
	}
	again, err := ruleBasis(append(json.RawMessage{}, rules[0]...))
	if err != nil || again != first {
		t.Fatalf("copy of the same rule: %q %v, want %q", again, err, first)
	}
	want, err := constraintengine.RawRuleBasis(rules[1])
	if err != nil {
		t.Fatal(err)
	}
	if got, err := ruleBasis(rules[1]); err != nil || got != want {
		t.Fatalf("second rule: %q %v, want %q", got, err, want)
	}
	transition, err := ruleTransition(rules[0])
	if err != nil {
		t.Fatal(err)
	}
	direct, err := constraintengine.RuleTransitionOf(rules[0])
	if err != nil || transition.Component != direct.Component || transition.From != direct.From || transition.To != direct.To {
		t.Fatalf("transition %+v, want %+v (%v)", transition, direct, err)
	}
	calls := 0
	broken := json.RawMessage(`{"memo":"not a rule"`)
	for i := 0; i < 2; i++ {
		if _, err := memoRule(memoBasis, broken, func(json.RawMessage) (string, error) { calls++; return "", errors.New("boom") }); err == nil {
			t.Fatal("failure swallowed")
		}
	}
	if calls != 2 {
		t.Fatalf("failing derivation ran %d times, want 2", calls)
	}
}
