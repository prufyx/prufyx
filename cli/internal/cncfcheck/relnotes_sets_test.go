// SPDX-License-Identifier: AGPL-3.0-only

package cncfcheck

import (
	"bytes"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
)

func relnotesInput(fact string, complete bool, members ...string) []byte {
	quoted := make([]string, len(members))
	for i, m := range members {
		quoted[i] = fmt.Sprintf("%q", m)
	}
	return []byte(fmt.Sprintf(`{"schema":"prufyx.io/operator-declared-constraint-input/v1alpha1","authority":"OPERATOR_DECLARED_MINIMIZED","current":{"components":[{"component":"pkg:github/cortexproject/cortex","version":"1.8.1","facts":[{"id":%q,"state":"declared","setValue":{"members":[%s],"complete":%t}}]}]},"proposed":{"components":[{"component":"pkg:github/cortexproject/cortex","version":"1.9.0","facts":[]}]}}`,
		fact, strings.Join(quoted, ","), complete))
}

// A set member with another case is not a real name of these projects and
// never compares equal to the lower-case forbidden one: the set is refused,
// never passed. falco's single-letter options differ by case and stay exact.
func TestRelnotesSetsRefuseNonCanonicalCase(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		fact    string
		members []string
		refused bool
	}{
		{factCortexFlags, []string{"Store.max-look-back-period"}, true},
		{factCortexFlags, []string{"STORE.MAX-LOOK-BACK-PERIOD"}, true},
		{factCortexFlags, []string{"store.max-look-back-period"}, false},
		{factFalcoFlags, []string{"Mesos-API"}, true},
		{factFalcoFlags, []string{"Pm"}, true},
		{factFalcoFlags, []string{"M", "m"}, false},
		{factFalcoConfigKey, []string{"Outputs.rate"}, true},
		{factThanosFlags, []string{"Log.request.decision"}, true},
	} {
		_, _, err := guardRelnotesSets(relnotesInput(tc.fact, true, tc.members...))
		if tc.refused != errors.Is(err, ErrInvalid) || (!tc.refused && err != nil) {
			t.Fatalf("%s %v: err=%v, refused want %v", tc.fact, tc.members, err, tc.refused)
		}
	}
	if err := ValidateCanonicalInput("cortex", relnotesInput(factCortexFlags, true, "Store.max-look-back-period")); !errors.Is(err, ErrInvalid) {
		t.Fatalf("ValidateCanonicalInput accepted a non-canonical member: %v", err)
	}
}

// A complete set holding a flag the same release removed without a rule is
// handed to the engine as not complete; a set without one is untouched.
func TestRelnotesSetsDowngradeUnreviewedSiblings(t *testing.T) {
	t.Parallel()
	for fact, siblings := range relnotesUnreviewedRemovals {
		for _, sibling := range siblings {
			got, down, err := guardRelnotesSets(relnotesInput(fact, true, sibling))
			if err != nil || !down || !bytes.Contains(got, []byte(`"complete":false`)) || !bytes.Contains(got, []byte(sibling)) {
				t.Fatalf("%s %s: down=%v err=%v got=%s", fact, sibling, down, err, got)
			}
			// Already incomplete: nothing to change.
			if got, down, err := guardRelnotesSets(relnotesInput(fact, false, sibling)); err != nil || down || !bytes.Contains(got, []byte(`"complete":false`)) {
				t.Fatalf("%s %s incomplete: down=%v err=%v", fact, sibling, down, err)
			}
		}
	}
}

// The guard leaves every input that needs no change byte for byte, and its
// sibling table holds canonical members no shipped crossing rule forbids.
func TestRelnotesGuardIsMinimal(t *testing.T) {
	t.Parallel()
	for _, raw := range [][]byte{
		relnotesInput(factCortexFlags, true, "store.max-look-back-period"),
		relnotesInput(factCortexFlags, true),
		relnotesInput("component.kubernetes.kubelet_feature_gates_set", true, "SomeGate"),
		[]byte(`{}`), []byte(`not json _set"`),
	} {
		got, down, err := guardRelnotesSets(raw)
		if err != nil || down || !bytes.Equal(got, raw) {
			t.Fatalf("input %.60s changed: down=%v err=%v", raw, down, err)
		}
	}
	for fact, siblings := range relnotesUnreviewedRemovals {
		if !relnotesGuardedFacts[fact] || !slices.IsSorted(siblings) || !RegisteredFact(fact) {
			t.Fatalf("%s: not a registered release-note fact or siblings unsorted", fact)
		}
		for _, sibling := range siblings {
			if !relnotesSpelling(fact, sibling) {
				t.Fatalf("%s: sibling %s is not canonical", fact, sibling)
			}
			for _, entry := range shippedPack(t).Entries {
				if strings.Contains(string(entry.Rule), `"crossing"`) && strings.Contains(string(entry.Rule), `"`+sibling+`"`) {
					t.Fatalf("%s is both a reviewed rule member and an unreviewed sibling", sibling)
				}
			}
		}
	}
	for fact := range relnotesGuardedFacts {
		if !RegisteredFact(fact) {
			t.Fatalf("%s is not a registered fact", fact)
		}
	}
}

// A fact id spelled with JSON escapes is the same id to the engine's parser:
// the guard decodes every input, so the spelling cannot skip it.
func TestRelnotesGuardSeesEscapedFactIDs(t *testing.T) {
	t.Parallel()
	escaped := bytes.Replace(relnotesInput(factCortexFlags, true, "cluster.peer"), []byte("cli_flags_set"), []byte("cli_flags\\u005fset"), 1)
	if bytes.Equal(escaped, relnotesInput(factCortexFlags, true, "cluster.peer")) {
		t.Fatal("test input not escaped")
	}
	if _, down, err := guardRelnotesSets(escaped); err != nil || !down {
		t.Fatalf("escaped id not downgraded: down=%v err=%v", down, err)
	}
	upper := bytes.Replace(relnotesInput(factCortexFlags, true, "Store.max-look-back-period"), []byte("cli_flags_set"), []byte("cli_flags\\u005fset"), 1)
	if _, _, err := guardRelnotesSets(upper); !errors.Is(err, ErrInvalid) {
		t.Fatalf("escaped id with an upper-case member: %v", err)
	}
}

// A rewrite never makes valid an input the engine's own gate refuses.
func TestRelnotesParseGuardedKeepsTheEngineGate(t *testing.T) {
	t.Parallel()
	b, err := load()
	if err != nil {
		t.Fatal(err)
	}
	good := relnotesInput(factCortexFlags, true, "cluster.peer")
	if _, down, err := parseGuarded(good, b.registry); err != nil || !down {
		t.Fatalf("good input: down=%v err=%v", down, err)
	}
	for name, raw := range map[string][]byte{
		"duplicate key": bytes.Replace(good, []byte(`"authority":"OPERATOR_DECLARED_MINIMIZED",`), []byte(`"authority":"OPERATOR_DECLARED_MINIMIZED","authority":"OPERATOR_DECLARED_MINIMIZED",`), 1),
		"trailing data": append(append([]byte{}, good...), []byte(` {}`)...),
		"invalid utf-8": bytes.Replace(good, []byte("cluster.peer"), []byte("cluster.pe\xffr"), 1),
	} {
		if _, _, err := parseGuarded(raw, b.registry); !errors.Is(err, ErrInvalid) {
			t.Fatalf("%s accepted: %v", name, err)
		}
	}
}

func falcoTwoSetInput(flags []string, flagsComplete bool, keys []string, keysComplete bool) []byte {
	set := func(id string, members []string, complete bool) string {
		quoted := make([]string, len(members))
		for i, m := range members {
			quoted[i] = fmt.Sprintf("%q", m)
		}
		return fmt.Sprintf(`{"id":%q,"state":"declared","setValue":{"members":[%s],"complete":%t}}`, id, strings.Join(quoted, ","), complete)
	}
	return []byte(fmt.Sprintf(`{"schema":"prufyx.io/operator-declared-constraint-input/v1alpha1","authority":"OPERATOR_DECLARED_MINIMIZED","current":{"components":[{"component":"pkg:github/falcosecurity/falco","version":"0.36.2","facts":[%s,%s]}]},"proposed":{"components":[{"component":"pkg:github/falcosecurity/falco","version":"0.37.0","facts":[]}]}}`,
		set(factFalcoConfigKey, keys, keysComplete), set(factFalcoFlags, flags, flagsComplete)))
}

// falco 0.37.0 removed command-line options beside the config keys its two
// rules read: a declared removed option keeps the clean config-key set from
// being complete, whether or not the flag set itself is complete.
func TestRelnotesCrossFactRemovalsDowngradeTheConfigKeySet(t *testing.T) {
	t.Parallel()
	for _, removed := range relnotesCrossFactRemovals[factFalcoFlags][0].members {
		for _, flagsComplete := range []bool{true, false} {
			got, down, err := guardRelnotesSets(falcoTwoSetInput([]string{removed}, flagsComplete, nil, true))
			if err != nil || !down {
				t.Fatalf("%s complete=%v: down=%v err=%v", removed, flagsComplete, down, err)
			}
			// Only the config-key set changes; the flag set keeps its own state.
			if bytes.Count(got, []byte(`"complete":false`)) != 1+btoi(!flagsComplete) {
				t.Fatalf("%s complete=%v: unexpected rewrite %s", removed, flagsComplete, got)
			}
		}
	}
	// An unrelated flag, or no config-key set, changes nothing.
	for _, raw := range [][]byte{
		falcoTwoSetInput([]string{"v"}, true, nil, true),
		falcoTwoSetInput([]string{"userspace"}, true, []string{"outputs.rate"}, false),
	} {
		if got, down, err := guardRelnotesSets(raw); err != nil || down || !bytes.Equal(got, raw) {
			t.Fatalf("changed: down=%v err=%v", down, err)
		}
	}
	for fact, removals := range relnotesCrossFactRemovals {
		for _, removal := range removals {
			if !relnotesGuardedFacts[fact] || !relnotesGuardedFacts[removal.target] || !slices.IsSorted(removal.members) {
				t.Fatalf("%s -> %s: not guarded facts or unsorted", fact, removal.target)
			}
			for _, m := range removal.members {
				if !relnotesSpelling(fact, m) {
					t.Fatalf("%s: member %s not canonical", fact, m)
				}
			}
		}
	}
}

func btoi(b bool) int {
	if b {
		return 1
	}
	return 0
}
