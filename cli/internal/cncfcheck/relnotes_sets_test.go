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
		if !relnotesSetFacts[fact] || !slices.IsSorted(siblings) || !RegisteredFact(fact) {
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
	for fact := range relnotesSetFacts {
		if !RegisteredFact(fact) {
			t.Fatalf("%s is not a registered fact", fact)
		}
	}
}
