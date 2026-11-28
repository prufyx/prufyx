// SPDX-License-Identifier: AGPL-3.0-only

package knowledgepublish

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/cncfcheck"
)

// The shared admission refuses a target set that carries the opt-in pack
// level unless its index names the floor.
func TestAdmissionHoldsTheOptInLevelToItsFloor(t *testing.T) {
	raw, err := os.ReadFile("../../cncfcheck/data/rules.json")
	if err != nil {
		t.Fatal(err)
	}
	shipped, err := cncfcheck.RequiredPackSchema(raw)
	if err != nil {
		t.Fatal(err)
	}
	pack := bytes.Replace(raw, []byte(`"`+shipped+`"`), []byte(`"prufyx.io/cncf-source-rule-pack/v1alpha16"`), 1)
	if bytes.Equal(pack, raw) {
		t.Fatalf("the shipped pack does not state %s", shipped)
	}
	// Without line attestations the listed family's own floor cannot be the
	// reason for a refusal.
	var members map[string]json.RawMessage
	if err := json.Unmarshal(pack, &members); err != nil {
		t.Fatal(err)
	}
	delete(members, "lineAttestations")
	if pack, err = json.Marshal(members); err != nil {
		t.Fatal(err)
	}
	index, built, _, err := cncfcheck.BuildExternalTargetsFromPackPinned(pack, "5", cncfcheck.BoundaryCoveredFloor)
	if err != nil {
		t.Fatal(err)
	}
	targets := make([]Target, 0, len(built))
	for _, target := range built {
		targets = append(targets, Target{Path: target.Path, Raw: target.Bytes})
	}
	if _, err := admitTargetSet(index.Bytes, targets); err != nil {
		t.Fatalf("the set with the floor was refused: %v", err)
	}
	member := []byte(`,"minClientVersion":"` + cncfcheck.BoundaryCoveredFloor + `"`)
	if !bytes.Contains(index.Bytes, member) {
		t.Fatal("no floor member")
	}
	for _, replacement := range []string{"", `,"minClientVersion":"v0.1.0-beta.0"`, `,"minClientVersion":"v0.1.0-beta.2"`} {
		_, err := admitTargetSet(bytes.Replace(index.Bytes, member, []byte(replacement), 1), targets)
		if !errors.Is(err, ErrRejected) || !strings.Contains(err.Error(), "opt-in pack level") {
			t.Fatalf("floor %q: %v", replacement, err)
		}
	}
}
