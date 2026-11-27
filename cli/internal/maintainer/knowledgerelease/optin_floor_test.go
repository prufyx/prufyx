// SPDX-License-Identifier: AGPL-3.0-only

package knowledgerelease

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/cncfcheck"
)

// The release build checks the opt-in floor itself, whatever built the
// targets.
func TestReleaseRefusesTheOptInLevelBelowItsFloor(t *testing.T) {
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
	previous := buildPinned
	t.Cleanup(func() { buildPinned = previous })
	// A builder that ignores the oldest supported client.
	buildPinned = func(revision string, _ []byte, _ string) (cncfcheck.ExternalTarget, []cncfcheck.ExternalTarget, int, error) {
		return cncfcheck.BuildExternalTargetsFromPackPinned(pack, revision, cncfcheck.BoundaryCoveredFloor)
	}
	for _, oldest := range []string{"", "v0.1.0-beta.0", "v0.1.0-beta.1", "v0.1.0-beta.1.1"} {
		_, err := buildProjectTargets(Options{FirstRelease: true, Revision: "5", OldestClient: oldest})
		if !errors.Is(err, ErrRejected) || !strings.Contains(err.Error(), "opt-in pack level") {
			t.Fatalf("oldest %q: %v", oldest, err)
		}
	}
}
