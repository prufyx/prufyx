// SPDX-License-Identifier: AGPL-3.0-only

package crdbatchfixture

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/cncfcheck"
	"github.com/prufyx/prufyx/cli/internal/extract/crdbatchids"
)

func data(t *testing.T, name string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "cncfcheck", "data", name))
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func entryIDs(t *testing.T, pack []byte) map[string]string {
	t.Helper()
	var p struct {
		Entries []json.RawMessage `json:"entries"`
	}
	if err := json.Unmarshal(pack, &p); err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	for _, raw := range p.Entries {
		var e struct {
			Rule struct {
				ID string `json:"id"`
			} `json:"rule"`
		}
		if err := json.Unmarshal(raw, &e); err != nil {
			t.Fatal(err)
		}
		var compact bytes.Buffer
		if err := json.Compact(&compact, raw); err != nil {
			t.Fatal(err)
		}
		out[e.Rule.ID] = compact.String()
	}
	return out
}

// Without leaves a pack without the batch unchanged; from the shipped pack
// with the batch it removes exactly the batch, keeps every other rule as it
// is, and yields a pack the CNCF loader admits.
func TestWithout(t *testing.T) {
	shipped := data(t, "rules.json")
	without, err := Without(shipped)
	if err != nil {
		t.Fatal(err)
	}
	if held, err := crdbatchids.Holds(without); err != nil || held {
		t.Fatalf("the rebuilt pack holds the batch: %v %v", held, err)
	}
	if !crdbatchids.Shipped() {
		if !bytes.Equal(without, shipped) {
			t.Fatal("a pack without the batch changed")
		}
		return
	}
	before, after := entryIDs(t, shipped), entryIDs(t, without)
	if len(before)-len(after) != len(crdbatchids.IDs()) {
		t.Fatalf("%d rules removed, the batch has %d", len(before)-len(after), len(crdbatchids.IDs()))
	}
	for id, entry := range after {
		if before[id] != entry {
			t.Fatalf("rule %s changed", id)
		}
	}
	if bytes.Contains(without, []byte("lineAttestations")) {
		t.Fatal("line attestations left")
	}
	if _, err := cncfcheck.CheckPackFiles(data(t, "landscape-projects.json"), data(t, "priority-portfolio.json"), without); err != nil {
		t.Fatalf("the rebuilt pack is refused: %v", err)
	}
}
