// SPDX-License-Identifier: AGPL-3.0-only

package knowledgegate

import (
	"encoding/json"
	"sort"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/extract/extractpack"
)

// The tool and the gate agree on every case of the pairing table
// (12-M1): `extract supersede` plans exactly the pairs the gate pairs, and
// when the gate would refuse any removal of the table's case, the tool
// refuses the whole run (exit 3) and prints no map.
func TestExtractSupersedeAndTheGateAgree(t *testing.T) {
	for _, tc := range pairCases(t) {
		t.Run(tc.name, func(t *testing.T) {
			var entries []json.RawMessage
			for _, c := range tc.rs {
				entries = append(entries, json.RawMessage(c.base.Raw))
			}
			pack, err := json.Marshal(map[string]any{"schema": "test-pack/v1", "revision": "rev-1", "entries": entries})
			if err != nil {
				t.Fatal(err)
			}
			var run []json.RawMessage
			for _, c := range tc.ms {
				run = append(run, json.RawMessage(c.head.Raw))
			}

			all := append(append([]*Change{}, tc.rs...), tc.ms...)
			pairSupersedes(all)
			var gate []extractpack.Pair
			for _, c := range tc.rs {
				if c.supersededBy != nil {
					gate = append(gate, extractpack.Pair{Old: c.RuleID, New: c.supersededBy.RuleID})
				}
			}
			sort.Slice(gate, func(i, j int) bool { return gate[i].Old < gate[j].Old })

			tool, err := extractpack.PlanSupersede(pack, run)
			if err != nil {
				if len(tc.want) > 0 {
					t.Fatalf("the gate pairs %v but the tool refuses: %v", tc.want, err)
				}
				// The tool refuses. The gate must then also have left at
				// least one removal of the case unpaired: the tool is
				// never stricter than needed in a way the gate is not.
				if len(gate) == len(tc.rs) && len(tc.rs) > 0 {
					t.Fatalf("the tool refuses (%v) a run the gate admits completely: %v", err, gate)
				}
				return
			}
			if len(tool) != len(gate) {
				t.Fatalf("the tool plans %v, the gate pairs %v", tool, gate)
			}
			for i := range tool {
				if tool[i] != gate[i] {
					t.Fatalf("the tool plans %v, the gate pairs %v", tool, gate)
				}
			}
			if len(gate) != len(tc.want) {
				t.Fatalf("pairs %v, table wants %v", gate, tc.want)
			}
		})
	}
}
