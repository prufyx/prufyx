// SPDX-License-Identifier: AGPL-3.0-only

package knowledgegate

import (
	"encoding/json"
	"fmt"
)

// proofLedgerLen counts the entries of the withheld-item ledger an extractor
// records at the top level of a pair's proof (a "ledger" array). A proof
// without that member has none. A ledger member that is not an array, or a
// proof that cannot be encoded, is an error: the gate treats what it cannot
// read as a ledger it cannot prove empty.
func proofLedgerLen(proof any) (int, error) {
	raw, err := json.Marshal(proof)
	if err != nil {
		return 0, fmt.Errorf("pair proof cannot be encoded: %w", err)
	}
	var obj map[string]json.RawMessage
	if json.Unmarshal(raw, &obj) != nil {
		return 0, nil // not an object (null, array, scalar): it has no ledger member
	}
	member, ok := obj["ledger"]
	if !ok {
		return 0, nil
	}
	var entries []json.RawMessage
	if err := json.Unmarshal(member, &entries); err != nil {
		return 0, fmt.Errorf("pair proof ledger is not an array: %w", err)
	}
	return len(entries), nil
}
