// SPDX-License-Identifier: AGPL-3.0-only

package knowledgegate

import (
	"bytes"
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
	dec := json.NewDecoder(bytes.NewReader(raw))
	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		return 0, nil // not an object (null, array, scalar): it has no ledger member
	}
	seen := map[string]bool{}
	var member json.RawMessage
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return 0, fmt.Errorf("pair proof cannot be read: %w", err)
		}
		key, _ := tok.(string)
		if seen[key] {
			return 0, fmt.Errorf("pair proof repeats the member %q", key)
		}
		seen[key] = true
		var v json.RawMessage
		if err := dec.Decode(&v); err != nil {
			return 0, fmt.Errorf("pair proof cannot be read: %w", err)
		}
		if key == "ledger" {
			member = v
		}
	}
	if !seen["ledger"] {
		return 0, nil
	}
	if bytes.Equal(bytes.TrimSpace(member), []byte("null")) {
		return 0, fmt.Errorf("pair proof ledger is null, not an array")
	}
	var entries []json.RawMessage
	if err := json.Unmarshal(member, &entries); err != nil {
		return 0, fmt.Errorf("pair proof ledger is not an array: %w", err)
	}
	return len(entries), nil
}
