// SPDX-License-Identifier: AGPL-3.0-only

package lineattest

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
)

// PackMember is the rule pack member that holds the attestation section.
const PackMember = "lineAttestations"

// PackMembers are the exact top-level member names of a rule pack. The pack
// loader's document type must name exactly these (a test pins it).
var PackMembers = []string{"schema", "revision", "policyId", "policyDigest", "landscapeFileDigest", "registryDigest", "entries", PackMember}

// PackSection reads the top level of a rule pack and returns its raw
// attestation section; present is false when the pack has none. It is the
// only way a pack's attestation section is located, so every reader sees
// the same bytes.
//
// Member names are compared exactly: case-sensitively and without Unicode
// folding. encoding/json would match "LineAttestations" or
// "lineAttestationſ" to the lineAttestations field, and with two spellings
// present it would keep the last one, so a reader that looked the section up
// by its exact name could validate one section while the loader served
// another. Any top-level name that is not exactly one of PackMembers, and
// any name that repeats, is therefore an error, and so is anything other
// than one JSON object.
func PackSection(pack []byte) (section json.RawMessage, present bool, err error) {
	known := map[string]bool{}
	for _, name := range PackMembers {
		known[name] = true
	}
	dec := json.NewDecoder(bytes.NewReader(pack))
	tok, err := dec.Token()
	if err != nil || tok != json.Delim('{') {
		return nil, false, fmt.Errorf("%w: the rule pack must be a JSON object", ErrInvalid)
	}
	seen := map[string]bool{}
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return nil, false, fmt.Errorf("%w: rule pack: %v", ErrInvalid, err)
		}
		name, _ := tok.(string)
		if !known[name] {
			return nil, false, fmt.Errorf("%w: rule pack member %q is not one of the pack's members (names are case-sensitive)", ErrInvalid, name)
		}
		if seen[name] {
			return nil, false, fmt.Errorf("%w: rule pack member %q repeats", ErrInvalid, name)
		}
		seen[name] = true
		var value json.RawMessage
		if err := dec.Decode(&value); err != nil {
			return nil, false, fmt.Errorf("%w: rule pack member %q: %v", ErrInvalid, name, err)
		}
		if name == PackMember {
			section, present = value, true
		}
	}
	if tok, err := dec.Token(); err != nil || tok != json.Delim('}') {
		return nil, false, fmt.Errorf("%w: rule pack: unterminated object", ErrInvalid)
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, false, fmt.Errorf("%w: rule pack: trailing data", ErrInvalid)
	}
	return section, present, nil
}
