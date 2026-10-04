// SPDX-License-Identifier: AGPL-3.0-only

package lineattest

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"slices"

	"github.com/prufyx/prufyx/cli/internal/strictjson"
)

// PackMember is the rule pack member that holds the attestation section.
const PackMember = "lineAttestations"

// PackMembers are the exact top-level member names of a rule pack. The pack
// loader's document type must name exactly these (a test pins it).
// "pathPolicies" is the upgrade-path policy section (upgradepath.PackMember)
// and "distributions" the distribution section (distribution.PackMember);
// both are spelled out here because those packages build on this one.
var PackMembers = []string{"schema", "revision", "policyId", "policyDigest", "landscapeFileDigest", "registryDigest", "entries", PackMember, "pathPolicies", "distributions"}

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
// than one JSON object. Below the top level the shared strict check
// applies: no object anywhere in the pack may hold a repeated member or
// members whose names differ only in letter case.
func PackSection(pack []byte) (section json.RawMessage, present bool, err error) {
	return PackMemberSection(pack, PackMember)
}

// PackMemberSection is PackSection for any one of PackMembers: it checks the
// whole top level exactly as PackSection does and returns the raw value of
// member; present is false when the pack has no such member. A member that
// is not one of PackMembers is an error.
func PackMemberSection(pack []byte, member string) (section json.RawMessage, present bool, err error) {
	if !slices.Contains(PackMembers, member) {
		return nil, false, fmt.Errorf("%w: %q is not a rule pack member", ErrInvalid, member)
	}
	// Below the top level the shared strict check applies, so every
	// reader of any pack section reads the same values.
	if err := strictjson.Check(pack); err != nil {
		return nil, false, fmt.Errorf("%w: rule pack: %v", ErrInvalid, err)
	}
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
		if name == member {
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
