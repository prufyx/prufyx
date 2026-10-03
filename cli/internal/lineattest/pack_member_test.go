// SPDX-License-Identifier: AGPL-3.0-only

package lineattest

import (
	"errors"
	"testing"
)

func TestPackMemberSection(t *testing.T) {
	pack := []byte(`{"schema":"s","entries":[],"pathPolicies":[1],"lineAttestations":[2]}`)
	for member, want := range map[string]string{"pathPolicies": "[1]", PackMember: "[2]", "entries": "[]"} {
		got, present, err := PackMemberSection(pack, member)
		if err != nil || !present || string(got) != want {
			t.Fatalf("%s: %s %v %v", member, got, present, err)
		}
	}
	if _, present, err := PackMemberSection([]byte(`{"schema":"s"}`), "pathPolicies"); err != nil || present {
		t.Fatalf("absent member: %v %v", present, err)
	}
	if _, _, err := PackMemberSection(pack, "PathPolicies"); !errors.Is(err, ErrInvalid) {
		t.Fatal("a member name outside the pack's members was looked up")
	}
	if _, _, err := PackMemberSection([]byte(`{"PathPolicies":[]}`), "pathPolicies"); !errors.Is(err, ErrInvalid) {
		t.Fatal("a variant spelling was read as no section")
	}
}
