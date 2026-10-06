// SPDX-License-Identifier: AGPL-3.0-only

package knowledgepin

import "testing"

func TestShippedPinsAreEmptyOrCanonical(t *testing.T) {
	if len(Profiles()) == 0 {
		t.Fatal("no pin entries")
	}
	for _, name := range Profiles() {
		if !Valid(Digest(name)) {
			t.Fatalf("pin for %s is malformed", name)
		}
	}
	if _, ok := pins["cncf-projects"]; !ok {
		t.Fatal("cncf-projects pin entry missing")
	}
}

func TestValid(t *testing.T) {
	good := "sha256:" + "ab01234567890123456789012345678901234567890123456789012345678901"
	for v, want := range map[string]bool{
		"": true, good: true,
		"ab01234567890123456789012345678901234567890123456789012345678901":        false,
		"sha256:AB01234567890123456789012345678901234567890123456789012345678901": false,
		"sha256:zz01234567890123456789012345678901234567890123456789012345678901": false,
		"sha256:abc": false,
	} {
		if Valid(v) != want {
			t.Fatalf("Valid(%q) != %v", v, want)
		}
	}
	if Digest("unknown") != "" {
		t.Fatal("unknown profile pinned")
	}
}
