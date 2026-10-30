// SPDX-License-Identifier: AGPL-3.0-only

// Package knowledgepin holds the product-embedded trust root pins for
// official knowledge profiles.
//
// A pin is the SHA-256 identity of the initial (version 1) TUF root of a
// profile's official knowledge feed. When a profile has a pin, `db update`
// accepts only a store whose initial root is exactly that root; later root
// versions are accepted only through the normal TUF root chain signed from
// it. An empty pin means no pinned root: an explicit bootstrap root and
// digest are required and nothing else changes.
//
// Changing a pin is a reviewed source change (see the knowledge publisher
// documentation for the ceremony).
package knowledgepin

import (
	_ "embed"
	"encoding/hex"
	"strings"
)

// pins maps a knowledge profile name to its pinned initial root digest in
// "sha256:<64 lowercase hex>" form. Empty means not pinned.
var pins = map[string]string{
	"cncf-projects": "sha256:11eff27032c4a3db126d030ae860e881e8e0dd1e7c37fcc4f10ef5fde70a326a",
}

//go:embed root.json
var cncfProjectsRoot []byte

// roots maps a profile name to its embedded initial root bytes. The root file
// was added together with its pin in one reviewed change and is registered here
// from a go:embed variable. A test
// asserts that every non-empty pin equals the digest of the embedded root.
var roots = map[string][]byte{
	"cncf-projects": cncfProjectsRoot,
}

// Root returns the embedded initial root of a profile. The caller must still
// admit it only if it hashes to the profile's pin (see Digest).
func Root(profile string) ([]byte, bool) {
	raw, ok := roots[profile]
	if !ok || len(raw) == 0 {
		return nil, false
	}
	return append([]byte(nil), raw...), true
}

// FeedURL is the official knowledge feed of the default profile.
const FeedURL = "https://prufyx.github.io/prufyx/knowledge/cncf-projects.tar"

// Digest returns the pinned initial root digest of a profile, or "" when the
// profile has no pin.
func Digest(profile string) string {
	return pins[profile]
}

// Profiles returns the profile names that have a pin entry, pinned or not.
func Profiles() []string {
	out := make([]string, 0, len(pins))
	for name := range pins {
		out = append(out, name)
	}
	return out
}

// Valid reports whether v is an empty pin or a canonical sha256 digest.
func Valid(v string) bool {
	if v == "" {
		return true
	}
	hexPart, ok := strings.CutPrefix(v, "sha256:")
	if !ok || len(hexPart) != 64 || strings.ToLower(hexPart) != hexPart {
		return false
	}
	_, err := hex.DecodeString(hexPart)
	return err == nil
}
