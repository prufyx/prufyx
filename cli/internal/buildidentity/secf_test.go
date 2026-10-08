// SPDX-License-Identifier: AGPL-3.0-only

package buildidentity

import (
	"runtime"
	"strings"
	"testing"
)

// setRelease installs a complete, self-consistent release identity whose
// trust root field is trustRoot, including the matching embedded marker, so
// the only thing under test is the trust root value itself.
func setRelease(trustRoot string) {
	resetLinkerValues()
	Version = "1.2.3"
	SourceRevision = "0123456789abcdef0123456789abcdef01234567"
	SourceTreeDigest = "sha256:" + strings.Repeat("a", 64)
	AllowlistDigest = "sha256:" + strings.Repeat("b", 64)
	BuildProfile = "community-linux-amd64"
	BuildEpoch = "1700000000"
	TrustRootDigest = trustRoot
	EmbeddedIdentity = Marker(Identity{Version: Version, ReleaseState: ReleaseStateRelease, SourceRevision: SourceRevision, SourceTreeDigest: SourceTreeDigest, AllowlistDigest: AllowlistDigest, BuildProfile: BuildProfile, BuildEpoch: "2023-11-14T22:13:20Z", GoVersion: runtime.Version(), TrustRootDigest: TrustRootDigest, CandidateOnly: true})
}

// A trust root digest is a trust claim that nothing in the binary checks:
// no signed statement can exist when the binary is built, and the knowledge
// root the binary enforces lives elsewhere (internal/knowledgepin). A linker
// flag must therefore not be able to make `prufyx version` and every report
// claim a pinned root. Only the canonical UNPINNED is accepted.
func TestReportRejectsUnverifiableTrustRootClaim(t *testing.T) {
	for _, claim := range []string{
		"sha256:" + strings.Repeat("c", 64),
		"unpinned",
		"Unpinned",
		"",
	} {
		t.Run(claim, func(t *testing.T) {
			old := linkerSnapshot()
			defer old.restore()
			setRelease(claim)
			if identity, err := Report(); err == nil {
				t.Fatalf("Report() accepted trust root claim %q: %#v", claim, identity)
			}
		})
	}
	old := linkerSnapshot()
	defer old.restore()
	setRelease(UnpinnedTrustRoot)
	if identity, err := Report(); err != nil || identity.TrustRootDigest != "UNPINNED" {
		t.Fatalf("canonical UNPINNED identity: %#v %v", identity, err)
	}
}

// A development identity is reported only when every linker input, the
// embedded marker included, is at its development default. Otherwise a
// binary could carry a byte-extractable release marker that a verifier
// reading the bytes (the documented cross-target contract) accepts while
// the binary itself reports a development build.
func TestReportRejectsReleaseMarkerInDevelopmentBuild(t *testing.T) {
	old := linkerSnapshot()
	defer old.restore()
	setRelease(UnpinnedTrustRoot)
	marker := EmbeddedIdentity
	resetLinkerValues()
	EmbeddedIdentity = marker
	if identity, err := Report(); err == nil {
		t.Fatalf("development defaults with a release marker were reported as %#v", identity)
	}
}
