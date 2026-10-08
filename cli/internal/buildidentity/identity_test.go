// SPDX-License-Identifier: AGPL-3.0-only

package buildidentity

import (
	"runtime"
	"strings"
	"testing"
)

func TestReportDevelopmentIsExplicitAndPathFree(t *testing.T) {
	old := linkerSnapshot()
	defer old.restore()
	resetLinkerValues()

	identity, err := Report()
	if err != nil {
		t.Fatal(err)
	}
	if identity.ReleaseState != ReleaseStateDevelopment || !identity.CandidateOnly {
		t.Fatalf("development identity = %#v", identity)
	}
	if identity.Version != "dev" || identity.SourceRevision != DevelopmentValue || identity.BuildProfile != DevelopmentProfile || identity.BuildEpoch != DevelopmentValue {
		t.Fatalf("development identity did not remain explicitly unbound: %#v", identity)
	}
}

func TestReportPinnedIdentityUsesExactInputsAndUTCBackendEpoch(t *testing.T) {
	old := linkerSnapshot()
	defer old.restore()
	Version = "1.2.3"
	SourceRevision = "0123456789abcdef0123456789abcdef01234567"
	SourceTreeDigest = "sha256:" + strings.Repeat("a", 64)
	AllowlistDigest = "sha256:" + strings.Repeat("b", 64)
	BuildProfile = "linux-amd64"
	BuildEpoch = "1700000000"
	TrustRootDigest = UnpinnedTrustRoot
	EmbeddedIdentity = Marker(Identity{Version: Version, ReleaseState: ReleaseStateRelease, SourceRevision: SourceRevision, SourceTreeDigest: SourceTreeDigest, AllowlistDigest: AllowlistDigest, BuildProfile: BuildProfile, BuildEpoch: "2023-11-14T22:13:20Z", GoVersion: runtime.Version(), TrustRootDigest: TrustRootDigest, CandidateOnly: true})

	identity, err := Report()
	if err != nil {
		t.Fatal(err)
	}
	if identity.ReleaseState != ReleaseStateRelease || !identity.CandidateOnly {
		t.Fatalf("pinned identity = %#v", identity)
	}
	if identity.Version != Version || identity.SourceRevision != SourceRevision || identity.SourceTreeDigest != SourceTreeDigest || identity.AllowlistDigest != AllowlistDigest || identity.BuildProfile != BuildProfile || identity.TrustRootDigest != TrustRootDigest {
		t.Fatalf("pinned values changed: %#v", identity)
	}
	if identity.BuildEpoch != "2023-11-14T22:13:20Z" {
		t.Fatalf("build epoch = %q, want UTC instant", identity.BuildEpoch)
	}
}

func TestReportAcceptsCommunityProfileAsDistinctFamily(t *testing.T) {
	old := linkerSnapshot()
	defer old.restore()
	resetLinkerValues()
	Version = "1.2.3"
	SourceRevision = "0123456789abcdef0123456789abcdef01234567"
	SourceTreeDigest = "sha256:" + strings.Repeat("a", 64)
	AllowlistDigest = "sha256:" + strings.Repeat("b", 64)
	BuildProfile = "community-darwin-arm64"
	BuildEpoch = "1700000000"
	TrustRootDigest = "UNPINNED"
	EmbeddedIdentity = Marker(Identity{Version: Version, ReleaseState: ReleaseStateRelease, SourceRevision: SourceRevision, SourceTreeDigest: SourceTreeDigest, AllowlistDigest: AllowlistDigest, BuildProfile: BuildProfile, BuildEpoch: "2023-11-14T22:13:20Z", GoVersion: runtime.Version(), TrustRootDigest: TrustRootDigest, CandidateOnly: true})

	identity, err := Report()
	if err != nil {
		t.Fatal(err)
	}
	if identity.BuildProfile != "community-darwin-arm64" || identity.ReleaseState != ReleaseStateRelease {
		t.Fatalf("community identity = %#v", identity)
	}
	if !IsCommunityProfile(identity.BuildProfile) || IsReleaseProfile(identity.BuildProfile) {
		t.Fatalf("community profile classification is wrong: %#v", identity.BuildProfile)
	}
}

func TestCommunityProfileNeverSatisfiesReleaseProfile(t *testing.T) {
	for _, community := range []string{"community-linux-amd64", "community-linux-arm64", "community-darwin-amd64", "community-darwin-arm64"} {
		if IsReleaseProfile(community) {
			t.Fatalf("community profile %q satisfied the strict signed-release profile check", community)
		}
		if !IsCommunityProfile(community) {
			t.Fatalf("community profile %q was not recognized as a community profile", community)
		}
	}
	for _, release := range []string{"linux-amd64", "linux-arm64"} {
		if IsCommunityProfile(release) {
			t.Fatalf("signed-release profile %q was accepted as a community profile", release)
		}
		if !IsReleaseProfile(release) {
			t.Fatalf("signed-release profile %q was not recognized", release)
		}
	}
	for _, bad := range []string{"community-windows-amd64", "community-linux-amd64 ", "/tmp", "linux-amd64-community"} {
		if IsReleaseProfile(bad) || IsCommunityProfile(bad) {
			t.Fatalf("invalid profile %q was accepted", bad)
		}
	}
}

func TestReportRejectsMalformedReleaseIdentity(t *testing.T) {
	cases := []struct {
		name string
		set  func()
	}{
		{"version", func() { Version = "release" }},
		{"revision", func() { Version = "1.2.3"; SourceRevision = "../private" }},
		{"tree digest", func() { Version = "1.2.3"; SourceTreeDigest = "sha256:" + strings.Repeat("0", 63) }},
		{"epoch", func() { Version = "1.2.3"; BuildEpoch = "-1" }},
		{"profile", func() { Version = "1.2.3"; BuildProfile = "/tmp" }},
		{"windows profile is not a recognized community target", func() { Version = "1.2.3"; BuildProfile = "community-windows-amd64" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			old := linkerSnapshot()
			defer old.restore()
			resetLinkerValues()
			tc.set()
			if _, err := Report(); err == nil || !strings.Contains(err.Error(), ErrIntegrity.Error()) {
				t.Fatalf("Report() error = %v, want integrity failure", err)
			}
		})
	}
}

func TestReportForVersionPreservesDeterministicPinnedFields(t *testing.T) {
	old := linkerSnapshot()
	defer old.restore()
	resetLinkerValues()
	SourceRevision = "0123456789abcdef"
	SourceTreeDigest = "sha256:" + strings.Repeat("a", 64)
	AllowlistDigest = "sha256:" + strings.Repeat("b", 64)
	BuildProfile = "linux-arm64"
	BuildEpoch = "0"
	TrustRootDigest = UnpinnedTrustRoot
	EmbeddedIdentity = Marker(Identity{Version: "1.2.3", ReleaseState: ReleaseStateRelease, SourceRevision: SourceRevision, SourceTreeDigest: SourceTreeDigest, AllowlistDigest: AllowlistDigest, BuildProfile: BuildProfile, BuildEpoch: "1970-01-01T00:00:00Z", GoVersion: runtime.Version(), TrustRootDigest: TrustRootDigest, CandidateOnly: true})
	first, err := ReportForVersion("1.2.3")
	if err != nil {
		t.Fatal(err)
	}
	second, err := ReportForVersion("1.2.3")
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatalf("same inputs yielded different identities: %#v != %#v", first, second)
	}
}

type snapshot struct {
	version, sourceRevision, sourceTreeDigest, allowlistDigest string
	buildProfile, buildEpoch, trustRootDigest                  string
	embeddedIdentity                                           string
}

func linkerSnapshot() snapshot {
	return snapshot{Version, SourceRevision, SourceTreeDigest, AllowlistDigest, BuildProfile, BuildEpoch, TrustRootDigest, EmbeddedIdentity}
}

func (s snapshot) restore() {
	Version, SourceRevision, SourceTreeDigest, AllowlistDigest = s.version, s.sourceRevision, s.sourceTreeDigest, s.allowlistDigest
	BuildProfile, BuildEpoch, TrustRootDigest, EmbeddedIdentity = s.buildProfile, s.buildEpoch, s.trustRootDigest, s.embeddedIdentity
}

func resetLinkerValues() {
	Version = DevelopmentVersion
	SourceRevision = DevelopmentValue
	SourceTreeDigest = DevelopmentValue
	AllowlistDigest = DevelopmentValue
	BuildProfile = DevelopmentProfile
	BuildEpoch = DevelopmentValue
	TrustRootDigest = DevelopmentValue
	EmbeddedIdentity = DevelopmentValue
}
